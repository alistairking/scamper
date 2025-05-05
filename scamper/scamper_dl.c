/*
 * scamper_dl: manage BPF/PF_PACKET datalink instances for scamper
 *
 * $Id: scamper_dl.c,v 1.235 2025/04/08 21:27:02 mjl Exp $
 *
 *          Matthew Luckie
 *          Ben Stasiewicz added fragmentation support.
 *          Stephen Eichler added SACK support.
 *          Alistair King added PACKET_RX_RING support.
 *
 *          Supported by:
 *           The University of Waikato
 *           NLANR Measurement and Network Analysis
 *           CAIDA
 *           The WIDE Project
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2014-2015 The Regents of the University of California
 * Copyright (C) 2022-2024 Matthew Luckie
 * Copyright (C) 2023-2024 The Regents of the University of California
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#if defined(HAVE_BPF) || defined(__linux__)
#define HAVE_BPF_FILTER
#endif

#if defined(BIOCSETFNR) || defined(__linux__)
#define HAVE_BPF_DYN_FILTER
#endif

#if defined(HAVE_BPF_DYN_FILTER) || defined(TEST_DL_FILTER_COMPILE)
#define DYN_FILTER_PORT_MAX 20
#endif

#ifdef HAVE_BPF
typedef struct bpf_insn    filt_insn_t;
typedef struct bpf_program filt_prog_t;
#endif

#ifdef __linux__
typedef struct sock_filter filt_insn_t;
typedef struct sock_fprog  filt_prog_t;
#endif

#include "scamper.h"
#include "scamper_debug.h"
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_fds.h"
#include "scamper_dl.h"
#include "scamper_priv.h"
#include "scamper_task.h"
#include "scamper_if.h"
#include "scamper_osinfo.h"
#include "utils.h"

#if defined(HAVE_BPF) && defined(DLT_APPLE_IP_OVER_IEEE1394)
#define HAVE_FIREWIRE
#elif defined(__linux__) && defined(ARPHRD_IEEE1394)
#define HAVE_FIREWIRE
#endif

#ifdef HAVE_STRUCT_TPACKET_REQ3
#define MAX_BLOCKS_PER_READ 1
struct ring
{
  uint8_t              *map;
  size_t                map_size;
  struct tpacket_req3   req;
  struct iovec         *blocks;
  /* number of elements (frames) in the frames iovec (tp_frame_nr) */
  unsigned int          blocks_cnt;
  /* current index into the iovecs */
  unsigned int          cur_block;
  unsigned int          accepted_pkts;
  unsigned int          dropped_pkts;
};

struct block_desc {
  uint32_t              version;
  uint32_t              offset_to_priv;
  struct tpacket_hdr_v1 h1;
};
#endif

struct scamper_dl
{
  /* the file descriptor that scamper has on the datalink */
  scamper_fd_t  *fdn;

  /* the callback used to read packets off the datalink */
  int          (*dlt_cb)(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len);

  /* the ifindex found in the corresponding scamper_fd_t */
  int            ifindex;

  /* the underlying type of the datalink (DLT_* or ARPHDR_* values) */
  int            type;

  /* how the user should frame packet to transmit on the datalink */
  int            tx_type;

  /* if we're using BPF, then we need to use an appropriately sized buffer */
#if defined(HAVE_BPF)
  u_int          readbuf_len;
#endif

#ifdef HAVE_STRUCT_TPACKET_REQ3
  struct ring   *ring;
#endif

};

#ifdef BUILDING_SCAMPER
static uint8_t          *readbuf = NULL;
static size_t            readbuf_len = 0;
#ifdef __linux__
static int               lo_ifindex = -1;
#endif
#ifdef HAVE_BPF
static const scamper_osinfo_t *osinfo = NULL;
#endif
#endif /* BUILDING_SCAMPER */

/*
 * dl_parse_ip
 *
 * pkt points to the beginning of an IP header.  given the length of the
 * packet, parse the contents into a datalink record structure.
 */
#if defined(BUILDING_SCAMPER) || defined(TEST_DL_PARSE_IP)
#ifdef TEST_DL_PARSE_IP
int dl_parse_ip(scamper_dl_rec_t *dl, uint8_t *pktbuf, size_t pktlen)
#else
static int dl_parse_ip(scamper_dl_rec_t *dl, uint8_t *pktbuf, size_t pktlen)
#endif
{
  struct ip        *ip4;
  struct ip6_hdr   *ip6;
  struct ip6_ext   *ip6_exthdr;
  struct ip6_frag  *ip6_fraghdr;
  struct icmp      *icmp4;
  struct icmp6_hdr *icmp6;
  struct tcphdr    *tcp;
  struct udphdr    *udp;
  size_t            iplen;
  size_t            extlen;
  uint8_t          *pkt = pktbuf;
  size_t            len = pktlen;
  size_t            off;
  uint8_t          *tmp;
  uint16_t          u16;
  int               i;

  /* minimum size of an IPv4 header, which is larger than an IPv6 header */
  if(pktlen < 20)
    return 0;

  if((pkt[0] >> 4) == 4) /* IPv4 */
    {
      ip4 = (struct ip *)pkt;

#ifndef _WIN32 /* windows does not separate ip_v and ip_hl */
      iplen = (ip4->ip_hl << 2);
#else
      iplen = ((ip4->ip_vhl) & 0xf) << 2;
#endif

      /*
       * make sure that the captured packet has enough to cover the whole
       * of the IP header
       */
      if(iplen > len)
	return 0;

      memset(dl, 0, sizeof(scamper_dl_rec_t));

      /* figure out fragmentation details */
      u16 = ntohs(ip4->ip_off);
      dl->dl_ip_off = (u16 & IP_OFFMASK) * 8;
      if(dl->dl_ip_off != 0 || (u16 & IP_MF) != 0)
	dl->dl_ip_flags |= SCAMPER_DL_IP_FLAG_FRAG;
      if((u16 & IP_DF) != 0)
	dl->dl_ip_flags |= SCAMPER_DL_IP_FLAG_DF;
      if((u16 & IP_MF) != 0)
	dl->dl_ip_flags |= SCAMPER_DL_IP_FLAG_MF;

      dl->dl_af       = AF_INET;
      dl->dl_ip_hl    = iplen;
      dl->dl_ip_proto = ip4->ip_p;
      dl->dl_ip_size  = ntohs(ip4->ip_len);
      dl->dl_ip_id    = ntohs(ip4->ip_id);
      dl->dl_ip_tos   = ip4->ip_tos;
      dl->dl_ip_ttl   = ip4->ip_ttl;
      dl->dl_ip_src   = (uint8_t *)&ip4->ip_src;
      dl->dl_ip_dst   = (uint8_t *)&ip4->ip_dst;

      dl->dl_flags    = SCAMPER_DL_REC_FLAG_NET;
      dl->dl_net_type = SCAMPER_DL_REC_NET_TYPE_IP;

      pkt += iplen;
      len -= iplen;
    }
  else if((pkt[0] >> 4) == 6) /* IPv6 */
    {
      ip6 = (struct ip6_hdr *)pkt;

      if((iplen = sizeof(struct ip6_hdr)) > len)
	return 0;

      memset(dl, 0, sizeof(scamper_dl_rec_t));

      dl->dl_af       = AF_INET6;
      dl->dl_ip_hl    = iplen;
      dl->dl_ip_flow  = ntohl(ip6->ip6_flow) & 0xfffff;
      dl->dl_ip_proto = ip6->ip6_nxt;
      dl->dl_ip_size  = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr);
      dl->dl_ip_hlim  = ip6->ip6_hlim;
      dl->dl_ip_tos   = (((pkt[0] & 0x0f) << 4) | (pkt[1] & 0xf0) >> 4);
      dl->dl_ip_src   = (uint8_t *)&ip6->ip6_src;
      dl->dl_ip_dst   = (uint8_t *)&ip6->ip6_dst;

      dl->dl_flags    = SCAMPER_DL_REC_FLAG_NET;
      dl->dl_net_type = SCAMPER_DL_REC_NET_TYPE_IP;

      pkt += iplen;
      len -= iplen;

      /* Process any IPv6 fragmentation headers */
      for(;;)
        {
	  switch(dl->dl_ip_proto)
            {
	    case IPPROTO_HOPOPTS:
	    case IPPROTO_DSTOPTS:
	    case IPPROTO_ROUTING:
	      if(sizeof(struct ip6_ext) > len)
		return 0;
	      ip6_exthdr = (struct ip6_ext *)pkt;
	      if((extlen = (ip6_exthdr->ip6e_len * 8) + 8) > len)
		return 0;
	      dl->dl_ip_proto = ip6_exthdr->ip6e_nxt;
	      break;

	    case IPPROTO_FRAGMENT:
	      if((extlen = sizeof(struct ip6_frag)) > len)
		return 0;
	      ip6_fraghdr = (struct ip6_frag *)pkt;
	      dl->dl_ip6_id = ntohl(ip6_fraghdr->ip6f_ident);
	      dl->dl_ip_off = ntohs(ip6_fraghdr->ip6f_offlg) & 0xfff8;
	      dl->dl_ip_proto = ip6_fraghdr->ip6f_nxt;
	      dl->dl_ip_flags |= SCAMPER_DL_IP_FLAG_FRAG;
	      if(ntohs(ip6_fraghdr->ip6f_offlg) & 0x1)
		dl->dl_ip_flags |= SCAMPER_DL_IP_FLAG_MF;
	      break;

	    default:
	      extlen = 0;
	      break;
            }

	  if(extlen == 0)
	    break;

	  dl->dl_ip_hl += extlen;
	  pkt += extlen;
	  len -= extlen;
        }
    }
  else
    {
      return 0;
    }

  dl->dl_ip_data    = pkt;
  dl->dl_ip_datalen = len;

  /*
   * can't do any further processing of the packet if we're seeing
   * a later fragment
   */
  if(dl->dl_ip_off != 0)
    {
      dl->dl_net_raw = pktbuf;
      dl->dl_net_rawlen = pktlen;
      return 1;
    }

  if(dl->dl_ip_proto == IPPROTO_UDP)
    {
      if(sizeof(struct udphdr) > len)
	return 0;

      udp = (struct udphdr *)pkt;
      dl->dl_udp_dport = ntohs(udp->uh_dport);
      dl->dl_udp_sport = ntohs(udp->uh_sport);
      dl->dl_udp_sum   = udp->uh_sum;
      dl->dl_flags    |= SCAMPER_DL_REC_FLAG_TRANS;
    }
  else if(dl->dl_ip_proto == IPPROTO_TCP)
    {
      if(sizeof(struct tcphdr) > len)
	return 0;

      tcp = (struct tcphdr *)pkt;
      dl->dl_tcp_dport  = ntohs(tcp->th_dport);
      dl->dl_tcp_sport  = ntohs(tcp->th_sport);
      dl->dl_tcp_seq    = ntohl(tcp->th_seq);
      dl->dl_tcp_ack    = ntohl(tcp->th_ack);
#ifndef _WIN32 /* windows does not separate th_off and th_x2 */
      dl->dl_tcp_hl     = tcp->th_off * 4;
#else
      dl->dl_tcp_hl     = (tcp->th_offx2 >> 4) * 4;
#endif
      dl->dl_tcp_flags  = tcp->th_flags;
      dl->dl_tcp_win    = ntohs(tcp->th_win);
      dl->dl_flags     |= SCAMPER_DL_REC_FLAG_TRANS;

      if(dl->dl_tcp_hl >= 20 && len >= dl->dl_tcp_hl)
	{
	  off = 20;
	  while(off < dl->dl_tcp_hl)
	    {
	      tmp = pkt + off;

	      if(tmp[0] == 0) /* End of option list */
		break;

	      if(tmp[0] == 1) /* no-op */
		{
		  off++;
		  continue;
		}

	      if(tmp[1] == 0)
		break;

	      /* make sure the option's length is sensible */
	      if(off + tmp[1] > dl->dl_tcp_hl)
		break;

	      if(tmp[0] == 2 && tmp[1] == 4) /* mss option */
		dl->dl_tcp_mss = bytes_ntohs(tmp+2);

	      if(tmp[0] == 4 && tmp[1] == 2) /* sack permitted option */
		dl->dl_tcp_opts |= SCAMPER_DL_TCP_OPT_SACKP;

	      if(tmp[0] == 8 && tmp[1] == 10) /* timestamps */
		{
		  dl->dl_tcp_opts |= SCAMPER_DL_TCP_OPT_TS;
		  dl->dl_tcp_tsval = bytes_ntohl(tmp+2);
		  dl->dl_tcp_tsecr = bytes_ntohl(tmp+6);
		}

	      if(tmp[0] == 5)
		{
		  if(tmp[1]==10 || tmp[1]==18 || tmp[1]==26 || tmp[1]==34)
		    {
		      dl->dl_tcp_sack_edgec = (tmp[1]-2) / 4;
		      for(i=0; i<(tmp[1]-2)/4; i++)
			dl->dl_tcp_sack_edges[i] = bytes_ntohl(tmp+2 + (i*4));
		    }
		  else
		    {
		      dl->dl_tcp_sack_edgec = -1;
		    }
		}

	      if(tmp[0] == 34 && tmp[1] >= 2)
		{
		  dl->dl_tcp_opts |= SCAMPER_DL_TCP_OPT_FO;
		  dl->dl_tcp_fo_cookielen = tmp[1] - 2;
		  memcpy(dl->dl_tcp_fo_cookie, tmp+2, dl->dl_tcp_fo_cookielen);
		}

	      if(tmp[0] == 254 && tmp[1] >= 4 && bytes_ntohs(tmp+2) == 0xF989)
		{
		  dl->dl_tcp_opts |= SCAMPER_DL_TCP_OPT_FO_EXP;
		  dl->dl_tcp_fo_cookielen = tmp[1] - 4;
		  memcpy(dl->dl_tcp_fo_cookie, tmp+4, dl->dl_tcp_fo_cookielen);
		}

	      off += tmp[1];
	    }

	  dl->dl_tcp_datalen = dl->dl_ip_size - dl->dl_ip_hl - dl->dl_tcp_hl;
	  if(dl->dl_tcp_datalen > 0)
	    dl->dl_tcp_data = pkt + dl->dl_tcp_hl;
	}
    }
  else if(dl->dl_ip_proto == IPPROTO_ICMP && dl->dl_af == AF_INET)
    {
      /* the absolute minimum ICMP header size is 8 bytes */
      if(ICMP_MINLEN > len)
	return 0;

      icmp4 = (struct icmp *)pkt;
      dl->dl_icmp_type = icmp4->icmp_type;
      dl->dl_icmp_code = icmp4->icmp_code;

      switch(dl->dl_icmp_type)
	{
	case ICMP_UNREACH:
	case ICMP_TIMXCEED:
	  if(ICMP_MINLEN + sizeof(struct ip) > len)
	    return 0;

	  if(dl->dl_icmp_type == ICMP_UNREACH &&
	     dl->dl_icmp_code == ICMP_UNREACH_NEEDFRAG)
	    dl->dl_icmp_nhmtu = ntohs(icmp4->icmp_nextmtu);

	  ip4 = &icmp4->icmp_ip;

	  dl->dl_icmp_ip_proto = ip4->ip_p;
	  dl->dl_icmp_ip_size  = ntohs(ip4->ip_len);
	  dl->dl_icmp_ip_id    = ntohs(ip4->ip_id);
	  dl->dl_icmp_ip_tos   = ip4->ip_tos;
	  dl->dl_icmp_ip_ttl   = ip4->ip_ttl;
	  dl->dl_icmp_ip_src   = (uint8_t *)&ip4->ip_src;
	  dl->dl_icmp_ip_dst   = (uint8_t *)&ip4->ip_dst;

	  /*
	   * the ICMP response should include the IP header and the first
	   * 8 bytes of the transport header.
	   */
#ifndef _WIN32 /* windows does not separate ip_v and ip_hl */
	  if((size_t)(ICMP_MINLEN + (ip4->ip_hl << 2) + 8) > len)
#else
	  if((size_t)(ICMP_MINLEN + ((ip4->ip_vhl & 0xf) << 2) + 8) > len)
#endif
	    {
	      return 0;
	    }

	  pkt = (uint8_t *)ip4;

#ifndef _WIN32 /* windows does not separate ip_v and ip_hl */
	  iplen = (ip4->ip_hl << 2);
#else
	  iplen = ((ip4->ip_vhl & 0xf) << 2);
#endif

	  pkt += iplen;

	  if(dl->dl_icmp_ip_proto == IPPROTO_UDP)
	    {
	      udp = (struct udphdr *)pkt;
	      dl->dl_icmp_udp_sport = ntohs(udp->uh_sport);
	      dl->dl_icmp_udp_dport = ntohs(udp->uh_dport);
	      dl->dl_icmp_udp_sum   = udp->uh_sum;
	    }
	  else if(dl->dl_icmp_ip_proto == IPPROTO_ICMP)
	    {
	      icmp4 = (struct icmp *)pkt;
	      dl->dl_icmp_icmp_type = icmp4->icmp_type;
	      dl->dl_icmp_icmp_code = icmp4->icmp_code;
	      dl->dl_icmp_icmp_id   = ntohs(icmp4->icmp_id);
	      dl->dl_icmp_icmp_seq  = ntohs(icmp4->icmp_seq);
	    }
	  else if(dl->dl_icmp_ip_proto == IPPROTO_TCP)
	    {
	      tcp = (struct tcphdr *)pkt;
	      dl->dl_icmp_tcp_sport = ntohs(tcp->th_sport);
	      dl->dl_icmp_tcp_dport = ntohs(tcp->th_dport);
	      dl->dl_icmp_tcp_seq   = ntohl(tcp->th_seq);
	    }
	  break;

	case ICMP_ECHOREPLY:
	case ICMP_ECHO:
	case ICMP_TSTAMPREPLY:
	case ICMP_TSTAMP:
	  dl->dl_icmp_id  = ntohs(icmp4->icmp_id);
	  dl->dl_icmp_seq = ntohs(icmp4->icmp_seq);
	  break;

	default:
	  return 0;
	}

      dl->dl_flags |= SCAMPER_DL_REC_FLAG_TRANS;
    }
  else if(dl->dl_ip_proto == IPPROTO_ICMPV6 && dl->dl_af == AF_INET6)
    {
      /* the absolute minimum ICMP header size is 8 bytes */
      if(sizeof(struct icmp6_hdr) > len)
	return 0;

      icmp6 = (struct icmp6_hdr *)pkt;
      dl->dl_icmp_type = icmp6->icmp6_type;
      dl->dl_icmp_code = icmp6->icmp6_code;
      pkt += sizeof(struct icmp6_hdr);
      len -= sizeof(struct icmp6_hdr);

      switch(dl->dl_icmp_type)
	{
	case ICMP6_TIME_EXCEEDED:
	case ICMP6_DST_UNREACH:
	case ICMP6_PACKET_TOO_BIG:
	  if(sizeof(struct ip6_hdr) + 8 > len)
	    return 0;

	  if(dl->dl_icmp_type == ICMP6_PACKET_TOO_BIG)
	    {
#ifndef _WIN32 /* windows does not provide icmp6_mtu in struct icmp6_hdr */
	      dl->dl_icmp_nhmtu = (ntohl(icmp6->icmp6_mtu) % 0xffff);
#else
	      dl->dl_icmp_nhmtu = ntohs(icmp6->icmp6_seq);
#endif
	    }

	  ip6 = (struct ip6_hdr *)pkt;

	  dl->dl_icmp_ip_proto = ip6->ip6_nxt;
	  dl->dl_icmp_ip_size  = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr);
	  dl->dl_icmp_ip_hlim  = ip6->ip6_hlim;
	  dl->dl_icmp_ip_flow  = ntohl(ip6->ip6_flow) & 0xfffff;
	  dl->dl_icmp_ip_tos = ((pkt[0] & 0xf) << 4) | ((pkt[1] & 0xf0) >> 4);
	  dl->dl_icmp_ip_src = (uint8_t *)&ip6->ip6_src;
	  dl->dl_icmp_ip_dst = (uint8_t *)&ip6->ip6_dst;

	  pkt += sizeof(struct ip6_hdr);

	  if(dl->dl_icmp_ip_proto == IPPROTO_UDP)
	    {
	      udp = (struct udphdr *)pkt;
	      dl->dl_icmp_udp_sport = ntohs(udp->uh_sport);
	      dl->dl_icmp_udp_dport = ntohs(udp->uh_dport);
	      dl->dl_icmp_udp_sum   = udp->uh_sum;
	    }
	  else if(dl->dl_icmp_ip_proto == IPPROTO_ICMPV6)
	    {
	      icmp6 = (struct icmp6_hdr *)pkt;
	      dl->dl_icmp_icmp_type = icmp6->icmp6_type;
	      dl->dl_icmp_icmp_code = icmp6->icmp6_code;
	      dl->dl_icmp_icmp_id   = ntohs(icmp6->icmp6_id);
	      dl->dl_icmp_icmp_seq  = ntohs(icmp6->icmp6_seq);
	    }
	  else if(dl->dl_icmp_ip_proto == IPPROTO_TCP)
	    {
	      tcp = (struct tcphdr *)pkt;
	      dl->dl_icmp_tcp_sport = ntohs(tcp->th_sport);
	      dl->dl_icmp_tcp_dport = ntohs(tcp->th_dport);
	      dl->dl_icmp_tcp_seq   = ntohl(tcp->th_seq);
	    }
	  break;

	case ICMP6_ECHO_REPLY:
	case ICMP6_ECHO_REQUEST:
	  dl->dl_icmp_id  = ntohs(icmp6->icmp6_id);
	  dl->dl_icmp_seq = ntohs(icmp6->icmp6_seq);
	  break;

	case ND_NEIGHBOR_ADVERT:
	  dl->dl_icmp6_nd_target   = pkt;
	  dl->dl_icmp6_nd_opts     = pkt + 16;
	  dl->dl_icmp6_nd_opts_len = len - 16;
	  break;

	default:
	  return 0;
	}

      dl->dl_flags |= SCAMPER_DL_REC_FLAG_TRANS;
    }
  else
    {
      return 0;
    }

  dl->dl_net_raw = pktbuf;
  dl->dl_net_rawlen = pktlen;
  return 1;
}
#endif /* BUILDING_SCAMPER or TEST_DL_PARSE_IP */

/*
 * dl_parse_arp
 *
 * pkt points to the beginning of an ARP payload.  given the length of the
 * packet, parse the contents into a datalink record structure.
 */
#if defined(BUILDING_SCAMPER) || defined(TEST_DL_PARSE_ARP)
#ifdef TEST_DL_PARSE_ARP
int dl_parse_arp(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len)
#else
static int dl_parse_arp(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len)
#endif
{
  size_t off;

  /* need to at least have a header, and the bits after the arp header */
  if(len <= 8 || (size_t)((pkt[4]*2) + (pkt[5]*2) + 8) > len)
    return 0;

  memset(dl, 0, sizeof(scamper_dl_rec_t));

  dl->dl_arp_hrd = bytes_ntohs(pkt+0);
  dl->dl_arp_pro = bytes_ntohs(pkt+2);
  dl->dl_arp_hln = pkt[4];
  dl->dl_arp_pln = pkt[5];
  dl->dl_arp_op  = bytes_ntohs(pkt+6);

  off = 8;
  dl->dl_arp_sha = pkt+off; off += dl->dl_arp_hln;
  dl->dl_arp_spa = pkt+off; off += dl->dl_arp_pln;
  dl->dl_arp_tha = pkt+off; off += dl->dl_arp_hln;
  dl->dl_arp_tpa = pkt+off;

  /* completed record is an arp frame */
  dl->dl_net_type = SCAMPER_DL_REC_NET_TYPE_ARP;

  dl->dl_net_raw    = pkt;
  dl->dl_net_rawlen = len;
  return 1;
}
#endif /* BUILDING_SCAMPER or TEST_DL_PARSE_ARP */

#if defined(BUILDING_SCAMPER) || defined(TEST_DL_FILTER_COMPILE)
#ifdef HAVE_BPF_FILTER
static void bpf_stmt(filt_insn_t *insns, size_t len, size_t *off,
		     uint16_t code, uint32_t k)
{
  if(*off >= len)
    return;
  insns[*off].code = code;
  insns[*off].jt   = 0;
  insns[*off].jf   = 0;
  insns[*off].k    = k;
  (*off)++;
  return;
}
#endif /* HAVE_BPF_FILTER */

#if defined(HAVE_BPF_DYN_FILTER) || defined(TEST_DL_FILTER_COMPILE)
static void bpf_jump(filt_insn_t *insns, size_t len, size_t *off,
		     uint16_t code, uint32_t k, uint8_t jt, uint8_t jf)
{
  if(*off >= len)
    return;
  insns[*off].code = code;
  insns[*off].jt   = jt;
  insns[*off].jf   = jf;
  insns[*off].k    = k;
  (*off)++;
  return;
}

static size_t bpf_ret_false(size_t len, size_t off)
{
  return len - off - 3;
}

static size_t bpf_ret_true(size_t len, size_t off)
{
  return len - off - 2;
}

static uint16_t bpf_portinsns_calc(const uint16_t *ports, uint16_t portc,
				   uint16_t *min, uint16_t *max)
{
  uint16_t i;

  if(portc == 0)
    return 0;

  /* check each port individually, both directions */
  if(portc <= DYN_FILTER_PORT_MAX)
    return (portc * 2) + 2;

  /* check if ports are within a range, both directions */
  *min = *max = ports[0];
  for(i=1; i<portc; i++)
    {
      if(*min > ports[i])
	*min = ports[i];
      else if(*max < ports[i])
	*max = ports[i];
    }
  return 6;
}

static void bpf_portinsns_enc(filt_insn_t *insns, size_t len, size_t *off,
			      const uint16_t *ports, uint16_t portc,
			      uint16_t min, uint16_t max,
			      uint16_t code, uint32_t ip_off)
{
  uint16_t i;

  /* check source port */
  bpf_stmt(insns, len, off, BPF_LD+code+BPF_H, ip_off + 0);
  if(portc <= DYN_FILTER_PORT_MAX)
    {
      for(i=0; i<portc; i++)
	bpf_jump(insns, len, off, BPF_JMP+BPF_JEQ+BPF_K, ports[i],
		 bpf_ret_true(len, *off), 0);
    }
  else
    {
      bpf_jump(insns, len, off, BPF_JMP+BPF_JGE+BPF_K, min, 0, 1);
      bpf_jump(insns, len, off, BPF_JMP+BPF_JGT+BPF_K, max,
	       0, bpf_ret_true(len, *off));
    }

  /* check destination port */
  bpf_stmt(insns, len, off, BPF_LD+code+BPF_H, ip_off + 2);
  if(portc <= DYN_FILTER_PORT_MAX)
    {
      for(i=0; i<portc; i++)
	bpf_jump(insns, len, off, BPF_JMP+BPF_JEQ+BPF_K, ports[i],
		 bpf_ret_true(len, *off),
		 portc - i > 1 ? 0 : bpf_ret_false(len, *off));
    }
  else
    {
      bpf_jump(insns, len, off, BPF_JMP+BPF_JGE+BPF_K, min, 0, 1);
      bpf_jump(insns, len, off, BPF_JMP+BPF_JGT+BPF_K, max,
	       bpf_ret_false(len, *off), bpf_ret_true(len, *off));
    }

  return;
}
#endif /* HAVE_BPF_DYN_FILTER or TEST_DL_FILTER_COMPILE */

#if defined(HAVE_BPF_DYN_FILTER) || defined(TEST_DL_FILTER_COMPILE)
#ifdef BUILDING_SCAMPER
static int dl_filter_compile(uint8_t rx_type, filt_prog_t *prog,
			     const uint16_t *ports, size_t portc)
#else
int dl_filter_compile(uint8_t rx_type, filt_prog_t *prog,
		      const uint16_t *ports, size_t portc)
#endif
{
  uint32_t ipv4_c, ipv6_c, udp4_c, udp6_c, tcp4_c, tcp6_c, ip_off, k_dlt;
  const uint16_t *udp4_ports; uint16_t udp4_portc, udp4_min = 0, udp4_max = 0;
  const uint16_t *tcp4_ports; uint16_t tcp4_portc, tcp4_min = 0, tcp4_max = 0;
  const uint16_t *udp6_ports; uint16_t udp6_portc, udp6_min = 0, udp6_max = 0;
  const uint16_t *tcp6_ports; uint16_t tcp6_portc, tcp6_min = 0, tcp6_max = 0;
  size_t len, off = 0;
  filt_insn_t *insns = NULL;

#ifdef __linux__
  int extra = 0;
#endif

  udp4_portc = ports[0]; udp4_ports = ports + 4;
  tcp4_portc = ports[1]; tcp4_ports = udp4_ports + udp4_portc;
  udp6_portc = ports[2]; udp6_ports = tcp4_ports + tcp4_portc;
  tcp6_portc = ports[3]; tcp6_ports = udp6_ports + udp6_portc;

  ipv4_c = 4;
  if(udp4_portc > 0 || tcp4_portc > 0)
    ipv4_c += 1;
  udp4_c = bpf_portinsns_calc(udp4_ports, udp4_portc, &udp4_min, &udp4_max);
  if(udp4_c > 0)
    ipv4_c += (1 + udp4_c);
  tcp4_c = bpf_portinsns_calc(tcp4_ports, tcp4_portc, &tcp4_min, &tcp4_max);
  if(tcp4_c > 0)
    ipv4_c += (1 + tcp4_c);

  ipv6_c = 2 + 4;
  udp6_c = bpf_portinsns_calc(udp6_ports, udp6_portc, &udp6_min, &udp6_max);
  if(udp6_c > 0)
    ipv6_c += (1 + udp6_c);
  tcp6_c = bpf_portinsns_calc(tcp6_ports, tcp6_portc, &tcp6_min, &tcp6_max);
  if(tcp6_c > 0)
    ipv6_c += (1 + tcp6_c);

  if(rx_type == SCAMPER_DL_RX_ETHERNET)
    len = 4;
#ifdef __linux__
  else if(rx_type == SCAMPER_DL_RX_COOKED)
    {
      len = 12;
#ifdef ARPHRD_SIT
      len++;
      extra++;
#endif
#ifdef ARPHRD_VOID
      len++;
      extra++;
#endif
    }
#endif /* __linux__ */
#if defined(HAVE_BPF) || defined(TEST_DL_FILTER_COMPILE)
  else if(rx_type == SCAMPER_DL_RX_NULL)
    len = 3;
#endif
  else if(rx_type == SCAMPER_DL_RX_RAW)
    len = 4;
  else
    return -1;

  len += 2 + ipv4_c + ipv6_c;

#ifdef __linux__
  /* prog.len is an unsigned short on linux */
  if(len > UINT16_MAX)
    return -1;
#endif

  if((insns = malloc(sizeof(filt_insn_t) * len)) == NULL)
    return -1;

  if(rx_type == SCAMPER_DL_RX_ETHERNET)
    {
      ip_off = 14;
      k_dlt = ETHERTYPE_IP;
      bpf_stmt(insns, len, &off, BPF_LD+BPF_ABS+BPF_H, 12);
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, k_dlt,
	       2,
	       0);
      k_dlt = ETHERTYPE_IPV6;
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, k_dlt,
	       ipv4_c + 1,
	       0);
      k_dlt = ETHERTYPE_ARP;
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, k_dlt,
	       bpf_ret_true(len, off),
	       bpf_ret_false(len, off));
    }
#ifdef __linux__
  else if(rx_type == SCAMPER_DL_RX_COOKED)
    {
      ip_off = 0;
      bpf_stmt(insns, len, &off, BPF_LD+BPF_ABS+BPF_H,
	       SKF_AD_OFF + SKF_AD_HATYPE);
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, ARPHRD_ETHER,
	       2 + extra, 0);
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, ARPHRD_LOOPBACK,
	       1 + extra, 0);
#ifdef ARPHRD_SIT
      extra--;
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, ARPHRD_SIT,
	       5 + extra, 0);
#endif
#ifdef ARPHRD_VOID
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, ARPHRD_VOID,
	       5, 0);
#endif
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, ARPHRD_PPP,
	       4, bpf_ret_false(len, off));

      /* handle ARPHRD_ETHER, ARPHRD_LOOPBACK */
      bpf_stmt(insns, len, &off, BPF_LD+BPF_ABS+BPF_H,
	       SKF_AD_OFF + SKF_AD_PROTOCOL);
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP,
	       4 + 2, 0);
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IPV6,
	       4 + ipv4_c + 1, 0);
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_ARP,
	       bpf_ret_true(len, off),
	       bpf_ret_false(len, off));

      /* handle ARPHRD_SIT, ARPHRD_VOID, ARPHRD_PPP */
      bpf_stmt(insns, len, &off, BPF_LD+BPF_ABS+BPF_B, 0);
      bpf_stmt(insns, len, &off, BPF_ALU+BPF_RSH+BPF_K, 4);
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, 4, 1, 0);
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, 6, ipv4_c,
	       bpf_ret_false(len, off));
    }
#endif /* __linux__ */
#if defined(HAVE_BPF) || defined(TEST_DL_FILTER_COMPILE)
  else if(rx_type == SCAMPER_DL_RX_NULL)
    {
      ip_off = 4;
      k_dlt = htonl(PF_INET);
      bpf_stmt(insns, len, &off, BPF_LD+BPF_ABS+BPF_W, 0);
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, k_dlt, 1, 0);
      k_dlt = htonl(PF_INET6);
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, k_dlt, ipv4_c,
	       bpf_ret_false(len, off));
    }
#endif
  else if(rx_type == SCAMPER_DL_RX_RAW)
    {
      ip_off = 0;
      bpf_stmt(insns, len, &off, BPF_LD+BPF_ABS+BPF_B, 0);
      bpf_stmt(insns, len, &off, BPF_ALU+BPF_RSH+BPF_K, 4);
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, 4, 1, 0);
      bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, 6, ipv4_c,
	       bpf_ret_false(len, off));
    }
  else
    {
      free(insns);
      return -1;
    }

  /* we know the packet is IPv4.  if fragment offset is > 0, pass it */
  bpf_stmt(insns, len, &off, BPF_LD+BPF_ABS+BPF_H, ip_off+6);
  bpf_jump(insns, len, &off, BPF_JMP+BPF_JSET+BPF_K, IP_OFFMASK,
	   ipv6_c + ipv4_c - 1, 0);

  /* load the protocol type into the accumulator */
  bpf_stmt(insns, len, &off, BPF_LD+BPF_ABS+BPF_B, ip_off+9);

  /* if it is ICMP, which is specific to IPv4, pass it */
  bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_ICMP,
	   bpf_ret_true(len, off),
	   udp4_portc > 0 || tcp4_portc > 0 ? 0 : bpf_ret_false(len, off));

  /*
   * calculate the length of the IP header so that we can then
   * calculate the distance of the transport header into the packet
   */
  if(udp4_portc > 0 || tcp4_portc > 0)
    bpf_stmt(insns, len, &off, BPF_LDX+BPF_MSH+BPF_B, ip_off);

  if(udp4_portc > 0)
    bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_UDP,
	     tcp4_portc > 0 ? 1 : 0,
	     tcp4_portc > 0 ? 0 : bpf_ret_false(len, off));

  if(tcp4_portc > 0)
    bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_TCP,
	     udp4_c, bpf_ret_false(len, off));

  if(udp4_portc > 0)
    bpf_portinsns_enc(insns, len, &off, udp4_ports, udp4_portc,
		      udp4_min, udp4_max, BPF_IND, ip_off);

  if(tcp4_portc > 0)
    bpf_portinsns_enc(insns, len, &off, tcp4_ports, tcp4_portc,
		      tcp4_min, tcp4_max, BPF_IND, ip_off);

  /* load the IPv6 protocol type into the accumulator */
  bpf_stmt(insns, len, &off, BPF_LD+BPF_ABS+BPF_B, ip_off+6);

  /* if it is ICMP, which is specific to IPv6, pass it */
  bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_ICMPV6,
	   bpf_ret_true(len, off), 0);

  if(udp6_portc > 0)
    bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_UDP,
	     4 + (tcp6_portc > 0 ? 1 : 0), 0);

  if(tcp6_portc > 0)
    bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_TCP,
	     4 + udp6_c, 0);

  /* just pass these packets through */
  bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_FRAGMENT,
	   bpf_ret_true(len, off), 0);
  bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_HOPOPTS,
	   bpf_ret_true(len, off), 0);
  bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_DSTOPTS,
	   bpf_ret_true(len, off), 0);
  bpf_jump(insns, len, &off, BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_ROUTING,
	   bpf_ret_true(len, off), bpf_ret_false(len, off));

  if(udp6_portc > 0)
    bpf_portinsns_enc(insns, len, &off, udp6_ports, udp6_portc,
		      udp6_min, udp6_max, BPF_ABS, ip_off + 40);

  if(tcp6_portc > 0)
    bpf_portinsns_enc(insns, len, &off, tcp6_ports, tcp6_portc,
		      tcp6_min, tcp6_max, BPF_ABS, ip_off + 40);

  /* branch targets to cause the packet to pass/fail the filter */
  bpf_stmt(insns, len, &off, BPF_RET+BPF_K, 0);
  bpf_stmt(insns, len, &off, BPF_RET+BPF_K, 65535);

#ifdef HAVE_BPF
  prog->bf_len = len;
  prog->bf_insns = insns;
#else
  prog->len = len;
  prog->filter = insns;
#endif

  return 0;
}
#endif /* HAVE_BPF_DYN_FILTER or TEST_DL_FILTER_COMPILE */
#endif /* BUILDING_SCAMPER or TEST_DL_FILTER_COMPILE */

#ifdef BUILDING_SCAMPER

/*
 * dlt_raw_cb
 *
 * handle raw IP frames.
 * i'm not sure how many of these interface types there are, but the linux
 * sit interface is an example of one that is...
 *
 */
static int dlt_raw_cb(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len)
{
  return dl_parse_ip(dl, pkt, len);
}

/*
 * dlt_null_cb
 *
 * handle the BSD loopback encapsulation.  the first 4 bytes say what protocol
 * family is used.  filter out anything that is not IPv4 / IPv6
 *
 */
#ifdef HAVE_BPF
static int dlt_null_cb(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len)
{
  uint32_t pf;

  /* ensure the packet holds at least 4 bytes for the psuedo header */
  if(len <= 4)
    return 0;

  memcpy(&pf, pkt, 4);
  if(pf == PF_INET || pf == PF_INET6)
    return dl_parse_ip(dl, pkt+4, len-4);

  return 0;
}
#endif

/*
 * dlt_en10mb_cb
 *
 * handle ethernet frames.
 *
 * an ethernet frame consists of
 *   - 6 bytes dst mac
 *   - 6 bytes src mac
 *   - 2 bytes type
 *
 */
static int dlt_en10mb_cb(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len)
{
  uint16_t u16;

  /* ensure the packet holds at least the length of the ethernet header */
  if(len <= 14)
    return 0;

  u16 = bytes_ntohs(pkt+12);
  if(u16 == ETHERTYPE_IP || u16 == ETHERTYPE_IPV6)
    return dl_parse_ip(dl, pkt+14, len-14);
  else if(u16 == ETHERTYPE_ARP)
    return dl_parse_arp(dl, pkt+14, len-14);

  return 0;
}

/*
 * dlt_firewire_cb
 *
 * handle IP frames on firewire devices.  a firewire layer-2 frame consists
 * of two 8 byte EUI64 addresses which represent the dst and the src
 * addresses, and a 2 byte ethertype
 */
#ifdef HAVE_FIREWIRE
static int dlt_firewire_cb(scamper_dl_rec_t *dl, uint8_t *pkt, size_t len)
{
  uint16_t type;

  /* ensure the packet holds at least the length of the firewire header */
  if(len <= 18)
    return 0;

  memcpy(&type, pkt+16, 2); type = ntohs(type);
  if(type == ETHERTYPE_IP || type == ETHERTYPE_IPV6)
    return dl_parse_ip(dl, pkt+18, len-18);

  return 0;
}
#endif

#if defined(HAVE_BPF)
static int dl_bpf_open_dev(char *dev, size_t len)
{
  int i=0, fd;

  do
    {
      snprintf(dev, len, "/dev/bpf%d", i);
      if((fd = open(dev, O_RDWR)) == -1)
	{
	  if(errno == EBUSY)
	    continue;
	  printerror(__func__, "could not open %s", dev);
	  return -1;
	}
      else break;
    }
  while(++i < 32768);

  return fd;
}

static int dl_bpf_open(int ifindex)
{
  struct ifreq ifreq;
  char dev[16];
  u_int blen;
  int fd = -1;

  /* work out the name corresponding to the ifindex */
  memset(&ifreq, 0, sizeof(ifreq));
  if(if_indextoname((unsigned int)ifindex, ifreq.ifr_name) == NULL)
    {
      printerror(__func__, "if_indextoname failed");
      goto err;
    }

  if((fd = dl_bpf_open_dev(dev, sizeof(dev))) == -1)
    {
      goto err;
    }

  /* get the suggested read buffer size */
  if(ioctl(fd, BIOCGBLEN, &blen) == -1)
    {
      printerror(__func__, "BIOCGBLEN %s", ifreq.ifr_name);
      goto err;
    }

  /*
   * try and get the system to use a larger buffer.  need to do this
   * before the call to BIOCSETIF.
   */
  if(blen < 65536)
    {
      blen = 65536;
      if(ioctl(fd, BIOCSBLEN, &blen) == -1)
	{
	  printerror(__func__, "BIOCSBLEN %s: %d", ifreq.ifr_name, blen);
	  goto err;
	}
    }

  /* set the interface that will be sniffed */
  if(ioctl(fd, BIOCSETIF, &ifreq) == -1)
    {
      printerror(__func__, "%s BIOCSETIF %s failed", dev, ifreq.ifr_name);
      goto err;
    }

  return fd;

 err:
  if(fd != -1) close(fd);
  return -1;
}

static int dl_bpf_node_init(const scamper_fd_t *fdn, scamper_dl_t *node)
{
  char ifname[IFNAMSIZ];
  u_int tmp;
  int fd;
  uint8_t *buf;

  /* get the file descriptor associated with the fd node */
  if((fd = scamper_fd_fd_get(fdn)) < 0)
    {
      goto err;
    }

  /* convert the interface index to a name */
  if(if_indextoname((unsigned int)node->ifindex, ifname) == NULL)
    {
      printerror(__func__,"if_indextoname %d failed", node->ifindex);
      goto err;
    }

  /* get the read buffer size */
  if(ioctl(fd, BIOCGBLEN, &node->readbuf_len) == -1)
    {
      printerror(__func__, "bpf BIOCGBLEN %s failed", ifname);
      goto err;
    }

  /* get the DLT type for the interface */
  if(ioctl(fd, BIOCGDLT, &tmp) == -1)
    {
      printerror(__func__, "bpf BIOCGDLT %s failed", ifname);
      goto err;
    }
  node->type = tmp;

  switch(node->type)
    {
    case DLT_NULL:
      node->dlt_cb = dlt_null_cb;
      if(osinfo->os_id == SCAMPER_OSINFO_OS_FREEBSD &&
	 osinfo->os_rel_dots > 0 && osinfo->os_rel[0] >= 6)
	{
	  node->tx_type = SCAMPER_DL_TX_NULL;
	}
      else
	{
	  node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
	}
      break;

    case DLT_EN10MB:
      node->dlt_cb = dlt_en10mb_cb;
      node->tx_type = SCAMPER_DL_TX_ETHERNET;
      break;

    case DLT_RAW:
      node->dlt_cb = dlt_raw_cb;
      node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
      break;

#if defined(DLT_APPLE_IP_OVER_IEEE1394)
    case DLT_APPLE_IP_OVER_IEEE1394:
      node->dlt_cb = dlt_firewire_cb;
      node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
      break;
#endif

    default:
      scamper_debug(__func__, "%s unhandled datalink %d", ifname, node->type);
      goto err;
    }

  scamper_debug(__func__, "bpf if %s index %d buflen %d datalink %d",
		ifname, node->ifindex, node->readbuf_len, node->type);

  tmp = 1;
  if(ioctl(fd, BIOCIMMEDIATE, &tmp) == -1)
    {
      printerror(__func__, "bpf BIOCIMMEDIATE failed");
      goto err;
    }

  if(readbuf_len < node->readbuf_len)
    {
      if((buf = realloc(readbuf, node->readbuf_len)) == NULL)
	{
	  printerror(__func__, "could not realloc");
	  return -1;
	}
      readbuf     = buf;
      readbuf_len = node->readbuf_len;
    }

  return 0;

 err:
  return -1;
}

static int dl_bpf_init(void)
{
  struct bpf_version bv;
  int  fd;
  char buf[16];
  int  err;
  int  rc = -1;

#ifdef HAVE_SETEUID
  uid_t uid, euid;
  if(scamper_seteuid_raise(&uid, &euid) != 0)
    return -1;
#endif

  if((fd = dl_bpf_open_dev(buf, sizeof(buf))) == -1)
    {
      if(errno == ENXIO)
	rc = 0;
      goto done;
    }

  err = ioctl(fd, BIOCVERSION, &bv);
  close(fd);
  if(err == -1)
    {
      printerror(__func__, "BIOCVERSION failed");
      goto done;
    }

#ifdef HAVE_SETEUID
  scamper_seteuid_lower(&uid, &euid);
#endif

  scamper_debug(__func__, "bpf version %d.%d", bv.bv_major, bv.bv_minor);
  if(bv.bv_major != BPF_MAJOR_VERSION || bv.bv_minor < BPF_MINOR_VERSION)
    {
      printerror_msg(__func__, "bpf ver %d.%d is incompatible with %d.%d",
		     bv.bv_major, bv.bv_minor,
		     BPF_MAJOR_VERSION, BPF_MINOR_VERSION);
      goto done;
    }

  osinfo = scamper_osinfo_get();
  if(osinfo->os_id == SCAMPER_OSINFO_OS_FREEBSD &&
     osinfo->os_rel_dots >= 2 && osinfo->os_rel[0] == 4 &&
     (osinfo->os_rel[1] == 3 || osinfo->os_rel[1] == 4))
    {
      printerror_msg(__func__,
		     "BPF file descriptors do not work with "
		     "select in FreeBSD 4.3 or 4.4");
      goto done;
    }

  rc = 0;

 done:
#ifdef HAVE_SETEUID
  scamper_seteuid_lower(&uid, &euid);
#endif
  return rc;
}

static int dl_bpf_read(int fd, scamper_dl_t *node)
{
  struct bpf_hdr    *bpf_hdr;
  scamper_dl_rec_t   dl;
  ssize_t            len;
  uint8_t           *buf = readbuf;

  while((len = read(fd, buf, node->readbuf_len)) == -1)
    {
      if(errno == EINTR) continue;
      if(errno == EWOULDBLOCK) return 0;
      printerror(__func__, "read %d bytes from fd %d failed",
		 node->readbuf_len, fd);
      return -1;
    }

  while(buf < readbuf + len)
    {
      bpf_hdr = (struct bpf_hdr *)buf;

      if(node->dlt_cb(&dl, buf + bpf_hdr->bh_hdrlen, bpf_hdr->bh_caplen))
	{
	  /* bpf always supplies a timestamp */
	  dl.dl_flags |= SCAMPER_DL_REC_FLAG_TIMESTAMP;
	  dl.dl_tv.tv_sec  = bpf_hdr->bh_tstamp.tv_sec;
	  dl.dl_tv.tv_usec = bpf_hdr->bh_tstamp.tv_usec;
	  dl.dl_ifindex = node->ifindex;

	  scamper_task_handledl(&dl);
	}

      buf += BPF_WORDALIGN(bpf_hdr->bh_caplen + bpf_hdr->bh_hdrlen);
    }

  return 0;
}

static int dl_bpf_tx(const scamper_dl_t *node, const uint8_t *pkt, size_t len)
{
  ssize_t wb;

  if((wb = write(scamper_fd_fd_get(node->fdn), pkt, len)) < (ssize_t)len)
    {
      if(wb == -1)
	printerror(__func__, "%d bytes failed", (int)len);
      else
	scamper_debug(__func__, "%d bytes sent of %d total", (int)wb,(int)len);
      return -1;
    }

  return 0;
}
#endif /* HAVE_BPF */

#ifdef __linux__
static int linux_read_sll(scamper_dl_rec_t *dl, struct sockaddr_ll *sll,
			  uint8_t *buf, size_t len)
{
  uint16_t proto;
  int rc = 0;

  /* don't see loopback packets twice */
  if(sll->sll_pkttype == PACKET_OUTGOING && sll->sll_ifindex == lo_ifindex)
    return 0;

  switch(sll->sll_hatype)
    {
    case ARPHRD_ETHER:
    case ARPHRD_LOOPBACK:
      proto = ntohs(sll->sll_protocol);
      if(proto == ETHERTYPE_IP || proto == ETHERTYPE_IPV6)
	rc = dl_parse_ip(dl, buf, len);
      else if(proto == ETHERTYPE_ARP)
	rc = dl_parse_arp(dl, buf, len);
      break;

#if defined(ARPHRD_SIT)
    case ARPHRD_SIT:
#endif
#if defined(ARPHRD_VOID)
    case ARPHRD_VOID:
#endif
    case ARPHRD_PPP:
      rc = dl_parse_ip(dl, buf, len);
      break;

#if defined(ARPHRD_IEEE1394)
    case ARPHRD_IEEE1394:
      proto = ntohs(sll->sll_protocol);
      if(proto == ETHERTYPE_IP || proto == ETHERTYPE_IPV6)
	rc = dl_parse_ip(dl, buf, len);
      break;
#endif
    }

  if(rc != 0)
    dl->dl_ifindex = sll->sll_ifindex;
  return rc;
}

#ifdef HAVE_STRUCT_TPACKET_REQ3
/*
 * ring_stats
 *
 * Dump some stats about packet loss. This is called every time we get
 * a frame in the ring with TP_STATUS_LOSING set, but it will only log
 * to stderr if packets have been dropped since the last call.
 */
static void ring_stats(scamper_dl_t *node)
{
  struct tpacket_stats stats;
  socklen_t statlen = sizeof(stats);
  struct ring *ring = node->ring;
  int fd = scamper_fd_fd_get(node->fdn);
  char buf[256];

  if(getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &statlen) != 0)
    {
      printerror(__func__, "failed to get socket stats");
      return;
    }
  ring->accepted_pkts += stats.tp_packets;
  ring->dropped_pkts += stats.tp_drops;

  snprintf(buf, sizeof(buf),
	   "fd=%d, pkts=%u, pkts_total=%u, drops=%u, drops_total=%u",
	   fd, stats.tp_packets, ring->accepted_pkts,
	   stats.tp_drops, ring->dropped_pkts);

  scamper_debug(__func__, "%s", buf);
  return;
}

static int ring_handle_frame(scamper_dl_t *node, struct tpacket3_hdr *frame)
{
  scamper_dl_rec_t dl;
  struct sockaddr_ll *sll;
  uint8_t *buf;
  ssize_t len;

  /* sanity check the packet length, and pick the smaller of len/snaplen */
  len = frame->tp_len;
  if(frame->tp_snaplen < len)
    len = frame->tp_snaplen;
  assert(len >= 0);

  /* grab a pointer to the start of the link layer headers */
  buf = (uint8_t *)frame + frame->tp_mac;

  if((frame->tp_status & TP_STATUS_LOSING) == TP_STATUS_LOSING)
    ring_stats(node);

  sll = (struct sockaddr_ll *)((uint8_t *)frame +
			       TPACKET_ALIGN(sizeof(struct tpacket3_hdr)));

  /* check if we want this packet, and populate the dl record */
  if(node->ifindex != 0)
    {
      if(sll->sll_pkttype == PACKET_OUTGOING && node->ifindex == lo_ifindex)
	return 0;
      if(node->dlt_cb(&dl, buf, len) == 0)
	return 0;
      dl.dl_ifindex = node->ifindex;
    }
  else
    {
      if(linux_read_sll(&dl, sll, buf, len) == 0)
	return 0;
    }

  /* populate dl timestamp info from the frame header */
  dl.dl_flags |= SCAMPER_DL_REC_FLAG_TIMESTAMP;
  dl.dl_tv.tv_sec = frame->tp_sec;
  dl.dl_tv.tv_usec = frame->tp_nsec / 1000;
  scamper_task_handledl(&dl);

  return 0;
}

static int ring_handle_block(scamper_dl_t *node, struct block_desc *block)
{
  uint32_t frames_cnt = block->h1.num_pkts;
  uint32_t off = block->h1.offset_to_first_pkt;
  uint32_t i;
  struct tpacket3_hdr *frame = (struct tpacket3_hdr *)((uint8_t *)block + off);

  for(i=0; i<frames_cnt; i++)
    {
      if(ring_handle_frame(node, frame) != 0)
	return -1;
      off = frame->tp_next_offset;
      frame = (struct tpacket3_hdr *)((uint8_t *)frame + off);
    }

  return 0;
}

static void ring_release_block(struct ring *ring, struct block_desc *block)
{
  block->h1.block_status = TP_STATUS_KERNEL;
  ring->cur_block = (ring->cur_block + 1) % ring->blocks_cnt;
  return;
}

static int ring_read(scamper_dl_t *node)
{
  struct ring *ring = node->ring;
  struct block_desc *block;
  int handled = 0;
  int rc;

  /* Process at most MAX_BLOCKS_PER_READ blocks before we yield control */
  block = ring->blocks[ring->cur_block].iov_base;
  while((block->h1.block_status & TP_STATUS_USER) == TP_STATUS_USER &&
	handled < MAX_BLOCKS_PER_READ)
    {
      rc = ring_handle_block(node, block);
      ring_release_block(ring, block);
      if(rc != 0)
	return -1;

      block = ring->blocks[ring->cur_block].iov_base;
      handled++;
    }

  return 0;
}

static void ring_free(struct ring *ring)
{
  if(ring->map != NULL && ring->map != MAP_FAILED)
    munmap(ring->map, ring->map_size);
  if(ring->blocks != NULL)
    free(ring->blocks);
  free(ring);
  return;
}

static int ring_init(scamper_dl_t *dl)
{
  struct ring *ring = NULL;
  unsigned int block_size = scamper_option_ring_block_size();
  unsigned int frame_size = TPACKET_ALIGNMENT << 6; /* 1KB frames enough? */
  unsigned int block_cnt = scamper_option_ring_blocks();
  unsigned int frame_cnt = (block_size / frame_size) * block_cnt;
  unsigned int i;
  int fd = scamper_fd_fd_get(dl->fdn);
  int flags;

  if((ring = malloc_zero(sizeof(struct ring))) == NULL)
    {
      printerror(__func__, "malloc failed");
      goto err;
    }

  ring->req.tp_block_size = block_size;
  ring->req.tp_block_nr = block_cnt;
  ring->req.tp_frame_size = frame_size;
  ring->req.tp_retire_blk_tov = 10; /* expire unfilled block after 10s */
  ring->req.tp_frame_nr = frame_cnt;
  ring->map_size = block_size * block_cnt;
  ring->blocks_cnt = block_cnt;
  ring->cur_block = 0;

  scamper_debug(__func__,
                "%s: initializing PACKET_RX_RING. "
                "block_size=%d, frame_size=%d, block_cnt=%d, "
                "frame_cnt=%d, alloc_size=%d, "
                "tp_block_size=%d, tp_block_nr=%d, "
                "tp_frame_size=%d, tp_frame_nr=%d",
                __func__, block_size, frame_size, block_cnt, frame_cnt,
                block_size * block_cnt,
                ring->req.tp_block_size, ring->req.tp_block_nr,
                ring->req.tp_frame_size, ring->req.tp_frame_nr);

  if(setsockopt_int(fd, SOL_PACKET, PACKET_VERSION, TPACKET_V3) != 0)
    {
      printerror(__func__, "PACKET_VERSION failed");
      goto err;
    }

  if(setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &ring->req, sizeof(ring->req)) != 0)
    {
      printerror(__func__, "PACKET_RX_RING failed");
      goto err;
    }

  /*
   * Allocate our ring. Even though the circular buffer is compound of
   * several physically discontiguous blocks of memory, they are
   * contiguous to the user space, hence just one call to mmap is
   * needed.
   */
  flags = MAP_SHARED | MAP_POPULATE;
  if(scamper_option_ring_locked())
    flags |= MAP_LOCKED;

  ring->map = mmap(NULL, ring->map_size, PROT_READ | PROT_WRITE, flags, fd, 0);
  if(ring->map == MAP_FAILED)
    {
      printerror(__func__, "ring mmap failed");
      goto err;
    }

  /* Allocate the iovecs that we'll use to find the blocks in the ring */
  if((ring->blocks = malloc_zero(block_cnt * sizeof(struct iovec))) == NULL)
    {
      printerror(__func__, "failed to allocate ring iovecs");
      goto err;
    }

  /*
   * Set up each element of the vector to point to a frame. This way
   * we can just iterate over the iovec to iterate over the frames.
   */
  for(i=0; i<block_cnt; i++)
    {
      ring->blocks[i].iov_base = ring->map + (i * block_size);
      ring->blocks[i].iov_len = block_size;
    }

  dl->ring = ring;
  return 0;

 err:
  if(ring != NULL) ring_free(ring);
  return -1;
}
#endif /* HAVE_STRUCT_TPACKET_REQ3 */

static int dl_linux_open(int ifindex)
{
  struct sockaddr_ll sll;
  int fd;

  /* open the socket in non cooked mode if not the "any" interface */
  if((fd = socket(PF_PACKET,
		  ifindex != 0 ? SOCK_RAW : SOCK_DGRAM,
		  htons(ETH_P_ALL))) == -1)
    {
      printerror(__func__, "could not open PF_PACKET");
      return -1;
    }

  /* scamper only wants packets on this interface */
  memset(&sll, 0, sizeof(sll));
  sll.sll_family   = AF_PACKET;
  sll.sll_ifindex  = ifindex;
  sll.sll_protocol = htons(ETH_P_ALL);
  if(bind(fd, (struct sockaddr *)&sll, sizeof(sll)) == -1)
    {
      printerror(__func__, "could not bind to %d", ifindex);
      close(fd);
      return -1;
    }

  return fd;
}

static int dl_linux_node_init(const scamper_fd_t *fdn, scamper_dl_t *node)
{
  struct ifreq ifreq;
  char ifname[IFNAMSIZ];
  int fd;
  int using_ring = 0;

  if((fd = scamper_fd_fd_get(fdn)) < 0)
    {
      goto err;
    }

  if(node->ifindex == 0)
    {
      node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
      node->type = -1;
      node->dlt_cb = NULL;
      goto finish;
    }

  if(if_indextoname(node->ifindex, ifname) == NULL)
    {
      printerror(__func__, "if_indextoname %d failed", node->ifindex);
      goto err;
    }

  /* find out what type of datalink the interface has */
  memcpy(ifreq.ifr_name, ifname, sizeof(ifreq.ifr_name));
  if(ioctl(fd, SIOCGIFHWADDR, &ifreq) == -1)
    {
      printerror(__func__, "%s SIOCGIFHWADDR failed", ifname);
      goto err;
    }

  node->type = ifreq.ifr_hwaddr.sa_family;

  /* scamper can only deal with ethernet datalinks at this time */
  switch(node->type)
    {
    case ARPHRD_ETHER:
      node->dlt_cb = dlt_en10mb_cb;
      node->tx_type = SCAMPER_DL_TX_ETHERNET;
      break;

    case ARPHRD_LOOPBACK:
      node->dlt_cb = dlt_en10mb_cb;
      node->tx_type = SCAMPER_DL_TX_ETHLOOP;
      break;

#if defined(ARPHRD_SIT)
    case ARPHRD_SIT:
#endif
    case ARPHRD_PPP:
      node->dlt_cb = dlt_raw_cb;
      node->tx_type = SCAMPER_DL_TX_RAW;
      break;

#if defined(ARPHRD_IEEE1394)
    case ARPHRD_IEEE1394:
      node->dlt_cb = dlt_firewire_cb;
      node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
      break;
#endif

#if defined(ARPHRD_VOID)
    case ARPHRD_VOID:
      node->dlt_cb = dlt_raw_cb;
      node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
      break;
#endif

    default:
      scamper_debug(__func__, "%s unhandled datalink %d", ifname, node->type);
      goto err;
    }

 finish:

#ifdef HAVE_STRUCT_TPACKET_REQ3
  if(scamper_option_ring())
    {
      if(ring_init(node) != 0)
	{
	  printerror(__func__, "failed to initialize ring");
	  goto err;
	}
      using_ring = 1;
    }
#endif
  if(using_ring == 0 && setsockopt_int(fd, SOL_SOCKET, SO_TIMESTAMP, 1) != 0)
    {
      printerror(__func__, "could not set SO_TIMESTAMP");
      goto err;
    }

  return 0;

 err:
  return -1;
}

static int linux_read(int fd, scamper_dl_t *node)
{
  scamper_dl_rec_t   dl;
  ssize_t            len;
  struct sockaddr_ll sll;
  size_t             s;
  uint8_t            ctrlbuf[256];
  struct msghdr      msg;
  struct cmsghdr    *cmsg;
  struct iovec       iov;

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (caddr_t)readbuf;
  iov.iov_len  = readbuf_len;

  msg.msg_name       = (caddr_t)&sll;
  msg.msg_namelen    = sizeof(sll);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (caddr_t)ctrlbuf;
  msg.msg_controllen = sizeof(ctrlbuf);

  if((len = recvmsg(fd, &msg, 0)) <= 0)
    return 0;

  /* sanity check the packet length */
  if((size_t)len > readbuf_len)
    s = readbuf_len;
  else
    s = (size_t)len;

  if(node->ifindex != 0)
    {
      if(sll.sll_pkttype == PACKET_OUTGOING && node->ifindex == lo_ifindex)
	return 0;
      if(node->dlt_cb(&dl, readbuf, s) == 0)
	return 0;
      dl.dl_ifindex = node->ifindex;
    }
  else
    {
      if(linux_read_sll(&dl, &sll, readbuf, s) == 0)
	return 0;
    }

  /*
   * if the packet passes the filter, we need to get the time it was rx'd.
   * scamper treats the failure of this ioctl as non-fatal
   */
  if(msg.msg_controllen >= sizeof(struct cmsghdr))
    {
      cmsg = (struct cmsghdr *)CMSG_FIRSTHDR(&msg);
      while(cmsg != NULL)
	{
	  if(cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMP)
	    {
	      dl.dl_flags |= SCAMPER_DL_REC_FLAG_TIMESTAMP;
	      timeval_cpy(&dl.dl_tv, (struct timeval *)CMSG_DATA(cmsg));
	      break;
	    }
	  cmsg = (struct cmsghdr *)CMSG_NXTHDR(&msg, cmsg);
	}
    }

  scamper_task_handledl(&dl);
  return 0;
}

static int dl_linux_read(int fd, scamper_dl_t *node)
{
#ifdef HAVE_STRUCT_TPACKET_REQ3
  if(scamper_option_ring())
    return ring_read(node);
#endif
  return linux_read(fd, node);
}

static int dl_linux_tx(const scamper_dl_t *node,const uint8_t *pkt,size_t len)
{
  struct sockaddr_ll sll;
  struct sockaddr *sa = (struct sockaddr *)&sll;
  ssize_t wb;
  int fd;
  uint8_t ipv;

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = node->ifindex;

  switch(node->tx_type)
    {
    case SCAMPER_DL_TX_ETHERNET:
    case SCAMPER_DL_TX_ETHLOOP:
      sll.sll_protocol = htons(ETH_P_ALL);
      break;

    case SCAMPER_DL_TX_RAW:
      ipv = pkt[0] >> 4;
      if(ipv == 4)
	sll.sll_protocol = htons(ETH_P_IP);
      else if(ipv == 6)
	sll.sll_protocol = htons(ETH_P_IPV6);
      else
	return 0;
      break;

    default:
      return 0;
    }

  fd = scamper_fd_fd_get(node->fdn);

  if((wb = sendto(fd, pkt, len, 0, sa, sizeof(sll))) < (ssize_t)len)
    {
      if(wb == -1)
	printerror(__func__, "%d bytes failed", (int)len);
      else
	scamper_debug(__func__, "%d bytes sent of %d total", (int)wb, (int)len);
      return -1;
    }

  return 0;
}

static int dl_linux_init(void)
{
  struct ifreq ifr;
  int fd;

#ifdef HAVE_SETEUID
  uid_t uid, euid;
#endif

  readbuf_len = 8192;
  if((readbuf = malloc_zero(readbuf_len)) == NULL)
    {
      printerror(__func__, "could not malloc readbuf");
      readbuf_len = 0;
      return -1;
    }

#ifdef HAVE_SETEUID
  if(scamper_seteuid_raise(&uid, &euid) != 0)
    return -1;
#endif
  fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
#ifdef HAVE_SETEUID
  scamper_seteuid_lower(&uid, &euid);
#endif

  /* get the loopback ifindex so we can filter duplicate replies */
  if(fd != -1)
    {
      memset(&ifr, 0, sizeof(ifr));
      ifr.ifr_name[0] = 'l'; ifr.ifr_name[1] = 'o'; /* lo */
      if(ioctl(fd, SIOCGIFINDEX, &ifr) != -1)
	lo_ifindex = ifr.ifr_ifindex;
      close(fd);
    }

  return 0;
}
#endif /* __linux__ */

#ifdef HAVE_DLPI
static int dl_dlpi_open(int ifindex)
{
  char ifname[5+IFNAMSIZ];
  int fd;

  strncpy(ifname, "/dev/", sizeof(ifname));
  if(if_indextoname(ifindex, ifname+5) == NULL)
    {
      printerror(__func__, "if_indextoname %d failed", ifindex);
      return -1;
    }

  if((fd = open(ifname, O_RDWR)) == -1)
    {
      printerror(__func__, "could not open %s", ifname);
      return -1;
    }

  return fd;
}

static int dl_dlpi_req(int fd, void *req, size_t len)
{
  union	DL_primitives *dlp;
  struct strbuf ctl;

  ctl.maxlen = 0;
  ctl.len = len;
  ctl.buf = (char *)req;

  if(putmsg(fd, &ctl, NULL, 0) == -1)
    {
      dlp = req;
      printerror(__func__, "could not putmsg %d", dlp->dl_primitive);
      return -1;
    }

  return 0;
}

static int dl_dlpi_ack(int fd, void *ack, int primitive)
{
  union	DL_primitives *dlp;
  struct strbuf ctl;
  int flags;

  flags = 0;
  ctl.maxlen = MAXDLBUF;
  ctl.len = 0;
  ctl.buf = (char *)ack;
  if(getmsg(fd, &ctl, NULL, &flags) == -1)
    {
      printerror(__func__, "could not getmsg %d", primitive);
      return -1;
    }

  dlp = ack;
  if(dlp->dl_primitive != primitive)
    {
      scamper_debug(__func__,
		    "expected %d, got %d", primitive, dlp->dl_primitive);
      return -1;
    }

  return 0;
}

static int dl_dlpi_promisc(int fd, int level)
{
  dl_promiscon_req_t promiscon_req;
  uint32_t buf[MAXDLBUF];

  promiscon_req.dl_primitive = DL_PROMISCON_REQ;
  promiscon_req.dl_level = level;
  if(dl_dlpi_req(fd, &promiscon_req, sizeof(promiscon_req)) == -1)
    {
      return -1;
    }

  /* check for an ack to the promisc req */
  if(dl_dlpi_ack(fd, buf, DL_OK_ACK) == -1)
    {
      return -1;
    }

  return 0;
}

static int strioctl(int fd, int cmd, void *dp, int len)
{
  struct strioctl str;

  str.ic_cmd = cmd;
  str.ic_timout = -1;
  str.ic_len = len;
  str.ic_dp = (char *)dp;
  if(ioctl(fd, I_STR, &str) == -1)
    {
      return -1;
    }

  return str.ic_len;
}

static int dl_dlpi_node_init(const scamper_fd_t *fdn, scamper_dl_t *node)
{
  uint32_t         buf[MAXDLBUF];
  struct timeval   tv;
  dl_info_req_t    info_req;
  dl_info_ack_t   *info_ack;
  dl_attach_req_t  attach_req;
  dl_bind_req_t    bind_req;
  int              i, fd;

#ifndef NDEBUG
  char             ifname[IFNAMSIZ];
#endif

  if((fd = scamper_fd_fd_get(fdn)) < 0)
    {
      return -1;
    }

  /*
   * send an information request to the datalink to determine what type
   * of packets they supply
   */
  info_req.dl_primitive = DL_INFO_REQ;
  if(dl_dlpi_req(fd, &info_req, sizeof(info_req)) == -1)
    {
      return -1;
    }

  /*
   * read the information acknowledgement, which contains details on the
   * type of the interface, etc.
   */
  if(dl_dlpi_ack(fd, buf, DL_INFO_ACK) == -1)
    {
      return -1;
    }
  info_ack = (dl_info_ack_t *)buf;

  /* record the mac type with the node */
  node->type = info_ack->dl_mac_type;

  /* determine how to handle the datalink */
  switch(node->type)
    {
    case DL_CSMACD:
    case DL_ETHER:
      node->dlt_cb = dlt_en10mb_cb;
      node->tx_type = SCAMPER_DL_TX_ETHERNET;
      break;

    default:
      node->tx_type = SCAMPER_DL_TX_UNSUPPORTED;
      scamper_debug(__func__, "unhandled datalink %d", node->type);
      return -1;
    }

  /* attach to the interface */
  if(info_ack->dl_provider_style == DL_STYLE2)
    {
      attach_req.dl_primitive = DL_ATTACH_REQ;
      attach_req.dl_ppa = 0;
      if(dl_dlpi_req(fd, &attach_req, sizeof(attach_req)) == -1)
	{
	  return -1;
	}

      /* check for a generic ack */
      if(dl_dlpi_ack(fd, buf, DL_OK_ACK) == -1)
	{
	  return -1;
	}
    }

  /* bind the interface */
  memset(&bind_req, 0, sizeof(bind_req));
  bind_req.dl_primitive = DL_BIND_REQ;
  bind_req.dl_service_mode = DL_CLDLS;
  if(dl_dlpi_req(fd, &bind_req, sizeof(bind_req)) == -1)
    {
      return -1;
    }

  /* check for an ack to the bind */
  if(dl_dlpi_ack(fd, buf, DL_BIND_ACK) == -1)
    {
      return -1;
    }

  /*
   * turn on phys and sap promisc modes.  dlpi will not supply outbound
   * probe packets unless in phys promisc mode.
   */
  if(dl_dlpi_promisc(fd, DL_PROMISC_PHYS) == -1 ||
     dl_dlpi_promisc(fd, DL_PROMISC_SAP) == -1)
    {
      return -1;
    }

  /* get full link layer */
  if(strioctl(fd, DLIOCRAW, NULL, 0) == -1)
    {
      printerror(__func__, "could not DLIOCRAW");
      return -1;
    }

  /* push bufmod */
  if(ioctl(fd, I_PUSH, "bufmod") == -1)
    {
      printerror(__func__, "could not push bufmod");
      return -1;
    }

  /* we need the first 1500 bytes of the packet */
  i = 1500;
  if(strioctl(fd, SBIOCSSNAP, &i, sizeof(i)) == -1)
    {
      printerror(__func__, "could not SBIOCSSNAP %d", i);
      return -1;
    }

  /* send the data every 50ms */
  tv.tv_sec = 0;
  tv.tv_usec = 50000;
  if(strioctl(fd, SBIOCSTIME, &tv, sizeof(tv)) == -1)
    {
      printerror(__func__, "could not SBIOCSTIME %d.%06d",
		 tv.tv_sec, tv.tv_usec);
      return -1;
    }

  /* set the chunk length */
  i = 65535;
  if(strioctl(fd, SBIOCSCHUNK, &i, sizeof(i)) == -1)
    {
      printerror(__func__, "could not SBIOCSCHUNK %d", i);
      return -1;
    }

  if(ioctl(fd, I_FLUSH, FLUSHR) == -1)
    {
      printerror(__func__, "could not flushr");
      return -1;
    }

#ifndef NDEBUG
  if(if_indextoname(node->ifindex, ifname) == NULL)
    {
      strncpy(ifname, "<null>", sizeof(ifname)-1);
      ifname[sizeof(ifname)-1] = '\0';
    }
  scamper_debug(__func__, "dlpi if %s index %d datalink %d",
		ifname, node->ifindex, node->type);
#endif

  return 0;
}

static int dl_dlpi_read(int fd, scamper_dl_t *node)
{
  scamper_dl_rec_t  dl;
  struct strbuf     data;
  struct sb_hdr    *sbh;
  uint8_t          *buf = readbuf;
  int               flags;

  flags = 0;
  data.buf = (void *)readbuf;
  data.maxlen = readbuf_len;
  data.len = 0;

  if(getmsg(fd, NULL, &data, &flags) == -1)
    {
      printerror(__func__, "could not getmsg");
      return -1;
    }

  while(buf < readbuf + data.len)
    {
      sbh = (struct sb_hdr *)buf;
      if(node->dlt_cb(&dl, buf + sizeof(struct sb_hdr), sbh->sbh_msglen))
	{
	  dl.dl_flags = SCAMPER_DL_REC_FLAG_TIMESTAMP;
	  dl.dl_tv.tv_sec  = sbh->sbh_timestamp.tv_sec;
	  dl.dl_tv.tv_usec = sbh->sbh_timestamp.tv_usec;
	  dl.dl_ifindex    = node->ifindex;
	  scamper_task_handledl(&dl);
	}
      buf += sbh->sbh_totlen;
    }

  return -1;
}

static int dl_dlpi_tx(const scamper_dl_t *node, const uint8_t *pkt, size_t len)
{
  struct strbuf data;
  int fd;

  if((fd = scamper_fd_fd_get(node->fdn)) < 0)
    return -1;

  memset(&data, 0, sizeof(data));
  data.buf = (void *)pkt;
  data.len = len;

  if(putmsg(fd, NULL, &data, 0) != 0)
    {
      printerror(__func__, "could not putmsg");
      return -1;
    }

  return 0;
}

static int dl_dlpi_init(void)
{
  readbuf_len = 65536; /* magic obtained from pcap-dlpi.c */
  if((readbuf = malloc_zero(readbuf_len)) == NULL)
    {
      printerror(__func__, "could not malloc readbuf");
      readbuf_len = 0;
      return -1;
    }
  return 0;
}

#endif /* HAVE_DLPI */

#ifdef HAVE_BPF_DYN_FILTER
static uint8_t dl_rx_type(const scamper_dl_t *node)
{
  if(node->dlt_cb == dlt_en10mb_cb)
    return SCAMPER_DL_RX_ETHERNET;
#ifdef __linux__
  if(node->ifindex == 0)
    return SCAMPER_DL_RX_COOKED;
#endif
#ifdef HAVE_BPF
  if(node->dlt_cb == dlt_null_cb)
    return SCAMPER_DL_RX_NULL;
#endif
  if(node->dlt_cb == dlt_raw_cb)
    return SCAMPER_DL_RX_RAW;
  return SCAMPER_DL_RX_UNSUPPORTED;
}
#endif /* HAVE_BPF_DYN_FILTER */

#ifdef HAVE_BPF_FILTER
int scamper_dl_filter(const scamper_dl_t *node,
		      const uint16_t *ports, size_t portc)
{
  filt_prog_t prog;
  filt_insn_t open[1];
  int rc, fd;
  size_t off = 0;

#ifdef HAVE_BPF_DYN_FILTER
  int dyn = scamper_option_dynfilter();
  uint8_t rx_type = dl_rx_type(node);
#endif

  memset(&prog, 0, sizeof(prog));
  bpf_stmt(open, 1, &off, BPF_RET+BPF_K, 65535);

  /* fallback to an open filter */
  if(ports == NULL
#ifdef HAVE_BPF_DYN_FILTER
     || dyn == 0 || dl_filter_compile(rx_type, &prog, ports, portc) != 0
#endif
     )
    {
#ifdef HAVE_BPF
      prog.bf_insns = open;
      prog.bf_len = 1;
#else
      prog.filter = open;
      prog.len = 1;
#endif
    }

  fd = scamper_fd_fd_get(node->fdn);

#ifdef HAVE_BPF
#ifndef BIOCSETFNR
  if((rc = ioctl(fd, BIOCSETF, (caddr_t)&prog)) != -1)
    rc = 0;
  else
    printerror(__func__, "BIOCSETF failed");
#else
  if((rc = ioctl(fd, dyn == 0 ? BIOCSETF : BIOCSETFNR, (caddr_t)&prog)) != -1)
    {
      rc = 0;
      scamper_debug(__func__, "filter %d successful", prog.bf_len);
    }
  else
    {
      if(dyn == 0)
	printerror(__func__, "BIOCSETF failed");
      else
	printerror(__func__, "BIOCSETFNR attempt 1 failed");
    }
  if(prog.bf_len > 1)
    {
      free(prog.bf_insns);
      if(rc == -1)
	{
	  prog.bf_insns = open;
	  prog.bf_len = 1;
	  if((rc = ioctl(fd, BIOCSETFNR, (caddr_t)&prog)) != -1)
	    {
	      rc = 0;
	      scamper_debug(__func__, "installed open filter");
	    }
	  else printerror(__func__, "BIOCSETFNR attempt 2 failed");
	}
    }
#endif /* BIOCSETFNR */
#else
  if((rc = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
		      (caddr_t)&prog, sizeof(prog))) != -1)
    {
      rc = 0;
      scamper_debug(__func__, "filter %d successful", prog.len);
    }
  else printerror(__func__, "SO_ATTACH_FILTER attempt 1 failed");

  if(prog.len > 1)
    {
      free(prog.filter);
      if(rc == -1)
	{
	  prog.filter = open;
	  prog.len = 1;
	  if((rc = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
			      (caddr_t)&prog, sizeof(prog))) != -1)
	    {
	      rc = 0;
	      scamper_debug(__func__, "installed open filter");
	    }
	  else printerror(__func__, "SO_ATTACH_FILTER attempt 2 failed");
	}
    }
#endif

  return rc;
}

static int dl_filter_init(const scamper_dl_t *node)
{
#ifdef HAVE_BPF_DYN_FILTER
  uint16_t *ports = NULL;
  size_t portc = 0;
  int rc;
  if(scamper_option_dynfilter() == 0 ||
     scamper_fds_sports(&ports, &portc) != 0)
    goto done;
  rc = scamper_dl_filter(node, ports, portc);
  if(ports != NULL)
    free(ports);
  return rc;
 done:
  /* ports will be null, nothing to free */
#endif
  return scamper_dl_filter(node, NULL, 0);
}

#endif /* HAVE_BPF_FILTER */

int scamper_dl_rec_src(scamper_dl_rec_t *dl, scamper_addr_t *addr)
{
  if(dl->dl_af == AF_INET)
    addr->type = SCAMPER_ADDR_TYPE_IPV4;
  else if(dl->dl_af == AF_INET6)
    addr->type = SCAMPER_ADDR_TYPE_IPV6;
  else
    return -1;

  addr->addr = dl->dl_ip_src;
  return 0;
}

int scamper_dl_rec_icmp_ip_dst(scamper_dl_rec_t *dl, scamper_addr_t *addr)
{
  if(dl->dl_af == AF_INET)
    addr->type = SCAMPER_ADDR_TYPE_IPV4;
  else if(dl->dl_af == AF_INET6)
    addr->type = SCAMPER_ADDR_TYPE_IPV6;
  else
    return -1;

  addr->addr = dl->dl_icmp_ip_dst;
  return 0;
}

#ifdef HAVE_SCAMPER_DEBUG
void scamper_dl_rec_frag_print(const scamper_dl_rec_t *dl)
{
  char addr[64];
  uint32_t id;

  assert(dl->dl_af == AF_INET || dl->dl_af == AF_INET6);

  if(scamper_debug_would() == 0)
    return;

  if(dl->dl_af == AF_INET)
    id = dl->dl_ip_id;
  else
    id = dl->dl_ip6_id;

  scamper_debug(NULL, "from %s len %d ipid %u off %u",
		addr_tostr(dl->dl_af, dl->dl_ip_src, addr, sizeof(addr)),
		dl->dl_ip_size, id, dl->dl_ip_off);

  return;
}

void scamper_dl_rec_udp_print(const scamper_dl_rec_t *dl)
{
  char addr[64], ipid[16];

  assert(dl->dl_af == AF_INET || dl->dl_af == AF_INET6);
  assert(dl->dl_ip_proto == IPPROTO_UDP);

  if(scamper_debug_would() == 0)
    return;

  if(dl->dl_af == AF_INET)
    snprintf(ipid, sizeof(ipid), "ipid 0x%04x ", dl->dl_ip_id);
  else
    ipid[0] = '\0';

  scamper_debug(NULL, "from %s %sudp %d:%d len %d",
		addr_tostr(dl->dl_af, dl->dl_ip_src, addr, sizeof(addr)),
		ipid, dl->dl_tcp_sport, dl->dl_tcp_dport, dl->dl_ip_size);
  return;
}

void scamper_dl_rec_tcp_print(const scamper_dl_rec_t *dl)
{
  static const char *tcpflags[] = {
    "fin",
    "syn",
    "rst",
    "psh",
    "ack",
    "urg",
    "ece",
    "cwr"
  };
  uint8_t u8;
  size_t off;
  char addr[64];
  char fbuf[32], *flags;
  char pos[32];
  char ipid[16];
  int i;

  assert(dl->dl_af == AF_INET || dl->dl_af == AF_INET6);
  assert(dl->dl_ip_proto == IPPROTO_TCP);

  if(scamper_debug_would() == 0)
    return;

  if((u8 = dl->dl_tcp_flags) != 0)
    {
      flags = fbuf;
      for(i=0; i<8; i++)
	{
	  if((dl->dl_tcp_flags & (1<<i)) != 0)
	    {
	      memcpy(flags, tcpflags[i], 3); flags += 3;
	      u8 &= ~(1<<i);
	      if(u8 != 0)
		{
		  *flags = '-';
		  flags++;
		}
	      else break;
	    }
	}
      *flags = '\0';
      flags = fbuf;
    }
  else
    {
      flags = "nil";
    }

  off = 0;
  string_concaf(pos, sizeof(pos), &off, "%u", dl->dl_tcp_seq);
  if(dl->dl_tcp_flags & TH_ACK)
    string_concaf(pos, sizeof(pos), &off, ":%u", dl->dl_tcp_ack);

  if(dl->dl_af == AF_INET)
    snprintf(ipid, sizeof(ipid), "ipid 0x%04x ", dl->dl_ip_id);
  else
    ipid[0] = '\0';

  scamper_debug(NULL, "from %s %stcp %d:%d %s %s len %d",
		addr_tostr(dl->dl_af, dl->dl_ip_src, addr, sizeof(addr)),
		ipid, dl->dl_tcp_sport, dl->dl_tcp_dport, flags, pos,
		dl->dl_ip_size);

  return;
}

void scamper_dl_rec_icmp_print(const scamper_dl_rec_t *dl)
{
  char *t = NULL, tbuf[64];
  char *c = NULL, cbuf[64];
  char addr[64];
  char ip[256];
  char icmp[256];
  char inner_ip[256];
  char inner_transport[256];
  size_t off;

  assert(dl->dl_af == AF_INET || dl->dl_af == AF_INET6);

  if(scamper_debug_would() == 0)
    return;

  if(dl->dl_af == AF_INET)
    {
      addr_tostr(AF_INET, dl->dl_ip_src, addr, sizeof(addr));
      snprintf(ip, sizeof(ip), "from %s size %d ttl %d tos 0x%02x ipid 0x%04x",
	       addr, dl->dl_ip_size, dl->dl_ip_ttl, dl->dl_ip_tos,
	       dl->dl_ip_id);

      switch(dl->dl_icmp_type)
        {
        case ICMP_UNREACH:
          t = "unreach";
          switch(dl->dl_icmp_code)
            {
            case ICMP_UNREACH_NET:           c = "net";           break;
            case ICMP_UNREACH_HOST:          c = "host";          break;
            case ICMP_UNREACH_PROTOCOL:      c = "protocol";      break;
            case ICMP_UNREACH_PORT:          c = "port";          break;
            case ICMP_UNREACH_SRCFAIL:       c = "src-rt failed"; break;
            case ICMP_UNREACH_NET_UNKNOWN:   c = "net unknown";   break;
            case ICMP_UNREACH_HOST_UNKNOWN:  c = "host unknown";  break;
            case ICMP_UNREACH_ISOLATED:      c = "isolated";      break;
            case ICMP_UNREACH_NET_PROHIB:    c = "net prohib";    break;
            case ICMP_UNREACH_HOST_PROHIB:   c = "host prohib";   break;
            case ICMP_UNREACH_TOSNET:        c = "tos net";       break;
            case ICMP_UNREACH_TOSHOST:       c = "tos host";      break;
            case ICMP_UNREACH_FILTER_PROHIB: c = "admin prohib";  break;
            case ICMP_UNREACH_NEEDFRAG:
	      /*
	       * use the type buf to be consistent with the ICMP6
	       * fragmentation required message
	       */
	      snprintf(tbuf, sizeof(tbuf), "need frag %d", dl->dl_icmp_nhmtu);
	      t = tbuf;
	      break;

            default:
	      snprintf(cbuf, sizeof(cbuf), "code %d", dl->dl_icmp_code);
	      c = cbuf;
	      break;
            }
          break;

        case ICMP_TIMXCEED:
          t = "time exceeded";
          switch(dl->dl_icmp_code)
            {
            case ICMP_TIMXCEED_INTRANS: c = "in trans"; break;
            case ICMP_TIMXCEED_REASS:   c = "in reass"; break;
            default:
	      snprintf(cbuf, sizeof(cbuf), "code %d", dl->dl_icmp_code);
	      c = cbuf;
	      break;
            }
          break;

	case ICMP_ECHOREPLY:
	  t = "echo reply";
	  snprintf(cbuf, sizeof(cbuf), "id %d seq %d",
		   dl->dl_icmp_id, dl->dl_icmp_seq);
	  c = cbuf;
	  break;

	case ICMP_TSTAMPREPLY:
	  t = "time reply";
	  snprintf(cbuf, sizeof(cbuf), "id %d seq %d",
		   dl->dl_icmp_id, dl->dl_icmp_seq);
	  c = cbuf;
	  break;
        }
    }
  else
    {
      addr_tostr(AF_INET6, dl->dl_ip_src, addr, sizeof(addr));
      off = 0;
      string_concaf(ip, sizeof(ip), &off, "from %s size %d hlim %d", addr,
		    dl->dl_ip_size, dl->dl_ip_hlim);
      if(dl->dl_ip_flags & SCAMPER_DL_IP_FLAG_FRAG)
	string_concaf(ip, sizeof(ip), &off, " ipid 0x%08x", dl->dl_ip6_id);

      switch(dl->dl_icmp_type)
        {
        case ICMP6_DST_UNREACH:
          t = "unreach";
          switch(dl->dl_icmp_code)
            {
            case ICMP6_DST_UNREACH_NOROUTE:     c = "no route";     break;
            case ICMP6_DST_UNREACH_ADMIN:       c = "admin prohib"; break;
            case ICMP6_DST_UNREACH_BEYONDSCOPE: c = "beyond scope"; break;
            case ICMP6_DST_UNREACH_ADDR:        c = "addr";         break;
            case ICMP6_DST_UNREACH_NOPORT:      c = "port";         break;

            default:
	      snprintf(cbuf, sizeof(cbuf), "code %d", dl->dl_icmp_code);
	      c = cbuf;
	      break;
            }
          break;

        case ICMP6_TIME_EXCEEDED:
          t = "time exceeded";
          switch(dl->dl_icmp_code)
            {
            case ICMP6_TIME_EXCEED_TRANSIT:    c = "in trans"; break;
            case ICMP6_TIME_EXCEED_REASSEMBLY: c = "in reass"; break;

            default:
	      snprintf(cbuf, sizeof(cbuf), "code %d", dl->dl_icmp_code);
	      c = cbuf;
	      break;
            }
          break;

	case ICMP6_PACKET_TOO_BIG:
	  snprintf(tbuf, sizeof(tbuf), "need frag %d", dl->dl_icmp_nhmtu);
	  t = tbuf;
	  break;

	case ICMP6_ECHO_REPLY:
	  t = "echo reply";
	  snprintf(cbuf, sizeof(cbuf), "id %d seq %d",
		   dl->dl_icmp_id, dl->dl_icmp_seq);
	  c = cbuf;
	  break;
        }
    }

  if(t == NULL)
    {
      snprintf(icmp, sizeof(icmp), "icmp %d code %d",
	       dl->dl_icmp_type, dl->dl_icmp_code);
    }
  else if(c == NULL)
    {
      snprintf(icmp, sizeof(icmp), "icmp %s", t);
    }
  else
    {
      snprintf(icmp, sizeof(icmp), "icmp %s %s", t, c);
    }

  if(dl->dl_icmp_ip_dst != NULL)
    {
      if(dl->dl_af == AF_INET)
	{
	  addr_tostr(AF_INET, dl->dl_icmp_ip_dst, addr, sizeof(addr));
	  snprintf(inner_ip, sizeof(inner_ip),
		   " to %s size %d ttl %d tos 0x%02x ipid 0x%04x",
		   addr, dl->dl_icmp_ip_size, dl->dl_icmp_ip_ttl,
		   dl->dl_icmp_ip_tos, dl->dl_icmp_ip_id);
	}
      else
	{
	  addr_tostr(AF_INET6, dl->dl_icmp_ip_dst, addr, sizeof(addr));
	  snprintf(inner_ip, sizeof(inner_ip),
		   " to %s size %d hlim %d flow 0x%05x", addr,
		   dl->dl_icmp_ip_size, dl->dl_icmp_ip_hlim,
		   dl->dl_icmp_ip_flow);
	}

      switch(dl->dl_icmp_ip_proto)
	{
	case IPPROTO_UDP:
	  snprintf(inner_transport, sizeof(inner_transport),
		   " proto UDP sport %d dport %d sum 0x%04x",
		   dl->dl_icmp_udp_sport, dl->dl_icmp_udp_dport,
		   ntohs(dl->dl_icmp_udp_sum));
	  break;

	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
	  snprintf(inner_transport, sizeof(inner_transport),
		   " proto ICMP type %d code %d id %04x seq %d",
		   dl->dl_icmp_icmp_type, dl->dl_icmp_icmp_code,
		   dl->dl_icmp_icmp_id, dl->dl_icmp_icmp_seq);
	  break;

	case IPPROTO_TCP:
	  snprintf(inner_transport, sizeof(inner_transport),
		   " proto TCP sport %d dport %d seq %08x",
		   dl->dl_icmp_tcp_sport, dl->dl_icmp_tcp_dport,
		   dl->dl_icmp_tcp_seq);
	  break;

	default:
	  inner_transport[0] = '\0';
	  break;
	}
    }
  else
    {
      inner_ip[0] = '\0';
      inner_transport[0] = '\0';
    }

  scamper_debug(NULL, "%s %s%s%s", ip, icmp, inner_ip, inner_transport);
  return;
}
#endif /* HAVE_SCAMPER_DEBUG */

/*
 * dl_read_cb
 *
 * this function is called by scamper_fds when a BPF fd fires as being
 * available to read from.
 */
#ifndef _WIN32 /* SOCKET vs int on windows */
void scamper_dl_read_cb(int fd, void *param)
#else
void scamper_dl_read_cb(SOCKET fd, void *param)
#endif
{
  assert(param != NULL);

#if defined(HAVE_BPF)
  dl_bpf_read(fd, (scamper_dl_t *)param);
#elif defined(__linux__)
  dl_linux_read(fd, (scamper_dl_t *)param);
#elif defined(HAVE_DLPI)
  dl_dlpi_read(fd, (scamper_dl_t *)param);
#endif

  return;
}

#endif /* ifdef BUILDING_SCAMPER */

void scamper_dl_state_free(scamper_dl_t *dl)
{
  assert(dl != NULL);
#if defined(BUILDING_SCAMPER) && defined(HAVE_STRUCT_TPACKET_REQ3)
  if(dl->ring != NULL)
    ring_free(dl->ring);
#endif
  free(dl);
  return;
}

/*
 * scamper_dl_state_alloc
 *
 * given the scamper_fd_t supplied, initialise the file descriptor and do
 * initial setup tasks, then compile and set a filter to pick up the packets
 * scamper is responsible for transmitting.
 */
scamper_dl_t *scamper_dl_state_alloc(scamper_fd_t *fdn)
{
  scamper_dl_t *dl = NULL;

  if((dl = malloc_zero(sizeof(scamper_dl_t))) == NULL)
    {
      printerror(__func__, "malloc node failed");
      goto err;
    }
  dl->fdn = fdn;

#if defined(BUILDING_SCAMPER)
  if(scamper_fd_ifindex(fdn, &dl->ifindex) != 0)
    {
      printerror_msg(__func__, "could not get ifindex");
      goto err;
    }

#if defined(HAVE_BPF)
  if(dl_bpf_node_init(fdn, dl) == -1)
#elif defined(__linux__)
  if(dl_linux_node_init(fdn, dl) == -1)
#elif defined(HAVE_DLPI)
  if(dl_dlpi_node_init(fdn, dl) == -1)
#endif
    {
      goto err;
    }

#if defined(HAVE_BPF_FILTER)
  dl_filter_init(dl);
#endif
#endif /* BUILDING_SCAMPER */

  return dl;

 err:
  scamper_dl_state_free(dl);
  return NULL;
}

#ifdef BUILDING_SCAMPER
int scamper_dl_tx(const scamper_dl_t *node, const uint8_t *pkt, size_t len)
{
#if defined(HAVE_BPF)
  if(dl_bpf_tx(node, pkt, len) == -1)
#elif defined(__linux__)
  if(dl_linux_tx(node, pkt, len) == -1)
#elif defined(HAVE_DLPI)
  if(dl_dlpi_tx(node, pkt, len) == -1)
#endif
    {
      return -1;
    }

  return 0;
}

int scamper_dl_tx_type(scamper_dl_t *dl)
{
  return dl->tx_type;
}

/*
 * scamper_dl_open_fd
 *
 * routine to actually open a datalink.  called by scamper_dl_open below,
 * as well as by the privsep code.
 */
int scamper_dl_open_fd(int ifindex)
{
#if defined(HAVE_BPF)
  return dl_bpf_open(ifindex);
#elif defined(__linux__)
  return dl_linux_open(ifindex);
#elif defined(HAVE_DLPI)
  return dl_dlpi_open(ifindex);
#elif defined(_WIN32) /* no supported datalink interface on windows */
  return -1;
#endif
}

/*
 * scamper_dl_open
 *
 * return a file descriptor for the datalink for the interface specified.
 * use privilege separation if required, otherwise open fd directly.
 */
int scamper_dl_open(int ifindex)
{
  int fd;

  if((fd = scamper_priv_dl(ifindex)) == -1)
    {
      printerror(__func__, "could not open ifindex %d", ifindex);
      return -1;
    }

  return fd;
}

void scamper_dl_cleanup()
{
  if(readbuf != NULL)
    {
      free(readbuf);
      readbuf = NULL;
    }

  return;
}

int scamper_dl_init()
{
#if defined(HAVE_BPF)
  return dl_bpf_init();
#elif defined(__linux__)
  return dl_linux_init();
#elif defined(HAVE_DLPI)
  return dl_dlpi_init();
#else
  return 0;
#endif
}

#endif /* ifdef BUILDING_SCAMPER */
