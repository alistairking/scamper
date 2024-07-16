/*
 * scamper_icmp4.c
 *
 * $Id: scamper_icmp4.c,v 1.138 2024/04/22 05:55:29 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2013-2014 The Regents of the University of California
 * Copyright (C) 2020-2023 Matthew Luckie
 * Copyright (C) 2023      The Regents of the University of California
 * Author: Matthew Luckie
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

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_task.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_icmp_resp.h"
#include "scamper_ip4.h"
#include "scamper_icmp4.h"
#include "scamper_privsep.h"
#include "scamper_debug.h"
#include "utils.h"

static uint8_t *txbuf = NULL;
static size_t   txbuf_len = 0;
static uint8_t  rxbuf[65536];

static void icmp4_header(scamper_probe_t *probe, uint8_t *buf)
{
  buf[0] = probe->pr_icmp_type; /* type */
  buf[1] = probe->pr_icmp_code; /* code */
  buf[2] = 0; buf[3] = 0;       /* checksum */

  switch(probe->pr_icmp_type)
    {
    case ICMP_ECHO:
    case ICMP_ECHOREPLY:
    case ICMP_TSTAMP:
      bytes_htons(buf+4, probe->pr_icmp_id);
      bytes_htons(buf+6, probe->pr_icmp_seq);
      break;

    case ICMP_UNREACH:
      memset(buf+4, 0, 4);
      if(probe->pr_icmp_code == ICMP_UNREACH_NEEDFRAG)
	bytes_htons(buf+6, probe->pr_icmp_mtu);
      break;

    default:
      memset(buf+4, 0, 4);
      break;
    }

  return;
}

uint16_t scamper_icmp4_cksum(scamper_probe_t *probe)
{
  uint8_t hdr[8];
  uint16_t tmp, *w;
  int i, sum = 0;

  icmp4_header(probe, hdr);

  w = (uint16_t *)hdr;
  for(i=0; i<8; i+=2)
    sum += *w++;

  w = (uint16_t *)probe->pr_data;
  for(i = probe->pr_len; i > 1; i -= 2)
    sum += *w++;
  if(i != 0)
    sum += ((uint8_t *)w)[0];

  /* fold the checksum */
  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  if((tmp = ~sum) == 0)
    {
      tmp = 0xffff;
    }

  return tmp;
}

static void icmp4_build(scamper_probe_t *probe, uint8_t *buf)
{
  uint16_t csum;

  icmp4_header(probe, buf);

  if(probe->pr_len > 0)
    memcpy(buf + 8, probe->pr_data, probe->pr_len);

  csum = in_cksum(buf, (size_t)(probe->pr_len + 8));
  memcpy(buf+2, &csum, 2);

  return;
}

int scamper_icmp4_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  size_t ip4hlen, req;
  int rc = 0;

  ip4hlen = *len;
  scamper_ip4_build(probe, buf, &ip4hlen);
  req = ip4hlen + 8 + probe->pr_len;

  if(req <= *len)
    icmp4_build(probe, buf + ip4hlen);
  else
    rc = -1;

  *len = req;
  return rc;
}

/*
 * scamper_icmp4_probe
 *
 * send an ICMP probe to a destination
 */
int scamper_icmp4_probe(scamper_probe_t *probe)
{
  struct sockaddr_in  sin4;
  char                addr[128];
  size_t              ip4hlen, len, tmp;
  int                 i, icmphdrlen;

#if !defined(IP_HDR_HTONS)
  struct ip          *ip;
#endif

  assert(probe != NULL);
  assert(probe->pr_ip_proto == IPPROTO_ICMP);
  assert(probe->pr_ip_dst != NULL);
  assert(probe->pr_ip_src != NULL);
  assert(probe->pr_len > 0 || probe->pr_data == NULL);

  switch(probe->pr_icmp_type)
    {
    case ICMP_ECHO:
    case ICMP_TSTAMP:
      icmphdrlen = (1 + 1 + 2 + 2 + 2);
      break;

    default:
      probe->pr_errno = EINVAL;
      return -1;
    }

  if((probe->pr_flags & SCAMPER_PROBE_FLAG_RXERR) == 0)
    scamper_ip4_hlen(probe, &ip4hlen);
  else
    ip4hlen = 0;

  /* compute length, for sake of readability */
  len = ip4hlen + icmphdrlen + probe->pr_len;

  if(txbuf_len < len)
    {
      if(realloc_wrap((void **)&txbuf, len) != 0)
	{
	  printerror(__func__, "could not realloc");
	  return -1;
	}
      txbuf_len = len;
    }

  /* build the IPv4 header from the probe structure */
  if((probe->pr_flags & SCAMPER_PROBE_FLAG_RXERR) == 0)
    {
      tmp = len;
      scamper_ip4_build(probe, txbuf, &tmp);

      /*
       * byte swap the length and offset fields back to host-byte order
       * if required
       */
#if !defined(IP_HDR_HTONS)
      ip = (struct ip *)txbuf;
      ip->ip_len = ntohs(ip->ip_len);
      ip->ip_off = ntohs(ip->ip_off);
#endif
    }
  else
    {
      i = probe->pr_ip_ttl;
      if(setsockopt(probe->pr_fd,IPPROTO_IP,IP_TTL, (void *)&i, sizeof(i)) < 0)
	{
	  printerror(__func__, "could not set IP_TTL");
	  return -1;
	}
    }

  icmp4_build(probe, txbuf + ip4hlen);

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET,
		   probe->pr_ip_dst->addr, 0);

  /* get the transmit time immediately before we send the packet */
  gettimeofday_wrap(&probe->pr_tx);

  i = sendto(probe->pr_fd, txbuf, len, 0, (struct sockaddr *)&sin4,
	     sizeof(struct sockaddr_in));

  if(i < 0)
    {
      /* error condition, could not send the packet at all */
      probe->pr_errno = errno;
      printerror(__func__, "could not send to %s (%d ttl, %d seq, %d len)",
		 scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)),
		 probe->pr_ip_ttl, probe->pr_icmp_seq, (int)len);
      return -1;
    }
  else if((size_t)i != len)
    {
      /* error condition, sent a portion of the probe */
      printerror_msg(__func__, "sent %d bytes of %d byte packet to %s",
		     i, (int)len,
		     scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)));
      return -1;
    }

  return 0;
}

/*
 * icmp4_quote_ip_len
 *
 * this function returns the ip header's length field inside an icmp message
 * in a consistent fashion based on the system it is running on and the
 * type of the message.
 *
 * thanks to the use of an ICMP_FILTER or scamper's own type filtering, the
 * two ICMP types scamper has to deal with are ICMP_TIMXCEED and ICMP_UNREACH
 *
 * note that the filtering will filter any ICMP_TIMXCEED message with a code
 * other than ICMP_TIMXCEED_INTRANS, but we might as well deal with the whole
 * type.
 *
 * the pragmatic way is just to use pcap, which passes packets up in network
 * byte order consistently.
 */
static uint16_t icmp4_quote_ip_len(const struct icmp *icmp)
{
  uint16_t len;

#if defined(__linux__) || defined(__OpenBSD__) || defined(__sun__) || defined(_WIN32)
  len = ntohs(icmp->icmp_ip.ip_len);
#elif defined(__FreeBSD__) && __FreeBSD_version >= 1000022
  len = ntohs(icmp->icmp_ip.ip_len);
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__) || defined(__DragonFly__)
  if(icmp->icmp_type == ICMP_TIMXCEED)
    {
      if(icmp->icmp_code <= 1)
	len = icmp->icmp_ip.ip_len;
      else
	len = ntohs(icmp->icmp_ip.ip_len);
    }
  else if(icmp->icmp_type == ICMP_UNREACH)
    {
      switch(icmp->icmp_code)
	{
	case ICMP_UNREACH_NET:
	case ICMP_UNREACH_HOST:
	case ICMP_UNREACH_PROTOCOL:
	case ICMP_UNREACH_PORT:
	case ICMP_UNREACH_SRCFAIL:
	case ICMP_UNREACH_NEEDFRAG:
	case ICMP_UNREACH_NET_UNKNOWN:
	case ICMP_UNREACH_NET_PROHIB:
	case ICMP_UNREACH_TOSNET:
	case ICMP_UNREACH_HOST_UNKNOWN:
	case ICMP_UNREACH_ISOLATED:
	case ICMP_UNREACH_HOST_PROHIB:
	case ICMP_UNREACH_TOSHOST:

# if defined(__FreeBSD__) || defined(__APPLE__) || defined(__DragonFly__)
	case ICMP_UNREACH_HOST_PRECEDENCE:
	case ICMP_UNREACH_PRECEDENCE_CUTOFF:
	case ICMP_UNREACH_FILTER_PROHIB:
# endif
	  len = icmp->icmp_ip.ip_len;
	  break;

	default:
	  len = ntohs(icmp->icmp_ip.ip_len);
	}
    }
  else if(icmp->icmp_type == ICMP_PARAMPROB)
    {
      if(icmp->icmp_code <= 1)
	len = icmp->icmp_ip.ip_len;
      else
	len = ntohs(icmp->icmp_ip.ip_len);
    }
  else
    {
      len = icmp->icmp_ip.ip_len;
    }
#else
  len = icmp->icmp_ip.ip_len;
#endif

  return len;
}

/*
 * scamper_icmp4_ip_len
 *
 * given the ip header encapsulating the icmp response, return the length
 * of the ip packet
 */
static uint16_t icmp4_ip_len(const struct ip *ip)
{
  uint16_t len;

#if defined(__linux__) || defined(__OpenBSD__) || defined(__sun__) || defined(_WIN32)
  len = ntohs(ip->ip_len);
#elif defined(__FreeBSD__) && __FreeBSD_version >= 1100030
  len = ntohs(ip->ip_len);
#else
  len = ip->ip_len + (ip->ip_hl << 2);
#endif

  return len;
}

static void ip_quote_rr(scamper_icmp_resp_t *ir, int rrc, void *rrs)
{
  ir->ir_inner_ipopt_rrc = rrc;
  ir->ir_inner_ipopt_rrs = rrs;
  return;
}

static void ip_rr(scamper_icmp_resp_t *ir, int rrc, void *rrs)
{
  ir->ir_ipopt_rrc = rrc;
  ir->ir_ipopt_rrs = rrs;
  return;
}

static uint8_t ip_tsc(int fl, int len)
{
  if(fl == 0)
    {
      if(len >= 4 && (len % 4) == 0)
	return len / 4;
    }
  else if(fl == 1 || fl == 3)
    {
      if(len >= 8 && (len % 8) == 0)
	return len / 8;
    }

  return 0;
}

static void ip_quote_ts(scamper_icmp_resp_t *ir, int fl,
			const uint8_t *buf, int len)
{
  const uint8_t *ptr = buf;
  uint8_t i, tsc;

  ir->ir_flags |= SCAMPER_ICMP_RESP_FLAG_INNER_IPOPT_TS;

  if((tsc = ip_tsc(fl, len)) == 0)
    return;

  if(fl == 1 || fl == 3)
    {
      ir->ir_inner_ipopt_tsips = malloc_zero(sizeof(struct in_addr) * tsc);
      if(ir->ir_inner_ipopt_tsips == NULL)
	return;
    }

  if((ir->ir_inner_ipopt_tstss = malloc_zero(sizeof(uint32_t) * tsc)) == NULL)
    return;

  for(i=0; i<tsc; i++)
    {
      if(fl == 1 || fl == 3)
	{
	  memcpy(&ir->ir_inner_ipopt_tsips[i], ptr, 4);
	  ptr += 4;
	}
      ir->ir_inner_ipopt_tstss[i] = bytes_ntohl(ptr);
      ptr += 4;
    }

  ir->ir_inner_ipopt_tsc = tsc;
  return;
}

static void ip_ts(scamper_icmp_resp_t *ir, int fl, const uint8_t *buf, int len)
{
  const uint8_t *ptr = buf;
  uint8_t i, tsc;
  size_t size;

  ir->ir_flags |= SCAMPER_ICMP_RESP_FLAG_IPOPT_TS;

  if((tsc = ip_tsc(fl, len)) == 0)
    return;

  if(fl == 1 || fl == 3)
    {
      size = sizeof(struct in_addr) * tsc;
      if((ir->ir_ipopt_tsips = malloc_zero(size)) == NULL)
	return;
    }

  if((ir->ir_ipopt_tstss = malloc_zero(sizeof(uint32_t) * tsc)) == NULL)
    return;

  for(i=0; i<tsc; i++)
    {
      if(fl == 1 || fl == 3)
	{
	  memcpy(&ir->ir_ipopt_tsips[i], ptr, 4);
	  ptr += 4;
	}
      ir->ir_ipopt_tstss[i] = bytes_ntohl(ptr);
      ptr += 4;
    }

  ir->ir_ipopt_tsc = tsc;
  return;
}

static void ipopt_parse(scamper_icmp_resp_t *ir, const uint8_t *buf, int iphl,
			void (*rr)(scamper_icmp_resp_t *, int, void *),
			void (*ts)(scamper_icmp_resp_t *, int,
				   const uint8_t *, int))
{
  int off, ol, p, fl, rrc;
  void *rrs;

  off = 20;
  while(off < iphl)
    {
      /* end of IP options */
      if(buf[off] == 0)
	break;

      /* no-op */
      if(buf[off] == 1)
	{
	  off++;
	  continue;
	}

      ol = buf[off+1];

      /* check to see if the option could be included */
      if(ol < 2 || off + ol > iphl)
	break;

      if(buf[off] == 7 && rr != NULL)
	{
	  /* record route */
	  p = buf[off+2];
	  if(p >= 4 && (p % 4) == 0 && (rrc = (p / 4) - 1) != 0 &&
	     (rrs = memdup(buf+off+3, rrc * 4)) != NULL)
	    {
	      rr(ir, rrc, rrs);
	    }
	}
      else if(buf[off] == 68 && ts != NULL)
	{
	  /* timestamp */
	  p  = buf[off+2];
	  fl = buf[off+3] & 0xf;
	  if(p == 1) /* RFC 781, not in 791 */
	    ts(ir, fl, buf+off+4, ol-4);
	  else if(p >= 5 && p-1 <= ol)
	    ts(ir, fl, buf+off+4, p-5);
	}

      off += ol;
    }

  return;
}

/*
 * icmp4_recv_ip
 *
 * copy details of the ICMP message and the time it was received into the
 * response structure.
 */
#ifndef _WIN32 /* windows does not have msghdr struct */
static void icmp4_recv_ip(int fd,
			  struct msghdr *msg,
#else
static void icmp4_recv_ip(SOCKET fd,
#endif
			  scamper_icmp_resp_t *ir, const uint8_t *buf, int iphl)
{
  const struct ip *ip = (const struct ip *)buf;
  const struct icmp *icmp = (const struct icmp *)(buf + iphl);

  /*
   * to start with, get a timestamp from the kernel if we can, otherwise
   * just get one from user-space.
   */
#if defined(SO_TIMESTAMP)
  struct cmsghdr *cmsg;

#ifdef IP_PKTINFO
  struct in_pktinfo *pi;
#endif

  /*
   * RFC 2292:
   * this should be taken care of by CMSG_FIRSTHDR, but not always is.
   */
  if(msg->msg_controllen >= sizeof(struct cmsghdr))
    {
      cmsg = (struct cmsghdr *)CMSG_FIRSTHDR(msg);
      while(cmsg != NULL)
	{
	  if(cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMP)
	    {
	      timeval_cpy(&ir->ir_rx, (struct timeval *)CMSG_DATA(cmsg));
	      ir->ir_flags |= SCAMPER_ICMP_RESP_FLAG_KERNRX;
	      goto next;
	    }

#if defined(IP_PKTINFO)
	  if(cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO)
	    {
	      pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
	      ir->ir_ifindex = pi->ipi_ifindex;
	      ir->ir_flags |= SCAMPER_ICMP_RESP_FLAG_IFINDEX;
	      goto next;
	    }
#endif

	next:
	  cmsg = (struct cmsghdr *)CMSG_NXTHDR(msg, cmsg);
	}
    }
#endif

#if defined(SIOCGSTAMP)
  if((ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_KERNRX) == 0)
    {
      if(ioctl(fd, SIOCGSTAMP, &ir->ir_rx) != -1)
	ir->ir_flags |= SCAMPER_ICMP_RESP_FLAG_KERNRX;
    }
#endif

  if((ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_KERNRX) == 0)
    gettimeofday_wrap(&ir->ir_rx);

  /* the response came from ... */
  memcpy(&ir->ir_ip_src.v4, &ip->ip_src, sizeof(struct in_addr));

  ir->ir_af        = AF_INET;
  ir->ir_ip_ttl    = ip->ip_ttl;
  ir->ir_ip_id     = ntohs(ip->ip_id);
  ir->ir_ip_tos    = ip->ip_tos;
  ir->ir_ip_size   = icmp4_ip_len(ip);
  ir->ir_icmp_type = icmp->icmp_type;
  ir->ir_icmp_code = icmp->icmp_code;
  ipopt_parse(ir, buf, iphl, ip_rr, ip_ts);

  return;
}

static int ip_hl(const void *buf)
{
  return (((const uint8_t *)buf)[0] & 0xf) << 2;
}

#if defined(IP_RECVERR) && !defined(_WIN32)
static int scamper_icmp4_recv_err(int fd, scamper_icmp_resp_t *resp)
{
  struct icmp *icmp = (struct icmp *)rxbuf;
  struct sock_extended_err *ee = NULL;
  struct sockaddr_in from, *sin;
  struct cmsghdr *cmsg;
  struct msghdr msg;
  struct iovec iov;
  ssize_t pbuflen;
  uint8_t type, code;
  uint8_t ctrlbuf[2048];
  int *ptr;

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (caddr_t)rxbuf;
  iov.iov_len  = sizeof(rxbuf);

  msg.msg_name       = (caddr_t)&from;
  msg.msg_namelen    = sizeof(from);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (caddr_t)ctrlbuf;
  msg.msg_controllen = sizeof(ctrlbuf);

  memset(resp, 0, sizeof(scamper_icmp_resp_t));
  resp->ir_fd = fd;
  resp->ir_af = AF_INET;
  resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_RXERR;

  /* two calls to recvmsg, first one looking in the error queue */
  if((pbuflen = recvmsg(fd, &msg, MSG_ERRQUEUE)) == -1 &&
     (pbuflen = recvmsg(fd, &msg, 0)) == -1)
    {
      printerror(__func__, "could not recvmsg");
      return -1;
    }
  if(msg.msg_controllen < sizeof(struct cmsghdr))
    return -1;

  /*
   * an ICMP header has to be at least 8 bytes:
   * 1 byte type, 1 byte code, 2 bytes checksum, 4 bytes 'data'
   */
  if(pbuflen < 8)
    {
      scamper_debug(__func__, "pbuflen %d < 8", (int)pbuflen);
      return -1;
    }

  cmsg = (struct cmsghdr *)CMSG_FIRSTHDR(&msg);
  while(cmsg != NULL)
    {
      if(cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMP)
	{
	  timeval_cpy(&resp->ir_rx, (struct timeval *)CMSG_DATA(cmsg));
	  resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_KERNRX;
	}
      else if(cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR)
	{
	  ee = (struct sock_extended_err *)CMSG_DATA(cmsg);
	  if(ee->ee_origin == SO_EE_ORIGIN_ICMP)
	    {
	      resp->ir_icmp_type = ee->ee_type;
	      resp->ir_icmp_code = ee->ee_code;
	      sin = (struct sockaddr_in *)SO_EE_OFFENDER(ee);
	      memcpy(&resp->ir_ip_src.v4,&sin->sin_addr,sizeof(struct in_addr));
	    }
	}
      else if(cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TTL)
	{
	  ptr = (int *)CMSG_DATA(cmsg);
	  resp->ir_ip_ttl = *ptr;
	}
      else if(cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_TOS)
	{
	  ptr = (int *)CMSG_DATA(cmsg);
	  resp->ir_ip_tos = *ptr;
	}
      cmsg = (struct cmsghdr *)CMSG_NXTHDR(&msg, cmsg);
    }

  if((resp->ir_flags & SCAMPER_ICMP_RESP_FLAG_KERNRX) == 0)
    gettimeofday_wrap(&resp->ir_rx);

  if(ee == NULL)
    {
      /*
       * if we get an ICMP echo reply, there is no 'inner' IP packet as there
       * was no error condition.
       * so get the outer packet's details and be done
       */
      type = icmp->icmp_type;
      if(type == ICMP_ECHOREPLY || type == ICMP_TSTAMPREPLY)
	{
	  resp->ir_icmp_id  = ntohs(icmp->icmp_id);
	  resp->ir_icmp_seq = ntohs(icmp->icmp_seq);
	  memcpy(&resp->ir_ip_src.v4, &from.sin_addr, sizeof(struct in_addr));

	  if(type == ICMP_TSTAMPREPLY)
	    {
	      resp->ir_icmp_tso = bytes_ntohl(rxbuf + 8);
	      resp->ir_icmp_tsr = bytes_ntohl(rxbuf + 12);
	      resp->ir_icmp_tst = bytes_ntohl(rxbuf + 16);
	    }
	  return 0;
	}
      return -1;
    }

  type = resp->ir_icmp_type;
  code = resp->ir_icmp_code;
  memcpy(&resp->ir_inner_ip_dst.v4, &from.sin_addr, sizeof(struct in_addr));
  resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_INNER_IP;

  /* check to see if the ICMP type / code is what we want */
  if((type != ICMP_TIMXCEED || code != ICMP_TIMXCEED_INTRANS) &&
     type != ICMP_UNREACH && type != ICMP_ECHOREPLY &&
     type != ICMP_TSTAMPREPLY && type != ICMP_PARAMPROB)
    {
      scamper_debug(__func__, "type %d, code %d not wanted", type, code);
      return -1;
    }

  /* record details of the IP header found in the ICMP error message */
  resp->ir_inner_ip_proto = IPPROTO_ICMP;

  if(type == ICMP_UNREACH && code == ICMP_UNREACH_NEEDFRAG)
    resp->ir_icmp_nhmtu = ntohs(icmp->icmp_nextmtu);

  if(type == ICMP_PARAMPROB && code == ICMP_PARAMPROB_ERRATPTR)
    resp->ir_icmp_pptr = icmp->icmp_pptr;

  resp->ir_inner_icmp_type = icmp->icmp_type;
  resp->ir_inner_icmp_code = icmp->icmp_code;
  resp->ir_inner_icmp_sum  = icmp->icmp_cksum;
  resp->ir_inner_icmp_id   = ntohs(icmp->icmp_id);
  resp->ir_inner_icmp_seq  = ntohs(icmp->icmp_seq);

  return 0;
}
#endif

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_icmp4_recv(int fd, scamper_icmp_resp_t *resp)
#else
int scamper_icmp4_recv(SOCKET fd, scamper_icmp_resp_t *resp)
#endif
{
  ssize_t              poffset;
  ssize_t              pbuflen;
  struct icmp         *icmp;
  struct ip           *ip_outer = (struct ip *)rxbuf;
  struct ip           *ip_inner;
  struct udphdr       *udp;
  struct tcphdr       *tcp;
  uint8_t              type, code;
  uint8_t              nh;
  int                  iphl;
  int                  iphlq;
  uint8_t             *ext;
  ssize_t              extlen;

#ifndef _WIN32 /* windows does not have msghdr or iovec */
  struct sockaddr_in   from;
  uint8_t              ctrlbuf[256];
  struct msghdr        msg;
  struct iovec         iov;

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (caddr_t)rxbuf;
  iov.iov_len  = sizeof(rxbuf);

  msg.msg_name       = (caddr_t)&from;
  msg.msg_namelen    = sizeof(from);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (caddr_t)ctrlbuf;
  msg.msg_controllen = sizeof(ctrlbuf);

  if((pbuflen = recvmsg(fd, &msg, 0)) == -1)
    {
      printerror(__func__, "could not recvmsg");
      return -1;
    }

#else

  if((pbuflen = recv(fd, rxbuf, sizeof(rxbuf), 0)) == SOCKET_ERROR)
    {
      printerror(__func__, "could not recv");
      return -1;
    }

#endif

  if((iphl = ip_hl(ip_outer)) < 20)
    {
      scamper_debug(__func__, "iphl %d < 20", iphl);
      return -1;
    }

  /*
   * an ICMP header has to be at least 8 bytes:
   * 1 byte type, 1 byte code, 2 bytes checksum, 4 bytes 'data'
   */
  if(pbuflen < iphl + 8)
    {
      scamper_debug(__func__, "pbuflen [%d] < iphl [%d] + 8",
		    (int)pbuflen, iphl);
      return -1;
    }

  icmp = (struct icmp *)(rxbuf + iphl);
  type = icmp->icmp_type;
  code = icmp->icmp_code;

  /* check to see if the ICMP type / code is what we want */
  if((type != ICMP_TIMXCEED || code != ICMP_TIMXCEED_INTRANS) &&
     type != ICMP_UNREACH && type != ICMP_ECHOREPLY &&
     type != ICMP_TSTAMPREPLY && type != ICMP_PARAMPROB)
    {
      scamper_debug(__func__, "type %d, code %d not wanted", type, code);
      return -1;
    }

  memset(resp, 0, sizeof(scamper_icmp_resp_t));

  resp->ir_fd = fd;

  /*
   * if we get an ICMP echo reply, there is no 'inner' IP packet as there
   * was no error condition.
   * so get the outer packet's details and be done
   */
  if(type == ICMP_ECHOREPLY || type == ICMP_TSTAMPREPLY)
    {
      resp->ir_icmp_id  = ntohs(icmp->icmp_id);
      resp->ir_icmp_seq = ntohs(icmp->icmp_seq);
      memcpy(&resp->ir_inner_ip_dst.v4, &ip_outer->ip_src,
	     sizeof(struct in_addr));

      if(type == ICMP_TSTAMPREPLY)
	{
	  resp->ir_icmp_tso = bytes_ntohl(rxbuf + iphl + 8);
	  resp->ir_icmp_tsr = bytes_ntohl(rxbuf + iphl + 12);
	  resp->ir_icmp_tst = bytes_ntohl(rxbuf + iphl + 16);
	}

      icmp4_recv_ip(fd,
#ifndef _WIN32 /* windows does not have msghdr struct */
		    &msg,
#endif
		    resp, rxbuf, iphl);

      return 0;
    }

  ip_inner = &icmp->icmp_ip;
  nh = ip_inner->ip_p;
  iphlq = ip_hl(ip_inner);
  poffset = iphl + 8 + iphlq;

  /* search for an ICMP / UDP / TCP header in this packet */
  while(poffset + 8 <= pbuflen)
    {
      /* if we can't deal with the inner header, then stop now */
      if(nh != IPPROTO_UDP && nh != IPPROTO_ICMP && nh != IPPROTO_TCP)
        {
          scamper_debug(__func__, "unhandled next header %d", nh);
	  return -1;
	}

      resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_INNER_IP;

      /* record details of the IP header and the ICMP headers */
      icmp4_recv_ip(fd,
#ifndef _WIN32 /* windows does not have msghdr struct */
		    &msg,
#endif
		    resp, rxbuf, iphl);

      /* record details of the IP header found in the ICMP error message */
      memcpy(&resp->ir_inner_ip_dst.v4, &ip_inner->ip_dst,
	     sizeof(struct in_addr));

      resp->ir_inner_ip_proto = nh;
      resp->ir_inner_ip_ttl   = ip_inner->ip_ttl;
      resp->ir_inner_ip_id    = ntohs(ip_inner->ip_id);
      resp->ir_inner_ip_off   = ntohs(ip_inner->ip_off) & IP_OFFMASK;
      resp->ir_inner_ip_tos   = ip_inner->ip_tos;
      resp->ir_inner_ip_size  = icmp4_quote_ip_len(icmp);

      if(type == ICMP_UNREACH && code == ICMP_UNREACH_NEEDFRAG)
	resp->ir_icmp_nhmtu = ntohs(icmp->icmp_nextmtu);

      if(type == ICMP_PARAMPROB && code == ICMP_PARAMPROB_ERRATPTR)
	resp->ir_icmp_pptr = icmp->icmp_pptr;

      if(resp->ir_inner_ip_off == 0)
	{
	  ipopt_parse(resp, rxbuf+iphl+8, iphlq, ip_quote_rr, ip_quote_ts);

	  if(nh == IPPROTO_UDP)
	    {
	      udp = (struct udphdr *)(rxbuf+poffset);
	      resp->ir_inner_udp_sport = ntohs(udp->uh_sport);
	      resp->ir_inner_udp_dport = ntohs(udp->uh_dport);
	      resp->ir_inner_udp_sum   = udp->uh_sum;
	    }
	  else if(nh == IPPROTO_ICMP)
	    {
	      icmp = (struct icmp *)(rxbuf+poffset);
	      resp->ir_inner_icmp_type = icmp->icmp_type;
	      resp->ir_inner_icmp_code = icmp->icmp_code;
	      resp->ir_inner_icmp_sum  = icmp->icmp_cksum;
	      resp->ir_inner_icmp_id   = ntohs(icmp->icmp_id);
	      resp->ir_inner_icmp_seq  = ntohs(icmp->icmp_seq);
	    }
	  else if(nh == IPPROTO_TCP)
	    {
	      tcp = (struct tcphdr *)(rxbuf+poffset);
	      resp->ir_inner_tcp_sport = ntohs(tcp->th_sport);
	      resp->ir_inner_tcp_dport = ntohs(tcp->th_dport);
	      resp->ir_inner_tcp_seq   = ntohl(tcp->th_seq);
	    }
	}
      else
	{
	  resp->ir_inner_data = rxbuf + poffset;
	  resp->ir_inner_datalen = pbuflen - poffset;
	}

      /*
       * check for ICMP extensions
       *
       * the length of the message must be at least padded out to 128 bytes,
       * and must have 4 bytes of header beyond that for there to be
       * extensions included.
       * RFC 4884 says that the first 4 bits of the extension header
       * corresponds to a version number, and the version is two.  But
       * it appears some systems have the version in the subsequent 4 bits.
       */
      if(pbuflen - (iphl+8) > 128 + 4)
	{
	  ext    = rxbuf   + (iphl + 8 + 128);
	  extlen = pbuflen - (iphl + 8 + 128);

	  if(((ext[0] & 0xf0) == 0x20 || ext[0] == 0x02) &&
	     ((ext[2] == 0 && ext[3] == 0) || in_cksum(ext, extlen) == 0))
	    {
	      resp->ir_ext    = memdup(ext, extlen);
	      resp->ir_extlen = extlen;
	    }
	}

      return 0;
    }

  scamper_debug(__func__, "packet not ours");

  return -1;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
void scamper_icmp4_read_cb(int fd, void *param)
#else
void scamper_icmp4_read_cb(SOCKET fd, void *param)
#endif
{
  scamper_icmp_resp_t ir;
  memset(&ir, 0, sizeof(ir));
  if(scamper_icmp4_recv(fd, &ir) == 0)
    scamper_task_handleicmp(&ir);
  scamper_icmp_resp_clean(&ir);
  return;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
void scamper_icmp4_read_err_cb(int fd, void *param)
#else
void scamper_icmp4_read_err_cb(SOCKET fd, void *param)
#endif
{
#if defined(IP_RECVERR) && !defined(_WIN32)
  scamper_icmp_resp_t ir;
  memset(&ir, 0, sizeof(ir));
  if(scamper_icmp4_recv_err(fd, &ir) == 0)
    scamper_task_handleicmp(&ir);
  scamper_icmp_resp_clean(&ir);
#endif
  return;
}

void scamper_icmp4_cleanup()
{
  if(txbuf != NULL)
    {
      free(txbuf);
      txbuf = NULL;
    }

  return;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_icmp4_open_err(const void *addr)
#else
SOCKET scamper_icmp4_open_err(const void *addr)
#endif
{
#ifdef IP_RECVERR
  struct sockaddr_in sin;
  char tmp[32];
  int opt;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if(socket_isinvalid(fd))
    {
      printerror(__func__, "could not open ICMP socket");
      goto err;
    }

  opt = 65535 + 128;
  if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set SO_RCVBUF");
      goto err;
    }

  opt = 65535 + 128;
  if(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set SO_SNDBUF");
      goto err;
    }

#if defined(SO_TIMESTAMP)
  opt = 1;
  if(setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, (void *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set SO_TIMESTAMP");
      goto err;
    }
#endif

  opt = 1;
  if(setsockopt(fd, SOL_IP, IP_RECVERR, (void *)&opt, sizeof(opt)) < 0)
    {
      printerror(__func__, "could not set IP_RECVERR");
      goto err;
    }

  opt = 1;
  if(setsockopt(fd, SOL_IP, IP_RECVTTL, (void *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set IP_RECVTTL");
      goto err;
    }

  opt = 1;
  if(setsockopt(fd, SOL_IP, IP_RECVTOS, (void *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set IP_RECVTOS");
      goto err;
    }

#ifdef IP_RECVOPTS
  opt = 1;
  if(setsockopt(fd, SOL_IP, IP_RECVOPTS, (void *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set IP_RECVOPTS");
      goto err;
    }
#endif

  if(addr != NULL)
    {
      sockaddr_compose((struct sockaddr *)&sin, AF_INET, addr, 0);
      if(bind(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0)
	{
	  printerror(__func__, "could not bind %s",
		     sockaddr_tostr((struct sockaddr *)&sin,tmp,sizeof(tmp)));
	  goto err;
	}
    }

  return fd;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
#endif /* #ifdef IP_RECVERR */
  return socket_invalid();
}

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_icmp4_open_fd(void)
#else
SOCKET scamper_icmp4_open_fd(void)
#endif
{
  int opt = 1;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

  fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if(socket_isinvalid(fd))
    {
      printerror(__func__, "could not open ICMP socket");
      goto err;
    }
  if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, (void *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set IP_HDRINCL");
      goto err;
    }
  return fd;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  return socket_invalid();
}

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_icmp4_open(const void *addr)
#else
SOCKET scamper_icmp4_open(const void *addr)
#endif
{
  struct sockaddr_in sin;
  char tmp[32];
  int opt;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd = -1;
#else
  SOCKET fd = INVALID_SOCKET;
#endif

#if defined(ICMP_FILTER)
  struct icmp_filter filter;
#endif

#ifdef DISABLE_PRIVSEP
#ifdef HAVE_SETEUID
  uid_t uid = scamper_getuid();
  uid_t euid = scamper_geteuid();
  if(uid != euid && seteuid(euid) != 0)
    {
      printerror(__func__, "could not claim euid");
      goto err;
    }
#endif
  fd = scamper_icmp4_open_fd();
#ifdef HAVE_SETEUID
  if(uid != euid && seteuid(uid) != 0)
    {
      printerror(__func__, "could not return to uid");
      exit(-errno);
    }
#endif
#else
  fd = scamper_privsep_open_icmp(AF_INET);
#endif
  if(socket_isinvalid(fd))
    return socket_invalid();

  opt = 65535 + 128;
  if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set SO_RCVBUF");
      goto err;
    }

  opt = 65535 + 128;
  if(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set SO_SNDBUF");
      goto err;
    }

#if defined(SO_TIMESTAMP)
  opt = 1;
  if(setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, (void *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set SO_TIMESTAMP");
      goto err;
    }
#endif

  /*
   * ask the icmp6 socket to supply the interface on which it receives
   * a packet.
   */
#if defined(IP_RECVPKTINFO)
  opt = 1;
  if(setsockopt(fd, IPPROTO_IP, IP_RECVPKTINFO, (void *)&opt, sizeof(opt)) != 0)
    {
      printerror(__func__, "could not set IP_RECVPKTINFO");
    }
#elif defined(IP_PKTINFO)
  opt = 1;
  if(setsockopt(fd, IPPROTO_IP, IP_PKTINFO, (void *)&opt, sizeof(opt)) != 0)
    {
      printerror(__func__, "could not set IP_PKTINFO");
    }
#endif

  /*
   * on linux systems with ICMP_FILTER defined, filter all messages except
   * destination unreachable and time exceeded messages
   */
#if defined(ICMP_FILTER)
  filter.data = ~((1 << ICMP_DEST_UNREACH)  |
		  (1 << ICMP_TIME_EXCEEDED) |
		  (1 << ICMP_ECHOREPLY) |
		  (1 << ICMP_TSTAMPREPLY) |
		  (1 << ICMP_PARAMPROB)
		  );
  if(setsockopt(fd, SOL_RAW, ICMP_FILTER, &filter, sizeof(filter)) == -1)
    {
      printerror(__func__, "could not set ICMP_FILTER");
      goto err;
    }
#endif

  if(addr != NULL)
    {
      sockaddr_compose((struct sockaddr *)&sin, AF_INET, addr, 0);
      if(bind(fd, (struct sockaddr *)&sin, sizeof(sin)) != 0)
	{
	  printerror(__func__, "could not bind %s",
		     sockaddr_tostr((struct sockaddr *)&sin,tmp,sizeof(tmp)));
	  goto err;
	}
    }

  return fd;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  return socket_invalid();
}
