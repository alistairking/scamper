/*
 * sc_wartsdump
 *
 * $Id: sc_wartsdump.c,v 1.296 2024/05/01 07:46:20 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2019-2023 Matthew Luckie
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

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "trace/scamper_trace.h"
#include "ping/scamper_ping.h"
#include "tracelb/scamper_tracelb.h"
#include "dealias/scamper_dealias.h"
#include "neighbourdisc/scamper_neighbourdisc.h"
#include "tbit/scamper_tbit.h"
#include "sting/scamper_sting.h"
#include "sniff/scamper_sniff.h"
#include "host/scamper_host.h"
#include "http/scamper_http.h"
#include "udpprobe/scamper_udpprobe.h"
#include "scamper_file.h"
#include "utils.h"

static void usage()
{
  fprintf(stderr, "usage: sc_wartsdump <file>\n");
  return;
}

static char *icmp_unreach_tostr(char *buf, size_t len, int at, uint8_t co)
{
  char *p = NULL;

  if(at == SCAMPER_ADDR_TYPE_IPV4)
    {
      switch(co)
	{
	case ICMP_UNREACH_NET:           p = "net";           break;
	case ICMP_UNREACH_HOST:          p = "host";          break;
	case ICMP_UNREACH_PROTOCOL:      p = "protocol";      break;
	case ICMP_UNREACH_PORT:          p = "port";          break;
	case ICMP_UNREACH_SRCFAIL:       p = "src-rt failed"; break;
	case ICMP_UNREACH_NET_UNKNOWN:   p = "net unknown";   break;
	case ICMP_UNREACH_HOST_UNKNOWN:  p = "host unknown";  break;
	case ICMP_UNREACH_ISOLATED:      p = "isolated";      break;
	case ICMP_UNREACH_NET_PROHIB:    p = "net prohib";    break;
	case ICMP_UNREACH_HOST_PROHIB:   p = "host prohib";   break;
	case ICMP_UNREACH_TOSNET:        p = "tos net";       break;
	case ICMP_UNREACH_TOSHOST:       p = "tos host";      break;
	case ICMP_UNREACH_FILTER_PROHIB: p = "admin prohib";  break;
	case ICMP_UNREACH_NEEDFRAG:      p = "need frag";     break;
	}
    }
  else
    {
      switch(co)
	{
	case ICMP6_DST_UNREACH_NOROUTE:     p = "no route";     break;
	case ICMP6_DST_UNREACH_ADMIN:       p = "admin prohib"; break;
	case ICMP6_DST_UNREACH_BEYONDSCOPE: p = "beyond scope"; break;
	case ICMP6_DST_UNREACH_ADDR:        p = "addr"; break;
	case ICMP6_DST_UNREACH_NOPORT:      p = "port"; break;
	}
    }

  if(p != NULL)
    snprintf(buf, len, "%s", p);
  else
    snprintf(buf, len, "%d", co);

  return buf;
}

static void dump_list_summary(scamper_list_t *list)
{
  const char *str;
  if(list != NULL)
    {
      printf(" list id: %d", scamper_list_id_get(list));
      if((str = scamper_list_name_get(list)) != NULL)
	printf(", name: %s", str);
      if((str = scamper_list_monitor_get(list)) != NULL)
	printf(", monitor: %s", str);
      printf("\n");
    }
  return;
}

static void dump_cycle_summary(scamper_cycle_t *cycle)
{
  if(cycle != NULL)
    printf(" cycle id: %d\n", scamper_cycle_id_get(cycle));
  return;
}

static void dump_tcp_flags(uint8_t flags)
{
  if(flags != 0)
    {
      printf(" (%s%s%s%s%s%s%s%s )",
	     (flags & 0x01) ? " fin" : "",
	     (flags & 0x02) ? " syn" : "",
	     (flags & 0x04) ? " rst" : "",
	     (flags & 0x08) ? " psh" : "",
	     (flags & 0x10) ? " ack" : "",
	     (flags & 0x20) ? " urg" : "",
	     (flags & 0x40) ? " ece" : "",
	     (flags & 0x80) ? " cwr" : "");
    }
  return;
}

static void dump_timeval(const char *label, const struct timeval *start)
{
  time_t tt = start->tv_sec;
  char buf[32];
  memcpy(buf, ctime(&tt), 24); buf[24] = '\0';
  printf(" %s: %s %06d\n", label, buf, (int)start->tv_usec);
  return;
}

static void dump_wait(const char *label, const struct timeval *tv)
{
  uint32_t u32 = tv->tv_usec;
  char buf[32];
  int x = 6;
  printf("%s: %u", label, (uint32_t)tv->tv_sec);
  if(u32 > 0)
    {
      while((u32 % 10) == 0)
	{
	  u32 /= 10;
	  x--;
	}
      snprintf(buf, sizeof(buf), ".%%0%du", x);
      printf(buf, u32);
    }
  printf("s");
  return;
}

static void dump_trace_hop(const scamper_trace_t *trace,
			   const scamper_trace_hop_t *hop)
{
  scamper_addr_t *hop_addr = scamper_trace_hop_addr_get(hop);
  const struct timeval *start, *tx, *rtt;
  const scamper_icmpext_t *ie;
  struct timeval tv;
  const char *str;
  uint32_t u32, hop_flags;
  uint16_t m, mplsc;
  uint8_t u8;
  char buf[256];
  char *comma = "";

  printf("hop %2d  %s", scamper_trace_hop_probe_ttl_get(hop),
	 scamper_addr_tostr(hop_addr, buf, sizeof(buf)));
  if((str = scamper_trace_hop_name_get(hop)) != NULL)
    printf(" name %s", str);
  printf("\n");

  printf(" attempt: %d", scamper_trace_hop_probe_id_get(hop));
  tx = scamper_trace_hop_tx_get(hop);
  if(tx->tv_sec != 0)
    {
      start = scamper_trace_start_get(trace);
      timeval_diff_tv(&tv, start, tx);
      printf(", tx: %d.%06ds", (int)tv.tv_sec, (int)tv.tv_usec);
    }
  rtt = scamper_trace_hop_rtt_get(hop);
  printf(", rtt: %d.%06ds, probe-size: %d\n",
	 (int)rtt->tv_sec, (int)rtt->tv_usec,
	 scamper_trace_hop_probe_size_get(hop));

  hop_flags = scamper_trace_hop_flags_get(hop);
  if(hop_flags & SCAMPER_TRACE_HOP_FLAG_REPLY_TTL)
    {
      printf("%s reply-ttl: %d", comma, scamper_trace_hop_reply_ttl_get(hop));
      comma = ",";
    }

  if((scamper_trace_flags_get(trace) & SCAMPER_TRACE_FLAG_RXERR) == 0)
    {
      printf("%s reply-size: %d", comma, scamper_trace_hop_reply_size_get(hop));
      comma = ",";
      if(scamper_addr_isipv4(hop_addr))
	printf("%s reply-ipid: 0x%04x", comma,
	       scamper_trace_hop_reply_ipid_get(hop));
    }

  printf("%s reply-tos: 0x%02x\n", comma, scamper_trace_hop_reply_tos_get(hop));

  if(scamper_trace_hop_is_icmp(hop))
    {
      printf(" icmp-type: %d, icmp-code: %d",
	     scamper_trace_hop_icmp_type_get(hop),
	     scamper_trace_hop_icmp_code_get(hop));
      if(scamper_trace_hop_is_icmp_q(hop))
	{
	  printf(", q-ttl: %d, q-len: %d, q-tos %d",
		 scamper_trace_hop_icmp_q_ttl_get(hop),
		 scamper_trace_hop_icmp_q_ipl_get(hop),
		 scamper_trace_hop_icmp_q_tos_get(hop));
	}
      if(scamper_trace_hop_is_icmp_ptb(hop))
	printf(", nhmtu: %d", scamper_trace_hop_icmp_nhmtu_get(hop));
      printf("\n");
    }
  else if(scamper_trace_hop_is_tcp(hop))
    {
      u8 = scamper_trace_hop_tcp_flags_get(hop);
      printf(" tcp-flags: 0x%02x", u8);
      dump_tcp_flags(u8);
      printf("\n");
    }

  printf(" flags: 0x%02x", hop_flags);
  if(hop_flags != 0)
    {
      printf(" (");
      if(hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_SOCK_RX)
	printf(" sockrxts");
      if(hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_TX)
	printf(" dltxts");
      if(hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_RX)
	printf(" dlrxts");
      if(hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_TSC)
	printf(" tscrtt");
      if(hop_flags & SCAMPER_TRACE_HOP_FLAG_REPLY_TTL)
	printf(" replyttl");
      printf(" )");
    }
  printf("\n");

  for(ie = scamper_trace_hop_icmpext_get(hop); ie != NULL;
      ie = scamper_icmpext_next_get(ie))
    {
      if(scamper_icmpext_is_mpls(ie))
	{
	  mplsc = scamper_icmpext_mpls_count_get(ie);
	  for(m=0; m<mplsc; m++)
	    {
	      u32 = scamper_icmpext_mpls_label_get(ie, m);
	      printf("%9s ttl: %d, s: %d, exp: %d, label: %d\n",
		     (m == 0) ? "mpls ext" : "",
		     scamper_icmpext_mpls_ttl_get(ie, m),
		     scamper_icmpext_mpls_s_get(ie, m),
		     scamper_icmpext_mpls_exp_get(ie, m), u32);
	    }
	}
    }

  return;
}

static void dump_trace(scamper_trace_t *trace)
{
  const scamper_trace_hop_t *hop;
  const scamper_trace_dtree_t *dt;
  const scamper_trace_pmtud_t *pmtud;
  const scamper_trace_pmtud_n_t *n;
  const struct timeval *tv;
  scamper_addr_t *addr, *dst;
  const char *str;
  uint32_t flags;
  uint16_t u16, sport, dport, hop_count;
  uint8_t u8, stop_reason, stop_data, notec, n_type;
  char buf[256];

  dst = scamper_trace_dst_get(trace);

  if((addr = scamper_trace_src_get(trace)) != NULL)
    {
      scamper_addr_tostr(addr, buf, sizeof(buf));
      printf("traceroute from %s to ", buf);
      printf("%s\n", scamper_addr_tostr(dst, buf, sizeof(buf)));
    }
  else
    {
      printf("traceroute to %s\n", scamper_addr_tostr(dst, buf, sizeof(buf)));
    }

  dump_list_summary(scamper_trace_list_get(trace));
  dump_cycle_summary(scamper_trace_cycle_get(trace));
  printf(" user-id: %d\n", scamper_trace_userid_get(trace));
  if((addr = scamper_trace_rtr_get(trace)) != NULL)
    printf(" rtr: %s\n", scamper_addr_tostr(addr, buf, sizeof(buf)));
  dump_timeval("start", scamper_trace_start_get(trace));

  hop_count = scamper_trace_hop_count_get(trace);
  sport = scamper_trace_sport_get(trace);
  dport = scamper_trace_dport_get(trace);
  printf(" type: ");
  switch(scamper_trace_type_get(trace))
    {
    case SCAMPER_TRACE_TYPE_ICMP_ECHO:
      printf("icmp, echo id: %d", sport);
      break;

    case SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS:
      /*
       * if the byte ordering of the trace->sport used in the icmp csum
       * is unknown -- that is, not known to be correct, print that detail
       */
      printf("icmp paris, echo id: %d", sport);
      if(scamper_trace_flag_is_icmpcsumdp(trace))
	printf(", csum: 0x%04x", dport);
      break;

    case SCAMPER_TRACE_TYPE_UDP:
      printf("udp, sport: %d, base dport: %d", sport, dport);
      break;

    case SCAMPER_TRACE_TYPE_UDP_PARIS:
      printf("udp paris, sport: %d, dport: %d", sport, dport);
      break;

    case SCAMPER_TRACE_TYPE_TCP:
      printf("tcp, sport: %d, dport: %d", sport, dport);
      break;

    case SCAMPER_TRACE_TYPE_TCP_ACK:
      printf("tcp-ack, sport: %d, dport: %d", sport, dport);
      break;

    default:
      printf("%d", scamper_trace_type_get(trace));
      break;
    }
  if((u16 = scamper_trace_offset_get(trace)) != 0)
    printf(", offset %d", u16);
  printf("\n");

  if((dt = scamper_trace_dtree_get(trace)) != NULL)
    {
      printf(" doubletree firsthop: %d", scamper_trace_dtree_firsthop_get(dt));
      if((str = scamper_trace_dtree_lss_get(dt)) != NULL)
	printf(", lss-name: %s", str);
      if((addr = scamper_trace_dtree_lss_stop_get(dt)) != NULL)
	printf(", lss-stop: %s", scamper_addr_tostr(addr, buf, sizeof(buf)));
      if((addr = scamper_trace_dtree_gss_stop_get(dt)) != NULL)
	printf(", gss-stop: %s", scamper_addr_tostr(addr, buf, sizeof(buf)));
      printf("\n");
    }

  printf(" attempts: %d, hoplimit: %d, loops: %d, probec: %d, hopcount: %d",
	 scamper_trace_attempts_get(trace), scamper_trace_hoplimit_get(trace),
	 scamper_trace_loops_get(trace), scamper_trace_probec_get(trace),
	 hop_count);
  if((u8 = scamper_trace_stop_hop_get(trace)) != 0)
    printf(", stophop: %d", u8);
  printf("\n");
  printf(" squeries: %d, firsthop: %d, gaplimit: %d, gapaction: %s\n",
	 scamper_trace_squeries_get(trace),
	 scamper_trace_firsthop_get(trace),
	 scamper_trace_gaplimit_get(trace),
	 scamper_trace_gapaction_tostr(trace, buf, sizeof(buf)));
  dump_wait(" wait-timeout", scamper_trace_wait_timeout_get(trace));
  tv = scamper_trace_wait_probe_get(trace);
  if(timeval_iszero(tv) == 0)
    dump_wait(", wait-probe", tv);
  if((u8 = scamper_trace_confidence_get(trace)) != 0)
    printf(", confidence: %d%%", u8);
  printf(", tos: 0x%02x\n", scamper_trace_tos_get(trace));

  flags = scamper_trace_flags_get(trace);
  printf(" flags: 0x%02x", flags);
  if(flags != 0)
    {
      printf(" (");
      if(flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS)
	printf(" all-attempts");
      if(flags & SCAMPER_TRACE_FLAG_PMTUD)
	printf(" pmtud");
      if(flags & SCAMPER_TRACE_FLAG_DL)
	printf(" dl");
      if(flags & SCAMPER_TRACE_FLAG_IGNORETTLDST)
	printf(" ignorettldst");
      if(flags & SCAMPER_TRACE_FLAG_DOUBLETREE)
	printf(" doubletree");
      if(flags & SCAMPER_TRACE_FLAG_ICMPCSUMDP)
	printf(" icmp-csum-dport");
      if(flags & SCAMPER_TRACE_FLAG_CONSTPAYLOAD)
	printf(" const-payload");
      if(flags & SCAMPER_TRACE_FLAG_RXERR)
	printf(" rxerr");
      if(flags & SCAMPER_TRACE_FLAG_PTR)
	printf(" ptr");
      printf(" )");
    }
  printf("\n");

  printf(" stop reason: ");
  stop_reason = scamper_trace_stop_reason_get(trace);
  stop_data = scamper_trace_stop_data_get(trace);
  switch(stop_reason)
    {
    case SCAMPER_TRACE_STOP_NONE:
      printf("none");
      break;

    case SCAMPER_TRACE_STOP_COMPLETED:
      printf("done");
      break;

    case SCAMPER_TRACE_STOP_UNREACH:
      printf("icmp unreach %s",
	     icmp_unreach_tostr(buf, sizeof(buf),
				scamper_addr_type_get(dst), stop_data));
      break;

    case SCAMPER_TRACE_STOP_ICMP:
      printf("icmp type %d", stop_data);
      break;

    case SCAMPER_TRACE_STOP_LOOP:
      printf("loop");
      break;

    case SCAMPER_TRACE_STOP_GAPLIMIT:
      printf("gaplimit");
      break;

    case SCAMPER_TRACE_STOP_ERROR:
      printf("errno %d", stop_data);
      break;

    case SCAMPER_TRACE_STOP_HOPLIMIT:
      printf("hoplimit");
      break;

    case SCAMPER_TRACE_STOP_GSS:
      printf("dtree-gss");
      break;

    case SCAMPER_TRACE_STOP_HALTED:
      printf("halted");
      break;

    default:
      printf("reason 0x%02x data 0x%02x", stop_reason, stop_data);
      break;
    }
  printf("\n");

  for(u16=0; u16<hop_count; u16++)
    for(hop = scamper_trace_hop_get(trace, u16); hop != NULL;
	hop = scamper_trace_hop_next_get(hop))
      dump_trace_hop(trace, hop);

  /* dump any last-ditch probing hops */
  for(hop = scamper_trace_lastditch_get(trace); hop != NULL;
      hop = scamper_trace_hop_next_get(hop))
    dump_trace_hop(trace, hop);

  if((pmtud = scamper_trace_pmtud_get(trace)) != NULL)
    {
      printf("pmtud: ver %d ifmtu %d, pmtu %d",
	     scamper_trace_pmtud_ver_get(pmtud),
	     scamper_trace_pmtud_ifmtu_get(pmtud),
	     scamper_trace_pmtud_pmtu_get(pmtud));
      if((u16 = scamper_trace_pmtud_outmtu_get(pmtud)) != 0)
	printf(", outmtu %d", u16);
      if((notec = scamper_trace_pmtud_notec_get(pmtud)) != 0)
	printf(", notec %d", notec);
      printf("\n");
      for(u8=0; u8<notec; u8++)
	{
	  n = scamper_trace_pmtud_note_get(pmtud, u8);
	  hop = scamper_trace_pmtud_n_hop_get(n);
	  printf(" note %d: nhmtu %d, ", u8,
		 scamper_trace_pmtud_n_nhmtu_get(n));

	  if(hop != NULL)
	    scamper_addr_tostr(scamper_trace_hop_addr_get(hop),buf,sizeof(buf));
	  else
	    buf[0] = '\0';

	  n_type = scamper_trace_pmtud_n_type_get(n);
	  if(n_type == SCAMPER_TRACE_PMTUD_N_TYPE_PTB)
	    printf("ptb %s", buf);
	  else if(n_type == SCAMPER_TRACE_PMTUD_N_TYPE_PTB_BAD && hop != NULL)
	    printf("ptb-bad %s mtu %d", buf,
		   scamper_trace_hop_icmp_nhmtu_get(hop));
	  else if(n_type == SCAMPER_TRACE_PMTUD_N_TYPE_SILENCE)
	    printf("silence > ttl %d",
		   hop != NULL ? scamper_trace_hop_probe_ttl_get(hop) : 0);
	  else
	    printf("type-%d", n_type);
	  printf("\n");
	}
      for(hop = scamper_trace_pmtud_hops_get(pmtud); hop != NULL;
	  hop = scamper_trace_hop_next_get(hop))
	dump_trace_hop(trace, hop);
    }

  printf("\n");

  scamper_trace_free(trace);

  return;
}

static void dump_tracelb_reply(const scamper_tracelb_probe_t *probe,
			       const scamper_tracelb_reply_t *reply)
{
  const scamper_icmpext_t *ie;
  const struct timeval *tx, *rx;
  scamper_addr_t *from;
  struct timeval rtt;
  char buf[128];
  uint32_t u32;
  uint16_t m, mplsc;
  uint8_t tcp_flags;

  tx = scamper_tracelb_probe_tx_get(probe);
  rx = scamper_tracelb_reply_rx_get(reply);
  timeval_diff_tv(&rtt, tx, rx);

  if((from = scamper_tracelb_reply_from_get(reply)) != NULL)
    scamper_addr_tostr(from, buf, sizeof(buf));
  else
    snprintf(buf, sizeof(buf), "<null>");

  printf("   reply from: %s, rtt: %d.%06d, ttl: %d", buf,
	 (int)rtt.tv_sec, (int)rtt.tv_usec,
	 scamper_tracelb_reply_ttl_get(reply));

  if(from != NULL && scamper_addr_isipv4(from))
    printf(", ipid: 0x%04x", scamper_tracelb_reply_ipid_get(reply));
  printf("\n");

  if(scamper_tracelb_reply_is_tcp(reply))
    {
      tcp_flags = scamper_tracelb_reply_tcp_flags_get(reply);
      printf("     tcp flags 0x%02x", tcp_flags);
      dump_tcp_flags(tcp_flags);
      printf("\n");
    }
  else
    {
      printf("     icmp: %d/%d",
	     scamper_tracelb_reply_icmp_type_get(reply),
	     scamper_tracelb_reply_icmp_code_get(reply));
      if(scamper_tracelb_reply_is_icmp_q(reply))
	{
	  printf(", q-tos: 0x%02x, q-ttl: %d",
		 scamper_tracelb_reply_icmp_q_tos_get(reply),
		 scamper_tracelb_reply_icmp_q_ttl_get(reply));
	}
      printf("\n");

      for(ie = scamper_tracelb_reply_icmp_ext_get(reply); ie != NULL;
	  ie = scamper_icmpext_next_get(ie))
	{
	  if(scamper_icmpext_is_mpls(ie))
	    {
	      mplsc = scamper_icmpext_mpls_count_get(ie);
	      for(m=0; m<mplsc; m++)
		{
		  u32 = scamper_icmpext_mpls_label_get(ie, m);
		  printf("   %9s: label %d exp %d s %d ttl %d\n",
			 (m == 0) ? "  icmp-ext mpls" : "", u32,
			 scamper_icmpext_mpls_exp_get(ie, m),
			 scamper_icmpext_mpls_s_get(ie, m),
			 scamper_icmpext_mpls_ttl_get(ie, m));
		}
	    }
	}
    }

  return;
}

static void dump_tracelb_probe(const scamper_tracelb_t *trace,
			       const scamper_tracelb_probe_t *probe)
{
  const struct timeval *tx;
  uint16_t i, rxc;

  tx = scamper_tracelb_probe_tx_get(probe);
  printf("  probe flowid: %d, ttl: %d, attempt: %d, tx: %d.%06d\n",
	 scamper_tracelb_probe_flowid_get(probe),
	 scamper_tracelb_probe_ttl_get(probe),
	 scamper_tracelb_probe_attempt_get(probe),
	 (int)tx->tv_sec, (int)tx->tv_usec);

  rxc = scamper_tracelb_probe_rxc_get(probe);
  for(i=0; i<rxc; i++)
    dump_tracelb_reply(probe, scamper_tracelb_probe_rx_get(probe, i));

  return;
}

static void dump_tracelb(scamper_tracelb_t *trace)
{
  static const char *flags[] = {
    "ptr"
  };
  const scamper_tracelb_link_t *link;
  const scamper_tracelb_node_t *node, *from, *to;
  const scamper_tracelb_probeset_t *set;
  const char *name;
  scamper_addr_t *addr;
  uint32_t u32;
  uint16_t i, j, l, nodec, linkc, probec;
  uint8_t u8, k, hopc;
  char buf[256], src[256];

  printf("tracelb");
  if((addr = scamper_tracelb_src_get(trace)) != NULL)
    printf(" from %s", scamper_addr_tostr(addr, src, sizeof(src)));
  addr = scamper_tracelb_dst_get(trace);
  printf(" to %s\n", scamper_addr_tostr(addr, buf, sizeof(buf)));

  dump_list_summary(scamper_tracelb_list_get(trace));
  dump_cycle_summary(scamper_tracelb_cycle_get(trace));
  printf(" user-id: %d\n", scamper_tracelb_userid_get(trace));
  if((addr = scamper_tracelb_rtr_get(trace)) != NULL)
    printf(" rtr: %s\n", scamper_addr_tostr(addr, buf, sizeof(buf)));
  dump_timeval("start", scamper_tracelb_start_get(trace));

  printf(" type: ");
  switch((u8 = scamper_tracelb_type_get(trace)))
    {
    case SCAMPER_TRACELB_TYPE_ICMP_ECHO:
      printf("%s id: %d", scamper_tracelb_type_tostr(trace, buf, sizeof(buf)),
	     scamper_tracelb_sport_get(trace));
      break;

    case SCAMPER_TRACELB_TYPE_UDP_DPORT:
    case SCAMPER_TRACELB_TYPE_UDP_SPORT:
    case SCAMPER_TRACELB_TYPE_TCP_SPORT:
    case SCAMPER_TRACELB_TYPE_TCP_ACK_SPORT:
      printf("%s %d:%d", scamper_tracelb_type_tostr(trace, buf, sizeof(buf)),
	     scamper_tracelb_sport_get(trace),
	     scamper_tracelb_dport_get(trace));
      break;

    default:
      printf("%d", u8);
      break;
    }
  printf(", tos: 0x%02x\n", scamper_tracelb_tos_get(trace));

  printf(" firsthop: %d, attempts: %d, confidence: %d\n",
	 scamper_tracelb_firsthop_get(trace),
	 scamper_tracelb_attempts_get(trace),
	 scamper_tracelb_confidence_get(trace));
  printf(" probe-size: %d", scamper_tracelb_probe_size_get(trace));
  dump_wait(", wait-probe", scamper_tracelb_wait_probe_get(trace));
  dump_wait(", wait-timeout", scamper_tracelb_wait_timeout_get(trace));
  printf("\n");

  printf(" nodec: %d, linkc: %d, probec: %d, probec_max: %d\n",
	 scamper_tracelb_nodec_get(trace), scamper_tracelb_linkc_get(trace),
	 scamper_tracelb_probec_get(trace),
	 scamper_tracelb_probec_max_get(trace));
  if((u32 = scamper_tracelb_flags_get(trace)) != 0)
    {
      printf(" flags:");
      l = 0;
      for(i=0; i<1; i++)
	{
	  if((u32 & (0x1 << i)) == 0)
	    continue;
	  if(l > 0)
	    printf(",");
	  printf(" %s", flags[i]);
	  l++;
	}
      printf("\n");
    }

  nodec = scamper_tracelb_nodec_get(trace);
  for(i=0; i<nodec; i++)
    {
      node = scamper_tracelb_node_get(trace, i);

      if((addr = scamper_tracelb_node_addr_get(node)) != NULL)
	scamper_addr_tostr(addr, buf, sizeof(buf));
      else
	snprintf(buf, sizeof(buf), "*");

      printf("node %d %s", i, buf);
      if(scamper_tracelb_node_is_q_ttl(node) != 0)
	printf(", q-ttl %d", scamper_tracelb_node_q_ttl_get(node));
      if((name = scamper_tracelb_node_name_get(node)) != NULL)
	printf(", name %s", name);
      printf("\n");

      linkc = scamper_tracelb_node_linkc_get(node);
      for(j=0; j<linkc; j++)
	{
	  link = scamper_tracelb_node_link_get(node, j);
	  from = scamper_tracelb_link_from_get(link);
	  to = scamper_tracelb_link_to_get(link);
	  if((addr = scamper_tracelb_node_addr_get(from)) != NULL)
	    scamper_addr_tostr(addr, src, sizeof(buf));
	  else
	    snprintf(src, sizeof(src), "*");
	  if(to != NULL)
	    {
	      if((addr = scamper_tracelb_node_addr_get(to)) != NULL)
		scamper_addr_tostr(addr, buf, sizeof(buf));
	      else
		snprintf(buf, sizeof(buf), "<null>");
	    }
	  else snprintf(buf, sizeof(buf), "*");
	  hopc = scamper_tracelb_link_hopc_get(link);
	  printf(" link %s -> %s hopc %d\n", src, buf, hopc);

	  for(k=0; k<hopc; k++)
	    {
	      set = scamper_tracelb_link_probeset_get(link, k);
	      probec = scamper_tracelb_probeset_probec_get(set);
	      for(l=0; l<probec; l++)
		dump_tracelb_probe(trace,
				   scamper_tracelb_probeset_probe_get(set, l));
	    }
	}
    }
  printf("\n");

  scamper_tracelb_free(trace);
  return;
}

static char *ping_tsreply_tostr(char *buf, size_t len, uint32_t val)
{
  uint32_t hh, mm, ss, ms;
  ms = val % 1000;
  ss = val / 1000;
  hh = ss / 3600; ss -= (hh * 3600);
  mm = ss / 60; ss -= (mm * 60);
  snprintf(buf, len, "%02d:%02d:%02d.%03d", hh, mm, ss, ms);
  return buf;
}

static void dump_ping_reply(const scamper_ping_t *ping,
			    const scamper_ping_reply_t *reply)
{
  const scamper_ping_reply_v4rr_t *v4rr;
  const scamper_ping_reply_v4ts_t *v4ts;
  const scamper_ping_reply_tsreply_t *tsreply;
  const struct timeval *start, *tx, *rtt;
  const char *str;
  scamper_addr_t *addr;
  uint32_t flags, tso, tsr, tst, tsc;
  uint16_t probe_id, sport;
  uint8_t i, ipc;
  char buf[256];
  struct timeval txoff;

  start = scamper_ping_start_get(ping);
  addr = scamper_ping_reply_addr_get(reply);
  tx = scamper_ping_reply_tx_get(reply);
  rtt = scamper_ping_reply_rtt_get(reply);
  probe_id = scamper_ping_reply_probe_id_get(reply);
  printf("reply from %s, attempt: %d",
	 scamper_addr_tostr(addr, buf, sizeof(buf)), probe_id+1);
  if(timeval_cmp(tx, start) >= 0)
    {
      timeval_diff_tv(&txoff, start, tx);
      printf(", tx: %d.%06ds", (int)txoff.tv_sec, (int)txoff.tv_usec);
    }
  printf(", rtt: %d.%06ds\n", (int)rtt->tv_sec, (int)rtt->tv_usec);

  printf(" size: %d", scamper_ping_reply_size_get(reply));
  flags = scamper_ping_reply_flags_get(reply);
  if(flags & SCAMPER_PING_REPLY_FLAG_REPLY_TTL)
    printf(", ttl: %d", scamper_ping_reply_ttl_get(reply));
  if(flags & SCAMPER_PING_REPLY_FLAG_REPLY_TOS)
    printf(", tos: 0x%02x", scamper_ping_reply_tos_get(reply));
  if((sport = scamper_ping_reply_probe_sport_get(reply)) != 0)
    printf(", probe-sport: %u", sport);
  if(flags & SCAMPER_PING_REPLY_FLAG_PROBE_IPID)
    printf(", probe-ipid: 0x%04x", scamper_ping_reply_probe_ipid_get(reply));
  if((str = scamper_ping_reply_ifname_get(reply)) != NULL)
    printf(", ifname: %s", str);
  if(flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID)
    {
      if(scamper_addr_isipv4(addr))
	printf(", reply-ipid: 0x%04x", scamper_ping_reply_ipid_get(reply));
      else
	printf(", reply-ipid32: 0x%08x", scamper_ping_reply_ipid32_get(reply));
    }
  if(flags & SCAMPER_PING_REPLY_FLAG_DLTX)
    printf(", dltx");
  if(flags & SCAMPER_PING_REPLY_FLAG_DLRX)
    printf(", dlrx");
  printf("\n");

  if(scamper_ping_reply_is_icmp(reply))
    {
      printf(" icmp type: %d, code: %d\n",
	     scamper_ping_reply_icmp_type_get(reply),
	     scamper_ping_reply_icmp_code_get(reply));
    }
  else if(scamper_ping_reply_is_tcp(reply))
    {
      i = scamper_ping_reply_tcp_flags_get(reply);
      printf(" tcp flags: %02x", i);
      dump_tcp_flags(i);
      printf("\n");
    }

  if((tsreply = scamper_ping_reply_tsreply_get(reply)) != NULL)
    {
      tso = scamper_ping_reply_tsreply_tso_get(tsreply);
      tsr = scamper_ping_reply_tsreply_tsr_get(tsreply);
      tst = scamper_ping_reply_tsreply_tst_get(tsreply);
      printf(" icmp-tsreply:");
      printf(" tso=%s", ping_tsreply_tostr(buf, sizeof(buf), tso));
      printf(" tsr=%s", ping_tsreply_tostr(buf, sizeof(buf), tsr));
      printf(" tst=%s\n", ping_tsreply_tostr(buf, sizeof(buf), tst));
    }

  if((v4rr = scamper_ping_reply_v4rr_get(reply)) != NULL)
    {
      printf(" record route:");
      ipc = scamper_ping_reply_v4rr_ipc_get(v4rr);
      for(i=0; i<ipc; i++)
	{
	  if((i % 3) == 0 && i != 0)
	    printf("\n              ");
	  addr = scamper_ping_reply_v4rr_ip_get(v4rr, i);
	  printf(" %-15s", scamper_addr_tostr(addr, buf, sizeof(buf)));
	}
      printf("\n");
    }

  if((v4ts = scamper_ping_reply_v4ts_get(reply)) != NULL)
    {
      tsc = scamper_ping_reply_v4ts_tsc_get(v4ts);
      printf(" IP timestamp option: tsc %d", tsc);
      if(scamper_ping_reply_v4ts_hasip(v4ts))
	{
	  for(i=0; i<tsc; i++)
	    {
	      if((i % 2) == 0)
		printf("\n  ");
	      else if(i != 0)
		printf("    ");
	      addr = scamper_ping_reply_v4ts_ip_get(v4ts, i);
	      printf("%-15s 0x%08x",
		     scamper_addr_tostr(addr, buf, sizeof(buf)),
		     scamper_ping_reply_v4ts_ts_get(v4ts, i));
	    }
	}
      else
	{
	  for(i=0; i<tsc; i++)
	    {
	      if((i % 3) == 0)
		printf("\n  ");
	      printf(" 0x%08x", scamper_ping_reply_v4ts_ts_get(v4ts, i));
	    }
	}
      printf("\n");
    }

  return;
}

static void dump_ping(scamper_ping_t *ping)
{
  static const char *flagstr[] = {
    "v4rr", "spoof", "payload", "tsonly", "tsandaddr", "icmpsum", "dl", "tbt",
    "nosrc",
  };
  const scamper_ping_reply_t *reply;
  const scamper_ping_v4ts_t *v4ts;
  const uint8_t *probe_data;
  scamper_addr_t *addr;
  char buf[256];
  uint32_t u32, flags;
  uint16_t u16, ping_sent, probe_datalen;
  uint8_t u8, ipc;

  flags = scamper_ping_flags_get(ping);
  scamper_addr_tostr(scamper_ping_src_get(ping), buf, sizeof(buf));
  printf("ping from %s", buf);
  if(flags & SCAMPER_PING_FLAG_SPOOF)
    printf(" (spoofed)");
  scamper_addr_tostr(scamper_ping_dst_get(ping), buf, sizeof(buf));
  printf(" to %s\n", buf);

  dump_list_summary(scamper_ping_list_get(ping));
  dump_cycle_summary(scamper_ping_cycle_get(ping));
  printf(" user-id: %d\n", scamper_ping_userid_get(ping));
  if((addr = scamper_ping_rtr_get(ping)) != NULL)
    printf(" rtr: %s\n", scamper_addr_tostr(addr, buf, sizeof(buf)));
  dump_timeval("start", scamper_ping_start_get(ping));

  printf(" probe-count: %d", scamper_ping_probe_count_get(ping));
  if((u16 = scamper_ping_reply_count_get(ping)) > 0)
    printf(", replies-req: %d", u16);
  printf(", size: %d", scamper_ping_probe_size_get(ping));
  if((u16 = scamper_ping_reply_pmtu_get(ping)) > 0)
    printf(", reply-pmtu: %d", u16);
  dump_wait(", wait", scamper_ping_wait_probe_get(ping));
  dump_wait(", timeout", scamper_ping_wait_timeout_get(ping));
  printf(", ttl: %u, tos: 0x%02x\n", scamper_ping_probe_ttl_get(ping),
	 scamper_ping_probe_tos_get(ping));

  if(flags != 0)
    {
      printf(" flags:");
      u32 = 0;
      for(u8=0; u8<9; u8++)
	{
	  if((flags & (0x1 << u8)) == 0)
	    continue;
	  if(u32 > 0)
	    printf(",");
	  printf(" %s", flagstr[u8]);
	  u32++;
	}
      printf("\n");
    }

  printf(" method: %s", scamper_ping_method_tostr(ping, buf, sizeof(buf)));
  switch(scamper_ping_probe_method_get(ping))
    {
    case SCAMPER_PING_METHOD_ICMP_ECHO:
    case SCAMPER_PING_METHOD_ICMP_TIME:
      printf(", icmp-id: %d", scamper_ping_probe_sport_get(ping));
      if((flags & SCAMPER_PING_FLAG_ICMPSUM) != 0)
	printf(", icmp-csum: %04x", scamper_ping_probe_icmpsum_get(ping));
      break;

    case SCAMPER_PING_METHOD_UDP:
    case SCAMPER_PING_METHOD_TCP_ACK:
    case SCAMPER_PING_METHOD_TCP_SYN:
    case SCAMPER_PING_METHOD_TCP_RST:
    case SCAMPER_PING_METHOD_TCP_SYNACK:
      printf(", sport: %d, dport: %d",
	     scamper_ping_probe_sport_get(ping),
	     scamper_ping_probe_dport_get(ping));
      break;

    case SCAMPER_PING_METHOD_TCP_ACK_SPORT:
    case SCAMPER_PING_METHOD_TCP_SYN_SPORT:
      printf(", base-sport: %d, dport: %d",
	     scamper_ping_probe_sport_get(ping),
	     scamper_ping_probe_dport_get(ping));
      break;

    case SCAMPER_PING_METHOD_UDP_DPORT:
      printf(", sport: %d, base-dport %d",
	     scamper_ping_probe_sport_get(ping),
	     scamper_ping_probe_dport_get(ping));
      break;
    }

  if(scamper_ping_method_is_tcp(ping))
    printf(", seq: %u, ack: %u",
	   scamper_ping_probe_tcpseq_get(ping),
	   scamper_ping_probe_tcpack_get(ping));

  printf("\n");

  if((v4ts = scamper_ping_probe_tsps_get(ping)) != NULL)
    {
      printf(" timestamp-prespec:");
      ipc = scamper_ping_v4ts_ipc_get(v4ts);
      for(u8=0; u8<ipc; u8++)
	{
	  addr = scamper_ping_v4ts_ip_get(v4ts, u8);
	  printf(" %s", scamper_addr_tostr(addr, buf, sizeof(buf)));
	}
      printf("\n");
    }

  /* dump pad bytes, if used */
  if((probe_datalen = scamper_ping_probe_datalen_get(ping)) > 0 &&
     (probe_data = scamper_ping_probe_data_get(ping)) != NULL)
    {
      if((flags & SCAMPER_PING_FLAG_PAYLOAD) != 0)
	printf(" payload");
      else
	printf(" pattern");
      printf(" bytes (%d): ", probe_datalen);
      for(u16=0; u16<probe_datalen; u16++)
	printf("%02x", probe_data[u16]);
      printf("\n");
    }

  ping_sent = scamper_ping_sent_get(ping);
  printf(" probes-sent: %d, stop-reason: ", ping_sent);
  switch(scamper_ping_stop_reason_get(ping))
    {
    case SCAMPER_PING_STOP_NONE:
      printf("none"); break;

    case SCAMPER_PING_STOP_COMPLETED:
      printf("done"); break;

    case SCAMPER_PING_STOP_ERROR:
      printf("sendto errno %d", scamper_ping_stop_data_get(ping)); break;

    case SCAMPER_PING_STOP_HALTED:
      printf("halted"); break;

    default:
      printf("reason 0x%02x data 0x%02x",
	     scamper_ping_stop_reason_get(ping),
	     scamper_ping_stop_data_get(ping));
      break;
    }
  printf("\n");

  for(u16=0; u16<ping_sent; u16++)
    {
      for(reply = scamper_ping_reply_get(ping, u16); reply != NULL;
	  reply = scamper_ping_reply_next_get(reply))
	{
	  dump_ping_reply(ping, reply);
	}
    }

  printf("\n");

  scamper_ping_free(ping);

  return;
}

static void dump_dealias_probedef(const scamper_dealias_probedef_t *def)
{
  const scamper_dealias_probedef_icmp_t *icmp;
  const scamper_dealias_probedef_udp_t *udp;
  const scamper_dealias_probedef_tcp_t *tcp;
  scamper_addr_t *addr;
  char dst[128], src[128];
  uint16_t u16;
  uint8_t method;

  addr = scamper_dealias_probedef_dst_get(def);
  scamper_addr_tostr(addr, dst, sizeof(dst));
  addr = scamper_dealias_probedef_src_get(def);
  scamper_addr_tostr(addr, src, sizeof(src));

  printf(" probedef %d: dst: %s, ttl: %d, tos: 0x%02x\n  src: %s",
	 scamper_dealias_probedef_id_get(def), dst,
	 scamper_dealias_probedef_ttl_get(def),
	 scamper_dealias_probedef_tos_get(def), src);

  if((u16 = scamper_dealias_probedef_size_get(def)) > 0)
    printf(", size: %d", u16);
  if((u16 = scamper_dealias_probedef_mtu_get(def)) > 0)
    printf(", mtu: %d", u16);
  printf("\n");

  method = scamper_dealias_probedef_method_get(def);

  if((icmp = scamper_dealias_probedef_icmp_get(def)) != NULL)
    {
      printf("  icmp-echo csum: %04x, id: %04x\n",
	     scamper_dealias_probedef_icmp_csum_get(icmp),
	     scamper_dealias_probedef_icmp_id_get(icmp));
    }
  else if((udp = scamper_dealias_probedef_udp_get(def)) != NULL)
    {
      if(method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP)
	printf("  udp");
      else if(method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT)
	printf("  udp-dport");
      else
	printf("  udp-%d", method);
      printf(" %d:%d\n",
	     scamper_dealias_probedef_udp_sport_get(udp),
	     scamper_dealias_probedef_udp_dport_get(udp));
    }
  else if((tcp = scamper_dealias_probedef_tcp_get(def)) != NULL)
    {
      if(method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	printf("  tcp-ack");
      else if(method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT)
	printf("  tcp-ack-sport");
      else if(method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_SYN_SPORT)
	printf("  tcp-syn-sport");
      else
	printf("  tcp-%d", method);
      printf(" %d:%d ",
	     scamper_dealias_probedef_tcp_sport_get(tcp),
	     scamper_dealias_probedef_tcp_dport_get(tcp));
      dump_tcp_flags(scamper_dealias_probedef_tcp_flags_get(tcp));
      printf("\n");
    }
  else
    {
      printf("%d\n", method);
    }
  return;
}

static void dump_dealias(scamper_dealias_t *dealias)
{
  const scamper_dealias_prefixscan_t *ps;
  const scamper_dealias_mercator_t *mercator;
  const scamper_dealias_radargun_t *radargun;
  const scamper_dealias_ally_t *ally;
  const scamper_dealias_bump_t *bump;
  const scamper_dealias_midarest_t *me;
  const scamper_dealias_midardisc_t *md;
  const scamper_dealias_midardisc_round_t *r;
  const scamper_dealias_probe_t *probe;
  const scamper_dealias_reply_t *reply;
  const scamper_dealias_probedef_t *def;
  const struct timeval *tx, *rx;
  scamper_addr_t *a, *b, *ab, *src, *dst;
  struct timeval rtt;
  const struct timeval *tv;
  uint32_t i, probec, probedefc, begin, end;
  uint16_t u16, xc, replyc, reply_size;
  uint8_t u8, method, result;
  char buf[256];
  int j;

  method = scamper_dealias_method_get(dealias);

  /* first line: dealias */
  printf("dealias");
  if(method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    {
      mercator = scamper_dealias_mercator_get(dealias);
      def = scamper_dealias_mercator_def_get(mercator);
      scamper_addr_tostr(scamper_dealias_probedef_src_get(def),buf,sizeof(buf));
      printf(" from %s", buf);
      scamper_addr_tostr(scamper_dealias_probedef_dst_get(def),buf,sizeof(buf));
      printf(" to %s", buf);
    }
  printf("\n");

  /* dump list, cycle, start time */
  dump_list_summary(scamper_dealias_list_get(dealias));
  dump_cycle_summary(scamper_dealias_cycle_get(dealias));
  printf(" user-id: %d\n", scamper_dealias_userid_get(dealias));
  dump_timeval("start", scamper_dealias_start_get(dealias));

  /* method headers */
  printf(" method: ");
  if(method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    {
      printf("mercator, attempts: %d",
	     scamper_dealias_mercator_attempts_get(mercator));
      dump_wait(", timeout",
		scamper_dealias_mercator_wait_timeout_get(mercator));
      printf("\n");
      dump_dealias_probedef(def);
    }
  else if(method == SCAMPER_DEALIAS_METHOD_ALLY)
    {
      ally = scamper_dealias_ally_get(dealias);
      printf("ally, attempts: %d, fudge: %d",
	     scamper_dealias_ally_attempts_get(ally),
	     scamper_dealias_ally_fudge_get(ally));
      dump_wait(", wait-probe", scamper_dealias_ally_wait_probe_get(ally));
      dump_wait(", wait-timeout", scamper_dealias_ally_wait_timeout_get(ally));
      if(scamper_dealias_ally_is_nobs(ally))
	printf(", nobs");
      printf("\n");
      dump_dealias_probedef(scamper_dealias_ally_def0_get(ally));
      dump_dealias_probedef(scamper_dealias_ally_def1_get(ally));
    }
  else if(method == SCAMPER_DEALIAS_METHOD_BUMP)
    {
      bump = scamper_dealias_bump_get(dealias);
      printf("bump, attempts: %d",
	     scamper_dealias_bump_attempts_get(bump));
      dump_wait(", wait-probe", scamper_dealias_bump_wait_probe_get(bump));
      printf(", bump-limit: %d\n",
	     scamper_dealias_bump_limit_get(bump));
      dump_dealias_probedef(scamper_dealias_bump_def0_get(bump));
      dump_dealias_probedef(scamper_dealias_bump_def1_get(bump));
    }
  else if(method == SCAMPER_DEALIAS_METHOD_RADARGUN)
    {
      radargun = scamper_dealias_radargun_get(dealias);
      printf("radargun, rounds: %d, probedefc: %d\n",
	     scamper_dealias_radargun_rounds_get(radargun),
	     scamper_dealias_radargun_defc_get(radargun));
      dump_wait("  wait-probe",
		scamper_dealias_radargun_wait_probe_get(radargun));
      dump_wait(", wait-round",
		scamper_dealias_radargun_wait_round_get(radargun));
      dump_wait(", wait-timeout",
		scamper_dealias_radargun_wait_timeout_get(radargun));
      printf("\n");

      if((u8 = scamper_dealias_radargun_flags_get(radargun)) != 0)
	{
	  printf("  flags: ");
	  for(i=0; i<8; i++)
	    {
	      if((u8 & (1 << i)) == 0)
		continue;
	      switch(1 << i)
		{
		case SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE:
		  printf("shuffle");
		  break;

		default:
		  printf("0x%02x", 1<<i);
		  break;
		}

	      u8 &= ~(1 << i);
	      if(u8 != 0)
		printf(", ");
	      else
		break;
	    }
	  printf("\n");
	}
      probedefc = scamper_dealias_radargun_defc_get(radargun);
      for(i=0; i<probedefc; i++)
	dump_dealias_probedef(scamper_dealias_radargun_def_get(radargun, i));
    }
  else if(method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    {
      ps = scamper_dealias_prefixscan_get(dealias);
      a = scamper_dealias_prefixscan_a_get(ps);
      b = scamper_dealias_prefixscan_b_get(ps);
      printf("prefixscan, %s:", scamper_addr_tostr(a, buf, sizeof(buf)));
      printf("%s/%d", scamper_addr_tostr(b, buf, sizeof(buf)),
	     scamper_dealias_prefixscan_prefix_get(ps));
      if((ab = scamper_dealias_prefixscan_ab_get(ps)) != NULL)
	printf(", alias: %s/%d", scamper_addr_tostr(ab, buf, sizeof(buf)),
	       scamper_addr_prefixhosts(b, ab));
      printf("\n");

      printf("  attempts: %d, replyc: %d, fudge: %d",
	     scamper_dealias_prefixscan_attempts_get(ps),
	     scamper_dealias_prefixscan_replyc_get(ps),
	     scamper_dealias_prefixscan_fudge_get(ps));
      dump_wait(", wait-probe",
		scamper_dealias_prefixscan_wait_probe_get(ps));
      dump_wait(", wait-timeout",
		scamper_dealias_prefixscan_wait_timeout_get(ps));
      if(scamper_dealias_prefixscan_is_nobs(ps))
	printf(", nobs");
      printf("\n");
      if((xc = scamper_dealias_prefixscan_xc_get(ps)) > 0)
	{
	  printf("  exclude:");
	  for(u16=0; u16<xc; u16++)
	    {
	      a = scamper_dealias_prefixscan_xs_get(ps, u16);
	      printf(" %s", scamper_addr_tostr(a, buf, sizeof(buf)));
	    }
	  printf("\n");
	}
      probedefc = scamper_dealias_prefixscan_defc_get(ps);
      for(i=0; i<probedefc; i++)
	dump_dealias_probedef(scamper_dealias_prefixscan_def_get(ps, i));
    }
  else if(method == SCAMPER_DEALIAS_METHOD_MIDAREST)
    {
      me = scamper_dealias_midarest_get(dealias);
      printf("midarest");
      dump_wait(", wait-probe", scamper_dealias_midarest_wait_probe_get(me));
      dump_wait(", wait-round", scamper_dealias_midarest_wait_round_get(me));
      printf("\n");
      dump_wait("  wait-timeout", scamper_dealias_midarest_wait_timeout_get(me));
      probedefc = scamper_dealias_midarest_defc_get(me);
      printf(", rounds: %d, probedefc: %d\n",
	     scamper_dealias_midarest_rounds_get(me),
	     probedefc);
      for(i=0; i<probedefc; i++)
	dump_dealias_probedef(scamper_dealias_midarest_def_get(me, i));
    }
  else if(method == SCAMPER_DEALIAS_METHOD_MIDARDISC)
    {
      md = scamper_dealias_midardisc_get(dealias);
      printf("midardisc");
      dump_wait(", wait-timeout",
		scamper_dealias_midardisc_wait_timeout_get(md));
      probedefc = scamper_dealias_midardisc_defc_get(md);
      printf(", probedefc: %d\n", probedefc);
      if((tv = scamper_dealias_midardisc_startat_get(md)) != NULL)
	dump_timeval("startat", tv);
      probec = 0;
      for(i=0; i<scamper_dealias_midardisc_schedc_get(md); i++)
	{
	  r = scamper_dealias_midardisc_sched_get(md, i);
	  tx = scamper_dealias_midardisc_round_start_get(r);
	  begin = scamper_dealias_midardisc_round_begin_get(r);
	  end = scamper_dealias_midardisc_round_end_get(r);
	  printf("  round %d: %u.%06u %u %u, %u-%u\n", i,
		 (uint32_t)tx->tv_sec, (uint32_t)tx->tv_usec, begin, end,
		 probec, probec + (end - begin));
	  probec += (end - begin + 1);
	}
      for(i=0; i<probedefc; i++)
	dump_dealias_probedef(scamper_dealias_midardisc_def_get(md, i));
    }
  else
    {
      printf("%d\n", method);
    }

  probec = scamper_dealias_probec_get(dealias);
  result = scamper_dealias_result_get(dealias);
  printf(" probes: %d, result: %s", probec,
	 scamper_dealias_result_tostr(result, buf, sizeof(buf)));

  if(method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN &&
     scamper_dealias_prefixscan_is_csa(ps))
    printf(", csa");
  printf("\n");

  for(i=0; i<probec; i++)
    {
      probe = scamper_dealias_probe_get(dealias, i);
      tx = scamper_dealias_probe_tx_get(probe);
      def = scamper_dealias_probe_def_get(probe);
      dst = scamper_dealias_probedef_dst_get(def);
      printf(" probe: %d, def: %d, seq: %d, tx: %d.%06d",
	     i, scamper_dealias_probedef_id_get(def),
	     scamper_dealias_probe_seq_get(probe),
	     (int)tx->tv_sec, (int)tx->tv_usec);
      if(scamper_addr_isipv4(dst))
	printf(", ipid: %04x", scamper_dealias_probe_ipid_get(probe));
      printf("\n");

      replyc = scamper_dealias_probe_replyc_get(probe);
      for(j=0; j<replyc; j++)
	{
	  reply = scamper_dealias_probe_reply_get(probe, j);
	  src = scamper_dealias_reply_src_get(reply);
	  rx = scamper_dealias_reply_rx_get(reply);
	  timeval_diff_tv(&rtt, tx, rx);
	  printf("  reply: %d, src: %s, ttl: %d, rtt: %d.%06d",
		 j, scamper_addr_tostr(src, buf, sizeof(buf)),
		 scamper_dealias_reply_ttl_get(reply),
		 (int)rtt.tv_sec, (int)rtt.tv_usec);
	  if((reply_size = scamper_dealias_reply_size_get(reply)) != 0)
	    printf(", size: %d", reply_size);
	  if(scamper_addr_isipv4(src))
	    printf(", ipid: %04x", scamper_dealias_reply_ipid_get(reply));
	  else if(scamper_dealias_reply_is_ipid32(reply))
	    printf(", ipid32: %08x", scamper_dealias_reply_ipid32_get(reply));
	  printf("\n");

	  if(scamper_dealias_reply_is_icmp(reply))
	    {
	      printf("  icmp-type: %d, icmp-code: %d",
		     scamper_dealias_reply_icmp_type_get(reply),
		     scamper_dealias_reply_icmp_code_get(reply));
	      if(scamper_dealias_reply_is_icmp_q(reply))
		printf(", icmp-q-ttl: %d",
		       scamper_dealias_reply_icmp_q_ttl_get(reply));
	      printf("\n");
	    }
	  else if(scamper_dealias_reply_is_tcp(reply))
	    {
	      printf("   tcp flags:");
	      dump_tcp_flags(scamper_dealias_reply_tcp_flags_get(reply));
	      printf("\n");
	    }
	  else
	    {
	      printf("  reply proto %d\n",
		     scamper_dealias_reply_proto_get(reply));
	    }
	}
    }

  printf("\n");

  scamper_dealias_free(dealias);
  return;
}

static void dump_neighbourdisc(scamper_neighbourdisc_t *nd)
{
  const scamper_neighbourdisc_probe_t *probe;
  const scamper_neighbourdisc_reply_t *reply;
  const struct timeval *tx;
  scamper_addr_t *addr;
  struct timeval rtt;
  uint16_t i, j, probec, replyc;
  uint8_t method, flags;
  char dst[128], buf[128];

  printf("neighbourdisc\n");
  dump_list_summary(scamper_neighbourdisc_list_get(nd));
  dump_cycle_summary(scamper_neighbourdisc_cycle_get(nd));
  printf(" user-id: %d\n", scamper_neighbourdisc_userid_get(nd));
  dump_timeval("start", scamper_neighbourdisc_start_get(nd));

  method = scamper_neighbourdisc_method_get(nd);
  if(method == SCAMPER_NEIGHBOURDISC_METHOD_ARP ||
     method == SCAMPER_NEIGHBOURDISC_METHOD_ND_NSOL)
    {
      if(method == SCAMPER_NEIGHBOURDISC_METHOD_ARP)
	printf(" method: arp");
      else
	printf(" method: ipv6 nsol");

      printf(", attempts: %d",
	     scamper_neighbourdisc_attempts_get(nd));
      dump_wait(", wait-timeout", scamper_neighbourdisc_wait_timeout_get(nd));
      printf(", replyc: %d, iface: %s\n",
	     scamper_neighbourdisc_replyc_get(nd),
	     scamper_neighbourdisc_ifname_get(nd));
      printf(" our-mac: %s\n",
	     scamper_addr_tostr(scamper_neighbourdisc_src_mac_get(nd),
				buf, sizeof(buf)));

      flags = scamper_neighbourdisc_flags_get(nd);
      printf(" flags: 0x%02x", flags);
      if(flags != 0)
	{
	  printf(" (");
	  if(flags & SCAMPER_NEIGHBOURDISC_FLAG_ALLATTEMPTS)
	    printf(" all-attempts");
	  if(flags & SCAMPER_NEIGHBOURDISC_FLAG_FIRSTRESPONSE)
	    printf(" first-response");
	  printf(" )");
	}
      printf("\n");
      scamper_addr_tostr(scamper_neighbourdisc_dst_ip_get(nd),dst,sizeof(dst));
      printf(" query:  who-has %s", dst);
      if((addr = scamper_neighbourdisc_src_ip_get(nd)) != NULL)
	printf(" tell %s", scamper_addr_tostr(addr, buf, sizeof(buf)));
      if((addr = scamper_neighbourdisc_dst_mac_get(nd)) != NULL)
	printf(" result: %s is-at %s\n", dst,
	       scamper_addr_tostr(addr, buf, sizeof(buf)));
    }

  probec = scamper_neighbourdisc_probec_get(nd);
  for(i=0; i<probec; i++)
    {
      probe = scamper_neighbourdisc_probe_get(nd, i);
      tx = scamper_neighbourdisc_probe_tx_get(probe);
      printf(" probe: %d, tx: %d.%06d\n",i, (int)tx->tv_sec, (int)tx->tv_usec);

      replyc = scamper_neighbourdisc_probe_replyc_get(probe);
      for(j=0; j<replyc; j++)
	{
	  reply = scamper_neighbourdisc_probe_reply_get(probe, j);
	  timeval_diff_tv(&rtt, tx,
			  scamper_neighbourdisc_reply_rx_get(reply));
	  printf("  reply: %d, rtt: %d.%06d, mac: %s\n",
		 i, (int)rtt.tv_sec, (int)rtt.tv_usec,
		 scamper_addr_tostr(scamper_neighbourdisc_reply_mac_get(reply),
				    buf, sizeof(buf)));
	}
    }

  printf("\n");

  scamper_neighbourdisc_free(nd);
  return;
}

static void tbit_bits_print(uint32_t flags,int bits, const char **f2s,int f2sc)
{
  int i, f = 0;
  uint32_t u32;

  if(flags == 0)
    return;
  for(i=0; i<bits; i++)
    {
      if((u32 = flags & (0x1 << i)) == 0) continue;
      if(f > 0) printf(",");
      if(i < f2sc)
	printf(" %s", f2s[i]);
      else
	printf(" 0x%x", u32);
      f++;
    }
  return;
}

static uint32_t tbit_isnoff(uint32_t isn, uint32_t seq)
{
  if(seq >= isn)
    return seq - isn;
  return TCP_MAX_SEQNUM - isn + seq + 1;
}

static void dump_tbit(scamper_tbit_t *tbit)
{
  static const char *tbit_options[] = {"tcpts", "sack"};
  static const char *null_options[] = {"tcpts", "ipts-syn", "iprr-syn",
				       "ipqs-syn", "sack", "fo", "fo-exp"};
  static const char *null_results[] = {"tcpts-ok", "sack-ok", "fo-ok"};
  const scamper_tbit_pmtud_t *pmtud;
  const scamper_tbit_null_t *null;
  const scamper_tbit_icw_t *icw;
  const scamper_tbit_blind_t *blind;
  const scamper_tbit_app_http_t *http;
  const scamper_tbit_app_bgp_t *bgp;
  const scamper_tbit_pkt_t *pkt;
  const struct timeval *start;
  const uint8_t *fo_cookie, *pkt_data, *tmp;
  scamper_addr_t *addr;
  struct timeval diff;
  uint16_t len, u16, datalen;
  uint8_t proto, flags, iphlen, tcphlen, mf, ecn, u8, txsyn, rxsyn, dir;
  uint32_t i, seq, ack, server_isn, client_isn, off, u32, pktc;
  char src[64], dst[64], buf[128], ipid[12], fstr[32], tfstr[32], sack[64];
  const char *host, *file;
  uint8_t cookie[16], cookielen;
  char *str;
  size_t soff;
  int frag;

  /* Start dumping the tbit test information */
  printf("tbit from %s to %s\n",
	 scamper_addr_tostr(scamper_tbit_src_get(tbit), src, sizeof(src)),
	 scamper_addr_tostr(scamper_tbit_dst_get(tbit), dst, sizeof(dst)));

  dump_list_summary(scamper_tbit_list_get(tbit));
  dump_cycle_summary(scamper_tbit_cycle_get(tbit));
  printf(" user-id: %d\n", scamper_tbit_userid_get(tbit));
  start = scamper_tbit_start_get(tbit);
  dump_timeval("start", start);

  printf(" sport: %d, dport: %d\n",
	 scamper_tbit_sport_get(tbit), scamper_tbit_dport_get(tbit));
  printf(" client-mss: %d, server-mss: %d, ttl: %u",
	 scamper_tbit_client_mss_get(tbit),
	 scamper_tbit_server_mss_get(tbit),
	 scamper_tbit_client_ipttl_get(tbit));
  if((u8 = scamper_tbit_client_wscale_get(tbit)) > 0)
    printf(", wscale: %u", u8);
  printf("\n");
  printf(" type: %s,", scamper_tbit_type_tostr(tbit, buf, sizeof(buf)));
  printf(" result: %s\n", scamper_tbit_result_tostr(tbit, buf, sizeof(buf)));
  if((u32 = scamper_tbit_options_get(tbit)) != 0)
    {
      printf(" options:");
      tbit_bits_print(u32, 32, tbit_options,
		      sizeof(tbit_options) / sizeof(char *));
      printf("\n");
    }

  if((cookielen = scamper_tbit_client_fo_cookielen_get(tbit)) > 0)
    {
      printf(" fo-cookie: ");
      fo_cookie = scamper_tbit_client_fo_cookie_get(tbit);
      for(u8=0; u8<cookielen; u8++)
	printf("%02x", fo_cookie[u8]);
      printf("\n");
    }

  if((pmtud = scamper_tbit_pmtud_get(tbit)) != NULL)
    {
      printf(" mtu: %d, ptb-retx: %d",
	     scamper_tbit_pmtud_mtu_get(pmtud),
	     scamper_tbit_pmtud_ptb_retx_get(pmtud));
      if((addr = scamper_tbit_pmtud_ptbsrc_get(pmtud)) != NULL)
	printf(", ptb-src: %s", scamper_addr_tostr(addr, src,sizeof(src)));
      u8 = scamper_tbit_pmtud_options_get(pmtud);
      if(u8 & SCAMPER_TBIT_PMTUD_OPTION_BLACKHOLE)
	printf(", blackhole");
      printf("\n");
    }
  else if((null = scamper_tbit_null_get(tbit)) != NULL)
    {
      if((u32 = scamper_tbit_null_options_get(null)) != 0)
	{
	  printf(" null-options:");
	  tbit_bits_print(u32, 32, null_options,
			  sizeof(null_options) / sizeof(char *));
	  printf("\n");
	}
      if((u32 = scamper_tbit_null_results_get(null)) != 0)
	{
	  printf(" results:");
	  tbit_bits_print(u32, 32, null_results,
			  sizeof(null_results) / sizeof(char *));
	  printf("\n");

	  if((u32 & SCAMPER_TBIT_NULL_RESULT_FO) &&
	     scamper_tbit_server_fo_cookie_get(tbit, cookie, &u8) != 0)
	    {
	      printf(" fo-cookie: ");
	      for(i=0; i<u8; i++)
		printf("%02x", cookie[i]);
	      printf("\n");
	    }
	}
    }
  else if((icw = scamper_tbit_icw_get(tbit)) != NULL &&
	  scamper_tbit_result_get(tbit) == SCAMPER_TBIT_RESULT_ICW_SUCCESS)
    {
      printf(" icw-start-seq: %u", scamper_tbit_icw_start_seq_get(icw));
      if(scamper_tbit_server_icw_size_get(tbit, &u32) == 0)
	printf(", icw-size: %u bytes", u32);
      printf("\n");
    }
  else if((blind = scamper_tbit_blind_get(tbit)) != NULL)
    {
      printf(" blind: offset %d, retx %u\n",
	     scamper_tbit_blind_off_get(blind),
	     scamper_tbit_blind_retx_get(blind));
    }

  if((http = scamper_tbit_app_http_get(tbit)) != NULL)
    {
      printf(" app: http");
      switch(scamper_tbit_app_http_type_get(http))
	{
	case SCAMPER_TBIT_APP_HTTP_TYPE_HTTPS: str = "https"; break;
	default: str = "http"; break;
	}

      host = scamper_tbit_app_http_host_get(http);
      file = scamper_tbit_app_http_file_get(http);
      if(host != NULL && file != NULL)
	printf(", url: %s://%s%s", str, host, file);
      else if(host != NULL)
	printf(", url: %s://%s", str, host);
      else
	printf(", file: %s", file);
      printf("\n");
    }
  else if((bgp = scamper_tbit_app_bgp_get(tbit)) != NULL)
    {
      printf(" app: bgp, asn: %u\n", scamper_tbit_app_bgp_asn_get(bgp));
    }

  client_isn = 0;
  server_isn = 0;
  txsyn      = 0;
  rxsyn      = 0;

  pktc = scamper_tbit_pktc_get(tbit);
  for(i=0; i<pktc; i++)
    {
      pkt = scamper_tbit_pkt_get(tbit, i);
      pkt_data = scamper_tbit_pkt_data_get(pkt);
      dir = scamper_tbit_pkt_dir_get(pkt);
      frag = 0; mf = 0; off = 0;
      ipid[0] = '\0';

      if((pkt_data[0] >> 4) == 4)
        {
	  iphlen = (pkt_data[0] & 0xf) * 4;
	  len = bytes_ntohs(pkt_data+2);
	  proto = pkt_data[9];
	  ecn = pkt_data[1] & 0x3;
	  if(pkt_data[6] & 0x20)
	    mf = 1;
	  off = (bytes_ntohs(pkt_data+6) & 0x1fff) * 8;
	  if(mf != 0 || off != 0)
	    frag = 1;
	  snprintf(ipid, sizeof(ipid), "%04x", bytes_ntohs(pkt_data+4));
        }
      else if((pkt_data[0] >> 4) == 6)
        {
	  iphlen = 40;
	  len = bytes_ntohs(pkt_data+4) + iphlen;
	  proto = pkt_data[6];
	  ecn = (pkt_data[1] & 0x30) >> 4;

	  for(;;)
            {
	      switch(proto)
                {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		  if(pkt_data[iphlen+1] == 0 ||
		     255 - iphlen <= (pkt_data[iphlen+1] * 8) + 8)
		    break;
		  proto = pkt_data[iphlen+0];
		  iphlen += (pkt_data[iphlen+1] * 8) + 8;
		  continue;

		case IPPROTO_FRAGMENT:
		  if(255 - iphlen <= 8)
		    break;
		  if(pkt_data[iphlen+3] & 0x1)
		    mf = 1;
		  off = (bytes_ntohs(pkt_data+iphlen+2) & 0xfff8);
		  snprintf(ipid, sizeof(ipid), "%x",
			   bytes_ntohl(pkt_data+iphlen+4));
		  proto = pkt_data[iphlen+0];
		  iphlen += 8;
		  frag = 1;
		  continue;
                }
	      break;
            }
        }
      else
	{
	  continue;
	}

      timeval_diff_tv(&diff, start, scamper_tbit_pkt_tv_get(pkt));
      printf(" [%3d.%03d] %s ", (int)diff.tv_sec, (int)(diff.tv_usec / 1000),
	     dir == SCAMPER_TBIT_PKT_DIR_TX ? "TX" : "RX");

      if(frag != 0)
	snprintf(fstr,sizeof(fstr),":%u%s", off, mf != 0 ? " MF" : "");
      else
	fstr[0] = '\0';

      if(off != 0)
	{
	  printf("%13s %4dF%17s%s%s", "", len, "", ipid, fstr);
	}
      else if(proto == IPPROTO_TCP)
        {
	  seq     = bytes_ntohl(pkt_data+iphlen+4);
	  ack     = bytes_ntohl(pkt_data+iphlen+8);
	  flags   = pkt_data[iphlen+13];
	  tcphlen = ((pkt_data[iphlen+12] & 0xf0) >> 4) * 4;

	  soff = 0; tfstr[0] = '\0';
	  if(flags & 0x2)
            {
	      if(flags & 0x10)
                {
		  if(rxsyn == 0)
		    {
		      server_isn = seq;
		      rxsyn = 1;
		    }
		  string_concat(tfstr, sizeof(tfstr), &soff, "SYN/ACK");
                }
	      else
                {
		  if(txsyn == 0)
		    {
		      client_isn = seq;
		      txsyn = 1;
		    }
		  string_concat(tfstr, sizeof(tfstr), &soff, "SYN");
                }
            }
	  else if(flags & 0x1)
	    string_concat(tfstr, sizeof(tfstr), &soff, "FIN");
	  else if(flags & 0x4)
	    string_concat(tfstr, sizeof(tfstr), &soff, "RST");

	  if(flags & 0x40)
	    string_concat(tfstr, sizeof(tfstr), &soff, "%sECE",
			  soff != 0 ? "/" : "");
	  if(flags & 0x80)
	    string_concat(tfstr, sizeof(tfstr), &soff, "%sCWR",
			  soff != 0 ? "/" : "");

	  /* parse TCP options for sack blocks */
	  u8 = 20; soff = 0; sack[0] = '\0';
	  while(u8 < tcphlen)
	    {
	      tmp = pkt_data + iphlen + u8;

	      if(tmp[0] == 0) /* end of option list */
		break;

	      if(tmp[0] == 1) /* nop */
		{
		  u8++;
		  continue;
		}

	      if(tmp[1] == 0 || u8 + tmp[1] > tcphlen)
		break;

	      /* sack edges */
	      if(tmp[0] == 5 &&
		 (tmp[1]==10 || tmp[1]==18 || tmp[1]==26 || tmp[1]==34))
		{
		  if(dir == SCAMPER_TBIT_PKT_DIR_TX)
		    u32 = server_isn;
		  else
		    u32 = client_isn;

		  string_concat(sack, sizeof(sack), &soff, " {");
		  for(u16=0; u16<(tmp[1]-2)/8; u16++)
		    string_concat(sack, sizeof(sack), &soff, "%s%u:%u",
				  u16 != 0 ? "," : "",
				  bytes_ntohl(tmp+2+(u16*8)) - u32,
				  bytes_ntohl(tmp+2+(u16*8)+4) - u32);
		  string_concat(sack, sizeof(sack), &soff, "}");
		}

	      u8 += tmp[1];
	    }

	  if(dir == SCAMPER_TBIT_PKT_DIR_TX)
            {
	      seq = tbit_isnoff(client_isn, seq);
	      ack = tbit_isnoff(server_isn, ack);
            }
	  else
            {
	      if(!(seq == 0 && (flags & TH_RST) != 0))
		seq = tbit_isnoff(server_isn, seq);
	      ack = tbit_isnoff(client_isn, ack);
            }

	  datalen = len - iphlen - tcphlen;

	  printf("%-13s %4d%s", tfstr, len, frag != 0 ? "F" : " ");
	  soff = 0;
	  string_concat(buf, sizeof(buf), &soff, " %u", seq);
	  if(flags & TH_ACK)
	    string_concat(buf, sizeof(buf), &soff, ":%u", ack);
	  if(datalen != 0)
	    string_concat(buf, sizeof(buf), &soff, "(%d)", datalen);
	  printf("%-17s%s", buf, ipid);
	  if(frag != 0) printf("%s", fstr);
	  if(datalen > 0 && (pkt_data[0] >> 4) == 4 && pkt_data[6] & 0x40)
	    printf(" DF");
	  if(ecn == 3)      printf(" CE");
	  else if(ecn != 0) printf(" ECT");
	  printf("%s", sack);
        }
      else if(proto == IPPROTO_ICMP)
        {
	  if(pkt_data[iphlen+0] == 3 && pkt_data[iphlen+1] == 4)
	    {
	      u16 = bytes_ntohs(pkt_data+iphlen+6);
	      printf("%-13s %4d  mtu = %d", "PTB", len, u16);
	    }
        }
      else if(proto == IPPROTO_ICMPV6)
        {
	  if(pkt_data[iphlen+0] == 2)
	    {
	      u32 = bytes_ntohl(pkt_data+iphlen+4);
	      printf("%-13s %4d  mtu = %d", "PTB", len, u32);
	    }
	}

      printf("\n");
    }

  fprintf(stdout,"\n");

  scamper_tbit_free(tbit);
  return;
}

static void dump_sting(scamper_sting_t *sting)
{
  const scamper_sting_pkt_t *pkt;
  const struct timeval *tv, *start;
  const uint8_t *pkt_data;
  struct timeval diff;
  char src[64], dst[64], buf[32], ipid[12], tfstr[32], *dir;
  uint32_t i, pktc, seq, ack, server_isn, client_isn;
  uint16_t len, pkt_len, datalen;
  uint8_t result, proto, flags, iphlen, tcphlen, pkt_flags;
  size_t tfoff;

  printf("sting from %s to %s\n",
	 scamper_addr_tostr(scamper_sting_src_get(sting), src, sizeof(src)),
	 scamper_addr_tostr(scamper_sting_dst_get(sting), dst, sizeof(dst)));

  start = scamper_sting_start_get(sting);
  dump_list_summary(scamper_sting_list_get(sting));
  dump_cycle_summary(scamper_sting_cycle_get(sting));
  printf(" user-id: %d\n", scamper_sting_userid_get(sting));
  dump_timeval("start", start);
  printf(" sport: %d, dport: %d\n",
	 scamper_sting_sport_get(sting), scamper_sting_dport_get(sting));
  printf(" count: %d", scamper_sting_count_get(sting));
  dump_wait(", mean", scamper_sting_mean_get(sting));
  dump_wait(", inter", scamper_sting_inter_get(sting));
  printf(", seqskip %d\n", scamper_sting_seqskip_get(sting));
  printf(" synretx: %d, dataretx: %d\n",
	 scamper_sting_synretx_get(sting), scamper_sting_dataretx_get(sting));
  printf(" dataackc: %d, holec: %d\n",
	 scamper_sting_dataackc_get(sting), scamper_sting_holec_get(sting));
  tv = scamper_sting_hsrtt_get(sting);
  printf(" hs-rtt: %d.%06d\n", (int)tv->tv_sec, (int)tv->tv_usec);

  printf(" result: "); result = scamper_sting_result_get(sting);
  if(result == SCAMPER_STING_RESULT_NONE)
    printf("none");
  else if(result == SCAMPER_STING_RESULT_COMPLETED)
    printf("completed");
  else
    printf("0x%02x", result);
  printf("\n");

  client_isn = 0;
  server_isn = 0;

  pktc = scamper_sting_pktc_get(sting);
  for(i=0; i<pktc; i++)
    {
      pkt = scamper_sting_pkt_get(sting, i);
      pkt_data = scamper_sting_pkt_data_get(pkt);
      pkt_len = scamper_sting_pkt_len_get(pkt);

      if((pkt_data[0] >> 4) == 4 && pkt_len >= 20)
        {
	  iphlen = (pkt_data[0] & 0xf) * 4;
	  len = bytes_ntohs(pkt_data+2);
	  proto = pkt_data[9];
	  snprintf(ipid, sizeof(ipid), " %04x", bytes_ntohs(pkt_data+4));
	}
      else if((pkt_data[0] >> 4) == 6 && pkt_len >= 40)
        {
	  iphlen = 40;
	  len = bytes_ntohs(pkt_data+4) + iphlen;
	  proto = pkt_data[6];
	  ipid[0] = '\0';

	  for(;;)
            {
	      switch(proto)
                {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		  if(pkt_data[iphlen+1] == 0 ||
		     255 - iphlen <= (pkt_data[iphlen+1] * 8) + 8)
		    break;
		  proto = pkt_data[iphlen+0];
		  iphlen += (pkt_data[iphlen+1] * 8) + 8;
		  continue;

		case IPPROTO_FRAGMENT:
		  if(255 - iphlen <= 8)
		    break;
		  proto = pkt_data[iphlen+0];
		  iphlen += 8;
		  continue;
                }
	      break;
            }
        }
      else continue;

      if(proto != IPPROTO_TCP)
	continue;

      timeval_diff_tv(&diff, start, scamper_sting_pkt_tv_get(pkt));
      pkt_flags = scamper_sting_pkt_flags_get(pkt);
      if(pkt_flags & SCAMPER_STING_PKT_FLAG_TX) dir = "TX";
      else if(pkt_flags & SCAMPER_STING_PKT_FLAG_RX) dir = "RX";
      else dir = "??";

      printf(" [%3d.%03d] %s ",(int)diff.tv_sec,(int)(diff.tv_usec/1000),dir);

      seq     = bytes_ntohl(pkt_data+iphlen+4);
      ack     = bytes_ntohl(pkt_data+iphlen+8);
      flags   = pkt_data[iphlen+13];
      tcphlen = ((pkt_data[iphlen+12] & 0xf0) >> 4) * 4;

      tfoff = 0;
      if(flags & 0x2)
	{
	  if(flags & 0x10)
	    {
	      server_isn = seq;
	      string_concat(tfstr, sizeof(tfstr), &tfoff, "SYN/ACK");
	    }
	  else
	    {
	      client_isn = seq;
	      string_concat(tfstr, sizeof(tfstr), &tfoff, "SYN");
	    }
	}
      else if(flags & 0x1)
	string_concat(tfstr, sizeof(tfstr), &tfoff, "FIN");
      else if(flags & 0x4)
	string_concat(tfstr, sizeof(tfstr), &tfoff, "RST");

      if(flags & 0x40)
	string_concat(tfstr, sizeof(tfstr), &tfoff, "%sECE",
		      tfoff != 0 ? "/" : "");
      if(flags & 0x80)
	string_concat(tfstr, sizeof(tfstr), &tfoff, "%sCWR",
		      tfoff != 0 ? "/" : "");
      if(tfoff == 0)
	tfstr[0] = '\0';

      if(pkt_flags & SCAMPER_STING_PKT_FLAG_TX)
	{
	  seq = tbit_isnoff(client_isn, seq);
	  ack = tbit_isnoff(server_isn, ack);
	}
      else
	{
	  seq = tbit_isnoff(server_isn, seq);
	  ack = tbit_isnoff(client_isn, ack);
	}

      datalen = len - iphlen - tcphlen;

      printf("%-13s %4d", tfstr, len);
      if(datalen != 0)
	snprintf(buf, sizeof(buf), " seq = %u:%u(%d)", seq, ack, datalen);
      else
	snprintf(buf, sizeof(buf), " seq = %u:%u", seq, ack);
      printf("%-23s%s\n", buf, ipid);
    }

  scamper_sting_free(sting);
  return;
}

static void dump_sniff(scamper_sniff_t *sniff)
{
  const scamper_sniff_pkt_t *pkt;
  const struct timeval *start;
  const uint8_t *ptr;
  struct timeval tv;
  uint8_t u8;
  uint16_t len;
  uint32_t i, j, pktc;
  int k;
  char src[64], dst[64], buf[32], *str;

  start = scamper_sniff_start_get(sniff);

  printf("sniff %s\n",
	 scamper_addr_tostr(scamper_sniff_src_get(sniff), src, sizeof(src)));
  dump_list_summary(scamper_sniff_list_get(sniff));
  dump_cycle_summary(scamper_sniff_cycle_get(sniff));
  printf(" user-id: %d\n", scamper_sniff_userid_get(sniff));
  dump_timeval("start", start);
  dump_timeval("finish", scamper_sniff_finish_get(sniff));
  printf(" limit-pktc: %d", scamper_sniff_limit_pktc_get(sniff));
  dump_wait(", limit-time", scamper_sniff_limit_time_get(sniff));
  printf(", icmp-id %d\n", scamper_sniff_icmpid_get(sniff));
  u8 = scamper_sniff_stop_reason_get(sniff);
  pktc = scamper_sniff_pktc_get(sniff);
  switch(u8)
    {
    case SCAMPER_SNIFF_STOP_NONE: str = "none"; break;
    case SCAMPER_SNIFF_STOP_ERROR: str = "error"; break;
    case SCAMPER_SNIFF_STOP_LIMIT_TIME: str = "limit-time"; break;
    case SCAMPER_SNIFF_STOP_LIMIT_PKTC: str = "limit-pktc"; break;
    case SCAMPER_SNIFF_STOP_HALTED: str = "halted"; break;
    default:
      snprintf(buf, sizeof(buf), "%d", u8);
      str = buf;
      break;
    }
  printf(" result: %s, pktc: %d\n", str, pktc);

  for(i=0; i<pktc; i++)
    {
      pkt = scamper_sniff_pkt_get(sniff, i);
      timeval_diff_tv(&tv, start, scamper_sniff_pkt_tv_get(pkt));
      printf(" %3d %d.%06d", i, (int)tv.tv_sec, (int)tv.tv_usec);

      ptr = scamper_sniff_pkt_data_get(pkt);
      len = scamper_sniff_pkt_len_get(pkt);

      u8 = (ptr[0] & 0xf0) >> 4;
      if(u8 == 4 && len >= 20)
	{
	  printf(" %s -> %s",
		 inet_ntop(AF_INET, ptr+12, src, sizeof(src)),
		 inet_ntop(AF_INET, ptr+16, dst, sizeof(dst)));
	}
      else if(u8 == 6 && len >= 40)
	{
	  printf(" %s -> %s",
		 inet_ntop(AF_INET6, ptr+8,  src, sizeof(src)),
		 inet_ntop(AF_INET6, ptr+24, dst, sizeof(dst)));
	}
      printf("\n");

      for(j=0; j+16<=len; j+=16)
	{
	  printf("     0x%04x: ", j);
	  for(k=0; k<8; k++)
	    {
	      printf(" %02x%02x", ptr[0], ptr[1]);
	      ptr += 2;
	    }
	  printf("\n");
	}
      if(len - j != 0)
	{
	  printf("     0x%04x: ", j);
	  while(j<len)
	    {
	      if((j % 2) == 0)
		printf(" ");
	      printf("%02x", *ptr);
	      ptr++;
	      j++;
	    }
	  printf("\n");
	}
    }

  scamper_sniff_free(sniff);
  return;
}

static void dump_host_rr(const scamper_host_rr_t *rr, const char *section)
{
  char buf[256];
  const char *name, *str;
  scamper_addr_t *addr;
  const scamper_host_rr_mx_t *mx;
  const scamper_host_rr_soa_t *soa;
  const scamper_host_rr_txt_t *txt;
  uint16_t class, type, i, strc;

  name = scamper_host_rr_name_get(rr);
  class = scamper_host_rr_class_get(rr);
  type = scamper_host_rr_type_get(rr);
  printf("  %s: %s %u ", section, name != NULL ? name : "<null>",
	 scamper_host_rr_ttl_get(rr));
  printf("%s ", scamper_host_qclass_tostr(class, buf, sizeof(buf)));
  printf("%s", scamper_host_qtype_tostr(type, buf, sizeof(buf)));

  switch(scamper_host_rr_data_type(class, type))
    {
    case SCAMPER_HOST_RR_DATA_TYPE_ADDR:
      addr = scamper_host_rr_addr_get(rr);
      printf(" %s", scamper_addr_tostr(addr, buf, sizeof(buf)));
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_STR:
      printf(" %s", scamper_host_rr_str_get(rr));
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_MX:
      mx = scamper_host_rr_mx_get(rr);
      printf(" %d %s", scamper_host_rr_mx_preference_get(mx),
	     scamper_host_rr_mx_exchange_get(mx));
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_SOA:
      soa = scamper_host_rr_soa_get(rr);
      printf(" %s %s %u %u %u %u %u",
	     scamper_host_rr_soa_mname_get(soa),
	     scamper_host_rr_soa_rname_get(soa),
	     scamper_host_rr_soa_serial_get(soa),
	     scamper_host_rr_soa_refresh_get(soa),
	     scamper_host_rr_soa_retry_get(soa),
	     scamper_host_rr_soa_expire_get(soa),
	     scamper_host_rr_soa_minimum_get(soa));
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_TXT:
      txt = scamper_host_rr_txt_get(rr);
      strc = scamper_host_rr_txt_strc_get(txt);
      printf(" %d", strc);
      for(i=0; i<strc; i++)
	{
	  str = scamper_host_rr_txt_str_get(txt, i);
	  printf(" \"%s\"", str != NULL ? str : "<null>");
	}
      break;
    }

  printf("\n");
  return;
}

static void dump_host(scamper_host_t *host)
{
  static const char *flags[8] = {"CD","AD","Z","RA","RD","TC","AA","0x80"};
  const scamper_host_query_t *query;
  const struct timeval *start, *tx, *rx;
  scamper_addr_t *addr;
  struct timeval tv;
  char buf[256], lower[256];
  uint32_t i, j, l;
  uint16_t qflags, count;
  uint8_t qcount, rcode, rflags;

  printf("host");
  if((addr = scamper_host_src_get(host)) != NULL)
    printf(" from %s", scamper_addr_tostr(addr, buf, sizeof(buf)));
  addr = scamper_host_dst_get(host);
  printf(" to %s\n", scamper_addr_tostr(addr, buf, sizeof(buf)));
  dump_list_summary(scamper_host_list_get(host));
  dump_cycle_summary(scamper_host_cycle_get(host));
  printf(" user-id: %d\n", scamper_host_userid_get(host));
  start = scamper_host_start_get(host);
  dump_timeval("start", start);

  if((qflags = scamper_host_flags_get(host)) != 0)
    {
      printf(" flags: ");
      if(qflags & SCAMPER_HOST_FLAG_NORECURSE)
	printf("norecurse");
      printf("\n");
    }

  dump_wait(" wait", scamper_host_wait_timeout_get(host));
  printf(", retries: %u, stop: %s\n", scamper_host_retries_get(host),
	 string_tolower(lower, sizeof(lower),
			scamper_host_stop_tostr(host, buf, sizeof(buf))));
  printf(" qname: %s, qclass: %s", scamper_host_qname_get(host),
	 scamper_host_qclass_tostr(scamper_host_qclass_get(host),
				   buf, sizeof(buf)));
  printf(", qtype: %s",
	 scamper_host_qtype_tostr(scamper_host_qtype_get(host),
				  buf, sizeof(buf)));
  qcount = scamper_host_qcount_get(host);
  printf(", qcount: %d\n", qcount);

  for(i=0; i<qcount; i++)
    {
      query = scamper_host_query_get(host, i);
      tx = scamper_host_query_tx_get(query);
      timeval_diff_tv(&tv, start, tx);
      printf(" query: %u, id: %u, tx: %d.%06d", i,
	     scamper_host_query_id_get(query),
	     (int)tv.tv_sec, (int)tv.tv_usec);
      rx = scamper_host_query_rx_get(query);
      if(rx->tv_sec != 0 || rx->tv_usec != 0)
	{
	  timeval_diff_tv(&tv, tx, rx);
	  printf(", rtt: %d.%06d", (int)tv.tv_sec, (int)tv.tv_usec);
	}
      printf(", an: %u, ns: %u, ar: %u",
	     scamper_host_query_ancount_get(query),
	     scamper_host_query_nscount_get(query),
	     scamper_host_query_arcount_get(query));
      printf("\n");

      if(rx->tv_sec != 0 || rx->tv_usec != 0)
	{
	  rcode = scamper_host_query_rcode_get(query);
	  printf("  rcode: %s",
		 scamper_host_rcode_tostr(rcode, buf, sizeof(buf)));

	  if((rflags = scamper_host_query_flags_get(query)) != 0)
	    {
	      printf(", flags:");
	      l = 0;
	      for(j=0; j<8; j++)
		{
		  if((rflags & (0x1 << j)) == 0)
		    continue;
		  if(l > 0) printf(",");
		  printf(" %s", flags[j]);
		  l++;
		}
	    }
	  printf("\n");
	}

      count = scamper_host_query_ancount_get(query);
      for(j=0; j<count; j++)
	dump_host_rr(scamper_host_query_an_get(query, j), "an");
      count = scamper_host_query_nscount_get(query);
      for(j=0; j<count; j++)
	dump_host_rr(scamper_host_query_ns_get(query, j), "ns");
      count = scamper_host_query_arcount_get(query);
      for(j=0; j<count; j++)
	dump_host_rr(scamper_host_query_ar_get(query, j), "ar");
    }
  printf("\n");

  scamper_host_free(host);
  return;
}

static void dump_http(scamper_http_t *http)
{
  const scamper_http_buf_t *htb;
  const struct timeval *start, *ts;
  const scamper_addr_t *addr;
  const uint8_t *htb_data;
  struct timeval tv;
  uint32_t bufc, u32;
  uint16_t dport, len, u16;
  uint8_t hdrc, u8;
  char buf[256], dir[8], type[8], *tmp;
  size_t s;

  printf("http");
  if((addr = scamper_http_src_get(http)) != NULL)
    printf(" from %s", scamper_addr_tostr(addr, buf, sizeof(buf)));
  addr = scamper_http_dst_get(http);
  printf(" to %s\n", scamper_addr_tostr(addr, buf, sizeof(buf)));
  dump_list_summary(scamper_http_list_get(http));
  dump_cycle_summary(scamper_http_cycle_get(http));
  printf(" user-id: %d\n", scamper_http_userid_get(http));
  start = scamper_http_start_get(http);
  dump_timeval("start", start);
  dport = scamper_http_dport_get(http);
  printf(" sport: %d, dport: %d\n", scamper_http_sport_get(http), dport);
  if((u32 = scamper_http_flags_get(http)) != 0)
    printf(" flags: 0x%x (%s )\n", u32,
	   (u32 & SCAMPER_HTTP_FLAG_INSECURE) ? " insecure" : "");
  dump_wait(" maxtime", scamper_http_maxtime_get(http));
  if((ts = scamper_http_hsrtt_get(http)) != NULL && timeval_iszero(ts) == 0)
    printf(", hs-rtt: %d.%06d", (int)ts->tv_sec, (int)ts->tv_usec);
  printf(", stop: %s", scamper_http_stop_tostr(http, buf, sizeof(buf)));
  if(scamper_http_status_code_get(http, &u16) == 0)
    printf(", status-code: %u", u16);
  printf("\n");

  if(scamper_http_url_len_get(http, &s) == 0 && (tmp = malloc(s)) != NULL)
    {
      if(scamper_http_url_get(http, tmp, s) == 0)
	printf(" url: %s\n", tmp);
      free(tmp);
    }

  if((hdrc = scamper_http_headerc_get(http)) > 0)
    {
      printf(" headers:\n");
      for(u8=0; u8<hdrc; u8++)
	printf("  %s\n", scamper_http_header_get(http, u8));
    }

  if((bufc = scamper_http_bufc_get(http)) > 0)
    {
      printf(" exchange:\n");
      for(u32=0; u32<bufc; u32++)
	{
	  if((htb = scamper_http_buf_get(http, u32)) == NULL ||
	     (ts = scamper_http_buf_tv_get(htb)) == NULL)
	    continue;
	  timeval_diff_tv(&tv, start, ts);
	  len = scamper_http_buf_len_get(htb);
	  snprintf(buf, sizeof(buf), "%s:%u",
		   scamper_http_buf_type_tostr(htb, type, sizeof(type)), len);
	  printf("  %d.%06d %s %-10s", (int)tv.tv_sec, (int)tv.tv_usec,
		 scamper_http_buf_dir_tostr(htb, dir, sizeof(dir)), buf);

	  if((htb_data = scamper_http_buf_data_get(htb)) != NULL)
	    {
	      u8 = 16;
	      for(u16=0; u16<((len < u8) ? len : u8); u16++)
		printf("%02x", htb_data[u16]);
	      while(u16++ < u8)
		printf("  ");
	      printf("  |");
	      for(u16=0; u16<((len < u8) ? len : u8); u16++)
		printf("%c", (isprint(htb_data[u16]) ? htb_data[u16] : '.'));
	      printf("|");
	    }
	  printf("\n");
	}
    }

  scamper_http_free(http);
  return;
}

static void dump_udpprobe(scamper_udpprobe_t *up)
{
  const scamper_udpprobe_probe_t *probe;
  const scamper_udpprobe_reply_t *reply;
  const struct timeval *start, *ts;
  const scamper_addr_t *addr;
  const uint8_t *data;
  struct timeval tv;
  uint16_t data_len, u16;
  uint8_t sentc, replyc, i, j;
  char buf[256];

  printf("udpprobe");
  if((addr = scamper_udpprobe_src_get(up)) != NULL)
    printf(" from %s", scamper_addr_tostr(addr, buf, sizeof(buf)));
  addr = scamper_udpprobe_dst_get(up);
  printf(" to %s\n", scamper_addr_tostr(addr, buf, sizeof(buf)));
  dump_list_summary(scamper_udpprobe_list_get(up));
  dump_cycle_summary(scamper_udpprobe_cycle_get(up));
  printf(" user-id: %d\n", scamper_udpprobe_userid_get(up));
  start = scamper_udpprobe_start_get(up);
  dump_timeval("start", start);
  dump_wait(" wait-timeout", scamper_udpprobe_wait_timeout_get(up));
  dump_wait(", wait-probe", scamper_udpprobe_wait_probe_get(up));
  printf(", sport: %d, dport: %d\n", scamper_udpprobe_sport_get(up),
	 scamper_udpprobe_dport_get(up));
  if((data = scamper_udpprobe_data_get(up)) != NULL &&
     (data_len = scamper_udpprobe_len_get(up)) != 0)
    {
      printf(" payload: (%d) ", data_len);
      for(u16=0; u16 < (data_len >= 20 ? 20 : data_len); u16++)
	printf("%02x", data[u16]);
      if(data_len > 20)
	printf(" + %d bytes", data_len - 20);
      printf("\n");
    }
  sentc = scamper_udpprobe_probe_sent_get(up);
  printf(" probe-count: %d, probe-sent: %d\n",
	 scamper_udpprobe_probe_count_get(up), sentc);

  for(i=0; i<sentc; i++)
    {
      if((probe = scamper_udpprobe_probe_get(up, i)) == NULL)
	continue;
      timeval_diff_tv(&tv, start, scamper_udpprobe_probe_tx_get(probe));
      replyc = scamper_udpprobe_probe_replyc_get(probe);
      printf("  %d.%06d probe: %d, sport: %d, replyc: %d\n",
	     (int)tv.tv_sec, (int)tv.tv_usec, i,
	     scamper_udpprobe_probe_sport_get(probe), replyc);
      for(j=0; j<replyc; j++)
	{
	  if((reply = scamper_udpprobe_probe_reply_get(probe, j)) == NULL ||
	     (ts = scamper_udpprobe_reply_rx_get(reply)) == NULL ||
	     (data_len = scamper_udpprobe_reply_len_get(reply)) == 0 ||
	     (data = scamper_udpprobe_reply_data_get(reply)) == NULL)
	    continue;
	  timeval_diff_tv(&tv, start, ts);
	  printf("  %d.%06d reply: %d, len: %d ",
		 (int)tv.tv_sec, (int)tv.tv_usec, j, data_len);
	  for(u16=0; u16 < (data_len >= 20 ? 20 : data_len); u16++)
	    printf("%02x", data[u16]);
	  if(data_len > 20)
	    printf(" + %d bytes", data_len - 20);
	  printf("\n");
	}
    }

  scamper_udpprobe_free(up);
  return;
}

static void dump_cycle(scamper_cycle_t *cycle, const char *type)
{
  scamper_list_t *list;
  time_t tt;
  char buf[32];

  if(strcmp(type, "start") == 0 || strcmp(type, "def") == 0)
    tt = scamper_cycle_start_time_get(cycle);
  else
    tt = scamper_cycle_stop_time_get(cycle);

  memcpy(buf, ctime(&tt), 24); buf[24] = '\0';

  list = scamper_cycle_list_get(cycle);
  printf("cycle %s, list %s %d, cycle %d, time %s\n", type,
	 scamper_list_name_get(list), scamper_list_id_get(list),
	 scamper_cycle_id_get(cycle), buf);
  scamper_cycle_free(cycle);
  return;
}

static void dump_list(scamper_list_t *list)
{
  const char *str;
  printf("list id %d, name %s", scamper_list_id_get(list),
	 scamper_list_name_get(list));
  if((str = scamper_list_descr_get(list)) != NULL)
    printf(", descr \"%s\"", str);
  printf("\n");
  scamper_list_free(list);
  return;
}

static void dump_addr(scamper_addr_t *addr)
{
  char buf[128];
  printf("addr %s\n", scamper_addr_tostr(addr, buf, sizeof(buf)));
  scamper_addr_free(addr);
  return;
}

int main(int argc, char *argv[])
{
  scamper_file_t        *file;
  scamper_file_filter_t *filter;
  uint16_t filter_types[] = {
    SCAMPER_FILE_OBJ_LIST,
    SCAMPER_FILE_OBJ_CYCLE_START,
    SCAMPER_FILE_OBJ_CYCLE_DEF,
    SCAMPER_FILE_OBJ_CYCLE_STOP,
    SCAMPER_FILE_OBJ_TRACE,
    SCAMPER_FILE_OBJ_PING,
    SCAMPER_FILE_OBJ_TRACELB,
    SCAMPER_FILE_OBJ_DEALIAS,
    SCAMPER_FILE_OBJ_NEIGHBOURDISC,
    SCAMPER_FILE_OBJ_TBIT,
    SCAMPER_FILE_OBJ_STING,
    SCAMPER_FILE_OBJ_SNIFF,
    SCAMPER_FILE_OBJ_HOST,
    SCAMPER_FILE_OBJ_HTTP,
    SCAMPER_FILE_OBJ_UDPPROBE,
  };
  uint16_t filter_cnt = sizeof(filter_types)/sizeof(uint16_t);
  void     *data;
  uint16_t  type;
  int       f;

#ifdef HAVE_WSASTARTUP
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2,2), &wsaData);
#endif

#if defined(DMALLOC)
  free(malloc(1));
#endif

  if((filter = scamper_file_filter_alloc(filter_types, filter_cnt)) == NULL)
    {
      usage();
      fprintf(stderr, "could not alloc filter\n");
      return -1;
    }

  for(f=0; f<argc; f++)
    {
      if(f == 0)
	{
	  if(argc > 1)
	    continue;

	  if((file=scamper_file_openfd(STDIN_FILENO,"-",'r',"warts")) == NULL)
	    {
	      usage();
	      fprintf(stderr, "could not use stdin\n");
	      return -1;
	    }
	}
      else
	{
	  if((file = scamper_file_open(argv[f], 'r', NULL)) == NULL)
	    {
	      usage();
	      fprintf(stderr, "could not open %s\n", argv[f]);
	      return -1;
	    }
	}

      while(scamper_file_read(file, filter, &type, &data) == 0)
	{
	  /* hit eof */
	  if(data == NULL)
	    goto done;

	  switch(type)
	    {
	    case SCAMPER_FILE_OBJ_ADDR:
	      dump_addr(data);
	      break;

	    case SCAMPER_FILE_OBJ_TRACE:
	      dump_trace(data);
	      break;

	    case SCAMPER_FILE_OBJ_PING:
	      dump_ping(data);
	      break;

	    case SCAMPER_FILE_OBJ_TRACELB:
	      dump_tracelb(data);
	      break;

	    case SCAMPER_FILE_OBJ_DEALIAS:
	      dump_dealias(data);
	      break;

	    case SCAMPER_FILE_OBJ_NEIGHBOURDISC:
	      dump_neighbourdisc(data);
	      break;

	    case SCAMPER_FILE_OBJ_TBIT:
	      dump_tbit(data);
	      break;

	    case SCAMPER_FILE_OBJ_STING:
	      dump_sting(data);
	      break;

	    case SCAMPER_FILE_OBJ_SNIFF:
	      dump_sniff(data);
	      break;

	    case SCAMPER_FILE_OBJ_HOST:
	      dump_host(data);
	      break;

	    case SCAMPER_FILE_OBJ_HTTP:
	      dump_http(data);
	      break;

	    case SCAMPER_FILE_OBJ_UDPPROBE:
	      dump_udpprobe(data);
	      break;

	    case SCAMPER_FILE_OBJ_LIST:
	      dump_list(data);
	      break;

	    case SCAMPER_FILE_OBJ_CYCLE_START:
	      dump_cycle(data, "start");
	      break;

	    case SCAMPER_FILE_OBJ_CYCLE_STOP:
	      dump_cycle(data, "stop");
	      break;

	    case SCAMPER_FILE_OBJ_CYCLE_DEF:
	      dump_cycle(data, "def");
	      break;
	    }
	}

    done:
      scamper_file_close(file);

      if(argc == 1)
	break;
    }

  scamper_file_filter_free(filter);
  return 0;
}
