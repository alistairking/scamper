/*
 * common_trace : common functions for unit testing trace
 *
 * $Id: common_trace.c,v 1.5 2025/02/14 04:16:00 mjl Exp $
 *
 *        Marcus Luckie, Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024 Matthew Luckie
 * Copyright (C) 2024 Marcus Luckie
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

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_file.h"
#include "scamper_trace.h"
#include "scamper_trace_int.h"
#include "scamper_ifname.h"
#include "scamper_ifname_int.h"
#include "scamper_icmpext.h"
#include "common_ok.h"
#include "common_trace.h"
#include "utils.h"

static int trace_hop_ok(const scamper_trace_hop_t *in,
			const scamper_trace_hop_t *out)
{
  if(addr_ok(in->hop_addr, out->hop_addr) != 0 ||
     str_ok(in->hop_name, out->hop_name) != 0 ||
     in->hop_flags != out->hop_flags ||
     in->hop_probe_id != out->hop_probe_id ||
     in->hop_probe_ttl != out->hop_probe_ttl ||
     in->hop_probe_size != out->hop_probe_size ||
     in->hop_reply_ttl != out->hop_reply_ttl ||
     in->hop_reply_tos != out->hop_reply_tos ||
     in->hop_reply_size != out->hop_reply_size ||
     in->hop_reply_ipid != out->hop_reply_ipid ||
     in->hop_icmp_type != out->hop_icmp_type ||
     in->hop_icmp_code != out->hop_icmp_code ||
     in->hop_icmp_q_ttl != out->hop_icmp_q_ttl ||
     in->hop_icmp_q_ipl != out->hop_icmp_q_ipl ||
     in->hop_icmp_q_tos != out->hop_icmp_q_tos ||
     in->hop_icmp_nhmtu != out->hop_icmp_nhmtu ||
     in->hop_tcp_flags != out->hop_tcp_flags ||
     timeval_cmp(&in->hop_tx, &out->hop_tx) != 0 ||
     timeval_cmp(&in->hop_rtt, &out->hop_rtt) != 0 ||
     icmpexts_ok(in->hop_icmp_exts, out->hop_icmp_exts) != 0)
    return -1;

  return 0;
}

int trace_ok(const scamper_trace_t *in, const scamper_trace_t *out)
{
  scamper_trace_hop_t *in_hop, *out_hop;
  uint16_t i;

  assert(in != NULL);
  if(out == NULL ||
     in->userid != out->userid ||
     addr_ok(in->src, out->src) != 0 ||
     addr_ok(in->dst, out->dst) != 0 ||
     addr_ok(in->rtr, out->rtr) != 0 ||
     timeval_cmp(&in->start, &out->start) != 0 ||
     in->hop_count != out->hop_count ||
     in->probec != out->probec ||
     in->stop_reason != out->stop_reason ||
     in->stop_data != out->stop_data ||
     in->stop_hop != out->stop_hop ||
     in->type != out->type ||
     in->attempts != out->attempts ||
     in->hoplimit != out->hoplimit ||
     in->squeries != out->squeries ||
     in->gaplimit != out->gaplimit ||
     in->gapaction != out->gapaction ||
     in->firsthop != out->firsthop ||
     in->tos != out->tos ||
     timeval_cmp(&in->wait_timeout, &out->wait_timeout) != 0 ||
     timeval_cmp(&in->wait_probe, &out->wait_probe) != 0 ||
     timeval_cmp(&in->wait_probe_hop, &out->wait_probe_hop) != 0 ||
     in->loops != out->loops ||
     in->loopaction != out->loopaction ||
     in->confidence != out->confidence ||
     in->probe_size != out->probe_size ||
     in->sport != out->sport ||
     in->dport != out->dport ||
     in->offset != out->offset ||
     in->flags != out->flags ||
     in->payload_len != out->payload_len ||
     buf_ok(in->payload, out->payload, in->payload_len) != 0)
    return -1;

  for(i=0; i<in->hop_count; i++)
    {
      in_hop = in->hops[i];
      out_hop = out->hops[i];
      while(in_hop != NULL)
	{
	  if(out_hop == NULL || trace_hop_ok(in_hop, out_hop) != 0)
	    return -1;
	  in_hop = in_hop->hop_next;
	  out_hop = out_hop->hop_next;
	}
      if(out_hop != NULL)
	return -1;
    }

  return 0;
}

static scamper_trace_hop_t *hop_alloc(const char *str, uint8_t ttl,
				      time_t tx_sec, uint32_t tx_usec,
				      time_t rtt_sec, uint32_t rtt_usec)
{
  scamper_trace_hop_t *hop = NULL;

  if((hop = scamper_trace_hop_alloc()) == NULL ||
     (hop->hop_addr = scamper_addr_fromstr(AF_UNSPEC, str)) == NULL)
    goto err;
  hop->hop_tx.tv_sec = tx_sec;
  hop->hop_tx.tv_usec = tx_usec;
  hop->hop_rtt.tv_sec = rtt_sec;
  hop->hop_rtt.tv_usec = rtt_usec;
  hop->hop_probe_ttl = ttl;

  if(scamper_addr_isipv4(hop->hop_addr))
    {
      hop->hop_icmp_type = ICMP_TIMXCEED;
      hop->hop_icmp_code = ICMP_TIMXCEED_INTRANS;
    }
  else
    {
      hop->hop_icmp_type = ICMP6_TIME_EXCEEDED;
      hop->hop_icmp_code = ICMP6_TIME_EXCEED_TRANSIT;
    }

  return hop;

 err:
  if(hop != NULL) scamper_trace_hop_free(hop);
  return NULL;
}

scamper_trace_t *trace_1(void)
{
  scamper_trace_t *trace = NULL;

  if((trace = scamper_trace_alloc()) == NULL ||
     (trace->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (trace->dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL ||
     scamper_trace_hops_alloc(trace, 5) != 0)
    goto err;

  trace->userid               = 69;
  trace->sport                = 120;
  trace->dport                = 154;
  trace->start.tv_sec         = 1724828853;
  trace->start.tv_usec        = 123456;
  trace->wait_timeout.tv_sec  = 1;
  trace->wait_timeout.tv_usec = 0;
  trace->wait_probe.tv_sec    = 0;
  trace->wait_probe.tv_usec   = 200000;
  trace->flags                = 0;
  trace->hop_count            = 5;
  trace->firsthop             = 1;
  trace->squeries             = 1;
  trace->gaplimit             = 3;
  trace->attempts             = 2;
  trace->probec               = 10;
  trace->flags               |= SCAMPER_TRACE_FLAG_ALLATTEMPTS;
  trace->stop_reason          = SCAMPER_TRACE_STOP_GAPLIMIT;
  trace->type                 = SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS;

  if((trace->hops[0] = hop_alloc("192.0.2.4", 1, 1724828853, 123456,
				 0, 253421)) == NULL ||
     (trace->hops[0]->hop_next = hop_alloc("192.0.2.4", 1, 1724828853, 423112,
					   0, 224313)) == NULL ||
     (trace->hops[1] = hop_alloc("192.0.2.5", 2, 1724828853, 734231,
				 0, 234287)) == NULL ||
     (trace->hops[1]->hop_next = hop_alloc("192.0.2.5", 2, 1724828853, 992312,
					   0, 279734)) == NULL)
    goto err;

  return trace;

 err:
  if(trace != NULL) scamper_trace_free(trace);
  return NULL;
}
