/*
 * common_trace : common functions for unit testing trace
 *
 * $Id: common_trace.c,v 1.12 2025/05/05 05:20:20 mjl Exp $
 *
 *        Marcus Luckie, Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024 Marcus Luckie
 * Copyright (C) 2024-2025 Matthew Luckie
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
#include "scamper_icmpext.h"
#include "scamper_trace.h"
#include "scamper_trace_int.h"
#include "scamper_ifname.h"
#include "scamper_ifname_int.h"
#include "common_ok.h"
#include "common_trace.h"
#include "utils.h"

typedef scamper_trace_t * (*scamper_trace_makefunc_t)(void);

static int trace_reply_ok(const scamper_trace_reply_t *in,
			  const scamper_trace_reply_t *out)
{
  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(addr_ok(in->addr, out->addr) != 0 ||
     str_ok(in->name, out->name) != 0 ||
     in->flags != out->flags ||
     in->ttl != out->ttl ||
     in->tos != out->tos ||
     in->size != out->size ||
     in->ipid != out->ipid ||
     in->reply_icmp_type != out->reply_icmp_type ||
     in->reply_icmp_code != out->reply_icmp_code ||
     in->reply_icmp_q_ttl != out->reply_icmp_q_ttl ||
     in->reply_icmp_q_ipl != out->reply_icmp_q_ipl ||
     in->reply_icmp_q_tos != out->reply_icmp_q_tos ||
     in->reply_icmp_nhmtu != out->reply_icmp_nhmtu ||
     in->reply_tcp_flags != out->reply_tcp_flags ||
     timeval_cmp(&in->rtt, &out->rtt) != 0 ||
     icmpexts_ok(in->icmp_exts, out->icmp_exts) != 0)
    return -1;

  return 0;
}

static int trace_probe_ok(const scamper_trace_probe_t *in,
			  const scamper_trace_probe_t *out)
{
  uint32_t r;

  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(in->id != out->id ||
     in->ttl != out->ttl ||
     in->size != out->size ||
     in->replyc != out->replyc ||
     in->flags != out->flags ||
     timeval_cmp(&in->tx, &out->tx) != 0)
    return -1;

  for(r=0; r<in->replyc; r++)
    if(trace_reply_ok(in->replies[r], out->replies[r]) != 0)
      return -1;

  return 0;
}

static int trace_lastditch_ok(const scamper_trace_lastditch_t *in,
			      const scamper_trace_lastditch_t *out)
{
  uint8_t i;

  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(in->probec != out->probec ||
     ptr_ok(in->probes, out->probes) != 0)
    return -1;

  for(i=0; i<in->probec; i++)
    if(trace_probe_ok(in->probes[i], out->probes[i]) != 0)
      return -1;

  return 0;
}

static int trace_pmtud_ok(const scamper_trace_pmtud_t *in,
			  const scamper_trace_pmtud_t *out)
{
  scamper_trace_pmtud_note_t *in_n, *out_n;
  uint8_t i;
  uint16_t j;

  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(in->ver != out->ver ||
     in->ifmtu != out->ifmtu ||
     in->outmtu != out->outmtu ||
     in->pmtu != out->pmtu ||
     in->notec != out->notec ||
     in->probec != out->probec ||
     ptr_ok(in->notes, out->notes) != 0 ||
     ptr_ok(in->probes, out->probes) != 0)
    return -1;

  for(i=0; i<in->notec; i++)
    {
      in_n = in->notes[i];
      out_n = out->notes[i];
      if(in_n == NULL || out_n == NULL ||
	 in_n->type != out_n->type ||
	 in_n->nhmtu != out_n->nhmtu ||
	 (in_n->reply != NULL &&
	  trace_reply_ok(in_n->reply, out_n->reply) != 0))
	return -1;
    }

  for(j=0; j<in->probec; j++)
    if(trace_probe_ok(in->probes[j], out->probes[j]) != 0)
      return -1;

  return 0;
}

int trace_probettl_ok(const scamper_trace_probettl_t *in,
		      const scamper_trace_probettl_t *out)
{
  uint16_t p;

  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(in->probec != out->probec)
    return -1;
  for(p=0; p<in->probec; p++)
    if(trace_probe_ok(in->probes[p], out->probes[p]) != 0)
      return -1;

  return 0;
}

int trace_ok(const scamper_trace_t *in, const scamper_trace_t *out)
{
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
     buf_ok(in->payload, out->payload, in->payload_len) != 0 ||
     trace_lastditch_ok(in->lastditch, out->lastditch) != 0 ||
     trace_pmtud_ok(in->pmtud, out->pmtud) != 0)
    return -1;

  for(i=0; i<in->hop_count; i++)
    if(trace_probettl_ok(in->hops[i], out->hops[i]) != 0)
      return -1;

  return 0;
}

static scamper_trace_probe_t *probe_alloc(uint8_t id,
					  uint8_t ttl, uint16_t size,
					  time_t tx_sec, uint32_t tx_usec)
{
  scamper_trace_probe_t *probe = NULL;

  if((probe = scamper_trace_probe_alloc()) == NULL)
    return NULL;
  probe->id = id;
  probe->ttl = ttl;
  probe->size = size;
  probe->tx.tv_sec = tx_sec;
  probe->tx.tv_usec = tx_usec;

  return probe;
}

static scamper_trace_reply_t *reply_alloc(const char *str, uint16_t probe_size,
					  uint8_t ttl, uint16_t size,
					  time_t rtt_sec, uint32_t rtt_usec)
{
  scamper_trace_reply_t *reply = NULL;

  if((reply = scamper_trace_reply_alloc()) == NULL ||
     (reply->addr = scamper_addr_fromstr(AF_UNSPEC, str)) == NULL)
    goto err;
  reply->ttl = ttl;
  reply->size = size;
  reply->rtt.tv_sec = rtt_sec;
  reply->rtt.tv_usec = rtt_usec;
  reply->reply_icmp_q_ipl = probe_size;
  reply->reply_icmp_q_ttl = 1;

  if(scamper_addr_isipv4(reply->addr))
    {
      reply->reply_icmp_type = ICMP_TIMXCEED;
      reply->reply_icmp_code = ICMP_TIMXCEED_INTRANS;
    }
  else
    {
      reply->reply_icmp_type = ICMP6_TIME_EXCEEDED;
      reply->reply_icmp_code = ICMP6_TIME_EXCEED_TRANSIT;
    }

  return reply;

 err:
  if(reply != NULL) scamper_trace_reply_free(reply);
  return NULL;
}

static int probe_reply_alloc(const char *str,
			     uint8_t p_id, uint8_t p_ttl, uint16_t p_size,
			     uint8_t r_ttl, uint16_t r_size,
			     time_t tx_sec, uint32_t tx_usec,
			     time_t rtt_sec, uint32_t rtt_usec,
			     scamper_trace_probe_t **p_out,
			     scamper_trace_reply_t **r_out)
{
  scamper_trace_probe_t *p = NULL;
  scamper_trace_reply_t *r = NULL;

  if((p = probe_alloc(p_id, p_ttl, p_size, tx_sec, tx_usec)) == NULL ||
     (r = reply_alloc(str, p_size, r_ttl, r_size, rtt_sec, rtt_usec)) == NULL ||
     scamper_trace_probe_reply_add(p, r) != 0)
    goto err;

  if(p_out != NULL) *p_out = p;
  if(r_out != NULL) *r_out = r;

  return 0;

 err:
  if(r != NULL) scamper_trace_reply_free(r);
  if(p != NULL) scamper_trace_probe_free(p);
  return -1;
}

static int trace_probe_reply_add(scamper_trace_t *trace, const char *str,
				 uint8_t probe_id,
				 uint8_t probe_ttl, uint16_t probe_size,
				 uint8_t reply_ttl, uint16_t reply_size,
				 time_t tx_sec, uint32_t tx_usec,
				 time_t rtt_sec, uint32_t rtt_usec,
				 scamper_trace_probe_t **p_out,
				 scamper_trace_reply_t **r_out)
{
  scamper_trace_probe_t *probe = NULL;
  scamper_trace_reply_t *reply = NULL;

  if(probe_reply_alloc(str, probe_id, probe_ttl, probe_size,
		       reply_ttl, reply_size, tx_sec, tx_usec,
		       rtt_sec, rtt_usec, &probe, &reply) != 0 ||
     scamper_trace_probettl_probe_add(trace->hops[probe_ttl-1], probe) != 0)
    goto err;

  if(p_out != NULL) *p_out = probe;
  if(r_out != NULL) *r_out = reply;

  return 0;

 err:
  if(reply != NULL) scamper_trace_reply_free(reply);
  if(probe != NULL) scamper_trace_probe_free(probe);
  return -1;
}

static int lastditch_probe_reply_add(scamper_trace_t *trace, const char *str,
				     uint8_t probe_id,
				     uint8_t probe_ttl, uint16_t probe_size,
				     uint8_t reply_ttl, uint16_t reply_size,
				     time_t tx_sec, uint32_t tx_usec,
				     time_t rtt_sec, uint32_t rtt_usec,
				     scamper_trace_probe_t **p_out,
				     scamper_trace_reply_t **r_out)
{
  scamper_trace_probe_t *probe = NULL;
  scamper_trace_reply_t *reply = NULL;

  if((trace->lastditch == NULL &&
      (trace->lastditch = scamper_trace_lastditch_alloc()) == NULL) ||
     probe_reply_alloc(str, probe_id, probe_ttl, probe_size,
		       reply_ttl, reply_size, tx_sec, tx_usec,
		       rtt_sec, rtt_usec, &probe, &reply) != 0 ||
     scamper_trace_lastditch_probe_add(trace->lastditch, probe) != 0)
    goto err;

  if(p_out != NULL) *p_out = probe;
  if(r_out != NULL) *r_out = reply;

  return 0;

 err:
  if(reply != NULL) scamper_trace_reply_free(reply);
  if(probe != NULL) scamper_trace_probe_free(probe);
  return -1;
}

static int pmtud_probe_reply_add(scamper_trace_t *trace, const char *str,
				 uint8_t probe_id,
				 uint8_t probe_ttl, uint16_t probe_size,
				 uint8_t reply_ttl, uint16_t reply_size,
				 time_t tx_sec, uint32_t tx_usec,
				 time_t rtt_sec, uint32_t rtt_usec,
				 scamper_trace_probe_t **p_out,
				 scamper_trace_reply_t **r_out)
{
  scamper_trace_probe_t *probe = NULL;
  scamper_trace_reply_t *reply = NULL;

  if((trace->pmtud == NULL &&
      (trace->pmtud = scamper_trace_pmtud_alloc()) == NULL) ||
     probe_reply_alloc(str, probe_id, probe_ttl, probe_size,
		       reply_ttl, reply_size, tx_sec, tx_usec,
		       rtt_sec, rtt_usec, &probe, &reply) != 0 ||
     scamper_trace_pmtud_probe_add(trace->pmtud, probe) != 0)
    goto err;

  if(p_out != NULL) *p_out = probe;
  if(r_out != NULL) *r_out = reply;

  return 0;

 err:
  if(reply != NULL) scamper_trace_reply_free(reply);
  if(probe != NULL) scamper_trace_probe_free(probe);
  return -1;
}

static int probettl_alloc(scamper_trace_t *trace, uint8_t n)
{
  uint8_t i;
  for(i=0; i<n; i++)
    if((trace->hops[i] = scamper_trace_probettl_alloc()) == NULL)
      return -1;
  return 0;
}

scamper_trace_t *trace_1(void)
{
  scamper_trace_t *trace = NULL;

  if((trace = scamper_trace_alloc()) == NULL ||
     (trace->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (trace->dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL ||
     scamper_trace_hops_alloc(trace, 5) != 0 ||
     probettl_alloc(trace, 2) != 0)
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

  if(trace_probe_reply_add(trace, "192.0.2.4", 1, 1, 44, 255, 56,
			   1724828853, 123456, 0, 253421, NULL, NULL) != 0 ||
     trace_probe_reply_add(trace, "192.0.2.4", 2, 1, 44, 255, 56,
			   1724828853, 423112, 0, 224313, NULL, NULL) != 0 ||
     trace_probe_reply_add(trace, "192.0.2.5", 1, 2, 44, 254, 72,
			   1724828853, 734231, 0, 234287, NULL, NULL) != 0 ||
     trace_probe_reply_add(trace, "192.0.2.5", 2, 2, 44, 254, 72,
			   1724828853, 992312, 0, 279734, NULL, NULL) != 0)
    goto err;

  return trace;

 err:
  if(trace != NULL) scamper_trace_free(trace);
  return NULL;
}

static scamper_trace_t *trace_2(void)
{
  scamper_trace_t *trace;
  scamper_trace_reply_t *r;

  if((trace = trace_1()) == NULL)
    goto err;

  trace->gapaction = 2;
  if(lastditch_probe_reply_add(trace, "192.0.2.2", 1, 255, 44, 240, 44,
			       1724828860, 534234, 0, 534223, NULL, &r) != 0)
    goto err;

  r->reply_icmp_type = ICMP_ECHOREPLY;
  r->reply_icmp_code = 0;
  r->reply_icmp_q_ipl = 0;
  r->reply_icmp_q_ttl = 0;

  return trace;

 err:
  if(trace != NULL) scamper_trace_free(trace);
  return NULL;
}

static scamper_trace_t *trace_3_base(void)
{
  scamper_trace_t *trace = NULL;
  scamper_trace_reply_t *r = NULL;

  if((trace = scamper_trace_alloc()) == NULL ||
     (trace->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (trace->dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL ||
     scamper_trace_hops_alloc(trace, 5) != 0 ||
     probettl_alloc(trace, 5) != 0)
    goto err;

  trace->userid               = 69;
  trace->sport                = 24419;
  trace->dport                = 34634;
  trace->start.tv_sec         = 1724828853;
  trace->start.tv_usec        = 123456;
  trace->wait_timeout.tv_sec  = 1;
  trace->wait_timeout.tv_usec = 0;
  trace->flags                = 0;
  trace->hop_count            = 5;
  trace->firsthop             = 1;
  trace->squeries             = 1;
  trace->gaplimit             = 5;
  trace->attempts             = 1;
  trace->probec               = 5;
  trace->stop_reason          = SCAMPER_TRACE_STOP_COMPLETED;
  trace->type                 = SCAMPER_TRACE_TYPE_UDP_PARIS;

  if(trace_probe_reply_add(trace, "192.0.2.4", 1, 1, 44, 255, 56,
			   1724828853, 123456, 0, 253421, NULL, NULL) != 0 ||
     trace_probe_reply_add(trace, "192.0.2.5", 1, 2, 44, 254, 72,
			   1724828853, 423112, 0, 234287, NULL, NULL) != 0 ||
     trace_probe_reply_add(trace, "192.0.2.6", 1, 3, 44, 253, 56,
			   1724828853, 734231, 0, 224313, NULL, NULL) != 0 ||
     trace_probe_reply_add(trace, "192.0.2.7", 1, 4, 44, 252, 72,
			   1724828853, 992312, 0, 279734, NULL, NULL) != 0 ||
     trace_probe_reply_add(trace, "192.0.2.2", 1, 5, 44, 251, 72,
			   1724828854, 243542, 0, 269439, NULL, &r) != 0)
    goto err;

  r->reply_icmp_type = ICMP_UNREACH;
  r->reply_icmp_code = ICMP_UNREACH_PORT;

  return trace;

 err:
  if(trace != NULL) scamper_trace_free(trace);
  return NULL;
}

static scamper_trace_t *trace_3(void)
{
  return trace_3_base();
}

static scamper_trace_t *trace_4(void)
{
  scamper_trace_t *trace = NULL;
  scamper_trace_probe_t *p = NULL;
  scamper_trace_reply_t *r = NULL;
  scamper_trace_pmtud_t *pmtud = NULL;
  scamper_trace_pmtud_note_t *n = NULL;

  if((trace = trace_3_base()) == NULL ||
     pmtud_probe_reply_add(trace, "192.0.2.4", 1, 1, 1500, 255, 596,
			   1724828860, 472568, 0, 219732, &p, &r) != 0 ||
     (n = scamper_trace_pmtud_note_alloc()) == NULL)
    goto err;

  trace->flags |= SCAMPER_TRACE_FLAG_PMTUD;

  pmtud = trace->pmtud;
  pmtud->ver = 2;
  pmtud->ifmtu = 1500;
  pmtud->pmtu = 1492;

  n->type = SCAMPER_TRACE_PMTUD_NOTE_TYPE_SILENCE;
  n->nhmtu = 1492;
  n->probe = p;
  n->reply = r;
  if(scamper_trace_pmtud_note_add(pmtud, n) != 0)
    goto err;

  return trace;

 err:
  if(n != NULL) scamper_trace_pmtud_note_free(n);
  if(trace != NULL) scamper_trace_free(trace);
  return NULL;
}

static scamper_trace_t *trace_5(void)
{
  scamper_trace_t *trace = NULL;
  scamper_trace_pmtud_t *pmtud = NULL;
  scamper_trace_pmtud_note_t *n = NULL;
  scamper_trace_probe_t *ps[3];
  scamper_trace_reply_t *rs[3];
  int i;

  memset(ps, 0, sizeof(ps));
  memset(rs, 0, sizeof(rs));

  if((trace = trace_3_base()) == NULL ||
     pmtud_probe_reply_add(trace, "192.0.2.5", 1, 255, 1500, 254, 72,
			   1724828860, 472568, 0, 219732, &ps[0],&rs[0]) != 0 ||
     pmtud_probe_reply_add(trace, "192.0.2.7", 1, 255, 1492, 252, 72,
			   1724828860, 701252, 0, 223927, &ps[1],&rs[1]) != 0 ||
     pmtud_probe_reply_add(trace, "192.0.2.2", 1, 255, 1480, 251, 72,
			   1724828860, 952023, 0, 252342, &ps[2],&rs[2]) != 0)
    goto err;

  trace->flags |= SCAMPER_TRACE_FLAG_PMTUD;

  pmtud = trace->pmtud;
  pmtud->ver = 2;
  pmtud->ifmtu = 1500;
  pmtud->pmtu = 1480;

  for(i=0; i<3; i++)
    rs[i]->reply_icmp_type = ICMP_UNREACH;
  rs[0]->reply_icmp_code  = ICMP_UNREACH_NEEDFRAG;
  rs[0]->reply_icmp_nhmtu = 1492;
  rs[1]->reply_icmp_code  = ICMP_UNREACH_NEEDFRAG;
  rs[1]->reply_icmp_nhmtu = 1480;
  rs[2]->reply_icmp_code  = ICMP_UNREACH_PORT;

  for(i=0; i<2; i++)
    {
      if((n = scamper_trace_pmtud_note_alloc()) == NULL)
	goto err;
      n->type = SCAMPER_TRACE_PMTUD_NOTE_TYPE_PTB;
      n->probe = ps[i];
      n->reply = rs[i];
      n->nhmtu = rs[i]->reply_icmp_nhmtu;
      if(scamper_trace_pmtud_note_add(pmtud, n) != 0)
	goto err;
    }

  return trace;

 err:
  if(n != NULL) scamper_trace_pmtud_note_free(n);
  if(trace != NULL) scamper_trace_free(trace);
  return NULL;
}

static scamper_trace_makefunc_t makers[] = {
  trace_1,
  trace_2,
  trace_3,
  trace_4,
  trace_5,
};

scamper_trace_t *trace_makers(size_t i)
{
  if(i >= sizeof(makers) / sizeof(scamper_trace_makefunc_t))
    return NULL;
  return makers[i]();
}

size_t trace_makerc(void)
{
  return sizeof(makers) / sizeof(scamper_trace_makefunc_t);
}
