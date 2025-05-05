/*
 * scamper_trace_lib.c
 *
 * $Id: scamper_trace_lib.c,v 1.19 2025/05/01 02:58:04 mjl Exp $
 *
 * Copyright (C) 2023-2025 Matthew Luckie
 *
 * Authors: Matthew Luckie
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
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_trace.h"
#include "scamper_trace_int.h"

#include "utils.h"

scamper_trace_hopiter_t *scamper_trace_hopiter_dup(scamper_trace_hopiter_t *in)
{
  return memdup(in, sizeof(scamper_trace_hopiter_t));
}

scamper_trace_hopiter_t *scamper_trace_hopiter_alloc(void)
{
  return malloc_zero(sizeof(scamper_trace_hopiter_t));
}

void scamper_trace_hopiter_free(scamper_trace_hopiter_t *hi)
{
  free(hi);
  return;
}

scamper_trace_pmtud_t *scamper_trace_pmtud_get(const scamper_trace_t *trace)
{
  return trace->pmtud;
}

uint8_t scamper_trace_pmtud_ver_get(const scamper_trace_pmtud_t *pmtud)
{
  return pmtud->ver;
}

uint16_t scamper_trace_pmtud_pmtu_get(const scamper_trace_pmtud_t *pmtud)
{
  return pmtud->pmtu;
}

uint16_t scamper_trace_pmtud_ifmtu_get(const scamper_trace_pmtud_t *pmtud)
{
  return pmtud->ifmtu;
}

uint16_t scamper_trace_pmtud_outmtu_get(const scamper_trace_pmtud_t *pmtud)
{
  return pmtud->outmtu;
}

uint8_t scamper_trace_pmtud_notec_get(const scamper_trace_pmtud_t *pmtud)
{
  return pmtud->notec;
}

scamper_trace_pmtud_note_t *
scamper_trace_pmtud_note_get(const scamper_trace_pmtud_t *pmtud, uint8_t note)
{
  if(note >= pmtud->notec || pmtud->notes == NULL)
    return NULL;
  return pmtud->notes[note];
}

uint16_t scamper_trace_pmtud_probec_get(const scamper_trace_pmtud_t *pmtud)
{
  return pmtud->probec;
}

scamper_trace_probe_t *
scamper_trace_pmtud_probe_get(const scamper_trace_pmtud_t *pmtud, uint16_t p)
{
  if(p >= pmtud->probec || pmtud->probes == NULL)
    return NULL;
  return pmtud->probes[p];
}

scamper_trace_probe_t *
scamper_trace_pmtud_note_probe_get(const scamper_trace_pmtud_note_t *n)
{
  return n->probe;
}

scamper_trace_reply_t *
scamper_trace_pmtud_note_reply_get(const scamper_trace_pmtud_note_t *n)
{
  return n->reply;
}

uint16_t scamper_trace_pmtud_note_nhmtu_get(const scamper_trace_pmtud_note_t *n)
{
  return n->nhmtu;
}

uint8_t scamper_trace_pmtud_note_type_get(const scamper_trace_pmtud_note_t *n)
{
  return n->type;
}

scamper_trace_lastditch_t *scamper_trace_lastditch_get(const scamper_trace_t *trace)
{
  return trace->lastditch;
}

uint8_t scamper_trace_lastditch_probec_get(const scamper_trace_lastditch_t *ld)
{
  return ld->probec;
}

scamper_trace_probe_t *scamper_trace_lastditch_probe_get(const scamper_trace_lastditch_t *ld, uint8_t p)
{
  if(p >= ld->probec || ld->probes == NULL)
    return NULL;
  return ld->probes[p];
}

scamper_trace_dtree_t *scamper_trace_dtree_get(const scamper_trace_t *trace)
{
  return trace->dtree;
}

scamper_addr_t *scamper_trace_dtree_lss_stop_get(const scamper_trace_dtree_t *dtree)
{
  return dtree->lss_stop;
}

scamper_addr_t *scamper_trace_dtree_gss_stop_get(const scamper_trace_dtree_t *dtree)
{
  return dtree->gss_stop;
}

uint8_t scamper_trace_dtree_firsthop_get(const scamper_trace_dtree_t *dtree)
{
  return dtree->firsthop;
}

const char *scamper_trace_dtree_lss_get(const scamper_trace_dtree_t *dtree)
{
  return dtree->lss;
}

scamper_addr_t *scamper_trace_reply_addr_get(const scamper_trace_reply_t *reply)
{
  return reply->addr;
}

const char *scamper_trace_reply_name_get(const scamper_trace_reply_t *reply)
{
  return reply->name;
}

uint32_t scamper_trace_reply_flags_get(const scamper_trace_reply_t *reply)
{
  return reply->flags;
}

uint16_t scamper_trace_payload_len_get(const scamper_trace_t *trace)
{
  return trace->payload_len;
}

const uint8_t *scamper_trace_payload_get(const scamper_trace_t *trace)
{
  return trace->payload;
}

const struct timeval *
scamper_trace_reply_rtt_get(const scamper_trace_reply_t *reply)
{
  return &reply->rtt;
}

uint8_t scamper_trace_reply_ttl_get(const scamper_trace_reply_t *reply)
{
  return reply->ttl;
}

uint8_t scamper_trace_reply_tos_get(const scamper_trace_reply_t *reply)
{
  return reply->tos;
}

uint16_t scamper_trace_reply_size_get(const scamper_trace_reply_t *reply)
{
  return reply->size;
}

uint16_t scamper_trace_reply_ipid_get(const scamper_trace_reply_t *reply)
{
  return reply->ipid;
}

int scamper_trace_reply_is_icmp_q(const scamper_trace_reply_t *reply)
{
  return SCAMPER_TRACE_REPLY_IS_ICMP_Q(reply);
}

int scamper_trace_reply_is_icmp_unreach_port(const scamper_trace_reply_t *reply)
{
  return SCAMPER_TRACE_REPLY_IS_ICMP_UNREACH_PORT(reply);
}

int scamper_trace_reply_is_icmp_echo_reply(const scamper_trace_reply_t *reply)
{
  return SCAMPER_TRACE_REPLY_IS_ICMP_ECHO_REPLY(reply);
}

int scamper_trace_reply_is_icmp_ttl_exp(const scamper_trace_reply_t *reply)
{
  return SCAMPER_TRACE_REPLY_IS_ICMP_TTL_EXP(reply);
}

int scamper_trace_reply_is_icmp_ptb(const scamper_trace_reply_t *reply)
{
  return SCAMPER_TRACE_REPLY_IS_ICMP_PTB(reply);
}

int scamper_trace_reply_is_tcp(const scamper_trace_reply_t *reply)
{
  return SCAMPER_TRACE_REPLY_IS_TCP(reply);
}

int scamper_trace_reply_is_icmp(const scamper_trace_reply_t *reply)
{
  return SCAMPER_TRACE_REPLY_IS_ICMP(reply);
}

uint16_t scamper_trace_reply_icmp_nhmtu_get(const scamper_trace_reply_t *reply)
{
  return reply->reply_icmp_nhmtu;
}

uint8_t scamper_trace_reply_icmp_q_ttl_get(const scamper_trace_reply_t *reply)
{
  return reply->reply_icmp_q_ttl;
}

uint8_t scamper_trace_reply_icmp_q_tos_get(const scamper_trace_reply_t *reply)
{
  return reply->reply_icmp_q_tos;
}

uint16_t scamper_trace_reply_icmp_q_ipl_get(const scamper_trace_reply_t *reply)
{
  return reply->reply_icmp_q_ipl;
}

uint8_t scamper_trace_reply_tcp_flags_get(const scamper_trace_reply_t *reply)
{
  return reply->reply_tcp_flags;
}

uint8_t scamper_trace_reply_icmp_type_get(const scamper_trace_reply_t *reply)
{
  return reply->reply_icmp_type;
}

uint8_t scamper_trace_reply_icmp_code_get(const scamper_trace_reply_t *reply)
{
  return reply->reply_icmp_code;
}

scamper_icmpexts_t *
scamper_trace_reply_icmp_exts_get(const scamper_trace_reply_t *reply)
{
  return reply->icmp_exts;
}

scamper_trace_probettl_t *
scamper_trace_probettl_get(const scamper_trace_t *trace, uint8_t ttl)
{
  if(trace->hops == NULL || ttl == 0 || ttl > trace->hop_count)
    return NULL;
  return trace->hops[ttl-1];
}

scamper_trace_probe_t *scamper_trace_probettl_probe_get(const scamper_trace_probettl_t *pttl, uint8_t i)
{
  if(i >= pttl->probec || pttl->probes == NULL)
    return NULL;
  return pttl->probes[i];
}

uint8_t scamper_trace_probettl_probec_get(const scamper_trace_probettl_t *pttl)
{
  return pttl->probec;
}

uint16_t scamper_trace_probe_replyc_get(const scamper_trace_probe_t *probe)
{
  return probe->replyc;
}

scamper_trace_reply_t *scamper_trace_probe_reply_get(const scamper_trace_probe_t *probe, uint16_t i)
{
  if(i >= probe->replyc || probe->replies == NULL)
    return NULL;
  return probe->replies[i];
}

const struct timeval *
scamper_trace_probe_tx_get(const scamper_trace_probe_t *probe)
{
  return &probe->tx;
}

uint8_t scamper_trace_probe_id_get(const scamper_trace_probe_t *probe)
{
  return probe->id;
}

uint8_t scamper_trace_probe_ttl_get(const scamper_trace_probe_t *probe)
{
  return probe->ttl;
}

uint16_t scamper_trace_probe_size_get(const scamper_trace_probe_t *probe)
{
  return probe->size;
}

uint8_t scamper_trace_type_get(const scamper_trace_t *trace)
{
  return trace->type;
}

uint8_t scamper_trace_attempts_get(const scamper_trace_t *trace)
{
  return trace->attempts;
}

uint8_t scamper_trace_hoplimit_get(const scamper_trace_t *trace)
{
  return trace->hoplimit;
}

uint8_t scamper_trace_squeries_get(const scamper_trace_t *trace)
{
  return trace->squeries;
}

uint8_t scamper_trace_gaplimit_get(const scamper_trace_t *trace)
{
  return trace->gaplimit;
}

uint8_t scamper_trace_gapaction_get(const scamper_trace_t *trace)
{
  return trace->gapaction;
}

scamper_addr_t *scamper_trace_src_get(const scamper_trace_t *trace)
{
  return trace->src;
}

scamper_addr_t *scamper_trace_dst_get(const scamper_trace_t *trace)
{
  return trace->dst;
}

int scamper_trace_dst_is_ipv4(const scamper_trace_t *trace)
{
  return SCAMPER_ADDR_TYPE_IS_IPV4(trace->dst);
}

scamper_addr_t *scamper_trace_rtr_get(const scamper_trace_t *trace)
{
  return trace->rtr;
}

scamper_list_t *scamper_trace_list_get(const scamper_trace_t *trace)
{
  return trace->list;
}

scamper_cycle_t *scamper_trace_cycle_get(const scamper_trace_t *trace)
{
  return trace->cycle;
}

uint32_t scamper_trace_userid_get(const scamper_trace_t *trace)
{
  return trace->userid;
}

const struct timeval *scamper_trace_start_get(const scamper_trace_t *trace)
{
  return &trace->start;
}

uint8_t scamper_trace_stop_reason_get(const scamper_trace_t *trace)
{
  return trace->stop_reason;
}

uint8_t scamper_trace_stop_data_get(const scamper_trace_t *trace)
{
  return trace->stop_data;
}

uint16_t scamper_trace_hop_count_get(const scamper_trace_t *trace)
{
  return trace->hop_count;
}

uint8_t scamper_trace_stop_hop_get(const scamper_trace_t *trace)
{
  return trace->stop_hop;
}

uint8_t scamper_trace_firsthop_get(const scamper_trace_t *trace)
{
  return trace->firsthop;
}

uint8_t scamper_trace_tos_get(const scamper_trace_t *trace)
{
  return trace->tos;
}

const struct timeval *scamper_trace_wait_timeout_get(const scamper_trace_t *trace)
{
  return &trace->wait_timeout;
}

const struct timeval *scamper_trace_wait_probe_get(const scamper_trace_t *trace)
{
  return &trace->wait_probe;
}

uint8_t scamper_trace_loops_get(const scamper_trace_t *trace)
{
  return trace->loops;
}

uint8_t scamper_trace_loopaction_get(const scamper_trace_t *trace)
{
  return trace->loopaction;
}

uint8_t scamper_trace_confidence_get(const scamper_trace_t *trace)
{
  return trace->confidence;
}

uint16_t scamper_trace_size_get(const scamper_trace_t *trace)
{
  return trace->probe_size;
}

uint16_t scamper_trace_sport_get(const scamper_trace_t *trace)
{
  return trace->sport;
}

uint16_t scamper_trace_dport_get(const scamper_trace_t *trace)
{
  return trace->dport;
}

uint16_t scamper_trace_offset_get(const scamper_trace_t *trace)
{
  return trace->offset;
}

uint32_t scamper_trace_flags_get(const scamper_trace_t *trace)
{
  return trace->flags;
}

uint16_t scamper_trace_probec_get(const scamper_trace_t *trace)
{
  return trace->probec;
}

int scamper_trace_type_is_udp(const scamper_trace_t *trace)
{
  return SCAMPER_TRACE_TYPE_IS_UDP(trace);
}

int scamper_trace_type_is_tcp(const scamper_trace_t *trace)
{
  return SCAMPER_TRACE_TYPE_IS_TCP(trace);
}

int scamper_trace_type_is_icmp(const scamper_trace_t *trace)
{
  return SCAMPER_TRACE_TYPE_IS_ICMP(trace);
}

int scamper_trace_flag_is_icmpcsumdp(const scamper_trace_t *trace)
{
  return SCAMPER_TRACE_FLAG_IS_ICMPCSUMDP(trace);
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_trace_lastditch_t *scamper_trace_lastditch_use(scamper_trace_lastditch_t *ld)
{
  ld->refcnt++;
  return ld;
}

scamper_trace_pmtud_t *scamper_trace_pmtud_use(scamper_trace_pmtud_t *pmtud)
{
  pmtud->refcnt++;
  return pmtud;
}

scamper_trace_pmtud_note_t *
scamper_trace_pmtud_note_use(scamper_trace_pmtud_note_t *n)
{
  n->refcnt++;
  return n;
}

scamper_trace_dtree_t *scamper_trace_dtree_use(scamper_trace_dtree_t *dt)
{
  dt->refcnt++;
  return dt;
}

scamper_trace_reply_t *scamper_trace_reply_use(scamper_trace_reply_t *hop)
{
  hop->refcnt++;
  return hop;
}

scamper_trace_probe_t *scamper_trace_probe_use(scamper_trace_probe_t *probe)
{
  probe->refcnt++;
  return probe;
}
#endif
