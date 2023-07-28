/*
 * scamper_ping_lib.c
 *
 * Copyright (C) 2023 Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_ping_lib.c,v 1.1 2023/05/31 23:22:18 mjl Exp $
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
#include "scamper_addr_int.h"
#include "scamper_ping.h"
#include "scamper_ping_int.h"

scamper_list_t *scamper_ping_list_get(const scamper_ping_t *ping)
{
  return ping->list;
}

scamper_cycle_t *scamper_ping_cycle_get(const scamper_ping_t *ping)
{
  return ping->cycle;
}

uint32_t scamper_ping_userid_get(const scamper_ping_t *ping)
{
  return ping->userid;
}

scamper_addr_t *scamper_ping_dst_get(const scamper_ping_t *ping)
{
  return ping->dst;
}

scamper_addr_t *scamper_ping_src_get(const scamper_ping_t *ping)
{
  return ping->src;
}

scamper_addr_t *scamper_ping_rtr_get(const scamper_ping_t *ping)
{
  return ping->rtr;
}

const struct timeval *scamper_ping_start_get(const scamper_ping_t *ping)
{
  return &ping->start;
}

uint8_t scamper_ping_stop_reason_get(const scamper_ping_t *ping)
{
  return ping->stop_reason;
}

uint8_t scamper_ping_stop_data_get(const scamper_ping_t *ping)
{
  return ping->stop_data;
}

const uint8_t *scamper_ping_probe_data_get(const scamper_ping_t *ping)
{
  return ping->probe_data;
}

uint16_t scamper_ping_probe_datalen_get(const scamper_ping_t *ping)
{
  return ping->probe_datalen;
}

uint16_t scamper_ping_probe_count_get(const scamper_ping_t *ping)
{
  return ping->probe_count;
}

uint16_t scamper_ping_probe_size_get(const scamper_ping_t *ping)
{
  return ping->probe_size;
}

uint8_t scamper_ping_probe_method_get(const scamper_ping_t *ping)
{
  return ping->probe_method;
}

int scamper_ping_method_is_icmp(const scamper_ping_t *ping)
{
  return SCAMPER_PING_METHOD_IS_ICMP(ping);
}
int scamper_ping_method_is_icmp_time(const scamper_ping_t *ping)
{
  return SCAMPER_PING_METHOD_IS_ICMP_TIME(ping);
}
int scamper_ping_method_is_tcp(const scamper_ping_t *ping)
{
  return SCAMPER_PING_METHOD_IS_TCP(ping);
}

int scamper_ping_method_is_tcp_ack_sport(const scamper_ping_t *ping)
{
  return SCAMPER_PING_METHOD_IS_TCP_ACK_SPORT(ping);
}

int scamper_ping_method_is_udp(const scamper_ping_t *ping)
{
  return SCAMPER_PING_METHOD_IS_UDP(ping);
}

int scamper_ping_method_is_vary_sport(const scamper_ping_t *ping)
{
  return SCAMPER_PING_METHOD_IS_VARY_SPORT(ping);
}

int scamper_ping_method_is_vary_dport(const scamper_ping_t *ping)
{
  return SCAMPER_PING_METHOD_IS_VARY_DPORT(ping);
}

uint8_t scamper_ping_probe_ttl_get(const scamper_ping_t *ping)
{
  return ping->probe_ttl;
}

uint8_t scamper_ping_probe_tos_get(const scamper_ping_t *ping)
{
  return ping->probe_tos;
}

uint8_t scamper_ping_probe_timeout_get(const scamper_ping_t *ping)
{
  return ping->probe_timeout;
}

uint32_t scamper_ping_probe_timeout_us_get(const scamper_ping_t *ping)
{
  return ping->probe_timeout_us;
}

uint8_t scamper_ping_probe_wait_get(const scamper_ping_t *ping)
{
  return ping->probe_wait;
}
uint32_t scamper_ping_probe_wait_us_get(const scamper_ping_t *ping)
{
  return ping->probe_wait_us;
}

uint16_t scamper_ping_probe_sport_get(const scamper_ping_t *ping)
{
  return ping->probe_sport;
}

uint16_t scamper_ping_probe_dport_get(const scamper_ping_t *ping)
{
  return ping->probe_dport;
}

uint16_t scamper_ping_probe_icmpsum_get(const scamper_ping_t *ping)
{
  return ping->probe_icmpsum;
}

uint32_t scamper_ping_probe_tcpseq_get(const scamper_ping_t *ping)
{
  return ping->probe_tcpseq;
}

uint32_t scamper_ping_probe_tcpack_get(const scamper_ping_t *ping)
{
  return ping->probe_tcpack;
}

const scamper_ping_v4ts_t *scamper_ping_probe_tsps_get(const scamper_ping_t *ping)
{
  return ping->probe_tsps;
}

uint32_t scamper_ping_flags_get(const scamper_ping_t *ping)
{
  return ping->flags;
}

uint16_t scamper_ping_reply_count_get(const scamper_ping_t *ping)
{
  return ping->reply_count;
}

uint16_t scamper_ping_reply_pmtu_get(const scamper_ping_t *ping)
{
  return ping->reply_pmtu;
}

uint16_t scamper_ping_sent_get(const scamper_ping_t *ping)
{
  return ping->ping_sent;
}

const scamper_ping_reply_t *scamper_ping_reply_get(const scamper_ping_t *ping, uint16_t i)
{
  if(i >= ping->ping_sent)
    return NULL;
  return ping->ping_replies[i];
}

int scamper_ping_reply_is_from_target(const scamper_ping_t *ping, const scamper_ping_reply_t *reply)
{
  return SCAMPER_PING_REPLY_IS_FROM_TARGET(ping, reply);
}

scamper_addr_t *scamper_ping_reply_addr_get(const scamper_ping_reply_t *reply)
{
  return reply->addr;
}

uint16_t scamper_ping_reply_probe_id_get(const scamper_ping_reply_t *reply)
{
  return reply->probe_id;
}

uint16_t scamper_ping_reply_probe_ipid_get(const scamper_ping_reply_t *reply)
{
  return reply->probe_ipid;
}

uint8_t scamper_ping_reply_proto_get(const scamper_ping_reply_t *reply)
{
  return reply->reply_proto;
}

uint8_t scamper_ping_reply_ttl_get(const scamper_ping_reply_t *reply)
{
  return reply->reply_ttl;
}

uint16_t scamper_ping_reply_size_get(const scamper_ping_reply_t *reply)
{
  return reply->reply_size;
}

uint16_t scamper_ping_reply_ipid_get(const scamper_ping_reply_t *reply)
{
  return reply->reply_ipid;
}

uint32_t scamper_ping_reply_ipid32_get(const scamper_ping_reply_t *reply)
{
  return reply->reply_ipid32;
}

uint32_t scamper_ping_reply_flags_get(const scamper_ping_reply_t *reply)
{
  return reply->flags;
}

int scamper_ping_reply_flag_is_reply_ipid(const scamper_ping_reply_t *reply)
{
  if((reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID) != 0)
    return 1;
  return 0;
}

uint8_t scamper_ping_reply_icmp_type_get(const scamper_ping_reply_t *reply)
{
  return reply->icmp_type;
}

uint8_t scamper_ping_reply_icmp_code_get(const scamper_ping_reply_t *reply)
{
  return reply->icmp_code;
}

uint8_t scamper_ping_reply_tcp_flags_get(const scamper_ping_reply_t *reply)
{
  return reply->tcp_flags;
}

int scamper_ping_reply_is_icmp(const scamper_ping_reply_t *reply)
{
  return SCAMPER_PING_REPLY_IS_ICMP(reply);
}

int scamper_ping_reply_is_tcp(const scamper_ping_reply_t *reply)
{
  return SCAMPER_PING_REPLY_IS_TCP(reply);
}

int scamper_ping_reply_is_udp(const scamper_ping_reply_t *reply)
{
  return SCAMPER_PING_REPLY_IS_UDP(reply);
}

int scamper_ping_reply_is_icmp_echo_reply(const scamper_ping_reply_t *reply)
{
  return SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply);
}

int scamper_ping_reply_is_icmp_unreach(const scamper_ping_reply_t *reply)
{
  return SCAMPER_PING_REPLY_IS_ICMP_UNREACH(reply);
}

int scamper_ping_reply_is_icmp_unreach_port(const scamper_ping_reply_t *reply)
{
  return SCAMPER_PING_REPLY_IS_ICMP_UNREACH_PORT(reply);
}

int scamper_ping_reply_is_icmp_ttl_exp(const scamper_ping_reply_t *reply)
{
  return SCAMPER_PING_REPLY_IS_ICMP_TTL_EXP(reply);
}

int scamper_ping_reply_is_icmp_tsreply(const scamper_ping_reply_t *reply)
{
  return SCAMPER_PING_REPLY_IS_ICMP_TSREPLY(reply);
}

const struct timeval *scamper_ping_reply_tx_get(const scamper_ping_reply_t *reply)
{
  return &reply->tx;
}

const struct timeval *scamper_ping_reply_rtt_get(const scamper_ping_reply_t *reply)
{
  return &reply->rtt;
}

const scamper_ping_reply_t *scamper_ping_reply_next_get(const scamper_ping_reply_t *reply)
{
  return reply->next;
}

const scamper_ping_reply_v4rr_t *scamper_ping_reply_v4rr_get(const scamper_ping_reply_t *reply)
{
  return reply->v4rr;
}

const scamper_ping_reply_v4ts_t *scamper_ping_reply_v4ts_get(const scamper_ping_reply_t *reply)
{
  return reply->v4ts;
}

const scamper_ping_reply_tsreply_t *scamper_ping_reply_tsreply_get(const scamper_ping_reply_t *reply)
{
  return reply->tsreply;
}

uint32_t scamper_ping_reply_tsreply_tso_get(const scamper_ping_reply_tsreply_t *tsr)
{
  return tsr->tso;
}

uint32_t scamper_ping_reply_tsreply_tsr_get(const scamper_ping_reply_tsreply_t *tsr)
{
  return tsr->tsr;
}

uint32_t scamper_ping_reply_tsreply_tst_get(const scamper_ping_reply_tsreply_t *tsr)
{
  return tsr->tst;
}

uint8_t scamper_ping_reply_v4rr_ipc_get(const scamper_ping_reply_v4rr_t *rr)
{
  return rr->ipc;
}

scamper_addr_t *scamper_ping_reply_v4rr_ip_get(const scamper_ping_reply_v4rr_t *rr, uint8_t i)
{
  if(rr->ipc <= i)
    return NULL;
  return rr->ip[i];
}

uint8_t scamper_ping_reply_v4ts_tsc_get(const scamper_ping_reply_v4ts_t *ts)
{
  return ts->tsc;
}

uint32_t scamper_ping_reply_v4ts_ts_get(const scamper_ping_reply_v4ts_t *ts, uint8_t i)
{
  if(ts->tsc <= i)
    return 0;
  return ts->tss[i];
}

int scamper_ping_reply_v4ts_hasip(const scamper_ping_reply_v4ts_t *ts)
{
  if(ts->tss != NULL)
    return 1;
  return 0;
}

scamper_addr_t *scamper_ping_reply_v4ts_ip_get(const scamper_ping_reply_v4ts_t *ts, uint8_t i)
{
  if(ts->tsc <= i)
    return NULL;
  return ts->ips[i];
}

uint8_t scamper_ping_v4ts_ipc_get(const scamper_ping_v4ts_t *ts)
{
  return ts->ipc;
}

scamper_addr_t *scamper_ping_v4ts_ip_get(const scamper_ping_v4ts_t *ts, uint8_t i)
{
  if(ts->ipc <= i)
    return NULL;
  return ts->ips[i];
}

uint32_t scamper_ping_stats_nreplies_get(const scamper_ping_stats_t *stats)
{
  return stats->nreplies;
}

uint32_t scamper_ping_stats_ndups_get(const scamper_ping_stats_t *stats)
{
  return stats->ndups;
}

uint32_t scamper_ping_stats_nloss_get(const scamper_ping_stats_t *stats)
{
  return stats->nloss;
}

uint32_t scamper_ping_stats_nerrs_get(const scamper_ping_stats_t *stats)
{
  return stats->nerrs;
}

const struct timeval *scamper_ping_stats_min_rtt_get(const scamper_ping_stats_t *stats)
{
  return &stats->min_rtt;
}

const struct timeval *scamper_ping_stats_max_rtt_get(const scamper_ping_stats_t *stats)
{
  return &stats->max_rtt;
}

const struct timeval *scamper_ping_stats_avg_rtt_get(const scamper_ping_stats_t *stats)
{
  return &stats->avg_rtt;
}

const struct timeval *scamper_ping_stats_stddev_rtt_get(const scamper_ping_stats_t *stats)
{
  return &stats->stddev_rtt;
}
