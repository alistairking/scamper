/*
 * scamper_tracelb_lib.c
 *
 * $Id: scamper_tracelb_lib.c,v 1.11 2023/12/21 06:11:32 mjl Exp $
 *
 * Copyright (C) 2023 Matthew Luckie
 * Author: Matthew Luckie
 *
 * Load-balancer traceroute technique authored by
 * Brice Augustin, Timur Friedman, Renata Teixeira; "Measuring Load-balanced
 *  Paths in the Internet", in Proc. Internet Measurement Conference 2007.
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
#include "scamper_tracelb.h"
#include "scamper_tracelb_int.h"

scamper_list_t *scamper_tracelb_list_get(const scamper_tracelb_t *trace)
{
  return trace->list;
}

scamper_cycle_t *scamper_tracelb_cycle_get(const scamper_tracelb_t *trace)
{
  return trace->cycle;
}

uint32_t scamper_tracelb_userid_get(const scamper_tracelb_t *trace)
{
  return trace->userid;
}

scamper_addr_t *scamper_tracelb_src_get(const scamper_tracelb_t *trace)
{
  return trace->src;
}

scamper_addr_t *scamper_tracelb_dst_get(const scamper_tracelb_t *trace)
{
  return trace->dst;
}

scamper_addr_t *scamper_tracelb_rtr_get(const scamper_tracelb_t *trace)
{
  return trace->rtr;
}

const struct timeval *scamper_tracelb_start_get(const scamper_tracelb_t *trace)
{
  return &trace->start;
}

uint16_t scamper_tracelb_sport_get(const scamper_tracelb_t *trace)
{
  return trace->sport;
}

uint16_t scamper_tracelb_dport_get(const scamper_tracelb_t *trace)
{
  return trace->dport;
}

uint16_t scamper_tracelb_probe_size_get(const scamper_tracelb_t *trace)
{
  return trace->probe_size;
}

uint8_t scamper_tracelb_type_get(const scamper_tracelb_t *trace)
{
  return trace->type;
}

uint8_t scamper_tracelb_firsthop_get(const scamper_tracelb_t *trace)
{
  return trace->firsthop;
}

const struct timeval *scamper_tracelb_wait_timeout_get(const scamper_tracelb_t *trace)
{
  return &trace->wait_timeout;
}

const struct timeval *scamper_tracelb_wait_probe_get(const scamper_tracelb_t *trace)
{
  return &trace->wait_probe;
}

uint8_t scamper_tracelb_attempts_get(const scamper_tracelb_t *trace)
{
  return trace->attempts;
}

uint8_t scamper_tracelb_confidence_get(const scamper_tracelb_t *trace)
{
  return trace->confidence;
}

uint8_t scamper_tracelb_tos_get(const scamper_tracelb_t *trace)
{
  return trace->tos;
}

uint8_t scamper_tracelb_gaplimit_get(const scamper_tracelb_t *trace)
{
  return trace->gaplimit;
}

uint32_t scamper_tracelb_flags_get(const scamper_tracelb_t *trace)
{
  return trace->flags;
}

uint32_t scamper_tracelb_probec_max_get(const scamper_tracelb_t *trace)
{
  return trace->probec_max;
}

scamper_tracelb_node_t *scamper_tracelb_node_get(const scamper_tracelb_t *trace, uint16_t i)
{
  if(i >= trace->nodec)
    return NULL;
  return trace->nodes[i];
}

uint16_t scamper_tracelb_nodec_get(const scamper_tracelb_t *trace)
{
  return trace->nodec;
}

scamper_tracelb_link_t *scamper_tracelb_link_get(const scamper_tracelb_t *trace, uint16_t i)
{
  if(i >= trace->linkc)
    return NULL;
  return trace->links[i];
}

uint16_t scamper_tracelb_linkc_get(const scamper_tracelb_t *trace)
{
  return trace->linkc;
}

uint32_t scamper_tracelb_probec_get(const scamper_tracelb_t *trace)
{
  return trace->probec;
}

uint32_t scamper_tracelb_error_get(const scamper_tracelb_t *trace)
{
  return trace->error;
}

int scamper_tracelb_type_is_udp(const scamper_tracelb_t *trace)
{
  return SCAMPER_TRACELB_TYPE_IS_UDP(trace);
}

int scamper_tracelb_type_is_tcp(const scamper_tracelb_t *trace)
{
  return SCAMPER_TRACELB_TYPE_IS_TCP(trace);
}

int scamper_tracelb_type_is_icmp(const scamper_tracelb_t *trace)
{
  return SCAMPER_TRACELB_TYPE_IS_ICMP(trace);
}

int scamper_tracelb_type_is_vary_sport(const scamper_tracelb_t *trace)
{
  return SCAMPER_TRACELB_TYPE_VARY_SPORT(trace);
}

scamper_addr_t *scamper_tracelb_node_addr_get(const scamper_tracelb_node_t *node)
{
  return node->addr;
}

const char *scamper_tracelb_node_name_get(const scamper_tracelb_node_t *node)
{
  return node->name;
}

uint32_t scamper_tracelb_node_flags_get(const scamper_tracelb_node_t *node)
{
  return node->flags;
}

uint8_t scamper_tracelb_node_q_ttl_get(const scamper_tracelb_node_t *node)
{
  return node->q_ttl;
}

int scamper_tracelb_node_is_q_ttl(const scamper_tracelb_node_t *node)
{
  if(node->flags & SCAMPER_TRACELB_NODE_FLAG_QTTL)
    return 1;
  return 0;
}

scamper_tracelb_link_t *scamper_tracelb_node_link_get(const scamper_tracelb_node_t *node, uint16_t i)
{
  if(i >= node->linkc)
    return NULL;
  return node->links[i];
}

uint16_t scamper_tracelb_node_linkc_get(const scamper_tracelb_node_t *node)
{
  return node->linkc;
}

scamper_tracelb_node_t *scamper_tracelb_link_from_get(const scamper_tracelb_link_t *link)
{
  return link->from;
}

scamper_tracelb_node_t *scamper_tracelb_link_to_get(const scamper_tracelb_link_t *link)
{
  return link->to;
}

uint8_t scamper_tracelb_link_hopc_get(const scamper_tracelb_link_t *link)
{
  return link->hopc;
}

scamper_tracelb_probeset_t *scamper_tracelb_link_probeset_get(const scamper_tracelb_link_t *link, uint8_t i)
{
  if(i >= link->hopc)
    return NULL;
  return link->sets[i];
}

scamper_tracelb_probe_t *scamper_tracelb_probeset_probe_get(const scamper_tracelb_probeset_t *set, uint16_t i)
{
  if(i >= set->probec)
    return NULL;
  return set->probes[i];
}

uint16_t scamper_tracelb_probeset_probec_get(const scamper_tracelb_probeset_t *set)
{
  return set->probec;
}

const struct timeval *scamper_tracelb_probe_tx_get(const scamper_tracelb_probe_t *probe)
{
  return &probe->tx;
}

uint16_t scamper_tracelb_probe_flowid_get(const scamper_tracelb_probe_t *probe)
{
  return probe->flowid;
}

uint8_t scamper_tracelb_probe_ttl_get(const scamper_tracelb_probe_t *probe)
{
  return probe->ttl;
}

uint8_t scamper_tracelb_probe_attempt_get(const scamper_tracelb_probe_t *probe)
{
  return probe->attempt;
}

scamper_tracelb_reply_t *scamper_tracelb_probe_rx_get(const scamper_tracelb_probe_t *probe, uint16_t i)
{
  if(i >= probe->rxc)
    return NULL;
  return probe->rxs[i];
}

uint16_t scamper_tracelb_probe_rxc_get(const scamper_tracelb_probe_t *probe)
{
  return probe->rxc;
}

scamper_addr_t *scamper_tracelb_reply_from_get(const scamper_tracelb_reply_t *reply)
{
  return reply->reply_from;
}

const struct timeval *scamper_tracelb_reply_rx_get(const scamper_tracelb_reply_t *reply)
{
  return &reply->reply_rx;
}

uint16_t scamper_tracelb_reply_ipid_get(const scamper_tracelb_reply_t *reply)
{
  return reply->reply_ipid;
}

uint8_t scamper_tracelb_reply_ttl_get(const scamper_tracelb_reply_t *reply)
{
  return reply->reply_ttl;
}

uint32_t scamper_tracelb_reply_flags_get(const scamper_tracelb_reply_t *reply)
{
  return reply->reply_flags;
}

uint8_t scamper_tracelb_reply_icmp_type_get(const scamper_tracelb_reply_t *reply)
{
  return reply->reply_icmp_type;
}

uint8_t scamper_tracelb_reply_icmp_code_get(const scamper_tracelb_reply_t *reply)
{
  return reply->reply_icmp_code;
}

uint8_t scamper_tracelb_reply_icmp_q_tos_get(const scamper_tracelb_reply_t *reply)
{
  return reply->reply_icmp_q_tos;
}

uint8_t scamper_tracelb_reply_icmp_q_ttl_get(const scamper_tracelb_reply_t *reply)
{
  return reply->reply_icmp_q_ttl;
}

scamper_icmpext_t *scamper_tracelb_reply_icmp_ext_get(const scamper_tracelb_reply_t *reply)
{
  return reply->reply_icmp_ext;
}

uint8_t scamper_tracelb_reply_tcp_flags_get(const scamper_tracelb_reply_t *reply)
{
  return reply->reply_tcp_flags;
}

int scamper_tracelb_reply_is_icmp_ttl_exp(const scamper_tracelb_reply_t *reply)
{
  return SCAMPER_TRACELB_REPLY_IS_ICMP_TTL_EXP(reply);
}

int scamper_tracelb_reply_is_icmp_unreach(const scamper_tracelb_reply_t *reply)
{
  return SCAMPER_TRACELB_REPLY_IS_ICMP_UNREACH(reply);
}

int scamper_tracelb_reply_is_tcp(const scamper_tracelb_reply_t *reply)
{
  return SCAMPER_TRACELB_REPLY_IS_TCP(reply);
}

int scamper_tracelb_reply_is_icmp(const scamper_tracelb_reply_t *reply)
{
  if(SCAMPER_TRACELB_REPLY_IS_TCP(reply) == 0)
    return 1;
  return 0;
}

int scamper_tracelb_reply_is_icmp_q(const scamper_tracelb_reply_t *reply)
{
  return (SCAMPER_TRACELB_REPLY_IS_ICMP_UNREACH(reply) ||
	  SCAMPER_TRACELB_REPLY_IS_ICMP_TTL_EXP(reply));
}

int scamper_tracelb_reply_is_reply_ttl(const scamper_tracelb_reply_t *reply)
{
  return SCAMPER_TRACELB_REPLY_IS_REPLY_TTL(reply);
}

uint16_t scamper_tracelb_probeset_summary_addrc_get(const scamper_tracelb_probeset_summary_t *sum)
{
  return sum->addrc;
}

scamper_addr_t *scamper_tracelb_probeset_summary_addr_get(const scamper_tracelb_probeset_summary_t *sum, uint16_t i)
{
  if(i >= sum->addrc)
    return NULL;
  return sum->addrs[i];
}

uint16_t scamper_tracelb_probeset_summary_nullc_get(const scamper_tracelb_probeset_summary_t *sum)
{
  return sum->nullc;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_tracelb_node_t *scamper_tracelb_node_use(scamper_tracelb_node_t *node)
{
  node->refcnt++;
  return node;
}

scamper_tracelb_link_t *scamper_tracelb_link_use(scamper_tracelb_link_t *link)
{
  link->refcnt++;
  return link;
}

scamper_tracelb_probe_t *scamper_tracelb_probe_use(scamper_tracelb_probe_t *p)
{
  p->refcnt++;
  return p;
}

scamper_tracelb_reply_t *scamper_tracelb_reply_use(scamper_tracelb_reply_t *r)
{
  r->refcnt++;
  return r;
}

scamper_tracelb_probeset_t *
scamper_tracelb_probeset_use(scamper_tracelb_probeset_t *set)
{
  set->refcnt++;
  return set;
}
#endif
