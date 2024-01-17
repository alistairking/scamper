/*
 * scamper_dealias_lib.c
 *
 * $Id: scamper_dealias_lib.c,v 1.22 2024/01/16 06:55:18 mjl Exp $
 *
 * Copyright (C) 2023 Matthew Luckie
 * Author: Matthew Luckie
 *
 * This code implements alias resolution techniques published by others
 * which require the network to be probed; the author of each technique
 * is detailed with its data structures.
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
#include "scamper_dealias.h"
#include "scamper_dealias_int.h"

scamper_list_t *scamper_dealias_list_get(const scamper_dealias_t *dealias)
{
  return dealias->list;
}

scamper_cycle_t *scamper_dealias_cycle_get(const scamper_dealias_t *dealias)
{
  return dealias->cycle;
}

uint32_t scamper_dealias_userid_get(const scamper_dealias_t *dealias)
{
  return dealias->userid;
}

const struct timeval *
scamper_dealias_start_get(const scamper_dealias_t *dealias)
{
  return &dealias->start;
}

uint8_t scamper_dealias_method_get(const scamper_dealias_t *dealias)
{
  return dealias->method;
}

uint8_t scamper_dealias_result_get(const scamper_dealias_t *dealias)
{
  return dealias->result;
}

int scamper_dealias_result_is_aliases(const scamper_dealias_t *dealias)
{
  return SCAMPER_DEALIAS_RESULT_IS_ALIASES(dealias);
}

scamper_dealias_ally_t *
scamper_dealias_ally_get(const scamper_dealias_t *dealias)
{
  if(dealias->method == SCAMPER_DEALIAS_METHOD_ALLY)
    return dealias->data;
  return NULL;
}

scamper_dealias_mercator_t *
scamper_dealias_mercator_get(const scamper_dealias_t *dealias)
{
  if(dealias->method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    return dealias->data;
  return NULL;
}

scamper_dealias_radargun_t *
scamper_dealias_radargun_get(const scamper_dealias_t *dealias)
{
  if(dealias->method == SCAMPER_DEALIAS_METHOD_RADARGUN)
    return dealias->data;
  return NULL;
}

scamper_dealias_prefixscan_t *
scamper_dealias_prefixscan_get(const scamper_dealias_t *dealias)
{
  if(dealias->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    return dealias->data;
  return NULL;
}

scamper_dealias_bump_t *
scamper_dealias_bump_get(const scamper_dealias_t *dealias)
{
  if(dealias->method == SCAMPER_DEALIAS_METHOD_BUMP)
    return dealias->data;
  return NULL;
}

scamper_dealias_midarest_t *
scamper_dealias_midarest_get(const scamper_dealias_t *dealias)
{
  if(dealias->method == SCAMPER_DEALIAS_METHOD_MIDAREST)
    return dealias->data;
  return NULL;
}

scamper_dealias_midardisc_t *
scamper_dealias_midardisc_get(const scamper_dealias_t *dealias)
{
  if(dealias->method == SCAMPER_DEALIAS_METHOD_MIDARDISC)
    return dealias->data;
  return NULL;
}

scamper_dealias_probe_t *
scamper_dealias_probe_get(const scamper_dealias_t *dealias, uint32_t i)
{
  if(i >= dealias->probec)
    return NULL;
  return dealias->probes[i];
}

uint32_t scamper_dealias_probec_get(const scamper_dealias_t *dealias)
{
  return dealias->probec;
}

int scamper_dealias_method_is_mercator(const scamper_dealias_t *dealias)
{
  return SCAMPER_DEALIAS_METHOD_IS_MERCATOR(dealias);
}

int scamper_dealias_method_is_ally(const scamper_dealias_t *dealias)
{
  return SCAMPER_DEALIAS_METHOD_IS_ALLY(dealias);
}

int scamper_dealias_method_is_radargun(const scamper_dealias_t *dealias)
{
  return SCAMPER_DEALIAS_METHOD_IS_RADARGUN(dealias);
}

int scamper_dealias_method_is_prefixscan(const scamper_dealias_t *dealias)
{
  return SCAMPER_DEALIAS_METHOD_IS_PREFIXSCAN(dealias);
}

int scamper_dealias_method_is_bump(const scamper_dealias_t *dealias)
{
  return SCAMPER_DEALIAS_METHOD_IS_BUMP(dealias);
}

int scamper_dealias_method_is_midarest(const scamper_dealias_t *dealias)
{
  return SCAMPER_DEALIAS_METHOD_IS_MIDAREST(dealias);
}

int scamper_dealias_method_is_midardisc(const scamper_dealias_t *dealias)
{
  return SCAMPER_DEALIAS_METHOD_IS_MIDARDISC(dealias);
}

scamper_dealias_probedef_t *
scamper_dealias_mercator_def_get(const scamper_dealias_mercator_t *mc)
{
  return mc->probedef;
}

uint8_t
scamper_dealias_mercator_attempts_get(const scamper_dealias_mercator_t *mc)
{
  return mc->attempts;
}

const struct timeval *
scamper_dealias_mercator_wait_timeout_get(const scamper_dealias_mercator_t *mc)
{
  return &mc->wait_timeout;
}

scamper_dealias_probedef_t *
scamper_dealias_ally_def0_get(const scamper_dealias_ally_t *ally)
{
  return ally->probedefs[0];
}

scamper_dealias_probedef_t *
scamper_dealias_ally_def1_get(const scamper_dealias_ally_t *ally)
{
  return ally->probedefs[1];
}

const struct timeval *
scamper_dealias_ally_wait_probe_get(const scamper_dealias_ally_t *ally)
{
  return &ally->wait_probe;
}

const struct timeval *
scamper_dealias_ally_wait_timeout_get(const scamper_dealias_ally_t *ally)
{
  return &ally->wait_timeout;
}

uint8_t scamper_dealias_ally_attempts_get(const scamper_dealias_ally_t *ally)
{
  return ally->attempts;
}

uint8_t scamper_dealias_ally_flags_get(const scamper_dealias_ally_t *ally)
{
  return ally->flags;
}

uint16_t scamper_dealias_ally_fudge_get(const scamper_dealias_ally_t *ally)
{
  return ally->fudge;
}

int scamper_dealias_ally_is_nobs(const scamper_dealias_ally_t *ally)
{
  return SCAMPER_DEALIAS_ALLY_IS_NOBS(ally);
}

scamper_dealias_probedef_t *
scamper_dealias_radargun_def_get(const scamper_dealias_radargun_t *rg, uint32_t i)
{
  if(i >= rg->probedefc)
    return NULL;
  return rg->probedefs[i];
}

uint32_t
scamper_dealias_radargun_defc_get(const scamper_dealias_radargun_t *rg)
{
  return rg->probedefc;
}

uint16_t
scamper_dealias_radargun_rounds_get(const scamper_dealias_radargun_t *rg)
{
  return rg->rounds;
}

const struct timeval *
scamper_dealias_radargun_wait_probe_get(const scamper_dealias_radargun_t *rg)
{
  return &rg->wait_probe;
}

const struct timeval *
scamper_dealias_radargun_wait_round_get(const scamper_dealias_radargun_t *rg)
{
  return &rg->wait_round;
}

const struct timeval *
scamper_dealias_radargun_wait_timeout_get(const scamper_dealias_radargun_t *rg)
{
  return &rg->wait_timeout;
}

uint8_t scamper_dealias_radargun_flags_get(const scamper_dealias_radargun_t *rg)
{
  return rg->flags;
}

scamper_addr_t *
scamper_dealias_prefixscan_a_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->a;
}

scamper_addr_t *
scamper_dealias_prefixscan_b_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->b;
}

scamper_addr_t *
scamper_dealias_prefixscan_ab_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->ab;
}

scamper_addr_t *
scamper_dealias_prefixscan_xs_get(const scamper_dealias_prefixscan_t *pf,
				  uint16_t i)
{
  if(i >= pf->xc)
    return NULL;
  return pf->xs[i];
}

uint16_t
scamper_dealias_prefixscan_xc_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->xc;
}

uint8_t
scamper_dealias_prefixscan_prefix_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->prefix;
}

uint8_t
scamper_dealias_prefixscan_attempts_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->attempts;
}

uint8_t
scamper_dealias_prefixscan_replyc_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->replyc;
}

uint16_t
scamper_dealias_prefixscan_fudge_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->fudge;
}

const struct timeval *
scamper_dealias_prefixscan_wait_probe_get(const scamper_dealias_prefixscan_t *pf)
{
  return &pf->wait_probe;
}

const struct timeval *
scamper_dealias_prefixscan_wait_timeout_get(const scamper_dealias_prefixscan_t *pf)
{
  return &pf->wait_timeout;
}

uint8_t
scamper_dealias_prefixscan_flags_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->flags;
}

scamper_dealias_probedef_t *
scamper_dealias_prefixscan_def_get(const scamper_dealias_prefixscan_t *pf,
				   uint16_t i)
{
  if(i >= pf->probedefc)
    return NULL;
  return pf->probedefs[i];
}

uint16_t
scamper_dealias_prefixscan_defc_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->probedefc;
}

int scamper_dealias_prefixscan_is_csa(const scamper_dealias_prefixscan_t *pfs)
{
  if(pfs->flags & SCAMPER_DEALIAS_PREFIXSCAN_FLAG_CSA)
    return 1;
  return 0;
}

int scamper_dealias_prefixscan_is_nobs(const scamper_dealias_prefixscan_t *ps)
{
  return SCAMPER_DEALIAS_PREFIXSCAN_IS_NOBS(ps);
}

scamper_dealias_probedef_t *
scamper_dealias_bump_def0_get(const scamper_dealias_bump_t *bump)
{
  return bump->probedefs[0];
}

scamper_dealias_probedef_t *
scamper_dealias_bump_def1_get(const scamper_dealias_bump_t *bump)
{
  return bump->probedefs[1];
}

const struct timeval *
scamper_dealias_bump_wait_probe_get(const scamper_dealias_bump_t *bump)
{
  return &bump->wait_probe;
}

uint16_t scamper_dealias_bump_limit_get(const scamper_dealias_bump_t *bump)
{
  return bump->bump_limit;
}

uint8_t scamper_dealias_bump_attempts_get(const scamper_dealias_bump_t *bump)
{
  return bump->attempts;
}

scamper_dealias_probedef_t *
scamper_dealias_midarest_def_get(const scamper_dealias_midarest_t *me,
				 uint16_t i)
{
  if(i >= me->probedefc || me->probedefs == NULL)
    return NULL;
  return me->probedefs[i];
}

uint16_t
scamper_dealias_midarest_defc_get(const scamper_dealias_midarest_t *me)
{
  return me->probedefc;
}

uint8_t
scamper_dealias_midarest_rounds_get(const scamper_dealias_midarest_t *me)
{
  return me->rounds;
}

const struct timeval *
scamper_dealias_midarest_wait_round_get(const scamper_dealias_midarest_t *me)
{
  return &me->wait_round;
}

const struct timeval *
scamper_dealias_midarest_wait_probe_get(const scamper_dealias_midarest_t *me)
{
  return &me->wait_probe;
}

const struct timeval *
scamper_dealias_midarest_wait_timeout_get(const scamper_dealias_midarest_t *me)
{
  return &me->wait_timeout;
}

const struct timeval *
scamper_dealias_midardisc_startat_get(const scamper_dealias_midardisc_t *md)
{
  return md->startat;
}

const struct timeval *
scamper_dealias_midardisc_wait_timeout_get(const scamper_dealias_midardisc_t *md)
{
  return &md->wait_timeout;
}

scamper_dealias_probedef_t *
scamper_dealias_midardisc_def_get(const scamper_dealias_midardisc_t *md,
				  uint32_t i)
{
  if(i >= md->probedefc || md->probedefs == NULL)
    return NULL;
  return md->probedefs[i];
}

uint32_t
scamper_dealias_midardisc_defc_get(const scamper_dealias_midardisc_t *md)
{
  return md->probedefc;
}

scamper_dealias_midardisc_round_t *
scamper_dealias_midardisc_sched_get(const scamper_dealias_midardisc_t *md,
				    uint32_t i)
{
  if(i >= md->schedc || md->sched == NULL)
    return NULL;
  return md->sched[i];
}

uint32_t
scamper_dealias_midardisc_schedc_get(const scamper_dealias_midardisc_t *md)
{
  return md->schedc;
}

uint32_t
scamper_dealias_midardisc_round_begin_get(const scamper_dealias_midardisc_round_t *r)
{
  return r->begin;
}

uint32_t
scamper_dealias_midardisc_round_end_get(const scamper_dealias_midardisc_round_t *r)
{
  return r->end;
}

const struct timeval *
scamper_dealias_midardisc_round_start_get(const scamper_dealias_midardisc_round_t *r)
{
  return &r->start;
}

void scamper_dealias_midardisc_round_begin_set(scamper_dealias_midardisc_round_t *r, uint32_t begin)
{
  r->begin = begin;
  return;
}

void scamper_dealias_midardisc_round_end_set(scamper_dealias_midardisc_round_t *r, uint32_t end)
{
  r->end = end;
  return;
}

void scamper_dealias_midardisc_round_start_set(scamper_dealias_midardisc_round_t *r, const struct timeval *start)
{
  r->start.tv_sec = start->tv_sec;
  r->start.tv_usec = start->tv_usec;
  return;
}

scamper_dealias_probedef_t *
scamper_dealias_probe_def_get(const scamper_dealias_probe_t *probe)
{
  return probe->def;
}

uint32_t scamper_dealias_probe_seq_get(const scamper_dealias_probe_t *probe)
{
  return probe->seq;
}

const struct timeval *
scamper_dealias_probe_tx_get(const scamper_dealias_probe_t *probe)
{
  return &probe->tx;
}

scamper_dealias_reply_t *
scamper_dealias_probe_reply_get(const scamper_dealias_probe_t *probe,uint16_t i)
{
  if(i >= probe->replyc)
    return NULL;
  return probe->replies[i];
}

uint16_t scamper_dealias_probe_replyc_get(const scamper_dealias_probe_t *probe)
{
  return probe->replyc;
}

uint16_t scamper_dealias_probe_ipid_get(const scamper_dealias_probe_t *probe)
{
  return probe->ipid;
}

scamper_addr_t *
scamper_dealias_probedef_src_get(const scamper_dealias_probedef_t *pd)
{
  return pd->src;
}

scamper_addr_t *
scamper_dealias_probedef_dst_get(const scamper_dealias_probedef_t *pd)
{
  return pd->dst;
}

uint32_t scamper_dealias_probedef_id_get(const scamper_dealias_probedef_t *pd)
{
  return pd->id;
}

uint8_t
scamper_dealias_probedef_method_get(const scamper_dealias_probedef_t *pd)
{
  return pd->method;
}

int scamper_dealias_probedef_is_udp(const scamper_dealias_probedef_t *pd)
{
  return SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(pd);
}

int scamper_dealias_probedef_is_tcp(const scamper_dealias_probedef_t *pd)
{
  return SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(pd);
}

int scamper_dealias_probedef_is_icmp(const scamper_dealias_probedef_t *pd)
{
  return SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(pd);
}

uint8_t scamper_dealias_probedef_ttl_get(const scamper_dealias_probedef_t *pd)
{
  return pd->ttl;
}

uint8_t scamper_dealias_probedef_tos_get(const scamper_dealias_probedef_t *pd)
{
  return pd->tos;
}

uint16_t scamper_dealias_probedef_size_get(const scamper_dealias_probedef_t *pd)
{
  return pd->size;
}

uint16_t scamper_dealias_probedef_mtu_get(const scamper_dealias_probedef_t *pd)
{
  return pd->mtu;
}

scamper_dealias_probedef_udp_t *
scamper_dealias_probedef_udp_get(const scamper_dealias_probedef_t *pd)
{
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(pd) == 0)
    return NULL;
  return (scamper_dealias_probedef_udp_t *)&pd->un.udp;
}

scamper_dealias_probedef_tcp_t *
scamper_dealias_probedef_tcp_get(const scamper_dealias_probedef_t *pd)
{
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(pd) == 0)
    return NULL;
  return (scamper_dealias_probedef_tcp_t *)&pd->un.tcp;
}

scamper_dealias_probedef_icmp_t *
scamper_dealias_probedef_icmp_get(const scamper_dealias_probedef_t *pd)
{
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(pd) == 0)
    return NULL;
  return (scamper_dealias_probedef_icmp_t *)&pd->un.icmp;
}

uint16_t
scamper_dealias_probedef_udp_sport_get(const scamper_dealias_probedef_udp_t *udp)
{
  return udp->sport;
}

uint16_t
scamper_dealias_probedef_udp_dport_get(const scamper_dealias_probedef_udp_t *udp)
{
  return udp->dport;
}

uint16_t
scamper_dealias_probedef_icmp_csum_get(const scamper_dealias_probedef_icmp_t *icmp)
{
  return icmp->csum;
}

uint16_t
scamper_dealias_probedef_icmp_id_get(const scamper_dealias_probedef_icmp_t *icmp)
{
  return icmp->id;
}

uint16_t scamper_dealias_probedef_tcp_sport_get(const scamper_dealias_probedef_tcp_t *tcp)
{
  return tcp->sport;
}

uint16_t scamper_dealias_probedef_tcp_dport_get(const scamper_dealias_probedef_tcp_t *tcp)
{
  return tcp->dport;
}

uint8_t scamper_dealias_probedef_tcp_flags_get(const scamper_dealias_probedef_tcp_t *tcp)
{
  return tcp->flags;
}

int scamper_dealias_probedef_method_set(scamper_dealias_probedef_t *pd, const char *meth)
{
  uint8_t m;
  if(scamper_dealias_probedef_method_fromstr(meth, &m) != 0)
    return -1;
  pd->method = m;
  return 0;
}

int scamper_dealias_probedef_src_set(scamper_dealias_probedef_t *pd,
				     scamper_addr_t *src)
{
  if(SCAMPER_ADDR_TYPE_IS_IPV4(src) == 0 && SCAMPER_ADDR_TYPE_IS_IPV6(src) == 0)
    return -1;
  if(pd->src != NULL)
    scamper_addr_free(pd->src);
  pd->src = scamper_addr_use(src);
  return 0;
}

int scamper_dealias_probedef_dst_set(scamper_dealias_probedef_t *pd,
				     scamper_addr_t *dst)
{
  if(SCAMPER_ADDR_TYPE_IS_IPV4(dst) == 0 && SCAMPER_ADDR_TYPE_IS_IPV6(dst) == 0)
    return -1;
  if(pd->dst != NULL)
    scamper_addr_free(pd->dst);
  pd->dst = scamper_addr_use(dst);
  return 0;
}

void scamper_dealias_probedef_ttl_set(scamper_dealias_probedef_t *pd,
				      uint8_t ttl)
{
  pd->ttl = ttl;
  return;
}

void scamper_dealias_probedef_tos_set(scamper_dealias_probedef_t *pd, uint8_t tos)
{
  pd->tos = tos;
  return;
}

void scamper_dealias_probedef_size_set(scamper_dealias_probedef_t *pd, uint16_t size)
{
  pd->size = size;
  return;
}

void scamper_dealias_probedef_mtu_set(scamper_dealias_probedef_t *pd, uint16_t mtu)
{
  pd->mtu = mtu;
  return;
}

void scamper_dealias_probedef_icmp_csum_set(scamper_dealias_probedef_icmp_t *icmp, uint16_t cs)
{
  icmp->csum = cs;
  return;
}

void scamper_dealias_probedef_icmp_id_set(scamper_dealias_probedef_icmp_t *icmp, uint16_t id)
{
  icmp->id = id;
  return;
}

void scamper_dealias_probedef_udp_sport_set(scamper_dealias_probedef_udp_t *udp, uint16_t sp)
{
  udp->sport = sp;
  return;
}

void scamper_dealias_probedef_udp_dport_set(scamper_dealias_probedef_udp_t *udp, uint16_t dp)
{
  udp->dport = dp;
  return;
}

void scamper_dealias_probedef_tcp_sport_set(scamper_dealias_probedef_tcp_t *tcp, uint16_t sp)
{
  tcp->sport = sp;
  return;
}

void scamper_dealias_probedef_tcp_dport_set(scamper_dealias_probedef_tcp_t *tcp, uint16_t dp)
{
  tcp->dport = dp;
  return;
}

scamper_addr_t *scamper_dealias_reply_src_get(const scamper_dealias_reply_t *reply)
{
  return reply->src;
}

const struct timeval *scamper_dealias_reply_rx_get(const scamper_dealias_reply_t *reply)
{
  return &reply->rx;
}

uint8_t scamper_dealias_reply_flags_get(const scamper_dealias_reply_t *reply)
{
  return reply->flags;
}

uint8_t scamper_dealias_reply_proto_get(const scamper_dealias_reply_t *reply)
{
  return reply->proto;
}

uint8_t scamper_dealias_reply_ttl_get(const scamper_dealias_reply_t *reply)
{
  return reply->ttl;
}

uint16_t scamper_dealias_reply_size_get(const scamper_dealias_reply_t *reply)
{
  return reply->size;
}

uint8_t scamper_dealias_reply_icmp_type_get(const scamper_dealias_reply_t *reply)
{
  return reply->icmp_type;
}

uint8_t scamper_dealias_reply_icmp_code_get(const scamper_dealias_reply_t *reply)
{
  return reply->icmp_code;
}

uint8_t scamper_dealias_reply_icmp_q_ttl_get(const scamper_dealias_reply_t *reply)
{
  return reply->icmp_q_ttl;
}

uint8_t scamper_dealias_reply_tcp_flags_get(const scamper_dealias_reply_t *reply)
{
  return reply->tcp_flags;
}

uint16_t scamper_dealias_reply_ipid_get(const scamper_dealias_reply_t *reply)
{
  return reply->ipid;
}

uint32_t scamper_dealias_reply_ipid32_get(const scamper_dealias_reply_t *reply)
{
  return reply->ipid32;
}

int scamper_dealias_reply_is_ipid32(const scamper_dealias_reply_t *reply)
{
  if(reply->flags & SCAMPER_DEALIAS_REPLY_FLAG_IPID32)
    return 1;
  return 0;
}

int scamper_dealias_reply_is_icmp_q(const scamper_dealias_reply_t *reply)
{
  if(SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH(reply) ||
     SCAMPER_DEALIAS_REPLY_IS_ICMP_TTL_EXP(reply))
    return 1;
  return 0;
}

int scamper_dealias_reply_is_icmp_unreach_port(const scamper_dealias_reply_t *reply)
{
  return SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH_PORT(reply);
}

int scamper_dealias_reply_is_icmp(const scamper_dealias_reply_t *reply)
{
  return SCAMPER_DEALIAS_REPLY_IS_ICMP(reply);
}

int scamper_dealias_reply_is_icmp_unreach(const scamper_dealias_reply_t *reply)
{
  return SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH(reply);
}

int scamper_dealias_reply_is_icmp_ttl_exp(const scamper_dealias_reply_t *reply)
{
  return SCAMPER_DEALIAS_REPLY_IS_ICMP_TTL_EXP(reply);
}

int scamper_dealias_reply_is_tcp(const scamper_dealias_reply_t *reply)
{
  return SCAMPER_DEALIAS_REPLY_IS_TCP(reply);
}

int scamper_dealias_reply_from_target(const scamper_dealias_probe_t *probe,
				      const scamper_dealias_reply_t *reply)
{
  return SCAMPER_DEALIAS_REPLY_FROM_TARGET(probe, reply);
}

scamper_icmpext_t *scamper_dealias_reply_icmp_ext_get(const scamper_dealias_reply_t *reply)
{
  return reply->icmp_ext;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_dealias_probedef_t *
scamper_dealias_probedef_use(scamper_dealias_probedef_t *probedef)
{
  probedef->refcnt++;
  return probedef;
}

scamper_dealias_probe_t *
scamper_dealias_probe_use(scamper_dealias_probe_t *probe)
{
  probe->refcnt++;
  return probe;
}

scamper_dealias_reply_t *
scamper_dealias_reply_use(scamper_dealias_reply_t *reply)
{
  reply->refcnt++;
  return reply;
}

scamper_dealias_ally_t *
scamper_dealias_ally_use(scamper_dealias_ally_t *ally)
{
  ally->refcnt++;
  return ally;
}

scamper_dealias_mercator_t *
scamper_dealias_mercator_use(scamper_dealias_mercator_t *mc)
{
  mc->refcnt++;
  return mc;
}

scamper_dealias_radargun_t *
scamper_dealias_radargun_use(scamper_dealias_radargun_t *rg)
{
  rg->refcnt++;
  return rg;
}

scamper_dealias_prefixscan_t *
scamper_dealias_prefixscan_use(scamper_dealias_prefixscan_t *pf)
{
  pf->refcnt++;
  return pf;
}

scamper_dealias_bump_t *
scamper_dealias_bump_use(scamper_dealias_bump_t *bump)
{
  bump->refcnt++;
  return bump;
}

scamper_dealias_midarest_t *
scamper_dealias_midarest_use(scamper_dealias_midarest_t *me)
{
  me->refcnt++;
  return me;
}
#endif
