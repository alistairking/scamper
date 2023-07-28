/*
 * scamper_dealias_lib.c
 *
 * $Id: scamper_dealias_lib.c,v 1.1 2023/05/31 23:22:18 mjl Exp $
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

const struct timeval *scamper_dealias_start_get(const scamper_dealias_t *dealias)
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

const scamper_dealias_ally_t *scamper_dealias_ally_get(const scamper_dealias_t *dealias)
{
  if(dealias->method == SCAMPER_DEALIAS_METHOD_ALLY)
    return dealias->data;
  return NULL;
}

const scamper_dealias_mercator_t *scamper_dealias_mercator_get(const scamper_dealias_t *dealias)
{
  if(dealias->method == SCAMPER_DEALIAS_METHOD_MERCATOR)
    return dealias->data;
  return NULL;
}

const scamper_dealias_radargun_t *scamper_dealias_radargun_get(const scamper_dealias_t *dealias)
{
  if(dealias->method == SCAMPER_DEALIAS_METHOD_RADARGUN)
    return dealias->data;
  return NULL;
}

const scamper_dealias_prefixscan_t *scamper_dealias_prefixscan_get(const scamper_dealias_t *dealias)
{
  if(dealias->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
    return dealias->data;
  return NULL;
}

const scamper_dealias_bump_t *scamper_dealias_bump_get(const scamper_dealias_t *dealias)
{
  if(dealias->method == SCAMPER_DEALIAS_METHOD_BUMP)
    return dealias->data;
  return NULL;
}

const scamper_dealias_probe_t *scamper_dealias_probe_get(const scamper_dealias_t *dealias, uint32_t i)
{
  if(i >= dealias->probec)
    return NULL;
  return dealias->probes[i];
}

uint32_t scamper_dealias_probec_get(const scamper_dealias_t *dealias)
{
  return dealias->probec;
}

int scamper_dealias_method_is_prefixscan(const scamper_dealias_t *dealias)
{
  return SCAMPER_DEALIAS_METHOD_IS_PREFIXSCAN(dealias);
}

int scamper_dealias_method_is_ally(const scamper_dealias_t *dealias)
{
  return SCAMPER_DEALIAS_METHOD_IS_ALLY(dealias);
}

const scamper_dealias_probedef_t *scamper_dealias_mercator_def_get(const scamper_dealias_mercator_t *mc)
{
  return &mc->probedef;
}

uint8_t scamper_dealias_mercator_attempts_get(const scamper_dealias_mercator_t *mc)
{
  return mc->attempts;
}

uint8_t scamper_dealias_mercator_wait_timeout_get(const scamper_dealias_mercator_t *mc)
{
  return mc->wait_timeout;
}

const scamper_dealias_probedef_t *scamper_dealias_ally_def0_get(const scamper_dealias_ally_t *ally)
{
  return &ally->probedefs[0];
}

const scamper_dealias_probedef_t *scamper_dealias_ally_def1_get(const scamper_dealias_ally_t *ally)
{
  return &ally->probedefs[1];
}

uint16_t scamper_dealias_ally_wait_probe_get(const scamper_dealias_ally_t *ally)
{
  return ally->wait_probe;
}

uint8_t scamper_dealias_ally_wait_timeout_get(const scamper_dealias_ally_t *ally)
{
  return ally->wait_timeout;
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

const scamper_dealias_probedef_t *scamper_dealias_radargun_def_get(const scamper_dealias_radargun_t *rg, uint32_t i)
{
  if(i >= rg->probedefc)
    return NULL;
  return &rg->probedefs[i];
}

uint32_t scamper_dealias_radargun_defc_get(const scamper_dealias_radargun_t *rg)
{
  return rg->probedefc;
}

uint16_t scamper_dealias_radargun_attempts_get(const scamper_dealias_radargun_t *rg)
{
  return rg->attempts;
}

uint16_t scamper_dealias_radargun_wait_probe_get(const scamper_dealias_radargun_t *rg)
{
  return rg->wait_probe;
}

uint32_t scamper_dealias_radargun_wait_round_get(const scamper_dealias_radargun_t *rg)
{
  return rg->wait_round;
}

uint8_t scamper_dealias_radargun_wait_timeout_get(const scamper_dealias_radargun_t *rg)
{
  return rg->wait_timeout;
}

uint8_t scamper_dealias_radargun_flags_get(const scamper_dealias_radargun_t *rg)
{
  return rg->flags;
}

scamper_addr_t *scamper_dealias_prefixscan_a_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->a;
}

scamper_addr_t *scamper_dealias_prefixscan_b_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->b;
}

scamper_addr_t *scamper_dealias_prefixscan_ab_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->ab;
}

scamper_addr_t *scamper_dealias_prefixscan_xs_get(const scamper_dealias_prefixscan_t *pf, uint16_t i)
{
  if(i >= pf->xc)
    return NULL;
  return pf->xs[i];
}

uint16_t scamper_dealias_prefixscan_xc_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->xc;
}

uint8_t scamper_dealias_prefixscan_prefix_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->prefix;
}

uint8_t scamper_dealias_prefixscan_attempts_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->attempts;
}

uint8_t scamper_dealias_prefixscan_replyc_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->replyc;
}

uint16_t scamper_dealias_prefixscan_fudge_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->fudge;
}

uint16_t scamper_dealias_prefixscan_wait_probe_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->wait_probe;
}

uint8_t scamper_dealias_prefixscan_wait_timeout_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->wait_timeout;
}

uint8_t scamper_dealias_prefixscan_flags_get(const scamper_dealias_prefixscan_t *pf)
{
  return pf->flags;
}

const scamper_dealias_probedef_t *scamper_dealias_prefixscan_def_get(const scamper_dealias_prefixscan_t *pf, uint16_t i)
{
  if(i >= pf->probedefc)
    return NULL;
  return &pf->probedefs[i];
}

uint16_t scamper_dealias_prefixscan_defc_get(const scamper_dealias_prefixscan_t *pf)
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

const scamper_dealias_probedef_t *scamper_dealias_bump_def0_get(const scamper_dealias_bump_t *bump)
{
  return &bump->probedefs[0];
}

const scamper_dealias_probedef_t *scamper_dealias_bump_def1_get(const scamper_dealias_bump_t *bump)
{
  return &bump->probedefs[1];
}

uint16_t scamper_dealias_bump_wait_probe_get(const scamper_dealias_bump_t *bump)
{
  return bump->wait_probe;
}

uint16_t scamper_dealias_bump_limit_get(const scamper_dealias_bump_t *bump)
{
  return bump->bump_limit;
}

uint8_t scamper_dealias_bump_attempts_get(const scamper_dealias_bump_t *bump)
{
  return bump->attempts;
}

const scamper_dealias_probedef_t *scamper_dealias_probe_def_get(const scamper_dealias_probe_t *probe)
{
  return probe->def;
}

uint32_t scamper_dealias_probe_seq_get(const scamper_dealias_probe_t *probe)
{
  return probe->seq;
}

const struct timeval *scamper_dealias_probe_tx_get(const scamper_dealias_probe_t *probe)
{
  return &probe->tx;
}

const scamper_dealias_reply_t *scamper_dealias_probe_reply_get(const scamper_dealias_probe_t *probe, uint16_t i)
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

scamper_addr_t *scamper_dealias_probedef_src_get(const scamper_dealias_probedef_t *pd)
{
  return pd->src;
}

scamper_addr_t *scamper_dealias_probedef_dst_get(const scamper_dealias_probedef_t *pd)
{
  return pd->dst;
}

uint32_t scamper_dealias_probedef_id_get(const scamper_dealias_probedef_t *pd)
{
  return pd->id;
}

uint8_t scamper_dealias_probedef_method_get(const scamper_dealias_probedef_t *pd)
{
  return pd->method;
}

int scamper_dealias_probedef_proto_is_udp(const scamper_dealias_probedef_t *pd)
{
  return SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(pd);
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

const scamper_dealias_probedef_udp_t  *scamper_dealias_probedef_udp_get(const scamper_dealias_probedef_t *pd)
{
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(pd) == 0)
    return NULL;
  return &pd->un.udp;
}

const scamper_dealias_probedef_tcp_t  *scamper_dealias_probedef_tcp_get(const scamper_dealias_probedef_t *pd)
{
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(pd) == 0)
    return NULL;
  return &pd->un.tcp;
}

const scamper_dealias_probedef_icmp_t *scamper_dealias_probedef_icmp_get(const scamper_dealias_probedef_t *pd)
{
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(pd) == 0)
    return NULL;
  return &pd->un.icmp;
}

uint16_t scamper_dealias_probedef_udp_sport_get(const scamper_dealias_probedef_udp_t *udp)
{
  return udp->sport;
}

uint16_t scamper_dealias_probedef_udp_dport_get(const scamper_dealias_probedef_udp_t *udp)
{
  return udp->dport;
}

uint16_t scamper_dealias_probedef_icmp_csum_get(const scamper_dealias_probedef_icmp_t *icmp)
{
  return icmp->csum;
}

uint16_t scamper_dealias_probedef_icmp_id_get(const scamper_dealias_probedef_icmp_t *icmp)
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

uint8_t scamper_dealias_reply_icmp_type_get(const scamper_dealias_reply_t *reply)
{
  return reply->icmp_type;
}

uint8_t scamper_dealias_reply_icmp_code_get(const scamper_dealias_reply_t *reply)
{
  return reply->icmp_code;
}

uint8_t scamper_dealias_reply_icmp_q_ip_ttl_get(const scamper_dealias_reply_t *reply)
{
  return reply->icmp_q_ip_ttl;
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

const scamper_icmpext_t *scamper_dealias_reply_icmp_ext_get(const scamper_dealias_reply_t *reply)
{
  return reply->icmp_ext;
}
