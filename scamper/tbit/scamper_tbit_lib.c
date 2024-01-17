/*
 * scamper_tbit_lib.c
 *
 * Copyright (C) 2023 Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_tbit_lib.c,v 1.4 2023/07/29 21:22:22 mjl Exp $
 *
 * This file implements algorithms described in the tbit-1.0 source code,
 * as well as the papers:
 *
 *  "On Inferring TCP Behaviour"
 *      by Jitendra Padhye and Sally Floyd
 *  "Measuring the Evolution of Transport Protocols in the Internet"
 *      by Alberto Medina, Mark Allman, and Sally Floyd.
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
#include "scamper_tbit.h"
#include "scamper_tbit_int.h"

const struct timeval *scamper_tbit_pkt_tv_get(const scamper_tbit_pkt_t *pkt)
{
  return &pkt->tv;
}

uint8_t scamper_tbit_pkt_dir_get(const scamper_tbit_pkt_t *pkt)
{
  return pkt->dir;
}

uint16_t scamper_tbit_pkt_len_get(const scamper_tbit_pkt_t *pkt)
{
  return pkt->len;
}

const uint8_t *scamper_tbit_pkt_data_get(const scamper_tbit_pkt_t *pkt)
{
  return pkt->data;
}

uint8_t scamper_tbit_app_http_type_get(const scamper_tbit_app_http_t *http)
{
  return http->type;
}

const char *scamper_tbit_app_http_host_get(const scamper_tbit_app_http_t *http)
{
  return http->host;
}

const char *scamper_tbit_app_http_file_get(const scamper_tbit_app_http_t *http)
{
  return http->file;
}

uint32_t scamper_tbit_app_bgp_asn_get(const scamper_tbit_app_bgp_t *bgp)
{
  return bgp->asn;
}

uint16_t scamper_tbit_pmtud_mtu_get(const scamper_tbit_pmtud_t *pmtu)
{
  return pmtu->mtu;
}

uint8_t scamper_tbit_pmtud_ptb_retx_get(const scamper_tbit_pmtud_t *pmtu)
{
  return pmtu->ptb_retx;
}

uint8_t scamper_tbit_pmtud_options_get(const scamper_tbit_pmtud_t *pmtu)
{
  return pmtu->options;
}

scamper_addr_t *scamper_tbit_pmtud_ptbsrc_get(const scamper_tbit_pmtud_t *pmtu)
{
  return pmtu->ptbsrc;
}

uint32_t scamper_tbit_null_options_get(const scamper_tbit_null_t *n)
{
  return n->options;
}

uint32_t scamper_tbit_null_results_get(const scamper_tbit_null_t *n)
{
  return n->results;
}

uint32_t scamper_tbit_icw_start_seq_get(const scamper_tbit_icw_t *icw)
{
  return icw->start_seq;
}

int32_t scamper_tbit_blind_off_get(const scamper_tbit_blind_t *blind)
{
  return blind->off;
}

uint8_t scamper_tbit_blind_retx_get(const scamper_tbit_blind_t *blind)
{
  return blind->retx;
}

scamper_list_t *scamper_tbit_list_get(const scamper_tbit_t *tbit)
{
  return tbit->list;
}

scamper_cycle_t *scamper_tbit_cycle_get(const scamper_tbit_t *tbit)
{
  return tbit->cycle;
}

uint32_t scamper_tbit_userid_get(const scamper_tbit_t *tbit)
{
  return tbit->userid;
}

scamper_addr_t *scamper_tbit_src_get(const scamper_tbit_t *tbit)
{
  return tbit->src;
}

scamper_addr_t *scamper_tbit_dst_get(const scamper_tbit_t *tbit)
{
  return tbit->dst;
}

uint16_t scamper_tbit_sport_get(const scamper_tbit_t *tbit)
{
  return tbit->sport;
}

uint16_t scamper_tbit_dport_get(const scamper_tbit_t *tbit)
{
  return tbit->dport;
}

const struct timeval *scamper_tbit_start_get(const scamper_tbit_t *tbit)
{
  return &tbit->start;
}

uint16_t scamper_tbit_result_get(const scamper_tbit_t *tbit)
{
  return tbit->result;
}

uint8_t scamper_tbit_type_get(const scamper_tbit_t *tbit)
{
  return tbit->type;
}

int scamper_tbit_type_is_blind(const scamper_tbit_t *tbit)
{
  return SCAMPER_TBIT_TYPE_IS_BLIND(tbit);
}

scamper_tbit_pmtud_t *scamper_tbit_pmtud_get(const scamper_tbit_t *tbit)
{
  if(tbit->type == SCAMPER_TBIT_TYPE_PMTUD)
    return tbit->data;
  return NULL;
}

scamper_tbit_icw_t *scamper_tbit_icw_get(const scamper_tbit_t *tbit)
{
  if(tbit->type == SCAMPER_TBIT_TYPE_ICW)
    return tbit->data;
  return NULL;
}

scamper_tbit_null_t *scamper_tbit_null_get(const scamper_tbit_t *tbit)
{
  if(tbit->type == SCAMPER_TBIT_TYPE_NULL)
    return tbit->data;
  return NULL;
}

scamper_tbit_blind_t *scamper_tbit_blind_get(const scamper_tbit_t *tbit)
{
  if(SCAMPER_TBIT_TYPE_IS_BLIND(tbit))
    return tbit->data;
  return NULL;
}

uint8_t scamper_tbit_app_proto_get(const scamper_tbit_t *tbit)
{
  return tbit->app_proto;
}

scamper_tbit_app_http_t *scamper_tbit_app_http_get(const scamper_tbit_t *tbit)
{
  if(tbit->app_proto == SCAMPER_TBIT_APP_HTTP)
    return tbit->app_data;
  return NULL;
}

scamper_tbit_app_bgp_t *scamper_tbit_app_bgp_get(const scamper_tbit_t *tbit)
{
  if(tbit->app_proto == SCAMPER_TBIT_APP_BGP)
    return tbit->app_data;
  return NULL;
}

uint32_t scamper_tbit_options_get(const scamper_tbit_t *tbit)
{
  return tbit->options;
}

uint16_t scamper_tbit_client_mss_get(const scamper_tbit_t *tbit)
{
  return tbit->client_mss;
}

uint16_t scamper_tbit_server_mss_get(const scamper_tbit_t *tbit)
{
  return tbit->server_mss;
}

const uint8_t *scamper_tbit_client_fo_cookie_get(const scamper_tbit_t *tbit)
{
  return tbit->client_fo_cookie;
}

uint8_t scamper_tbit_client_fo_cookielen_get(const scamper_tbit_t *tbit)
{
  return tbit->client_fo_cookielen;
}

uint8_t scamper_tbit_client_wscale_get(const scamper_tbit_t *tbit)
{
  return tbit->client_wscale;
}

uint8_t scamper_tbit_client_ipttl_get(const scamper_tbit_t *tbit)
{
  return tbit->client_ipttl;
}

uint8_t scamper_tbit_client_syn_retx_get(const scamper_tbit_t *tbit)
{
  return tbit->client_syn_retx;
}

uint8_t scamper_tbit_client_dat_retx_get(const scamper_tbit_t *tbit)
{
  return tbit->client_dat_retx;
}

scamper_tbit_pkt_t *scamper_tbit_pkt_get(const scamper_tbit_t *tbit,uint32_t i)
{
  if(tbit->pktc <= i)
    return NULL;
  return tbit->pkts[i];
}

const struct timeval *scamper_tbit_stats_synack_rtt_get(const scamper_tbit_stats_t *stats)
{
  return &stats->synack_rtt;
}

uint32_t scamper_tbit_stats_rx_xfersize_get(const scamper_tbit_stats_t *stats)
{
  return stats->rx_xfersize;
}

uint32_t scamper_tbit_stats_rx_totalsize_get(const scamper_tbit_stats_t *stats)
{
  return stats->rx_totalsize;
}

const struct timeval *scamper_tbit_stats_xfertime_get(const scamper_tbit_stats_t *stats)
{
  return &stats->xfertime;
}

uint32_t scamper_tbit_pktc_get(const scamper_tbit_t *tbit)
{
  return tbit->pktc;
}

uint32_t scamper_tbit_tcpqe_seq_get(const scamper_tbit_tcpqe_t *tqe)
{
  return tqe->seq;
}

uint16_t scamper_tbit_tcpqe_len_get(const scamper_tbit_tcpqe_t *tqe)
{
  return tqe->len;
}

uint8_t scamper_tbit_tcpqe_flags_get(const scamper_tbit_tcpqe_t *tqe)
{
  return tqe->flags;
}

const uint8_t *scamper_tbit_tcpqe_data_get(const scamper_tbit_tcpqe_t *tqe)
{
  return tqe->data;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_tbit_pkt_t *scamper_tbit_pkt_use(scamper_tbit_pkt_t *pkt)
{
  pkt->refcnt++;
  return pkt;
}
#endif
