/*
 * scamper_owamp_lib.c
 *
 * Copyright (C) 2025 The Regents of the University of California
 *
 * Author: Matthew Luckie
 *
 * $Id: scamper_owamp_lib.c,v 1.2 2025/12/05 02:15:27 mjl Exp $
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
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_owamp.h"
#include "scamper_owamp_int.h"

scamper_list_t *scamper_owamp_list_get(const scamper_owamp_t *owamp)
{
  return owamp->list;
}

scamper_cycle_t *scamper_owamp_cycle_get(const scamper_owamp_t *owamp)
{
  return owamp->cycle;
}

uint32_t scamper_owamp_userid_get(const scamper_owamp_t *owamp)
{
  return owamp->userid;
}

scamper_addr_t *scamper_owamp_dst_get(const scamper_owamp_t *owamp)
{
  return owamp->dst;
}

scamper_addr_t *scamper_owamp_src_get(const scamper_owamp_t *owamp)
{
  return owamp->src;
}

uint16_t scamper_owamp_dport_get(const scamper_owamp_t *owamp)
{
  return owamp->dport;
}

uint16_t scamper_owamp_flags_get(const scamper_owamp_t *owamp)
{
  return owamp->flags;
}

const struct timeval *scamper_owamp_start_get(const scamper_owamp_t *owamp)
{
  return &owamp->start;
}

const struct timeval *scamper_owamp_startat_get(const scamper_owamp_t *owamp)
{
  return &owamp->startat;
}

const struct timeval *scamper_owamp_wait_timeout_get(const scamper_owamp_t *owamp)
{
  return &owamp->wait_timeout;
}

uint32_t scamper_owamp_schedc_get(const scamper_owamp_t *owamp)
{
  return owamp->schedc;
}

scamper_owamp_sched_t *scamper_owamp_sched_get(const scamper_owamp_t *owamp, uint32_t i)
{
  if(i >= owamp->schedc || owamp->sched == NULL)
    return NULL;
  return owamp->sched[i];
}

uint32_t scamper_owamp_attempts_get(const scamper_owamp_t *owamp)
{
  return owamp->attempts;
}

uint16_t scamper_owamp_pktsize_get(const scamper_owamp_t *owamp)
{
  return owamp->pktsize;
}

uint8_t scamper_owamp_dir_get(const scamper_owamp_t *owamp)
{
  return owamp->dir;
}

uint8_t scamper_owamp_dscp_get(const scamper_owamp_t *owamp)
{
  return owamp->dscp;
}

uint8_t scamper_owamp_ttl_get(const scamper_owamp_t *owamp)
{
  return owamp->ttl;
}

const struct timeval *scamper_owamp_hsrtt_get(const scamper_owamp_t *owamp)
{
  return &owamp->hsrtt;
}

uint8_t scamper_owamp_result_get(const scamper_owamp_t *owamp)
{
  return owamp->result;
}

char *scamper_owamp_errmsg_get(const scamper_owamp_t *owamp)
{
  return owamp->errmsg;
}

uint16_t scamper_owamp_udp_sport_get(const scamper_owamp_t *owamp)
{
  return owamp->udp_sport;
}

uint16_t scamper_owamp_udp_dport_get(const scamper_owamp_t *owamp)
{
  return owamp->udp_dport;
}

uint32_t scamper_owamp_txc_get(const scamper_owamp_t *owamp)
{
  return owamp->txc;
}

scamper_owamp_tx_t *scamper_owamp_tx_get(const scamper_owamp_t *owamp, uint32_t i)
{
  if(i >= owamp->txc || owamp->txs == NULL)
    return NULL;
  return owamp->txs[i];
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_owamp_tx_t *scamper_owamp_tx_use(scamper_owamp_tx_t *tx)
{
  tx->refcnt++;
  return tx;
}
#endif

const struct timeval *scamper_owamp_tx_sched_get(const scamper_owamp_tx_t *tx)
{
  return &tx->sched;
}

const struct timeval *scamper_owamp_tx_stamp_get(const scamper_owamp_tx_t *tx)
{
  return &tx->stamp;
}

uint32_t scamper_owamp_tx_seq_get(const scamper_owamp_tx_t *tx)
{
  return tx->seq;
}

uint16_t scamper_owamp_tx_errest_get(const scamper_owamp_tx_t *tx)
{
  return tx->errest;
}

uint16_t scamper_owamp_tx_flags_get(const scamper_owamp_tx_t *tx)
{
  return tx->flags;
}

uint8_t scamper_owamp_tx_rxc_get(const scamper_owamp_tx_t *tx)
{
  return tx->rxc;
}

scamper_owamp_rx_t *scamper_owamp_tx_rx_get(const scamper_owamp_tx_t *tx, uint8_t i)
{
  if(i >= tx->rxc || tx->rxs == NULL)
    return NULL;
  return tx->rxs[i];
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_owamp_rx_t *scamper_owamp_rx_use(scamper_owamp_rx_t *rx)
{
  rx->refcnt++;
  return rx;
}
#endif

const struct timeval *scamper_owamp_rx_stamp_get(const scamper_owamp_rx_t *rx)
{
  return &rx->stamp;
}

uint16_t scamper_owamp_rx_errest_get(const scamper_owamp_rx_t *rx)
{
  return rx->errest;
}

uint8_t scamper_owamp_rx_flags_get(const scamper_owamp_rx_t *rx)
{
  return rx->flags;
}

uint8_t scamper_owamp_rx_dscp_get(const scamper_owamp_rx_t *rx)
{
  return rx->dscp;
}

uint8_t scamper_owamp_rx_ttl_get(const scamper_owamp_rx_t *rx)
{
  return rx->ttl;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_owamp_sched_t *scamper_owamp_sched_use(scamper_owamp_sched_t *sched)
{
  sched->refcnt++;
  return sched;
}
#endif

uint8_t scamper_owamp_sched_type_get(const scamper_owamp_sched_t *sched)
{
  return sched->type;
}

const struct timeval *scamper_owamp_sched_tv_get(const scamper_owamp_sched_t *sched)
{
  return &sched->tv;
}
