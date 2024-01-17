/*
 * scamper_sting_lib.c
 *
 * $Id: scamper_sting_lib.c,v 1.5 2023/12/24 00:03:21 mjl Exp $
 *
 * Copyright (C) 2023 Matthew Luckie
 * Author: Matthew Luckie
 *
 * This file implements algorithms described in the sting-0.7 source code,
 * as well as the paper:
 *
 *  Sting: a TCP-based Network Measurement Tool
 *  by Stefan Savage
 *  1999 USENIX Symposium on Internet Technologies and Systems
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
#include "scamper_sting.h"
#include "scamper_sting_int.h"

scamper_list_t *scamper_sting_list_get(const scamper_sting_t *sting)
{
  return sting->list;
}

scamper_cycle_t *scamper_sting_cycle_get(const scamper_sting_t *sting)
{
  return sting->cycle;
}

uint32_t scamper_sting_userid_get(const scamper_sting_t *sting)
{
  return sting->userid;
}

scamper_addr_t *scamper_sting_src_get(const scamper_sting_t *sting)
{
  return sting->src;
}

scamper_addr_t *scamper_sting_dst_get(const scamper_sting_t *sting)
{
  return sting->dst;
}

uint16_t scamper_sting_sport_get(const scamper_sting_t *sting)
{
  return sting->sport;
}

uint16_t scamper_sting_dport_get(const scamper_sting_t *sting)
{
  return sting->dport;
}

uint16_t scamper_sting_count_get(const scamper_sting_t *sting)
{
  return sting->count;
}

const struct timeval *scamper_sting_mean_get(const scamper_sting_t *sting)
{
  return &sting->mean;
}

const struct timeval *scamper_sting_inter_get(const scamper_sting_t *sting)
{
  return &sting->inter;
}

uint8_t scamper_sting_dist_get(const scamper_sting_t *sting)
{
  return sting->dist;
}

uint8_t scamper_sting_synretx_get(const scamper_sting_t *sting)
{
  return sting->synretx;
}

uint8_t scamper_sting_dataretx_get(const scamper_sting_t *sting)
{
  return sting->dataretx;
}

uint8_t scamper_sting_seqskip_get(const scamper_sting_t *sting)
{
  return sting->seqskip;
}

const uint8_t *scamper_sting_data_get(const scamper_sting_t *sting)
{
  return sting->data;
}

uint16_t scamper_sting_datalen_get(const scamper_sting_t *sting)
{
  return sting->datalen;
}

const struct timeval *scamper_sting_start_get(const scamper_sting_t *sting)
{
  return &sting->start;
}

const struct timeval *scamper_sting_hsrtt_get(const scamper_sting_t *sting)
{
  return &sting->hsrtt;
}

uint16_t scamper_sting_dataackc_get(const scamper_sting_t *sting)
{
  return sting->dataackc;
}

uint16_t scamper_sting_holec_get(const scamper_sting_t *sting)
{
  return sting->holec;
}

scamper_sting_pkt_t *scamper_sting_pkt_get(const scamper_sting_t *sting,
					   uint32_t i)
{
  if(sting->pktc <= i)
    return NULL;
  return sting->pkts[i];
}

uint32_t scamper_sting_pktc_get(const scamper_sting_t *sting)
{
  return sting->pktc;
}

uint8_t scamper_sting_result_get(const scamper_sting_t *sting)
{
  return sting->result;
}

const struct timeval *scamper_sting_pkt_tv_get(const scamper_sting_pkt_t *pkt)
{
  return &pkt->tv;
}

uint8_t scamper_sting_pkt_flags_get(const scamper_sting_pkt_t *pkt)
{
  return pkt->flags;
}

uint16_t scamper_sting_pkt_len_get(const scamper_sting_pkt_t *pkt)
{
  return pkt->len;
}

const uint8_t *scamper_sting_pkt_data_get(const scamper_sting_pkt_t *pkt)
{
  return pkt->data;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_sting_pkt_t *scamper_sting_pkt_use(scamper_sting_pkt_t *pkt)
{
  pkt->refcnt++;
  return pkt;
}
#endif
