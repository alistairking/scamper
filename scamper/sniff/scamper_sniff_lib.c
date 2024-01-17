/*
 * scamper_sniff.c
 *
 * $Id: scamper_sniff_lib.c,v 1.6 2024/01/02 17:51:46 mjl Exp $
 *
 * Copyright (C) 2023 Matthew Luckie
 * Author: Matthew Luckie
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
#include "scamper_sniff.h"
#include "scamper_sniff_int.h"

scamper_list_t *scamper_sniff_list_get(const scamper_sniff_t *sniff)
{
  return sniff->list;
}

scamper_cycle_t *scamper_sniff_cycle_get(const scamper_sniff_t *sniff)
{
  return sniff->cycle;
}

uint32_t scamper_sniff_userid_get(const scamper_sniff_t *sniff)
{
  return sniff->userid;
}

const struct timeval *scamper_sniff_start_get(const scamper_sniff_t *sniff)
{
  return &sniff->start;
}

const struct timeval *scamper_sniff_finish_get(const scamper_sniff_t *sniff)
{
  return &sniff->finish;
}

uint8_t scamper_sniff_stop_reason_get(const scamper_sniff_t *sniff)
{
  return sniff->stop_reason;
}

uint32_t scamper_sniff_limit_pktc_get(const scamper_sniff_t *sniff)
{
  return sniff->limit_pktc;
}

const struct timeval *scamper_sniff_limit_time_get(const scamper_sniff_t *sniff)
{
  return &sniff->limit_time;
}

scamper_addr_t *scamper_sniff_src_get(const scamper_sniff_t *sniff)
{
  return sniff->src;
}

uint16_t scamper_sniff_icmpid_get(const scamper_sniff_t *sniff)
{
  return sniff->icmpid;
}

scamper_sniff_pkt_t *scamper_sniff_pkt_get(const scamper_sniff_t *sniff,
					   uint32_t i)
{
  if(sniff->pktc <= i)
    return NULL;
  return sniff->pkts[i];
}

uint32_t scamper_sniff_pktc_get(const scamper_sniff_t *sniff)
{
  return sniff->pktc;
}

const struct timeval *scamper_sniff_pkt_tv_get(const scamper_sniff_pkt_t *pkt)
{
  return &pkt->tv;
}

const uint8_t *scamper_sniff_pkt_data_get(const scamper_sniff_pkt_t *pkt)
{
  return pkt->data;
}

uint16_t scamper_sniff_pkt_len_get(const scamper_sniff_pkt_t *pkt)
{
  return pkt->len;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_sniff_pkt_t *scamper_sniff_pkt_use(scamper_sniff_pkt_t *pkt)
{
  pkt->refcnt++;
  return pkt;
}
#endif
