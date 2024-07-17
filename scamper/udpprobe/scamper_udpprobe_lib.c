/*
 * scamper_udpprobe_lib.c
 *
 * $Id: scamper_udpprobe_lib.c,v 1.5 2024/04/04 22:57:01 mjl Exp $
 *
 * Copyright (C) 2023 The Regents of the University of California
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
#include "scamper_list.h"
#include "scamper_udpprobe.h"
#include "scamper_udpprobe_int.h"
#include "utils.h"

scamper_list_t *scamper_udpprobe_list_get(const scamper_udpprobe_t *udpp)
{
  return udpp->list;
}

scamper_cycle_t *scamper_udpprobe_cycle_get(const scamper_udpprobe_t *udpp)
{
  return udpp->cycle;
}

uint32_t scamper_udpprobe_userid_get(const scamper_udpprobe_t *udpp)
{
  return udpp->userid;
}

scamper_addr_t *scamper_udpprobe_src_get(const scamper_udpprobe_t *udpp)
{
  return udpp->src;
}

scamper_addr_t *scamper_udpprobe_dst_get(const scamper_udpprobe_t *udpp)
{
  return udpp->dst;
}

uint16_t scamper_udpprobe_sport_get(const scamper_udpprobe_t *udpp)
{
  return udpp->sport;
}

uint16_t scamper_udpprobe_dport_get(const scamper_udpprobe_t *udpp)
{
  return udpp->dport;
}

const struct timeval *scamper_udpprobe_start_get(const scamper_udpprobe_t *udpp)
{
  return &udpp->start;
}

const struct timeval *scamper_udpprobe_wait_timeout_get(const scamper_udpprobe_t *udpp)
{
  return &udpp->wait_timeout;
}

const struct timeval *scamper_udpprobe_wait_probe_get(const scamper_udpprobe_t *udpp)
{
  return &udpp->wait_probe;
}

int scamper_udpprobe_flag_is_exitfirst(const scamper_udpprobe_t *udpp)
{
  return SCAMPER_UDPPROBE_FLAG_IS_EXITFIRST(udpp);
}

const uint8_t *scamper_udpprobe_data_get(const scamper_udpprobe_t *up)
{
  return up->data;
}

uint16_t scamper_udpprobe_len_get(const scamper_udpprobe_t *up)
{
  return up->len;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_udpprobe_reply_t *scamper_udpprobe_reply_use(scamper_udpprobe_reply_t *ur)
{
  ur->refcnt++;
  return ur;
}
#endif

const uint8_t *scamper_udpprobe_reply_data_get(const scamper_udpprobe_reply_t *ur)
{
  return ur->data;
}

uint16_t scamper_udpprobe_reply_len_get(const scamper_udpprobe_reply_t *ur)
{
  return ur->len;
}

const struct timeval *scamper_udpprobe_reply_rx_get(const scamper_udpprobe_reply_t *ur)
{
  return &ur->rx;
}

uint8_t scamper_udpprobe_probe_count_get(const scamper_udpprobe_t *up)
{
  return up->probe_count;
}

uint8_t scamper_udpprobe_probe_sent_get(const scamper_udpprobe_t *up)
{
  return up->probe_sent;
}

uint8_t scamper_udpprobe_stop_count_get(const scamper_udpprobe_t *up)
{
  return up->stop_count;
}

scamper_udpprobe_probe_t *scamper_udpprobe_probe_get(const scamper_udpprobe_t *up, uint8_t i)
{
  if(up->probes == NULL || i >= up->probe_sent)
    return NULL;
  return up->probes[i];
}

const struct timeval *scamper_udpprobe_probe_tx_get(const scamper_udpprobe_probe_t *probe)
{
  return &probe->tx;
}

uint16_t scamper_udpprobe_probe_sport_get(const scamper_udpprobe_probe_t *probe)
{
  return probe->sport;
}

scamper_udpprobe_reply_t *scamper_udpprobe_probe_reply_get(const scamper_udpprobe_probe_t *probe, uint8_t i)
{
  if(probe->replies == NULL || i >= probe->replyc)
    return NULL;
  return probe->replies[i];
}

uint8_t scamper_udpprobe_probe_replyc_get(const scamper_udpprobe_probe_t *probe)
{
  return probe->replyc;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_udpprobe_probe_t *scamper_udpprobe_probe_use(scamper_udpprobe_probe_t *pr)
{
  pr->refcnt++;
  return pr;
}
#endif
