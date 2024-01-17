/*
 * scamper_neighbourdisc_lib.c
 *
 * $Id: scamper_neighbourdisc_lib.c,v 1.6 2023/12/24 00:19:25 mjl Exp $
 *
 * Copyright (C) 2023 Matthew Luckie
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
#include "scamper_neighbourdisc.h"
#include "scamper_neighbourdisc_int.h"

scamper_list_t *
scamper_neighbourdisc_list_get(const scamper_neighbourdisc_t *nd)
{
  return nd->list;
}

scamper_cycle_t *
scamper_neighbourdisc_cycle_get(const scamper_neighbourdisc_t *nd)
{
  return nd->cycle;
}

uint32_t scamper_neighbourdisc_userid_get(const scamper_neighbourdisc_t *nd)
{
  return nd->userid;
}

const struct timeval *
scamper_neighbourdisc_start_get(const scamper_neighbourdisc_t *nd)
{
  return &nd->start;
}

const char *scamper_neighbourdisc_ifname_get(const scamper_neighbourdisc_t *nd)
{
  return nd->ifname;
}

uint8_t scamper_neighbourdisc_method_get(const scamper_neighbourdisc_t *nd)
{
  return nd->method;
}

uint8_t scamper_neighbourdisc_flags_get(const scamper_neighbourdisc_t *nd)
{
  return nd->flags;
}

const struct timeval *
scamper_neighbourdisc_wait_timeout_get(const scamper_neighbourdisc_t *nd)
{
  return &nd->wait_timeout;
}

uint16_t scamper_neighbourdisc_attempts_get(const scamper_neighbourdisc_t *nd)
{
  return nd->attempts;
}

uint16_t scamper_neighbourdisc_replyc_get(const scamper_neighbourdisc_t *nd)
{
  return nd->replyc;
}

scamper_addr_t *
scamper_neighbourdisc_src_ip_get(const scamper_neighbourdisc_t *nd)
{
  return nd->src_ip;
}

scamper_addr_t *
scamper_neighbourdisc_src_mac_get(const scamper_neighbourdisc_t *nd)
{
  return nd->src_mac;
}

scamper_addr_t *
scamper_neighbourdisc_dst_ip_get(const scamper_neighbourdisc_t *nd)
{
  return nd->dst_ip;
}

scamper_addr_t *
scamper_neighbourdisc_dst_mac_get(const scamper_neighbourdisc_t *nd)
{
  return nd->dst_mac;
}

scamper_neighbourdisc_probe_t *
scamper_neighbourdisc_probe_get(const scamper_neighbourdisc_t *nd, uint16_t i)
{
  if(nd->probec <= i)
    return NULL;
  return nd->probes[i];
}

uint16_t scamper_neighbourdisc_probec_get(const scamper_neighbourdisc_t *nd)
{
  return nd->probec;
}

const struct timeval *
scamper_neighbourdisc_probe_tx_get(const scamper_neighbourdisc_probe_t *p)
{
  return &p->tx;
}

scamper_neighbourdisc_reply_t *
scamper_neighbourdisc_probe_reply_get(const scamper_neighbourdisc_probe_t *p,
				      uint16_t i)
{
  if(p->rxc <= i)
    return NULL;
  return p->rxs[i];
}

uint16_t
scamper_neighbourdisc_probe_replyc_get(const scamper_neighbourdisc_probe_t *p)
{
  return p->rxc;
}

const struct timeval *
scamper_neighbourdisc_reply_rx_get(const scamper_neighbourdisc_reply_t *r)
{
  return &r->rx;
}

scamper_addr_t *
scamper_neighbourdisc_reply_mac_get(const scamper_neighbourdisc_reply_t *r)
{
  return r->mac;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_neighbourdisc_reply_t *
scamper_neighbourdisc_reply_use(scamper_neighbourdisc_reply_t *r)
{
  r->refcnt++;
  return r;
}

scamper_neighbourdisc_probe_t *
scamper_neighbourdisc_probe_use(scamper_neighbourdisc_probe_t *p)
{
  p->refcnt++;
  return p;
}
#endif
