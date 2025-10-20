/*
 * common_host : common functions for unit testing neighbourdisc
 *
 * $Id: common_neighbourdisc.c,v 1.3 2025/10/19 20:49:19 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2025 Matthew Luckie
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
#include "scamper_file.h"
#include "scamper_neighbourdisc.h"
#include "scamper_neighbourdisc_int.h"

#include "utils.h"

#include "common.h"
#include "common_ok.h"

typedef scamper_neighbourdisc_t * (*scamper_neighbourdisc_makefunc_t)(void);

typedef int (*cmp_func_t)(const void *, const void *);

static int reply_ok(const scamper_neighbourdisc_reply_t *in,
		    const scamper_neighbourdisc_reply_t *out)
{
  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(timeval_cmp(&in->rx, &out->rx) ||
     addr_ok(in->mac, out->mac) != 0)
    return -1;
  return 0;
}

static int probe_ok(const scamper_neighbourdisc_probe_t *in,
		    const scamper_neighbourdisc_probe_t *out)
{
  uint16_t i;

  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(timeval_cmp(&in->tx, &out->tx) != 0 ||
     in->rxc != out->rxc)
    return -1;
  for(i=0; i<in->rxc; i++)
    if(reply_ok(in->rxs[i], out->rxs[i]) != 0)
      return -1;

  return 0;
}

int neighbourdisc_ok(const scamper_neighbourdisc_t *in,
		     const scamper_neighbourdisc_t *out)
{
  uint16_t i;

  assert(in != NULL);
  if(out == NULL ||
     in->userid != out->userid ||
     timeval_cmp(&in->start, &out->start) != 0 ||
     str_ok(in->ifname, out->ifname) != 0 ||
     str_ok(in->errmsg, out->errmsg) != 0 ||
     in->method != out->method ||
     in->flags != out->flags ||
     timeval_cmp(&in->wait_timeout, &out->wait_timeout) != 0 ||
     in->attempts != out->attempts ||
     in->replyc != out->replyc ||
     addr_ok(in->src_ip, out->src_ip) != 0 ||
     addr_ok(in->src_mac, out->src_mac) != 0 ||
     addr_ok(in->dst_ip, out->dst_ip) != 0 ||
     addr_ok(in->dst_mac, out->dst_mac) != 0 ||
     ptr_ok(in->probes, out->probes) != 0 ||
     in->probec != out->probec)
    return -1;

  for(i=0; i<in->probec; i++)
    if(probe_ok(in->probes[i], out->probes[i]) != 0)
      return -1;

  return 0;
}

/*
 * nd_1:
 *
 * ARP
 */
static scamper_neighbourdisc_t *nd_1(void)
{
  uint8_t src_mac[6] = {0x00, 0x00, 0x5e, 0x00, 0x53, 0x99};
  uint8_t dst_mac[6] = {0x00, 0x00, 0x5e, 0x00, 0x53, 0x26};
  scamper_neighbourdisc_t *nd = NULL;
  int at = SCAMPER_ADDR_TYPE_ETHERNET;
  scamper_neighbourdisc_probe_t *p;
  scamper_neighbourdisc_reply_t *r;

  if((nd = scamper_neighbourdisc_alloc()) == NULL ||
     (nd->ifname = strdup("em0")) == NULL ||
     (nd->src_ip = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (nd->dst_ip = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL ||
     (nd->src_mac = scamper_addr_alloc(at, src_mac)) == NULL ||
     (nd->dst_mac = scamper_addr_alloc(at, dst_mac)) == NULL ||
     scamper_neighbourdisc_probes_alloc(nd, 1) != 0 ||
     (nd->probes[nd->probec++] = p =
      scamper_neighbourdisc_probe_alloc()) == NULL ||
     scamper_neighbourdisc_replies_alloc(p, 1) != 0 ||
     (p->rxs[p->rxc++] = r = scamper_neighbourdisc_reply_alloc()) == NULL)
    goto err;

  nd->userid = 64;
  nd->start.tv_sec         = 1724828853;
  nd->start.tv_usec        = 123456;
  nd->method               = SCAMPER_NEIGHBOURDISC_METHOD_ARP;
  nd->flags                = SCAMPER_NEIGHBOURDISC_FLAG_FIRSTRESPONSE;
  nd->wait_timeout.tv_sec  = 1;
  nd->wait_timeout.tv_usec = 0;
  nd->attempts             = 1;
  nd->replyc               = 1;

  p->tx.tv_sec = nd->start.tv_sec;
  p->tx.tv_usec = nd->start.tv_usec + 23;

  r->rx.tv_sec = nd->start.tv_sec;
  r->rx.tv_usec = p->tx.tv_usec + 235;
  r->mac = scamper_addr_use(nd->dst_mac);

  return nd;

 err:
  if(nd != NULL) scamper_neighbourdisc_free(nd);
  return NULL;
}

static scamper_neighbourdisc_t *nd_2(void)
{
  scamper_neighbourdisc_t *nd = NULL;

  if((nd = scamper_neighbourdisc_alloc()) == NULL ||
     (nd->ifname = strdup("em0")) == NULL ||
     (nd->src_ip = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (nd->dst_ip = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL ||
     (nd->errmsg = strdup("hello world")) == NULL)
    goto err;

  nd->userid = 65;
  nd->start.tv_sec         = 1724828853;
  nd->start.tv_usec        = 123456;
  nd->method               = SCAMPER_NEIGHBOURDISC_METHOD_ARP;
  nd->flags                = SCAMPER_NEIGHBOURDISC_FLAG_FIRSTRESPONSE;
  nd->wait_timeout.tv_sec  = 1;
  nd->wait_timeout.tv_usec = 0;
  nd->attempts             = 1;

  return nd;

 err:
  if(nd != NULL) scamper_neighbourdisc_free(nd);
  return NULL;
}

static scamper_neighbourdisc_makefunc_t makers[] = {
  nd_1,
  nd_2,
};

scamper_neighbourdisc_t *neighbourdisc_makers(size_t i)
{
  if(i >= sizeof(makers) / sizeof(scamper_neighbourdisc_makefunc_t))
    return NULL;
  return makers[i]();
}

size_t neighbourdisc_makerc(void)
{
  return sizeof(makers) / sizeof(scamper_neighbourdisc_makefunc_t);
}
