/*
 * common_udpprobe : common functions for unit testing udpprobe
 *
 * $Id: common_udpprobe.c,v 1.1 2025/04/20 07:33:52 mjl Exp $
 *
 *        Marcus Luckie, Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024 Marcus Luckie
 * Copyright (C) 2024-2025 Matthew Luckie
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
#include "scamper_udpprobe.h"
#include "scamper_udpprobe_int.h"
#include "scamper_ifname.h"
#include "scamper_ifname_int.h"
#include "common_ok.h"
#include "common_udpprobe.h"
#include "utils.h"

typedef scamper_udpprobe_t * (*scamper_udpprobe_makefunc_t)(void);

typedef struct udpprobe
{
  time_t      tv_sec;
  suseconds_t tv_usec;
  uint16_t    sport;
} udpprobe_t;

static const udpprobe_t probes[] = {
  {1724828853, 123456, 26332},
  {1724828854, 124981, 52326},
  {1724828855, 126912, 24238},
};

static int udpprobe_reply_ok(const scamper_udpprobe_reply_t *in,
			     const scamper_udpprobe_reply_t *out)
{
  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(ptr_ok(in->data, out->data) != 0 ||
     in->len != out->len ||
     (in->data != NULL && buf_ok(in->data, out->data, in->len) != 0) ||
     timeval_cmp(&in->rx, &out->rx) != 0 ||
     ifname_ok(in->ifname, out->ifname) != 0)
    return -1;

  return 0;
}

static int udpprobe_probe_ok(const scamper_udpprobe_probe_t *in,
			     const scamper_udpprobe_probe_t *out)
{
  uint8_t i;

  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(timeval_cmp(&in->tx, &out->tx) != 0 ||
     in->sport != out->sport ||
     in->replyc != out->replyc ||
     ptr_ok(in->replies, out->replies) != 0)
    return -1;

  if(in->replies != NULL)
    {
      for(i=0; i<in->replyc; i++)
	if(udpprobe_reply_ok(in->replies[i], out->replies[i]) != 0)
	  return -1;
    }

  return 0;
}

int udpprobe_ok(const scamper_udpprobe_t *in, const scamper_udpprobe_t *out)
{
  uint8_t i;

  assert(in != NULL);
  if(out == NULL ||
     in->userid != out->userid ||
     addr_ok(in->src, out->src) != 0 ||
     addr_ok(in->dst, out->dst) != 0 ||
     in->sport != out->sport ||
     in->dport != out->dport ||
     in->probe_count != out->probe_count ||
     in->stop_count != out->stop_count ||
     timeval_cmp(&in->start, &out->start) != 0 ||
     timeval_cmp(&in->wait_timeout, &out->wait_timeout) != 0 ||
     timeval_cmp(&in->wait_probe, &out->wait_probe) != 0 ||
     in->flags != out->flags ||
     in->len != out->len ||
     buf_ok(in->data, out->data, in->len) != 0 ||
     in->stop != out->stop ||
     in->probe_sent != out->probe_sent ||
     ptr_ok(in->probes, out->probes) != 0)
    return -1;

  for(i=0; i<in->probe_sent; i++)
    if(udpprobe_probe_ok(in->probes[i], out->probes[i]) != 0)
      return -1;

  return 0;
}

static scamper_udpprobe_t *udpprobe_1_4(uint8_t probe_sent)
{
  scamper_udpprobe_t *up = NULL;
  scamper_udpprobe_probe_t *probe;
  size_t len = sizeof(scamper_udpprobe_probe_t *) * probe_sent;
  uint8_t data [] = { 5, 56, 32, 59 };
  uint8_t i;

  if((up = scamper_udpprobe_alloc()) == NULL ||
     (up->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (up->dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL ||
     (len > 0 && (up->probes = malloc_zero(len)) == NULL))
    goto err;

  up->userid               = 69;
  up->sport                = probes[0].sport;
  up->dport                = 154;
  up->probe_count          = 163;
  up->stop_count           = 50;
  up->start.tv_sec         = 1724828853;
  up->start.tv_usec        = 123456;
  up->wait_timeout.tv_sec  = 1;
  up->wait_timeout.tv_usec = 0;
  up->wait_probe.tv_sec    = 5;
  up->wait_probe.tv_usec   = 0;
  up->flags                = 0;
  up->data                 = memdup(data, 4);
  up->len                  = 4;
  up->stop                 = SCAMPER_UDPPROBE_STOP_DONE;
  up->probe_sent           = probe_sent;

  for(i=0; i<up->probe_sent; i++)
    {
      if((probe = scamper_udpprobe_probe_alloc()) == NULL)
	goto err;
      probe->sport = probes[i].sport;
      probe->tx.tv_sec = probes[i].tv_sec;
      probe->tx.tv_usec = probes[i].tv_usec;
      up->probes[i] = probe;
    }

  return up;

 err:
  if(up != NULL) scamper_udpprobe_free(up);
  return NULL;
}

static scamper_udpprobe_t *udpprobe_1(void)
{
  return udpprobe_1_4(0);
}

static scamper_udpprobe_t *udpprobe_2(void)
{
  return udpprobe_1_4(1);
}

static scamper_udpprobe_t *udpprobe_3(void)
{
  return udpprobe_1_4(2);
}

static scamper_udpprobe_t *udpprobe_4(void)
{
  return udpprobe_1_4(3);
}

static scamper_udpprobe_t *udpprobe_5_6(uint8_t replyc)
{
  scamper_udpprobe_t *up = NULL;
  scamper_udpprobe_reply_t *reply = NULL;
  size_t len = sizeof(scamper_udpprobe_reply_t *) * replyc;
  uint8_t data[] = { 127, 234, 2, 255, 0, 86 };
  uint8_t i, j;

  if((up = udpprobe_2()) == NULL ||
     (up->probes[0]->replies = malloc_zero(len)) == NULL)
    goto err;

  up->probes[0]->replyc = replyc;
  for(i=0; i<replyc; i++)
    {
      if((reply = scamper_udpprobe_reply_alloc()) == NULL ||
	 (reply->data = memdup(data, 6)) == NULL)
	goto err;
      reply->rx.tv_sec  = probes[0].tv_sec;
      reply->rx.tv_usec = probes[0].tv_usec + 52301 + (i * 20);
      reply->len        = 6;
      up->probes[0]->replies[i] = reply;
      for(j=0; j<reply->len; j++)
	reply->data[j] += i;
    }

  return up;

 err:
  if(up != NULL) scamper_udpprobe_free(up);
  return NULL;
}

static scamper_udpprobe_t *udpprobe_5(void)
{
  return udpprobe_5_6(1);
}

static scamper_udpprobe_t *udpprobe_6(void)
{
  return udpprobe_5_6(2);
}

static scamper_udpprobe_makefunc_t makers[] = {
  udpprobe_1,
  udpprobe_2,
  udpprobe_3,
  udpprobe_4,
  udpprobe_5,
  udpprobe_6,
};

scamper_udpprobe_t *udpprobe_makers(size_t i)
{
  if(i >= sizeof(makers) / sizeof(scamper_udpprobe_makefunc_t))
    return NULL;
  return makers[i](); 
}

size_t udpprobe_makerc(void)
{
  return sizeof(makers) / sizeof(scamper_udpprobe_makefunc_t);
}
