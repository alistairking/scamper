/*
 * scamper_ping.c
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2020-2023 Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_ping.c,v 1.60 2025/02/25 06:31:24 mjl Exp $
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
#include "scamper_addr_int.h"
#include "scamper_ifname.h"
#include "scamper_ping.h"
#include "scamper_ping_int.h"

#include "utils.h"

char *scamper_ping_method_tostr(const scamper_ping_t *ping,char *buf,size_t len)
{
  static char *m[] = {
    "icmp-echo",
    "tcp-ack",
    "tcp-ack-sport",
    "udp",
    "udp-dport",
    "icmp-time",
    "tcp-syn",
    "tcp-synack",
    "tcp-rst",
    "tcp-syn-sport",
    "udp-sport",
  };
  size_t off = 0;

  if(ping->method >= sizeof(m) / sizeof(char *))
    string_concat_u8(buf, len, &off, NULL, ping->method);
  else
    string_concat(buf, len, &off, m[ping->method]);

  return buf;
}

char *scamper_ping_stop_tostr(const scamper_ping_t *ping, char *buf, size_t len)
{
  static char *r[] = {
    "none",
    "done",
    "error",
    "halted",
  };
  size_t off = 0;

  if(ping->stop_reason >= sizeof(r) / sizeof(char *))
    string_concat_u8(buf, len, &off, NULL, ping->stop_reason);
  else
    string_concat(buf, len, &off, r[ping->stop_reason]);

  return buf;
}

void scamper_ping_stats_free(scamper_ping_stats_t *stats)
{
  free(stats);
  return;
}

scamper_ping_stats_t *scamper_ping_stats_alloc(const scamper_ping_t *ping)
{
  scamper_ping_stats_t *stats = NULL;
  scamper_ping_probe_t *probe;
  scamper_ping_reply_t *reply;
  uint16_t i, j;
  uint32_t us;
  double d, sum = 0, diff = 0, rtt;
  int first = 1;
  uint32_t n;
  uint32_t err, rxc;

  if((stats = malloc_zero(sizeof(scamper_ping_stats_t))) == NULL)
    return NULL;

  for(i=0; i<ping->ping_sent; i++)
    {
      if((probe = ping->probes[i]) == NULL)
	continue;

      rxc = 0;
      err = 0;

      for(j=0; j < probe->replyc; j++)
	{
	  reply = probe->replies[j];
	  if(SCAMPER_PING_REPLY_IS_FROM_TARGET(ping, reply))
	    {
	      if(first == 0)
		{
		  if(timeval_cmp(&reply->rtt, &stats->min_rtt) < 0)
		    timeval_cpy(&stats->min_rtt, &reply->rtt);
		  if(timeval_cmp(&reply->rtt, &stats->max_rtt) > 0)
		    timeval_cpy(&stats->max_rtt, &reply->rtt);
		}
	      else
		{
		  timeval_cpy(&stats->min_rtt, &reply->rtt);
		  timeval_cpy(&stats->max_rtt, &reply->rtt);
		  first = 0;
		}
	      sum += ((reply->rtt.tv_sec * 1000000) + reply->rtt.tv_usec);
	      rxc++;
	    }
	  else err++;
	}

      if(rxc > 0)
	{
	  stats->nreplies++;
	  stats->ndups += (rxc-1);
	}
      else stats->nloss++;

      stats->nerrs += err;
    }

  n = stats->nreplies + stats->ndups;

  if(n > 0)
    {
      /* compute the average */
      us = (uint32_t)(sum / n);
      stats->avg_rtt.tv_sec  = us / 1000000;
      stats->avg_rtt.tv_usec = us % 1000000;

      /* compute the standard deviation */
      d = (sum / n);
      sum = 0;
      for(i=0; i<ping->ping_sent; i++)
	{
	  if((probe = ping->probes[i]) == NULL)
	    continue;

	  for(j=0; j<probe->replyc; j++)
	    {
	      reply = probe->replies[j];
	      if(SCAMPER_PING_REPLY_IS_FROM_TARGET(ping, reply) == 0)
		continue;
	      rtt = ((reply->rtt.tv_sec * 1000000) + reply->rtt.tv_usec);
	      diff = rtt - d;
	      sum += (diff * diff);
	    }
	}

      us = (uint32_t)sqrt(sum/n);
      stats->stddev_rtt.tv_sec  = us / 1000000;
      stats->stddev_rtt.tv_usec = us % 1000000;
    }

  return stats;
}

scamper_ping_reply_tsreply_t *scamper_ping_reply_tsreply_alloc(void)
{
  return malloc_zero(sizeof(scamper_ping_reply_tsreply_t));
}

void scamper_ping_reply_tsreply_free(scamper_ping_reply_tsreply_t *tsr)
{
  free(tsr);
  return;
}

void scamper_ping_v4ts_free(scamper_ping_v4ts_t *ts)
{
  uint8_t i;

  if(ts == NULL)
    return;

  if(ts->ips != NULL)
    {
      for(i=0; i<ts->ipc; i++)
	if(ts->ips[i] != NULL)
	  scamper_addr_free(ts->ips[i]);
      free(ts->ips);
    }

  free(ts);
  return;
}

scamper_ping_v4ts_t *scamper_ping_v4ts_alloc(uint8_t ipc)
{
  scamper_ping_v4ts_t *ts = NULL;

  if(ipc == 0)
    goto err;

  if((ts = malloc_zero(sizeof(scamper_ping_v4ts_t))) == NULL)
    goto err;
  ts->ipc = ipc;

  if((ts->ips = malloc_zero(sizeof(scamper_addr_t *) * ipc)) == NULL)
    goto err;

  return ts;

 err:
  scamper_ping_v4ts_free(ts);
  return NULL;
}

int scamper_ping_probes_alloc(scamper_ping_t *ping, uint16_t count)
{
  size_t size = sizeof(scamper_ping_probe_t *) * count;
  if((ping->probes = malloc_zero(size)) == NULL)
    return -1;
  return 0;
}

scamper_ping_t *scamper_ping_alloc(void)
{
  return (scamper_ping_t *)malloc_zero(sizeof(scamper_ping_t));
}

scamper_ping_t *scamper_ping_dup(const scamper_ping_t *in)
{
  scamper_ping_t *out = NULL;
  uint16_t i;

  if((out = memdup(in, sizeof(scamper_ping_t))) == NULL)
    goto err;

  if(in->list != NULL)
    out->list = scamper_list_use(in->list);
  if(in->cycle != NULL)
    out->cycle = scamper_cycle_use(in->cycle);
  if(in->src != NULL)
    out->src = scamper_addr_use(in->src);
  if(in->dst != NULL)
    out->dst = scamper_addr_use(in->dst);
  if(in->rtr != NULL)
    out->rtr = scamper_addr_use(in->rtr);

  /* set everything to NULL that could possibly fail */
  out->data   = NULL;
  out->tsps   = NULL;
  out->data   = NULL;
  out->probes = NULL;

  if(in->data != NULL &&
     (out->data = memdup(in->data, in->datalen)) == NULL)
    goto err;

  if(in->ping_sent > 0)
    {
      if(scamper_ping_probes_alloc(out, in->ping_sent) != 0)
	goto err;

      for(i=0; i<in->ping_sent; i++)
	{
	  if(in->probes[i] == NULL)
	    continue;
	  if((out->probes[i] = scamper_ping_probe_dup(in->probes[i])) == NULL)
	    goto err;
	}
    }

  return out;

 err:
  if(out != NULL) scamper_ping_free(out);
  return NULL;
}

void scamper_ping_free(scamper_ping_t *ping)
{
  uint16_t i;

  if(ping == NULL) return;

  if(ping->probes != NULL)
    {
      for(i=0; i<ping->ping_sent; i++)
	if(ping->probes[i] != NULL)
	  scamper_ping_probe_free(ping->probes[i]);
      free(ping->probes);
    }

  if(ping->dst != NULL) scamper_addr_free(ping->dst);
  if(ping->src != NULL) scamper_addr_free(ping->src);
  if(ping->rtr != NULL) scamper_addr_free(ping->rtr);

  if(ping->cycle != NULL) scamper_cycle_free(ping->cycle);
  if(ping->list != NULL) scamper_list_free(ping->list);

  if(ping->tsps != NULL) scamper_ping_v4ts_free(ping->tsps);
  if(ping->data != NULL) free(ping->data);

  free(ping);
  return;
}

scamper_ping_probe_t *scamper_ping_probe_alloc(void)
{
  scamper_ping_probe_t *probe = malloc_zero(sizeof(scamper_ping_probe_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(probe != NULL)
    probe->refcnt = 1;
#endif
  return probe;
}

void scamper_ping_probe_free(scamper_ping_probe_t *probe)
{
  uint16_t j;

  if(probe == NULL)
    return;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--probe->refcnt > 0)
    return;
#endif

  if(probe->replies != NULL)
    {
      for(j=0; j<probe->replyc; j++)
	scamper_ping_reply_free(probe->replies[j]);
      free(probe->replies);
    }
  free(probe);

  return;
}

scamper_ping_probe_t *scamper_ping_probe_dup(const scamper_ping_probe_t *in)
{
  scamper_ping_probe_t *out = NULL;
  size_t len;
  uint16_t i;

  if((out = memdup(in, sizeof(scamper_ping_probe_t))) == NULL)
    return NULL;

#ifdef BUILDING_LIBSCAMPERFILE
  out->refcnt = 1;
#endif

  out->replies = NULL;

  if(in->replyc > 0)
    {
      len = sizeof(scamper_ping_reply_t *) * in->replyc;
      if((out->replies = malloc_zero(len)) == NULL)
	goto err;
      for(i=0; i<in->replyc; i++)
	if((out->replies[i] = scamper_ping_reply_dup(in->replies[i])) == NULL)
	  goto err;
    }

  return out;

 err:
  if(out != NULL) scamper_ping_probe_free(out);
  return NULL;
}

uint32_t scamper_ping_reply_total(const scamper_ping_t *ping)
{
  scamper_ping_probe_t *probe;
  uint32_t count = 0;
  uint16_t i;

  for(i=0; i<ping->ping_sent; i++)
    if((probe = ping->probes[i]) != NULL)
      count += probe->replyc;

  return count;
}

int scamper_ping_probe_reply_append(scamper_ping_probe_t *probe,
				    scamper_ping_reply_t *reply)
{
  size_t len = (probe->replyc + 1) * sizeof(scamper_ping_reply_t *);

  if(realloc_wrap((void **)&probe->replies, len) != 0)
    return -1;
  probe->replies[probe->replyc++] = reply;

  return 0;
}

void scamper_ping_reply_v4ts_free(scamper_ping_reply_v4ts_t *ts)
{
  uint8_t i;

  if(ts == NULL)
    return;

  if(ts->tss != NULL)
    free(ts->tss);

  if(ts->ips != NULL)
    {
      for(i=0; i<ts->tsc; i++)
	if(ts->ips[i] != NULL)
	  scamper_addr_free(ts->ips[i]);
      free(ts->ips);
    }

  free(ts);
  return;
}

scamper_ping_reply_v4ts_t *scamper_ping_reply_v4ts_alloc(uint8_t tsc, int ip)
{
  scamper_ping_reply_v4ts_t *ts = NULL;

  if((ts = malloc_zero(sizeof(scamper_ping_reply_v4ts_t))) == NULL)
    goto err;
  ts->tsc = tsc;

  if(tsc > 0)
    {
      if((ts->tss = malloc_zero(sizeof(uint32_t) * tsc)) == NULL)
	goto err;
      if(ip != 0 &&
	 (ts->ips = malloc_zero(sizeof(scamper_addr_t *) * tsc)) == NULL)
	goto err;
    }

  return ts;

 err:
  scamper_ping_reply_v4ts_free(ts);
  return NULL;
}

void scamper_ping_reply_v4rr_free(scamper_ping_reply_v4rr_t *rr)
{
  uint8_t i;

  if(rr == NULL)
    return;

  if(rr->ip != NULL)
    {
      for(i=0; i<rr->ipc; i++)
	if(rr->ip[i] != NULL)
	  scamper_addr_free(rr->ip[i]);
      free(rr->ip);
    }

  free(rr);
  return;
}

scamper_ping_reply_v4rr_t *
scamper_ping_reply_v4rr_dup(const scamper_ping_reply_v4rr_t *in)
{
  scamper_ping_reply_v4rr_t *out;
  uint8_t i;
  if((out = scamper_ping_reply_v4rr_alloc(in->ipc)) == NULL)
    return NULL;
  for(i=0; i<in->ipc; i++)
    if(in->ip[i] != NULL)
      out->ip[i] = scamper_addr_use(in->ip[i]);
  return out;
}

scamper_ping_reply_v4rr_t *scamper_ping_reply_v4rr_alloc(uint8_t ipc)
{
  scamper_ping_reply_v4rr_t *rr = NULL;

  if(ipc == 0)
    goto err;

  if((rr = malloc_zero(sizeof(scamper_ping_reply_v4rr_t))) == NULL)
    goto err;
  rr->ipc = ipc;

  if((rr->ip = malloc_zero(sizeof(scamper_addr_t *) * ipc)) == NULL)
    goto err;

  return rr;

 err:
  scamper_ping_reply_v4rr_free(rr);
  return NULL;
}

scamper_ping_reply_t *scamper_ping_reply_alloc(void)
{
  scamper_ping_reply_t *reply = malloc_zero(sizeof(scamper_ping_reply_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(reply != NULL)
    reply->refcnt = 1;
#endif
  return reply;
}

void scamper_ping_reply_free(scamper_ping_reply_t *reply)
{
  if(reply == NULL)
    return;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--reply->refcnt > 0)
    return;
#endif

  if(reply->addr != NULL)
    scamper_addr_free(reply->addr);

  if(reply->v4rr != NULL)
    scamper_ping_reply_v4rr_free(reply->v4rr);

  if(reply->v4ts != NULL)
    scamper_ping_reply_v4ts_free(reply->v4ts);

  if(reply->tsreply != NULL)
    scamper_ping_reply_tsreply_free(reply->tsreply);

  if(reply->ifname != NULL)
    scamper_ifname_free(reply->ifname);

  free(reply);
  return;
}

scamper_ping_reply_t *scamper_ping_reply_dup(const scamper_ping_reply_t *in)
{
  scamper_ping_reply_t *out = NULL;

  if((out = memdup(in, sizeof(scamper_ping_reply_t))) == NULL)
    return NULL;

#ifdef BUILDING_LIBSCAMPERFILE
  out->refcnt  = 1;
#endif

  out->ifname  = NULL;
  out->v4rr    = NULL;
  out->v4ts    = NULL;
  out->tsreply = NULL;

  if(in->addr != NULL)
    out->addr = scamper_addr_use(in->addr);
  if(in->ifname != NULL)
    out->ifname = scamper_ifname_use(in->ifname);
  if(in->v4rr != NULL)
    out->v4rr = scamper_ping_reply_v4rr_dup(in->v4rr);

  return out;
}
