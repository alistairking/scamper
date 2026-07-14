/*
 * common_ping : common functions for unit testing ping
 *
 * $Id: common_ping.c,v 1.14 2026/07/11 03:49:51 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024-2026 Matthew Luckie
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
#include "scamper_ping.h"
#include "scamper_ping_int.h"
#include "scamper_ifname.h"
#include "scamper_ifname_int.h"
#include "common_ok.h"
#include "common_ping.h"
#include "utils.h"

typedef scamper_ping_t * (*scamper_ping_makefunc_t)(void);

static int stats_ok(const scamper_ping_stats_t *in,
		    const scamper_ping_stats_t *out)
{
  if(in == NULL || out == NULL)
    return -1;

  if(in->nreplies != out->nreplies ||
     in->ndups != out->ndups ||
     in->nloss != out->nloss ||
     in->nerrs != out->nerrs ||
     in->npend != out->npend ||
     timeval_cmp(&in->min_rtt, &out->min_rtt) != 0 ||
     timeval_cmp(&in->max_rtt, &out->max_rtt) != 0 ||
     timeval_cmp(&in->avg_rtt, &out->avg_rtt) != 0 ||
     timeval_cmp(&in->stddev_rtt, &out->stddev_rtt) != 0)
    return -1;

  return 0;
}

static int v4rr_ok(const scamper_ping_reply_v4rr_t *in,
		   const scamper_ping_reply_v4rr_t *out)
{
  uint8_t i;

  if(in == NULL && out == NULL)
    return 0;

  if((in != NULL && out == NULL) ||
     (in == NULL && out != NULL) ||
     in->ipc != out->ipc)
    return -1;

  for(i=0; i<in->ipc; i++)
    if(addr_ok(in->ip[i], out->ip[i]) != 0)
      return -1;

  return 0;
}

static scamper_ping_reply_t *reply_add(scamper_ping_probe_t *probe,
				       const char *addr, const char *rxif)
{
  scamper_ping_reply_t *reply = NULL;

  if((reply = scamper_ping_reply_alloc()) == NULL ||
     (addr != NULL &&
      (reply->addr = scamper_addr_fromstr(AF_UNSPEC, addr)) == NULL) ||
     (rxif != NULL &&
      (reply->ifname = scamper_ifname_alloc(rxif)) == NULL) ||
     scamper_ping_probe_reply_append(probe, reply) != 0)
    goto err;

  return reply;

 err:
  if(reply != NULL) scamper_ping_reply_free(reply);
  return NULL;
}

static int ping_reply_ok(const scamper_ping_reply_t *in,
			 const scamper_ping_reply_t *out)
{
  if(in == NULL && out == NULL)
    return 0;

  if((in != NULL && out == NULL) ||
     (in == NULL && out != NULL) ||
     addr_ok(in->addr, out->addr) != 0 ||
     in->proto != out->proto ||
     in->ttl != out->ttl ||
     in->tos != out->tos ||
     in->size != out->size ||
     in->ipid32 != out->ipid32 ||
     in->flags != out->flags ||
     in->icmp_type != out->icmp_type ||
     in->icmp_code != out->icmp_code ||
     in->tcp_flags != out->tcp_flags ||
     timeval_cmp(&in->rtt, &out->rtt) != 0 ||
     ifname_ok(in->ifname, out->ifname) != 0 ||
     v4rr_ok(in->v4rr, out->v4rr) != 0)
    return -1;

  return 0;
}

static int ping_probe_ok(const scamper_ping_probe_t *in,
			 const scamper_ping_probe_t *out)
{
  uint16_t i;

  if(in == NULL && out == NULL)
    return 0;

  /*
   * when reading through warts, details for probes with no replies
   * are not stored.
   */
  if(in != NULL && out == NULL)
    {
      if(in->replyc != 0)
	return -1;
      return 0;
    }

  if((in == NULL && out != NULL) ||
     timeval_cmp(&in->tx, &out->tx) != 0 ||
     in->id != out->id ||
     in->ipid != out->ipid ||
     in->sport != out->sport ||
     in->flags != out->flags ||
     in->replyc != out->replyc)
    return -1;

  for(i=0; i<in->replyc; i++)
    if(ping_reply_ok(in->replies[i], out->replies[i]) != 0)
      return -1;

  return 0;
}

int ping_ok(const scamper_ping_t *in, const scamper_ping_t *out)
{
  scamper_ping_stats_t *in_stats = NULL, *out_stats = NULL;
  uint16_t i;
  int rc = -1;

  assert(in != NULL);
  if(out == NULL ||
     addr_ok(in->src, out->src) != 0 ||
     addr_ok(in->dst, out->dst) != 0 ||
     addr_ok(in->rtr, out->rtr) != 0 ||
     in->userid != out->userid ||
     timeval_cmp(&in->start, &out->start) != 0 ||
     in->stop_reason != out->stop_reason ||
     in->stop_data != out->stop_data ||
     str_ok(in->errmsg, out->errmsg) != 0 ||
     timeval_cmp(&in->wait_probe, &out->wait_probe) != 0 ||
     timeval_cmp(&in->wait_timeout, &out->wait_timeout) != 0 ||
     in->attempts != out->attempts ||
     in->size != out->size ||
     in->method != out->method ||
     in->ttl != out->ttl ||
     in->tos != out->tos ||
     in->sport != out->sport ||
     in->dport != out->dport ||
     in->icmpsum != out->icmpsum ||
     in->tcpseq != out->tcpseq ||
     in->tcpack != out->tcpack ||
     in->stop_count != out->stop_count ||
     in->pmtu != out->pmtu ||
     in->flags != out->flags ||
     in->ping_sent != out->ping_sent)
    goto done;

  for(i=0; i<in->ping_sent; i++)
    if(ping_probe_ok(in->probes[i], out->probes[i]) != 0)
      goto done;

  in_stats = scamper_ping_stats_alloc(in);
  out_stats = scamper_ping_stats_alloc(out);
  if(stats_ok(in_stats, out_stats) != 0)
    goto done;

  rc = 0;

 done:
  if(in_stats != NULL) scamper_ping_stats_free(in_stats);
  if(out_stats != NULL) scamper_ping_stats_free(out_stats);
  return rc;
}

static scamper_ping_t *ping_1(void)
{
  scamper_ping_t *ping = NULL;
  scamper_ping_probe_t *probe;
  scamper_ping_reply_t *reply;
  uint8_t pd[] = {0xAA, 0xBB, 0xCC, 0xDD};

  if((ping = scamper_ping_alloc()) == NULL ||
     (ping->src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (ping->dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL ||
     (ping->rtr = scamper_addr_fromstr_ipv6("2001:db8::3")) == NULL ||
     (ping->data = memdup(pd, sizeof(pd))) == NULL ||
     (ping->probes = malloc_zero(sizeof(void *) * 4)) == NULL)
    goto err;

  ping->userid               = 123456;
  ping->start.tv_sec         = 1724828853;
  ping->start.tv_usec        = 123456;
  ping->stop_reason          = SCAMPER_PING_STOP_COMPLETED;
  ping->datalen              = sizeof(pd);
  ping->wait_probe.tv_sec    = 1;
  ping->wait_probe.tv_usec   = 0;
  ping->wait_timeout.tv_sec  = 5;
  ping->wait_timeout.tv_usec = 0;
  ping->attempts             = 4;
  ping->size                 = 1400;
  ping->method               = SCAMPER_PING_METHOD_ICMP_ECHO;
  ping->ttl                  = 64;
  ping->tos                  = 0;
  ping->sport                = 0x1234;
  ping->dport                = 5;
  ping->flags               |= SCAMPER_PING_FLAG_ICMPSUM;
  ping->flags               |= SCAMPER_PING_FLAG_TBT;
  ping->icmpsum              = 32;
  ping->stop_count           = 1;
  ping->pmtu                 = 1280;
  ping->ping_sent            = 4;

  if((ping->probes[3] = probe = scamper_ping_probe_alloc()) == NULL ||
     (reply = reply_add(probe, "2001:db8::2", "em0")) == NULL)
    goto err;
  probe->id          = 3;
  probe->tx.tv_sec   = 1724828853;
  probe->tx.tv_usec  = 123567;
  probe->sport       = 0x7654;
  probe->flags       = SCAMPER_PING_REPLY_FLAG_DLTX;
  reply->proto       = IPPROTO_ICMPV6;
  reply->tos         = 0x1f;
  reply->size        = 1280;
  reply->icmp_type   = ICMP6_ECHO_REPLY;
  reply->ttl         = 187;
  reply->rtt.tv_sec  = 0;
  reply->rtt.tv_usec = 1423;
  reply->flags       = (SCAMPER_PING_REPLY_FLAG_REPLY_TOS |
			SCAMPER_PING_REPLY_FLAG_REPLY_TTL |
			SCAMPER_PING_REPLY_FLAG_REPLY_IPID |
			SCAMPER_PING_REPLY_FLAG_DLTX |
			SCAMPER_PING_REPLY_FLAG_DLRX);
  reply->ipid32      = 0x12345678;

  return ping;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  return NULL;
}

static scamper_ping_t *ping_2(void)
{
  scamper_ping_t *ping = NULL;
  scamper_ping_probe_t *probe;
  scamper_ping_reply_t *reply;

  if((ping = scamper_ping_alloc()) == NULL ||
     (ping->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (ping->dst = scamper_addr_fromstr_ipv4("192.0.30.64")) == NULL ||
     (ping->probes = malloc_zero(sizeof(void *) * 1)) == NULL)
    goto err;

  ping->userid               = 123457;
  ping->start.tv_sec         = 1724828854;
  ping->start.tv_usec        = 234567;
  ping->stop_reason          = SCAMPER_PING_STOP_COMPLETED;
  ping->wait_probe.tv_sec    = 1;
  ping->wait_probe.tv_usec   = 0;
  ping->wait_timeout.tv_sec  = 5;
  ping->wait_timeout.tv_usec = 0;
  ping->attempts             = 4;
  ping->size                 = 192;
  ping->method               = SCAMPER_PING_METHOD_ICMP_ECHO;
  ping->ttl                  = 64;
  ping->tos                  = 0;
  ping->sport                = 0x1234;
  ping->dport                = 5;
  ping->flags               |= SCAMPER_PING_FLAG_ICMPSUM;
  ping->icmpsum              = 32;
  ping->stop_count           = 1;
  ping->ping_sent            = 1;

  if((ping->probes[0] = probe = scamper_ping_probe_alloc()) == NULL ||
     (reply = reply_add(probe, "192.0.30.64", "em0")) == NULL ||
     (reply->v4rr = scamper_ping_reply_v4rr_alloc(5)) == NULL ||
     (reply->v4rr->ip[0] = scamper_addr_fromstr_ipv4("192.0.31.4")) == NULL ||
     (reply->v4rr->ip[1] = scamper_addr_fromstr_ipv4("192.0.31.8")) == NULL ||
     (reply->v4rr->ip[2] = scamper_addr_fromstr_ipv4("192.0.31.12")) == NULL ||
     (reply->v4rr->ip[3] = scamper_addr_fromstr_ipv4("192.0.31.16")) == NULL ||
     (reply->v4rr->ip[4] = scamper_addr_fromstr_ipv4("192.0.31.20")) == NULL)
    goto err;
  probe->id          = 0;
  probe->flags       = (SCAMPER_PING_REPLY_FLAG_PROBE_IPID |
			SCAMPER_PING_REPLY_FLAG_DLTX);
  probe->ipid        = 0xaabb;
  probe->tx.tv_sec   = 1724828854;
  probe->tx.tv_usec  = 234789;
  probe->sport       = 0x4321;

  reply->flags       = (SCAMPER_PING_REPLY_FLAG_PROBE_IPID |
			SCAMPER_PING_REPLY_FLAG_REPLY_TOS |
			SCAMPER_PING_REPLY_FLAG_REPLY_TTL |
			SCAMPER_PING_REPLY_FLAG_REPLY_IPID |
			SCAMPER_PING_REPLY_FLAG_DLTX |
			SCAMPER_PING_REPLY_FLAG_DLRX);
  reply->proto       = IPPROTO_ICMP;
  reply->tos         = 1;
  reply->size        = 192;
  reply->ipid32      = 0xbbaa;
  reply->icmp_type   = ICMP_ECHOREPLY;
  reply->rtt.tv_sec  = 0;
  reply->rtt.tv_usec = 4242;

  return ping;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  return NULL;
}

static scamper_ping_t *ping_3(void)
{
  scamper_ping_t *ping = NULL;

  if((ping = scamper_ping_alloc()) == NULL ||
     (ping->src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (ping->dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL ||
     (ping->errmsg = strdup("hello world")) == NULL)
    goto err;

  ping->userid               = 123458;
  ping->start.tv_sec         = 1724828855;
  ping->start.tv_usec        = 123457;
  ping->stop_reason          = SCAMPER_PING_STOP_ERROR;
  ping->wait_probe.tv_sec    = 1;
  ping->wait_probe.tv_usec   = 0;
  ping->wait_timeout.tv_sec  = 5;
  ping->wait_timeout.tv_usec = 0;
  ping->attempts             = 4;
  ping->size                 = 1400;
  ping->method               = SCAMPER_PING_METHOD_ICMP_ECHO;
  ping->ttl                  = 64;
  ping->tos                  = 0;
  ping->sport                = 0x1234;
  ping->dport                = 5;
  ping->flags               |= SCAMPER_PING_FLAG_ICMPSUM;
  ping->icmpsum              = 32;
  ping->stop_count           = 1;
  ping->ping_sent            = 0;

  return ping;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  return NULL;
}

static scamper_ping_t *ping_4(void)
{
  scamper_ping_t *ping = NULL;
  scamper_ping_probe_t *probe;
  uint8_t pd[] = {0xDD, 0xBB, 0xCC, 0xAA};
  int i;

  if((ping = scamper_ping_alloc()) == NULL ||
     (ping->src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (ping->dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL ||
     (ping->data = memdup(pd, sizeof(pd))) == NULL ||
     (ping->probes = malloc_zero(sizeof(void *) * 4)) == NULL)
    goto err;

  ping->userid               = 123459;
  ping->start.tv_sec         = 1724828856;
  ping->start.tv_usec        = 123459;
  ping->stop_reason          = SCAMPER_PING_STOP_COMPLETED;
  ping->datalen              = sizeof(pd);
  ping->wait_probe.tv_sec    = 1;
  ping->wait_probe.tv_usec   = 0;
  ping->wait_timeout.tv_sec  = 5;
  ping->wait_timeout.tv_usec = 0;
  ping->attempts             = 4;
  ping->size                 = 1400;
  ping->method               = SCAMPER_PING_METHOD_ICMP_ECHO;
  ping->ttl                  = 64;
  ping->tos                  = 0;
  ping->sport                = 0x1234;
  ping->dport                = 5;
  ping->flags               |= SCAMPER_PING_FLAG_ICMPSUM;
  ping->flags               |= SCAMPER_PING_FLAG_TBT;
  ping->icmpsum              = 32;
  ping->stop_count           = 1;
  ping->pmtu                 = 1280;
  ping->ping_sent            = 4;

  for(i=0; i<4; i++)
    {
      if((ping->probes[i] = probe = scamper_ping_probe_alloc()) == NULL)
	goto err;
      probe->id          = i;
      probe->tx.tv_sec   = 1724828853 + i;
      probe->tx.tv_usec  = 123567;
      probe->sport       = 0x7654 + i;
      probe->flags       = SCAMPER_PING_REPLY_FLAG_DLTX;
    }

  return ping;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  return NULL;
}

static scamper_ping_t *ping_5(void)
{
  scamper_ping_t *ping = NULL;
  scamper_ping_probe_t *probe;
  scamper_ping_reply_t *reply;
  uint8_t pd[] = {0x35, 0x26, 0x67, 0x92};
  int i;

  if((ping = scamper_ping_alloc()) == NULL ||
     (ping->src = scamper_addr_fromstr_ipv4("192.0.2.5")) == NULL ||
     (ping->dst = scamper_addr_fromstr_ipv4("192.0.30.46")) == NULL ||
     (ping->data = memdup(pd, sizeof(pd))) == NULL ||
     (ping->probes = malloc_zero(sizeof(void *) * 4)) == NULL)
    goto err;

  ping->userid               = 654321;
  ping->start.tv_sec         = 1724828857;
  ping->start.tv_usec        = 356267;
  ping->stop_reason          = SCAMPER_PING_STOP_COMPLETED;
  ping->datalen              = sizeof(pd);
  ping->wait_probe.tv_sec    = 1;
  ping->wait_probe.tv_usec   = 0;
  ping->wait_timeout.tv_sec  = 5;
  ping->wait_timeout.tv_usec = 0;
  ping->attempts             = 4;
  ping->size                 = 20 + 8 + 4;
  ping->method               = SCAMPER_PING_METHOD_UDP_SPORT;
  ping->ttl                  = 255;
  ping->tos                  = 32;
  ping->sport                = 53235;
  ping->dport                = 32768+666+1;
  ping->ping_sent            = 4;

  for(i=0; i<4; i++)
    {
      if((ping->probes[i] = probe = scamper_ping_probe_alloc()) == NULL ||
	 (reply = reply_add(probe, "192.0.30.46", NULL)) == NULL)
	goto err;
      probe->id          = i;
      probe->tx.tv_sec   = ping->start.tv_sec + i;
      probe->tx.tv_usec  = ping->start.tv_usec;
      probe->sport       = ping->sport + i;
      reply->proto       = IPPROTO_ICMP;
      reply->tos         = 0;
      reply->size        = 20 + 8 + 20 + 8;
      reply->icmp_type   = ICMP_UNREACH;
      reply->icmp_code   = ICMP_UNREACH_PORT;
      reply->ttl         = 187;
      reply->rtt.tv_sec  = 0;
      reply->rtt.tv_usec = 1423 + i;
      reply->flags       = (SCAMPER_PING_REPLY_FLAG_REPLY_TOS |
			    SCAMPER_PING_REPLY_FLAG_REPLY_TTL |
			    SCAMPER_PING_REPLY_FLAG_REPLY_IPID);
      reply->ipid32      = 0x5678 + i;
    }

  return ping;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  return NULL;
}

static scamper_ping_t *ping_6(void)
{
  scamper_ping_t *ping = NULL;
  scamper_ping_probe_t *probe;
  scamper_ping_reply_t *reply;
  int i;

  if((ping = scamper_ping_alloc()) == NULL ||
     (ping->src = scamper_addr_fromstr_ipv4("192.0.2.5")) == NULL ||
     (ping->dst = scamper_addr_fromstr_ipv4("192.0.30.46")) == NULL ||
     (ping->probes = malloc_zero(sizeof(void *) * 4)) == NULL)
    goto err;

  ping->userid               = 827659;
  ping->start.tv_sec         = 1724828858;
  ping->start.tv_usec        = 976305;
  ping->stop_reason          = SCAMPER_PING_STOP_COMPLETED;
  ping->datalen              = 0;
  ping->wait_probe.tv_sec    = 1;
  ping->wait_probe.tv_usec   = 0;
  ping->wait_timeout.tv_sec  = 5;
  ping->wait_timeout.tv_usec = 0;
  ping->attempts             = 4;
  ping->size                 = 20 + 8 + 4;
  ping->method               = SCAMPER_PING_METHOD_TCP_SYN_SPORT;
  ping->ttl                  = 255;
  ping->tos                  = 32;
  ping->sport                = 62348;
  ping->dport                = 443;
  ping->ping_sent            = 4;
  ping->tcpmss               = 1460;
  ping->tcpseq               = 0x89281893;

  for(i=0; i<4; i++)
    {
      if((ping->probes[i] = probe = scamper_ping_probe_alloc()) == NULL ||
	 (reply = reply_add(probe, "192.0.30.46", NULL)) == NULL)
	goto err;
      probe->id          = i;
      probe->tx.tv_sec   = ping->start.tv_sec + i;
      probe->tx.tv_usec  = ping->start.tv_usec;
      probe->sport       = ping->sport + i;
      reply->proto       = IPPROTO_TCP;
      reply->tcp_mss     = 1460;
      reply->tcp_flags   = TH_SYN | TH_ACK;
      reply->tos         = 0;
      reply->size        = 20 + 20;
      reply->ttl         = 251;
      reply->rtt.tv_sec  = 0;
      reply->rtt.tv_usec = 7614 + i;
      reply->flags       = (SCAMPER_PING_REPLY_FLAG_REPLY_TOS |
			    SCAMPER_PING_REPLY_FLAG_REPLY_TTL |
			    SCAMPER_PING_REPLY_FLAG_REPLY_IPID);
      reply->ipid32      = 0x8765 + i;
    }

  return ping;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  return NULL;
}

static scamper_ping_t *ping_7(void)
{
  scamper_ping_t *ping = NULL;
  scamper_ping_probe_t *probe;
  scamper_ping_reply_t *reply;
  uint16_t i, j;

  if((ping = ping_6()) == NULL)
    return NULL;

  for(i=0; i<ping->ping_sent; i++)
    {
      if((probe = ping->probes[i]) == NULL ||
	 probe->replyc == 0 || probe->replies == NULL)
	continue;
      for(j=0; j<probe->replyc; j++)
	{
	  if((reply = probe->replies[j]) == NULL)
	    continue;
	  reply->flags = reply->flags & ~(SCAMPER_PING_REPLY_FLAG_REPLY_TOS |
					  SCAMPER_PING_REPLY_FLAG_REPLY_TTL |
					  SCAMPER_PING_REPLY_FLAG_REPLY_IPID);
	  reply->ipid32 = 0;
	  reply->tos = 0;
	  reply->ttl = 0;
	}
    }

  return ping;
}  

static scamper_ping_t *ping_8(void)
{
  scamper_ping_t *ping = NULL;
  scamper_ping_probe_t *probe;
  scamper_ping_reply_t *reply;

  if((ping = scamper_ping_alloc()) == NULL ||
     (ping->src = scamper_addr_fromstr_ipv4("192.0.2.7")) == NULL ||
     (ping->dst = scamper_addr_fromstr_ipv4("192.0.30.32")) == NULL ||
     (ping->probes = malloc_zero(sizeof(void *) * 1)) == NULL ||
     (ping->probes[0] = probe = scamper_ping_probe_alloc()) == NULL ||
     (reply = reply_add(probe, "192.0.30.46", NULL)) == NULL)
    goto err;

  ping->userid               = 235106;
  ping->start.tv_sec         = 1724828859;
  ping->start.tv_usec        = 835622;
  ping->stop_reason          = SCAMPER_PING_STOP_COMPLETED;
  ping->wait_probe.tv_sec    = 1;
  ping->wait_probe.tv_usec   = 0;
  ping->wait_timeout.tv_sec  = 5;
  ping->wait_timeout.tv_usec = 0;
  ping->attempts             = 4;
  ping->size                 = 1500;
  ping->method               = SCAMPER_PING_METHOD_ICMP_ECHO;
  ping->ttl                  = 255;
  ping->sport                = 0x4321;
  ping->flags               |= SCAMPER_PING_FLAG_ICMPSUM;
  ping->icmpsum              = 64;
  ping->ping_sent            = 1;

  probe->tx.tv_sec   = ping->start.tv_sec;
  probe->tx.tv_usec  = ping->start.tv_usec;
  reply->proto       = IPPROTO_ICMP;
  reply->tos         = 0;
  reply->size        = 20 + 8 + 20 + 8;
  reply->icmp_type   = ICMP_UNREACH;
  reply->icmp_code   = ICMP_UNREACH_NEEDFRAG;
  reply->ttl         = 187;
  reply->rtt.tv_sec  = 0;
  reply->rtt.tv_usec = 150283;
  reply->flags       = (SCAMPER_PING_REPLY_FLAG_REPLY_TOS |
			SCAMPER_PING_REPLY_FLAG_REPLY_TTL |
			SCAMPER_PING_REPLY_FLAG_REPLY_IPID);
  reply->ipid32      = 0x3265;
  reply->icmp_nhmtu  = 1280;

  return ping;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  return NULL;
}

static scamper_ping_makefunc_t makers[] = {
  ping_1,
  ping_2,
  ping_3,
  ping_4,
  ping_5,
  ping_6,
  ping_7,
  ping_8,
};

scamper_ping_t *ping_makers(size_t i)
{
  if(i >= sizeof(makers) / sizeof(scamper_ping_makefunc_t))
    return NULL;
  return makers[i]();
}

size_t ping_makerc(void)
{
  return sizeof(makers) / sizeof(scamper_ping_makefunc_t);
}
