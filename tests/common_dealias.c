/*
 * common_dealias : common functions for unit testing dealias
 *
 * $Id: common_dealias.c,v 1.3 2025/05/05 05:20:20 mjl Exp $
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
#include "scamper_addr_int.h"
#include "scamper_file.h"
#include "scamper_icmpext.h"
#include "scamper_dealias.h"
#include "scamper_dealias_int.h"
#include "common_ok.h"
#include "common_dealias.h"
#include "utils.h"

typedef scamper_dealias_t * (*scamper_dealias_makefunc_t)(void);

static int dealias_reply_ok(const scamper_dealias_reply_t *in,
			    const scamper_dealias_reply_t *out)
{
  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(addr_ok(in->src, out->src) != 0 ||
     timeval_cmp(&in->rx, &out->rx) != 0 ||
     in->flags != out->flags ||
     in->proto != out->proto ||
     in->ttl != out->ttl ||
     in->icmp_type != out->icmp_type ||
     in->icmp_code != out->icmp_code ||
     in->icmp_q_ttl != out->icmp_q_ttl ||
     in->tcp_flags != out->tcp_flags ||
     in->size != out->size ||
     in->ipid != out->ipid ||
     in->ipid32 != out->ipid32 ||
     icmpexts_ok(in->icmp_exts, out->icmp_exts) != 0)
    return -1;

  return 0;
}

static int dealias_probe_ok(const scamper_dealias_probe_t *in,
			    const scamper_dealias_probe_t *out)
{
  uint16_t i;

  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(in->seq != out->seq ||
     timeval_cmp(&in->tx, &out->tx) != 0 ||
     ptr_ok(in->replies, out->replies) != 0 ||
     in->replyc != out->replyc ||
     in->ipid != out->ipid)
    return -1;

  for(i=0; i<in->replyc; i++)
    if(dealias_reply_ok(in->replies[i], out->replies[i]) != 0)
      return -1;

  return 0;
}

static int dealias_probedef_ok(const scamper_dealias_probedef_t *in,
			       const scamper_dealias_probedef_t *out)
{
  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(addr_ok(in->src, out->src) != 0 ||
     addr_ok(in->dst, out->dst) != 0 ||
     in->id != out->id ||
     in->method != out->method ||
     in->ttl != out->ttl ||
     in->tos != out->tos ||
     in->size != out->size ||
     in->mtu != out->mtu ||
     (SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(in) &&
      (in->un.udp.sport != out->un.udp.sport ||
       in->un.udp.dport != out->un.udp.dport)) ||
     (SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(in) &&
      (in->un.tcp.sport != out->un.tcp.sport ||
       in->un.tcp.dport != out->un.tcp.dport ||
       in->un.tcp.flags != out->un.tcp.flags)) ||
     (SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(in) &&
      (in->un.icmp.csum != out->un.icmp.csum ||
       in->un.icmp.id   != out->un.icmp.id)))
    return -1;

  return 0;
}

static int dealias_radargun_ok(const scamper_dealias_radargun_t *in,
			       const scamper_dealias_radargun_t *out)
{
  uint32_t i;

  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(in->probedefc != out->probedefc ||
     in->rounds != out->rounds ||
     in->flags != out->flags ||
     timeval_cmp(&in->wait_probe, &out->wait_probe) != 0 ||
     timeval_cmp(&in->wait_round, &out->wait_round) != 0 ||
     timeval_cmp(&in->wait_timeout, &out->wait_timeout) != 0)
    return -1;

  for(i=0; i<in->probedefc; i++)
    if(dealias_probedef_ok(in->probedefs[i], out->probedefs[i]) != 0)
      return -1;

  return 0;
}

static int dealias_ally_ok(const scamper_dealias_ally_t *in,
			   const scamper_dealias_ally_t *out)
{
  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(dealias_probedef_ok(in->probedefs[0], out->probedefs[0]) != 0 ||
     dealias_probedef_ok(in->probedefs[1], out->probedefs[1]) != 0 ||
     timeval_cmp(&in->wait_probe, &out->wait_probe) != 0 ||
     timeval_cmp(&in->wait_timeout, &out->wait_timeout) != 0 ||
     in->attempts != out->attempts ||
     in->flags != out->flags ||
     in->fudge != out->fudge)
    return -1;

  return 0;
}

static int dealias_mercator_ok(const scamper_dealias_mercator_t *in,
			       const scamper_dealias_mercator_t *out)
{
  if(ptr_ok(in, out) != 0)
    return -1;
  if(in == NULL)
    return 0;

  if(dealias_probedef_ok(in->probedef, out->probedef) != 0 ||
     in->attempts != out->attempts ||
     timeval_cmp(&in->wait_timeout, &out->wait_timeout) != 0)
    return -1;

  return 0;
}

int dealias_ok(const scamper_dealias_t *in, const scamper_dealias_t *out)
{
  uint32_t i;

  assert(in != NULL);

  if(out == NULL ||
     in->userid != out->userid ||
     timeval_cmp(&in->start, &out->start) != 0 ||
     in->method != out->method ||
     in->result != out->result ||
     ptr_ok(in->data, out->data) != 0 ||
     ptr_ok(in->probes, out->probes) != 0 ||
     in->probec != out->probec)
    return -1;

  for(i=0; i<in->probec; i++)
    if(dealias_probe_ok(in->probes[i], out->probes[i]) != 0)
      return -1;

  if((in->method == SCAMPER_DEALIAS_METHOD_MERCATOR &&
      dealias_mercator_ok(in->data, out->data) != 0) ||
     (in->method == SCAMPER_DEALIAS_METHOD_ALLY &&
      dealias_ally_ok(in->data, out->data) != 0) ||
     (in->method == SCAMPER_DEALIAS_METHOD_RADARGUN &&
      dealias_radargun_ok(in->data, out->data) != 0))
    return -1;

  return 0;
}

static scamper_dealias_probedef_t *probedef_alloc(const char *src,
						  const char *dst, uint32_t id,
						  uint8_t method, uint8_t ttl,
						  uint16_t size)
{
  scamper_dealias_probedef_t *pd = NULL;

  if((pd = scamper_dealias_probedef_alloc()) == NULL ||
     (pd->src = scamper_addr_fromstr(AF_UNSPEC, src)) == NULL ||
     (pd->dst = scamper_addr_fromstr(AF_UNSPEC, dst)) == NULL)
    goto err;
  pd->id = id;
  pd->method = method;
  pd->ttl = ttl;
  pd->size = size;
  return pd;

 err:
  if(pd != NULL) scamper_dealias_probedef_free(pd);
  return NULL;
}

static scamper_dealias_probe_t *probe_add(scamper_dealias_t *dealias,
					  scamper_dealias_probedef_t *def,
					  uint32_t seq, time_t tx_sec,
					  suseconds_t tx_usec, uint16_t ipid)
{
  scamper_dealias_probe_t *probe;

  if((probe = scamper_dealias_probe_alloc()) == NULL)
    return NULL;

  probe->def = def;
  probe->seq = seq;
  probe->tx.tv_sec = tx_sec;
  probe->tx.tv_usec = tx_usec;
  probe->ipid = ipid;
  dealias->probes[dealias->probec++] = probe;

  return probe;
}

static scamper_dealias_reply_t *reply_add(scamper_dealias_probe_t *probe,
					  const char *src, time_t rx_sec,
					  suseconds_t rx_usec, uint8_t proto,
					  uint8_t ttl, uint32_t ipid)
{
  scamper_dealias_reply_t *reply = NULL;

  if((reply = scamper_dealias_reply_alloc()) == NULL ||
     (reply->src = scamper_addr_fromstr(AF_UNSPEC, src)) == NULL)
    goto err;

  reply->rx.tv_sec = rx_sec;
  reply->rx.tv_usec = rx_usec;
  reply->proto = proto;
  reply->ttl = ttl;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(reply->src))
    reply->ipid = ipid;
  else
    reply->ipid32 = ipid;

  probe->replies[probe->replyc++] = reply;
  return reply;

 err:
  if(reply != NULL) scamper_dealias_reply_free(reply);
  return NULL;
}

static scamper_dealias_mercator_t *mercator_add(scamper_dealias_t *dealias)
{
  if((dealias->data = scamper_dealias_mercator_alloc()) == NULL)
    return NULL;
  dealias->method = SCAMPER_DEALIAS_METHOD_MERCATOR;
  return dealias->data;
}

static scamper_dealias_ally_t *ally_add(scamper_dealias_t *dealias)
{
  if((dealias->data = scamper_dealias_ally_alloc()) == NULL)
    return NULL;
  dealias->method = SCAMPER_DEALIAS_METHOD_ALLY;
  return dealias->data;
}

static scamper_dealias_radargun_t *radargun_add(scamper_dealias_t *dealias)
{
  if((dealias->data = scamper_dealias_radargun_alloc()) == NULL)
    return NULL;
  dealias->method = SCAMPER_DEALIAS_METHOD_RADARGUN;
  return dealias->data;
}

static scamper_dealias_t *dealias_1(void)
{
  scamper_dealias_t *dealias = NULL;
  scamper_dealias_mercator_t *mc;
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply;

  if((dealias = scamper_dealias_alloc()) == NULL ||
     (mc = mercator_add(dealias)) == NULL ||
     (mc->probedef = probedef_alloc("192.0.2.1", "192.0.2.2", 0,
				    SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP,
				    255, 72)) == NULL ||
     scamper_dealias_probes_alloc(dealias, 1) != 0 ||
     (probe = probe_add(dealias, mc->probedef, 0, 1724828853, 125828,
			0xabab)) == NULL ||
     scamper_dealias_replies_alloc(probe, 1) != 0 ||
     (reply = reply_add(probe, "192.0.2.3", 1724828853, 148760,
			IPPROTO_ICMP, 255, 0x9876)) == NULL)
    goto err;

  dealias->userid = 1234567890;
  dealias->start.tv_sec = 1724828853;
  dealias->start.tv_usec = 123456;
  dealias->result = SCAMPER_DEALIAS_RESULT_ALIASES;

  mc->probedef->un.udp.sport = 35216;
  mc->probedef->un.udp.dport = 34345;
  mc->attempts = 2;
  mc->wait_timeout.tv_sec = 1;

  reply->icmp_type = ICMP_UNREACH;
  reply->icmp_code = ICMP_UNREACH_PORT;
  reply->icmp_q_ttl = 254;

  return dealias;

 err:
  if(dealias != NULL) scamper_dealias_free(dealias);
  return NULL;
}

static scamper_dealias_t *dealias_2(void)
{
  scamper_dealias_t *dealias = NULL;
  scamper_dealias_ally_t *ally;
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply;
  int i;

  if((dealias = scamper_dealias_alloc()) == NULL ||
     (ally = ally_add(dealias)) == NULL ||
     (ally->probedefs[0] =
      probedef_alloc("192.0.2.1", "192.0.2.2", 0,
		     SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO,
		     255, 44)) == NULL ||
     (ally->probedefs[1] =
      probedef_alloc("192.0.2.1", "192.0.2.4", 0,
		     SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO,
		     255, 44)) == NULL ||
     scamper_dealias_probes_alloc(dealias, 5) != 0 ||
     /* first probe / response */
     (probe = probe_add(dealias, ally->probedefs[0], 0, 1724828853, 125828,
			0xafaf)) == NULL ||
     scamper_dealias_replies_alloc(probe, 1) != 0 ||
     reply_add(probe, "192.0.2.2", 1724828853, 148760,
	       IPPROTO_ICMP, 255, 0x9876) == NULL ||
     /* second probe / response */
     (probe = probe_add(dealias, ally->probedefs[1], 0, 1724828853, 725828,
			0xaeae)) == NULL ||
     scamper_dealias_replies_alloc(probe, 1) != 0 ||
     reply_add(probe, "192.0.2.4", 1724828853, 748760,
	       IPPROTO_ICMP, 255, 0x9877) == NULL ||
     /* third probe / response */
     (probe = probe_add(dealias, ally->probedefs[0], 1, 1724828854, 325828,
			0xafaf)) == NULL ||
     scamper_dealias_replies_alloc(probe, 1) != 0 ||
     reply_add(probe, "192.0.2.2", 1724828854, 348760,
	       IPPROTO_ICMP, 255, 0x9878) == NULL ||
     /* fourth probe / response */
     (probe = probe_add(dealias, ally->probedefs[1], 1, 1724828854, 925828,
			0xaeae)) == NULL ||
     scamper_dealias_replies_alloc(probe, 1) != 0 ||
     reply_add(probe, "192.0.2.4", 1724828854, 948760,
	       IPPROTO_ICMP, 255, 0x9879) == NULL ||
     /* fifth probe / response */
     (probe = probe_add(dealias, ally->probedefs[0], 2, 1724828855, 525828,
			0xafaf)) == NULL ||
     scamper_dealias_replies_alloc(probe, 1) != 0 ||
     reply_add(probe, "192.0.2.2", 1724828855, 548760,
	       IPPROTO_ICMP, 255, 0x9880) == NULL)
    goto err;

  dealias->userid = 1234567890;
  dealias->start.tv_sec = 1724828853;
  dealias->start.tv_usec = 123456;
  dealias->result = SCAMPER_DEALIAS_RESULT_ALIASES;
  for(i=0; i<5; i++)
    {
      reply = dealias->probes[i]->replies[0];
      reply->icmp_type = ICMP_ECHOREPLY;
    }

  ally->wait_probe.tv_sec = 0;
  ally->wait_probe.tv_usec = 600000;
  ally->wait_timeout.tv_sec = 1;
  ally->wait_timeout.tv_usec = 0;
  ally->attempts = 5;
  ally->flags = SCAMPER_DEALIAS_ALLY_FLAG_NOBS;
  ally->fudge = 500;
  for(i=0; i<2; i++)
    {
      ally->probedefs[i]->un.icmp.csum = 0x420;
      ally->probedefs[i]->un.icmp.id   = 54321;
    }

  return dealias;

 err:
  if(dealias != NULL) scamper_dealias_free(dealias);
  return NULL;
}

static scamper_dealias_t *dealias_3(void)
{
  scamper_dealias_t *dealias = NULL;
  scamper_dealias_radargun_t *rg;
  int methods[3], sizes[3], i;
  char buf[32];

  if((dealias = scamper_dealias_alloc()) == NULL ||
     (rg = radargun_add(dealias)) == NULL ||
     scamper_dealias_radargun_probedefs_alloc(rg, 10) != 0)
    goto err;

  dealias->userid = 1234567890;
  dealias->start.tv_sec = 1724828853;
  dealias->start.tv_usec = 123456;
  dealias->result = SCAMPER_DEALIAS_RESULT_NONE;

  methods[0] = SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO; sizes[0] = 60;
  methods[1] = SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK;   sizes[1] = 40;
  methods[2] = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;       sizes[2] = 50;

  rg->probedefc = 10;
  rg->rounds = 30;
  rg->wait_probe.tv_sec = 0;   rg->wait_probe.tv_usec = 100000;
  rg->wait_timeout.tv_sec = 1; rg->wait_timeout.tv_usec = 0;
  rg->wait_round.tv_sec = 3;   rg->wait_round.tv_usec = 0;
  for(i=0; i<10; i++)
    {
      snprintf(buf, sizeof(buf), "192.0.2.%d", i+10);
      if((rg->probedefs[i] =
	  probedef_alloc("192.0.2.5", buf, i, methods[i%3], 255-i,
			 sizes[i%3])) == NULL)
	goto err;
      
    }

  return dealias;

 err:
  if(dealias != NULL) scamper_dealias_free(dealias);
  return NULL;
}

static scamper_dealias_makefunc_t makers[] = {
  dealias_1,
  dealias_2,
  dealias_3,
};

scamper_dealias_t *dealias_makers(size_t i)
{
  if(i >= sizeof(makers) / sizeof(scamper_dealias_makefunc_t))
    return NULL;
  return makers[i]();
}

size_t dealias_makerc(void)
{
  return sizeof(makers) / sizeof(scamper_dealias_makefunc_t);
}
