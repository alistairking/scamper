/*
 * common_owamp : common functions for unit testing owamp
 *
 * $Id: common_owamp.c,v 1.1 2026/01/04 19:54:18 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2026 The Regents of the University of California
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
#include "scamper_owamp.h"
#include "scamper_owamp_int.h"
#include "common_ok.h"
#include "common_owamp.h"
#include "utils.h"

typedef scamper_owamp_t * (*scamper_owamp_makefunc_t)(void);

static int owamp_rx_ok(const scamper_owamp_rx_t *in,
		       const scamper_owamp_rx_t *out)
{
  if(in == NULL && out == NULL)
    return 0;

  if((in != NULL && out == NULL) ||
     (in == NULL && out != NULL) ||
     timeval_cmp(&in->stamp, &out->stamp) != 0 ||
     in->errest != out->errest ||
     in->flags != out->flags ||
     in->dscp != out->dscp ||
     in->ttl != out->ttl)
    return -1;

  return 0;
}

static int owamp_tx_ok(const scamper_owamp_tx_t *in,
		       const scamper_owamp_tx_t *out)
{
  uint8_t i;

  if(in == NULL && out == NULL)
    return 0;

  if((in != NULL && out == NULL) ||
     (in == NULL && out != NULL) ||
     in->seq != out->seq ||
     in->errest != out->errest ||
     in->flags != out->flags ||
     in->rxc != out->rxc)
    return -1;

  for(i=0; i<in->rxc; i++)
    if(owamp_rx_ok(in->rxs[i], out->rxs[i]) != 0)
      return -1;

  return 0;
}

static int owamp_sched_ok(const scamper_owamp_sched_t *in,
			  const scamper_owamp_sched_t *out)
{
  if(in == NULL && out == NULL)
    return 0;

  if((in != NULL && out == NULL) ||
     (in == NULL && out != NULL) ||
     timeval_cmp(&in->tv, &out->tv) != 0 ||
     in->type != out->type)
    return -1;

  return 0;
}

int owamp_ok(const scamper_owamp_t *in, const scamper_owamp_t *out)
{
  uint32_t i;

  assert(in != NULL);
  if(out == NULL ||
     addr_ok(in->src, out->src) != 0 ||
     addr_ok(in->dst, out->dst) != 0 ||
     in->userid != out->userid ||
     in->dport != out->dport ||
     in->flags != out->flags ||
     timeval_cmp(&in->start, &out->start) != 0 ||
     timeval_cmp(&in->startat, &out->startat) != 0 ||
     timeval_cmp(&in->wait_timeout, &out->wait_timeout) != 0 ||
     in->schedc != out->schedc ||
     in->attempts != out->attempts ||
     in->pktsize != out->pktsize ||
     in->dir != out->dir ||
     in->dscp != out->dscp ||
     in->ttl != out->ttl ||
     timeval_cmp(&in->hsrtt, &out->hsrtt) != 0 ||
     in->result != out->result ||
     str_ok(in->errmsg, out->errmsg) != 0 ||
     in->udp_sport != out->udp_sport ||
     in->udp_dport != out->udp_dport ||
     in->txc != out->txc)
    return -1;

  for(i=0; i<in->schedc; i++)
    if(owamp_sched_ok(in->sched[i], out->sched[i]) != 0)
      return -1;

  for(i=0; i<in->txc; i++)
    if(owamp_tx_ok(in->txs[i], out->txs[i]) != 0)
      return -1;

  return 0;
}

static int sched_add(scamper_owamp_t *owamp,
		     uint8_t type, time_t sec, suseconds_t usec)
{
  scamper_owamp_sched_t *sched = NULL;

  if((sched = scamper_owamp_sched_alloc()) == NULL)
    return -1;

  owamp->sched[owamp->schedc++] = sched;
  sched->type = type;
  sched->tv.tv_sec = sec;
  sched->tv.tv_usec = usec;

  return 0;
}

static scamper_owamp_tx_t *tx_add(scamper_owamp_t *owamp,
				  const struct timeval *ts, uint32_t sq)
{
  scamper_owamp_tx_t *tx = NULL;

  if((tx = scamper_owamp_tx_alloc()) == NULL)
    return NULL;

  owamp->txs[owamp->txc++] = tx;
  timeval_cpy(&tx->stamp, ts);
  tx->seq = sq;

  return tx;
}

static scamper_owamp_rx_t *rx_add(scamper_owamp_tx_t *tx)
{
  scamper_owamp_rx_t *rx = NULL;

  if((rx = scamper_owamp_rx_alloc()) == NULL ||
     scamper_owamp_tx_rxadd(tx, rx) != 0)
    goto err;

  return rx;

 err:
  if(rx != NULL) scamper_owamp_rx_free(rx);
  return NULL;
}

static scamper_owamp_t *owamp_1(void)
{
  scamper_owamp_t *owamp = NULL;

  if((owamp = scamper_owamp_alloc()) == NULL ||
     (owamp->src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (owamp->dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL ||
     scamper_owamp_scheds_alloc(owamp, 1) != 0 ||
     sched_add(owamp, SCAMPER_OWAMP_SCHED_TYPE_FIXED, 0, 100000) != 0)
    goto err;

  owamp->userid               = 123456;
  owamp->dport                = 861;
  owamp->start.tv_sec         = 1724828853;
  owamp->start.tv_usec        = 123456;
  owamp->startat.tv_sec       = 1724828854;
  owamp->startat.tv_usec      = 523652;
  owamp->wait_timeout.tv_sec  = 2;
  owamp->wait_timeout.tv_usec = 0;
  owamp->attempts             = 10;
  owamp->pktsize              = 40 + 8 + 14;
  owamp->dir                  = SCAMPER_OWAMP_DIR_TX;
  owamp->dscp                 = 0;
  owamp->ttl                  = 255;
  owamp->hsrtt.tv_sec         = 0;
  owamp->hsrtt.tv_usec        = 52396;

  return owamp;

 err:
  if(owamp != NULL) scamper_owamp_free(owamp);
  return NULL;
}

static scamper_owamp_t *owamp_2(void)
{
  scamper_owamp_t *owamp = NULL;
  struct timeval tv;
  uint32_t i;

  if((owamp = owamp_1()) == NULL ||
     scamper_owamp_txs_alloc(owamp, owamp->attempts) != 0)
    goto err;

  owamp->dir    = SCAMPER_OWAMP_DIR_RX;
  owamp->result = SCAMPER_OWAMP_RESULT_DONE;

  timeval_add_tv3(&tv, &owamp->startat, &owamp->sched[0]->tv);
  for(i=0; i<owamp->attempts; i++)
    {
      if(tx_add(owamp, &tv, i) == NULL)
	goto err;
      timeval_add_tv3(&tv, &tv, &owamp->sched[0]->tv);
    }

  return owamp;

 err:
  if(owamp != NULL) scamper_owamp_free(owamp);
  return NULL;
}

static scamper_owamp_t *owamp_3(void)
{
  scamper_owamp_t *owamp = NULL;
  scamper_owamp_rx_t *rx;
  uint32_t i;

  if((owamp = owamp_2()) == NULL)
    goto err;

  owamp->dscp = 55;

  for(i=0; i<owamp->attempts; i++)
    {
      if((rx = rx_add(owamp->txs[i])) == NULL)
	goto err;
      timeval_add_us(&rx->stamp, &owamp->txs[i]->stamp, 235260);
      rx->ttl = 243;
      rx->flags |= (SCAMPER_OWAMP_RX_FLAG_TTL | SCAMPER_OWAMP_RX_FLAG_DSCP);
    }

  return owamp;

 err:
  if(owamp != NULL) scamper_owamp_free(owamp);
  return NULL;
}

static scamper_owamp_makefunc_t makers[] = {
  owamp_1,
  owamp_2,
  owamp_3,
};

scamper_owamp_t *owamp_makers(size_t i)
{
  if(i >= sizeof(makers) / sizeof(scamper_owamp_makefunc_t))
    return NULL;
  return makers[i]();
}

size_t owamp_makerc(void)
{
  return sizeof(makers) / sizeof(scamper_owamp_makefunc_t);
}
