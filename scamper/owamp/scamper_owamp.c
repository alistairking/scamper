/*
 * scamper_owamp.c
 *
 * $Id: scamper_owamp.c,v 1.3 2026/01/04 19:43:21 mjl Exp $
 *
 * Copyright (C) 2025-2026 The Regents of the University of California
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
#include "scamper_owamp.h"
#include "scamper_owamp_int.h"
#include "utils.h"

int scamper_owamp_scheds_alloc(scamper_owamp_t *owamp, uint32_t c)
{
  size_t len = sizeof(scamper_owamp_sched_t *) * c;
  if((owamp->sched = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

int scamper_owamp_txs_alloc(scamper_owamp_t *owamp, uint32_t c)
{
  size_t len = sizeof(scamper_owamp_tx_t *) * c;
  if((owamp->txs = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

char *scamper_owamp_sched_type_tostr(const scamper_owamp_sched_t *sched,
				     char *buf, size_t len)
{
  static char *m[] = {
    "fixed",
    "exponential",
  };
  size_t off = 0;

  if(sched->type >= sizeof(m) / sizeof(char *))
    string_concat_u8(buf, len, &off, NULL, sched->type);
  else
    string_concat(buf, len, &off, m[sched->type]);

  return buf;
}

void scamper_owamp_sched_free(scamper_owamp_sched_t *sched)
{
#ifdef BUILDING_LIBSCAMPERFILE
  if(--sched->refcnt > 0)
    return;
#endif
  free(sched);
  return;
}

scamper_owamp_sched_t *scamper_owamp_sched_alloc(void)
{
  scamper_owamp_sched_t *sched = malloc_zero(sizeof(scamper_owamp_sched_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(sched != NULL)
    sched->refcnt = 1;
#endif
  return sched;
}

void scamper_owamp_rx_free(scamper_owamp_rx_t *rx)
{
#ifdef BUILDING_LIBSCAMPERFILE
  if(--rx->refcnt > 0)
    return;
#endif
  free(rx);
  return;
}

scamper_owamp_rx_t *scamper_owamp_rx_alloc(void)
{
  scamper_owamp_rx_t *rx = malloc_zero(sizeof(scamper_owamp_rx_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(rx != NULL)
    rx->refcnt = 1;
#endif
  return rx;
}

int scamper_owamp_tx_rxadd(scamper_owamp_tx_t *tx, scamper_owamp_rx_t *rx)
{
  size_t len;

  if(tx->rxc == 255)
    return -1;
  len = (tx->rxc + 1) * sizeof(scamper_owamp_rx_t *);
  if(realloc_wrap((void **)&tx->rxs, len) != 0)
    return -1;
  tx->rxs[tx->rxc++] = rx;
  return 0;
}

void scamper_owamp_tx_free(scamper_owamp_tx_t *tx)
{
  uint8_t i;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--tx->refcnt > 0)
    return;
#endif

  if(tx->rxs != NULL)
    {
      for(i=0; i<tx->rxc; i++)
	if(tx->rxs[i] != NULL)
	  scamper_owamp_rx_free(tx->rxs[i]);
      free(tx->rxs);
    }
  free(tx);
  return;
}

scamper_owamp_tx_t *scamper_owamp_tx_alloc(void)
{
  scamper_owamp_tx_t *tx = malloc_zero(sizeof(scamper_owamp_tx_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(tx != NULL)
    tx->refcnt = 1;
#endif
  return tx;
}

char *scamper_owamp_result_tostr(const scamper_owamp_t *owamp,
				 char *buf, size_t len)
{
  static char *m[] = {
    "none",
    "done",
    "halted",
    "error",
    "noconn",
    "notaccepted",
    "nomode",
    "timeout",
  };
  size_t off = 0;

  if(owamp->result >= sizeof(m) / sizeof(char *))
    string_concat_u8(buf, len, &off, NULL, owamp->result);
  else
    string_concat(buf, len, &off, m[owamp->result]);

  return buf;
}

char *scamper_owamp_dir_tostr(const scamper_owamp_t *owamp,
			      char *buf, size_t len)
{
  static char *m[] = {
    "tx",
    "rx",
  };
  size_t off = 0;

  if(owamp->dir >= sizeof(m) / sizeof(char *))
    string_concat_u8(buf, len, &off, NULL, owamp->dir);
  else
    string_concat(buf, len, &off, m[owamp->dir]);

  return buf;
}

void scamper_owamp_free(scamper_owamp_t *owamp)
{
  uint32_t i;

  if(owamp->txs != NULL)
    {
      for(i=0; i<owamp->txc; i++)
	if(owamp->txs[i] != NULL)
	  scamper_owamp_tx_free(owamp->txs[i]);
      free(owamp->txs);
    }

  if(owamp->sched != NULL)
    {
      for(i=0; i<owamp->schedc; i++)
	if(owamp->sched[i] != NULL)
	  scamper_owamp_sched_free(owamp->sched[i]);
      free(owamp->sched);
    }

  if(owamp->list != NULL) scamper_list_free(owamp->list);
  if(owamp->cycle != NULL) scamper_cycle_free(owamp->cycle);
  if(owamp->src != NULL) scamper_addr_free(owamp->src);
  if(owamp->dst != NULL) scamper_addr_free(owamp->dst);
  if(owamp->errmsg != NULL) free(owamp->errmsg);
  free(owamp);

  return;
}

scamper_owamp_t *scamper_owamp_alloc(void)
{
  return malloc_zero(sizeof(scamper_owamp_t));
}
