/*
 * scamper_owamp_int.h
 *
 * $Id: scamper_owamp_int.h,v 1.3 2026/01/04 19:43:21 mjl Exp $
 *
 * Copyright (C) 2025-2026 The Regents of the University of California
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

#ifndef __SCAMPER_OWAMP_INT_H
#define __SCAMPER_OWAMP_INT_H

scamper_owamp_t *scamper_owamp_alloc(void);
scamper_owamp_tx_t *scamper_owamp_tx_alloc(void);
scamper_owamp_rx_t *scamper_owamp_rx_alloc(void);
scamper_owamp_sched_t *scamper_owamp_sched_alloc(void);

int scamper_owamp_scheds_alloc(scamper_owamp_t *owamp, uint32_t c);
int scamper_owamp_txs_alloc(scamper_owamp_t *owamp, uint32_t c);

int scamper_owamp_tx_rxadd(scamper_owamp_tx_t *tx, scamper_owamp_rx_t *rx);

#define SCAMPER_OWAMP_TX_FLAG_IS_SENT(tx) \
  (((tx)->flags & SCAMPER_OWAMP_TX_FLAG_NOTSENT) == 0)

#define SCAMPER_OWAMP_TX_FLAG_IS_NOTSENT(tx) \
  (((tx)->flags & SCAMPER_OWAMP_TX_FLAG_NOTSENT) != 0)

struct scamper_owamp_rx
{
  struct timeval            stamp;
  uint16_t                  errest;
  uint8_t                   flags;
  uint8_t                   dscp;
  uint8_t                   ttl;

#ifdef BUILDING_LIBSCAMPERFILE
  int                       refcnt;
#endif
};

struct scamper_owamp_tx
{
  struct timeval            sched;
  struct timeval            stamp;
  uint32_t                  seq;
  uint16_t                  errest;
  uint8_t                   flags;
  uint8_t                   rxc;
  scamper_owamp_rx_t      **rxs;

#ifdef BUILDING_LIBSCAMPERFILE
  int                       refcnt;
#endif
};

struct scamper_owamp_sched
{
  struct timeval            tv;
  uint8_t                   type;

#ifdef BUILDING_LIBSCAMPERFILE
  int                       refcnt;
#endif
};

struct scamper_owamp
{
  scamper_list_t            *list;
  scamper_cycle_t           *cycle;
  scamper_addr_t            *src;
  scamper_addr_t            *dst;
  uint32_t                   userid;       /* -U userid */
  uint16_t                   dport;
  uint16_t                   flags;
  struct timeval             start;
  struct timeval             startat;      /* -@ startat */
  struct timeval             wait_timeout; /* -w wait-timeout */
  scamper_owamp_sched_t    **sched;        /* -i sched */
  uint32_t                   schedc;
  uint32_t                   attempts;     /* -c count */
  uint16_t                   pktsize;      /* -s size */
  uint8_t                    dir;          /* -d dir */
  uint8_t                    dscp;         /* -D dscp */
  uint8_t                    ttl;          /* -m ttl */

  struct timeval             hsrtt;
  uint8_t                    result;
  char                      *errmsg;
  uint16_t                   udp_sport;
  uint16_t                   udp_dport;

  scamper_owamp_tx_t       **txs;
  uint32_t                   txc;
};

#endif /* __SCAMPER_OWAMP_INT_H */
