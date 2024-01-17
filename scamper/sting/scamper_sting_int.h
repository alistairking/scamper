/*
 * scamper_sting_int.h
 *
 * Copyright (C) 2008 The University of Waikato
 * Copyright (C) 2012 The Regents of the University of California
 * Copyright (C) 2023 Matthew Luckie
 *
 * Author: Matthew Luckie
 *
 * $Id: scamper_sting_int.h,v 1.3 2023/12/24 00:03:21 mjl Exp $
 *
 * This file implements algorithms described in the sting-0.7 source code,
 * as well as the paper:
 *
 *  Sting: a TCP-based Network Measurement Tool
 *  by Stefan Savage
 *  1999 USENIX Symposium on Internet Technologies and Systems
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

#ifndef __SCAMPER_STING_INT_H
#define __SCAMPER_STING_INT_H

scamper_sting_t *scamper_sting_alloc(void);

int scamper_sting_data_set(scamper_sting_t *,const uint8_t *,uint16_t);
int scamper_sting_pkts_alloc(scamper_sting_t *, uint32_t);
int scamper_sting_pkt_record(scamper_sting_t *, scamper_sting_pkt_t *);
scamper_sting_pkt_t *scamper_sting_pkt_alloc(uint8_t flags, uint8_t *data,
					     uint16_t len, struct timeval *tv);

struct scamper_sting_pkt
{
  struct timeval tv;
  uint8_t        flags;
  uint16_t       len;
  uint8_t       *data;

#ifdef BUILDING_LIBSCAMPERFILE
  int            refcnt;
#endif
};

/*
 * scamper_sting
 *
 * results of a measurement conducted with sting
 */
struct scamper_sting
{
  /*
   * management
   */
  scamper_list_t        *list;     /* list corresponding to task */
  scamper_cycle_t       *cycle;    /* cycle corresponding to task */
  uint32_t               userid;

  /*
   * parameters used in probing
   */
  scamper_addr_t        *src;      /* source address */
  scamper_addr_t        *dst;      /* destination address */
  uint16_t               sport;    /* source port */
  uint16_t               dport;    /* destination port */
  uint16_t               count;    /* number of probes to send */
  struct timeval         mean;     /* mean inter-packet delay */
  struct timeval         inter;    /* inter-phase delay */
  uint8_t                dist;     /* inter-packet delay distribution to tx */
  uint8_t                synretx;  /* number of times to retransmit syn  */
  uint8_t                dataretx; /* number of times to retransmit data */
  uint8_t                seqskip;  /* size of initial hole */
  uint8_t               *data;     /* data to use */
  uint16_t               datalen;  /* length of data */

  /*
   * data collected
   */
  struct timeval         start;    /* time measurement commenced */
  struct timeval         hsrtt;    /* rtt of syn -> syn/ack */
  uint16_t               dataackc; /* number of acks rx'd in data-seeding */
  uint16_t               holec;    /* number of holes filled (fwd loss) */
  scamper_sting_pkt_t  **pkts;     /* array of packets in the test */
  uint32_t               pktc;     /* number of packets in the test */
  uint8_t                result;   /* did sting complete? */
};

#endif /* __SCAMPER_STING_INT_H */
