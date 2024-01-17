/*
 * scamper_tbit_int.h
 *
 * $Id: scamper_tbit_int.h,v 1.5 2023/07/29 07:34:45 mjl Exp $
 *
 * Copyright (C) 2009-2010 Ben Stasiewicz
 * Copyright (C) 2010-2011 University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2012,2015 The Regents of the University of California
 * Copyright (C) 2023      Matthew Luckie
 *
 * This file implements algorithms described in the tbit-1.0 source code,
 * as well as the papers:
 *
 *  "On Inferring TCP Behaviour"
 *      by Jitendra Padhye and Sally Floyd
 *  "Measuring the Evolution of Transport Protocols in the Internet" by
 *      by Alberto Medina, Mark Allman, and Sally Floyd.
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

#ifndef __SCAMPER_TBIT_INT_H
#define __SCAMPER_TBIT_INT_H

scamper_tbit_t *scamper_tbit_alloc(void);

scamper_tbit_pmtud_t *scamper_tbit_pmtud_alloc(void);
void scamper_tbit_pmtud_free(scamper_tbit_pmtud_t *pmtud);

scamper_tbit_icw_t *scamper_tbit_icw_alloc(void);
void scamper_tbit_icw_free(scamper_tbit_icw_t *icw);

scamper_tbit_null_t *scamper_tbit_null_alloc(void);
void scamper_tbit_null_free(scamper_tbit_null_t *null);

scamper_tbit_blind_t *scamper_tbit_blind_alloc(void);
void scamper_tbit_blind_free(scamper_tbit_blind_t *blind);

scamper_tbit_app_http_t *scamper_tbit_app_http_alloc(uint8_t type,
						     char *host, char *file);

scamper_tbit_pkt_t *scamper_tbit_pkt_alloc(uint8_t dir, uint8_t *data,
					   uint16_t len, struct timeval *tv);

scamper_tbit_app_bgp_t *scamper_tbit_app_bgp_alloc(void);
void scamper_tbit_app_bgp_free(scamper_tbit_app_bgp_t *bgp);

int scamper_tbit_pkts_alloc(scamper_tbit_t *tbit, uint32_t count);
int scamper_tbit_record_pkt(scamper_tbit_t *tbit, scamper_tbit_pkt_t *pkt);

void scamper_tbit_app_http_free(scamper_tbit_app_http_t *http);

int scamper_tbit_client_fo_cookie_set(scamper_tbit_t *tbit,
				      uint8_t *c, uint8_t l);

/*
 * convenience functions.
 *
 * scamper_tbit_data_inrange: determine if a particular packet and length
 *  are in range or not.
 *
 * scamper_tbit_data_seqoff: determine the difference in sequence number
 *  space between a and b handling wrapping.  this function assumes that
 *  the caller has used scamper_tbit_data_inrange first to determine
 *  the packet is in the current window.
 *
 */
int scamper_tbit_data_inrange(uint32_t rcv_nxt, uint32_t seq, uint16_t len);
int scamper_tbit_data_seqoff(uint32_t rcv_nxt, uint32_t seq);

/*
 * scamper_tbit_tcpq functions.
 *
 * these functions are used to maintain in-order processing of TCP packets
 * when the packets are received out of order.  for these routines to work
 * correctly, all TCP packets that are received in range must be processed
 * through the queue so that the queue knows what sequence number is
 * expected.
 *
 * scamper_tbit_tcpq_alloc: allocate a new tcp data queue with an initial
 *  sequence number seeding the queue.
 *
 * scamper_tbit_tcpq_free: free the tcp data queue.  the ff parameter is an
 *  optional free() function that can be called on all queue entry param
 *  fields.
 *
 * scamper_tbit_tcpq_add: add a new segment to the queue.  the seq, flags,
 *  and length must be supplied.  the param field is an optional field that
 *  will be returned with the queue entry when the segment is returned in
 *  order.
 *
 * scamper_tbit_tcpq_seg: return the sequence number and payload length of
 *  the next packet in line to be returned.  the segment remains in the queue.
 *  returns -1 if there is no segment in the queue, zero otherwise.
 *
 * scamper_tbit_tcpq_pop: return the next queue entry that is next in line
 *  to be returned.  the segment is now the responsibility of the caller.
 *
 * scamper_tbit_tcpq_sack: return a set of sack blocks that specify the
 *  state of the tcpq.  the caller must pass a pointer to an array of
 *  (c*2) uint32_t.  the routine returns the number of sack blocks
 *  computed given the constraint of c and the state of the queue.
 *
 * scamper_tbit_tcpq_tail: returns the sequence number at the tail of the
 *  tcp, even if there are gaps in the tcpq.
 *
 * scamper_tbit_tcpqe_free: free the queue entry passed in.  ff is an
 *  optional free() function that will be called on the param if not null.
 *
 */
typedef struct scamper_tbit_tcpq scamper_tbit_tcpq_t;
typedef struct scamper_tbit_tcpqe scamper_tbit_tcpqe_t;

uint32_t scamper_tbit_tcpqe_seq_get(const scamper_tbit_tcpqe_t *tqe);
uint16_t scamper_tbit_tcpqe_len_get(const scamper_tbit_tcpqe_t *tqe);
uint8_t scamper_tbit_tcpqe_flags_get(const scamper_tbit_tcpqe_t *tqe);
const uint8_t *scamper_tbit_tcpqe_data_get(const scamper_tbit_tcpqe_t *tqe);

scamper_tbit_tcpq_t *scamper_tbit_tcpq_alloc(uint32_t isn);
void scamper_tbit_tcpq_free(scamper_tbit_tcpq_t *q, void (*ff)(void *));
void scamper_tbit_tcpq_flush(scamper_tbit_tcpq_t *q, void (*ff)(void *));
int scamper_tbit_tcpq_add(scamper_tbit_tcpq_t *q, uint32_t seq,
			  uint8_t flags, uint16_t len, uint8_t *data);
int scamper_tbit_tcpq_seg(scamper_tbit_tcpq_t *q,uint32_t *seq,uint16_t *len);
scamper_tbit_tcpqe_t *scamper_tbit_tcpq_pop(scamper_tbit_tcpq_t *q);
int scamper_tbit_tcpq_sack(scamper_tbit_tcpq_t *q, uint32_t *blocks, int c);
uint32_t scamper_tbit_tcpq_tail(const scamper_tbit_tcpq_t *q);
void scamper_tbit_tcpqe_free(scamper_tbit_tcpqe_t *qe, void (*ff)(void *));

struct scamper_tbit
{
  scamper_list_t      *list;
  scamper_cycle_t     *cycle;
  uint32_t             userid;

  scamper_addr_t      *src;
  scamper_addr_t      *dst;
  uint16_t             sport;
  uint16_t             dport;
  struct timeval       start;

  /* outcome of test */
  uint16_t             result;

  /* type of tbit test and data specific to that test */
  uint8_t              type;
  void                *data;

  /* details of application protocol used */
  uint8_t              app_proto;
  void                *app_data;

  /* client and server mss values advertised */
  uint32_t             options;
  uint16_t             client_mss;
  uint16_t             server_mss;
  uint8_t             *client_fo_cookie;
  uint8_t              client_fo_cookielen;
  uint8_t              client_wscale;
  uint8_t              client_ipttl;

  /* various generic retransmit values */
  uint8_t              client_syn_retx;
  uint8_t              client_dat_retx;

  /* packets collected as part of this test */
  scamper_tbit_pkt_t **pkts;
  uint32_t             pktc;
};

struct scamper_tbit_pkt
{
  struct timeval       tv;
  uint8_t              dir;
  uint16_t             len;
  uint8_t             *data;

#ifdef BUILDING_LIBSCAMPERFILE
  int                  refcnt;
#endif
};

struct scamper_tbit_app_http
{
  uint8_t              type;
  char                *host;
  char                *file;
};

struct scamper_tbit_app_bgp
{
  uint32_t             asn;
};

struct scamper_tbit_pmtud
{
  uint16_t             mtu;
  uint8_t              ptb_retx;
  uint8_t              options;
  scamper_addr_t      *ptbsrc;
};

struct scamper_tbit_null
{
  uint16_t             options;
  uint16_t             results;
};

struct scamper_tbit_icw
{
  uint32_t             start_seq;
};

struct scamper_tbit_blind
{
  int32_t              off;
  uint8_t              retx;
};

struct scamper_tbit_stats
{
  struct timeval synack_rtt;
  uint32_t       rx_xfersize;
  uint32_t       rx_totalsize;
  struct timeval xfertime;
};

struct scamper_tbit_tcpqe
{
  uint32_t seq;
  uint16_t len;
  uint8_t  flags;
  uint8_t *data;
};

#define SCAMPER_TBIT_TYPE_IS_BLIND(tbit) (		\
 (tbit)->type == SCAMPER_TBIT_TYPE_BLIND_RST ||		\
 (tbit)->type == SCAMPER_TBIT_TYPE_BLIND_SYN ||		\
 (tbit)->type == SCAMPER_TBIT_TYPE_BLIND_FIN ||		\
 (tbit)->type == SCAMPER_TBIT_TYPE_BLIND_DATA)

#endif /* __SCAMPER_TBIT_INT_H */
