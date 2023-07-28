/*
 * scamper_tbit_int.h
 *
 * $Id: scamper_tbit_int.h,v 1.2 2023/05/29 21:41:32 mjl Exp $
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
  uint8_t             *fo_cookie;
  uint8_t              fo_cookielen;
  uint8_t              wscale;
  uint8_t              ttl;

  /* various generic retransmit values */
  uint8_t              syn_retx;
  uint8_t              dat_retx;

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
