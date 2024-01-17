/*
 * scamper_sniff_int.h
 *
 * $Id: scamper_sniff_int.h,v 1.5 2024/01/02 17:51:46 mjl Exp $
 *
 * Copyright (C) 2011 The University of Waikato
 * Author: Matthew Luckie
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

#ifndef __SCAMPER_SNIFF_INT_H
#define __SCAMPER_SNIFF_INT_H

scamper_sniff_t *scamper_sniff_alloc(void);
scamper_sniff_pkt_t *scamper_sniff_pkt_alloc(uint8_t *data, uint16_t len,
					     struct timeval *tv);
int scamper_sniff_pkts_alloc(scamper_sniff_t *sniff, int pktc);

struct scamper_sniff_pkt
{
  struct timeval        tv;
  uint8_t              *data;
  uint16_t              len;

#ifdef BUILDING_LIBSCAMPERFILE
  int                   refcnt;
#endif
};

struct scamper_sniff
{
  scamper_list_t       *list;
  scamper_cycle_t      *cycle;
  uint32_t              userid;

  struct timeval        start;
  struct timeval        finish;
  uint8_t               stop_reason;
  uint32_t              limit_pktc;
  struct timeval        limit_time;

  scamper_addr_t       *src;
  uint16_t              icmpid;

  scamper_sniff_pkt_t **pkts;
  uint32_t              pktc;
};

#endif /* __SCAMPER_SNIFF_INT_H */
