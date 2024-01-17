/*
 * scamper_sniff.h
 *
 * $Id: scamper_sniff.h,v 1.11 2024/01/02 17:51:46 mjl Exp $
 *
 * Copyright (C) 2011 The University of Waikato
 * Copyright (C) 2023 Matthew Luckie
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

#ifndef __SCAMPER_SNIFF_H
#define __SCAMPER_SNIFF_H

#define SCAMPER_SNIFF_STOP_NONE           0x00
#define SCAMPER_SNIFF_STOP_ERROR          0x01
#define SCAMPER_SNIFF_STOP_LIMIT_TIME     0x02
#define SCAMPER_SNIFF_STOP_LIMIT_PKTC     0x03
#define SCAMPER_SNIFF_STOP_HALTED         0x04

typedef struct scamper_sniff_pkt scamper_sniff_pkt_t;
typedef struct scamper_sniff scamper_sniff_t;

void scamper_sniff_free(scamper_sniff_t *sniff);
scamper_list_t *scamper_sniff_list_get(const scamper_sniff_t *sniff);
scamper_cycle_t *scamper_sniff_cycle_get(const scamper_sniff_t *sniff);
uint32_t scamper_sniff_userid_get(const scamper_sniff_t *sniff);
const struct timeval *scamper_sniff_start_get(const scamper_sniff_t *sniff);
const struct timeval *scamper_sniff_finish_get(const scamper_sniff_t *sniff);
uint8_t scamper_sniff_stop_reason_get(const scamper_sniff_t *sniff);
uint32_t scamper_sniff_limit_pktc_get(const scamper_sniff_t *sniff);
const struct timeval *scamper_sniff_limit_time_get(const scamper_sniff_t *sniff);
scamper_addr_t *scamper_sniff_src_get(const scamper_sniff_t *sniff);
uint16_t scamper_sniff_icmpid_get(const scamper_sniff_t *sniff);
scamper_sniff_pkt_t *scamper_sniff_pkt_get(const scamper_sniff_t *sniff,
					   uint32_t i);
uint32_t scamper_sniff_pktc_get(const scamper_sniff_t *sniff);

scamper_sniff_pkt_t *scamper_sniff_pkt_use(scamper_sniff_pkt_t *pkt);
void scamper_sniff_pkt_free(scamper_sniff_pkt_t *pkt);
const struct timeval *scamper_sniff_pkt_tv_get(const scamper_sniff_pkt_t *pkt);
const uint8_t *scamper_sniff_pkt_data_get(const scamper_sniff_pkt_t *pkt);
uint16_t scamper_sniff_pkt_len_get(const scamper_sniff_pkt_t *pkt);

#endif /* __SCAMPER_SNIFF_H */
