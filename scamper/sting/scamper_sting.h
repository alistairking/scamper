/*
 * scamper_sting.h
 *
 * Copyright (C) 2008 The University of Waikato
 * Copyright (C) 2012 The Regents of the University of California
 * Copyright (C) 2023 Matthew Luckie
 *
 * Author: Matthew Luckie
 *
 * $Id: scamper_sting.h,v 1.13 2023/12/24 00:03:21 mjl Exp $
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

#ifndef __SCAMPER_STING_H
#define __SCAMPER_STING_H

typedef struct scamper_sting scamper_sting_t;
typedef struct scamper_sting_pkt scamper_sting_pkt_t;

void scamper_sting_free(scamper_sting_t *sting);
scamper_list_t *scamper_sting_list_get(const scamper_sting_t *sting);
scamper_cycle_t *scamper_sting_cycle_get(const scamper_sting_t *sting);
uint32_t scamper_sting_userid_get(const scamper_sting_t *sting);
scamper_addr_t *scamper_sting_src_get(const scamper_sting_t *sting);
scamper_addr_t *scamper_sting_dst_get(const scamper_sting_t *sting);
uint16_t scamper_sting_sport_get(const scamper_sting_t *sting);
uint16_t scamper_sting_dport_get(const scamper_sting_t *sting);
uint16_t scamper_sting_count_get(const scamper_sting_t *sting);
const struct timeval *scamper_sting_mean_get(const scamper_sting_t *sting);
const struct timeval *scamper_sting_inter_get(const scamper_sting_t *sting);
uint8_t scamper_sting_dist_get(const scamper_sting_t *sting);
uint8_t scamper_sting_synretx_get(const scamper_sting_t *sting);
uint8_t scamper_sting_dataretx_get(const scamper_sting_t *sting);
uint8_t scamper_sting_seqskip_get(const scamper_sting_t *sting);
const uint8_t *scamper_sting_data_get(const scamper_sting_t *sting);
uint16_t scamper_sting_datalen_get(const scamper_sting_t *sting);
const struct timeval *scamper_sting_start_get(const scamper_sting_t *sting);
const struct timeval *scamper_sting_hsrtt_get(const scamper_sting_t *sting);
uint16_t scamper_sting_dataackc_get(const scamper_sting_t *sting);
uint16_t scamper_sting_holec_get(const scamper_sting_t *sting);
scamper_sting_pkt_t *scamper_sting_pkt_get(const scamper_sting_t *sting,
					   uint32_t i);
uint32_t scamper_sting_pktc_get(const scamper_sting_t *sting);
uint8_t scamper_sting_result_get(const scamper_sting_t *sting);

scamper_sting_pkt_t *scamper_sting_pkt_use(scamper_sting_pkt_t *pkt);
void scamper_sting_pkt_free(scamper_sting_pkt_t *pkt);
const struct timeval *scamper_sting_pkt_tv_get(const scamper_sting_pkt_t *pkt);
uint8_t scamper_sting_pkt_flags_get(const scamper_sting_pkt_t *pkt);
uint16_t scamper_sting_pkt_len_get(const scamper_sting_pkt_t *pkt);
const uint8_t *scamper_sting_pkt_data_get(const scamper_sting_pkt_t *pkt);

#define SCAMPER_STING_RESULT_NONE       0
#define SCAMPER_STING_RESULT_COMPLETED  1

#define SCAMPER_STING_DISTRIBUTION_EXPONENTIAL 1
#define SCAMPER_STING_DISTRIBUTION_PERIODIC    2
#define SCAMPER_STING_DISTRIBUTION_UNIFORM     3

#define SCAMPER_STING_PKT_FLAG_TX   0x01
#define SCAMPER_STING_PKT_FLAG_RX   0x02
#define SCAMPER_STING_PKT_FLAG_DATA 0x04
#define SCAMPER_STING_PKT_FLAG_HOLE 0x08

#endif /* __SCAMPER_STING_H */
