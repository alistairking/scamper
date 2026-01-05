/*
 * scamper_owamp.h
 *
 * $Id: scamper_owamp.h,v 1.1 2025/12/04 08:11:00 mjl Exp $
 *
 * Copyright (C) 2025 The Regents of the University of California
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

#ifndef __SCAMPER_OWAMP_H
#define __SCAMPER_OWAMP_H

typedef struct scamper_owamp scamper_owamp_t;
typedef struct scamper_owamp_tx scamper_owamp_tx_t;
typedef struct scamper_owamp_rx scamper_owamp_rx_t;
typedef struct scamper_owamp_sched scamper_owamp_sched_t;

char *scamper_owamp_tojson(const scamper_owamp_t *owamp, size_t *len);

void scamper_owamp_free(scamper_owamp_t *owamp);
scamper_list_t *scamper_owamp_list_get(const scamper_owamp_t *owamp);
scamper_cycle_t *scamper_owamp_cycle_get(const scamper_owamp_t *owamp);
uint32_t scamper_owamp_userid_get(const scamper_owamp_t *owamp);
scamper_addr_t *scamper_owamp_dst_get(const scamper_owamp_t *owamp);
scamper_addr_t *scamper_owamp_src_get(const scamper_owamp_t *owamp);
uint16_t scamper_owamp_dport_get(const scamper_owamp_t *owamp);
uint16_t scamper_owamp_flags_get(const scamper_owamp_t *owamp);
const struct timeval *scamper_owamp_start_get(const scamper_owamp_t *owamp);
const struct timeval *scamper_owamp_startat_get(const scamper_owamp_t *owamp);
const struct timeval *scamper_owamp_wait_timeout_get(const scamper_owamp_t *owamp);
uint32_t scamper_owamp_schedc_get(const scamper_owamp_t *owamp);
scamper_owamp_sched_t *scamper_owamp_sched_get(const scamper_owamp_t *owamp, uint32_t i);
uint32_t scamper_owamp_attempts_get(const scamper_owamp_t *owamp);
uint16_t scamper_owamp_pktsize_get(const scamper_owamp_t *owamp);
uint8_t scamper_owamp_dir_get(const scamper_owamp_t *owamp);
char *scamper_owamp_dir_tostr(const scamper_owamp_t *owamp, char *buf, size_t len);
uint8_t scamper_owamp_dscp_get(const scamper_owamp_t *owamp);
uint8_t scamper_owamp_ttl_get(const scamper_owamp_t *owamp);
const struct timeval *scamper_owamp_hsrtt_get(const scamper_owamp_t *owamp);
uint8_t scamper_owamp_result_get(const scamper_owamp_t *owamp);
char *scamper_owamp_result_tostr(const scamper_owamp_t *owamp, char *buf, size_t len);
char *scamper_owamp_errmsg_get(const scamper_owamp_t *owamp);
uint16_t scamper_owamp_udp_sport_get(const scamper_owamp_t *owamp);
uint16_t scamper_owamp_udp_dport_get(const scamper_owamp_t *owamp);
uint32_t scamper_owamp_txc_get(const scamper_owamp_t *owamp);
scamper_owamp_tx_t *scamper_owamp_tx_get(const scamper_owamp_t *owamp, uint32_t i);

scamper_owamp_tx_t *scamper_owamp_tx_use(scamper_owamp_tx_t *tx);
void scamper_owamp_tx_free(scamper_owamp_tx_t *tx);
const struct timeval *scamper_owamp_tx_sched_get(const scamper_owamp_tx_t *tx);
const struct timeval *scamper_owamp_tx_stamp_get(const scamper_owamp_tx_t *tx);
uint32_t scamper_owamp_tx_seq_get(const scamper_owamp_tx_t *tx);
uint16_t scamper_owamp_tx_errest_get(const scamper_owamp_tx_t *tx);
uint16_t scamper_owamp_tx_flags_get(const scamper_owamp_tx_t *tx);
uint8_t scamper_owamp_tx_rxc_get(const scamper_owamp_tx_t *tx);
scamper_owamp_rx_t *scamper_owamp_tx_rx_get(const scamper_owamp_tx_t *tx, uint8_t i);

scamper_owamp_rx_t *scamper_owamp_rx_use(scamper_owamp_rx_t *rx);
void scamper_owamp_rx_free(scamper_owamp_rx_t *rx);
const struct timeval *scamper_owamp_rx_stamp_get(const scamper_owamp_rx_t *rx);
uint16_t scamper_owamp_rx_errest_get(const scamper_owamp_rx_t *rx);
uint8_t scamper_owamp_rx_flags_get(const scamper_owamp_rx_t *rx);
uint8_t scamper_owamp_rx_dscp_get(const scamper_owamp_rx_t *rx);
uint8_t scamper_owamp_rx_ttl_get(const scamper_owamp_rx_t *rx);

scamper_owamp_sched_t *scamper_owamp_sched_use(scamper_owamp_sched_t *sched);
void scamper_owamp_sched_free(scamper_owamp_sched_t *sched);
char *scamper_owamp_sched_type_tostr(const scamper_owamp_sched_t *sched, char *buf, size_t len);
uint8_t scamper_owamp_sched_type_get(const scamper_owamp_sched_t *sched);
const struct timeval *scamper_owamp_sched_tv_get(const scamper_owamp_sched_t *sched);

#define SCAMPER_OWAMP_RESULT_NONE        0
#define SCAMPER_OWAMP_RESULT_DONE        1
#define SCAMPER_OWAMP_RESULT_HALTED      2
#define SCAMPER_OWAMP_RESULT_ERROR       3
#define SCAMPER_OWAMP_RESULT_NOCONN      4
#define SCAMPER_OWAMP_RESULT_NOTACCEPTED 5
#define SCAMPER_OWAMP_RESULT_NOMODE      6
#define SCAMPER_OWAMP_RESULT_TIMEOUT     7

#define SCAMPER_OWAMP_DIR_TX        0
#define SCAMPER_OWAMP_DIR_RX        1

#define SCAMPER_OWAMP_FLAG_ZERO     0x0001 /* padding bytes should be zero */

#define SCAMPER_OWAMP_TX_FLAG_NOTSENT 0x01
#define SCAMPER_OWAMP_TX_FLAG_ERREST  0x02

#define SCAMPER_OWAMP_RX_FLAG_DSCP    0x01
#define SCAMPER_OWAMP_RX_FLAG_TTL     0x02
#define SCAMPER_OWAMP_RX_FLAG_ERREST  0x04

#define SCAMPER_OWAMP_SCHED_TYPE_FIXED 0
#define SCAMPER_OWAMP_SCHED_TYPE_EXP   1

#endif /* __SCAMPER_OWAMP_H */
