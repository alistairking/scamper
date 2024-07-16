/*
 * scamper_udpprobe.h
 *
 * $Id: scamper_udpprobe.h,v 1.5 2024/04/04 22:57:01 mjl Exp $
 *
 * Copyright (C) 2023 The Regents of the University of California
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

#ifndef __SCAMPER_UDPPROBE_H
#define __SCAMPER_UDPPROBE_H

typedef struct scamper_udpprobe scamper_udpprobe_t;
typedef struct scamper_udpprobe_probe scamper_udpprobe_probe_t;
typedef struct scamper_udpprobe_reply scamper_udpprobe_reply_t;

/* scamper_udpprobe_t functions */
void scamper_udpprobe_free(scamper_udpprobe_t *up);
scamper_list_t *scamper_udpprobe_list_get(const scamper_udpprobe_t *up);
scamper_cycle_t *scamper_udpprobe_cycle_get(const scamper_udpprobe_t *up);
uint32_t scamper_udpprobe_userid_get(const scamper_udpprobe_t *up);
scamper_addr_t *scamper_udpprobe_src_get(const scamper_udpprobe_t *up);
scamper_addr_t *scamper_udpprobe_dst_get(const scamper_udpprobe_t *up);
uint16_t scamper_udpprobe_sport_get(const scamper_udpprobe_t *up);
uint16_t scamper_udpprobe_dport_get(const scamper_udpprobe_t *up);
const struct timeval *scamper_udpprobe_start_get(const scamper_udpprobe_t *up);
const struct timeval *scamper_udpprobe_wait_timeout_get(const scamper_udpprobe_t *up);
const struct timeval *scamper_udpprobe_wait_probe_get(const scamper_udpprobe_t *up);
int scamper_udpprobe_flag_is_exitfirst(const scamper_udpprobe_t *up);
const uint8_t *scamper_udpprobe_data_get(const scamper_udpprobe_t *up);
uint16_t scamper_udpprobe_len_get(const scamper_udpprobe_t *up);
uint8_t scamper_udpprobe_probe_count_get(const scamper_udpprobe_t *up);
uint8_t scamper_udpprobe_probe_sent_get(const scamper_udpprobe_t *up);
uint8_t scamper_udpprobe_stop_count_get(const scamper_udpprobe_t *up);
scamper_udpprobe_probe_t *scamper_udpprobe_probe_get(const scamper_udpprobe_t *up, uint8_t i);

/* scamper_udpprobe_probe_t functions */
void scamper_udpprobe_probe_free(scamper_udpprobe_probe_t *pr);
scamper_udpprobe_probe_t *scamper_udpprobe_probe_use(scamper_udpprobe_probe_t *probe);
const struct timeval *scamper_udpprobe_probe_tx_get(const scamper_udpprobe_probe_t *probe);
uint16_t scamper_udpprobe_probe_sport_get(const scamper_udpprobe_probe_t *probe);
scamper_udpprobe_reply_t *scamper_udpprobe_probe_reply_get(const scamper_udpprobe_probe_t *probe, uint8_t i);
uint8_t scamper_udpprobe_probe_replyc_get(const scamper_udpprobe_probe_t *probe);

/* scamper_udpprobe_reply_t functions */
void scamper_udpprobe_reply_free(scamper_udpprobe_reply_t *ur);
scamper_udpprobe_reply_t *scamper_udpprobe_reply_use(scamper_udpprobe_reply_t *ur);
const uint8_t *scamper_udpprobe_reply_data_get(const scamper_udpprobe_reply_t *ur);
uint16_t scamper_udpprobe_reply_len_get(const scamper_udpprobe_reply_t *ur);
const struct timeval *scamper_udpprobe_reply_rx_get(const scamper_udpprobe_reply_t *ur);

#endif /* __SCAMPER_UDPPROBE_H */
