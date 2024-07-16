/*
 * scamper_ping.h
 *
 * $Id: scamper_ping.h,v 1.74 2024/05/01 07:46:20 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2020-2023 Matthew Luckie
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

#ifndef __SCAMPER_PING_H
#define __SCAMPER_PING_H

typedef struct scamper_ping scamper_ping_t;
typedef struct scamper_ping_v4ts scamper_ping_v4ts_t;
typedef struct scamper_ping_reply scamper_ping_reply_t;
typedef struct scamper_ping_reply_v4rr scamper_ping_reply_v4rr_t;
typedef struct scamper_ping_reply_v4ts scamper_ping_reply_v4ts_t;
typedef struct scamper_ping_reply_tsreply scamper_ping_reply_tsreply_t;
typedef struct scamper_ping_stats scamper_ping_stats_t;

#define SCAMPER_PING_STOP_NONE      0x00 /* null reason */
#define SCAMPER_PING_STOP_COMPLETED 0x01 /* sent all probes */
#define SCAMPER_PING_STOP_ERROR     0x02 /* error occured during ping */
#define SCAMPER_PING_STOP_HALTED    0x03 /* halted */

#define SCAMPER_PING_REPLY_FLAG_REPLY_TTL  0x01 /* reply ttl included */
#define SCAMPER_PING_REPLY_FLAG_REPLY_IPID 0x02 /* reply ipid included */
#define SCAMPER_PING_REPLY_FLAG_PROBE_IPID 0x04 /* probe ipid included */
#define SCAMPER_PING_REPLY_FLAG_DLTX       0x08 /* datalink tx timestamp */
#define SCAMPER_PING_REPLY_FLAG_DLRX       0x10 /* datalink rx timestamp */
#define SCAMPER_PING_REPLY_FLAG_REPLY_TOS  0x20 /* reply tos included */

#define SCAMPER_PING_METHOD_ICMP_ECHO     0x00
#define SCAMPER_PING_METHOD_TCP_ACK       0x01
#define SCAMPER_PING_METHOD_TCP_ACK_SPORT 0x02
#define SCAMPER_PING_METHOD_UDP           0x03
#define SCAMPER_PING_METHOD_UDP_DPORT     0x04
#define SCAMPER_PING_METHOD_ICMP_TIME     0x05
#define SCAMPER_PING_METHOD_TCP_SYN       0x06
#define SCAMPER_PING_METHOD_TCP_SYNACK    0x07
#define SCAMPER_PING_METHOD_TCP_RST       0x08
#define SCAMPER_PING_METHOD_TCP_SYN_SPORT 0x09

#define SCAMPER_PING_FLAG_V4RR            0x01 /* -R: IPv4 record route */
#define SCAMPER_PING_FLAG_SPOOF           0x02 /* -O spoof: spoof src */
#define SCAMPER_PING_FLAG_PAYLOAD         0x04 /* probe_data is payload */
#define SCAMPER_PING_FLAG_TSONLY          0x08 /* -T tsonly */
#define SCAMPER_PING_FLAG_TSANDADDR       0x10 /* -T tsandaddr */
#define SCAMPER_PING_FLAG_ICMPSUM         0x20 /* -C csum */
#define SCAMPER_PING_FLAG_DL              0x40 /* -O dl: timestamp from dl */
#define SCAMPER_PING_FLAG_TBT             0x80 /* -O tbt: too big trick */
#define SCAMPER_PING_FLAG_NOSRC           0x100 /* -O nosrc: do not embed src */
#define SCAMPER_PING_FLAG_RAW             0x200 /* -O raw: tx with raw IPv4 */

/* basic routines to use and free scamper_ping structures */
void scamper_ping_free(scamper_ping_t *ping);

/* get methods for accessing ping structure variables */
scamper_list_t *scamper_ping_list_get(const scamper_ping_t *ping);
scamper_cycle_t *scamper_ping_cycle_get(const scamper_ping_t *ping);
uint32_t scamper_ping_userid_get(const scamper_ping_t *ping);
scamper_addr_t *scamper_ping_dst_get(const scamper_ping_t *ping);
scamper_addr_t *scamper_ping_src_get(const scamper_ping_t *ping);
scamper_addr_t *scamper_ping_rtr_get(const scamper_ping_t *ping);
const struct timeval *scamper_ping_start_get(const scamper_ping_t *ping);
uint8_t scamper_ping_stop_reason_get(const scamper_ping_t *ping);
uint8_t scamper_ping_stop_data_get(const scamper_ping_t *ping);
const uint8_t *scamper_ping_probe_data_get(const scamper_ping_t *ping);
uint16_t scamper_ping_probe_datalen_get(const scamper_ping_t *ping);
uint16_t scamper_ping_probe_count_get(const scamper_ping_t *ping);
uint16_t scamper_ping_probe_size_get(const scamper_ping_t *ping);
uint8_t scamper_ping_probe_method_get(const scamper_ping_t *ping);
char *scamper_ping_method_tostr(const scamper_ping_t *ping, char *buf, size_t len);
int scamper_ping_method_is_icmp(const scamper_ping_t *ping);
int scamper_ping_method_is_icmp_time(const scamper_ping_t *ping);
int scamper_ping_method_is_tcp(const scamper_ping_t *ping);
int scamper_ping_method_is_tcp_ack_sport(const scamper_ping_t *ping);
int scamper_ping_method_is_udp(const scamper_ping_t *ping);
int scamper_ping_method_is_vary_sport(const scamper_ping_t *ping);
int scamper_ping_method_is_vary_dport(const scamper_ping_t *ping);
const struct timeval *scamper_ping_wait_timeout_get(const scamper_ping_t *ping);
const struct timeval *scamper_ping_wait_probe_get(const scamper_ping_t *ping);
uint8_t scamper_ping_probe_ttl_get(const scamper_ping_t *ping);
uint8_t scamper_ping_probe_tos_get(const scamper_ping_t *ping);
uint16_t scamper_ping_probe_sport_get(const scamper_ping_t *ping);
uint16_t scamper_ping_probe_dport_get(const scamper_ping_t *ping);
uint16_t scamper_ping_probe_icmpsum_get(const scamper_ping_t *ping);
uint32_t scamper_ping_probe_tcpseq_get(const scamper_ping_t *ping);
uint32_t scamper_ping_probe_tcpack_get(const scamper_ping_t *ping);
scamper_ping_v4ts_t *scamper_ping_probe_tsps_get(const scamper_ping_t *ping);
uint32_t scamper_ping_flags_get(const scamper_ping_t *ping);
uint16_t scamper_ping_reply_count_get(const scamper_ping_t *ping);
uint16_t scamper_ping_reply_pmtu_get(const scamper_ping_t *ping);
uint16_t scamper_ping_sent_get(const scamper_ping_t *ping);
scamper_ping_reply_t *scamper_ping_reply_get(const scamper_ping_t *ping,
					     uint16_t i);

/* basic routines to use and free scamper_ping_reply structures */
scamper_ping_reply_t *scamper_ping_reply_use(scamper_ping_reply_t *reply);
void scamper_ping_reply_free(scamper_ping_reply_t *reply);

/* get methods for accessing ping reply structure variables */
int scamper_ping_reply_is_from_target(const scamper_ping_t *ping,
				      const scamper_ping_reply_t *reply);
scamper_addr_t *scamper_ping_reply_addr_get(const scamper_ping_reply_t *reply);
uint16_t scamper_ping_reply_probe_id_get(const scamper_ping_reply_t *reply);
uint16_t scamper_ping_reply_probe_ipid_get(const scamper_ping_reply_t *reply);
uint16_t scamper_ping_reply_probe_sport_get(const scamper_ping_reply_t *reply);
uint8_t scamper_ping_reply_proto_get(const scamper_ping_reply_t *reply);
uint8_t scamper_ping_reply_ttl_get(const scamper_ping_reply_t *reply);
uint8_t scamper_ping_reply_tos_get(const scamper_ping_reply_t *reply);
uint16_t scamper_ping_reply_size_get(const scamper_ping_reply_t *reply);
uint16_t scamper_ping_reply_ipid_get(const scamper_ping_reply_t *reply);
uint32_t scamper_ping_reply_ipid32_get(const scamper_ping_reply_t *reply);
uint32_t scamper_ping_reply_flags_get(const scamper_ping_reply_t *reply);
int scamper_ping_reply_flag_is_reply_ipid(const scamper_ping_reply_t *reply);
uint8_t scamper_ping_reply_icmp_type_get(const scamper_ping_reply_t *reply);
uint8_t scamper_ping_reply_icmp_code_get(const scamper_ping_reply_t *reply);
uint8_t scamper_ping_reply_tcp_flags_get(const scamper_ping_reply_t *reply);
const char *scamper_ping_reply_ifname_get(const scamper_ping_reply_t *reply);
int scamper_ping_reply_is_icmp(const scamper_ping_reply_t *reply);
int scamper_ping_reply_is_tcp(const scamper_ping_reply_t *reply);
int scamper_ping_reply_is_udp(const scamper_ping_reply_t *reply);
int scamper_ping_reply_is_icmp_echo_reply(const scamper_ping_reply_t *reply);
int scamper_ping_reply_is_icmp_unreach(const scamper_ping_reply_t *reply);
int scamper_ping_reply_is_icmp_unreach_port(const scamper_ping_reply_t *reply);
int scamper_ping_reply_is_icmp_ttl_exp(const scamper_ping_reply_t *reply);
int scamper_ping_reply_is_icmp_tsreply(const scamper_ping_reply_t *reply);
const struct timeval *scamper_ping_reply_tx_get(const scamper_ping_reply_t *reply);
const struct timeval *scamper_ping_reply_rtt_get(const scamper_ping_reply_t *reply);
scamper_ping_reply_t *scamper_ping_reply_next_get(const scamper_ping_reply_t *reply);
scamper_ping_reply_v4rr_t *scamper_ping_reply_v4rr_get(const scamper_ping_reply_t *reply);
scamper_ping_reply_v4ts_t *scamper_ping_reply_v4ts_get(const scamper_ping_reply_t *reply);
scamper_ping_reply_tsreply_t *scamper_ping_reply_tsreply_get(const scamper_ping_reply_t *reply);

void scamper_ping_reply_tsreply_free(scamper_ping_reply_tsreply_t *tsr);
uint32_t scamper_ping_reply_tsreply_tso_get(const scamper_ping_reply_tsreply_t *tsr);
uint32_t scamper_ping_reply_tsreply_tsr_get(const scamper_ping_reply_tsreply_t *tsr);
uint32_t scamper_ping_reply_tsreply_tst_get(const scamper_ping_reply_tsreply_t *tsr);

void scamper_ping_reply_v4rr_free(scamper_ping_reply_v4rr_t *rr);
uint8_t scamper_ping_reply_v4rr_ipc_get(const scamper_ping_reply_v4rr_t *rr);
scamper_addr_t *scamper_ping_reply_v4rr_ip_get(const scamper_ping_reply_v4rr_t *rr, uint8_t i);

void scamper_ping_reply_v4ts_free(scamper_ping_reply_v4ts_t *ts);
uint8_t scamper_ping_reply_v4ts_tsc_get(const scamper_ping_reply_v4ts_t *ts);
uint32_t scamper_ping_reply_v4ts_ts_get(const scamper_ping_reply_v4ts_t *ts,
					uint8_t i);
int scamper_ping_reply_v4ts_hasip(const scamper_ping_reply_v4ts_t *ts);
scamper_addr_t *scamper_ping_reply_v4ts_ip_get(const scamper_ping_reply_v4ts_t *ts, uint8_t i);

void scamper_ping_v4ts_free(scamper_ping_v4ts_t *ts);
uint8_t scamper_ping_v4ts_ipc_get(const scamper_ping_v4ts_t *ts);
scamper_addr_t *scamper_ping_v4ts_ip_get(const scamper_ping_v4ts_t *ts, uint8_t i);

/* routine to return basic stats for the measurement */
scamper_ping_stats_t *scamper_ping_stats_alloc(const scamper_ping_t *ping);
void scamper_ping_stats_free(scamper_ping_stats_t *stats);
uint32_t scamper_ping_stats_nreplies_get(const scamper_ping_stats_t *stats);
uint32_t scamper_ping_stats_ndups_get(const scamper_ping_stats_t *stats);
uint32_t scamper_ping_stats_nloss_get(const scamper_ping_stats_t *stats);
uint32_t scamper_ping_stats_nerrs_get(const scamper_ping_stats_t *stats);
const struct timeval *scamper_ping_stats_min_rtt_get(const scamper_ping_stats_t *stats);
const struct timeval *scamper_ping_stats_max_rtt_get(const scamper_ping_stats_t *stats);
const struct timeval *scamper_ping_stats_avg_rtt_get(const scamper_ping_stats_t *stats);
const struct timeval *scamper_ping_stats_stddev_rtt_get(const scamper_ping_stats_t *stats);

#endif /* __SCAMPER_PING_H */
