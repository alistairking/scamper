/*
 * scamper_ping.h
 *
 * $Id: scamper_ping.h,v 1.88 2025/05/29 07:44:16 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2020-2024 Matthew Luckie
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
typedef struct scamper_ping_probe scamper_ping_probe_t;
typedef struct scamper_ping_reply scamper_ping_reply_t;
typedef struct scamper_ping_reply_v4rr scamper_ping_reply_v4rr_t;
typedef struct scamper_ping_reply_v4ts scamper_ping_reply_v4ts_t;
typedef struct scamper_ping_reply_tsreply scamper_ping_reply_tsreply_t;
typedef struct scamper_ping_stats scamper_ping_stats_t;

#define SCAMPER_PING_STOP_NONE         0 /* null reason */
#define SCAMPER_PING_STOP_COMPLETED    1 /* sent all probes */
#define SCAMPER_PING_STOP_ERROR        2 /* error occured during ping */
#define SCAMPER_PING_STOP_HALTED       3 /* halted */
#define SCAMPER_PING_STOP_INPROGRESS   4 /* measurement in-progress */

#define SCAMPER_PING_REPLY_FLAG_REPLY_TTL  0x01 /* reply ttl included */
#define SCAMPER_PING_REPLY_FLAG_REPLY_IPID 0x02 /* reply ipid included */
#define SCAMPER_PING_REPLY_FLAG_PROBE_IPID 0x04 /* probe ipid included */
#define SCAMPER_PING_REPLY_FLAG_DLTX       0x08 /* datalink tx timestamp */
#define SCAMPER_PING_REPLY_FLAG_DLRX       0x10 /* datalink rx timestamp */
#define SCAMPER_PING_REPLY_FLAG_REPLY_TOS  0x20 /* reply tos included */
#define SCAMPER_PING_REPLY_FLAG_PENDING    0x40 /* no reply, not timed out */

#define SCAMPER_PING_METHOD_ICMP_ECHO     0
#define SCAMPER_PING_METHOD_TCP_ACK       1
#define SCAMPER_PING_METHOD_TCP_ACK_SPORT 2
#define SCAMPER_PING_METHOD_UDP           3
#define SCAMPER_PING_METHOD_UDP_DPORT     4
#define SCAMPER_PING_METHOD_ICMP_TIME     5
#define SCAMPER_PING_METHOD_TCP_SYN       6
#define SCAMPER_PING_METHOD_TCP_SYNACK    7
#define SCAMPER_PING_METHOD_TCP_RST       8
#define SCAMPER_PING_METHOD_TCP_SYN_SPORT 9
#define SCAMPER_PING_METHOD_UDP_SPORT     10

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
#define SCAMPER_PING_FLAG_SOCKRX          0x400 /* -O sockrx: rx from socket */
#define SCAMPER_PING_FLAG_DLTX            0x800 /* -O dltx: use dl to tx */

char *scamper_ping_tojson(const scamper_ping_t *ping, size_t *len);
char *scamper_ping_totext(const scamper_ping_t *ping, size_t *len);

/* basic routines to use and free scamper_ping structures */
scamper_ping_t *scamper_ping_dup(const scamper_ping_t *ping);
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
char *scamper_ping_stop_tostr(const scamper_ping_t *ping,char *buf,size_t len);
const uint8_t *scamper_ping_data_get(const scamper_ping_t *ping);
uint16_t scamper_ping_datalen_get(const scamper_ping_t *ping);
uint16_t scamper_ping_attempts_get(const scamper_ping_t *ping);
uint16_t scamper_ping_pktsize_get(const scamper_ping_t *ping);
uint8_t scamper_ping_method_get(const scamper_ping_t *ping);
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
uint8_t scamper_ping_ttl_get(const scamper_ping_t *ping);
uint8_t scamper_ping_tos_get(const scamper_ping_t *ping);
uint16_t scamper_ping_sport_get(const scamper_ping_t *ping);
uint16_t scamper_ping_dport_get(const scamper_ping_t *ping);
uint16_t scamper_ping_icmpsum_get(const scamper_ping_t *ping);
uint32_t scamper_ping_tcpseq_get(const scamper_ping_t *ping);
uint32_t scamper_ping_tcpack_get(const scamper_ping_t *ping);
uint16_t scamper_ping_tcpmss_get(const scamper_ping_t *ping);
scamper_ping_v4ts_t *scamper_ping_tsps_get(const scamper_ping_t *ping);
uint32_t scamper_ping_flags_get(const scamper_ping_t *ping);
uint16_t scamper_ping_stop_count_get(const scamper_ping_t *ping);
uint16_t scamper_ping_pmtu_get(const scamper_ping_t *ping);
uint16_t scamper_ping_sent_get(const scamper_ping_t *ping);
scamper_ping_probe_t *scamper_ping_probe_get(const scamper_ping_t *ping,
					     uint16_t i);

scamper_ping_probe_t *scamper_ping_probe_use(scamper_ping_probe_t *probe);
scamper_ping_probe_t *scamper_ping_probe_dup(const scamper_ping_probe_t *probe);
void scamper_ping_probe_free(scamper_ping_probe_t *probe);
uint16_t scamper_ping_probe_id_get(const scamper_ping_probe_t *probe);
uint16_t scamper_ping_probe_ipid_get(const scamper_ping_probe_t *probe);
uint16_t scamper_ping_probe_sport_get(const scamper_ping_probe_t *probe);
uint8_t scamper_ping_probe_flags_get(const scamper_ping_probe_t *probe);
const struct timeval *scamper_ping_probe_tx_get(const scamper_ping_probe_t *probe);
scamper_ping_reply_t *scamper_ping_probe_reply_get(const scamper_ping_probe_t *probe, uint16_t i);
uint16_t scamper_ping_probe_replyc_get(const scamper_ping_probe_t *probe);

/* basic routines to use and free scamper_ping_reply structures */
scamper_ping_reply_t *scamper_ping_reply_use(scamper_ping_reply_t *reply);
scamper_ping_reply_t *scamper_ping_reply_dup(const scamper_ping_reply_t *reply);
void scamper_ping_reply_free(scamper_ping_reply_t *reply);

/* get methods for accessing ping reply structure variables */
int scamper_ping_reply_is_from_target(const scamper_ping_t *ping,
				      const scamper_ping_reply_t *reply);
scamper_addr_t *scamper_ping_reply_addr_get(const scamper_ping_reply_t *reply);
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
uint16_t scamper_ping_reply_icmp_nhmtu_get(const scamper_ping_reply_t *reply);
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
int scamper_ping_reply_is_icmp_ptb(const scamper_ping_reply_t *reply);
const struct timeval *scamper_ping_reply_rtt_get(const scamper_ping_reply_t *reply);
scamper_ping_reply_v4rr_t *scamper_ping_reply_v4rr_get(const scamper_ping_reply_t *reply);
scamper_ping_reply_v4ts_t *scamper_ping_reply_v4ts_get(const scamper_ping_reply_t *reply);
scamper_ping_reply_tsreply_t *scamper_ping_reply_tsreply_get(const scamper_ping_reply_t *reply);

void scamper_ping_reply_tsreply_free(scamper_ping_reply_tsreply_t *tsr);
uint32_t scamper_ping_reply_tsreply_tso_get(const scamper_ping_reply_tsreply_t *tsr);
uint32_t scamper_ping_reply_tsreply_tsr_get(const scamper_ping_reply_tsreply_t *tsr);
uint32_t scamper_ping_reply_tsreply_tst_get(const scamper_ping_reply_tsreply_t *tsr);

scamper_ping_reply_v4rr_t *scamper_ping_reply_v4rr_dup(const scamper_ping_reply_v4rr_t *rr);
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
