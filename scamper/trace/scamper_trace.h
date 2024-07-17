/*
 * scamper_trace.h
 *
 * $Id: scamper_trace.h,v 1.161 2024/03/04 06:59:23 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2008      Alistair King
 * Copyright (C) 2015      The Regents of the University of California
 * Copyright (C) 2015      The University of Waikato
 * Copyright (C) 2019-2023 Matthew Luckie
 *
 * Authors: Matthew Luckie
 *          Doubletree implementation by Alistair King
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

#ifndef __SCAMPER_TRACE_H
#define __SCAMPER_TRACE_H

/*
 * the structures underlying the following typedefs are defined and allocated
 * in scamper_trace_int.h
 *
 * there are get functions below for obtaining values held in those structs.
 * only internal scamper components should include scamper_trace_int.h
 */
typedef struct scamper_trace scamper_trace_t;
typedef struct scamper_trace_hop scamper_trace_hop_t;
typedef struct scamper_trace_pmtud_n scamper_trace_pmtud_n_t;
typedef struct scamper_trace_pmtud scamper_trace_pmtud_t;
typedef struct scamper_trace_dtree scamper_trace_dtree_t;

void scamper_trace_free(scamper_trace_t *trace);
scamper_addr_t *scamper_trace_src_get(const scamper_trace_t *trace);
scamper_addr_t *scamper_trace_dst_get(const scamper_trace_t *trace);
int scamper_trace_dst_is_ipv4(const scamper_trace_t *trace);
scamper_addr_t *scamper_trace_rtr_get(const scamper_trace_t *trace);
scamper_list_t *scamper_trace_list_get(const scamper_trace_t *trace);
scamper_cycle_t *scamper_trace_cycle_get(const scamper_trace_t *trace);
uint32_t scamper_trace_userid_get(const scamper_trace_t *trace);
const struct timeval *scamper_trace_start_get(const scamper_trace_t *trace);
uint8_t scamper_trace_stop_reason_get(const scamper_trace_t *trace);
uint8_t scamper_trace_stop_data_get(const scamper_trace_t *trace);
char *scamper_trace_stop_tostr(const scamper_trace_t *trace,
			       char *buf, size_t len);
scamper_trace_hop_t *scamper_trace_hop_get(const scamper_trace_t *trace,
					   uint8_t i);
uint16_t scamper_trace_hop_count_get(const scamper_trace_t *trace);
uint8_t scamper_trace_stop_hop_get(const scamper_trace_t *trace);

uint8_t scamper_trace_type_get(const scamper_trace_t *trace);
char *scamper_trace_type_tostr(const scamper_trace_t *trace,
			       char *buf, size_t len);

uint8_t scamper_trace_attempts_get(const scamper_trace_t *trace);
uint8_t scamper_trace_hoplimit_get(const scamper_trace_t *trace);
uint8_t scamper_trace_squeries_get(const scamper_trace_t *trace);
uint8_t scamper_trace_gaplimit_get(const scamper_trace_t *trace);
uint8_t scamper_trace_gapaction_get(const scamper_trace_t *trace);
char *scamper_trace_gapaction_tostr(const scamper_trace_t *trace,
				    char *buf, size_t len);
uint8_t scamper_trace_firsthop_get(const scamper_trace_t *trace);
uint8_t scamper_trace_tos_get(const scamper_trace_t *trace);
const struct timeval *scamper_trace_wait_timeout_get(const scamper_trace_t *trace);
const struct timeval *scamper_trace_wait_probe_get(const scamper_trace_t *trace);
uint8_t scamper_trace_loops_get(const scamper_trace_t *trace);
uint8_t scamper_trace_loopaction_get(const scamper_trace_t *trace);
uint8_t scamper_trace_confidence_get(const scamper_trace_t *trace);
uint16_t scamper_trace_probe_size_get(const scamper_trace_t *trace);
uint16_t scamper_trace_sport_get(const scamper_trace_t *trace);
uint16_t scamper_trace_dport_get(const scamper_trace_t *trace);
uint16_t scamper_trace_offset_get(const scamper_trace_t *trace);
uint32_t scamper_trace_flags_get(const scamper_trace_t *trace);
uint16_t scamper_trace_payload_len_get(const scamper_trace_t *trace);
const uint8_t *scamper_trace_payload_get(const scamper_trace_t *trace);
uint16_t scamper_trace_probec_get(const scamper_trace_t *trace);
scamper_trace_hop_t *scamper_trace_lastditch_get(const scamper_trace_t *trace);
int scamper_trace_type_is_udp(const scamper_trace_t *trace);
int scamper_trace_type_is_tcp(const scamper_trace_t *trace);
int scamper_trace_type_is_icmp(const scamper_trace_t *trace);
int scamper_trace_flag_is_icmpcsumdp(const scamper_trace_t *trace);

/* use and free hop structures */
scamper_trace_hop_t *scamper_trace_hop_use(scamper_trace_hop_t *hop);
void scamper_trace_hop_free(scamper_trace_hop_t *hop);

/* sorting order for two hops by their address */
int scamper_trace_hop_addr_cmp(const scamper_trace_hop_t *a,
			       const scamper_trace_hop_t *b);

scamper_addr_t *scamper_trace_hop_addr_get(const scamper_trace_hop_t *hop);
const char *scamper_trace_hop_name_get(const scamper_trace_hop_t *hop);
uint32_t scamper_trace_hop_flags_get(const scamper_trace_hop_t *hop);
const struct timeval *scamper_trace_hop_tx_get(const scamper_trace_hop_t *hop);
const struct timeval *scamper_trace_hop_rtt_get(const scamper_trace_hop_t *hop);
uint8_t scamper_trace_hop_probe_id_get(const scamper_trace_hop_t *hop);
uint8_t scamper_trace_hop_probe_ttl_get(const scamper_trace_hop_t *hop);
uint16_t scamper_trace_hop_probe_size_get(const scamper_trace_hop_t *hop);
uint8_t scamper_trace_hop_reply_ttl_get(const scamper_trace_hop_t *hop);
uint8_t scamper_trace_hop_reply_tos_get(const scamper_trace_hop_t *hop);
uint8_t scamper_trace_hop_icmp_type_get(const scamper_trace_hop_t *hop);
uint8_t scamper_trace_hop_icmp_code_get(const scamper_trace_hop_t *hop);
uint16_t scamper_trace_hop_reply_size_get(const scamper_trace_hop_t *hop);
uint16_t scamper_trace_hop_reply_ipid_get(const scamper_trace_hop_t *hop);
int scamper_trace_hop_is_tcp(const scamper_trace_hop_t *hop);
int scamper_trace_hop_is_icmp(const scamper_trace_hop_t *hop);
int scamper_trace_hop_is_icmp_q(const scamper_trace_hop_t *hop);
int scamper_trace_hop_is_icmp_unreach_port(const scamper_trace_hop_t *hop);
int scamper_trace_hop_is_icmp_echo_reply(const scamper_trace_hop_t *hop);
int scamper_trace_hop_is_icmp_ttl_exp(const scamper_trace_hop_t *hop);
int scamper_trace_hop_is_icmp_ptb(const scamper_trace_hop_t *hop);
uint16_t scamper_trace_hop_icmp_nhmtu_get(const scamper_trace_hop_t *hop);
uint8_t scamper_trace_hop_icmp_q_ttl_get(const scamper_trace_hop_t *hop);
uint8_t scamper_trace_hop_icmp_q_tos_get(const scamper_trace_hop_t *hop);
uint16_t scamper_trace_hop_icmp_q_ipl_get(const scamper_trace_hop_t *hop);
uint8_t scamper_trace_hop_tcp_flags_get(const scamper_trace_hop_t *hop);
scamper_trace_hop_t *scamper_trace_hop_next_get(const scamper_trace_hop_t *hop);

#ifdef __SCAMPER_ICMPEXT_H
scamper_icmpext_t *scamper_trace_hop_icmpext_get(const scamper_trace_hop_t *hop);
#endif

#define SCAMPER_TRACE_STOP_NONE      0x00 /* null reason */
#define SCAMPER_TRACE_STOP_COMPLETED 0x01 /* got an ICMP port unreach */
#define SCAMPER_TRACE_STOP_UNREACH   0x02 /* got an other ICMP unreach code */
#define SCAMPER_TRACE_STOP_ICMP      0x03 /* got an ICMP msg, not unreach */
#define SCAMPER_TRACE_STOP_LOOP      0x04 /* loop detected */
#define SCAMPER_TRACE_STOP_GAPLIMIT  0x05 /* gaplimit reached */
#define SCAMPER_TRACE_STOP_ERROR     0x06 /* sendto error */
#define SCAMPER_TRACE_STOP_HOPLIMIT  0x07 /* hoplimit reached */
#define SCAMPER_TRACE_STOP_GSS       0x08 /* found hop in global stop set */
#define SCAMPER_TRACE_STOP_HALTED    0x09 /* halted */

#define SCAMPER_TRACE_FLAG_ALLATTEMPTS  0x01 /* send all allotted attempts */
#define SCAMPER_TRACE_FLAG_PMTUD        0x02 /* conduct PMTU discovery */
#define SCAMPER_TRACE_FLAG_DL           0x04 /* datalink for TX timestamps */
#define SCAMPER_TRACE_FLAG_IGNORETTLDST 0x08 /* ignore ttl exp. rx f/ dst */
#define SCAMPER_TRACE_FLAG_DOUBLETREE   0x10 /* doubletree */
#define SCAMPER_TRACE_FLAG_ICMPCSUMDP   0x20 /* icmp csum found in dport */
#define SCAMPER_TRACE_FLAG_CONSTPAYLOAD 0x40 /* do not hack payload for csum */
#define SCAMPER_TRACE_FLAG_RXERR        0x80 /* used rxerr socket */
#define SCAMPER_TRACE_FLAG_PTR          0x100 /* do ptr lookups */
#define SCAMPER_TRACE_FLAG_RAW          0x200 /* use raw socket */

#define SCAMPER_TRACE_TYPE_ICMP_ECHO       0x01 /* ICMP echo requests */
#define SCAMPER_TRACE_TYPE_UDP             0x02 /* UDP to unused ports */
#define SCAMPER_TRACE_TYPE_TCP             0x03 /* TCP SYN packets */
#define SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS 0x04 /* paris traceroute */
#define SCAMPER_TRACE_TYPE_UDP_PARIS       0x05 /* paris traceroute */
#define SCAMPER_TRACE_TYPE_TCP_ACK         0x06 /* TCP ACK packets */

#define SCAMPER_TRACE_GAPACTION_STOP      0x01 /* stop when gaplimit reached */
#define SCAMPER_TRACE_GAPACTION_LASTDITCH 0x02 /* send TTL-255 probes */

/*
 * scamper hop flags:
 * these flags give extra meaning to fields found in the hop structure
 * by default.
 */
#define SCAMPER_TRACE_HOP_FLAG_TS_SOCK_RX 0x01 /* socket rx timestamp */
#define SCAMPER_TRACE_HOP_FLAG_TS_DL_TX   0x02 /* datalink tx timestamp */
#define SCAMPER_TRACE_HOP_FLAG_TS_DL_RX   0x04 /* datalink rx timestamp */
#define SCAMPER_TRACE_HOP_FLAG_TS_TSC     0x08 /* rtt computed w/ tsc clock */
#define SCAMPER_TRACE_HOP_FLAG_REPLY_TTL  0x10 /* reply ttl included */
#define SCAMPER_TRACE_HOP_FLAG_TCP        0x20 /* reply is TCP */
#define SCAMPER_TRACE_HOP_FLAG_UDP        0x40 /* reply is UDP */

#define SCAMPER_TRACE_PMTUD_N_TYPE_PTB      1
#define SCAMPER_TRACE_PMTUD_N_TYPE_PTB_BAD  2
#define SCAMPER_TRACE_PMTUD_N_TYPE_SILENCE  3

#define SCAMPER_TRACE_DTREE_FLAG_NOBACK 0x01

/*
 * scamper_trace_pmtud_free:
 *  free the attached pmtud record from the trace structure
 */
void scamper_trace_pmtud_free(scamper_trace_pmtud_t *trace);
scamper_trace_pmtud_t *scamper_trace_pmtud_use(scamper_trace_pmtud_t *pmtud);
scamper_trace_pmtud_t *scamper_trace_pmtud_get(const scamper_trace_t *trace);
uint8_t scamper_trace_pmtud_ver_get(const scamper_trace_pmtud_t *pmtud);
uint16_t scamper_trace_pmtud_pmtu_get(const scamper_trace_pmtud_t *pmtud);
uint16_t scamper_trace_pmtud_ifmtu_get(const scamper_trace_pmtud_t *pmtud);
uint16_t scamper_trace_pmtud_outmtu_get(const scamper_trace_pmtud_t *pmtud);
uint8_t scamper_trace_pmtud_notec_get(const scamper_trace_pmtud_t *pmtud);
scamper_trace_hop_t *
scamper_trace_pmtud_hops_get(const scamper_trace_pmtud_t *pmtud);
scamper_trace_pmtud_n_t *
scamper_trace_pmtud_note_get(const scamper_trace_pmtud_t *pmtud, uint8_t note);

scamper_trace_pmtud_n_t *scamper_trace_pmtud_n_use(scamper_trace_pmtud_n_t *n);
void scamper_trace_pmtud_n_free(scamper_trace_pmtud_n_t *n);
scamper_trace_hop_t *
scamper_trace_pmtud_n_hop_get(const scamper_trace_pmtud_n_t *n);
uint16_t scamper_trace_pmtud_n_nhmtu_get(const scamper_trace_pmtud_n_t *n);
uint8_t scamper_trace_pmtud_n_type_get(const scamper_trace_pmtud_n_t *n);

/*
 * functions for helping with doubletree
 */
scamper_trace_dtree_t *scamper_trace_dtree_use(scamper_trace_dtree_t *dtree);
void scamper_trace_dtree_free(scamper_trace_dtree_t *dtree);
scamper_trace_dtree_t *scamper_trace_dtree_get(const scamper_trace_t *trace);
scamper_trace_dtree_t *scamper_trace_dtree_use(scamper_trace_dtree_t *dtree);
scamper_addr_t *
scamper_trace_dtree_lss_stop_get(const scamper_trace_dtree_t *dt);
scamper_addr_t *
scamper_trace_dtree_gss_stop_get(const scamper_trace_dtree_t *dt);
uint8_t scamper_trace_dtree_firsthop_get(const scamper_trace_dtree_t *dtree);
const char *scamper_trace_dtree_lss_get(const scamper_trace_dtree_t *dtree);


#endif /* __SCAMPER_TRACE_H */
