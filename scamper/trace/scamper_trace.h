/*
 * scamper_trace.h
 *
 * $Id: scamper_trace.h,v 1.176 2025/05/04 23:58:33 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2008      Alistair King
 * Copyright (C) 2015      The Regents of the University of California
 * Copyright (C) 2015      The University of Waikato
 * Copyright (C) 2019-2025 Matthew Luckie
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

#define SCAMPER_TRACE_STOP_NONE         0 /* null reason */
#define SCAMPER_TRACE_STOP_COMPLETED    1 /* got an ICMP port unreach */
#define SCAMPER_TRACE_STOP_UNREACH      2 /* got an other ICMP unreach code */
#define SCAMPER_TRACE_STOP_ICMP         3 /* got an ICMP msg, not unreach */
#define SCAMPER_TRACE_STOP_LOOP         4 /* loop detected */
#define SCAMPER_TRACE_STOP_GAPLIMIT     5 /* gaplimit reached */
#define SCAMPER_TRACE_STOP_ERROR        6 /* sendto error */
#define SCAMPER_TRACE_STOP_HOPLIMIT     7 /* hoplimit reached */
#define SCAMPER_TRACE_STOP_GSS          8 /* found hop in global stop set */
#define SCAMPER_TRACE_STOP_HALTED       9 /* halted */

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
 * scamper reply flags:
 * these flags give extra meaning to fields found in the reply structure
 */
#define SCAMPER_TRACE_REPLY_FLAG_TS_SOCK_RX 0x01 /* socket rx timestamp */
#define SCAMPER_TRACE_REPLY_FLAG_TS_DL_TX   0x02 /* datalink tx timestamp */
#define SCAMPER_TRACE_REPLY_FLAG_TS_DL_RX   0x04 /* datalink rx timestamp */
#define SCAMPER_TRACE_REPLY_FLAG_REPLY_TTL  0x10 /* reply ttl included */
#define SCAMPER_TRACE_REPLY_FLAG_TCP        0x20 /* reply is TCP */
#define SCAMPER_TRACE_REPLY_FLAG_UDP        0x40 /* reply is UDP */

#define SCAMPER_TRACE_PMTUD_NOTE_TYPE_PTB      1
#define SCAMPER_TRACE_PMTUD_NOTE_TYPE_PTB_BAD  2
#define SCAMPER_TRACE_PMTUD_NOTE_TYPE_SILENCE  3

#define SCAMPER_TRACE_DTREE_FLAG_NOBACK 0x01

/*
 * the structures underlying the following typedefs are defined and allocated
 * in scamper_trace_int.h
 *
 * there are get functions below for obtaining values held in those structs.
 * only internal scamper components should include scamper_trace_int.h
 */
typedef struct scamper_trace scamper_trace_t;
typedef struct scamper_trace_probe scamper_trace_probe_t;
typedef struct scamper_trace_probettl scamper_trace_probettl_t;
typedef struct scamper_trace_reply scamper_trace_reply_t;
typedef struct scamper_trace_pmtud_note scamper_trace_pmtud_note_t;
typedef struct scamper_trace_pmtud scamper_trace_pmtud_t;
typedef struct scamper_trace_dtree scamper_trace_dtree_t;
typedef struct scamper_trace_lastditch scamper_trace_lastditch_t;
typedef struct scamper_trace_hopiter scamper_trace_hopiter_t;

char *scamper_trace_tojson(const scamper_trace_t *trace, size_t *len);

scamper_trace_t *scamper_trace_dup(scamper_trace_t *trace);
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
scamper_trace_probettl_t *scamper_trace_probettl_get(const scamper_trace_t *trace, uint8_t i);
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
uint16_t scamper_trace_size_get(const scamper_trace_t *trace);
uint16_t scamper_trace_sport_get(const scamper_trace_t *trace);
uint16_t scamper_trace_dport_get(const scamper_trace_t *trace);
uint16_t scamper_trace_offset_get(const scamper_trace_t *trace);
uint32_t scamper_trace_flags_get(const scamper_trace_t *trace);
uint16_t scamper_trace_payload_len_get(const scamper_trace_t *trace);
const uint8_t *scamper_trace_payload_get(const scamper_trace_t *trace);
uint16_t scamper_trace_probec_get(const scamper_trace_t *trace);
int scamper_trace_type_is_udp(const scamper_trace_t *trace);
int scamper_trace_type_is_tcp(const scamper_trace_t *trace);
int scamper_trace_type_is_icmp(const scamper_trace_t *trace);
int scamper_trace_flag_is_icmpcsumdp(const scamper_trace_t *trace);

scamper_trace_probe_t *scamper_trace_probettl_probe_get(const scamper_trace_probettl_t *pttl, uint8_t i);
uint8_t scamper_trace_probettl_probec_get(const scamper_trace_probettl_t *pttl);
scamper_trace_reply_t *scamper_trace_probettl_reply_get(const scamper_trace_probettl_t *pttl);

/*
 * functions for interacting with traceroute probe structures
 */
scamper_trace_probe_t *scamper_trace_probe_dup(const scamper_trace_probe_t *probe);
scamper_trace_probe_t *scamper_trace_probe_use(scamper_trace_probe_t *probe);
uint16_t scamper_trace_probe_replyc_get(const scamper_trace_probe_t *probe);
void scamper_trace_probe_free(scamper_trace_probe_t *probe);
scamper_trace_reply_t *scamper_trace_probe_reply_get(const scamper_trace_probe_t *probe, uint16_t i);
int scamper_trace_probe_reply_add(scamper_trace_probe_t *probe,
				  scamper_trace_reply_t *reply);
const struct timeval *scamper_trace_probe_tx_get(const scamper_trace_probe_t *probe);
uint8_t scamper_trace_probe_id_get(const scamper_trace_probe_t *probe);
uint8_t scamper_trace_probe_ttl_get(const scamper_trace_probe_t *probe);
uint16_t scamper_trace_probe_size_get(const scamper_trace_probe_t *probe);

/* use and free reply structures */
scamper_trace_reply_t *scamper_trace_reply_dup(const scamper_trace_reply_t *reply);
scamper_trace_reply_t *scamper_trace_reply_use(scamper_trace_reply_t *reply);
void scamper_trace_reply_free(scamper_trace_reply_t *reply);

/* sorting order for two replies by their address */
int scamper_trace_reply_addr_cmp(const scamper_trace_reply_t *a,
				 const scamper_trace_reply_t *b);

scamper_addr_t *scamper_trace_reply_addr_get(const scamper_trace_reply_t *reply);
const char *scamper_trace_reply_name_get(const scamper_trace_reply_t *reply);
uint32_t scamper_trace_reply_flags_get(const scamper_trace_reply_t *reply);

const struct timeval *scamper_trace_reply_rtt_get(const scamper_trace_reply_t *reply);

uint8_t scamper_trace_reply_ttl_get(const scamper_trace_reply_t *reply);
uint8_t scamper_trace_reply_tos_get(const scamper_trace_reply_t *reply);
uint8_t scamper_trace_reply_icmp_type_get(const scamper_trace_reply_t *reply);
uint8_t scamper_trace_reply_icmp_code_get(const scamper_trace_reply_t *reply);
uint16_t scamper_trace_reply_size_get(const scamper_trace_reply_t *reply);
uint16_t scamper_trace_reply_ipid_get(const scamper_trace_reply_t *reply);
int scamper_trace_reply_is_tcp(const scamper_trace_reply_t *reply);
int scamper_trace_reply_is_icmp(const scamper_trace_reply_t *reply);
int scamper_trace_reply_is_icmp_q(const scamper_trace_reply_t *reply);
int scamper_trace_reply_is_icmp_unreach_port(const scamper_trace_reply_t *reply);
int scamper_trace_reply_is_icmp_echo_reply(const scamper_trace_reply_t *reply);
int scamper_trace_reply_is_icmp_ttl_exp(const scamper_trace_reply_t *reply);
int scamper_trace_reply_is_icmp_ptb(const scamper_trace_reply_t *reply);
uint16_t scamper_trace_reply_icmp_nhmtu_get(const scamper_trace_reply_t *reply);
uint8_t scamper_trace_reply_icmp_q_ttl_get(const scamper_trace_reply_t *reply);
uint8_t scamper_trace_reply_icmp_q_tos_get(const scamper_trace_reply_t *reply);
uint16_t scamper_trace_reply_icmp_q_ipl_get(const scamper_trace_reply_t *reply);
uint8_t scamper_trace_reply_tcp_flags_get(const scamper_trace_reply_t *reply);

#ifdef __SCAMPER_ICMPEXT_H
scamper_icmpexts_t *
scamper_trace_reply_icmp_exts_get(const scamper_trace_reply_t *reply);
#endif

/*
 * functions for processing pmtud data
 */
void scamper_trace_pmtud_free(scamper_trace_pmtud_t *pmtud);
scamper_trace_pmtud_t *scamper_trace_pmtud_use(scamper_trace_pmtud_t *pmtud);
scamper_trace_pmtud_t *scamper_trace_pmtud_get(const scamper_trace_t *trace);
uint8_t scamper_trace_pmtud_ver_get(const scamper_trace_pmtud_t *pmtud);
uint16_t scamper_trace_pmtud_pmtu_get(const scamper_trace_pmtud_t *pmtud);
uint16_t scamper_trace_pmtud_ifmtu_get(const scamper_trace_pmtud_t *pmtud);
uint16_t scamper_trace_pmtud_outmtu_get(const scamper_trace_pmtud_t *pmtud);
uint8_t scamper_trace_pmtud_notec_get(const scamper_trace_pmtud_t *pmtud);
scamper_trace_pmtud_note_t *
scamper_trace_pmtud_note_get(const scamper_trace_pmtud_t *pmtud, uint8_t note);
uint16_t scamper_trace_pmtud_probec_get(const scamper_trace_pmtud_t *pmtud);
scamper_trace_probe_t *
scamper_trace_pmtud_probe_get(const scamper_trace_pmtud_t *pmtud, uint16_t p);

scamper_trace_pmtud_note_t *
scamper_trace_pmtud_note_use(scamper_trace_pmtud_note_t *n);
void scamper_trace_pmtud_note_free(scamper_trace_pmtud_note_t *n);
scamper_trace_probe_t *
scamper_trace_pmtud_note_probe_get(const scamper_trace_pmtud_note_t *n);
scamper_trace_reply_t *
scamper_trace_pmtud_note_reply_get(const scamper_trace_pmtud_note_t *n);
uint16_t scamper_trace_pmtud_note_nhmtu_get(const scamper_trace_pmtud_note_t *n);
uint8_t scamper_trace_pmtud_note_type_get(const scamper_trace_pmtud_note_t *n);
char *scamper_trace_pmtud_note_type_tostr(const scamper_trace_pmtud_note_t *n,
					  char *buf, size_t len);

/*
 * functions for processing last-ditch probing data
 */
void scamper_trace_lastditch_free(scamper_trace_lastditch_t *ld);
scamper_trace_lastditch_t *scamper_trace_lastditch_use(scamper_trace_lastditch_t *ld);
scamper_trace_lastditch_t *
scamper_trace_lastditch_get(const scamper_trace_t *trace);
uint8_t scamper_trace_lastditch_probec_get(const scamper_trace_lastditch_t *ld);
scamper_trace_probe_t *
scamper_trace_lastditch_probe_get(const scamper_trace_lastditch_t *ld, uint8_t p);

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

/*
 * functions for iterating through replies in a traceroute
 */
scamper_trace_hopiter_t *scamper_trace_hopiter_alloc(void);
void scamper_trace_hopiter_free(scamper_trace_hopiter_t *hi);
void scamper_trace_hopiter_reset(scamper_trace_hopiter_t *hi);
int scamper_trace_hopiter_ttl_set(scamper_trace_hopiter_t *hi,
				  uint8_t ttl, uint8_t max);
scamper_trace_probe_t *
scamper_trace_hopiter_probe_get(const scamper_trace_hopiter_t *hi);

scamper_trace_reply_t *
scamper_trace_hopiter_next(const scamper_trace_t *trace,
			   scamper_trace_hopiter_t *hi);
scamper_trace_reply_t *
scamper_trace_lastditch_hopiter_next(const scamper_trace_lastditch_t *ld,
				     scamper_trace_hopiter_t *hi);
scamper_trace_reply_t *
scamper_trace_pmtud_hopiter_next(const scamper_trace_pmtud_t *pmtud,
				 scamper_trace_hopiter_t *hi);

#endif /* __SCAMPER_TRACE_H */
