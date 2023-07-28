/*
 * scamper_dealias.h
 *
 * $Id: scamper_dealias.h,v 1.46 2023/05/29 07:17:30 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012-2013 The Regents of the University of California
 * Copyright (C) 2023      Matthew Luckie
 * Author: Matthew Luckie
 *
 * This code implements alias resolution techniques published by others
 * which require the network to be probed; the author of each technique
 * is detailed with its data structures.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the replye that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef __SCAMPER_DEALIAS_H
#define __SCAMPER_DEALIAS_H

typedef struct scamper_dealias scamper_dealias_t;
typedef struct scamper_dealias_mercator scamper_dealias_mercator_t;
typedef struct scamper_dealias_ally scamper_dealias_ally_t;
typedef struct scamper_dealias_radargun scamper_dealias_radargun_t;
typedef struct scamper_dealias_prefixscan scamper_dealias_prefixscan_t;
typedef struct scamper_dealias_bump scamper_dealias_bump_t;
typedef struct scamper_dealias_probe scamper_dealias_probe_t;
typedef struct scamper_dealias_probedef_udp scamper_dealias_probedef_udp_t;
typedef struct scamper_dealias_probedef_icmp scamper_dealias_probedef_icmp_t;
typedef struct scamper_dealias_probedef_tcp scamper_dealias_probedef_tcp_t;
typedef struct scamper_dealias_probedef scamper_dealias_probedef_t;
typedef struct scamper_dealias_reply scamper_dealias_reply_t;

#define SCAMPER_DEALIAS_METHOD_MERCATOR   1
#define SCAMPER_DEALIAS_METHOD_ALLY       2
#define SCAMPER_DEALIAS_METHOD_RADARGUN   3
#define SCAMPER_DEALIAS_METHOD_PREFIXSCAN 4
#define SCAMPER_DEALIAS_METHOD_BUMP       5

#define SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO     1
#define SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK       2
#define SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP           3
#define SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT 4
#define SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT     5
#define SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_SYN_SPORT 6

#define SCAMPER_DEALIAS_RESULT_NONE       0
#define SCAMPER_DEALIAS_RESULT_ALIASES    1
#define SCAMPER_DEALIAS_RESULT_NOTALIASES 2
#define SCAMPER_DEALIAS_RESULT_HALTED     3
#define SCAMPER_DEALIAS_RESULT_IPIDECHO   4

#define SCAMPER_DEALIAS_ALLY_FLAG_NOBS        1
#define SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE 1
#define SCAMPER_DEALIAS_PREFIXSCAN_FLAG_NOBS  1
#define SCAMPER_DEALIAS_PREFIXSCAN_FLAG_CSA   2

#define SCAMPER_DEALIAS_REPLY_FLAG_IPID32 1

scamper_list_t *scamper_dealias_list_get(const scamper_dealias_t *dealias);
scamper_cycle_t *scamper_dealias_cycle_get(const scamper_dealias_t *dealias);
uint32_t scamper_dealias_userid_get(const scamper_dealias_t *dealias);
const struct timeval *scamper_dealias_start_get(const scamper_dealias_t *dealias);
uint8_t scamper_dealias_method_get(const scamper_dealias_t *dealias);
uint8_t scamper_dealias_result_get(const scamper_dealias_t *dealias);
const scamper_dealias_ally_t *scamper_dealias_ally_get(const scamper_dealias_t *dealias);
const scamper_dealias_mercator_t *scamper_dealias_mercator_get(const scamper_dealias_t *dealias);
const scamper_dealias_radargun_t *scamper_dealias_radargun_get(const scamper_dealias_t *dealias);
const scamper_dealias_prefixscan_t *scamper_dealias_prefixscan_get(const scamper_dealias_t *dealias);
const scamper_dealias_bump_t *scamper_dealias_bump_get(const scamper_dealias_t *dealias);
const scamper_dealias_probe_t *scamper_dealias_probe_get(const scamper_dealias_t *dealias, uint32_t i);
uint32_t scamper_dealias_probec_get(const scamper_dealias_t *dealias);
int scamper_dealias_method_is_prefixscan(const scamper_dealias_t *dealias);
int scamper_dealias_method_is_ally(const scamper_dealias_t *dealias);

const scamper_dealias_probedef_t *scamper_dealias_mercator_def_get(const scamper_dealias_mercator_t *mc);
uint8_t scamper_dealias_mercator_attempts_get(const scamper_dealias_mercator_t *mc);
uint8_t scamper_dealias_mercator_wait_timeout_get(const scamper_dealias_mercator_t *mc);

const scamper_dealias_probedef_t *scamper_dealias_ally_def0_get(const scamper_dealias_ally_t *ally);
const scamper_dealias_probedef_t *scamper_dealias_ally_def1_get(const scamper_dealias_ally_t *ally);
uint16_t scamper_dealias_ally_wait_probe_get(const scamper_dealias_ally_t *ally);
uint8_t scamper_dealias_ally_wait_timeout_get(const scamper_dealias_ally_t *ally);
uint8_t scamper_dealias_ally_attempts_get(const scamper_dealias_ally_t *ally);
uint8_t scamper_dealias_ally_flags_get(const scamper_dealias_ally_t *ally);
uint16_t scamper_dealias_ally_fudge_get(const scamper_dealias_ally_t *ally);
int scamper_dealias_ally_is_nobs(const scamper_dealias_ally_t *ally);

const scamper_dealias_probedef_t *scamper_dealias_radargun_def_get(const scamper_dealias_radargun_t *rg, uint32_t i);
uint32_t scamper_dealias_radargun_defc_get(const scamper_dealias_radargun_t *rg);
uint16_t scamper_dealias_radargun_attempts_get(const scamper_dealias_radargun_t *rg);
uint16_t scamper_dealias_radargun_wait_probe_get(const scamper_dealias_radargun_t *rg);
uint32_t scamper_dealias_radargun_wait_round_get(const scamper_dealias_radargun_t *rg);
uint8_t scamper_dealias_radargun_wait_timeout_get(const scamper_dealias_radargun_t *rg);
uint8_t scamper_dealias_radargun_flags_get(const scamper_dealias_radargun_t *rg);

scamper_addr_t *scamper_dealias_prefixscan_a_get(const scamper_dealias_prefixscan_t *pf);
scamper_addr_t *scamper_dealias_prefixscan_b_get(const scamper_dealias_prefixscan_t *pf);
scamper_addr_t *scamper_dealias_prefixscan_ab_get(const scamper_dealias_prefixscan_t *pf);
scamper_addr_t *scamper_dealias_prefixscan_xs_get(const scamper_dealias_prefixscan_t *pf, uint16_t i);
uint16_t scamper_dealias_prefixscan_xc_get(const scamper_dealias_prefixscan_t *pf);
uint8_t scamper_dealias_prefixscan_prefix_get(const scamper_dealias_prefixscan_t *pf);
uint8_t scamper_dealias_prefixscan_attempts_get(const scamper_dealias_prefixscan_t *pf);
uint8_t scamper_dealias_prefixscan_replyc_get(const scamper_dealias_prefixscan_t *pf);
uint16_t scamper_dealias_prefixscan_fudge_get(const scamper_dealias_prefixscan_t *pf);
uint16_t scamper_dealias_prefixscan_wait_probe_get(const scamper_dealias_prefixscan_t *pf);
uint8_t scamper_dealias_prefixscan_wait_timeout_get(const scamper_dealias_prefixscan_t *pf);
uint8_t scamper_dealias_prefixscan_flags_get(const scamper_dealias_prefixscan_t *pf);
const scamper_dealias_probedef_t *scamper_dealias_prefixscan_def_get(const scamper_dealias_prefixscan_t *pf, uint16_t i);
uint16_t scamper_dealias_prefixscan_defc_get(const scamper_dealias_prefixscan_t *pf);
int scamper_dealias_prefixscan_is_csa(const scamper_dealias_prefixscan_t *pfs);
int scamper_dealias_prefixscan_is_nobs(const scamper_dealias_prefixscan_t *pfs);

const scamper_dealias_probedef_t *scamper_dealias_bump_def0_get(const scamper_dealias_bump_t *bump);
const scamper_dealias_probedef_t *scamper_dealias_bump_def1_get(const scamper_dealias_bump_t *bump);
uint16_t scamper_dealias_bump_wait_probe_get(const scamper_dealias_bump_t *bump);
uint16_t scamper_dealias_bump_limit_get(const scamper_dealias_bump_t *bump);
uint8_t scamper_dealias_bump_attempts_get(const scamper_dealias_bump_t *bump);

const scamper_dealias_probedef_t *scamper_dealias_probe_def_get(const scamper_dealias_probe_t *probe);
uint32_t scamper_dealias_probe_seq_get(const scamper_dealias_probe_t *probe);
const struct timeval *scamper_dealias_probe_tx_get(const scamper_dealias_probe_t *probe);
const scamper_dealias_reply_t *scamper_dealias_probe_reply_get(const scamper_dealias_probe_t *probe, uint16_t i);
uint16_t scamper_dealias_probe_replyc_get(const scamper_dealias_probe_t *probe);
uint16_t scamper_dealias_probe_ipid_get(const scamper_dealias_probe_t *probe);

scamper_addr_t *scamper_dealias_probedef_src_get(const scamper_dealias_probedef_t *pd);
scamper_addr_t *scamper_dealias_probedef_dst_get(const scamper_dealias_probedef_t *pd);
uint32_t scamper_dealias_probedef_id_get(const scamper_dealias_probedef_t *pd);
uint8_t scamper_dealias_probedef_method_get(const scamper_dealias_probedef_t *pd);
int scamper_dealias_probedef_proto_is_udp(const scamper_dealias_probedef_t *pd);
uint8_t scamper_dealias_probedef_ttl_get(const scamper_dealias_probedef_t *pd);
uint8_t scamper_dealias_probedef_tos_get(const scamper_dealias_probedef_t *pd);
uint16_t scamper_dealias_probedef_size_get(const scamper_dealias_probedef_t *pd);
uint16_t scamper_dealias_probedef_mtu_get(const scamper_dealias_probedef_t *pd);
const scamper_dealias_probedef_udp_t *scamper_dealias_probedef_udp_get(const scamper_dealias_probedef_t *pd);
const scamper_dealias_probedef_tcp_t *scamper_dealias_probedef_tcp_get(const scamper_dealias_probedef_t *pd);
const scamper_dealias_probedef_icmp_t *scamper_dealias_probedef_icmp_get(const scamper_dealias_probedef_t *pd);

uint16_t scamper_dealias_probedef_udp_sport_get(const scamper_dealias_probedef_udp_t *udp);
uint16_t scamper_dealias_probedef_udp_dport_get(const scamper_dealias_probedef_udp_t *udp);

uint16_t scamper_dealias_probedef_icmp_csum_get(const scamper_dealias_probedef_icmp_t *icmp);
uint16_t scamper_dealias_probedef_icmp_id_get(const scamper_dealias_probedef_icmp_t *icmp);

uint16_t scamper_dealias_probedef_tcp_sport_get(const scamper_dealias_probedef_tcp_t *tcp);
uint16_t scamper_dealias_probedef_tcp_dport_get(const scamper_dealias_probedef_tcp_t *tcp);
uint8_t scamper_dealias_probedef_tcp_flags_get(const scamper_dealias_probedef_tcp_t *tcp);

scamper_addr_t *scamper_dealias_reply_src_get(const scamper_dealias_reply_t *reply);
const struct timeval *scamper_dealias_reply_rx_get(const scamper_dealias_reply_t *reply);
uint8_t scamper_dealias_reply_flags_get(const scamper_dealias_reply_t *reply);
uint8_t scamper_dealias_reply_proto_get(const scamper_dealias_reply_t *reply);
uint8_t scamper_dealias_reply_ttl_get(const scamper_dealias_reply_t *reply);
uint8_t scamper_dealias_reply_icmp_type_get(const scamper_dealias_reply_t *reply);
uint8_t scamper_dealias_reply_icmp_code_get(const scamper_dealias_reply_t *reply);
uint8_t scamper_dealias_reply_icmp_q_ip_ttl_get(const scamper_dealias_reply_t *reply);
uint8_t scamper_dealias_reply_tcp_flags_get(const scamper_dealias_reply_t *reply);
uint16_t scamper_dealias_reply_ipid_get(const scamper_dealias_reply_t *reply);
uint32_t scamper_dealias_reply_ipid32_get(const scamper_dealias_reply_t *reply);
int scamper_dealias_reply_is_ipid32(const scamper_dealias_reply_t *reply);
int scamper_dealias_reply_is_icmp_unreach_port(const scamper_dealias_reply_t *reply);
int scamper_dealias_reply_is_icmp(const scamper_dealias_reply_t *reply);
int scamper_dealias_reply_is_icmp_unreach(const scamper_dealias_reply_t *reply);
int scamper_dealias_reply_is_icmp_ttl_exp(const scamper_dealias_reply_t *reply);
int scamper_dealias_reply_is_tcp(const scamper_dealias_reply_t *reply);
int scamper_dealias_reply_from_target(const scamper_dealias_probe_t *probe,
				      const scamper_dealias_reply_t *reply);

#ifdef __SCAMPER_ICMPEXT_H
const scamper_icmpext_t *scamper_dealias_reply_icmp_ext_get(const scamper_dealias_reply_t *reply);
#endif

scamper_dealias_t *scamper_dealias_alloc(void);
void scamper_dealias_free(scamper_dealias_t *);

scamper_dealias_probe_t *scamper_dealias_probe_alloc(void);
void scamper_dealias_probe_free(scamper_dealias_probe_t *);

scamper_dealias_probedef_t *scamper_dealias_probedef_alloc(void);
void scamper_dealias_probedef_free(scamper_dealias_probedef_t *);

scamper_dealias_reply_t *scamper_dealias_reply_alloc(void);
void scamper_dealias_reply_free(scamper_dealias_reply_t *);
uint32_t scamper_dealias_reply_count(const scamper_dealias_t *);

const char *scamper_dealias_method_tostr(uint8_t method, char *, size_t);
const char *scamper_dealias_result_tostr(uint8_t result, char *, size_t);
const char *scamper_dealias_probedef_method_tostr(const scamper_dealias_probedef_t *,
						  char *, size_t);

int scamper_dealias_probes_alloc(scamper_dealias_t *, uint32_t);
int scamper_dealias_replies_alloc(scamper_dealias_probe_t *, uint16_t);

/* these functions allow the probes recorded to be ordered to suit */
void scamper_dealias_probes_sort_tx(scamper_dealias_t *);
void scamper_dealias_probes_sort_seq(scamper_dealias_t *);
void scamper_dealias_probes_sort_def(scamper_dealias_t *);

int scamper_dealias_probe_add(scamper_dealias_t *,
			      scamper_dealias_probe_t *);
int scamper_dealias_reply_add(scamper_dealias_probe_t *,
			      scamper_dealias_reply_t *);

int scamper_dealias_ally_alloc(scamper_dealias_t *);
int scamper_dealias_mercator_alloc(scamper_dealias_t *);
int scamper_dealias_radargun_alloc(scamper_dealias_t *);
int scamper_dealias_prefixscan_alloc(scamper_dealias_t *);
int scamper_dealias_bump_alloc(scamper_dealias_t *);

/*
 * scamper_dealias_ipid_inseq
 *
 * convenience function to consider if a sequence of IPIDs are in sequence
 * (given a fudge value).
 *
 * the first two parameters: array of probes and its length.
 * the third parameter:      fudge factor
 * the fourth parameter:     0: no byteswap, 1: byteswap, 2: don't care
 *
 */
int scamper_dealias_ipid_inseq(scamper_dealias_probe_t **, int, uint16_t, int);

int scamper_dealias_prefixscan_xs_add(scamper_dealias_t *, scamper_addr_t *);
int scamper_dealias_prefixscan_xs_in(scamper_dealias_t *, scamper_addr_t *);
int scamper_dealias_prefixscan_xs_alloc(scamper_dealias_prefixscan_t *,
					uint16_t);

int scamper_dealias_prefixscan_probedef_add(scamper_dealias_t *,
					    scamper_dealias_probedef_t *);

int scamper_dealias_prefixscan_probedefs_alloc(scamper_dealias_prefixscan_t *,
					       uint32_t);

int scamper_dealias_radargun_fudge(scamper_dealias_t *,
				   scamper_dealias_probedef_t *,
				   scamper_dealias_probedef_t **, int *, int);

int scamper_dealias_radargun_probedefs_alloc(scamper_dealias_radargun_t *,
					     uint32_t);

#endif /* __SCAMPER_DEALIAS_H */
