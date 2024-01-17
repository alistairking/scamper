/*
 * scamper_dealias.h
 *
 * $Id: scamper_dealias.h,v 1.69 2024/01/16 06:55:18 mjl Exp $
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
typedef struct scamper_dealias_midarest scamper_dealias_midarest_t;
typedef struct scamper_dealias_midardisc scamper_dealias_midardisc_t;
typedef struct scamper_dealias_midardisc_round scamper_dealias_midardisc_round_t;
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
#define SCAMPER_DEALIAS_METHOD_MIDAREST   6
#define SCAMPER_DEALIAS_METHOD_MIDARDISC  7
#define SCAMPER_DEALIAS_METHOD_MAX        7

#define SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO     1
#define SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK       2
#define SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP           3
#define SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT 4
#define SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT     5
#define SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_SYN_SPORT 6
#define SCAMPER_DEALIAS_PROBEDEF_METHOD_MAX           6

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

/* get basic properties of the alias resolution method */
scamper_list_t *scamper_dealias_list_get(const scamper_dealias_t *dealias);
scamper_cycle_t *scamper_dealias_cycle_get(const scamper_dealias_t *dealias);
uint32_t scamper_dealias_userid_get(const scamper_dealias_t *dealias);
const struct timeval *scamper_dealias_start_get(const scamper_dealias_t *dealias);
uint32_t scamper_dealias_probec_get(const scamper_dealias_t *dealias);
scamper_dealias_probe_t *scamper_dealias_probe_get(const scamper_dealias_t *dealias, uint32_t i);

/* get the individual data structures specific to a given method */
scamper_dealias_ally_t *scamper_dealias_ally_get(const scamper_dealias_t *dealias);
scamper_dealias_mercator_t *scamper_dealias_mercator_get(const scamper_dealias_t *dealias);
scamper_dealias_radargun_t *scamper_dealias_radargun_get(const scamper_dealias_t *dealias);
scamper_dealias_prefixscan_t *scamper_dealias_prefixscan_get(const scamper_dealias_t *dealias);
scamper_dealias_bump_t *scamper_dealias_bump_get(const scamper_dealias_t *dealias);
scamper_dealias_midarest_t *scamper_dealias_midarest_get(const scamper_dealias_t *dealias);
scamper_dealias_midardisc_t *scamper_dealias_midardisc_get(const scamper_dealias_t *dealias);

/* functions to determine the type of alias resolution */
uint8_t scamper_dealias_method_get(const scamper_dealias_t *dealias);
int scamper_dealias_method_is_mercator(const scamper_dealias_t *dealias);
int scamper_dealias_method_is_ally(const scamper_dealias_t *dealias);
int scamper_dealias_method_is_prefixscan(const scamper_dealias_t *dealias);
int scamper_dealias_method_is_radargun(const scamper_dealias_t *dealias);
int scamper_dealias_method_is_bump(const scamper_dealias_t *dealias);
int scamper_dealias_method_is_midarest(const scamper_dealias_t *dealias);
int scamper_dealias_method_is_midardisc(const scamper_dealias_t *dealias);

/* functions to determine the result of the method */
uint8_t scamper_dealias_result_get(const scamper_dealias_t *dealias);
int scamper_dealias_result_is_aliases(const scamper_dealias_t *dealias);

/* functions to get properties of a mercator alias resolution */
scamper_dealias_probedef_t *scamper_dealias_mercator_def_get(const scamper_dealias_mercator_t *mc);
uint8_t scamper_dealias_mercator_attempts_get(const scamper_dealias_mercator_t *mc);
const struct timeval *scamper_dealias_mercator_wait_timeout_get(const scamper_dealias_mercator_t *mc);

/* functions to get properties of a ally alias resolution */
scamper_dealias_probedef_t *scamper_dealias_ally_def0_get(const scamper_dealias_ally_t *ally);
scamper_dealias_probedef_t *scamper_dealias_ally_def1_get(const scamper_dealias_ally_t *ally);
const struct timeval *scamper_dealias_ally_wait_probe_get(const scamper_dealias_ally_t *ally);
const struct timeval *scamper_dealias_ally_wait_timeout_get(const scamper_dealias_ally_t *ally);
uint8_t scamper_dealias_ally_attempts_get(const scamper_dealias_ally_t *ally);
uint8_t scamper_dealias_ally_flags_get(const scamper_dealias_ally_t *ally);
uint16_t scamper_dealias_ally_fudge_get(const scamper_dealias_ally_t *ally);
int scamper_dealias_ally_is_nobs(const scamper_dealias_ally_t *ally);

/* functions to get properties of a radargun alias resolution */
scamper_dealias_probedef_t *scamper_dealias_radargun_def_get(const scamper_dealias_radargun_t *rg, uint32_t i);
uint32_t scamper_dealias_radargun_defc_get(const scamper_dealias_radargun_t *rg);
uint16_t scamper_dealias_radargun_rounds_get(const scamper_dealias_radargun_t *rg);
const struct timeval *scamper_dealias_radargun_wait_probe_get(const scamper_dealias_radargun_t *rg);
const struct timeval *scamper_dealias_radargun_wait_round_get(const scamper_dealias_radargun_t *rg);
const struct timeval *scamper_dealias_radargun_wait_timeout_get(const scamper_dealias_radargun_t *rg);
uint8_t scamper_dealias_radargun_flags_get(const scamper_dealias_radargun_t *rg);

/* functions to get properties of a prefixscan alias resolution */
scamper_addr_t *scamper_dealias_prefixscan_a_get(const scamper_dealias_prefixscan_t *pf);
scamper_addr_t *scamper_dealias_prefixscan_b_get(const scamper_dealias_prefixscan_t *pf);
scamper_addr_t *scamper_dealias_prefixscan_ab_get(const scamper_dealias_prefixscan_t *pf);
scamper_addr_t *scamper_dealias_prefixscan_xs_get(const scamper_dealias_prefixscan_t *pf, uint16_t i);
uint16_t scamper_dealias_prefixscan_xc_get(const scamper_dealias_prefixscan_t *pf);
uint8_t scamper_dealias_prefixscan_prefix_get(const scamper_dealias_prefixscan_t *pf);
uint8_t scamper_dealias_prefixscan_attempts_get(const scamper_dealias_prefixscan_t *pf);
uint8_t scamper_dealias_prefixscan_replyc_get(const scamper_dealias_prefixscan_t *pf);
uint16_t scamper_dealias_prefixscan_fudge_get(const scamper_dealias_prefixscan_t *pf);
const struct timeval *scamper_dealias_prefixscan_wait_probe_get(const scamper_dealias_prefixscan_t *pf);
const struct timeval *scamper_dealias_prefixscan_wait_timeout_get(const scamper_dealias_prefixscan_t *pf);
uint8_t scamper_dealias_prefixscan_flags_get(const scamper_dealias_prefixscan_t *pf);
scamper_dealias_probedef_t *scamper_dealias_prefixscan_def_get(const scamper_dealias_prefixscan_t *pf, uint16_t i);
uint16_t scamper_dealias_prefixscan_defc_get(const scamper_dealias_prefixscan_t *pf);
int scamper_dealias_prefixscan_is_csa(const scamper_dealias_prefixscan_t *pfs);
int scamper_dealias_prefixscan_is_nobs(const scamper_dealias_prefixscan_t *pfs);

/* functions to get properties of a bump alias resolution */
scamper_dealias_probedef_t *scamper_dealias_bump_def0_get(const scamper_dealias_bump_t *bump);
scamper_dealias_probedef_t *scamper_dealias_bump_def1_get(const scamper_dealias_bump_t *bump);
const struct timeval *scamper_dealias_bump_wait_probe_get(const scamper_dealias_bump_t *bump);
uint16_t scamper_dealias_bump_limit_get(const scamper_dealias_bump_t *bump);
uint8_t scamper_dealias_bump_attempts_get(const scamper_dealias_bump_t *bump);

/* functions to get properties of midarest alias resolution */
scamper_dealias_probedef_t *scamper_dealias_midarest_def_get(const scamper_dealias_midarest_t *me, uint16_t i);
uint16_t scamper_dealias_midarest_defc_get(const scamper_dealias_midarest_t *me);
uint8_t scamper_dealias_midarest_rounds_get(const scamper_dealias_midarest_t *me);
const struct timeval *scamper_dealias_midarest_wait_probe_get(const scamper_dealias_midarest_t *me);
const struct timeval *scamper_dealias_midarest_wait_round_get(const scamper_dealias_midarest_t *me);
const struct timeval *scamper_dealias_midarest_wait_timeout_get(const scamper_dealias_midarest_t *me);

/* functions to get properties of midardisc alias resolution */
const struct timeval *scamper_dealias_midardisc_startat_get(const scamper_dealias_midardisc_t *md);
const struct timeval *scamper_dealias_midardisc_wait_timeout_get(const scamper_dealias_midardisc_t *md);
uint32_t scamper_dealias_midardisc_defc_get(const scamper_dealias_midardisc_t *md);
scamper_dealias_probedef_t *scamper_dealias_midardisc_def_get(const scamper_dealias_midardisc_t *md, uint32_t i);
uint32_t scamper_dealias_midardisc_schedc_get(const scamper_dealias_midardisc_t *md);
scamper_dealias_midardisc_round_t *scamper_dealias_midardisc_sched_get(const scamper_dealias_midardisc_t *md, uint32_t i);

/* functions to get and set properties of a midardisc round */
scamper_dealias_midardisc_round_t *scamper_dealias_midardisc_round_alloc(void);
void scamper_dealias_midardisc_round_begin_set(scamper_dealias_midardisc_round_t *r, uint32_t begin);
void scamper_dealias_midardisc_round_end_set(scamper_dealias_midardisc_round_t *r, uint32_t end);
void scamper_dealias_midardisc_round_start_set(scamper_dealias_midardisc_round_t *r, const struct timeval *start);
uint32_t scamper_dealias_midardisc_round_begin_get(const scamper_dealias_midardisc_round_t *r);
uint32_t scamper_dealias_midardisc_round_end_get(const scamper_dealias_midardisc_round_t *r);
const struct timeval *scamper_dealias_midardisc_round_start_get(const scamper_dealias_midardisc_round_t *r);

scamper_dealias_probedef_t *scamper_dealias_probe_def_get(const scamper_dealias_probe_t *probe);
uint32_t scamper_dealias_probe_seq_get(const scamper_dealias_probe_t *probe);
const struct timeval *scamper_dealias_probe_tx_get(const scamper_dealias_probe_t *probe);
scamper_dealias_reply_t *scamper_dealias_probe_reply_get(const scamper_dealias_probe_t *probe, uint16_t i);
uint16_t scamper_dealias_probe_replyc_get(const scamper_dealias_probe_t *probe);
uint16_t scamper_dealias_probe_ipid_get(const scamper_dealias_probe_t *probe);

scamper_dealias_probedef_t *scamper_dealias_probedef_alloc(void);
int scamper_dealias_probedef_method_set(scamper_dealias_probedef_t *pd, const char *meth);
int scamper_dealias_probedef_src_set(scamper_dealias_probedef_t *pd, scamper_addr_t *src);
int scamper_dealias_probedef_dst_set(scamper_dealias_probedef_t *pd, scamper_addr_t *dst);
void scamper_dealias_probedef_ttl_set(scamper_dealias_probedef_t *pd, uint8_t ttl);
void scamper_dealias_probedef_tos_set(scamper_dealias_probedef_t *pd, uint8_t tos);
void scamper_dealias_probedef_size_set(scamper_dealias_probedef_t *pd, uint16_t size);
void scamper_dealias_probedef_mtu_set(scamper_dealias_probedef_t *pd, uint16_t mtu);
void scamper_dealias_probedef_icmp_csum_set(scamper_dealias_probedef_icmp_t *icmp, uint16_t cs);
void scamper_dealias_probedef_icmp_id_set(scamper_dealias_probedef_icmp_t *icmp, uint16_t id);
void scamper_dealias_probedef_udp_sport_set(scamper_dealias_probedef_udp_t *udp, uint16_t sp);
void scamper_dealias_probedef_udp_dport_set(scamper_dealias_probedef_udp_t *udp, uint16_t dp);
void scamper_dealias_probedef_tcp_sport_set(scamper_dealias_probedef_tcp_t *tcp, uint16_t sp);
void scamper_dealias_probedef_tcp_dport_set(scamper_dealias_probedef_tcp_t *tcp, uint16_t dp);

scamper_addr_t *scamper_dealias_probedef_src_get(const scamper_dealias_probedef_t *pd);
scamper_addr_t *scamper_dealias_probedef_dst_get(const scamper_dealias_probedef_t *pd);
uint32_t scamper_dealias_probedef_id_get(const scamper_dealias_probedef_t *pd);
uint8_t scamper_dealias_probedef_method_get(const scamper_dealias_probedef_t *pd);
int scamper_dealias_probedef_method_fromstr(const char *str, uint8_t *meth);
int scamper_dealias_probedef_is_udp(const scamper_dealias_probedef_t *pd);
int scamper_dealias_probedef_is_icmp(const scamper_dealias_probedef_t *pd);
int scamper_dealias_probedef_is_tcp(const scamper_dealias_probedef_t *pd);
uint8_t scamper_dealias_probedef_ttl_get(const scamper_dealias_probedef_t *pd);
uint8_t scamper_dealias_probedef_tos_get(const scamper_dealias_probedef_t *pd);
uint16_t scamper_dealias_probedef_size_get(const scamper_dealias_probedef_t *pd);
uint16_t scamper_dealias_probedef_mtu_get(const scamper_dealias_probedef_t *pd);
scamper_dealias_probedef_udp_t *scamper_dealias_probedef_udp_get(const scamper_dealias_probedef_t *pd);
scamper_dealias_probedef_tcp_t *scamper_dealias_probedef_tcp_get(const scamper_dealias_probedef_t *pd);
scamper_dealias_probedef_icmp_t *scamper_dealias_probedef_icmp_get(const scamper_dealias_probedef_t *pd);

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
uint16_t scamper_dealias_reply_size_get(const scamper_dealias_reply_t *reply);

int scamper_dealias_reply_is_icmp(const scamper_dealias_reply_t *reply);
uint8_t scamper_dealias_reply_icmp_type_get(const scamper_dealias_reply_t *reply);
uint8_t scamper_dealias_reply_icmp_code_get(const scamper_dealias_reply_t *reply);
int scamper_dealias_reply_is_icmp_q(const scamper_dealias_reply_t *reply);
uint8_t scamper_dealias_reply_icmp_q_ttl_get(const scamper_dealias_reply_t *reply);
int scamper_dealias_reply_is_ipid32(const scamper_dealias_reply_t *reply);
uint16_t scamper_dealias_reply_ipid_get(const scamper_dealias_reply_t *reply);
uint32_t scamper_dealias_reply_ipid32_get(const scamper_dealias_reply_t *reply);
int scamper_dealias_reply_is_icmp_unreach(const scamper_dealias_reply_t *reply);
int scamper_dealias_reply_is_icmp_unreach_port(const scamper_dealias_reply_t *reply);
int scamper_dealias_reply_is_icmp_ttl_exp(const scamper_dealias_reply_t *reply);
int scamper_dealias_reply_is_tcp(const scamper_dealias_reply_t *reply);
uint8_t scamper_dealias_reply_tcp_flags_get(const scamper_dealias_reply_t *reply);
int scamper_dealias_reply_from_target(const scamper_dealias_probe_t *probe,
				      const scamper_dealias_reply_t *reply);

#ifdef __SCAMPER_ICMPEXT_H
scamper_icmpext_t *scamper_dealias_reply_icmp_ext_get(const scamper_dealias_reply_t *reply);
#endif

void scamper_dealias_free(scamper_dealias_t *dealias);

scamper_dealias_probe_t *scamper_dealias_probe_use(scamper_dealias_probe_t *probe);
void scamper_dealias_probe_free(scamper_dealias_probe_t *probe);

scamper_dealias_probedef_t *scamper_dealias_probedef_use(scamper_dealias_probedef_t *pd);
void scamper_dealias_probedef_free(scamper_dealias_probedef_t *pd);

scamper_dealias_reply_t *scamper_dealias_reply_use(scamper_dealias_reply_t *reply);
void scamper_dealias_reply_free(scamper_dealias_reply_t *reply);

scamper_dealias_mercator_t *scamper_dealias_mercator_use(scamper_dealias_mercator_t *mc);
void scamper_dealias_mercator_free(scamper_dealias_mercator_t *mc);

scamper_dealias_ally_t *scamper_dealias_ally_use(scamper_dealias_ally_t *ally);
void scamper_dealias_ally_free(scamper_dealias_ally_t *ally);

scamper_dealias_radargun_t *scamper_dealias_radargun_use(scamper_dealias_radargun_t *rg);
void scamper_dealias_radargun_free(scamper_dealias_radargun_t *rg);

scamper_dealias_prefixscan_t *scamper_dealias_prefixscan_use(scamper_dealias_prefixscan_t *pf);
void scamper_dealias_prefixscan_free(scamper_dealias_prefixscan_t *pf);

scamper_dealias_bump_t *scamper_dealias_bump_use(scamper_dealias_bump_t *bump);
void scamper_dealias_bump_free(scamper_dealias_bump_t *bump);

scamper_dealias_midarest_t *scamper_dealias_midarest_use(scamper_dealias_midarest_t *me);
void scamper_dealias_midarest_free(scamper_dealias_midarest_t *me);

scamper_dealias_midardisc_t *scamper_dealias_midardisc_use(scamper_dealias_midardisc_t *md);
void scamper_dealias_midardisc_free(scamper_dealias_midardisc_t *md);
void scamper_dealias_midardisc_round_free(scamper_dealias_midardisc_round_t *r);

uint32_t scamper_dealias_reply_count(const scamper_dealias_t *dealias);

char *scamper_dealias_method_tostr(uint8_t method, char *buf, size_t len);
char *scamper_dealias_result_tostr(uint8_t result, char *buf, size_t len);
char *scamper_dealias_probedef_method_tostr(const scamper_dealias_probedef_t *def,
					    char *buf, size_t len);

/* these functions allow the probes recorded to be ordered to suit */
void scamper_dealias_probes_sort_tx(scamper_dealias_t *dealias);
void scamper_dealias_probes_sort_seq(scamper_dealias_t *dealias);
void scamper_dealias_probes_sort_def(scamper_dealias_t *dealias);

#endif /* __SCAMPER_DEALIAS_H */
