/*
 * scamper_host
 *
 * $Id: scamper_host.h,v 1.13 2023/05/20 05:10:56 mjl Exp $
 *
 * Copyright (C) 2018-2023 Matthew Luckie
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

#ifndef __SCAMPER_HOST_H
#define __SCAMPER_HOST_H

typedef struct scamper_host scamper_host_t;
typedef struct scamper_host_query scamper_host_query_t;
typedef struct scamper_host_rr scamper_host_rr_t;
typedef struct scamper_host_rr_soa scamper_host_rr_soa_t;
typedef struct scamper_host_rr_mx scamper_host_rr_mx_t;

scamper_host_t *scamper_host_alloc(void);
void scamper_host_free(scamper_host_t *);
int scamper_host_queries_alloc(scamper_host_t *host, int n);
char *scamper_host_stop_tostr(const scamper_host_t *h, char *b, size_t l);
char *scamper_host_qtype_tostr(uint16_t type, char *b, size_t l);
char *scamper_host_qclass_tostr(uint16_t class, char *b, size_t l);
char *scamper_host_rcode_tostr(uint8_t rcode, char *b, size_t l);
scamper_list_t *scamper_host_list_get(const scamper_host_t *host);
scamper_cycle_t *scamper_host_cycle_get(const scamper_host_t *host);
scamper_addr_t *scamper_host_src_get(const scamper_host_t *host);
scamper_addr_t *scamper_host_dst_get(const scamper_host_t *host);
uint32_t scamper_host_userid_get(const scamper_host_t *host);
const struct timeval *scamper_host_start_get(const scamper_host_t *host);
uint16_t scamper_host_flags_get(const scamper_host_t *host);
uint16_t scamper_host_wait_get(const scamper_host_t *host);
uint8_t scamper_host_stop_get(const scamper_host_t *host);
uint8_t scamper_host_retries_get(const scamper_host_t *host);
uint16_t scamper_host_qtype_get(const scamper_host_t *host);
uint16_t scamper_host_qclass_get(const scamper_host_t *host);
const char *scamper_host_qname_get(const scamper_host_t *host);
uint8_t scamper_host_qcount_get(const scamper_host_t *host);
const scamper_host_query_t *scamper_host_query_get(const scamper_host_t *host, uint8_t i);

scamper_host_query_t *scamper_host_query_alloc(void);
int scamper_host_query_rr_alloc(scamper_host_query_t *query);
const struct timeval *scamper_host_query_tx_get(const scamper_host_query_t *q);
const struct timeval *scamper_host_query_rx_get(const scamper_host_query_t *q);
uint8_t scamper_host_query_rcode_get(const scamper_host_query_t *q);
uint8_t scamper_host_query_flags_get(const scamper_host_query_t *q);
uint16_t scamper_host_query_id_get(const scamper_host_query_t *q);
uint16_t scamper_host_query_ancount_get(const scamper_host_query_t *q);
uint16_t scamper_host_query_nscount_get(const scamper_host_query_t *q);
uint16_t scamper_host_query_arcount_get(const scamper_host_query_t *q);
const scamper_host_rr_t *scamper_host_query_an_get(const scamper_host_query_t *q, uint16_t i);
const scamper_host_rr_t *scamper_host_query_ns_get(const scamper_host_query_t *q, uint16_t i);
const scamper_host_rr_t *scamper_host_query_ar_get(const scamper_host_query_t *q, uint16_t i);

scamper_host_rr_t *scamper_host_rr_alloc(const char *,
					 uint16_t, uint16_t, uint32_t);
void scamper_host_rr_free(scamper_host_rr_t *);
int scamper_host_rr_data_type(uint16_t class, uint16_t type);
const char *scamper_host_rr_data_str_typestr(uint16_t class, uint16_t type);
uint16_t scamper_host_rr_class_get(const scamper_host_rr_t *rr);
uint16_t scamper_host_rr_type_get(const scamper_host_rr_t *rr);
const char *scamper_host_rr_name_get(const scamper_host_rr_t *rr);
uint32_t scamper_host_rr_ttl_get(const scamper_host_rr_t *rr);
const void *scamper_host_rr_v_get(const scamper_host_rr_t *rr);
scamper_addr_t *scamper_host_rr_addr_get(const scamper_host_rr_t *rr);
const char *scamper_host_rr_str_get(const scamper_host_rr_t *rr);
const scamper_host_rr_soa_t *scamper_host_rr_soa_get(const scamper_host_rr_t *rr);
const scamper_host_rr_mx_t *scamper_host_rr_mx_get(const scamper_host_rr_t *rr);

scamper_host_rr_mx_t *scamper_host_rr_mx_alloc(uint16_t, const char *);
void scamper_host_rr_mx_free(scamper_host_rr_mx_t *);
uint16_t scamper_host_rr_mx_preference_get(const scamper_host_rr_mx_t *mx);
const char *scamper_host_rr_mx_exchange_get(const scamper_host_rr_mx_t *mx);

scamper_host_rr_soa_t *scamper_host_rr_soa_alloc(const char *, const char *);
void scamper_host_rr_soa_free(scamper_host_rr_soa_t *);
const char *scamper_host_rr_soa_mname_get(const scamper_host_rr_soa_t *soa);
const char *scamper_host_rr_soa_rname_get(const scamper_host_rr_soa_t *soa);
uint32_t scamper_host_rr_soa_serial_get(const scamper_host_rr_soa_t *soa);
uint32_t scamper_host_rr_soa_refresh_get(const scamper_host_rr_soa_t *soa);
uint32_t scamper_host_rr_soa_retry_get(const scamper_host_rr_soa_t *soa);
uint32_t scamper_host_rr_soa_expire_get(const scamper_host_rr_soa_t *soa);
uint32_t scamper_host_rr_soa_minimum_get(const scamper_host_rr_soa_t *soa);

#define SCAMPER_HOST_FLAG_NORECURSE 0x0001

#define SCAMPER_HOST_CLASS_IN     1

#define SCAMPER_HOST_TYPE_A       1
#define SCAMPER_HOST_TYPE_NS      2
#define SCAMPER_HOST_TYPE_CNAME   5
#define SCAMPER_HOST_TYPE_SOA     6
#define SCAMPER_HOST_TYPE_PTR    12
#define SCAMPER_HOST_TYPE_MX     15
#define SCAMPER_HOST_TYPE_TXT    16
#define SCAMPER_HOST_TYPE_AAAA   28
#define SCAMPER_HOST_TYPE_DS     43
#define SCAMPER_HOST_TYPE_SSHFP  44
#define SCAMPER_HOST_TYPE_RRSIG  46
#define SCAMPER_HOST_TYPE_NSEC   47
#define SCAMPER_HOST_TYPE_DNSKEY 48

#define SCAMPER_HOST_STOP_NONE    0
#define SCAMPER_HOST_STOP_DONE    1
#define SCAMPER_HOST_STOP_TIMEOUT 2
#define SCAMPER_HOST_STOP_HALTED  3
#define SCAMPER_HOST_STOP_ERROR   4

#define SCAMPER_HOST_QUERY_RCODE_NOERROR  0
#define SCAMPER_HOST_QUERY_RCODE_FORMERR  1
#define SCAMPER_HOST_QUERY_RCODE_SERVFAIL 2
#define SCAMPER_HOST_QUERY_RCODE_NXDOMAIN 3
#define SCAMPER_HOST_QUERY_RCODE_NOTIMP   4
#define SCAMPER_HOST_QUERY_RCODE_REFUSED  5
#define SCAMPER_HOST_QUERY_RCODE_YXDOMAIN 6
#define SCAMPER_HOST_QUERY_RCODE_YXRRSET  7
#define SCAMPER_HOST_QUERY_RCODE_NXRRSET  8
#define SCAMPER_HOST_QUERY_RCODE_NOTAUTH  9
#define SCAMPER_HOST_QUERY_RCODE_NOTZONE  10

#define SCAMPER_HOST_QUERY_FLAG_AA        0x40
#define SCAMPER_HOST_QUERY_FLAG_TC        0x20
#define SCAMPER_HOST_QUERY_FLAG_RD        0x10
#define SCAMPER_HOST_QUERY_FLAG_RA        0x08
#define SCAMPER_HOST_QUERY_FLAG_AD        0x02
#define SCAMPER_HOST_QUERY_FLAG_CD        0x01

#define SCAMPER_HOST_RR_DATA_TYPE_ADDR 1
#define SCAMPER_HOST_RR_DATA_TYPE_STR  2
#define SCAMPER_HOST_RR_DATA_TYPE_SOA  3
#define SCAMPER_HOST_RR_DATA_TYPE_MX   4

#endif /* __SCAMPER_HOST_H */
