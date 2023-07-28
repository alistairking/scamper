/*
 * scamper_tracelb.h
 *
 * $Id: scamper_tracelb.h,v 1.70 2023/06/01 21:50:13 mjl Exp $
 *
 * Copyright (C) 2008-2009 The University of Waikato
 * Copyright (C) 2018-2023 Matthew Luckie
 * Author: Matthew Luckie
 *
 * Load-balancer traceroute technique authored by
 * Brice Augustin, Timur Friedman, Renata Teixeira; "Measuring Load-balanced
 *  Paths in the Internet", in Proc. Internet Measurement Conference 2007.
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

#ifndef __SCAMPER_TRACELB_H
#define __SCAMPER_TRACELB_H

/* forward declare some important structures */
typedef struct scamper_tracelb scamper_tracelb_t;
typedef struct scamper_tracelb_node scamper_tracelb_node_t;
typedef struct scamper_tracelb_link scamper_tracelb_link_t;
typedef struct scamper_tracelb_probe scamper_tracelb_probe_t;
typedef struct scamper_tracelb_reply scamper_tracelb_reply_t;
typedef struct scamper_tracelb_probeset scamper_tracelb_probeset_t;
typedef struct scamper_tracelb_probeset_summary scamper_tracelb_probeset_summary_t;

scamper_list_t *scamper_tracelb_list_get(const scamper_tracelb_t *trace);
scamper_cycle_t *scamper_tracelb_cycle_get(const scamper_tracelb_t *trace);
uint32_t scamper_tracelb_userid_get(const scamper_tracelb_t *trace);
scamper_addr_t *scamper_tracelb_src_get(const scamper_tracelb_t *trace);
scamper_addr_t *scamper_tracelb_dst_get(const scamper_tracelb_t *trace);
scamper_addr_t *scamper_tracelb_rtr_get(const scamper_tracelb_t *trace);
const struct timeval *scamper_tracelb_start_get(const scamper_tracelb_t *trace);
uint16_t scamper_tracelb_sport_get(const scamper_tracelb_t *trace);
uint16_t scamper_tracelb_dport_get(const scamper_tracelb_t *trace);
uint16_t scamper_tracelb_probe_size_get(const scamper_tracelb_t *trace);
uint8_t scamper_tracelb_type_get(const scamper_tracelb_t *trace);
uint8_t scamper_tracelb_firsthop_get(const scamper_tracelb_t *trace);
uint8_t scamper_tracelb_wait_timeout_get(const scamper_tracelb_t *trace);
uint8_t scamper_tracelb_wait_probe_get(const scamper_tracelb_t *trace);
uint8_t scamper_tracelb_attempts_get(const scamper_tracelb_t *trace);
uint8_t scamper_tracelb_confidence_get(const scamper_tracelb_t *trace);
uint8_t scamper_tracelb_tos_get(const scamper_tracelb_t *trace);
uint8_t scamper_tracelb_gaplimit_get(const scamper_tracelb_t *trace);
uint32_t scamper_tracelb_flags_get(const scamper_tracelb_t *trace);
uint32_t scamper_tracelb_probec_max_get(const scamper_tracelb_t *trace);
uint16_t scamper_tracelb_nodec_get(const scamper_tracelb_t *trace);
const scamper_tracelb_node_t *scamper_tracelb_node_get(const scamper_tracelb_t *trace, uint16_t i);
uint16_t scamper_tracelb_linkc_get(const scamper_tracelb_t *trace);
const scamper_tracelb_link_t *scamper_tracelb_link_get(const scamper_tracelb_t *trace, uint16_t i);
uint32_t scamper_tracelb_probec_get(const scamper_tracelb_t *trace);
uint32_t scamper_tracelb_error_get(const scamper_tracelb_t *trace);

scamper_addr_t *scamper_tracelb_node_addr_get(const scamper_tracelb_node_t *node);
const char *scamper_tracelb_node_name_get(const scamper_tracelb_node_t *node);
uint32_t scamper_tracelb_node_flags_get(const scamper_tracelb_node_t *node);
uint8_t scamper_tracelb_node_q_ttl_get(const scamper_tracelb_node_t *node);
const scamper_tracelb_link_t *scamper_tracelb_node_link_get(const scamper_tracelb_node_t *node, uint16_t i);
uint16_t scamper_tracelb_node_linkc_get(const scamper_tracelb_node_t *node);
int scamper_tracelb_node_is_qttl(const scamper_tracelb_node_t *node);

const scamper_tracelb_node_t *scamper_tracelb_link_from_get(const scamper_tracelb_link_t *link);
const scamper_tracelb_node_t *scamper_tracelb_link_to_get(const scamper_tracelb_link_t *link);
uint8_t scamper_tracelb_link_hopc_get(const scamper_tracelb_link_t *link);
const scamper_tracelb_probeset_t *scamper_tracelb_link_probeset_get(const scamper_tracelb_link_t *link, uint8_t hop);

scamper_tracelb_probe_t *scamper_tracelb_probeset_probe_get(const scamper_tracelb_probeset_t *set, uint16_t i);
uint16_t scamper_tracelb_probeset_probec_get(const scamper_tracelb_probeset_t *set);

const struct timeval *scamper_tracelb_probe_tx_get(const scamper_tracelb_probe_t *probe);
uint16_t scamper_tracelb_probe_flowid_get(const scamper_tracelb_probe_t *probe);
uint8_t scamper_tracelb_probe_ttl_get(const scamper_tracelb_probe_t *probe);
uint8_t scamper_tracelb_probe_attempt_get(const scamper_tracelb_probe_t *probe);
const scamper_tracelb_reply_t *scamper_tracelb_probe_rx_get(const scamper_tracelb_probe_t *probe, uint16_t i);
uint16_t scamper_tracelb_probe_rxc_get(const scamper_tracelb_probe_t *probe);

scamper_addr_t *scamper_tracelb_reply_from_get(const scamper_tracelb_reply_t *reply);
const struct timeval *scamper_tracelb_reply_rx_get(const scamper_tracelb_reply_t *reply);
uint16_t scamper_tracelb_reply_ipid_get(const scamper_tracelb_reply_t *reply);
uint8_t scamper_tracelb_reply_ttl_get(const scamper_tracelb_reply_t *reply);
uint32_t scamper_tracelb_reply_flags_get(const scamper_tracelb_reply_t *reply);
uint8_t scamper_tracelb_reply_icmp_type_get(const scamper_tracelb_reply_t *reply);
uint8_t scamper_tracelb_reply_icmp_code_get(const scamper_tracelb_reply_t *reply);
uint8_t scamper_tracelb_reply_icmp_q_tos_get(const scamper_tracelb_reply_t *reply);
uint8_t scamper_tracelb_reply_icmp_q_ttl_get(const scamper_tracelb_reply_t *reply);
uint8_t scamper_tracelb_reply_tcp_flags_get(const scamper_tracelb_reply_t *reply);
int scamper_tracelb_reply_is_icmp_ttl_exp(const scamper_tracelb_reply_t *reply);
int scamper_tracelb_reply_is_icmp_unreach(const scamper_tracelb_reply_t *reply);
int scamper_tracelb_reply_is_tcp(const scamper_tracelb_reply_t *reply);

#ifdef __SCAMPER_ICMPEXT_H
const scamper_icmpext_t *scamper_tracelb_reply_icmp_ext_get(const scamper_tracelb_reply_t *reply);
#endif /* __SCAMPER_ICMPEXT_H */

/*
 * these values give the 'type' member of a scamper_tracelb_t structure
 * some meaning.
 */
#define SCAMPER_TRACELB_TYPE_UDP_DPORT      0x01 /* vary udp-dport */
#define SCAMPER_TRACELB_TYPE_ICMP_ECHO      0x02 /* vary icmp checksum */
#define SCAMPER_TRACELB_TYPE_UDP_SPORT      0x03 /* vary udp-sport */
#define SCAMPER_TRACELB_TYPE_TCP_SPORT      0x04 /* vary tcp-sport */
#define SCAMPER_TRACELB_TYPE_TCP_ACK_SPORT  0x05 /* tcp-ack, vary sport */

/*
 * these values give the 'flags' member of a scamper_tracelb_t structure
 * some meaning.
 */
#define SCAMPER_TRACELB_FLAG_PTR            0x01 /* do ptr lookups */

/*
 * these values give the 'flags' member of a scamper_tracelb_node_t
 * structure some meaning.
 */
#define SCAMPER_TRACELB_NODE_FLAG_QTTL      0x01

#define SCAMPER_TRACELB_REPLY_FLAG_REPLY_TTL  0x01 /* reply ttl included */
#define SCAMPER_TRACELB_REPLY_FLAG_TCP        0x02 /* reply is TCP */

/*
 * basic scamper_tracelb_t routines:
 *
 *  scamper_tracelb_alloc: allocate a scamper_tracelb_t structure
 *  scamper_tracelb_free:  free a scamper_tracelb_t and contents
 *  scamper_tracelb_type_tostr: return a string specifying the trace type
 */
scamper_tracelb_t *scamper_tracelb_alloc(void);
void               scamper_tracelb_free(scamper_tracelb_t *);
char              *scamper_tracelb_type_tostr(const scamper_tracelb_t *trace,
					      char *buf, size_t len);

/*
 * basic scamper_tracelb_node_t routines:
 *
 *  scamper_tracelb_node_alloc: allocate a scamper_tracelb_node_t structure
 *  scamper_tracelb_node_free:  free a scamper_tracelb_node_t and contents
 *  scamper_tracelb_node_find:  find a node structure by address
 *  scamper_tracelb_node_cmp:   comparison function for comparing nodes
 */
scamper_tracelb_node_t *scamper_tracelb_node_alloc(scamper_addr_t *);
void                    scamper_tracelb_node_free(scamper_tracelb_node_t *);
scamper_tracelb_node_t *scamper_tracelb_node_find(scamper_tracelb_t *,
						  scamper_tracelb_node_t *);
int scamper_tracelb_node_cmp(const scamper_tracelb_node_t *,
			     const scamper_tracelb_node_t *);
int scamper_tracelb_node_links_alloc(scamper_tracelb_node_t *, uint16_t);

/*
 * basic scamper_tracelb_reply_t routines:
 *
 *  scamper_tracelb_reply_alloc: allocate a scamper_tracelb_reply_t structure
 *  scamper_tracelb_reply_free:  free a reply structure
 */
scamper_tracelb_reply_t *scamper_tracelb_reply_alloc(scamper_addr_t *);
void scamper_tracelb_reply_free(scamper_tracelb_reply_t *);

/*
 * basic scamper_tracelb_probe_t routines:
 *
 */
scamper_tracelb_probe_t *scamper_tracelb_probe_alloc(void);
void scamper_tracelb_probe_free(scamper_tracelb_probe_t *);
int scamper_tracelb_probe_replies_alloc(scamper_tracelb_probe_t *, uint16_t);

/*
 * basic scamper_tracelb_link_t routines:
 *
 *  scamper_tracelb_link_alloc: allocate a scamper_tracelb_link_t structure
 *  scamper_tracelb_link_free:  free a scamper_tracelb_link_t and contents
 *  scamper_tracelb_link_cmp:   convenient function to compare links with
 */
scamper_tracelb_link_t *scamper_tracelb_link_alloc(void);
void scamper_tracelb_link_free(scamper_tracelb_link_t *);
int scamper_tracelb_link_cmp(const scamper_tracelb_link_t *,
			     const scamper_tracelb_link_t *);
int scamper_tracelb_link_probeset(scamper_tracelb_link_t *,
				  scamper_tracelb_probeset_t *);
int scamper_tracelb_link_probesets_alloc(scamper_tracelb_link_t *, uint8_t);

/*
 * basic scamper_tracelb_probeset_t routines:
 *
 */
scamper_tracelb_probeset_t *scamper_tracelb_probeset_alloc(void);
void scamper_tracelb_probeset_free(scamper_tracelb_probeset_t *);
int scamper_tracelb_probeset_add(scamper_tracelb_probeset_t *,
				 scamper_tracelb_probe_t *);
int scamper_tracelb_probeset_probes_alloc(scamper_tracelb_probeset_t *,
					  uint16_t);

/*
 * routines to summarise a set of probes beyond a specific node
 *
 */
scamper_tracelb_probeset_summary_t *scamper_tracelb_probeset_summary_alloc(scamper_tracelb_probeset_t *);
void scamper_tracelb_probeset_summary_free(scamper_tracelb_probeset_summary_t *);

/*
 * these functions allocate arrays of appropriate size, all elements
 * initialised to null.
 */
int scamper_tracelb_nodes_alloc(scamper_tracelb_t *, uint16_t);
int scamper_tracelb_links_alloc(scamper_tracelb_t *, uint16_t);

#endif /* __SCAMPER_TRACELB_H */
