/*
 * scamper_trace_int.h
 *
 * $Id: scamper_trace_int.h,v 1.8 2024/03/04 05:10:28 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2008      Alistair King
 * Copyright (C) 2015      The Regents of the University of California
 * Copyright (C) 2015      The University of Waikato
 * Copyright (C) 2019-2023 Matthew Luckie
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

#ifndef __SCAMPER_TRACE_INT_H
#define __SCAMPER_TRACE_INT_H

/*
 * scamper_trace_alloc:
 *  allocate a brand new scamper trace object, empty of any data
 */
scamper_trace_t *scamper_trace_alloc(void);
scamper_trace_hop_t *scamper_trace_hop_alloc(void);

/*
 * scamper_trace_hops_alloc:
 *  allocate an array of hop records to the trace object
 */
int scamper_trace_hops_alloc(scamper_trace_t *trace, uint16_t hops);

/*
 * scamper_trace_pmtud_alloc:
 *  allocate a blank pmtud record for the trace structure
 */
scamper_trace_pmtud_t *scamper_trace_pmtud_alloc(void);

scamper_trace_pmtud_n_t *scamper_trace_pmtud_n_alloc(void);
int scamper_trace_pmtud_n_alloc_c(scamper_trace_pmtud_t *pmtud, uint8_t c);
int scamper_trace_pmtud_n_add(scamper_trace_pmtud_t *pmtud,
			      scamper_trace_pmtud_n_t *n);

scamper_trace_dtree_t *scamper_trace_dtree_alloc(void);

int scamper_trace_dtree_lss_set(scamper_trace_dtree_t *dtree, const char *lss);
int scamper_trace_dtree_gss_alloc(scamper_trace_dtree_t *dtree, uint16_t cnt);

void scamper_trace_dtree_gss_sort(const scamper_trace_dtree_t *dtree);
scamper_addr_t *scamper_trace_dtree_gss_find(const scamper_trace_dtree_t *dtree,
                                             const scamper_addr_t *iface);

#define SCAMPER_TRACE_HOP_IS_TCP(hop) (			\
 (hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TCP) != 0)

#define SCAMPER_TRACE_HOP_IS_UDP(hop) (				\
 (hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_UDP) != 0)

#define SCAMPER_TRACE_HOP_IS_ICMP(hop) (                        \
 (hop->hop_flags & (SCAMPER_TRACE_HOP_FLAG_TCP|			\
		    SCAMPER_TRACE_HOP_FLAG_UDP)) == 0)

#define SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP(hop) (		\
 SCAMPER_TRACE_HOP_IS_ICMP(hop) &&				\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 11) ||				\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 3)))

#define SCAMPER_TRACE_HOP_IS_ICMP_TTL_EXP_TRANS(hop) (		\
 SCAMPER_TRACE_HOP_IS_ICMP(hop) &&				\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 11 && (hop)->hop_icmp_code == 0) ||	\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 3 && (hop)->hop_icmp_code == 0)))

#define SCAMPER_TRACE_HOP_IS_ICMP_PTB(hop) (			\
 SCAMPER_TRACE_HOP_IS_ICMP(hop) &&				\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 3 && (hop)->hop_icmp_code == 4) ||	\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 2)))

#define SCAMPER_TRACE_HOP_IS_ICMP_PTB_BADSUGG(hop) (		\
 SCAMPER_TRACE_HOP_IS_ICMP_PTB((hop)) &&			\
 (hop)->hop_probe_size <= (hop)->hop_icmp_nhmtu)

#define SCAMPER_TRACE_HOP_IS_ICMP_UNREACH(hop) (		\
 SCAMPER_TRACE_HOP_IS_ICMP(hop) &&				\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 3) ||				\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 1)))

#define SCAMPER_TRACE_HOP_IS_ICMP_UNREACH_PORT(hop) (		\
 SCAMPER_TRACE_HOP_IS_ICMP(hop) &&				\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 3 && (hop)->hop_icmp_code == 3) ||	\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 1 && (hop)->hop_icmp_code == 4)))

#define SCAMPER_TRACE_HOP_IS_ICMP_ECHO_REPLY(hop) (		\
 SCAMPER_TRACE_HOP_IS_ICMP(hop) &&				\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (hop)->hop_icmp_type == 0) ||				\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (hop)->hop_icmp_type == 129)))

#define SCAMPER_TRACE_HOP_IS_ICMP_Q(hop) (			\
 SCAMPER_TRACE_HOP_IS_ICMP(hop) &&				\
 (((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   ((hop)->hop_icmp_type == 3 || (hop)->hop_icmp_type == 11)) ||\
  ((hop)->hop_addr->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   ((hop)->hop_icmp_type >= 1 && (hop)->hop_icmp_type <= 3))))

/*
 * this macro is a more convenient way to check that the hop record
 * has both the tx and rx timestamps from the datalink for computing the
 * RTT
 */
#define SCAMPER_TRACE_HOP_FLAG_DL_RTT(hop)			\
 ((hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_TX) &&		\
  (hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_RX))

#define SCAMPER_TRACE_TYPE_IS_ICMP(trace) (			\
 (trace)->type == SCAMPER_TRACE_TYPE_ICMP_ECHO ||		\
 (trace)->type == SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS)

#define SCAMPER_TRACE_TYPE_IS_UDP(trace) (			\
 (trace)->type == SCAMPER_TRACE_TYPE_UDP ||			\
 (trace)->type == SCAMPER_TRACE_TYPE_UDP_PARIS)

#define SCAMPER_TRACE_TYPE_IS_TCP(trace) (			\
 (trace)->type == SCAMPER_TRACE_TYPE_TCP ||			\
 (trace)->type == SCAMPER_TRACE_TYPE_TCP_ACK)

#define SCAMPER_TRACE_TYPE_IS_UDP_PARIS(trace) (		\
 (trace)->type == SCAMPER_TRACE_TYPE_UDP_PARIS)

#define SCAMPER_TRACE_TYPE_IS_ICMP_ECHO_PARIS(trace) (		\
 (trace)->type == SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS)

/*
 * macros for dealing with scamper trace flags.
 */
#define SCAMPER_TRACE_FLAG_IS_ICMPCSUMDP(trace) (		\
 (trace)->flags & SCAMPER_TRACE_FLAG_ICMPCSUMDP)

#define SCAMPER_TRACE_FLAG_IS_PMTUD(trace) (			\
 (trace)->flags & SCAMPER_TRACE_FLAG_PMTUD)

#define SCAMPER_TRACE_FLAG_IS_DOUBLETREE(trace) (		\
 (trace)->flags & SCAMPER_TRACE_FLAG_DOUBLETREE)

#define SCAMPER_TRACE_FLAG_IS_DL(trace) (			\
 (trace)->flags & SCAMPER_TRACE_FLAG_DL)

#define SCAMPER_TRACE_FLAG_IS_IGNORETTLDST(trace) (		\
 (trace)->flags & SCAMPER_TRACE_FLAG_IGNORETTLDST)

#define SCAMPER_TRACE_FLAG_IS_ALLATTEMPTS(trace) (		\
 (trace)->flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS)

#define SCAMPER_TRACE_FLAG_IS_CONSTPAYLOAD(trace) (		\
 (trace)->flags & SCAMPER_TRACE_FLAG_CONSTPAYLOAD)

struct scamper_trace
{
  /* the current list, cycle, and defaults */
  struct scamper_list   *list;
  struct scamper_cycle  *cycle;
  uint32_t               userid;

  /* source and destination addresses of the trace */
  struct scamper_addr   *src;
  struct scamper_addr   *dst;
  struct scamper_addr   *rtr;

  /* when the trace commenced */
  struct timeval         start;

  /* hops array, number of valid hops specified by hop_count */
  scamper_trace_hop_t  **hops;
  uint16_t               hop_count;

  /* number of probes sent for this traceroute */
  uint16_t               probec;

  /* why the trace finished */
  uint8_t                stop_reason;
  uint8_t                stop_data;

  /* if we did a parallel traceroute */
  uint8_t                stop_hop;

  /* trace parameters */
  uint8_t                type;
  uint8_t                attempts;
  uint8_t                hoplimit;
  uint8_t                squeries;
  uint8_t                gaplimit;
  uint8_t                gapaction;
  uint8_t                firsthop;
  uint8_t                tos;
  struct timeval         wait_timeout;
  struct timeval         wait_probe;
  struct timeval         wait_probe_hop;
  uint8_t                loops;
  uint8_t                loopaction;
  uint8_t                confidence;
  uint16_t               probe_size;
  uint16_t               sport;
  uint16_t               dport;
  uint16_t               offset;
  uint32_t               flags;

  /* payload */
  uint8_t               *payload;
  uint16_t               payload_len;

  /* if we perform PMTU discovery on the trace, then record the data here */
  scamper_trace_pmtud_t *pmtud;

  /* if we perform last ditch probing, then record any responses here */
  scamper_trace_hop_t   *lastditch;

  /* if we perform doubletree, record doubletree parameters and data here */
  scamper_trace_dtree_t *dtree;
};

/*
 * scamper_trace_hop:
 *
 * hold data on each response received as part of a traceroute.
 */
struct scamper_trace_hop
{
  /* the address / name of the hop that responded */
  scamper_addr_t              *hop_addr;
  char                        *hop_name;

  /* flags defined by SCAMPER_TRACE_HOP_FLAG_* */
  uint8_t                      hop_flags;

  /*
   * probe_id:   the attempt # this probe is in response to [count from 0]
   * probe_ttl:  the ttl that we sent to the trace->dst
   * probe_size: the size of the probe we sent
   * reply_ttl:  the ttl of the reply packet
   * reply_tos:  the TOS of the reply packet
   * reply_size: the size of the icmp response we received
   * reply_ipid: the IPID value in the response
   */
  uint8_t                      hop_probe_id;
  uint8_t                      hop_probe_ttl;
  uint16_t                     hop_probe_size;
  uint8_t                      hop_reply_ttl;
  uint8_t                      hop_reply_tos;
  uint16_t                     hop_reply_size;
  uint16_t                     hop_reply_ipid;

  /* icmp type / code returned by this hop */
  union
  {
    struct hop_icmp
    {
      uint8_t                  hop_icmp_type;
      uint8_t                  hop_icmp_code;
      uint8_t                  hop_icmp_q_ttl;
      uint8_t                  hop_icmp_q_tos;
      uint16_t                 hop_icmp_q_ipl;
      uint16_t                 hop_icmp_nhmtu;
    } icmp;
    struct hop_tcp
    {
      uint8_t                  hop_tcp_flags;
    } tcp;
  } hop_un;

  /* time elapsed between sending the probe and receiving this resp */
  struct timeval               hop_tx;
  struct timeval               hop_rtt;

  /* ICMP extensions */
  struct scamper_icmpext      *hop_icmpext;

  struct scamper_trace_hop    *hop_next;

#ifdef BUILDING_LIBSCAMPERFILE
  int                          refcnt;
#endif
};

#define hop_icmp_type  hop_un.icmp.hop_icmp_type
#define hop_icmp_code  hop_un.icmp.hop_icmp_code
#define hop_icmp_q_ttl hop_un.icmp.hop_icmp_q_ttl
#define hop_icmp_q_ipl hop_un.icmp.hop_icmp_q_ipl
#define hop_icmp_q_tos hop_un.icmp.hop_icmp_q_tos
#define hop_icmp_nhmtu hop_un.icmp.hop_icmp_nhmtu
#define hop_tcp_flags  hop_un.tcp.hop_tcp_flags

/*
 * scamper_trace_pmtud_n_t
 *
 * notes about PMTUD process; the record says the behaviour that was deduced,
 * what the next-hop MTU is, and which hop it corresponds to.  The hop
 * record is one of those listed in the parent scamper_trace_pmtud_t
 * structure.
 */
struct scamper_trace_pmtud_n
{
  uint8_t              type;
  uint16_t             nhmtu;
  scamper_trace_hop_t *hop;
#ifdef BUILDING_LIBSCAMPERFILE
  int                  refcnt;
#endif
};

/*
 * scamper_trace_pmtud_t
 *
 * container for data collected.
 *
 * version 1 has ifmtu, outmtu, pmtu, and a list of hops from which it must
 * be deduced what the behaviours observed are.
 * version 2 has ifmtu, outmtu, pmtu, all responses received during pmtud
 * process, and a set of annotations about what was inferred.
 */
struct scamper_trace_pmtud
{
  uint8_t                   ver;    /* version of data-storing method */
  uint16_t                  ifmtu;  /* the outgoing interface's MTU */
  uint16_t                  outmtu; /* MTU to first hop, if diff from ifmtu */
  uint16_t                  pmtu;   /* packet size that reached target */
  scamper_trace_hop_t      *hops;   /* icmp messages */
  scamper_trace_pmtud_n_t **notes;  /* annotations about pmtud */
  uint8_t                   notec;  /* number of annotations */
#ifdef BUILDING_LIBSCAMPERFILE
  int                       refcnt;
#endif
};

struct scamper_trace_dtree
{
  char            *lss;
  uint8_t          firsthop;
  uint8_t          flags;
  uint16_t         gssc;
  scamper_addr_t **gss;
  scamper_addr_t  *gss_stop;
  scamper_addr_t  *lss_stop;
#ifdef BUILDING_LIBSCAMPERFILE
  int              refcnt;
#endif
};

#endif /* __SCAMPER_TRACE_INT_H */
