/*
 * scamper_tracelb_int.h
 *
 * $Id: scamper_tracelb_int.h,v 1.5 2023/12/21 06:11:32 mjl Exp $
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

#ifndef __SCAMPER_TRACELB_INT_H
#define __SCAMPER_TRACELB_INT_H

scamper_tracelb_t *scamper_tracelb_alloc(void);
scamper_tracelb_node_t *scamper_tracelb_node_alloc(scamper_addr_t *addr);
int scamper_tracelb_node_links_alloc(scamper_tracelb_node_t *node, uint16_t c);
scamper_tracelb_reply_t *scamper_tracelb_reply_alloc(scamper_addr_t *addr);
scamper_tracelb_probe_t *scamper_tracelb_probe_alloc(void);
int scamper_tracelb_probe_replies_alloc(scamper_tracelb_probe_t *p, uint16_t c);
scamper_tracelb_link_t *scamper_tracelb_link_alloc(void);
int scamper_tracelb_link_probesets_alloc(scamper_tracelb_link_t *l, uint8_t c);
scamper_tracelb_probeset_t *scamper_tracelb_probeset_alloc(void);
int scamper_tracelb_probeset_probes_alloc(scamper_tracelb_probeset_t *set,
					  uint16_t count);
int scamper_tracelb_nodes_alloc(scamper_tracelb_t *trace, uint16_t c);
int scamper_tracelb_links_alloc(scamper_tracelb_t *trace, uint16_t c);

scamper_tracelb_node_t *scamper_tracelb_node_find(scamper_tracelb_t *trace,
						  scamper_tracelb_node_t *node);
int scamper_tracelb_node_cmp(const scamper_tracelb_node_t *a,
			     const scamper_tracelb_node_t *b);

int scamper_tracelb_link_cmp(const scamper_tracelb_link_t *a,
			     const scamper_tracelb_link_t *b);
int scamper_tracelb_link_probeset(scamper_tracelb_link_t *link,
				  scamper_tracelb_probeset_t *set);

int scamper_tracelb_probeset_add(scamper_tracelb_probeset_t *set,
				 scamper_tracelb_probe_t *probe);

#define SCAMPER_TRACELB_FLAG_PTR              0x01 /* do ptr lookups */
#define SCAMPER_TRACELB_NODE_FLAG_QTTL        0x01 /* node has q-ttl set */
#define SCAMPER_TRACELB_REPLY_FLAG_REPLY_TTL  0x01 /* reply ttl included */
#define SCAMPER_TRACELB_REPLY_FLAG_TCP        0x02 /* reply is TCP */

#define SCAMPER_TRACELB_NODE_QTTL(node) \
 ((node)->flags & SCAMPER_TRACELB_NODE_FLAG_QTTL)

#define SCAMPER_TRACELB_REPLY_IS_ICMP_TTL_EXP(reply) (			\
 ((reply)->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) == 0 &&	\
 (((reply)->reply_from->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (reply)->reply_icmp_type == 11) ||					\
  ((reply)->reply_from->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (reply)->reply_icmp_type == 3)))

#define SCAMPER_TRACELB_REPLY_IS_ICMP_UNREACH(reply) (			\
 ((reply)->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) == 0 &&	\
 (((reply)->reply_from->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (reply)->reply_icmp_type == 3) ||					\
  ((reply)->reply_from->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (reply)->reply_icmp_type == 1)))

#define SCAMPER_TRACELB_REPLY_IS_ICMP_UNREACH_PORT(reply) (		\
 ((reply)->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) == 0 &&	\
 (((reply)->reply_from->type == SCAMPER_ADDR_TYPE_IPV4 &&		\
   (reply)->reply_icmp_type == 3 && (reply)->reply_icmp_code == 3) ||	\
  ((reply)->reply_from->type == SCAMPER_ADDR_TYPE_IPV6 &&		\
   (reply)->reply_icmp_type == 1 && (reply)->reply_icmp_code == 4)))

#define SCAMPER_TRACELB_REPLY_IS_TCP(reply) (				\
 ((reply)->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) != 0)

#define SCAMPER_TRACELB_REPLY_IS_REPLY_TTL(reply) (			\
 ((reply)->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_REPLY_TTL) != 0)

#define SCAMPER_TRACELB_TYPE_IS_TCP(trace) (				\
 ((trace)->type == SCAMPER_TRACELB_TYPE_TCP_SPORT ||			\
  (trace)->type == SCAMPER_TRACELB_TYPE_TCP_ACK_SPORT))

#define SCAMPER_TRACELB_TYPE_IS_UDP(trace) (				\
 ((trace)->type == SCAMPER_TRACELB_TYPE_UDP_SPORT ||			\
  (trace)->type == SCAMPER_TRACELB_TYPE_UDP_DPORT))

#define SCAMPER_TRACELB_TYPE_IS_ICMP(trace) (				\
 ((trace)->type == SCAMPER_TRACELB_TYPE_ICMP_ECHO))

#define SCAMPER_TRACELB_TYPE_VARY_SPORT(trace) (			\
 ((trace)->type == SCAMPER_TRACELB_TYPE_UDP_SPORT ||			\
  (trace)->type == SCAMPER_TRACELB_TYPE_TCP_SPORT ||			\
  (trace)->type == SCAMPER_TRACELB_TYPE_TCP_ACK_SPORT))

/*
 * scamper_tracelb_reply_t
 *
 * record details of each reply received.
 */
struct scamper_tracelb_reply
{
  scamper_addr_t        *reply_from;       /* source of response */
  struct timeval         reply_rx;         /* receive time */
  uint16_t               reply_ipid;       /* IP ID of reply packet */
  uint8_t                reply_ttl;        /* ttl of the reply packet */
  uint8_t                reply_flags;      /* reply flags */

  union
  {
    struct scamper_tracelb_reply_icmp
    {
      uint8_t            reply_icmp_type;  /* icmp type of the reply */
      uint8_t            reply_icmp_code;  /* icmp code of the reply */
      uint8_t            reply_icmp_q_tos; /* tos byte in quote */
      uint8_t            reply_icmp_q_ttl; /* ttl byte in quote */
      scamper_icmpext_t *reply_icmp_ext;   /* icmp extensions included */
    } icmp;
    struct scamper_tracelb_reply_tcp
    {
      uint8_t            reply_tcp_flags;  /* tcp flags of the reply */
    } tcp;
  } reply_un;

#ifdef BUILDING_LIBSCAMPERFILE
  int                    refcnt;
#endif
};

#define reply_icmp_type  reply_un.icmp.reply_icmp_type
#define reply_icmp_code  reply_un.icmp.reply_icmp_code
#define reply_icmp_ext   reply_un.icmp.reply_icmp_ext
#define reply_icmp_q_ttl reply_un.icmp.reply_icmp_q_ttl
#define reply_icmp_q_tos reply_un.icmp.reply_icmp_q_tos
#define reply_tcp_flags  reply_un.tcp.reply_tcp_flags

/*
 * scamper_tracelb_probe_t
 *
 * record details of each probe sent, and any replies received.
 */
struct scamper_tracelb_probe
{
  struct timeval                tx;
  uint16_t                      flowid;
  uint8_t                       ttl;
  uint8_t                       attempt;
  scamper_tracelb_reply_t     **rxs;
  uint16_t                      rxc;

#ifdef BUILDING_LIBSCAMPERFILE
  int                           refcnt;
#endif
};

/*
 * scamper_tracelb_probeset_t
 *
 * record details of each probe sent in a particular set.
 */
struct scamper_tracelb_probeset
{
  scamper_tracelb_probe_t     **probes; /* array of probes sent */
  uint16_t                      probec; /* number of probes sent */

#ifdef BUILDING_LIBSCAMPERFILE
  int                           refcnt;
#endif
};

struct scamper_tracelb_probeset_summary
{
  scamper_addr_t              **addrs;
  uint16_t                      addrc;
  uint16_t                      nullc;
};

/*
 * scamper_tracelb_node_t
 *
 * record details of each node encountered
 */
struct scamper_tracelb_node
{
  scamper_addr_t               *addr;  /* address of the node */
  char                         *name;  /* PTR for the addr */
  uint8_t                       flags; /* associated flags */
  uint8_t                       q_ttl; /* quoted ttl */
  scamper_tracelb_link_t      **links; /* links */
  uint16_t                      linkc; /* number of links */

#ifdef BUILDING_LIBSCAMPERFILE
  int                           refcnt;
#endif
};

/*
 * scamper_tracelb_link_t
 *
 * record probe details of each link encountered
 */
struct scamper_tracelb_link
{
  scamper_tracelb_node_t       *from;  /* link from */
  scamper_tracelb_node_t       *to;    /* link to */
  uint8_t                       hopc;  /* distance between the nodes */
  scamper_tracelb_probeset_t  **sets;  /* array of probesets, for each hop */

#ifdef BUILDING_LIBSCAMPERFILE
  int                           refcnt;
#endif
};

/*
 * scamper_tracelb_t
 *
 * structure containing the results of probing to enumerate all load balanced
 * paths towards a destination
 */
struct scamper_tracelb
{
  /* the current list, cycle, and defaults */
  scamper_list_t            *list;
  scamper_cycle_t           *cycle;
  uint32_t                   userid;

  /* source and destination addresses of the load balancer trace */
  scamper_addr_t            *src;
  scamper_addr_t            *dst;
  scamper_addr_t            *rtr;

  /* when the load balancer trace commenced */
  struct timeval             start;

  /* load balancer traceroute parameters */
  uint16_t                   sport;        /* base source port */
  uint16_t                   dport;        /* base destination port */
  uint16_t                   probe_size;   /* size of probe to send */
  uint8_t                    type;         /* probe type to use */
  uint8_t                    firsthop;     /* where to start probing */
  uint8_t                    attempts;     /* number of attempts per probe */
  uint8_t                    confidence;   /* confidence level to attain */
  uint8_t                    tos;          /* type-of-service byte to use */
  uint8_t                    gaplimit;     /* max consecutive unresp. hops */
  uint8_t                    flags;        /* flags */
  uint32_t                   probec_max;   /* max number of probes to send */
  struct timeval             wait_timeout; /* seconds to wait before timeout */
  struct timeval             wait_probe;   /* min. inter-probe time per ttl */

  /*
   * data collected:
   *
   * nodes:
   *  an IP address from each node inferred between the source and the
   *  destination, recorded in the order they were discovered in
   *
   * links:
   *  all links between the source and destination, sorted numerically by
   *  from address and then by to address; each link contains the replies
   *  collected for it
   *
   * probec:
   *  count of probes sent.  includes retries.
   *
   * error:
   *  if non-zero, something went wrong.
   */
  scamper_tracelb_node_t   **nodes;
  uint16_t                   nodec;
  scamper_tracelb_link_t   **links;
  uint16_t                   linkc;
  uint32_t                   probec;
  uint8_t                    error;
};

#endif /* __SCAMPER_TRACELB_INT_H */
