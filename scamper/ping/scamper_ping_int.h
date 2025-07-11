/*
 * scamper_ping_int.h
 *
 * $Id: scamper_ping_int.h,v 1.20 2025/05/29 07:50:34 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2020-2025 Matthew Luckie
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

#ifndef __SCAMPER_PING_INT_H
#define __SCAMPER_PING_INT_H

scamper_ping_t *scamper_ping_alloc(void);
scamper_ping_v4ts_t *scamper_ping_v4ts_alloc(uint8_t ipc);
scamper_ping_probe_t *scamper_ping_probe_alloc(void);
scamper_ping_reply_t *scamper_ping_reply_alloc(void);
scamper_ping_reply_v4ts_t *scamper_ping_reply_v4ts_alloc(uint8_t tsc, int ip);
scamper_ping_reply_v4rr_t *scamper_ping_reply_v4rr_alloc(uint8_t ipc);
scamper_ping_reply_tsreply_t *scamper_ping_reply_tsreply_alloc(void);

int scamper_ping_probes_alloc(scamper_ping_t *ping, uint16_t count);
int scamper_ping_probe_replies_alloc(scamper_ping_probe_t *probe,
				     uint16_t count);
int scamper_ping_probe_reply_append(scamper_ping_probe_t *probe,
				    scamper_ping_reply_t *reply);

/* count how many replies were received in total */
uint32_t scamper_ping_reply_total(const scamper_ping_t *ping);

#define SCAMPER_PING_REPLY_IS_ICMP(reply) ( \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 && (reply)->proto == 1) || \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 && (reply)->proto == 58))

#define SCAMPER_PING_REPLY_IS_TCP(reply) ((reply)->proto == 6)

#define SCAMPER_PING_REPLY_IS_UDP(reply) ((reply)->proto == 17)

#define SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply) (     \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&         \
  (reply)->proto == 1 && (reply)->icmp_type == 0) ||	   \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&         \
  (reply)->proto == 58 && (reply)->icmp_type == 129))

#define SCAMPER_PING_REPLY_IS_ICMP_UNREACH(reply) (        \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&         \
  (reply)->proto == 1 && (reply)->icmp_type == 3) ||	   \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&         \
  (reply)->proto == 58 && (reply)->icmp_type == 1))

#define SCAMPER_PING_REPLY_IS_ICMP_UNREACH_PORT(reply) (   \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&         \
  (reply)->proto == 1 &&				   \
  (reply)->icmp_type == 3 && (reply)->icmp_code == 3) ||   \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&         \
  (reply)->proto == 58 &&                            \
  (reply)->icmp_type == 1 && (reply)->icmp_code == 4))

#define SCAMPER_PING_REPLY_IS_ICMP_TTL_EXP(reply) (        \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&         \
  (reply)->proto == 1 && (reply)->icmp_type == 11) ||	   \
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&         \
  (reply)->proto == 58 && (reply)->icmp_type == 3))

#define SCAMPER_PING_REPLY_IS_ICMP_TSREPLY(reply) ( \
 (reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&   \
 (reply)->proto == 1 && (reply)->icmp_type == 14)

#define SCAMPER_PING_REPLY_IS_ICMP_PTB(reply) (		\
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV4 &&	\
  (reply)->proto == 1 && 				\
  (reply)->icmp_type == 3 &&				\
  (reply)->icmp_code == 4) ||				\
 ((reply)->addr->type == SCAMPER_ADDR_TYPE_IPV6 &&	\
  (reply)->proto == 58 &&				\
  (reply)->icmp_type == 2)) 

#define SCAMPER_PING_METHOD_IS_ICMP(ping) (         \
 (ping)->method == SCAMPER_PING_METHOD_ICMP_ECHO || \
 (ping)->method == SCAMPER_PING_METHOD_ICMP_TIME)

#define SCAMPER_PING_METHOD_IS_TCP(ping) (              \
 (ping)->method == SCAMPER_PING_METHOD_TCP_ACK ||       \
 (ping)->method == SCAMPER_PING_METHOD_TCP_ACK_SPORT || \
 (ping)->method == SCAMPER_PING_METHOD_TCP_SYN ||       \
 (ping)->method == SCAMPER_PING_METHOD_TCP_SYNACK ||    \
 (ping)->method == SCAMPER_PING_METHOD_TCP_RST ||       \
 (ping)->method == SCAMPER_PING_METHOD_TCP_SYN_SPORT)

#define SCAMPER_PING_METHOD_IS_TCP_ACK_SPORT(ping) (  \
 (ping)->method == SCAMPER_PING_METHOD_TCP_ACK_SPORT)

#define SCAMPER_PING_METHOD_IS_UDP(ping) (          \
 (ping)->method == SCAMPER_PING_METHOD_UDP ||       \
 (ping)->method == SCAMPER_PING_METHOD_UDP_SPORT || \
 (ping)->method == SCAMPER_PING_METHOD_UDP_DPORT)

#define SCAMPER_PING_METHOD_IS_ICMP_TIME(ping) (    \
 (ping)->method == SCAMPER_PING_METHOD_ICMP_TIME)

#define SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping) (    \
 (ping)->method == SCAMPER_PING_METHOD_ICMP_ECHO)

#define SCAMPER_PING_METHOD_IS_VARY_SPORT(ping) (       \
 (ping)->method == SCAMPER_PING_METHOD_TCP_ACK_SPORT ||	\
 (ping)->method == SCAMPER_PING_METHOD_TCP_SYN_SPORT ||	\
 (ping)->method == SCAMPER_PING_METHOD_UDP_SPORT)

#define SCAMPER_PING_METHOD_IS_VARY_DPORT(ping) (  \
 (ping)->method == SCAMPER_PING_METHOD_UDP_DPORT)

#define SCAMPER_PING_REPLY_IS_FROM_TARGET(ping, reply) ( \
 (SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping) &&           \
  SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply)) ||    \
 (SCAMPER_PING_METHOD_IS_ICMP_TIME(ping) &&           \
  SCAMPER_PING_REPLY_IS_ICMP_TSREPLY(reply)) ||       \
 (SCAMPER_PING_METHOD_IS_TCP(ping) &&                 \
  SCAMPER_PING_REPLY_IS_TCP(reply)) ||                \
 (SCAMPER_PING_METHOD_IS_UDP(ping) &&                 \
  (SCAMPER_PING_REPLY_IS_ICMP_UNREACH_PORT(reply) ||  \
   SCAMPER_PING_REPLY_IS_UDP(reply))))

#define SCAMPER_PING_FLAG_IS_V4RR(ping) (	\
 (ping)->flags & SCAMPER_PING_FLAG_V4RR)

#define SCAMPER_PING_FLAG_IS_SPOOF(ping) (	\
 (ping)->flags & SCAMPER_PING_FLAG_SPOOF)

#define SCAMPER_PING_FLAG_IS_DLTX(ping) (	\
 (ping)->flags & SCAMPER_PING_FLAG_DLTX)

#define SCAMPER_PING_FLAG_IS_PAYLOAD(ping) (	\
 (ping)->flags & SCAMPER_PING_FLAG_PAYLOAD)

#define SCAMPER_PING_FLAG_IS_TSONLY(ping) (	\
 (ping)->flags & SCAMPER_PING_FLAG_TSONLY)

#define SCAMPER_PING_FLAG_IS_TSANDADDR(ping) (	\
 (ping)->flags & SCAMPER_PING_FLAG_TSANDADDR)

#define SCAMPER_PING_FLAG_IS_ICMPSUM(ping) (	\
 (ping)->flags & SCAMPER_PING_FLAG_ICMPSUM)

#define SCAMPER_PING_FLAG_IS_DL(ping) (		\
 (ping)->flags & SCAMPER_PING_FLAG_DL)

#define SCAMPER_PING_FLAG_IS_TBT(ping) (	\
 (ping)->flags & SCAMPER_PING_FLAG_TBT)

#define SCAMPER_PING_FLAG_IS_NOSRC(ping) (	\
 (ping)->flags & SCAMPER_PING_FLAG_NOSRC)

#define SCAMPER_PING_FLAG_IS_RAW(ping) (	\
 (ping)->flags & SCAMPER_PING_FLAG_RAW)

#define SCAMPER_PING_FLAG_IS_SOCKRX(ping) (	\
 (ping)->flags & SCAMPER_PING_FLAG_SOCKRX)

#define SCAMPER_PING_PROBE_FLAGS_MASK(reply) ( \
 (reply)->flags & (SCAMPER_PING_REPLY_FLAG_PROBE_IPID | \
		   SCAMPER_PING_REPLY_FLAG_DLTX))

struct scamper_ping_stats
{
  uint32_t       nreplies;
  uint32_t       ndups;
  uint32_t       nloss;
  uint32_t       nerrs;
  uint32_t       npend;
  struct timeval min_rtt;
  struct timeval max_rtt;
  struct timeval avg_rtt;
  struct timeval stddev_rtt;
};

struct scamper_ifname;

/*
 * scamper_ping_reply_v4rr
 *
 * if the ping probes are using the IP record route option, this structure
 * contains the interfaces extracted from the response.
 */
struct scamper_ping_reply_v4rr
{
  scamper_addr_t **ip;
  uint8_t          ipc;
};

/*
 * scamper_ping_reply_v4ts
 *
 * if the ping probes are using the IPv4 timestamp option, this structure
 * contains data extracted from the response.  if the ping->flags field
 * has SCAMPER_PING_FLAG_TSONLY set, then there are no IP addresses included.
 * otherwise, if SCAMPER_PING_FLAG_TSANDADDR is set then there are IP
 * addresses.
 */
struct scamper_ping_reply_v4ts
{
  scamper_addr_t **ips; /* IP addresses, if SCAMPER_PING_FLAG_TSANDADDR */
  uint32_t        *tss; /* timestamps */
  uint8_t          tsc; /* the number of timestamps (ip addresses) */
};

/*
 * scamper_ping_reply_tsreply
 *
 * if the ping probes are ICMP timestamp requests, these are the timestamps
 * recorded in the response.
 */
struct scamper_ping_reply_tsreply
{
  uint32_t         tso;
  uint32_t         tsr;
  uint32_t         tst;
};

/*
 * scamper_ping_v4ts
 *
 * if the ping probe is using the IPv4 pre-specified timestamp option, this
 * structure contains the IP addresses to include.  a maximum of four.
 */
struct scamper_ping_v4ts
{
  scamper_addr_t **ips;
  uint8_t          ipc;
};

/*
 * scamper_ping_reply
 *
 * a ping reply structure keeps track of how a ping packet was responded to.
 */
struct scamper_ping_reply
{
  /* where the response came from */
  scamper_addr_t            *addr;

  /* flags defined by SCAMPER_PING_REPLY_FLAG_* */
  uint8_t                    flags;

  /* the TTL / size of the packet that is returned */
  uint8_t                    proto;
  uint8_t                    ttl;
  uint8_t                    tos;
  uint32_t                   ipid32;
  uint16_t                   size;

  /* the icmp type / code returned */
  uint8_t                    icmp_type;
  uint8_t                    icmp_code;
  uint16_t                   icmp_nhmtu;

  /* the tcp flags returned */
  uint16_t                   tcp_mss;
  uint8_t                    tcp_flags;

  /* the time elapsed between sending the probe and getting this response */
  struct timeval             rtt;

  /* the name of the interface that received the response */
  struct scamper_ifname     *ifname;

  /* data found in IP options, if any */
  scamper_ping_reply_v4rr_t *v4rr;
  scamper_ping_reply_v4ts_t *v4ts;
  scamper_ping_reply_tsreply_t *tsreply;

#ifdef BUILDING_LIBSCAMPERFILE
  int                        refcnt;
#endif
};

struct scamper_ping_probe
{
  struct timeval             tx;
  uint16_t                   id;
  uint16_t                   ipid;
  uint16_t                   sport;
  uint8_t                    flags;

  scamper_ping_reply_t     **replies;
  uint16_t                   replyc;

#ifdef BUILDING_LIBSCAMPERFILE
  int                        refcnt;
#endif
};

/*
 * scamper_ping
 *
 * this structure contains details of a ping between a source and a
 * destination.  is specifies the parameters to the ping and the
 * replies themselves.
 */
struct scamper_ping
{
  /* the list / cycle that this ping is in relation to */
  scamper_list_t        *list;
  scamper_cycle_t       *cycle;
  uint32_t               userid;

  /* source and destination addresses of the ping */
  scamper_addr_t        *src;          /* -S option */
  scamper_addr_t        *dst;
  scamper_addr_t        *rtr;          /* -r option */

  /* when the ping started */
  struct timeval         start;

  /* why the ping finished */
  uint8_t                stop_reason;
  uint8_t                stop_data;

  /* the data to use inside of a probe.  if null then all zeros */
  uint8_t               *data;
  uint16_t               datalen;

  /* ping options */
  struct timeval         wait_probe;       /* -i */
  struct timeval         wait_timeout;     /* -W */
  uint16_t               attempts;         /* -c */
  uint16_t               size;             /* -s */
  uint8_t                method;           /* -P */
  uint8_t                ttl;              /* -m */
  uint8_t                tos;              /* -z */
  uint8_t                stream;           /* -y */
  uint16_t               sport;            /* -F */
  uint16_t               dport;            /* -d */
  uint16_t               icmpsum;          /* -C */
  uint16_t               tcpmss;           /* -O mss= */
  uint32_t               tcpseq;           /* -A w/ tcp-syn and tcp-rst */
  uint32_t               tcpack;           /* -A w/ other tcp probe methods */
  uint16_t               stop_count;       /* -o */
  uint16_t               pmtu;             /* -M */
  scamper_ping_v4ts_t   *tsps;             /* -T */
  uint32_t               flags;

  /* actual data collected with the ping */
  scamper_ping_probe_t **probes;
  uint16_t               ping_sent;
};

#endif /* __SCAMPER_PING_INT_H */
