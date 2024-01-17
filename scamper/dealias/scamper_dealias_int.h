/*
 * scamper_dealias_int.h
 *
 * $Id: scamper_dealias_int.h,v 1.18 2024/01/16 06:55:18 mjl Exp $
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

#ifndef __SCAMPER_DEALIAS_INT_H
#define __SCAMPER_DEALIAS_INT_H

#define SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def) (        \
 (def)->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO)

#define SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def) (         \
 (def)->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP ||     \
 (def)->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT)

#define SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def) (               \
 (def)->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK ||       \
 (def)->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT || \
 (def)->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_SYN_SPORT)

#define SCAMPER_DEALIAS_PROBEDEF_VARY_TCP_SPORT(def) ( \
 (def)->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT || \
 (def)->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_SYN_SPORT)

#define SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP_ACK(def) (           \
 (def)->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK ||       \
 (def)->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT)

#define SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP_SYN(def) (           \
 (def)->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_SYN_SPORT)

#define SCAMPER_DEALIAS_REPLY_IS_ICMP(reply) ( \
 ((reply)->proto == 1 || (reply)->proto == 58))

#define SCAMPER_DEALIAS_REPLY_IS_TCP(reply) ( \
 ((reply)->proto == 6))

#define SCAMPER_DEALIAS_REPLY_IS_ICMP_TTL_EXP(reply) ( \
 ((reply)->proto == 1  && (reply)->icmp_type == 11) || \
 ((reply)->proto == 58 && (reply)->icmp_type == 3))

#define SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH(reply) ( \
 ((reply)->proto == 1  && (reply)->icmp_type == 3) ||  \
 ((reply)->proto == 58 && (reply)->icmp_type == 1))

#define SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH_PORT(reply) ( \
 ((reply)->proto == 1 &&                                    \
  (reply)->icmp_type == 3 && (reply)->icmp_code == 3) ||    \
 ((reply)->proto == 58 &&                                   \
  (reply)->icmp_type == 1 && (reply)->icmp_code == 4))

#define SCAMPER_DEALIAS_REPLY_IS_ICMP_ECHO_REPLY(reply) ( \
 ((reply)->proto == 1  && (reply)->icmp_type == 0) ||     \
 ((reply)->proto == 58 && (reply)->icmp_type == 129))

#define SCAMPER_DEALIAS_METHOD_IS_MERCATOR(d) ( \
 (d)->method == SCAMPER_DEALIAS_METHOD_MERCATOR)

#define SCAMPER_DEALIAS_METHOD_IS_ALLY(d) ( \
 (d)->method == SCAMPER_DEALIAS_METHOD_ALLY)

#define SCAMPER_DEALIAS_METHOD_IS_RADARGUN(d) ( \
 (d)->method == SCAMPER_DEALIAS_METHOD_RADARGUN)

#define SCAMPER_DEALIAS_METHOD_IS_PREFIXSCAN(d) ( \
 (d)->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)

#define SCAMPER_DEALIAS_METHOD_IS_BUMP(d) ( \
 (d)->method == SCAMPER_DEALIAS_METHOD_BUMP)

#define SCAMPER_DEALIAS_METHOD_IS_MIDAREST(d) ( \
 (d)->method == SCAMPER_DEALIAS_METHOD_MIDAREST)

#define SCAMPER_DEALIAS_METHOD_IS_MIDARDISC(d) ( \
 (d)->method == SCAMPER_DEALIAS_METHOD_MIDARDISC)

#define SCAMPER_DEALIAS_RESULT_IS_NONE(d) ( \
 (d)->result == SCAMPER_DEALIAS_RESULT_NONE)

#define SCAMPER_DEALIAS_RESULT_IS_ALIASES(d) ( \
 (d)->result == SCAMPER_DEALIAS_RESULT_ALIASES)

#define SCAMPER_DEALIAS_RESULT_IS_NOTALIASES(d) ( \
 (d)->result == SCAMPER_DEALIAS_RESULT_NOTALIASES)

#define SCAMPER_DEALIAS_ALLY_IS_NOBS(ally) (	  \
 (ally)->flags & SCAMPER_DEALIAS_ALLY_FLAG_NOBS)

#define SCAMPER_DEALIAS_PREFIXSCAN_IS_NOBS(pfs) ( \
 (pfs)->flags & SCAMPER_DEALIAS_PREFIXSCAN_FLAG_NOBS)

#define SCAMPER_DEALIAS_REPLY_FROM_TARGET(p, r) (          \
 (SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP((p)->def) &&  \
  SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH_PORT((r))) ||      \
 (SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP((p)->def) && \
  SCAMPER_DEALIAS_REPLY_IS_ICMP_ECHO_REPLY((r))) ||        \
 (SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP((p)->def) &&  \
  SCAMPER_DEALIAS_REPLY_IS_TCP((r))))

struct scamper_dealias_reply
{
  scamper_addr_t               *src;
  struct timeval                rx;
  uint8_t                       flags;
  uint8_t                       proto;
  uint8_t                       ttl;
  uint8_t                       icmp_type;
  uint8_t                       icmp_code;
  uint8_t                       icmp_q_ttl;
  uint8_t                       tcp_flags;
  uint16_t                      size;
  uint16_t                      ipid;
  uint32_t                      ipid32;
  struct scamper_icmpext       *icmp_ext;

#ifdef BUILDING_LIBSCAMPERFILE
  int                           refcnt;
#endif
};

struct scamper_dealias_probedef_udp
{
  uint16_t sport;
  uint16_t dport;
};

struct scamper_dealias_probedef_icmp
{
  uint16_t csum;
  uint16_t id;
};

struct scamper_dealias_probedef_tcp
{
  uint16_t sport;
  uint16_t dport;
  uint8_t  flags;
};

struct scamper_dealias_probedef
{
  scamper_addr_t                   *src;
  scamper_addr_t                   *dst;
  uint32_t                          id;
  uint8_t                           method;
  uint8_t                           ttl;
  uint8_t                           tos;
  uint16_t                          size;
  uint16_t                          mtu;
  union
  {
    scamper_dealias_probedef_udp_t  udp;
    scamper_dealias_probedef_tcp_t  tcp;
    scamper_dealias_probedef_icmp_t icmp;
  } un;

#ifdef BUILDING_LIBSCAMPERFILE
  int                               refcnt;
#endif
};

struct scamper_dealias_probe
{
  scamper_dealias_probedef_t   *def;
  uint32_t                      seq;
  struct timeval                tx;
  scamper_dealias_reply_t     **replies;
  uint16_t                      replyc;
  uint16_t                      ipid;

#ifdef BUILDING_LIBSCAMPERFILE
  int                           refcnt;
#endif
};

struct scamper_dealias_mercator
{
  scamper_dealias_probedef_t   *probedef;
  uint8_t                       attempts;
  struct timeval                wait_timeout;

#ifdef BUILDING_LIBSCAMPERFILE
  int                           refcnt;
#endif
};

struct scamper_dealias_ally
{
  scamper_dealias_probedef_t   *probedefs[2];
  struct timeval                wait_probe;
  struct timeval                wait_timeout;
  uint8_t                       attempts;
  uint8_t                       flags;
  uint16_t                      fudge;

#ifdef BUILDING_LIBSCAMPERFILE
  int                           refcnt;
#endif
};

/*
 * scamper_dealias_radargun
 *
 * the following variables define a radargun measurement.  radargun was
 * first defined in the following paper:
 *
 *   Fixing ally's growing pains with velocity modeling.  Adam Bender, Rob
 *   Sherwood, Neil Spring. Proc. IMC 2008, pages 337-342.
 *
 * probedefs    : structures defining the form of a probe packet
 * rounds       : number of times to send each probe packet
 * flags        : flags to adjust the behaviour of radargun
 * wait_probe   : minimum length of time to wait between probes in a round
 * wait_round   : minimum length of time to wait between attempts
 * wait_timeout : minimum length of time to wait for a response
 */
struct scamper_dealias_radargun
{
  scamper_dealias_probedef_t  **probedefs;
  uint32_t                      probedefc;
  uint16_t                      rounds;
  uint8_t                       flags;
  struct timeval                wait_probe;
  struct timeval                wait_round;
  struct timeval                wait_timeout;

#ifdef BUILDING_LIBSCAMPERFILE
  int                           refcnt;
#endif
};

/*
 * scamper_dealias_prefixscan
 *
 * given an IP link defined by `a' and `b', try and find an alias for `a'
 * that would be found on the same subnet as `b'.  if such an alias is
 * found, store it in `ab'.
 */
struct scamper_dealias_prefixscan
{
  scamper_addr_t                     *a;            /* hop a */
  scamper_addr_t                     *b;            /* hop b */
  scamper_addr_t                     *ab;           /* alias found */
  scamper_addr_t                    **xs;           /* ifaces to exclude */
  uint16_t                            xc;           /* # ifaces to exclude */
  uint8_t                             prefix;       /* range of IPs to scan */
  uint8_t                             attempts;     /* how many attempts */
  uint8_t                             replyc;       /* replies required */
  uint16_t                            fudge;        /* ipid fudge */
  struct timeval                      wait_probe;   /* how long b/w probes */
  struct timeval                      wait_timeout; /* when to declare lost */
  uint8_t                             flags;        /* flags */
  scamper_dealias_probedef_t        **probedefs;    /* probedefs used */
  uint16_t                            probedefc;    /* how many were used */

#ifdef BUILDING_LIBSCAMPERFILE
  int                                 refcnt;
#endif
};

/*
 * scamper_dealias_bump
 *
 * given two IP addresses thought to be aliases, try and confirm this by
 * attempting to bump their IP-ID counters out of synchronisation.
 */
struct scamper_dealias_bump
{
  scamper_dealias_probedef_t   *probedefs[2];
  struct timeval                wait_probe;
  uint16_t                      bump_limit;
  uint8_t                       attempts;

#ifdef BUILDING_LIBSCAMPERFILE
  int                           refcnt;
#endif
};

struct scamper_dealias_midarest
{
  scamper_dealias_probedef_t  **probedefs;
  uint16_t                      probedefc;
  uint8_t                       rounds;       /* the number of rounds */
  struct timeval                wait_probe;   /* time to wait between probes */
  struct timeval                wait_round;   /* length of each round */
  struct timeval                wait_timeout; /* how long to wait for replies */

#ifdef BUILDING_LIBSCAMPERFILE
  int                           refcnt;
#endif
};

struct scamper_dealias_midardisc_round
{
  struct timeval                start;        /* relative time to start */
  uint32_t                      begin;        /* begin index into probedefs */
  uint32_t                      end;          /* end index into probedefs */
};

struct scamper_dealias_midardisc
{
  scamper_dealias_probedef_t        **probedefs;
  uint32_t                            probedefc;
  scamper_dealias_midardisc_round_t **sched;
  uint32_t                            schedc;
  struct timeval                     *startat;
  struct timeval                      wait_timeout;

#ifdef BUILDING_LIBSCAMPERFILE
  int                                 refcnt;
#endif
};

struct scamper_dealias
{
  scamper_list_t               *list;
  scamper_cycle_t              *cycle;
  uint32_t                      userid;
  struct timeval                start;
  uint8_t                       method;
  uint8_t                       result;
  void                         *data;
  scamper_dealias_probe_t     **probes;
  uint32_t                      probec;
};

scamper_dealias_t *scamper_dealias_alloc(void);
scamper_dealias_probe_t *scamper_dealias_probe_alloc(void);
scamper_dealias_reply_t *scamper_dealias_reply_alloc(void);

scamper_dealias_ally_t *scamper_dealias_ally_alloc(void);
scamper_dealias_mercator_t *scamper_dealias_mercator_alloc(void);
scamper_dealias_radargun_t *scamper_dealias_radargun_alloc(void);
scamper_dealias_prefixscan_t *scamper_dealias_prefixscan_alloc(void);
scamper_dealias_bump_t *scamper_dealias_bump_alloc(void);
scamper_dealias_midarest_t *scamper_dealias_midarest_alloc(void);
scamper_dealias_midardisc_t *scamper_dealias_midardisc_alloc(void);

int scamper_dealias_probes_alloc(scamper_dealias_t *, uint32_t);
int scamper_dealias_replies_alloc(scamper_dealias_probe_t *, uint16_t);

int scamper_dealias_probe_add(scamper_dealias_t *dealias,
			      scamper_dealias_probe_t *probe);
int scamper_dealias_reply_add(scamper_dealias_probe_t *probe,
			      scamper_dealias_reply_t *reply);

int scamper_dealias_prefixscan_probedefs_alloc(scamper_dealias_prefixscan_t *,
					       uint32_t);
int scamper_dealias_prefixscan_probedef_add(scamper_dealias_t *,
					    const scamper_dealias_probedef_t *);

int scamper_dealias_radargun_probedefs_alloc(scamper_dealias_radargun_t *,
					     uint32_t);

int scamper_dealias_prefixscan_xs_alloc(scamper_dealias_prefixscan_t *,
					uint16_t);
int scamper_dealias_prefixscan_xs_add(scamper_dealias_t *, scamper_addr_t *);
int scamper_dealias_prefixscan_xs_in(scamper_dealias_t *, scamper_addr_t *);

int scamper_dealias_midarest_probedefs_alloc(scamper_dealias_midarest_t *me,
					     uint16_t c);
int scamper_dealias_midardisc_probedefs_alloc(scamper_dealias_midardisc_t *md,
					      uint32_t c);
int scamper_dealias_midardisc_sched_alloc(scamper_dealias_midardisc_t *md,
					  uint32_t c);

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
int scamper_dealias_ipid_inseq(scamper_dealias_probe_t **probes, int probec,
			       uint16_t fudge, int bs);

#endif /* __SCAMPER_DEALIAS_INT_H */
