/*
 * scamper_do_trace.c
 *
 * $Id: scamper_trace_do.c,v 1.414 2025/05/03 01:40:35 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2008      Alistair King
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2015      The University of Waikato
 * Copyright (C) 2019-2025 Matthew Luckie
 * Copyright (C) 2024      The Regents of the University of California
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_config.h"
#include "scamper_debug.h"
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_icmpext_int.h"
#include "scamper_trace.h"
#include "scamper_trace_int.h"
#include "scamper_task.h"
#include "scamper_queue.h"
#include "scamper_icmp_resp.h"
#include "scamper_dl.h"
#include "scamper_fds.h"
#include "scamper_dlhdr.h"
#include "scamper_probe.h"
#include "scamper_rtsock.h"
#include "scamper_getsrc.h"
#include "scamper_file.h"
#include "scamper_trace_do.h"
#include "scamper_addr2mac.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_tcp4.h"
#include "scamper_udp4.h"
#include "scamper_udp6.h"
#include "scamper_if.h"
#include "scamper_osinfo.h"
#ifndef DISABLE_SCAMPER_HOST
#include "host/scamper_host_do.h"
#endif
#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "mjl_heap.h"
#include "utils.h"

/*
 * pmtud_L2_state
 *
 * this struct records state when inferring the MTU of the underlying media.
 *
 * when scamper has to discover the MTU of the link itself, it uses the L2
 * table above to choose a suitable initial guess.  it records the index
 * into the L2 table into L2_idx.
 */
typedef struct pmtud_L2_state
{
  int                    idx;   /* index into the L2 table */
  int                    lower; /* lower bounds of the L2 search space */
  int                    upper; /* upper bounds of the L2 search space */
  int                    in;    /* probe size to not get a suitable response */
  int                    out;   /* size of probe to infer underlying MTU */
  scamper_trace_reply_t *hop;   /* the last probe to obtain a response */
} pmtud_L2_state_t;

/*
 * pmtud_TTL_state
 *
 * this struct records state when inferring the TTL range of hops that
 * are responsible for not sending a fragmentation required message where
 * one is required.
 */
typedef struct pmtud_TTL_state
{
  int                    lower; /* lower bounds of the TTL search space */
  int                    upper; /* upper bounds of the TTL search space */
  scamper_trace_reply_t *hop;   /* the last TTL probe to obtain a response */
} pmtud_TTL_state_t;

/*
 * pmtud_L2
 *
 * this struct associates a known MTU with an index into an array.
 */
typedef struct pmtud_L2
{
  int   idx;            /* index into the L2 array where this node resides */
  int   mtu;            /* the MTU of the link */
} pmtud_L2_t;

typedef struct trace_lss
{
  char             *name;
  splaytree_t      *tree;
  splaytree_node_t *node;
} trace_lss_t;

/*
 * trace_probe
 *
 * this struct keeps state of each probe sent with the trace
 */
typedef struct trace_probe
{
  scamper_trace_probe_t *probe; /* data recorded in trace object */
  struct timeval  dl_rx;  /* datalink rx timestamp for first reply */
  uint8_t         mode;   /* the mode scamper was in when probe was sent */
  uint8_t         flags;  /* the probe's flags */
  uint16_t        id;     /* the probe's ID value */
} trace_probe_t;

#ifndef DISABLE_SCAMPER_HOST
typedef struct trace_host
{
  scamper_addr_t          *addr;   /* address to look up */
  char                    *name;   /* name, if known */
  scamper_host_do_t       *hostdo; /* hostdo structure while waiting */
  slist_t                 *hops;   /* list of hops that want the answer */
} trace_host_t;
#endif

#define TRACE_PROBE_FLAG_STORED  0x01
#define TRACE_PROBE_FLAG_DL_RX   0x02
#define TRACE_PROBE_FLAG_TIMEOUT 0x04
#define TRACE_ALLOC_HOPS         16

/*
 * trace_pmtud_state
 *
 * these fields are used in Path MTU discovery
 */
typedef struct trace_pmtud_state
{
  pmtud_L2_state_t           *L2;           /* state kept for L2 MTU search */
  pmtud_TTL_state_t          *TTL;          /* state kept for TTL search */
  scamper_trace_reply_t      *last_fragmsg; /* last fragmentation msg stored */
  scamper_trace_pmtud_note_t *note;         /* note to fill out */
} trace_pmtud_state_t;

/*
 * trace_dtree_state
 *
 * these fields are used for doubletree, when there's a local stop set
 * involved.
 * the lss contains the list of addresses visited when probing backwards.
 * this is a subset of the global lss.
 * it is used to probe backwards through a loop, where otherwise probing
 * would be halted by the first address in the loop being added to the lss
 * the first time it is seen.
 */
typedef struct trace_dtree_state
{
  scamper_addr_t     **lss;
  size_t               lssc;
  trace_lss_t         *lsst;
} trace_dtree_state_t;

/*
 * trace_conf_state
 *
 * these fields are used when probing to enumerate all interfaces at a hop
 */
typedef struct trace_conf_state
{
  scamper_addr_t     **interfaces;    /* ifaces found so far at this ttl */
  size_t               interfacec;    /* count of interfaces */
  uint8_t              confidence;    /* index into k[] */
  uint8_t              n;             /* index into k[] */
} trace_conf_state_t;

/*
 * trace_para_state
 *
 * these fields are used when probing hops in parallel
 */
typedef struct trace_para_state
{
  dlist_t             *window;        /* current window of probes */
  slist_t             *probeq;        /* probes to retry */
  heap_t              *hopwait;       /* hops waiting to be re-probed */
  uint8_t              max_ttl;       /* max TTL that got a response */
  uint8_t              floor;         /* lower bound of parallel window */
} trace_para_state_t;

/*
 * trace_hop_state
 *
 * this structure is kept per-hop when squeries > 1
 */
typedef struct trace_hop_state
{
  struct timeval           last_tx;
  uint8_t                  ttl;
  uint8_t                  attempt;
  uint16_t                 id;
} trace_hop_state_t;

/*
 * trace_state
 *
 * this is a fairly large struct that keeps state for the traceroute
 * process.  it also deals with state in the PMTUD phase, if used.
 */
typedef struct trace_state
{
  uint8_t              mode;          /* current trace mode scamper is in */
  uint8_t              attempt;       /* attempt number at the current probe */
  uint8_t              loopc;         /* count of loops so far */
  uint8_t              flags;         /* flags for keeping state */
  uint16_t             ttl;           /* ttl to set in the probe packet */
  uint16_t             alloc_hops;    /* number of trace->hops allocated */
  uint16_t             payload_size;  /* how much payload to include */
  uint16_t             header_size;   /* size of headers */
  struct timeval       last_tx;       /* when the last probe was */

#ifndef DISABLE_SCAMPER_HOST
  splaytree_t         *ths;           /* tree for host lookups */
#endif

#ifndef _WIN32 /* windows does not have a routing socket */
  scamper_fd_t        *rtsock;        /* fd to query route socket with */
#endif

  scamper_fd_t        *icmp;          /* fd to listen to icmp packets with */
  scamper_fd_t        *probe;         /* fd to probe with */
  scamper_fd_t        *dl;            /* struct to use with datalink access */
  scamper_fd_t        *raw;           /* raw socket for tcp/udp probes */

  scamper_dlhdr_t     *dlhdr;         /* header to use with datalink */
  scamper_route_t     *route;         /* looking up a route */

  trace_probe_t      **probes;        /* probes sent so far */
  uint16_t             id_next;       /* next id to use in probes */
  uint16_t             id_max;        /* maximum id available */

  trace_pmtud_state_t *pmtud;         /* pmtud probing state */
  trace_dtree_state_t *dtree;         /* doubletree probing state */
  trace_conf_state_t  *conf;          /* confidence probing state */
  trace_para_state_t  *para;          /* parallel probing state */
} trace_state_t;

#define TRACE_STATE_FLAG_ICMP_ID 0x01

static const uint8_t MODE_RTSOCK           = 0;
static const uint8_t MODE_DLHDR            = 1;
static const uint8_t MODE_TRACE            = 2;
static const uint8_t MODE_LASTDITCH        = 3;
static const uint8_t MODE_PMTUD_DEFAULT    = 4;
static const uint8_t MODE_PMTUD_SILENT_L2  = 5;
static const uint8_t MODE_PMTUD_SILENT_TTL = 6;
static const uint8_t MODE_PMTUD_BADSUGG    = 7;
static const uint8_t MODE_DTREE_FIRST      = 8;
static const uint8_t MODE_DTREE_FWD        = 9;
static const uint8_t MODE_DTREE_BACK       = 10;
static const uint8_t MODE_PARALLEL         = 11;
static const uint8_t MODE_PARALLEL_FINISH  = 12;

#define MODE_MIN             MODE_TRACE
#define MODE_MAX             MODE_PARALLEL_FINISH

#define MODE_IS_TRACE(mode) ((mode) == MODE_TRACE)

#define MODE_IS_LASTDITCH(mode) ((mode) == MODE_LASTDITCH)

#define MODE_IS_PMTUD(mode) ((mode) == MODE_PMTUD_DEFAULT ||	\
			     (mode) == MODE_PMTUD_SILENT_L2 ||	\
			     (mode) == MODE_PMTUD_SILENT_TTL ||	\
			     (mode) == MODE_PMTUD_BADSUGG)

#define MODE_IS_DTREE(mode) ((mode) == MODE_DTREE_FIRST ||	\
			     (mode) == MODE_DTREE_FWD ||	\
			     (mode) == MODE_DTREE_BACK)

#define MODE_IS_PARALLEL(mode) ((mode) == MODE_PARALLEL ||	\
				(mode) == MODE_PARALLEL_FINISH)

/* the callback functions registered with the trace task */
static scamper_task_funcs_t trace_funcs;

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

/* temporary tx buffer shared amongst measurements */
extern uint8_t *txbuf;
extern size_t   txbuf_len;

/* running scamper configuration */
extern scamper_config_t *config;

/* local stop sets */
static splaytree_t *lsses = NULL;

/*
 * these MTUs were largely taken from the NetBSD version of traceroute, and
 * are used to choose a packet size to probe with in the absence of a
 * Fragmentation Needed message.
 *
 * they have been annotated with their corresponding Layer 2 type, largely
 * taken from RFC 1191
 */
static const pmtud_L2_t L2[] =
{
  { 0,    68}, /* Official RFC 791 minimum MTU */
  { 1,   296}, /* Point-to-Point links, (low delay) */
  { 2,   508},
  { 3,   512}, /* NetBIOS */
  { 4,   544}, /* DEC IP Portal */
  { 5,   552},
  { 6,   576}, /* X25 MTU, IPv4 Minimum MTU */
  { 7,  1006}, /* SLIP */
  { 8,  1280}, /* IPv6 Minimum MTU */
  { 9,  1454}, /* an optimally sized PPPoE frame in DSL */
  {10,  1480}, /* Ethernet MTU with tunnel over IPv4 */
  {11,  1492}, /* IEEE 802.3 */
  {12,  1500}, /* Ethernet MTU */
  {13,  1514}, /* Ethernet Max MTU */
  {14,  1536}, /* Exp. Ethernet Nets */
  {15,  2002}, /* IEEE 802.5, Recommended MTU */
  {16,  2048}, /* Wideband Network */
  {17,  4352}, /* FDDI */
  {18,  4464}, /* IEEE 802.5, Maximum MTU */
  {19,  4470}, /* ATM / T3 / SONET SDH */
  {20,  8166}, /* IEEE 802.4 */
  {21,  9000}, /* Broadcom GigE MTU */
  {22,  9192}, /* OC-192 and other really fast media */
  {23, 16110}, /* Intel Pro 1000 MTU */
  {24, 17914}, /* 16Mb IBM Token Ring */
  {25, 65535}  /* The IPv[46] Maximum MTU */
};

static const pmtud_L2_t *L2_1454 = &L2[9];
static const pmtud_L2_t *L2_1500 = &L2[12];
static const int         L2_cnt  = sizeof(L2) / sizeof(pmtud_L2_t);

static void trace_next_mode(scamper_task_t *task, const struct timeval *now);

static scamper_trace_t *trace_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static trace_state_t *trace_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static int k(trace_conf_state_t *conf)
{
  /*
   * number of probes (k) to send to rule out a load-balancer having n hops;
   * 95% confidence level first from 823-augustin-e2emon.pdf, then extended
   * with gmp-based code.
   * 99% confidence derived with gmp-based code.
   */
  static const int k[][2] = {
    {   0,   0 },
    {   0,   0 },
    {   6,   8 }, /* n=2  : +6, +8 */
    {  11,  15 }, /* n=3  : +5, +7 */
    {  16,  21 }, /* n=4  : +5, +6 */
    {  21,  28 }, /* n=5  : +5, +7 */
    {  27,  36 }, /* n=6  : +6, +8 */
    {  33,  43 }, /* n=7  : +6, +7 */
    {  38,  51 }, /* n=8  : +5, +8 */
    {  44,  58 }, /* n=9  : +6, +7 */
    {  51,  66 }, /* n=10 : +7, +8 */
    {  57,  74 }, /* n=11 : +6, +8 */
    {  63,  82 }, /* n=12 : +6, +8 */
    {  70,  90 }, /* n=13 : +7, +8 */
    {  76,  98 }, /* n=14 : +6, +8 */
    {  83, 106 }, /* n=15 : +7, +8 */
    {  90, 115 }, /* n=16 : +7, +9 */
    {  96, 123 }, /* n=17 : +6, +8 */
    { 103, 132 }, /* n=18 : +7, +9 */
    { 110, 140 }, /* n=19 : +7, +8 */
    { 117, 149 }, /* n=20 : +7, +9 */
    { 124, 157 }, /* n=21 */
    { 131, 166 }, /* n=22 */
    { 138, 175 }, /* n=23 */
    { 145, 183 }, /* n=24 */
    { 152, 192 }, /* n=25 */
  };

#define TRACE_CONFIDENCE_MAX_N 25

  assert(conf->confidence < 2);
  assert(conf->n >= 2);
  assert(conf->n <= TRACE_CONFIDENCE_MAX_N);
  return k[conf->n][conf->confidence];
}

/*
 * trace_stop
 *
 * set the trace's stop parameters to whatever it is passed
 */
static void trace_stop(scamper_trace_t *trace,
		       const uint8_t reason, const uint8_t data)
{
  /* if we've already set a stop reason, then don't clobber it */
  if(trace->stop_reason != SCAMPER_TRACE_STOP_NONE)
    {
      scamper_debug(__func__, "reason %d/%d precedes %d/%d",
		    trace->stop_reason, trace->stop_data, reason, data);
      return;
    }

  trace->stop_reason = reason;
  trace->stop_data   = data;

  return;
}

static void trace_stop_completed(scamper_trace_t *trace)
{
  trace_stop(trace, SCAMPER_TRACE_STOP_COMPLETED, 0);
  return;
}

static void trace_stop_gaplimit(scamper_trace_t *trace)
{
  trace_stop(trace, SCAMPER_TRACE_STOP_GAPLIMIT, 0);
  return;
}

static void trace_stop_error(scamper_trace_t *trace, int error)
{
  trace_stop(trace, SCAMPER_TRACE_STOP_ERROR, error);
  return;
}

static void trace_stop_hoplimit(scamper_trace_t *trace)
{
  trace_stop(trace, SCAMPER_TRACE_STOP_HOPLIMIT, 0);
  return;
}

static scamper_trace_reply_t *trace_hop_get(const scamper_trace_t *trace,
					    uint8_t i)
{
  if(trace->hops[i] != NULL)
    return scamper_trace_probettl_reply_get(trace->hops[i]);
  return NULL;
}

static int trace_hop_state_cmp(const trace_hop_state_t *a,
			       const trace_hop_state_t *b)
{
  return timeval_cmp(&b->last_tx, &a->last_tx);
}

#ifndef DISABLE_SCAMPER_HOST
static int trace_host_cmp(const trace_host_t *a, const trace_host_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static void trace_host_free(trace_host_t *th)
{
  if(th->hostdo != NULL) scamper_host_do_free(th->hostdo);
  if(th->addr != NULL) scamper_addr_free(th->addr);
  if(th->name != NULL) free(th->name);
  if(th->hops != NULL) slist_free(th->hops);
  free(th);
  return;
}

static trace_host_t *trace_host_alloc(scamper_trace_reply_t *hop)
{
  trace_host_t *th = NULL;
  if((th = malloc_zero(sizeof(trace_host_t))) == NULL ||
     (th->hops = slist_alloc()) == NULL ||
     slist_tail_push(th->hops, hop) == NULL)
    goto err;
  th->addr = scamper_addr_use(hop->addr);
  return th;

 err:
  if(th != NULL) trace_host_free(th);
  return NULL;
}
#endif

/*
 * trace_queue_probe
 *
 * we want to send a probe now, but that time might be earlier than
 * allowed by trace->wait_probe given the last time scamper sent a
 * packet for this destination.
 */
static int trace_queue_probe(scamper_task_t *task, const struct timeval *now)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  struct timeval next_tx;

  /*
   * we've got a reply, send the next probe now if we don't need to
   * wait a minimum length of time between probes
   */
  if(timeval_iszero(&trace->wait_probe))
    return scamper_task_queue_probe(task);

  /* enforce the minimum delay between probes */
  timeval_add_tv3(&next_tx, &state->last_tx, &trace->wait_probe);
  if(timeval_cmp(&next_tx, now) <= 0)
    return scamper_task_queue_probe(task);
  return scamper_task_queue_wait_tv(task, &next_tx);
}

static int trace_queue_done(scamper_task_t *task)
{
  scamper_task_queue_done(task, 0);
  return 0;
}

/*
 * trace_parallel_isempty
 *
 * is the queue for parallel probing empty?
 */
static int trace_parallel_isempty(const trace_para_state_t *state)
{
  if(slist_count(state->probeq) != 0 ||
     dlist_count(state->window) != 0 ||
     (state->hopwait != NULL && heap_count(state->hopwait) != 0))
    return 0;
  return 1;
}

static int trace_queue_parallel(scamper_task_t *task, const struct timeval *now)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  trace_para_state_t *para = state->para;
  trace_hop_state_t *hs;
  trace_probe_t *tp;
  struct timeval next[2], tv;
  int nextc = 0;
  int i;

  assert(para != NULL);

  /*
   * if we're enforcing a minimum time between probes to the same hop,
   * then check to see if time has elapsed
   */
  if(para->hopwait != NULL)
    {
      while((hs = heap_head_item(para->hopwait)) != NULL)
	{
	  timeval_add_tv3(&tv, &hs->last_tx, &trace->wait_probe_hop);
	  if(timeval_cmp(&tv, now) > 0)
	    {
	      timeval_cpy(&next[nextc++], &tv);
	      break;
	    }
	  heap_remove(para->hopwait);
	  if(slist_tail_push(para->probeq, hs) == NULL)
	    {
	      printerror(__func__, "could not push hs");
	      free(hs);
	      return -1;
	    }
	}
    }

  /* expire probes whose attempts/timeout has elapsed */
  while((hs = dlist_head_item(para->window)) != NULL)
    {
      timeval_add_tv3(&tv, &hs->last_tx, &trace->wait_timeout);
      if(timeval_cmp(&tv, now) > 0)
	{
	  timeval_cpy(&next[nextc++], &tv);
	  break;
	}
      dlist_head_pop(para->window);

      tp = state->probes[hs->id]; assert(tp->probe->replyc == 0);
      tp->flags |= TRACE_PROBE_FLAG_TIMEOUT;
      if(hs->attempt < trace->attempts)
	{
	  if(slist_tail_push(para->probeq, hs) == NULL)
	    {
	      printerror(__func__, "could not push hs");
	      free(hs);
	      return -1;
	    }
	  continue;
	}

      assert(tp->probe->ttl == hs->ttl);
      if(tp->probe->ttl > para->floor)
	para->floor = tp->probe->ttl;
      free(hs);
    }

  /* probe ready to go right now */
  if(slist_count(para->probeq) > 0)
    return trace_queue_probe(task, now);

  /*
   * if we are in the parallel probing mode and we have room for more
   * probes, then keep going
   */
  if(state->mode == MODE_PARALLEL)
    {
      if(state->ttl <= (trace->hoplimit == 0 ? 255 : trace->hoplimit) &&
	 state->ttl - para->floor <= trace->squeries &&
	 state->ttl - para->max_ttl <= trace->gaplimit)
	return trace_queue_probe(task, now);
    }
  else if(state->mode == MODE_PARALLEL_FINISH)
    {
      if(trace_parallel_isempty(para))
	goto next_mode;
    }

  if(trace_parallel_isempty(para))
    {
      /*
       * if we haven't checked to see if the path is dead yet, check
       * to see if we should do so at this time.  a dead path is
       * defined as a path that has an unresponsive target host, which
       * we stop tracing after the gaplimit is reached.
       */
      if(para->floor - (trace->firsthop - 1) >= trace->gaplimit)
	{
	  /* see if there are any responses for the possible gaplimit hops */
	  for(i=0; i<trace->gaplimit; i++)
	    if(trace_hop_get(trace, para->floor-1-i) != NULL)
	      break;

	  /* gaplimit reached */
	  if(i == trace->gaplimit)
	    {
	      trace_stop_gaplimit(trace);
	      goto next_mode;
	    }
	}

      /* check for hoplimit condition */
      if((trace->hoplimit == 0 ? 255 : trace->hoplimit) <= trace->hop_count)
	{
	  trace_stop_hoplimit(trace);
	  goto next_mode;
	}
    }

  /* set timeout based on when to re-probe an outstanding hop */
  assert(nextc > 0 && nextc <= 2);
  if(nextc == 2 && timeval_cmp(&next[1], &next[0]) < 0)
    timeval_cpy(&next[0], &next[1]);
  if(timeval_cmp(&next[0], now) <= 0)
    return trace_queue_probe(task, now);
  return scamper_task_queue_wait_tv(task, &next[0]);

 next_mode:
  trace_next_mode(task, now);
  return 0;
}

static int trace_queue_serial(scamper_task_t *task, const struct timeval *now)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  trace_probe_t *tp;
  struct timeval next_tx;

  /*
   * get the most recent probe we sent.  if we haven't got a reply yet,
   * see if we've reached the timeout.
   */
  tp = state->probes[state->id_next-1];
  if(tp->probe->replyc == 0)
    {
      /* set timeout based on when to re-probe an outstanding hop */
      timeval_add_tv3(&next_tx, &state->last_tx, &trace->wait_timeout);
      if(timeval_cmp(&next_tx, now) <= 0)
	return trace_queue_probe(task, now);
      return scamper_task_queue_wait_tv(task, &next_tx);
    }

  return trace_queue_probe(task, now);
}

/*
 * trace_queue
 *
 * the task is ready to be probed again.  put it in a queue to wait a little
 * longer, or put it into the queue to be probed asap.
 */
static int trace_queue(scamper_task_t *task, const struct timeval *now)
{
  trace_state_t *state = trace_getstate(task);
  if(MODE_IS_PARALLEL(state->mode))
    return trace_queue_parallel(task, now);
  return trace_queue_serial(task, now);
}

static void trace_lss_free(trace_lss_t *lss)
{
  if(lss == NULL)
    return;

  if(lss->name != NULL)
    free(lss->name);
  if(lss->tree != NULL)
    splaytree_free(lss->tree, (splaytree_free_t)scamper_addr_free);

  free(lss);
  return;
}

static int trace_lss_cmp(const trace_lss_t *a, const trace_lss_t *b)
{
  return strcasecmp(a->name, b->name);
}

static trace_lss_t *trace_lss_get(char *name)
{
  trace_lss_t findme, *lss;

  /* allocate a local stop set tree if necessary */
  if(lsses == NULL &&
     (lsses = splaytree_alloc((splaytree_cmp_t)trace_lss_cmp)) == NULL)
    {
      printerror(__func__, "could not allocate lss");
      return NULL;
    }

  findme.name = name;
  if((lss = splaytree_find(lsses, &findme)) != NULL)
    return lss;

  if((lss = malloc_zero(sizeof(trace_lss_t))) == NULL ||
     (lss->name = strdup(name)) == NULL ||
     (lss->tree = splaytree_alloc((splaytree_cmp_t)scamper_addr_cmp))==NULL ||
     (lss->node = splaytree_insert(lsses, lss)) == NULL)
    {
      trace_lss_free(lss);
      return NULL;
    }

  return lss;
}

/*
 * pmtud_L2_set_probesize
 *
 * given the lower and upper values of the PMTU search, suggest a packet
 * size to probe next.  apply a few heuristics to the search to try and
 * find the PMTU to the next node faster.
 */
static void pmtud_L2_set_probesize(trace_state_t *state, int lower, int upper)
{
  pmtud_L2_state_t *l2;
  int idx, size;

  /* callers should detect end of L2 search before calling this function */
  assert(lower + 1 != upper);

  /* make sure there is a L2 structure there */
  assert(state->pmtud != NULL);
  assert(state->pmtud->L2 != NULL);
  l2 = state->pmtud->L2;

  /* make sure the L2->idx parameter has been set (to something reasonable) */
  idx = l2->idx;
  assert(idx >= 0);
  assert(idx < L2_cnt);

  /* make sure the suggested window size is within the current window */
  assert(l2->lower == -1 || lower >= l2->lower);
  assert(l2->upper == -1 || upper <= l2->upper);

  /*
   * if we've narrowed it down to between two entries in the L2 table,
   * then try one byte higher than the lower, as there's a fair chance
   * the underlying mtu will be L2[idx].mtu.
   *
   * we make an exception if the lower bounds is Ethernet: there exists
   * a strong possibility the underlying MTU is Ethernet, and the cost
   * of guessing wrong [i.e. getting an unexpected response] is small.
   */
  if(lower == 1500 || (lower == L2[idx].mtu && upper <= L2[idx+1].mtu))
    {
      size = lower + 1;
    }
  /*
   * if there is a media MTU higher than the current lower bounds that
   * is smaller than the upper bounds, then try it
   */
  else if(lower >= L2[idx].mtu && L2[idx+1].mtu < upper)
    {
      size = L2[++idx].mtu;
    }
  /*
   * if we did not get a response to the last media MTU probe, and there
   * is a smaller known media MTU to try, then try it now
   */
  else if(upper == L2[idx].mtu && lower < L2[idx-1].mtu)
    {
      size = L2[--idx].mtu;
    }
  /*
   * scamper is operating between two known MTU types, do a binary chop
   */
  else
    {
      size = (lower + upper) / 2;
    }

  state->attempt = 0;
  state->payload_size = size - state->header_size;
  l2->idx = idx;
  l2->lower = lower;
  l2->upper = upper;

  return;
}

/*
 * pmtud_L2_init
 *
 * utility to search the L2 table for a suitable initial probe size, based
 * on known [to scamper] L2 media MTUs in relation to the last probe sent that
 * went unacknowledged.
 */
static int pmtud_L2_init(trace_state_t *state)
{
  pmtud_L2_state_t *l2;
  int size = state->header_size + state->payload_size;
  int idx;

  /*
   * if the probe that was not answered is > 1500 bytes and scamper has
   * not got a response to a packet 1500 bytes or larger yet, then
   * forcibly try the ethernet MTU next, as the chances are good that the
   * media will be plain old ethernet.
   */
  if(size > 1500)
    {
      idx = L2_1500->idx;
    }
  /*
   * if the probe that was not answered is > 1454 bytes, then forcibly try
   * the lower bounds of X-over-ethernet types.
   */
  else if(size > 1454)
    {
      idx = L2_1454->idx;
    }
  else
    {
      for(idx=0; idx<L2_cnt-1; idx++)
	if(size > L2[idx].mtu && size <= L2[idx+1].mtu)
	  break;
    }

  if((l2 = malloc_zero(sizeof(pmtud_L2_state_t))) == NULL)
    {
      printerror(__func__, "could not malloc L2");
      return -1;
    }
  l2->idx   = idx;
  l2->lower = -1;
  l2->upper = size;
  l2->in    = size;
  l2->out   = -1;

  state->pmtud->L2    = l2;
  state->payload_size = L2[idx].mtu - state->header_size;
  state->attempt      = 0;

  return 0;
}

/*
 * pmtud_TTL_set_probettl
 *
 * return: 0 if there are no more TTLs to probe, 1 if probing should continue
 */
static int pmtud_TTL_set_probettl(scamper_task_t *task,
				  const int lower, int upper)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  int cur;

  assert(state->pmtud->TTL != NULL);

  /* check to see if we have to do any more TTL searching */
  while(lower + 1 < upper)
    {
      /* halve the TTL space */
      cur = (lower + upper) / 2;

      /*
       * check to see if experience at soliciting a TTL expired message has
       * been good.  skip TTLs that have been non-responsive
       */
      while(cur < upper && trace->hops[cur-1] == NULL)
	{
	  cur++;
	}

      /* scamper got a suitable TTL probe value, so we are done */
      if(cur != upper)
	{
	  state->pmtud->TTL->lower = lower;
	  state->pmtud->TTL->upper = upper;
	  state->ttl = cur;
	  state->attempt = 0;
	  return 1;
	}

      /*
       * there are no TTLs above the half-way point to probe for, so try for
       * ones lower
       */
      upper = (lower + upper) / 2;
    }

  return 0;
}

/*
 * hop_find
 *
 * check to see if there is any other hop in the trace with the same
 * address; if so, return the probe that found it
 */
static scamper_trace_probe_t *hop_find(const scamper_trace_t *trace,
				       const scamper_addr_t *addr)
{
  scamper_trace_hopiter_t hi;
  scamper_trace_reply_t *hop;

  if(trace->firsthop == 0 || trace->hop_count == 0 ||
     scamper_trace_hopiter_ttl_set(&hi, trace->firsthop, 0) != 0)
    return NULL;

  while((hop = scamper_trace_hopiter_next(trace, &hi)) != NULL)
    if(scamper_addr_cmp(hop->addr, addr) == 0)
      return scamper_trace_hopiter_probe_get(&hi);

  return NULL;
}

/*
 * pmtud_TTL_init
 *
 * initialise the bounds of a TTL search
 */
static int pmtud_TTL_init(scamper_task_t *task)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  trace_pmtud_state_t *pmtud = state->pmtud;
  pmtud_L2_state_t *l2 = pmtud->L2;
  scamper_trace_probe_t *probe;
  scamper_trace_reply_t *hop;
  int lower, upper;

  if((pmtud->TTL = malloc_zero(sizeof(pmtud_TTL_state_t))) == NULL)
    {
      printerror(__func__, "could not malloc TTL");
      return -1;
    }

  /*
   * the packet size that is dropped silently is the size we are
   * doing a TTL limited search with
   */
  state->payload_size = l2->in - state->header_size;

  /*
   * use the last ICMP fragmentation required message recorded in the
   * path MTU discovery phase to infer a suitable lower-bound for inferring
   * the range of TTLs that could be responsible for not sending an ICMP
   * fragmentation required message
   */
  hop = pmtud->last_fragmsg;
  if(hop == NULL || (lower = hop->probe->ttl - hop->reply_icmp_q_ttl) < 1)
    lower = 0;

  /*
   * the upper bound of TTLs to search is set by closest response past
   * the hop that sends nothing
   */
  if((probe = hop_find(trace, l2->hop->addr)) != NULL)
    {
      upper = probe->ttl;
    }
  else
    {
      upper = l2->hop->probe->ttl - l2->hop->reply_icmp_q_ttl + 1;
    }

  /* if the TTL limited search is a null operation, then say so */
  if(pmtud_TTL_set_probettl(task, lower, upper) == 0)
    return 0;

  return 1;
}

/*
 * pmtu_L2_search_end
 *
 * scamper has had to infer the underlying next-hop MTU due to a pmtud
 * fault.  given the hop used to infer the nhmtu, insert that into the
 * trace and tidy up.
 */
static int pmtud_L2_search_end(scamper_task_t *task)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  scamper_trace_pmtud_note_t *note;
  scamper_trace_reply_t *hop;
  uint16_t out;

  assert(state->pmtud->L2 != NULL);
  assert(state->pmtud->L2->out >= 0);
  assert(state->pmtud->L2->out <= 65535);

  out = state->pmtud->L2->out;
  hop = state->pmtud->L2->hop;

  /* don't need the L2 struct anymore */
  free(state->pmtud->L2);
  state->pmtud->L2 = NULL;

  note = state->pmtud->note;
  note->nhmtu = out;
  scamper_trace_pmtud_note_add(trace->pmtud, note);
  state->pmtud->note = NULL;

  /*
   * copy details of the TTL-expired message furthest into the path
   * into the trace if there is one to copy
   */
  if(state->pmtud->TTL != NULL)
    {
      if(state->pmtud->TTL->hop != NULL)
	{
	  /*
	   * if there is a TTL search, then the note wants to have the
	   * farthest hop into the path to annotate where the silence begins.
	   */
	  note->reply = state->pmtud->TTL->hop;
	  note->probe = note->reply->probe;
	}
      else if(state->pmtud->TTL->lower == 0)
	{
	  /*
	   * if there was no TTL response with the large packet from anywhere
	   * in the path, and the lowest TTL tried was zero, then we infer
	   * that the host itself has an MTU mismatch with the particular
	   * router it is using for the destination
	   */
	  trace->pmtud->outmtu = out;
	}

      free(state->pmtud->TTL);
      state->pmtud->TTL = NULL;
    }

  if(hop != NULL)
    {
      /*
       * copy details of the hop to terminate the largest probe into
       * the pmtu struct.  hops between the TTL expired message (if we
       * have one) and the ICMP unreach message have their PMTU inferred
       */
      state->pmtud->last_fragmsg = hop;

      /*
       * if the hop that we last recorded is a hop message that would
       * ordinarily have caused scamper to stop PMTU discovery, then
       * stop it now
       */
      if(!SCAMPER_TRACE_REPLY_IS_ICMP_PTB(hop))
	{
	  trace->pmtud->pmtu = hop->probe->size;
	  trace_queue_done(task);
	  return 1;
	}
    }

  state->payload_size = out - state->header_size;
  state->mode = MODE_PMTUD_DEFAULT;
  state->attempt = 0;
  state->ttl = 255;

  return 0;
}

static int pmtud_default_pre(trace_state_t *state, trace_probe_t *tp)
{
  /*
   * if the response is for a probe that fits with the current
   * probing details, then record it
   */
  if(tp->mode != MODE_PMTUD_DEFAULT)
    return 0;
  if(tp->probe->size != state->header_size + state->payload_size)
    return 0;

  return 1;
}

static int pmtud_silent_l2_pre(pmtud_L2_state_t *l2, trace_probe_t *tp)
{
  assert(l2 != NULL);

  /*
   * if we get a response that is out of the bounds we are searching, it
   * could be a delayed message.  at the moment, we just ignore the response.
   */
  if(tp->probe->size < l2->lower || l2->upper <= tp->probe->size)
    {
      scamper_debug(__func__, "L2 search %d < %d || %d <= %d",
		    tp->probe->size, l2->lower, l2->upper, tp->probe->size);
      return 0;
    }

  return 1;
}

static void pmtud_silent_l2_post(scamper_task_t *task, trace_probe_t *tp,
				 scamper_trace_reply_t *hop)
{
  trace_state_t *state = trace_getstate(task);
  pmtud_L2_state_t *l2 = state->pmtud->L2;
  struct timeval now;

  l2->hop = hop;

  /*
   * if there is still space to search, reduce the search space and send
   * another probe
   */
  if(tp->probe->size + 1 != l2->upper)
    {
      /*
       * raise the lower bounds of our search based on successfully
       * receiving a response for a given packet size.
       */
      pmtud_L2_set_probesize(state, tp->probe->size, l2->upper);
    }
  else
    {
      l2->lower = l2->out = tp->probe->size;
      if(pmtud_TTL_init(task) == 1)
	{
	  state->mode = MODE_PMTUD_SILENT_TTL;
	}
      else
	{
	  trace_queue_done(task);
	  return;
	}
    }

  gettimeofday_wrap(&now);
  trace_queue(task, &now);
  return;
}

static void pmtud_badsugg_post(scamper_task_t *task, int lower, int upper)
{
  trace_state_t *state = trace_getstate(task);
  struct timeval now;

  if(lower + 1 != upper)
    {
      pmtud_L2_set_probesize(state, lower, upper);
    }
  else
    {
      /* terminate the search now */
      state->pmtud->L2->lower = state->pmtud->L2->out = lower;
      state->pmtud->L2->upper = upper;

      /* if the pmtud is completed, then move on */
      if(pmtud_L2_search_end(task) == 1)
	return;
    }

  /* put the trace back into the probe queue */
  gettimeofday_wrap(&now);
  trace_queue(task, &now);
  return;
}

static int conf_iface_add(trace_conf_state_t *conf, scamper_addr_t *iface)
{
  size_t len;

  /* interface already in the set */
  if(array_find((void **)conf->interfaces, conf->interfacec,
		iface, (array_cmp_t)scamper_addr_cmp) != NULL)
    return 0;

  /* increase array size for one more interface */
  len = (conf->interfacec + 1) * sizeof(scamper_addr_t *);
  if(realloc_wrap((void **)&conf->interfaces, len) != 0)
    return -1;

  conf->interfaces[conf->interfacec++] = iface;
  if(conf->interfacec > 1)
    {
      array_qsort((void **)conf->interfaces, conf->interfacec,
		  (array_cmp_t)scamper_addr_cmp);
      conf->n++;
    }

  return 0;
}

static int dtree_lss_add(trace_dtree_state_t *dtree, scamper_addr_t *iface)
{
  if(splaytree_insert(dtree->lsst->tree, iface) == NULL)
    return -1;
  scamper_addr_use(iface);
  if(array_insert((void ***)&dtree->lss, &dtree->lssc, iface,
		  (array_cmp_t)scamper_addr_cmp) != 0)
    return -1;
  return 0;
}

static int dtree_lss_in(trace_lss_t *lsst, scamper_addr_t *iface)
{
  if(splaytree_find(lsst->tree, iface) != NULL)
    return 1;
  return 0;
}

static int state_lss_in(trace_state_t *state, scamper_addr_t *iface)
{
  trace_dtree_state_t *dtree = state->dtree;
  if(dtree != NULL &&
     array_find((void **)dtree->lss, dtree->lssc, iface,
		(array_cmp_t)scamper_addr_cmp) != NULL)
    return 1;
  return 0;
}

/*
 * trace_ipid_fudge
 *
 * play games with the embedded IP ID, which may come back with a different
 * IP ID than what was sent; return the ID of the corresponding probe in *id.
 * this code was inspired by information from David Malone.
 *
 * the IPID transmitted is assigned from a counter (state->id_next) which
 * starts from one -- *not* zero.  this is so systems that zero the IPID
 * will not confuse this algorithm.
 *
 * the IPID is transmitted by scamper in network byte order.
 *
 */
static int trace_ipid_fudge(const trace_state_t *state,
			    const uint16_t ipid, uint16_t *id)
{
  /* ensure the IP ID is not zero */
  if(ipid == 0)
    return -1;

  /* check if the IP ID is in range */
  if(ipid <= state->id_next)
    {
      *id = ipid - 1;
      return 0;
    }

  /* check if the IP ID was incremented */
  if(ipid == state->id_next + 1)
    {
      scamper_debug(__func__, "ip id one greater than sent");
      *id = ipid - 2;
      return 0;
    }

  /* check if the IP ID was byte swapped. XXX: is this correct? */
  if(byteswap16(ipid) <= state->id_next)
    {
      scamper_debug(__func__, "ip id byte swapped");
      *id = byteswap16(ipid) - 1;
      return 0;
    }

  return -1;
}

/*
 * trace_isloop
 *
 * given a trace and a hop record, determine if there is a loop.
 */
static int trace_isloop(const scamper_trace_t *trace,
			const scamper_trace_reply_t *hop,
			trace_state_t *state)
{
  scamper_trace_hopiter_t hi;
  scamper_trace_reply_t *tmp;
  uint16_t i;

  /* need at least a couple of probes first */
  if(hop->probe->ttl <= trace->firsthop)
    return 0;

  /*
   * check to see if the address has already been seen this hop; if it has,
   * then we've already checked this address for loops so we don't need to
   * check it again.
   */
  scamper_trace_hopiter_ttl_set(&hi, hop->probe->ttl, hop->probe->ttl);
  while((tmp = scamper_trace_hopiter_next(trace, &hi)) != NULL && tmp != hop)
    if(scamper_addr_cmp(hop->addr, tmp->addr) == 0)
      return 0;

  /* compare all hop records until the hop prior to this one */
  for(i=trace->firsthop-1; i<trace->hop_count; i++)
    {
      /* skip over hops at the same distance as the one we are comparing to */
      if(i == hop->probe->ttl-1)
	continue;

      scamper_trace_hopiter_ttl_set(&hi, i+1, i+1);
      while((tmp = scamper_trace_hopiter_next(trace, &hi)) != NULL)
	{
	  /* if the addresses match, then there is a loop */
	  if(scamper_addr_cmp(hop->addr, tmp->addr) == 0)
	    {
	      /*
	       * if the loop is between adjacent hops, continue probing.
	       * scamper used to only allow zero-ttl forwarding
	       * (tmp->reply_icmp_q_ttl == 0 && hop->reply_icmp_q_ttl == 1)
	       * but in 2015 there are prevalent loops between
	       * adjacent hops where that condition halts probing too soon
	       */
	      if(tmp->probe->ttl + 1 == hop->probe->ttl ||
		 tmp->probe->ttl - 1 == hop->probe->ttl)
		return 0;

	      /* check if the loop condition is met */
	      state->loopc++;
	      if(state->loopc >= trace->loops)
		return 1;

	      /* count the loop just once for this hop */
	      return 0;
	    }
	}
    }

  return 0;
}

/*
 * trace_handlerror
 *
 * the code encountered some error when doing the traceroute, so stop the
 * trace now.
 */
static int trace_handleerror(scamper_task_t *task, const int error)
{
  trace_stop_error(trace_getdata(task), error);
  trace_queue_done(task);
  return 0;
}

#ifndef DISABLE_SCAMPER_HOST
static void trace_hop_ptr_cb(void *param, const char *name)
{
  trace_host_t *th = param;
  scamper_trace_reply_t *hop;

  /* don't need the hostdo structure any more */
  th->hostdo = NULL;

  if(name != NULL)
    {
      /* not not check return value from strdup, non fatal error */
      th->name = strdup(name);
      while((hop = slist_head_pop(th->hops)) != NULL)
	hop->name = strdup(name);
      slist_free(th->hops); th->hops = NULL;
    }

  return;
}

static int trace_hop_ptr(const scamper_task_t *task, scamper_trace_reply_t *hop)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  trace_host_t fm, *th = NULL;

  if((trace->flags & SCAMPER_TRACE_FLAG_PTR) == 0)
    return 0;

  /* if we don't have a trace_host tree yet, create one */
  if(state->ths == NULL &&
     (state->ths = splaytree_alloc((splaytree_cmp_t)trace_host_cmp)) == NULL)
    {
      printerror(__func__, "could not alloc state->ths");
      goto err;
    }

  /* see if we've already looked this address up */
  fm.addr = hop->addr;
  if((th = splaytree_find(state->ths, &fm)) != NULL)
    {
      /*
       * if we already have a name, copy it over.  otherwise, if the
       * host lookup is currently underway, add this hop to the list
       * waiting.
       *
       * none of this is fatal: name lookups are nice to have.
       */
      if(th->name != NULL)
	hop->name = strdup(th->name);
      else if(th->hostdo != NULL)
	slist_tail_push(th->hops, hop);
      return 0;
    }

  /* add state for the name lookup */
  if((th = trace_host_alloc(hop)) == NULL)
    {
      printerror(__func__, "could not alloc th");
      goto err;
    }
  if(splaytree_insert(state->ths, th) == NULL)
    {
      trace_host_free(th);
      printerror(__func__, "could not insert th");
      goto err;
    }
  th->hostdo = scamper_do_host_do_ptr(th->addr, th, trace_hop_ptr_cb);
  if(th->hostdo == NULL)
    {
      printerror(__func__, "could not scamper_do_host_do_ptr");
      goto err;
    }

  return 0;

 err:
  return -1;
}
#endif

/*
 * trace_hop
 *
 * this function creates a generic hop record with the basic details from
 * the probe structure copied in, as well as an address based on the details
 * passed in
 */
static scamper_trace_reply_t *trace_hop(const scamper_task_t *task,
					const trace_probe_t *tp,
					int af, const void *addr)
{
  scamper_trace_reply_t *hop = NULL;
  int type;

  /* determine the scamper address type to use from the address family */
  if(af == AF_INET) type = SCAMPER_ADDR_TYPE_IPV4;
  else if(af == AF_INET6) type = SCAMPER_ADDR_TYPE_IPV6;
  else goto err;

  if((hop = scamper_trace_reply_alloc()) == NULL ||
     (hop->addr = scamper_addrcache_get(addrcache, type, addr)) == NULL)
    {
      printerror(__func__, "could not alloc hop");
      goto err;
    }

#ifndef DISABLE_SCAMPER_HOST
  if(trace_hop_ptr(task, hop) != 0)
    {
      printerror(__func__, "could not lookup ptr");
      goto err;
    }
#endif

  hop->probe = tp->probe;

  /*
   * if the probe's datalink tx timestamp flag is set, scamper has a tx
   * timestamp recorded
   */
  if(hop->probe->flags & SCAMPER_TRACE_REPLY_FLAG_TS_DL_TX)
    hop->flags |= SCAMPER_TRACE_REPLY_FLAG_TS_DL_TX;

  return hop;

 err:
  if(hop != NULL) scamper_trace_reply_free(hop);
  return NULL;
}

/*
 * trace_icmp_hop
 *
 * given a trace probe and an ICMP response, allocate and initialise a
 * scamper_trace_hop record.
 */
static scamper_trace_reply_t *trace_icmp_hop(const scamper_task_t *task,
					     trace_probe_t *tp,
					     scamper_icmp_resp_t *ir)
{
  scamper_trace_reply_t *hop = NULL;
  scamper_addr_t addr;

  /* get a pointer to the source address of the ICMP response */
  if(scamper_icmp_resp_src(ir, &addr) != 0)
    goto err;

  /* create a generic hop record without any special bits filled out */
  if((hop = trace_hop(task, tp, ir->ir_af, addr.addr)) == NULL)
    goto err;

  /* fill out the basic bits of the hop structure */
  hop->size = ir->ir_ip_size;
  hop->tos  = ir->ir_ip_tos;
  hop->reply_icmp_type = ir->ir_icmp_type;
  hop->reply_icmp_code = ir->ir_icmp_code;

  /*
   * we cannot depend on the TTL field of the IP packet being made available,
   * so we signal explicitly when the reply ttl is valid
   */
  if(ir->ir_ip_ttl != -1)
    {
      hop->ttl = (uint8_t)ir->ir_ip_ttl;
      hop->flags |= SCAMPER_TRACE_REPLY_FLAG_REPLY_TTL;
    }

  /*
   * if the probe's datalink rx timestamp flag is set, scamper has a rx
   * timestamp recorded
   */
  if(tp->flags & TRACE_PROBE_FLAG_DL_RX)
    {
      hop->flags |= SCAMPER_TRACE_REPLY_FLAG_TS_DL_RX;
      timeval_diff_tv(&hop->rtt, &tp->probe->tx, &tp->dl_rx);
    }
  else
    {
      timeval_diff_tv(&hop->rtt, &tp->probe->tx, &ir->ir_rx);
      if(ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_KERNRX)
	hop->flags |= SCAMPER_TRACE_REPLY_FLAG_TS_SOCK_RX;
    }

  if(SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir))
    hop->reply_icmp_nhmtu = ir->ir_icmp_nhmtu;

  if(ir->ir_af == AF_INET)
    hop->ipid = ir->ir_ip_id;

  if(SCAMPER_ICMP_RESP_INNER_IS_SET(ir))
    {
      hop->reply_icmp_q_ttl = ir->ir_inner_ip_ttl;
      hop->reply_icmp_q_ipl = ir->ir_inner_ip_size;
      hop->reply_icmp_q_tos = ir->ir_inner_ip_tos;
    }

  /* if ICMP extensions are included, then parse and include them. */
  if(ir->ir_ext != NULL &&
     scamper_icmpext_parse(&hop->icmp_exts, ir->ir_ext, ir->ir_extlen) != 0)
    {
      goto err;
    }

  assert(tp->probe->replyc < UINT16_MAX);
  if(scamper_trace_probe_reply_add(tp->probe, hop) != 0)
    goto err;

  return hop;

 err:
  if(hop != NULL) scamper_trace_reply_free(hop);
  return NULL;
}

static scamper_trace_reply_t *trace_dl_hop(scamper_task_t *task,
					   const trace_probe_t *tp,
					   const scamper_dl_rec_t *dl)
{
  scamper_trace_reply_t *hop = NULL;

  /* create a generic hop record without any special bits filled out */
  if((hop = trace_hop(task, tp, dl->dl_af, dl->dl_ip_src)) == NULL)
    goto err;

  /* fill out the basic bits of the hop structure */
  hop->size = dl->dl_ip_size;
  hop->ttl = dl->dl_ip_ttl;
  hop->tos = dl->dl_ip_tos;
  hop->flags |= (SCAMPER_TRACE_REPLY_FLAG_REPLY_TTL |
		 SCAMPER_TRACE_REPLY_FLAG_TS_DL_RX);
  timeval_diff_tv(&hop->rtt, &tp->probe->tx, &dl->dl_tv);

  if(dl->dl_af == AF_INET)
    hop->ipid = dl->dl_ip_id;

  if(dl->dl_ip_proto == IPPROTO_TCP)
    {
      hop->reply_tcp_flags = dl->dl_tcp_flags;
      hop->flags |= SCAMPER_TRACE_REPLY_FLAG_TCP;
    }
  else if(dl->dl_ip_proto == IPPROTO_UDP)
    {
      hop->flags |= SCAMPER_TRACE_REPLY_FLAG_UDP;
    }

  assert(tp->probe->replyc < UINT16_MAX);
  if(scamper_trace_probe_reply_add(tp->probe, hop) != 0)
    goto err;

  return hop;

 err:
  if(hop != NULL) scamper_trace_reply_free(hop);
  return NULL;
}

static uint8_t trace_first_mode(const scamper_trace_t *trace)
{
  if(SCAMPER_TRACE_FLAG_IS_DOUBLETREE(trace))
    return MODE_DTREE_FIRST;
  if(trace->squeries > 1)
    return MODE_PARALLEL;
  return MODE_TRACE;
}

/*
 * trace_next_mode
 *
 * if the trace is going into another mode, this function figures out
 * which mode to put it into
 */
static void trace_next_mode(scamper_task_t *task, const struct timeval *now)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  uint16_t ifmtu;
  int ifindex;

  if(state->mode == MODE_PARALLEL && trace_parallel_isempty(state->para) == 0)
    {
      state->mode = MODE_PARALLEL_FINISH;
      trace_queue(task, now);
      return;
    }

  if(SCAMPER_TRACE_FLAG_IS_DOUBLETREE(trace))
    {
      if(state->mode == MODE_DTREE_FWD)
	{
	  if(trace->firsthop > 1 &&
	     (trace->dtree->flags & SCAMPER_TRACE_DTREE_FLAG_NOBACK) == 0)
	    {
	      state->mode    = MODE_DTREE_BACK;
	      state->ttl     = trace->firsthop - 1;
	      state->attempt = 0;
	      trace_queue(task, now);
	    }
	  else goto done;
	}
      else if(state->mode == MODE_DTREE_BACK)
	goto done;
      return;
    }

  if(SCAMPER_TRACE_FLAG_IS_PMTUD(trace))
    {
      if(trace->stop_reason == SCAMPER_TRACE_STOP_HOPLIMIT ||
	 trace->stop_reason == SCAMPER_TRACE_STOP_GAPLIMIT ||
	 trace->stop_reason == SCAMPER_TRACE_STOP_LOOP ||
	 trace->stop_reason == SCAMPER_TRACE_STOP_NONE)
	goto done;

      /* if the interface's MTU is useless, then we can't do PMTUD */
      scamper_fd_ifindex(state->dl, &ifindex);
      if(scamper_if_getmtu(ifindex,&ifmtu) == -1 || ifmtu <= state->header_size)
	goto done;
      if((trace->pmtud = scamper_trace_pmtud_alloc()) == NULL)
	goto done;
      if((state->pmtud = malloc_zero(sizeof(trace_pmtud_state_t))) == NULL)
	goto done;
      trace->pmtud->ifmtu = ifmtu;
      trace->pmtud->ver   = 2;

      state->attempt      = 0;
      state->mode         = MODE_PMTUD_DEFAULT;
      state->payload_size = ifmtu - state->header_size;
      state->ttl          = 255;

      trace_queue(task, now);
      return;
    }

 done:
  trace_queue_done(task);
  return;
}

/*
 * trace_stop_reason
 *
 * check to see if we have a stop condition based on the hop record
 */
static void trace_stop_reason(scamper_trace_t *trace,
			      scamper_trace_reply_t *hop,
			      trace_state_t *state,
			      uint8_t *stop_reason, uint8_t *stop_data)
{
  /*
   * the message received is an ICMP port unreachable -- something that
   * the destination should have sent.  make sure the port unreachable
   * message makes sense based on the traceroute type.
   */
  if(SCAMPER_TRACE_REPLY_IS_ICMP_UNREACH_PORT(hop) &&
     (SCAMPER_TRACE_TYPE_IS_UDP(trace) || SCAMPER_TRACE_TYPE_IS_TCP(trace)))
    {
      *stop_reason = SCAMPER_TRACE_STOP_COMPLETED;
      *stop_data = 0;
    }
  else if(SCAMPER_TRACE_REPLY_IS_ICMP_UNREACH(hop))
    {
      *stop_reason = SCAMPER_TRACE_STOP_UNREACH;
      *stop_data = hop->reply_icmp_code;
    }
  else if(SCAMPER_TRACE_REPLY_IS_ICMP_ECHO_REPLY(hop))
    {
      /*
       * the message received is an ICMP echo reply -- something that only
       * makes sense to include as part of the traceroute if the traceroute
       * is using echo requests.
       */
      if(trace->type == SCAMPER_TRACE_TYPE_ICMP_ECHO ||
	 trace->type == SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS)
	{
	  *stop_reason = SCAMPER_TRACE_STOP_COMPLETED;
	  *stop_data = 0;
	}
      else
	{
	  *stop_reason = SCAMPER_TRACE_STOP_NONE;
	  *stop_data = 0;
	}
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(trace->dst) &&
	  hop->reply_icmp_type == ICMP6_PACKET_TOO_BIG)
    {
      /*
       * IPv6 uses a different ICMP type for packet too big messages, so
       * check this.
       */
      *stop_reason = SCAMPER_TRACE_STOP_ICMP;
      *stop_data   = hop->reply_icmp_type;
    }
  else if(trace->loops != 0 && trace_isloop(trace, hop, state) != 0)
    {
      /* check for a loop condition */
      *stop_reason = SCAMPER_TRACE_STOP_LOOP;
      *stop_data   = 0;
    }
  else if(SCAMPER_TRACE_REPLY_IS_ICMP_TTL_EXP(hop) &&
	  SCAMPER_TRACE_FLAG_IS_IGNORETTLDST(trace) == 0 &&
	  scamper_addr_cmp(trace->dst, hop->addr) == 0)
    {
      /*
       * if an ICMP TTL expired message is received from an IP address
       * matching the destination being probed, and the traceroute is
       * to stop when this occurs, then stop.
       */
      *stop_reason = SCAMPER_TRACE_STOP_COMPLETED;
      *stop_data   = 0;
    }
  else if(SCAMPER_TRACE_TYPE_IS_TCP(trace) && SCAMPER_TRACE_REPLY_IS_TCP(hop))
    {
      *stop_reason = SCAMPER_TRACE_STOP_COMPLETED;
      *stop_data   = 0;
    }
  else if(SCAMPER_TRACE_FLAG_IS_DOUBLETREE(trace) &&
	  scamper_trace_dtree_gss_find(trace->dtree, hop->addr) != NULL)
    {
      *stop_reason = SCAMPER_TRACE_STOP_GSS;
      *stop_data   = 0;
      trace->dtree->gss_stop = scamper_addr_use(hop->addr);
    }
  else
    {
      *stop_reason = SCAMPER_TRACE_STOP_NONE;
      *stop_data   = 0;
    }

  return;
}

/*
 * handleicmp_trace
 *
 * we received an ICMP response in the traceroute state.  check to see
 * if the probe is in sequence, and adjust the trace accordingly.
 */
static int handleicmp_trace(scamper_task_t *task,
			    scamper_icmp_resp_t *ir,
			    trace_probe_t *tp)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  scamper_trace_hopiter_t hi;
  trace_conf_state_t *conf;
  scamper_trace_reply_t *hop;
  struct timeval now;
  uint8_t stop_reason, stop_data;

  assert(state->mode == MODE_TRACE ||
	 state->mode == MODE_DTREE_FWD || state->mode == MODE_DTREE_BACK);

  /* we should only have to deal with probes sent while in the trace state */
  if(tp->mode != MODE_TRACE &&
     tp->mode != MODE_DTREE_FWD && tp->mode != MODE_DTREE_BACK)
    {
      return 0;
    }

  /* create a hop record and insert it into the trace */
  if((hop = trace_icmp_hop(task, tp, ir)) == NULL)
    return -1;

  /*
   * if the response is not for the current working hop (i.e. a late reply)
   * check if probing should now halt.  otherwise keep waiting.
   */
  if(tp->probe->ttl != state->ttl)
    {
      /* XXX: handle doubletree */
      trace_stop_reason(trace, hop, state, &stop_reason, &stop_data);
      if(stop_reason != SCAMPER_TRACE_STOP_NONE)
	{
	  trace_stop(trace, stop_reason, stop_data);
	  goto next_mode;
	}
      return 0;
    }

  /*
   * the rest of the code in this function deals with the fact this is a
   * reply for the current working hop.
   *
   * check if we are to send all allotted probes to the target
   */
  if(SCAMPER_TRACE_FLAG_IS_ALLATTEMPTS(trace))
    {
      assert(trace->confidence == 0);

      /*
       * if we get an out of order reply, then we go back to waiting for
       * the one we just probed for
       */
      if(tp->probe->id != state->attempt)
	return 0;

      /*
       * this response is for the last probe sent.  if there are still
       * probes to send for this hop, then send the next one
       */
      if(state->attempt < trace->attempts)
	goto probe;
    }
  else if(trace->confidence != 0)
    {
      /*
       * record details of the interface, if its details are not
       * currently held
       */
      conf = state->conf;
      if(conf_iface_add(conf, hop->addr) != 0)
	{
	  printerror(__func__, "could not add interface");
	  trace_handleerror(task, errno);
	  return -1;
	}

      /*
       * make sure we know the required number of probes to send to reach
       * a particular confidence level
       */
      if(conf->n <= TRACE_CONFIDENCE_MAX_N)
	{
	  /*
	   * if we get an out of order reply, then we go back to waiting for
	   * the one we just probed for
	   */
	  if(tp->probe->id != state->attempt)
	    return 0;

	  /*
	   * this response is for the last probe sent.  if there are still
	   * probes to send for this hop, then send the next one
	   */
	  if(state->attempt < k(conf))
	    goto probe;
	}

      free(conf->interfaces);
      conf->interfaces = NULL;
      conf->interfacec = 0;
      conf->n = 2;
    }

  state->attempt = 0;

  if(state->mode == MODE_DTREE_BACK)
    {
      if(state->ttl == 1)
	goto next_mode;

      /*
       * consult the local stop set to see if we should stop backwards
       * probing yet.
       */
      if(state->dtree != NULL && state->dtree->lsst != NULL &&
	 dtree_lss_in(state->dtree->lsst, hop->addr) == 0)
	{
	  dtree_lss_add(state->dtree, hop->addr);
	  state->ttl--;
	  trace->firsthop--;
	  goto probe;
	}

      /*
       * if it is in the local stop set because there is forwarding loop
       * in this trace, handle that.
       */
      if(state_lss_in(state, hop->addr) != 0)
	{
	  state->ttl--;
	  trace->firsthop--;
	  goto probe;
	}

      trace->dtree->lss_stop = scamper_addr_use(hop->addr);
      goto next_mode;
    }

  state->ttl++;

  /*
   * if we're in a mode where we only care about the first response to
   * a probe, then check it now.  the else block below handles the case
   * where we want a larger number of responses from a hop.
   */
  if(trace->confidence == 0 && SCAMPER_TRACE_FLAG_IS_ALLATTEMPTS(trace) == 0)
    {
      /* check to see if we have a stop reason from the ICMP response */
      trace_stop_reason(trace, hop, state, &stop_reason, &stop_data);
      if(stop_reason != SCAMPER_TRACE_STOP_NONE)
	{
	  /* did we get a stop condition out of all that? */
	  trace_stop(trace, stop_reason, stop_data);
	  goto next_mode;
	}
    }
  else
    {
      /* check all replies for a reason to halt the trace */
      scamper_trace_hopiter_ttl_set(&hi, trace->hop_count, trace->hop_count);
      while((hop = scamper_trace_hopiter_next(trace, &hi)) != NULL)
	{
	  trace_stop_reason(trace, hop, state, &stop_reason, &stop_data);
	  if(stop_reason != SCAMPER_TRACE_STOP_NONE)
	    {
	      /* did we get a stop condition out of all that? */
	      trace_stop(trace, stop_reason, stop_data);
	      goto next_mode;
	    }
	}
    }

  /* check if we've reached the hoplimit */
  if((trace->hoplimit == 0 ? 255 : trace->hoplimit) <= trace->hop_count)
    {
      /* if not, has the hop limit now reached? */
      trace_stop_hoplimit(trace);
      goto next_mode;
    }

 probe:
  /* keep probing */
  gettimeofday_wrap(&now);
  trace_queue(task, &now);
  return 0;

 next_mode:
  gettimeofday_wrap(&now);
  trace_next_mode(task, &now);
  return 0;
}

/*
 * handleicmp_dtree_first
 *
 * handle receiving an ICMP response to the first series of doubletree
 * probes which aims to find the place at which to commence probing
 */
static int handleicmp_dtree_first(scamper_task_t *task,
				  scamper_icmp_resp_t *ir, trace_probe_t *tp)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  scamper_trace_reply_t *hop;
  struct timeval now;
  scamper_addr_t src;
  uint8_t stop_reason, stop_data;
  int done = 0;

  /* make sure the corresponding probe is one that was sent in this mode */
  if(tp->mode != MODE_DTREE_FIRST)
    return 0;

  /* ignore late replies if the firsthop has been shifted back */
  if(tp->probe->ttl > trace->firsthop)
    return 0;
  assert(tp->probe->ttl == trace->firsthop);

  /* get the source address of the reply */
  if(scamper_icmp_resp_src(ir, &src) != 0)
    return -1;

  /* the next probe we sent will be the first attempt at it */
  state->attempt = 0;

  /* check to see if the distance should be reduced */
  if(SCAMPER_ICMP_RESP_IS_UNREACH(ir) ||
     SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir) ||
     SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir) ||
     scamper_addr_cmp(trace->dst, &src) == 0)
    {
      /* halve the probe ttl if that can be done */
      if(tp->probe->ttl > 1)
	{
	  trace->firsthop /= 2;
	  state->ttl = trace->firsthop;
	  goto probe;
	}
      assert(tp->probe->ttl == 1);

      /* got response which can't be probed past at first hop. we're done */
      done = 1;
    }

  /* create a hop record and insert it into the trace */
  if((hop = trace_icmp_hop(task, tp, ir)) == NULL)
    return -1;

  /* if we are done (can't probe beyond first hop) then finish */
  if(done != 0)
    {
      trace->firsthop = 1;
      trace_stop_reason(trace, hop, state, &stop_reason, &stop_data);
      assert(stop_reason != SCAMPER_TRACE_STOP_NONE);
      trace_stop(trace, stop_reason, stop_data);
      trace_queue_done(task);
      return 0;
    }

  /*
   * if the response comes from an address not in the global stop set,
   * then probe forward
   */
  if(scamper_trace_dtree_gss_find(trace->dtree, hop->addr) == NULL)
    {
      state->ttl  = tp->probe->ttl + 1;
      state->mode = MODE_DTREE_FWD;
      goto probe;
    }

  /* hit something in the global stop set. probe backwards */
  trace->stop_reason = SCAMPER_TRACE_STOP_GSS;
  trace->stop_data   = 0;
  trace->dtree->gss_stop = scamper_addr_use(hop->addr);

  /* can't probe backwards, so we're done */
  if(trace->firsthop == 1 ||
     (trace->dtree->flags & SCAMPER_TRACE_DTREE_FLAG_NOBACK) != 0)
    {
      trace_queue_done(task);
      return 0;
    }

  /* backwards probing */
  state->ttl  = trace->firsthop - 1;
  state->mode = MODE_DTREE_BACK;

 probe:
  gettimeofday_wrap(&now);
  trace_queue(task, &now);
  return 0;
}

/*
 * handleicmp_lastditch
 *
 * we received an ICMP response while checking if the end-host is
 * responsive.
 */
static int handleicmp_lastditch(scamper_task_t *task,
				scamper_icmp_resp_t *ir, trace_probe_t *tp)
{
  scamper_trace_t *trace = trace_getdata(task);

  /* record the response in the trace */
  if((MODE_IS_TRACE(tp->mode) || MODE_IS_LASTDITCH(tp->mode)) &&
     trace_icmp_hop(task, tp, ir) == NULL)
    return -1;

  if(MODE_IS_LASTDITCH(tp->mode))
    {
      trace_stop_gaplimit(trace);
      trace_queue_done(task);
    }

  return 0;
}

static int handleicmp_pmtud_default(scamper_task_t *task,
				    scamper_icmp_resp_t *ir, trace_probe_t *tp)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  scamper_trace_pmtud_note_t *note;
  scamper_trace_reply_t *hop;
  struct timeval now;

  if(pmtud_default_pre(state, tp) == 0)
    return 0;

  if((hop = trace_icmp_hop(task, tp, ir)) == NULL)
    return -1;
  state->pmtud->last_fragmsg = hop;

  if(SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir))
    {
      if((note = scamper_trace_pmtud_note_alloc()) == NULL)
	{
	  printerror(__func__, "could not alloc note");
	  return -1;
	}
      note->reply = hop;
      note->probe = hop->probe;

      /* PTB has no useful NHMTU */
      if(ir->ir_icmp_nhmtu == 0 || ir->ir_icmp_nhmtu >= tp->probe->size)
	{
	  note->type = SCAMPER_TRACE_PMTUD_NOTE_TYPE_PTB_BAD;
	  state->pmtud->note = note;
	  state->mode = MODE_PMTUD_BADSUGG;
	  pmtud_L2_init(state);
	  goto probe;
	}

      scamper_trace_pmtud_note_add(trace->pmtud, note);

      if(ir->ir_icmp_nhmtu < state->header_size)
	{
	  /* stop if the PTB has an MTU that is too small to be probed */
	  note->type = SCAMPER_TRACE_PMTUD_NOTE_TYPE_PTB_BAD;
	  trace_queue_done(task);
	}
      else
	{
	  note->type = SCAMPER_TRACE_PMTUD_NOTE_TYPE_PTB;
	  note->nhmtu = ir->ir_icmp_nhmtu;
	  state->attempt = 0;
	  state->payload_size = ir->ir_icmp_nhmtu - state->header_size;
	  goto probe;
	}
    }
  else if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) ||
	  SCAMPER_ICMP_RESP_IS_UNREACH(ir) ||
	  SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir))
    {
      trace->pmtud->pmtu = tp->probe->size;
      trace_queue_done(task);
    }

  return 0;

 probe:
  gettimeofday_wrap(&now);
  trace_queue(task, &now);
  return 0;
}

static int handleicmp_pmtud_silent_l2(scamper_task_t *task,
				      scamper_icmp_resp_t *ir,
				      trace_probe_t *tp)
{
  trace_state_t *state = trace_getstate(task);
  scamper_trace_reply_t *hop;

  /* do we consider the packet? */
  if(pmtud_silent_l2_pre(state->pmtud->L2, tp) == 0)
    return 0;

  /* record the hop details */
  if((hop = trace_icmp_hop(task, tp, ir)) == NULL)
    return -1;

  pmtud_silent_l2_post(task, tp, hop);
  return 0;
}

static int handleicmp_pmtud_silent_ttl(scamper_task_t *task,
				       scamper_icmp_resp_t *ir,
				       trace_probe_t *tp)
{
  trace_state_t *state = trace_getstate(task);
  scamper_trace_reply_t *hop;
  struct timeval now;

  /* we got a TTL expired message */
  if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir))
    {
      /* record the hop details */
      if((hop = trace_icmp_hop(task, tp, ir)) == NULL)
	return -1;

      assert(state->pmtud->TTL != NULL);
      state->pmtud->TTL->hop = hop;

      /* if there is no more TTL space to search, then we are done */
      if(pmtud_TTL_set_probettl(task, tp->probe->ttl,
				state->pmtud->TTL->upper) == 0)
	{
	  /*
	   * if we are not finished with PMTU yet, put the trace back in
	   * the queue
	   */
	  if(pmtud_L2_search_end(task) == 1)
	    return 0;
	}

      /* put the trace back into the probe queue */
      goto probe;
    }
  /*
   * if we get a fragmentation required message during a TTL limited
   * search for the MTU inferred, then record the message and stop
   * the TTL limited search
   */
  else if(SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir) &&
	  ir->ir_icmp_nhmtu == state->pmtud->L2->out)
    {
      /* record the hop details */
      if(trace_icmp_hop(task, tp, ir) == NULL)
	return -1;

      state->attempt      = 0;
      state->payload_size = ir->ir_icmp_nhmtu - state->header_size;
      state->ttl          = 255;
      state->mode         = MODE_PMTUD_DEFAULT;

      free(state->pmtud->L2);  state->pmtud->L2 = NULL;
      free(state->pmtud->TTL); state->pmtud->TTL = NULL;

      /* put the trace back into the probe queue */
      goto probe;
    }

  return 0;

 probe:
  gettimeofday_wrap(&now);
  trace_queue(task, &now);
  return 0;
}

/*
 * handleicmp_pmtud_badsugg
 *
 * we are in the badsugg state, which is used to infer a 'correct' next-hop
 * mtu size when the suggested packet size is no help.
 */
static int handleicmp_pmtud_badsugg(scamper_task_t *task,
				    scamper_icmp_resp_t *ir, trace_probe_t *tp)
{
  trace_state_t *state = trace_getstate(task);
  scamper_trace_reply_t *hop;
  int lower, upper;

  if((hop = trace_icmp_hop(task, tp, ir)) == NULL)
    return -1;

  assert(state->pmtud->L2 != NULL);

  /*
   * adjust the window we are searching based on where the response came
   * from and the size of the probe that caused the response
   */
  if(scamper_trace_reply_addr_cmp(state->pmtud->last_fragmsg, hop) == 0)
    {
      lower = state->pmtud->L2->lower;
      upper = tp->probe->size;
    }
  else
    {
      lower = tp->probe->size;
      upper = state->pmtud->L2->upper;

      /* replace the layer-2 hop we get a response for with this hop */
      state->pmtud->L2->hop = hop;
    }

  pmtud_badsugg_post(task, lower, upper);
  return 0;
}

static int handleicmp_parallel(scamper_task_t *task,
			       scamper_icmp_resp_t *ir, trace_probe_t *tp)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  trace_para_state_t *para = state->para;
  scamper_trace_reply_t *hop = NULL;
  trace_hop_state_t *hs;
  struct timeval now, next_tx;
  dlist_node_t *dn;
  uint8_t stop_reason, stop_data;

  if(MODE_IS_PARALLEL(state->mode) == 0)
    return 0;

  /* create a hop record and insert it into the trace */
  if((hop = trace_icmp_hop(task, tp, ir)) == NULL)
    return -1;

  if(tp->probe->ttl > para->floor)
    para->floor = tp->probe->ttl;

  if(tp->probe->ttl > para->max_ttl)
    para->max_ttl = tp->probe->ttl;

  /*
   * find the hop state, which we will do if this response is the
   * first response for the probe.
   */
  for(dn=dlist_head_node(para->window); dn != NULL; dn=dlist_node_next(dn))
    {
      hs = dlist_node_item(dn);
      if(hs->id == tp->id)
	break;
    }

  gettimeofday_wrap(&now);

  /* found a matching node in the window */
  if(dn != NULL)
    {
      /* remove the node from the probe window */
      dlist_node_pop(para->window, dn);

      /*
       * expire the hop state if we do not send all attempts per hop,
       * or if we've already sent all attempts per hop
       */
      if(SCAMPER_TRACE_FLAG_IS_ALLATTEMPTS(trace) &&
	 hs->attempt < trace->attempts)
	{
	  /*
	   * if there's no minimum delay probing the same hop, or that
	   * length of time has elapsed, then probe it as soon as
	   * possible.
	   */
	  timeval_add_tv3(&next_tx, &hs->last_tx, &trace->wait_probe_hop);
	  if(para->hopwait == NULL ||
	     timeval_cmp(&next_tx, &now) <= 0)
	    {
	      if(slist_tail_push(para->probeq, hs) == NULL)
		{
		  printerror(__func__, "could not push hs");
		  free(hs);
		  return -1;
		}
	    }
	  else
	    {
	      if(heap_insert(para->hopwait, hs) == NULL)
		{
		  printerror(__func__, "could not insert hs");
		  free(hs);
		  return -1;
		}
	    }
	}
      else free(hs);
    }

  if(trace->stop_reason == SCAMPER_TRACE_STOP_NONE)
    {
      trace_stop_reason(trace, hop, state, &stop_reason, &stop_data);
      if(stop_reason != SCAMPER_TRACE_STOP_NONE)
	{
	  /* did we get a stop condition out of all that? */
	  trace_stop(trace, stop_reason, stop_data);
	  goto next_mode;
	}
    }

  if(state->mode == MODE_PARALLEL_FINISH && trace_parallel_isempty(para))
    goto next_mode;

  /* put the trace back into the probe queue */
  trace_queue(task, &now);
  return 0;

 next_mode:
  trace_next_mode(task, &now);
  return 0;
}

static void do_trace_handle_icmp(scamper_task_t *task, scamper_icmp_resp_t *ir)
{
  static int (*const func[])(scamper_task_t *, scamper_icmp_resp_t *,
			     trace_probe_t *) = {
    NULL,                        /* MODE_RTSOCK */
    NULL,                        /* MODE_DLHDR */
    handleicmp_trace,            /* MODE_TRACE */
    handleicmp_lastditch,        /* MODE_LASTDITCH */
    handleicmp_pmtud_default,    /* MODE_PMTUD_DEFAULT */
    handleicmp_pmtud_silent_l2,  /* MODE_PMTUD_SILENT_L2 */
    handleicmp_pmtud_silent_ttl, /* MODE_PMTUD_SILENT_TTL */
    handleicmp_pmtud_badsugg,    /* MODE_PMTUD_BADSUGG */
    handleicmp_dtree_first,      /* MODE_DTREE_FIRST */
    handleicmp_trace,            /* MODE_DTREE_FWD */
    handleicmp_trace,            /* MODE_DTREE_BACK */
    handleicmp_parallel,         /* MODE_PARALLEL */
    handleicmp_parallel,         /* MODE_PARALLEL_FINISH */
  };

  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t   *state = trace_getstate(task);
  trace_probe_t   *tp;
  uint16_t         id;
  uint8_t          proto;

  if(state == NULL || trace->probec == 0)
    return;

  assert(state->mode <= MODE_MAX);

  /*
   * ignore the message if it is received on an fd that we didn't use to send
   * it.  this is to avoid recording duplicate replies if an unbound socket
   * is in use.
   */
  if(ir->ir_fd != scamper_fd_fd_get(state->icmp))
    {
      return;
    }

  /*
   * if the trace is in a mode that does not handle ICMP responses, then
   * stop now
   */
  if(func[state->mode] == NULL)
    return;

  /* if the ICMP type is not something that we care for, then drop it */
  if(!((SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) ||
	SCAMPER_ICMP_RESP_IS_UNREACH(ir) ||
	SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir)) &&
       SCAMPER_ICMP_RESP_INNER_IS_SET(ir) &&
       trace->offset == ir->ir_inner_ip_off) &&
     !(SCAMPER_TRACE_TYPE_IS_ICMP(trace) &&
       SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir)))
    {
      return;
    }

  if(trace->offset != 0)
    {
      if(ir->ir_inner_data == NULL)
	return;

      if((SCAMPER_TRACE_TYPE_IS_UDP(trace) &&
	  ir->ir_inner_ip_proto != IPPROTO_UDP) ||
	 (SCAMPER_TRACE_TYPE_IS_TCP(trace) &&
	  ir->ir_inner_ip_proto != IPPROTO_TCP))
	return;

      if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	{
	  if(SCAMPER_TRACE_TYPE_IS_ICMP(trace) &&
	     ir->ir_inner_ip_proto != IPPROTO_ICMP)
	    return;

	  if(ir->ir_inner_datalen < 8)
	    return;

	  if(bytes_ntohs(ir->ir_inner_data+0) != trace->sport ||
	     bytes_ntohs(ir->ir_inner_data+2) != trace->dport)
	    return;

	  id = bytes_ntohl(ir->ir_inner_data+4);
	}
      else
	{
	  if(SCAMPER_TRACE_TYPE_IS_ICMP(trace) &&
	     ir->ir_inner_ip_proto != IPPROTO_ICMPV6)
	    return;

	  if((ir->ir_inner_ip_id >> 16) != trace->sport)
	    return;

	  if(ir->ir_inner_datalen < 4)
	    return;

	  id = bytes_ntohl(ir->ir_inner_data);
	}
    }
  else if(SCAMPER_TRACE_TYPE_IS_UDP(trace))
    {
      /*
       * if the ICMP response does not reference a UDP probe sent from our
       * source port to a destination probe we're likely to have probed, then
       * ignore the packet
       */
      if(ir->ir_inner_ip_proto  != IPPROTO_UDP ||
	 ir->ir_inner_udp_sport != trace->sport)
	return;

      if(trace->type == SCAMPER_TRACE_TYPE_UDP)
	{
	  if(ir->ir_inner_udp_dport <  trace->dport ||
	     ir->ir_inner_udp_dport >= trace->dport+state->id_next)
	    return;

	  /* XXX: handle wrap-around */
	  id = ir->ir_inner_udp_dport - trace->dport;
	}
      else if(trace->type == SCAMPER_TRACE_TYPE_UDP_PARIS)
	{
	  if(ir->ir_inner_udp_dport != trace->dport)
	    return;

	  if(ir->ir_af == AF_INET)
	    {
	      if(ntohs(ir->ir_inner_udp_sum) == ir->ir_inner_ip_id &&
		 ir->ir_inner_udp_sum != 0)
		{
		  id = ntohs(ir->ir_inner_udp_sum) - 1;
		}
	      else if(trace_ipid_fudge(state, ir->ir_inner_ip_id, &id) != 0)
		{
		  return;
		}
	    }
	  else if(SCAMPER_TRACE_FLAG_IS_CONSTPAYLOAD(trace) == 0)
	    {
	      if(ir->ir_inner_udp_sum == 0)
		return;
	      id = ntohs(ir->ir_inner_udp_sum) - 1;
	    }
	  else
	    {
	      if(ir->ir_inner_ip_flow == 0)
		return;
	      id = ir->ir_inner_ip_flow - 1;
	    }
	}
      else return;
    }
  else if(SCAMPER_TRACE_TYPE_IS_ICMP(trace))
    {
      if(SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir) == 0)
	{
	  if(ir->ir_af == AF_INET) proto = IPPROTO_ICMP;
	  else if(ir->ir_af == AF_INET6) proto = IPPROTO_ICMPV6;
	  else return;

	  if((ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_RXERR) != 0 &&
	     (state->flags & TRACE_STATE_FLAG_ICMP_ID) == 0)
	    {
	      trace->sport = ir->ir_inner_icmp_id;
	      state->flags |= TRACE_STATE_FLAG_ICMP_ID;
	    }

	  if(ir->ir_inner_ip_proto != proto          ||
	     ((ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_RXERR) == 0 &&
	      ir->ir_inner_icmp_id != trace->sport) ||
	     ir->ir_inner_icmp_seq >= state->id_next)
	    {
	      return;
	    }

	  id = ir->ir_inner_icmp_seq;
	}
      else
	{
	  if((ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_RXERR) != 0 &&
	     (state->flags & TRACE_STATE_FLAG_ICMP_ID) == 0)
	    {
	      trace->sport = ir->ir_inner_icmp_id;
	      state->flags |= TRACE_STATE_FLAG_ICMP_ID;
	    }

	  if(((ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_RXERR) == 0 &&
	      ir->ir_icmp_id != trace->sport) ||
	     ir->ir_icmp_seq >= state->id_next)
	    {
	      return;
	    }

	  id = ir->ir_icmp_seq;
	}
    }
  else if(SCAMPER_TRACE_TYPE_IS_TCP(trace))
    {
      /*
       * if the ICMP response does not reference a TCP probe sent from our
       * source port to the destination port specified then ignore the
       * ICMP packet
       */
      if(SCAMPER_ICMP_RESP_INNER_IS_SET(ir) == 0 ||
	 ir->ir_inner_ip_proto  != IPPROTO_TCP ||
	 ir->ir_inner_tcp_sport != trace->sport ||
	 ir->ir_inner_tcp_dport != trace->dport)
	{
	  return;
	}

      if(ir->ir_af == AF_INET)
	{
	  /* determine which probe id the ip id corresponds to */
	  if(trace_ipid_fudge(state, ir->ir_inner_ip_id, &id) != 0)
	    return;
	}
      else
	{
	  if(ir->ir_inner_ip_flow == 0)
	    return;
	  id = ir->ir_inner_ip_flow - 1;
	}
    }
  else
    {
      return;
    }

  if(id < state->id_next)
    {
      tp = state->probes[id];
      if(tp->probe->replyc < UINT16_MAX)
	func[state->mode](task, ir, tp);
    }

  return;
}

/*
 * timeout_trace
 *
 * this function is called if the trace timed out on the wait queue, and
 * all allotted attempts have been sent.
 */
static void timeout_trace(scamper_task_t *task)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  scamper_trace_hopiter_t hi;
  scamper_trace_reply_t *hop;
  uint8_t stop_reason, stop_data;
  struct timeval now;
  int i;

  /* we tried this hop, so move onto the next */
  state->ttl++;

  /* tidy up after any confidence probing */
  if(state->conf != NULL && state->conf->interfaces != NULL)
    {
      free(state->conf->interfaces);
      state->conf->interfaces = NULL;
      state->conf->interfacec = 0;
    }
  if(state->conf != NULL)
    {
      assert(state->conf->interfaces == NULL);
      assert(state->conf->interfacec == 0);
      state->conf->n = 2;
    }

  /*
   * if we probed for all attempts on the hop, then check to see if we
   * got any responses on this hop, and if we did, check to see if we
   * should stop probing this target yet
   */
  if(SCAMPER_TRACE_FLAG_IS_ALLATTEMPTS(trace) || trace->confidence != 0)
    {
      scamper_trace_hopiter_ttl_set(&hi, trace->hop_count, trace->hop_count);
      while((hop = scamper_trace_hopiter_next(trace, &hi)) != NULL)
	{
	  /*
	   * first, check to see if there is a reason to stop probing with
	   * this particular hop record
	   */
	  trace_stop_reason(trace, hop, state, &stop_reason, &stop_data);
	  if(stop_reason != SCAMPER_TRACE_STOP_NONE)
	    {
	      trace_stop(trace, stop_reason, stop_data);
	      goto next_mode;
	    }
	}
    }

  if((trace->hoplimit == 0 ? 255 : trace->hoplimit) <= trace->hop_count)
    {
      trace_stop_hoplimit(trace);
      goto next_mode;
    }

  /*
   * if we haven't checked to see if the path is dead yet, check to see
   * if we should do so at this time.  a dead path is defined as a path
   * that has an unresponsive target host, which we stop tracing after
   * the gaplimit is reached.
   */
  if(trace->hop_count - (trace->firsthop - 1) >= trace->gaplimit)
    {
      for(i=0; i<trace->gaplimit; i++)
	if(trace_hop_get(trace, trace->hop_count - 1 - i) != NULL)
	  break;

      if(i < trace->gaplimit)
	return;

      if(trace->gapaction == SCAMPER_TRACE_GAPACTION_LASTDITCH)
	{
	  if((trace->lastditch = scamper_trace_lastditch_alloc()) == NULL)
	    {
	      trace_handleerror(task, errno);
	      return;
	    }
	  state->mode = MODE_LASTDITCH;
	  state->ttl = 255;
	  return;
	}

      trace_stop_gaplimit(trace);
      goto next_mode;
    }

  return;

 next_mode:
  gettimeofday_wrap(&now);
  trace_next_mode(task, &now);
  return;
}

static void timeout_dtree_back(scamper_task_t *task)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  trace_dtree_state_t *dtree = state->dtree;
  scamper_trace_hopiter_t hi;
  scamper_trace_reply_t *hop;
  struct timeval now;

  assert(state->conf != NULL);

  /* tidy up after any confidence probing */
  if(state->conf->interfaces != NULL)
    {
      free(state->conf->interfaces);
      state->conf->interfaces = NULL;
      state->conf->interfacec = 0;
    }

  if(state->ttl == 1)
    goto next_mode;

  if(dtree != NULL && dtree->lsst != NULL &&
     (SCAMPER_TRACE_FLAG_IS_ALLATTEMPTS(trace) || trace->confidence != 0))
    {
      scamper_trace_hopiter_ttl_set(&hi, state->ttl, state->ttl);
      while((hop = scamper_trace_hopiter_next(trace, &hi)) != NULL)
	if(dtree_lss_in(dtree->lsst, hop->addr) != 0)
	  goto next_mode;
    }

  state->attempt = 0;
  state->ttl--;
  trace->firsthop--;

  gettimeofday_wrap(&now);
  trace_queue(task, &now);
  return;

 next_mode:
  gettimeofday_wrap(&now);
  trace_next_mode(task, &now);
  return;
}

static void timeout_dtree_first(scamper_task_t *task)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);

  /*
   * go into forwards probing mode if we've made it all the way back to
   * ttl one
   */
  if(state->ttl == 1)
    {
      state->mode = MODE_DTREE_FWD;
      state->ttl++;
      return;
    }

  /* halve ttl and try again */
  state->ttl /= 2;
  trace->firsthop /= 2;
  return;
}

static void timeout_lastditch(scamper_task_t *task)
{
  /* we received no responses to any of the last-ditch probes */
  trace_stop_gaplimit(trace_getdata(task));
  trace_queue_done(task);
  return;
}

static void timeout_pmtud_default(scamper_task_t *task)
{
  trace_state_t *state = trace_getstate(task);
  scamper_trace_pmtud_note_t *note;

  if((note = scamper_trace_pmtud_note_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc note");
      trace_handleerror(task, errno);
      return;
    }
  note->type = SCAMPER_TRACE_PMTUD_NOTE_TYPE_SILENCE;
  state->pmtud->note = note;

  pmtud_L2_init(state);
  state->mode = MODE_PMTUD_SILENT_L2;
  return;
}

static void timeout_pmtud_silent_l2(scamper_task_t *task)
{
  trace_state_t *state = trace_getstate(task);
  int size = state->header_size + state->payload_size;

  assert(state->pmtud->L2 != NULL);

  /*
   * have we scanned the L2 table to the official minimum MTU?
   * if we have, then PMTU fails and we abort.
   */
  if(state->pmtud->L2->idx == 0)
    {
      trace_queue_done(task);
      return;
    }

  /*
   * we did not get a response for this probe size
   * if we can halve the search space again, then do that
   */
  if(state->pmtud->L2->lower + 1 != size)
    {
      pmtud_L2_set_probesize(state, state->pmtud->L2->lower, size);
    }
  else
    {
      state->pmtud->L2->out = state->pmtud->L2->lower;

      /* set the bounds of the TTL search */
      if(pmtud_TTL_init(task) == 1)
	state->mode = MODE_PMTUD_SILENT_TTL;
      else
	trace_queue_done(task);
    }

  return;
}

static void timeout_pmtud_silent_ttl(scamper_task_t *task)
{
  trace_state_t *state = trace_getstate(task);

  assert(state->pmtud->TTL != NULL);

  /*
   * select another TTL to probe with, if possible. if not, then
   * the search halts and we move on
   */
  if(pmtud_TTL_set_probettl(task, state->pmtud->TTL->lower, state->ttl) == 0)
    pmtud_L2_search_end(task);

  return;
}

/*
 * timeout_pmtud_badsugg
 *
 * if we timeout while trying to determine the underlying MTU on a path
 * where a router gives a bad suggestion, chances are that an ICMP blackhole
 * exists later in the path.  try sending a larger packet, if we can.
 */
static void timeout_pmtud_badsugg(scamper_task_t *task)
{
  trace_state_t *state = trace_getstate(task);
  int lower, upper;

  assert(state->pmtud->L2 != NULL);

  lower = state->header_size + state->payload_size;
  upper = state->pmtud->L2->upper;
  state->pmtud->L2->hop = NULL;

  if(lower + 1 != upper)
    {
      pmtud_L2_set_probesize(state, lower, upper);
    }
  else
    {
      /* terminate the search now */
      state->pmtud->L2->lower = state->pmtud->L2->out = lower;
      pmtud_L2_search_end(task);
    }

  return;
}

/*
 * do_trace_handle_timeout
 *
 * the trace has expired while sitting on the wait queue.
 * handle this event appropriately.
 */
static void do_trace_handle_timeout(scamper_task_t *task)
{
  static void (* const func[])(scamper_task_t *) = {
    NULL,                      /* MODE_RTSOCK */
    NULL,                      /* MODE_DLHDR */
    timeout_trace,             /* MODE_TRACE */
    timeout_lastditch,         /* MODE_LASTDITCH */
    timeout_pmtud_default,     /* MODE_PMTUD_DEFAULT */
    timeout_pmtud_silent_l2,   /* MODE_PMTUD_SILENT_L2 */
    timeout_pmtud_silent_ttl,  /* MODE_PMTUD_SILENT_TTL */
    timeout_pmtud_badsugg,     /* MODE_PMTUD_BADSUGG */
    timeout_dtree_first,       /* MODE_DTREE_FIRST */
    timeout_trace,             /* MODE_DTREE_FWD */
    timeout_dtree_back,        /* MODE_DTREE_BACK */
    NULL,                      /* MODE_PARALLEL */
    NULL,                      /* MODE_PARALLEL_FINISH */
  };

  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t   *state = trace_getstate(task);
  trace_probe_t   *tp;
  struct timeval now;

#ifdef HAVE_SCAMPER_DEBUG
  char buf[128];
#endif

  assert(state->mode <= MODE_MAX);

  if(state->mode == MODE_RTSOCK || state->mode == MODE_DLHDR)
    {
      scamper_debug(__func__, "mode %d dst %s", state->mode,
		    scamper_addr_tostr(trace->dst, buf, sizeof(buf)));
      trace_handleerror(task, 0);
      return;
    }

  if(MODE_IS_PARALLEL(state->mode))
    {
      gettimeofday_wrap(&now);
      trace_queue(task, &now);
      return;
    }

  tp = state->probes[state->id_next-1];
  if(tp->probe->replyc == 0)
    {
      tp->flags |= TRACE_PROBE_FLAG_TIMEOUT;
    }
  else
    {
      assert(trace->wait_probe.tv_sec != 0 || trace->wait_probe.tv_usec != 0);
      return;
    }

  /*
   * if we have sent all allotted attempts for this probe type, then
   * handle this particular probe failing
   */
  if((trace->confidence == 0 && state->attempt == trace->attempts) ||
     (trace->confidence != 0 && state->attempt == k(state->conf)))
    {
      /* we're probably going to send another probe, so reset the attempt # */
      state->attempt = 0;

      /* call the function that handles a timeout in this particular mode */
      func[state->mode](task);
    }

  return;
}

static int handletp_trace(scamper_task_t *task, scamper_dl_rec_t *dl,
			  trace_probe_t *tp)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  trace_conf_state_t *conf;
  scamper_trace_reply_t *hop;
  struct timeval now;

  /* we should only have to deal with probes sent while in the trace state */
  if(tp->mode != MODE_TRACE)
    return 0;

  /* create a hop record based off the TCP data */
  if((hop = trace_dl_hop(task, tp, dl)) == NULL)
    return -1;

  /* if we are sending all allotted probes to the target */
  if(SCAMPER_TRACE_FLAG_IS_ALLATTEMPTS(trace))
    {
      if(tp->probe->id != trace->attempts)
	goto probe;
    }
  else if(trace->confidence != 0 && (conf = state->conf) != NULL)
    {
      /* record details of the interface */
      if(conf_iface_add(conf, hop->addr) != 0)
	{
	  printerror(__func__, "could not add interface");
	  trace_handleerror(task, errno);
	  return -1;
	}

      /* if there are still probes to send for this hop, send the next one */
      if(conf->n <= TRACE_CONFIDENCE_MAX_N && state->attempt < k(conf))
	goto probe;
    }

  trace_stop_completed(trace);
  gettimeofday_wrap(&now);
  trace_next_mode(task, &now);

  return 0;

 probe:
  gettimeofday_wrap(&now);
  trace_queue(task, &now);
  return 0;
}

static int handletp_lastditch(scamper_task_t *task, scamper_dl_rec_t *dl,
			      trace_probe_t *tp)
{
  scamper_trace_t *trace = trace_getdata(task);

  /* only handle TCP responses in these two states */
  if(tp->mode != MODE_TRACE && tp->mode != MODE_LASTDITCH)
    return 0;

  /* create a hop record based off the TCP data */
  if(trace_dl_hop(task, tp, dl) == NULL)
    return -1;

  if(tp->mode == MODE_LASTDITCH)
    trace_stop_gaplimit(trace);
  else
    trace_stop_completed(trace);

  trace_queue_done(task);
  return 0;
}

static int handletp_pmtud_default(scamper_task_t *task, scamper_dl_rec_t *dl,
				  trace_probe_t *tp)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  scamper_trace_reply_t *hop;

  if(dl->dl_ip_proto != IPPROTO_TCP ||
     pmtud_default_pre(state, tp) == 0)
    return 0;

  if((hop = trace_dl_hop(task, tp, dl)) == NULL)
    return -1;
  state->pmtud->last_fragmsg = hop;

  trace->pmtud->pmtu = tp->probe->size;
  trace_queue_done(task);

  return 0;
}

static int handletp_pmtud_silent_ttl(scamper_task_t *task, scamper_dl_rec_t *dl,
				     trace_probe_t *tp)
{
  scamper_debug(__func__, "hello");
  return 0;
}

static int handletp_pmtud_silent_l2(scamper_task_t *task, scamper_dl_rec_t *dl,
				    trace_probe_t *tp)
{
  trace_state_t *state = trace_getstate(task);
  scamper_trace_reply_t *hop;

  /* do we consider the packet? */
  if(dl->dl_ip_proto != IPPROTO_TCP ||
     pmtud_silent_l2_pre(state->pmtud->L2, tp) == 0)
    return 0;

  /* record the hop details */
  if((hop = trace_dl_hop(task, tp, dl)) == NULL)
    return -1;

  pmtud_silent_l2_post(task, tp, hop);
  return 0;
}

static int handletp_pmtud_badsugg(scamper_task_t *task, scamper_dl_rec_t *dl,
				  trace_probe_t *tp)
{
  trace_state_t *state = trace_getstate(task);
  scamper_trace_reply_t *hop;
  int lower, upper;

  /* do we consider the packet? */
  if(dl->dl_ip_proto != IPPROTO_TCP)
    return 0;

  /* record the hop details */
  if((hop = trace_dl_hop(task, tp, dl)) == NULL)
    return -1;

  assert(state->pmtud->L2 != NULL);

  lower = tp->probe->size;
  upper = state->pmtud->L2->upper;

  /* replace the layer-2 hop we get a response for with this hop */
  state->pmtud->L2->hop = hop;

  pmtud_badsugg_post(task, lower, upper);
  return 0;
}

/*
 * dlin_trace
 *
 * handle a datalink record for an inbound packet which was sent
 * for a probe in the trace state.
 *
 * in this case, we use the timestamp to update the hop record.
 */
static void dlin_trace(scamper_trace_t *trace,
		       scamper_dl_rec_t *dl, trace_probe_t *tp)
{
  scamper_trace_reply_t *hop;
  struct timeval new_rtt;

  if(tp->probe->replyc == 0)
    return;

  /* adjust the rtt based on the timestamp included in the datalink record */
  timeval_diff_tv(&new_rtt, &tp->probe->tx, &tp->dl_rx);

  /*
   * only adjust the timestamp for the first response, packet
   * matching issues for extra responses without further logic
   */
  hop = tp->probe->replies[0];
  scamper_debug(__func__,
		"hop %ld.%06d dl_rec %ld.%06d diff %d",
		(long)hop->rtt.tv_sec, (int)hop->rtt.tv_usec,
		(long)new_rtt.tv_sec, (int)new_rtt.tv_usec,
		timeval_diff_us(&new_rtt, &hop->rtt));

  hop->flags &= ~(SCAMPER_TRACE_REPLY_FLAG_TS_SOCK_RX);
  hop->flags |= SCAMPER_TRACE_REPLY_FLAG_TS_DL_RX;
  timeval_cpy(&hop->rtt, &new_rtt);

  return;
}

/*
 * dlout_apply
 *
 * adjust the RTT recorded for a probe/reply sequence based on an updated
 * transmit timestamp corresponding to when the packet was queued at the
 * network interface.
 */
static void dlout_apply(trace_probe_t *tp, const struct timeval *dl_tx)
{
  struct timeval diff;
  scamper_trace_reply_t *hop;
  uint16_t r;

  timeval_diff_tv(&diff, &tp->probe->tx, dl_tx);
  scamper_debug(__func__, "probe %ld.%06d dl %ld.%06d diff %ld.%06d",
		(long)tp->probe->tx.tv_sec, (int)tp->probe->tx.tv_usec,
		(long)dl_tx->tv_sec, (int)dl_tx->tv_usec,
		(long)diff.tv_sec, (int)diff.tv_usec);

  /*
   * if we've already processed a datalink timestamp for this
   * transmitted packet, we're done.
   */
  if((tp->probe->flags & SCAMPER_TRACE_REPLY_FLAG_TS_DL_TX) != 0)
    return;

  /*
   * if the transmit time we have in user-space is after the timestamp
   * that we observed on the datalink, then we're done
   */
  if(timeval_cmp(&tp->probe->tx, dl_tx) > 0)
    return;

  tp->probe->flags |= SCAMPER_TRACE_REPLY_FLAG_TS_DL_TX;
  timeval_cpy(&tp->probe->tx, dl_tx);

  for(r=0; r<tp->probe->replyc; r++)
    {
      hop = tp->probe->replies[r];
      hop->flags |= SCAMPER_TRACE_REPLY_FLAG_TS_DL_TX;
      if(timeval_cmp(&hop->rtt, &diff) >= 0)
	timeval_sub_tv(&hop->rtt, &diff);
    }

  return;
}

/*
 * do_trace_handle_dl
 *
 * handle a datalink record that may have something useful for the
 * traceroute, such as a more accurate timestamp.
 */
static void do_trace_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  static void (* const dlout_func[])(trace_probe_t *, const struct timeval *) =
  {
    NULL,            /* MODE_RTSOCK */
    NULL,            /* MODE_DLHDR */
    dlout_apply,     /* MODE_TRACE */
    dlout_apply,     /* MODE_LASTDITCH */
    NULL,            /* MODE_PMTUD_DEFAULT */
    NULL,            /* MODE_PMTUD_SILENT_L2 */
    NULL,            /* MODE_PMTUD_SILENT_TTL */
    NULL,            /* MODE_PMTUD_BADSUGG */
    NULL,            /* MODE_DTREE_FIRST */
    NULL,            /* MODE_DTREE_FWD */
    NULL,            /* MODE_DTREE_BACK */
    dlout_apply,     /* MODE_PARALLEL */
    dlout_apply,     /* MODE_PARALLEL_FINISH */
  };

  static void (* const dlin_func[])(scamper_trace_t *, scamper_dl_rec_t *,
				    trace_probe_t *) =
  {
    NULL,            /* MODE_RTSOCK */
    NULL,            /* MODE_DLHDR */
    dlin_trace,      /* MODE_TRACE */
    NULL,            /* MODE_LASTDITCH */
    NULL,            /* MODE_PMTUD_DEFAULT */
    NULL,            /* MODE_PMTUD_SILENT_L2 */
    NULL,            /* MODE_PMTUD_SILENT_TTL */
    NULL,            /* MODE_PMTUD_BADSUGG */
    NULL,            /* MODE_DTREE_FIRST */
    NULL,            /* MODE_DTREE_FWD */
    NULL,            /* MODE_DTREE_BACK */
    dlin_trace,      /* MODE_PARALLEL */
    dlin_trace,      /* MODE_PARALLEL_FINISH */
  };

  static int (* const handletp_func[])(scamper_task_t *,
				       scamper_dl_rec_t *, trace_probe_t *) =
  {
    NULL,                /* MODE_RTSOCK */
    NULL,                /* MODE_DLHDR */
    handletp_trace,      /* MODE_TRACE */
    handletp_lastditch,  /* MODE_LASTDITCH */
    handletp_pmtud_default,    /* MODE_PMTUD_DEFAULT */
    handletp_pmtud_silent_l2,  /* MODE_PMTUD_SILENT_L2 */
    handletp_pmtud_silent_ttl, /* MODE_PMTUD_SILENT_TTL */
    handletp_pmtud_badsugg,    /* MODE_PMTUD_BADSUGG */
    NULL,                /* MODE_DTREE_FIRST */
    NULL,                /* MODE_DTREE_FWD */
    NULL,                /* MODE_DTREE_BACK */
    NULL,                /* MODE_PARALLEL */
    NULL,                /* MODE_PARALLEL_FINISH */
  };
  static const int DIR_INBOUND  = 0;
  static const int DIR_OUTBOUND = 1;

  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t   *state = trace_getstate(task);
  trace_probe_t   *tp;
  uint16_t         probe_id;
  int              direction;

  if(state == NULL || trace->probec == 0)
    return;

  assert(dl->dl_af == AF_INET || dl->dl_af == AF_INET6);

  /* if this record has no timestamp, go no further */
  if((dl->dl_flags & SCAMPER_DL_REC_FLAG_TIMESTAMP) == 0)
    return;

  if(SCAMPER_DL_IS_IP(dl) == 0)
    return;

  /*
   * try and determine the direction of the packet and the associated probe
   * for this datalink record
   */
  if(trace->type == SCAMPER_TRACE_TYPE_UDP ||
     trace->type == SCAMPER_TRACE_TYPE_UDP_PARIS)
    {
      if(dl->dl_ip_proto == IPPROTO_UDP)
	{
	  /*
	   * for probe/response matching, the logic is as follows.
	   * for classic UDP traceroute where the destination port changes
	   * with each probe, we can use the port as a probe identifier.
	   * for UDP-paris traceroute, the logic is more complicated.
	   * for outbound UDP packets, we can use the UDP checksum value
	   * as long as the const-payload option is not used, or the
	   * IPv4-ID or IPv6-flow-id.
	   * for inbound UDP packets, we have to assume that the response
	   * is for the last sent probe.
	   */
	  if(dl->dl_udp_sport == trace->sport &&
	     scamper_addr_raw_cmp(trace->dst, dl->dl_ip_dst) == 0 &&
	     scamper_addr_raw_cmp(trace->src, dl->dl_ip_src) == 0)
	    {
	      direction = DIR_OUTBOUND;
	      if(trace->type == SCAMPER_TRACE_TYPE_UDP)
		probe_id = dl->dl_udp_dport - trace->dport;
	      else if(SCAMPER_TRACE_FLAG_IS_CONSTPAYLOAD(trace) == 0)
		probe_id = ntohs(dl->dl_udp_sum) - 1;
	      else if(dl->dl_af == AF_INET)
		probe_id = dl->dl_ip_id - 1;
	      else if(dl->dl_af == AF_INET6)
		probe_id = dl->dl_ip_flow - 1;
	      else
		return;
	    }
	  else if(dl->dl_udp_dport == trace->sport &&
		  scamper_addr_raw_cmp(trace->dst, dl->dl_ip_src) == 0 &&
		  scamper_addr_raw_cmp(trace->src, dl->dl_ip_dst) == 0)
	    {
	      direction = DIR_INBOUND;
	      if(trace->type == SCAMPER_TRACE_TYPE_UDP)
		probe_id = dl->dl_udp_sport - trace->dport;
	      else
		probe_id = state->id_next - 1;
	    }
	  else return;
	}
      else if(SCAMPER_DL_IS_ICMP(dl))
	{
	  if(SCAMPER_DL_IS_ICMP_TTL_EXP(dl) == 0 &&
	     SCAMPER_DL_IS_ICMP_UNREACH(dl) == 0 &&
	     SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl) == 0)
	    {
	      return;
	    }
	  if(dl->dl_icmp_ip_proto != IPPROTO_UDP)
	    return;
	  if(dl->dl_icmp_udp_sport != trace->sport)
	    return;

	  direction = DIR_INBOUND;

	  if(trace->type == SCAMPER_TRACE_TYPE_UDP)
	    {
	      probe_id = dl->dl_icmp_udp_dport - trace->dport;
	    }
	  else
	    {
	      if(dl->dl_icmp_udp_dport != trace->dport)
		return;

	      if(dl->dl_af == AF_INET)
		{
		  if(ntohs(dl->dl_icmp_udp_sum) == dl->dl_icmp_ip_id &&
		     dl->dl_icmp_udp_sum != 0)
		    {
		      probe_id = ntohs(dl->dl_icmp_udp_sum) - 1;
		    }
		  else if(trace_ipid_fudge(state,dl->dl_icmp_ip_id,
					   &probe_id) != 0)
		    {
		      return;
		    }
		}
	      else if(SCAMPER_TRACE_FLAG_IS_CONSTPAYLOAD(trace) == 0)
		{
		  if(dl->dl_icmp_udp_sum == 0)
		    return;
		  probe_id = ntohs(dl->dl_icmp_udp_sum) - 1;
		}
	      else
		{
		  probe_id = dl->dl_ip_flow - 1;
		}
	    }
	}
      else return;
    }
  else if(trace->type == SCAMPER_TRACE_TYPE_ICMP_ECHO ||
	  trace->type == SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS)
    {
      if(SCAMPER_DL_IS_ICMP(dl) == 0)
	return;

      if(SCAMPER_DL_IS_ICMP_ECHO_REQUEST(dl))
	{
	  if(dl->dl_icmp_id != trace->sport)
	    return;
	  probe_id = dl->dl_icmp_seq;
	  direction = DIR_OUTBOUND;
	}
      else if(SCAMPER_DL_IS_ICMP_ECHO_REPLY(dl))
	{
	  if(dl->dl_icmp_id != trace->sport)
	    return;
	  probe_id = dl->dl_icmp_seq;
	  direction = DIR_INBOUND;
	}
      else if((SCAMPER_DL_IS_ICMP_TTL_EXP(dl) ||
	       SCAMPER_DL_IS_ICMP_UNREACH(dl) ||
	       SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl)) &&
	      SCAMPER_DL_IS_ICMP_Q_ICMP_ECHO_REQ(dl))
	{
	  if(dl->dl_icmp_icmp_id != trace->sport)
	    return;
	  probe_id = dl->dl_icmp_icmp_seq;
	  direction = DIR_INBOUND;
	}
      else return;
    }
  else if(SCAMPER_TRACE_TYPE_IS_TCP(trace))
    {
      if(dl->dl_ip_proto == IPPROTO_TCP)
	{
	  /*
	   * if the sport and dport match what we probe with, then the
	   * probe is probably an outgoing one.  also check flags field
	   * is consistent with the probe method
	   */
	  if(dl->dl_tcp_sport == trace->sport &&
	     dl->dl_tcp_dport == trace->dport &&
	     scamper_addr_raw_cmp(trace->dst, dl->dl_ip_dst) == 0 &&
	     scamper_addr_raw_cmp(trace->src, dl->dl_ip_src) == 0 &&
	     ((trace->type == SCAMPER_TRACE_TYPE_TCP &&
	       dl->dl_tcp_flags == TH_SYN) ||
	      (trace->type == SCAMPER_TRACE_TYPE_TCP_ACK &&
	       dl->dl_tcp_flags == TH_ACK)))
	    {
	      direction = DIR_OUTBOUND;
	      if(dl->dl_af == AF_INET)
		probe_id = dl->dl_ip_id - 1;
	      else
		probe_id = dl->dl_ip_flow - 1;
	    }
	  else if(dl->dl_tcp_sport == trace->dport &&
		  dl->dl_tcp_dport == trace->sport &&
		  scamper_addr_raw_cmp(trace->dst, dl->dl_ip_src) == 0 &&
		  scamper_addr_raw_cmp(trace->src, dl->dl_ip_dst) == 0)
	    {
	      /*
	       * this is an inbound packet.
	       * there is no easy way to determine which probe the reply is
	       * for, so assume it was for the last one
	       */
	      direction = DIR_INBOUND;
	      probe_id = state->id_next - 1;
	    }
	  else return;
	}
      else if(SCAMPER_DL_IS_ICMP(dl))
	{
	  if(SCAMPER_DL_IS_ICMP_TTL_EXP(dl) == 0 &&
	     SCAMPER_DL_IS_ICMP_UNREACH(dl) == 0 &&
	     SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl) == 0)
	    {
	      return;
	    }
	  if(dl->dl_icmp_ip_proto  != IPPROTO_TCP  ||
	     dl->dl_icmp_tcp_sport != trace->sport ||
	     dl->dl_icmp_tcp_dport != trace->dport)
	    {
	      return;
	    }

	  /* determine which probe the ICMP response corresponds to */
	  if(dl->dl_af == AF_INET)
	    {
	      if(trace_ipid_fudge(state, dl->dl_icmp_ip_id, &probe_id) != 0)
		return;
	    }
	  else
	    {
	      if(dl->dl_icmp_ip_flow == 0)
		return;
	      probe_id = dl->dl_icmp_ip_flow - 1;
	    }

	  /* this is an inbound packet */
	  direction = DIR_INBOUND;
	}
      else return;
    }
  else return;

  /* find the probe that corresponds to this datalink record */
  if(probe_id >= state->id_next)
    return;
  tp = state->probes[probe_id];

  /* make sure the probe structure makes sense */
  assert(tp->mode <= MODE_MAX);

  /* if this is an inbound packet with a timestamp attached */
  if(direction == DIR_INBOUND && (tp->flags & TRACE_PROBE_FLAG_DL_RX) == 0)
    {
      /* update the receive timestamp stored with the probe */
      tp->flags |= TRACE_PROBE_FLAG_DL_RX;
      timeval_cpy(&tp->dl_rx, &dl->dl_tv);

      if(dl->dl_ip_proto == IPPROTO_TCP || dl->dl_ip_proto == IPPROTO_UDP)
	{
	  /*
	   * inbound TCP and UDP packets result in a hop record being
	   * created
	   */
	  if(handletp_func[tp->mode] != NULL && tp->probe->replyc < UINT16_MAX)
	    {
	      if(dl->dl_ip_proto == IPPROTO_TCP)
		scamper_dl_rec_tcp_print(dl);
	      else
		scamper_dl_rec_udp_print(dl);
	      handletp_func[tp->mode](task, dl, tp);
	    }
	}
      else
	{
	  /*
	   * other datalink records result in timestamps being adjusted
	   */
	  if(dlin_func[tp->mode] != NULL)
	    dlin_func[tp->mode](trace, dl, tp);
	}
    }
  else if(direction == DIR_OUTBOUND)
    {
      /* adjust tx timestamp, and the RTTs of any replies */
      if(dlout_func[tp->mode] != NULL)
	dlout_func[tp->mode](tp, &dl->dl_tv);
    }

  return;
}

/*
 * trace_handle_dlhdr:
 *
 * this callback function takes an incoming datalink header and deals with
 * it.
 */
static void trace_handle_dlhdr(scamper_dlhdr_t *dlhdr)
{
  scamper_task_t *task = dlhdr->param;
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);

  if(dlhdr->error != 0)
    {
      trace_queue_done(task);
      return;
    }

  state->attempt = 0;
  state->mode = trace_first_mode(trace);

  scamper_task_queue_probe(task);
  return;
}

static void trace_handle_rt(scamper_route_t *rt)
{
  scamper_task_t *task = rt->param;
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  struct timeval tv;
  scamper_dl_t *dl;

  if(state->mode != MODE_RTSOCK || state->route != rt)
    goto done;

#ifndef _WIN32 /* windows does not have a routing socket */
  if(state->rtsock != NULL)
    {
      scamper_fd_free(state->rtsock);
      state->rtsock = NULL;
    }
#endif

  if(rt->error != 0 || rt->ifindex < 0)
    {
      printerror(__func__, "could not get ifindex");
      trace_handleerror(task, errno);
      goto done;
    }

  /*
   * if scamper is supposed to get tx timestamps from the datalink, or
   * scamper needs the datalink to transmit packets, then try and get a
   * datalink on the ifindex specified.
   */
  if((state->dl = scamper_fd_dl(rt->ifindex)) == NULL)
    {
      scamper_debug(__func__, "could not get dl for %d", rt->ifindex);
      trace_handleerror(task, errno);
      goto done;
    }
  dl = scamper_fd_dl_get(state->dl);

  /*
   * when doing tcp traceroute to an IPv4 destination, it isn't the end
   * of the world if we can't probe using a datalink socket, as we can
   * fall back to a raw socket.
   */
  if(SCAMPER_TRACE_TYPE_IS_TCP(trace) && state->raw == NULL &&
     trace->rtr == NULL &&
     scamper_dl_tx_type(dl) == SCAMPER_DL_TX_UNSUPPORTED &&
     SCAMPER_ADDR_TYPE_IS_IPV4(trace->dst))
    {
      state->raw = scamper_fd_ip4();
    }

  /*
   * if we're doing path MTU discovery, or doing tcp traceroute, or
   * doing udp paris traceroute, or relaying probes via a specific
   * router, or sending fragments, determine the underlying framing to
   * use with each probe packet that will be sent on the datalink.
   */
  if(SCAMPER_TRACE_FLAG_IS_PMTUD(trace) ||
     (SCAMPER_TRACE_TYPE_IS_TCP(trace) && state->raw == NULL) ||
     trace->offset != 0 || trace->rtr != NULL ||
     SCAMPER_TRACE_FLAG_IS_DL(trace) ||
     (SCAMPER_TRACE_TYPE_IS_UDP_PARIS(trace) && scamper_osinfo_is_sunos()))
    {
      state->mode = MODE_DLHDR;
      if((state->dlhdr = scamper_dlhdr_alloc()) == NULL)
	{
	  trace_handleerror(task, errno);
	  goto done;
	}
      if(trace->rtr == NULL)
	state->dlhdr->dst = scamper_addr_use(trace->dst);
      else
	state->dlhdr->dst = scamper_addr_use(trace->rtr);
      state->dlhdr->gw = rt->gw != NULL ? scamper_addr_use(rt->gw) : NULL;
      state->dlhdr->ifindex = rt->ifindex;
      state->dlhdr->txtype = scamper_dl_tx_type(dl);
      state->dlhdr->param = task;
      state->dlhdr->cb = trace_handle_dlhdr;
      if(scamper_dlhdr_get(state->dlhdr) != 0)
	{
	  trace_handleerror(task, errno);
	  goto done;
	}
    }

  /* if we're using a raw socket to do tcp traceroute, then start probing */
  if(SCAMPER_TRACE_TYPE_IS_TCP(trace) && state->raw != NULL)
    {
      state->attempt = 0;
      state->mode = trace_first_mode(trace);
      scamper_task_queue_probe(task);
      return;
    }

  if(state->mode == MODE_DLHDR && scamper_task_queue_isdone(task) == 0)
    {
      gettimeofday_wrap(&tv);
      timeval_add_tv(&tv, &trace->wait_timeout);
      scamper_task_queue_wait_tv(task, &tv);
    }

  assert(state->mode != MODE_RTSOCK);

 done:
  scamper_route_free(rt);
  if(state->route == rt)
    state->route = NULL;
  return;
}

static void do_trace_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_trace_t *trace = trace_getdata(task);
  scamper_trace_reply_t *hop;
  scamper_trace_hopiter_t hi;
  trace_state_t *state;
  uint8_t stop_reason, stop_data;

  if(trace->squeries > 1 && (state = trace_getstate(task)) != NULL)
    {
      state->loopc = 0;

      scamper_trace_hopiter_ttl_set(&hi, trace->firsthop, 0);
      while((hop = scamper_trace_hopiter_next(trace, &hi)) != NULL)
	{
	  trace_stop_reason(trace, hop, state, &stop_reason, &stop_data);
	  if(stop_reason != SCAMPER_TRACE_STOP_NONE)
	    {
	      if(trace->hop_count > hop->probe->ttl)
		{
		  trace->stop_reason = stop_reason;
		  trace->stop_data = stop_data;
		  trace->stop_hop = hop->probe->ttl;
		}
	      goto write;
	    }
	}
    }

 write:
  scamper_file_write_trace(sf, trace, task);
  return;
}

static void trace_pmtud_state_free(trace_pmtud_state_t *state)
{
  if(state->L2 != NULL)  free(state->L2);
  if(state->TTL != NULL) free(state->TTL);
  if(state->note != NULL) scamper_trace_pmtud_note_free(state->note);
  free(state);
  return;
}

static void trace_dtree_state_free(trace_dtree_state_t *state)
{
  if(state->lss != NULL) free(state->lss);
  free(state);
  return;
}

static int trace_conf_state_alloc(const scamper_trace_t *trace,
				  trace_state_t *state)
{
  if((state->conf = malloc_zero(sizeof(trace_conf_state_t))) == NULL)
    return -1;
  state->conf->n = 2;
  if(trace->confidence == 99)
    state->conf->confidence = 1;
  return 0;
}

static void trace_conf_state_free(trace_conf_state_t *state)
{
  if(state->interfaces != NULL) free(state->interfaces);
  free(state);
  return;
}

static int trace_para_state_alloc(const scamper_trace_t *trace,
				  trace_state_t *state)
{
  trace_para_state_t *para;

  if((state->para = malloc_zero(sizeof(trace_para_state_t))) == NULL ||
     (state->para->window = dlist_alloc()) == NULL ||
     (state->para->probeq = slist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc state");
      return -1;
    }

  para = state->para;
  if(timeval_iszero(&trace->wait_probe_hop) == 0 &&
     (para->hopwait = heap_alloc((heap_cmp_t)trace_hop_state_cmp)) == NULL)
    {
      printerror(__func__, "could not alloc waithop");
      return -1;
    }

  return 0;
}

static void trace_para_state_free(trace_para_state_t *state)
{
  if(state->window != NULL) dlist_free_cb(state->window, free);
  if(state->probeq != NULL) slist_free_cb(state->probeq, free);
  if(state->hopwait != NULL) heap_free(state->hopwait, free);
  free(state);
  return;
}

static void trace_state_free(trace_state_t *state)
{
  trace_probe_t *tp;
  int i;

  /* free the probe records scamper kept */
  if(state->probes != NULL)
    {
      for(i=0; i<state->id_next; i++)
	{
	  if((tp = state->probes[i]) == NULL)
	    continue;
	  if((tp->flags & TRACE_PROBE_FLAG_STORED) == 0 && tp->probe != NULL)
	    scamper_trace_probe_free(tp->probe);
	  free(tp);
	}
      free(state->probes);
    }

#ifndef _WIN32 /* windows does not have a routing socket */
  if(state->rtsock != NULL)     scamper_fd_free(state->rtsock);
#endif

  if(state->dl != NULL)         scamper_fd_free(state->dl);
  if(state->icmp != NULL)       scamper_fd_free(state->icmp);
  if(state->probe != NULL)      scamper_fd_free(state->probe);
  if(state->raw != NULL)        scamper_fd_free(state->raw);
  if(state->route != NULL)      scamper_route_free(state->route);
  if(state->dlhdr != NULL)      scamper_dlhdr_free(state->dlhdr);
  if(state->conf != NULL)       trace_conf_state_free(state->conf);
  if(state->dtree != NULL)      trace_dtree_state_free(state->dtree);
  if(state->pmtud != NULL)      trace_pmtud_state_free(state->pmtud);
  if(state->para != NULL)       trace_para_state_free(state->para);
#ifndef DISABLE_SCAMPER_HOST
  if(state->ths != NULL)
    splaytree_free(state->ths, (splaytree_free_t)trace_host_free);
#endif

  free(state);
  return;
}

/*
 * trace_probe_headerlen
 *
 * return the length of headers sent on probe packets with this trace
 */
static uint16_t trace_probe_headerlen(const scamper_trace_t *trace)
{
  uint16_t len;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(trace->dst))
    len = 20;
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(trace->dst))
    len = 40;
  else
    return 0;

  if(trace->offset > 0)
    return len;

  if(SCAMPER_TRACE_TYPE_IS_UDP(trace))
    len += 8;
  else if(SCAMPER_TRACE_TYPE_IS_ICMP(trace))
    len += (1 + 1 + 2 + 2 + 2);
  else if(SCAMPER_TRACE_TYPE_IS_TCP(trace))
    len += 20;
  else
    return 0;

  return len;
}

static int trace_state_alloc(scamper_task_t *task)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  int id_max;

  assert(trace != NULL);

  if(trace->confidence != 0 && trace_conf_state_alloc(trace, state) != 0)
    goto err;

  if(trace->squeries > 1 && trace_para_state_alloc(trace, state) != 0)
    goto err;

  /* allocate memory to record hops */
  state->alloc_hops = TRACE_ALLOC_HOPS;
  if(trace->firsthop >= state->alloc_hops)
    {
      if(state->alloc_hops + (uint16_t)trace->firsthop > 256)
	state->alloc_hops = 256;
      else
	state->alloc_hops += trace->firsthop;
    }

  /* if we're doing doubletree probing, then allocate state for that */
  if(trace->dtree != NULL)
    {
      if((state->dtree = malloc_zero(sizeof(trace_dtree_state_t))) == NULL)
	goto err;
      if(trace->dtree->lss != NULL &&
	 (state->dtree->lsst = trace_lss_get(trace->dtree->lss)) == NULL)
	goto err;
    }

  if(scamper_trace_hops_alloc(trace, state->alloc_hops) == -1)
    {
      printerror(__func__, "could not malloc hops");
      goto err;
    }

  /* allocate enough ids to probe each hop with max number of attempts */
  id_max = (state->alloc_hops - trace->firsthop + 2) * trace->attempts;

  /* allocate enough space to store state for each probe */
  if((state->probes = malloc_zero(sizeof(trace_probe_t *) * id_max)) == NULL)
    {
      printerror(__func__, "could not malloc probes");
      goto err;
    }

  if((state->header_size = trace_probe_headerlen(trace)) == 0)
    {
      printerror_msg(__func__, "unknown probe headerlen");
      goto err;
    }
  assert(trace->probe_size >= state->header_size);

  state->dl           = NULL;
  state->dlhdr        = NULL;
  state->ttl          = trace->firsthop;
  state->payload_size = trace->probe_size - state->header_size;
  state->id_max       = id_max;

  /* if scamper has to get the ifindex, then start in the rtsock mode */
  if(SCAMPER_TRACE_FLAG_IS_PMTUD(trace) || SCAMPER_TRACE_FLAG_IS_DL(trace) ||
     SCAMPER_TRACE_TYPE_IS_TCP(trace) || trace->offset != 0 ||
     trace->rtr != NULL ||
     (SCAMPER_TRACE_TYPE_IS_UDP_PARIS(trace) && scamper_osinfo_is_sunos()))
    {
      state->mode = MODE_RTSOCK;
#ifndef _WIN32 /* windows does not have a routing socket */
      if((state->rtsock = scamper_fd_rtsock()) == NULL)
	goto err;
#endif
    }
  else
    {
      state->mode = trace_first_mode(trace);
    }

  if(scamper_option_icmp_rxerr() != 0)
    {
      trace->flags |= SCAMPER_TRACE_FLAG_RXERR;
      if((SCAMPER_TRACE_TYPE_IS_ICMP(trace) &&
	  SCAMPER_ADDR_TYPE_IS_IPV4(trace->dst)) ||
	 (SCAMPER_TRACE_TYPE_IS_UDP(trace) &&
	  SCAMPER_ADDR_TYPE_IS_IPV6(trace->dst)))
	{
	  state->icmp = scamper_fd_use(state->probe);
	}
      if(state->icmp == NULL)
	goto err;
    }
  else
    {
      if(SCAMPER_ADDR_TYPE_IS_IPV4(trace->dst))
	state->icmp = scamper_fd_icmp4(trace->src->addr);
      else if(SCAMPER_ADDR_TYPE_IS_IPV6(trace->dst))
	state->icmp = scamper_fd_icmp6(trace->src->addr);
      if(state->icmp == NULL)
	goto err;

      if(SCAMPER_TRACE_TYPE_IS_UDP(trace) &&
	 SCAMPER_ADDR_TYPE_IS_IPV4(trace->dst) &&
	 (state->raw = scamper_fd_udp4raw(trace->src->addr)) == NULL)
	goto err;
      else if(SCAMPER_TRACE_TYPE_IS_TCP(trace) &&
	 SCAMPER_ADDR_TYPE_IS_IPV4(trace->dst) &&
	 (trace->flags & SCAMPER_TRACE_FLAG_RAW) != 0 &&
	 (state->raw = scamper_fd_ip4()) == NULL)
	goto err;
    }

  return 0;

 err:
  return -1;
}

static void do_trace_halt(scamper_task_t *task)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace->stop_reason = SCAMPER_TRACE_STOP_HALTED;
  trace_queue_done(task);
  return;
}

static void do_trace_free(scamper_task_t *task)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);

  if(state != NULL)
    trace_state_free(state);
  if(trace != NULL)
    scamper_trace_free(trace);

  return;
}

/*
 * do_trace_probe
 *
 * time to probe, so send the packet.
 */
static void do_trace_probe(scamper_task_t *task)
{
  scamper_probe_ipopt_t opt;
  trace_hop_state_t *hs = NULL;
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t   *state = trace_getstate(task);
  scamper_trace_probe_t *stp = NULL;
  trace_probe_t   *tp = NULL;
  scamper_probe_t  probe;
  struct timeval   tv;
  uint16_t         u16, i;
  size_t           size;

  assert(trace != NULL);
  assert(trace->dst != NULL);
  assert(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4 ||
	 trace->dst->type == SCAMPER_ADDR_TYPE_IPV6);

  if(state == NULL)
    {
      trace_handleerror(task, 0);
      return;
    }

  if(state->icmp != NULL)
    {
      assert(MODE_IS_PARALLEL(state->mode) ||
	     state->attempt < trace->attempts || trace->confidence != 0);
      assert(state->id_next <= state->id_max);
      assert(state->alloc_hops > 0);
      assert(state->alloc_hops <= 256);
      assert(state->ttl != 0);
    }
  else
    {
      /* timestamp when the trace began */
      gettimeofday_wrap(&trace->start);

      /* allocate state and store it with the task */
      if(trace_state_alloc(task) != 0)
	goto err;
      state = trace_getstate(task);
    }

  if(state->mode == MODE_RTSOCK)
    {
      if(trace->rtr == NULL)
	state->route = scamper_route_alloc(trace->dst, task, trace_handle_rt);
      else
	state->route = scamper_route_alloc(trace->rtr, task, trace_handle_rt);
      if(state->route == NULL)
	goto err;

#ifndef _WIN32 /* windows does not have a routing socket */
      if(scamper_rtsock_getroute(state->rtsock, state->route) != 0)
	goto err;
      state->attempt++;
#else
      if(scamper_rtsock_getroute(state->route) != 0)
	goto err;
#endif

      if(scamper_task_queue_isdone(task))
	return;

      if(state->mode == MODE_RTSOCK || state->mode == MODE_DLHDR)
	{
	  gettimeofday_wrap(&tv);
	  timeval_add_tv(&tv, &trace->wait_timeout);
	  scamper_task_queue_wait_tv(task, &tv);
	  return;
	}
    }

  /* allocate some more space to store probes, if necessary */
  if(state->id_next == state->id_max)
    {
      u16  = state->id_max + TRACE_ALLOC_HOPS;
      size = sizeof(trace_probe_t *) * u16;
      if(realloc_wrap((void **)&state->probes, size) != 0)
	{
	  printerror(__func__, "could not realloc");
	  goto err;
	}
      state->id_max = u16;
    }

  /* allocate a larger global txbuf if needed */
  if(txbuf_len < state->payload_size)
    {
      if(realloc_wrap((void **)&txbuf, state->payload_size) != 0)
	{
	  printerror(__func__, "could not realloc");
	  goto err;
	}
      txbuf_len = state->payload_size;
    }

  memset(&probe, 0, sizeof(probe));
  probe.pr_fd        = scamper_fd_fd_get(state->probe);
  probe.pr_ip_src    = trace->src;
  probe.pr_ip_dst    = trace->dst;
  probe.pr_ip_tos    = trace->tos;
  if(state->payload_size > 0)
    {
      probe.pr_len   = state->payload_size;
      probe.pr_data  = txbuf;
    }

  if(MODE_IS_PARALLEL(state->mode))
    {
      if((hs = slist_head_pop(state->para->probeq)) != NULL)
	{
	  /* re-probe an existing hop */
	  assert(hs->attempt < trace->attempts);
	  if(dlist_tail_push(state->para->window, hs) == NULL)
	    {
	      free(hs);
	      printerror(__func__, "could not push trace_hop_state_t");
	      goto err;
	    }
	}
      else
	{
	  /* probe a new hop */
	  assert(state->mode == MODE_PARALLEL);
	  if((hs = malloc_zero(sizeof(trace_hop_state_t))) == NULL ||
	     dlist_tail_push(state->para->window, hs) == NULL)
	    {
	      if(hs != NULL) free(hs);
	      printerror(__func__, "could not push trace_hop_state_t");
	      goto err;
	    }
	  hs->ttl = state->ttl;
	  state->ttl++;
	}

      probe.pr_ip_ttl = hs->ttl;
    }
  else
    {
      probe.pr_ip_ttl = state->ttl;
    }

  if(SCAMPER_TRACE_TYPE_IS_UDP(trace))
    probe.pr_ip_proto = IPPROTO_UDP;
  else if(SCAMPER_TRACE_TYPE_IS_TCP(trace))
    probe.pr_ip_proto = IPPROTO_TCP;
  else if(SCAMPER_TRACE_TYPE_IS_ICMP(trace))
    if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
      probe.pr_ip_proto = IPPROTO_ICMP;
    else
      probe.pr_ip_proto = IPPROTO_ICMPV6;
  else
    goto err;

  if(trace->flags & SCAMPER_TRACE_FLAG_RXERR)
    probe.pr_flags |= SCAMPER_PROBE_FLAG_RXERR;

  /*
   * while the paris traceroute paper says that the payload of the
   * packet is set so that the checksum field can be used to
   * identify a returned probe, the paris traceroute code uses the
   * IP ID field.
   * this is presumably because FreeBSD systems seem to reset the
   * UDP checksum quoted in ICMP destination unreachable messages.
   * scamper's paris traceroute implementation used both IP ID and
   * UDP checksum.
   */
  probe.pr_ip_id = state->id_next + 1;

  if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    probe.pr_ip_off  = IP_DF;

  if(state->dl != NULL &&
     (MODE_IS_PMTUD(state->mode) ||
      trace->offset != 0 ||
      trace->rtr != NULL ||
      (SCAMPER_TRACE_TYPE_IS_UDP_PARIS(trace) && scamper_osinfo_is_sunos()) ||
      (SCAMPER_TRACE_TYPE_IS_UDP_PARIS(trace) &&
       SCAMPER_TRACE_FLAG_IS_CONSTPAYLOAD(trace) &&
       SCAMPER_ADDR_TYPE_IS_IPV6(trace->dst)) ||
      (SCAMPER_TRACE_TYPE_IS_TCP(trace) && state->raw == NULL)))
    {
      probe.pr_dl     = scamper_fd_dl_get(state->dl);
      probe.pr_dlhdr  = state->dlhdr;
    }

  if(trace->payload_len == 0 || MODE_IS_PMTUD(state->mode))
    {
      if(probe.pr_len > 0)
	memset(probe.pr_data, 0, probe.pr_len);
    }
  else
    {
      memcpy(probe.pr_data, trace->payload, trace->payload_len);
    }

  if(trace->offset != 0)
    {
      assert(SCAMPER_ADDR_TYPE_IS_IPV6(trace->dst));
      probe.pr_ip_off = trace->offset;
      probe.pr_ipopts = &opt;
      probe.pr_ipoptc = 1;

      opt.type = SCAMPER_PROBE_IPOPTS_V6FRAG;
      opt.opt_v6frag_off = trace->offset << 3;
      opt.opt_v6frag_id  = (trace->sport << 16) | trace->probec;

      /* use the first 4 bytes of the payload for packet matching */
      bytes_htonl(probe.pr_data, trace->probec);
    }
  else if(SCAMPER_TRACE_TYPE_IS_UDP(trace))
    {
      probe.pr_udp_sport = trace->sport;
      probe.pr_udp_dport = trace->dport;

      /*
       * traditional traceroute identifies probes by varying the UDP
       * destination port number.  UDP-based paris traceroute identifies
       * probes by varying the UDP checksum -- accomplished by manipulating
       * the payload of the packet to get sequential values for the checksum
       */
      if(trace->type == SCAMPER_TRACE_TYPE_UDP)
	{
	  probe.pr_udp_dport += state->id_next;
	}
      else if(SCAMPER_TRACE_FLAG_IS_CONSTPAYLOAD(trace) == 0)
	{
	  /*
	   * hack the checksum to be our id field by setting the checksum
	   * id we want into the packet's body, then calculate the checksum
	   * across the packet, and then set the packet's body to be the
	   * value returned for the checksum.  this effectively swaps two
	   * 16 bit quantities in the packet
	   */
	  bytes_htons(probe.pr_data, state->id_next + 1);
	  if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	    u16 = scamper_udp4_cksum(&probe);
	  else
	    u16 = scamper_udp6_cksum(&probe);
	  memcpy(probe.pr_data, &u16, 2);
	}
      else if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV6)
	probe.pr_ip_flow = state->id_next + 1;

      if(state->raw != NULL)
	probe.pr_fd = scamper_fd_fd_get(state->raw);
    }
  else if(SCAMPER_TRACE_TYPE_IS_ICMP(trace))
    {
      SCAMPER_PROBE_ICMP_ECHO(&probe, trace->sport, state->id_next);

      /*
       * ICMP-based paris traceroute tries to ensure the same path is taken
       * through a load balancer by sending all probes with a constant value
       * for the checksum.  manipulate the payload so this happens.
       */
      if(trace->type == SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS)
	{
	  probe.pr_icmp_sum = htons(trace->dport);
	  u16 = htons(trace->dport);
	  memcpy(probe.pr_data, &u16, 2);
	  if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	    u16 = scamper_icmp4_cksum(&probe);
	  else
	    u16 = scamper_icmp6_cksum(&probe);
	  memcpy(probe.pr_data, &u16, 2);
	}
    }
  else
    {
      assert(SCAMPER_TRACE_TYPE_IS_TCP(trace));

      if(state->raw != NULL)
	probe.pr_fd = scamper_fd_fd_get(state->raw);
      else
	probe.pr_fd = -1;

      probe.pr_tcp_sport = trace->sport;
      probe.pr_tcp_dport = trace->dport;
      probe.pr_tcp_seq   = 0;
      probe.pr_tcp_ack   = 0;
      probe.pr_tcp_win   = 0;

      if(trace->type == SCAMPER_TRACE_TYPE_TCP)
	probe.pr_tcp_flags = TH_SYN;
      else
	probe.pr_tcp_flags = TH_ACK;

      if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV6)
	probe.pr_ip_flow = state->id_next + 1;
    }


  /* allocate some more space in the trace to store replies, if necessary */
  if(MODE_IS_TRACE(state->mode) ||
     MODE_IS_DTREE(state->mode) || MODE_IS_PARALLEL(state->mode))
    {
      if(probe.pr_ip_ttl >= state->alloc_hops)
	{
	  /*
	   * figure out exactly how many hops should be allocated in the
	   * trace structure
	   */
	  u16 = ((probe.pr_ip_ttl / TRACE_ALLOC_HOPS) + 1) * TRACE_ALLOC_HOPS;
	  if(u16 > 256)
	    u16 = 256;
	  assert(u16 > probe.pr_ip_ttl);

	  /* allocate the new hops */
	  if(scamper_trace_hops_alloc(trace, u16) != 0)
	    {
	      printerror(__func__, "could not realloc hops");
	      goto err;
	    }

	  /* initialise the new hops to have null pointers */
	  for(i=state->alloc_hops; i<u16; i++)
	    trace->hops[i] = NULL;
	  state->alloc_hops = u16;
	}

      u16 = probe.pr_ip_ttl-1;
      if(trace->hops[u16] == NULL &&
	 (trace->hops[u16] = scamper_trace_probettl_alloc()) == NULL)
	{
	  printerror(__func__, "could not alloc probettl");
	  goto err;
	}
      if(probe.pr_ip_ttl > trace->hop_count)
	trace->hop_count = probe.pr_ip_ttl;
    }

  /*
   * allocate a trace probe state record before we try and send the probe
   * as there is no point sending something into the wild that we can't
   * record
   */
  if((tp = malloc_zero(sizeof(trace_probe_t))) == NULL ||
     (stp = scamper_trace_probe_alloc()) == NULL)
    {
      printerror(__func__, "could not malloc trace_probe_t");
      goto err;
    }

  /* send the probe */
  if(scamper_probe(&probe) == -1)
    {
      errno = probe.pr_errno;
      goto err;
    }

  /* another probe sent */
  trace->probec++;

  tp->probe = stp;
  timeval_cpy(&tp->probe->tx, &probe.pr_tx);
  tp->probe->ttl = probe.pr_ip_ttl;
  tp->probe->size = probe.pr_len + state->header_size;
  tp->mode = state->mode;
  tp->id = state->id_next;

  if(MODE_IS_PARALLEL(state->mode))
    {
      assert(hs != NULL);
      timeval_cpy(&hs->last_tx, &probe.pr_tx);
      hs->attempt++;
      hs->id = state->id_next;
      stp->id = hs->attempt;
      assert(trace->hop_count + trace->squeries + 1 >= state->ttl);
    }
  else
    {
      state->attempt++;
      stp->id = state->attempt;
    }

  if(MODE_IS_TRACE(state->mode) ||
     MODE_IS_DTREE(state->mode) || MODE_IS_PARALLEL(state->mode))
    {
      u16 = probe.pr_ip_ttl-1;
      if(scamper_trace_probettl_probe_add(trace->hops[u16], stp) != 0)
	goto err;
      tp->flags |= TRACE_PROBE_FLAG_STORED;
    }
  else if(MODE_IS_LASTDITCH(state->mode))
    {
      assert(trace->lastditch != NULL);
      if(scamper_trace_lastditch_probe_add(trace->lastditch, stp) != 0)
	goto err;
      tp->flags |= TRACE_PROBE_FLAG_STORED;
    }
  else if(MODE_IS_PMTUD(state->mode))
    {
      assert(trace->pmtud != NULL);
      if(scamper_trace_pmtud_probe_add(trace->pmtud, stp) != 0)
	goto err;
      tp->flags |= TRACE_PROBE_FLAG_STORED;
    }

  state->probes[state->id_next] = tp;
  state->id_next++;

  timeval_cpy(&state->last_tx, &probe.pr_tx);

  trace_queue(task, &probe.pr_tx);
  return;

 err:
  if(stp != NULL) scamper_trace_probe_free(stp);
  if(tp != NULL) free(tp);
  trace_handleerror(task, errno);
  return;
}

void scamper_do_trace_free(void *data)
{
  scamper_trace_free((scamper_trace_t *)data);
  return;
}

int scamper_do_trace_dtree_lss_clear(char *name)
{
  trace_lss_t *lss, findme;
  findme.name = name;
  if((lss = splaytree_find(lsses, &findme)) == NULL)
    return -1;
  splaytree_empty(lss->tree, (splaytree_free_t)scamper_addr_free);
  return 0;
}

static void do_trace_sigs(scamper_task_t *task)
{
  scamper_trace_t *trace = trace_getdata(task);
  trace_state_t *state = trace_getstate(task);
  scamper_task_sig_t *sig = NULL;
  char errbuf[256];
  size_t errlen = sizeof(errbuf);
  int i;

  /*
   * this function might have already been called if the task was held
   * because its signature overlapped with another task.
   */
  if(state != NULL)
    return;

  /* allocate state for storing fds in */
  if((state = malloc_zero(sizeof(trace_state_t))) == NULL)
    {
      scamper_debug(__func__, "could not malloc state");
      goto err;
    }

  /* declare the signature of the task's probes */
  if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
    {
      scamper_debug(__func__, "could not alloc task signature");
      goto err;
    }
  sig->sig_tx_ip_dst = scamper_addr_use(trace->dst);
  if(trace->src == NULL &&
     (trace->src = scamper_getsrc(trace->dst, 0, errbuf, errlen)) == NULL)
    {
      scamper_debug(__func__, "%s", errbuf);
      goto err;
    }

  /*
   * get the probe socket so that we can get a task signature.  leave
   * the rest for later
   */
  if(scamper_option_icmp_rxerr() != 0)
    {
      if(SCAMPER_TRACE_TYPE_IS_ICMP(trace) &&
	 SCAMPER_ADDR_TYPE_IS_IPV4(trace->dst))
	state->probe = scamper_fd_icmp4err(trace->src->addr);
      else if(SCAMPER_TRACE_TYPE_IS_UDP(trace) &&
	      SCAMPER_ADDR_TYPE_IS_IPV6(trace->dst))
	state->probe = scamper_fd_udp6err_dst(trace->src->addr, trace->sport,
					      NULL, 0,
					      trace->dst->addr, trace->dport);
    }
  else
    {
      if(SCAMPER_TRACE_TYPE_IS_TCP(trace))
	{
	  if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	    state->probe = scamper_fd_tcp4_dst(NULL, trace->sport, NULL, 0,
					       trace->dst->addr, trace->dport);
	  else
	    state->probe = scamper_fd_tcp6_dst(NULL, trace->sport, NULL, 0,
					       trace->dst->addr, trace->dport);
	}
      else if(SCAMPER_TRACE_TYPE_IS_ICMP(trace))
	{
	  if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	    state->probe = scamper_fd_icmp4(trace->src->addr);
	  else
	    state->probe = scamper_fd_icmp6(trace->src->addr);
	}
      else if(SCAMPER_TRACE_TYPE_IS_UDP(trace))
	{
	  if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	    state->probe = scamper_fd_udp4dg_dst(trace->src->addr,
						 trace->sport,
						 NULL, 0,
						 trace->dst->addr,
						 trace->dport);
	  else
	    state->probe = scamper_fd_udp6_dst(trace->src->addr, trace->sport,
					       NULL, 0,
					       trace->dst->addr, trace->dport);
	}
    }

  if(state->probe == NULL)
    {
      scamper_debug(__func__, "could not open probe socket");
      goto err;
    }

  if(trace->sport == 0)
    {
      if(SCAMPER_TRACE_TYPE_IS_UDP(trace) ||
	 SCAMPER_TRACE_TYPE_IS_TCP(trace))
	{
	  if(scamper_fd_sport(state->probe, &trace->sport) != 0)
	    {
	      scamper_debug(__func__, "could not get sport");
	      goto err;
	    }
	}
      else if(SCAMPER_TRACE_TYPE_IS_ICMP(trace))
	{
	  /* try the default ID value to start with */
	  trace->sport = scamper_pid_u16() | 0x8000;
	  SCAMPER_TASK_SIG_ICMP_ECHO(sig, trace->sport);
	  if(scamper_task_find(sig) != NULL)
	    {
	      /*
	       * then try 5 random 16-bit numbers for the ICMP ID
	       * field.  if they all have current tasks, then this
	       * ping will block on the task with the last random
	       * 16-bit ID value.
	       */
	      for(i=0; i<5; i++)
		{
		  random_u16(&trace->sport);
		  SCAMPER_TASK_SIG_ICMP_ECHO(sig, trace->sport);
		  if(scamper_task_find(sig) == NULL)
		    break;
		}
	    }
	}
    }

  switch(trace->type)
    {
    case SCAMPER_TRACE_TYPE_ICMP_ECHO:
    case SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS:
      SCAMPER_TASK_SIG_ICMP_ECHO(sig, trace->sport);
      break;

    case SCAMPER_TRACE_TYPE_UDP:
      SCAMPER_TASK_SIG_UDP_DPORT(sig, trace->sport, 0, 65535);
      break;

    case SCAMPER_TRACE_TYPE_UDP_PARIS:
      SCAMPER_TASK_SIG_UDP(sig, trace->sport, trace->dport);
      break;

    case SCAMPER_TRACE_TYPE_TCP:
    case SCAMPER_TRACE_TYPE_TCP_ACK:
      SCAMPER_TASK_SIG_TCP(sig, trace->sport, trace->dport);
      break;

    default:
      scamper_debug(__func__, "unhandled type %d", trace->type);
      goto err;
    }

  if(scamper_task_sig_add(task, sig) != 0)
    {
      scamper_debug(__func__, "could not add signature to task");
      goto err;
    }
  sig = NULL;

  scamper_task_setstate(task, state);
  return;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  if(state != NULL) trace_state_free(state);
  return;
}

/*
 * scamper_do_trace_alloctask
 *
 */
scamper_task_t *scamper_do_trace_alloctask(void *data,
					   scamper_list_t *list,
					   scamper_cycle_t *cycle,
					   char *errbuf, size_t errlen)
{
  scamper_trace_t *trace = (scamper_trace_t *)data;
  scamper_task_t *task = NULL;

  /* allocate a task structure and store the trace with it */
  if((task = scamper_task_alloc(trace, &trace_funcs)) == NULL)
    {
      snprintf(errbuf, errlen, "%s: could not alloc task", __func__);
      return NULL;
    }

  /* associate the list and cycle with the trace */
  trace->list = scamper_list_use(list);
  trace->cycle = scamper_cycle_use(cycle);

  return task;
}

int scamper_do_trace_enabled(void)
{
  return config->trace_enable;
}

uint32_t scamper_do_trace_userid(void *data)
{
  return ((scamper_trace_t *)data)->userid;
}

void scamper_do_trace_cleanup(void)
{
  if(lsses != NULL)
    {
      splaytree_free(lsses, (splaytree_free_t)trace_lss_free);
      lsses = NULL;
    }

  return;
}

int scamper_do_trace_init(void)
{
  trace_funcs.probe          = do_trace_probe;
  trace_funcs.handle_icmp    = do_trace_handle_icmp;
  trace_funcs.handle_dl      = do_trace_handle_dl;
  trace_funcs.handle_timeout = do_trace_handle_timeout;
  trace_funcs.write          = do_trace_write;
  trace_funcs.task_free      = do_trace_free;
  trace_funcs.halt           = do_trace_halt;
  trace_funcs.sigs           = do_trace_sigs;

  return 0;
}
