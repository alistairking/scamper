/*
 * scamper_do_dealias.c
 *
 * $Id: scamper_dealias_do.c,v 1.199 2024/03/04 19:36:41 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012-2013 Matthew Luckie
 * Copyright (C) 2012-2014 The Regents of the University of California
 * Copyright (C) 2016-2023 Matthew Luckie
 * Copyright (C) 2023-2024 The Regents of the University of California
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
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_dealias.h"
#include "scamper_dealias_int.h"
#include "scamper_task.h"
#include "scamper_icmp_resp.h"
#include "scamper_fds.h"
#include "scamper_dl.h"
#include "scamper_dlhdr.h"
#include "scamper_rtsock.h"
#include "scamper_probe.h"
#include "scamper_getsrc.h"
#include "scamper_udp4.h"
#include "scamper_udp6.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_debug.h"
#include "scamper_dealias_do.h"
#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "utils.h"

static scamper_task_funcs_t funcs;

/* packet buffer for generating the payload of each packet */
static uint8_t             *pktbuf     = NULL;
static size_t               pktbuf_len = 0;

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

typedef struct dealias_target
{
  scamper_addr_t              *addr;
  dlist_t                     *probes;
  uint16_t                     tcp_sport;
  uint16_t                     udp_dport;
} dealias_target_t;

typedef struct dealias_probe
{
  dealias_target_t            *target;
  scamper_dealias_probe_t     *probe;
  uint16_t                     match_field;
  dlist_node_t                *target_node;
} dealias_probe_t;

typedef struct dealias_prefixscan
{
  scamper_dealias_probedef_t  *probedefs;
  uint32_t                     probedefc;
  scamper_addr_t             **aaliases;
  size_t                       aaliasc;
  int                          attempt;
  int                          seq;
  int                          round0;
  int                          round;
  int                          replyc;
} dealias_prefixscan_t;

typedef struct dealias_radargun
{
  uint32_t                    *order; /* probedef order */
  uint32_t                     i;     /* index into order */
  struct timeval               next_round;
} dealias_radargun_t;

typedef struct dealias_bump
{
  uint8_t                      step;
  uint8_t                      attempt;
  uint16_t                     bump;
} dealias_bump_t;

typedef struct dealias_midarest
{
  uint32_t                    *order; /* probedef order */
  uint32_t                     i;     /* index into order */
  uint32_t                     addrc; /* number of unique addresses */
  struct timeval               next_round;
} dealias_midarest_t;

typedef struct dealias_midardisc
{
  struct timeval               start;  /* time this [should've] started */
  struct timeval               finish; /* time for this round to complete */
} dealias_midardisc_t;

typedef struct dealias_probedef
{
  scamper_dealias_probedef_t  *def;
  dealias_target_t            *target;
  uint32_t                     tcp_seq;
  uint32_t                     tcp_ack;
  uint16_t                     pktbuf_len;
  uint8_t                      flags;
  uint8_t                      echo;
} dealias_probedef_t;

typedef struct dealias_ptb
{
  scamper_dealias_probedef_t  *def;
  uint8_t                     *quote;
  uint16_t                     quote_len;
} dealias_ptb_t;

typedef struct dealias_state
{
  uint8_t                      id;
  uint8_t                      flags;
  uint16_t                     icmpseq;
  scamper_dealias_probedef_t **probedefs;
  uint32_t                     probedefc;
  dealias_probedef_t         **pds;
  size_t                       pdc;
  uint32_t                     probe;
  uint32_t                     round;
  struct timeval               last_tx;
  struct timeval               next_tx;
  struct timeval               ptb_tx;
  splaytree_t                 *targets;
  dlist_t                     *recent_probes;
  void                        *methodstate;
  slist_t                     *ptbq;
  slist_t                     *discard;
} dealias_state_t;

#define DEALIAS_STATE_FLAG_DL 0x01

#define DEALIAS_PROBEDEF_FLAG_RX_IPID 0x01
#define DEALIAS_PROBEDEF_FLAG_TX_PTB  0x02

#ifdef NDEBUG
#define dealias_state_assert(state) ((void)0)
#endif

#ifndef NDEBUG
static void dealias_state_assert(const dealias_state_t *state)
{
  size_t i;
  if(state == NULL)
    return;
  for(i=0; i<state->pdc; i++)
    {
      assert(state->pds[i] != NULL);
      assert(state->pds[i]->def->id == (uint32_t)i);
    }
  return;
}
#endif

static scamper_dealias_t *dealias_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static dealias_state_t *dealias_getstate(const scamper_task_t *task)
{
  dealias_state_t *state = scamper_task_getstate(task);
  dealias_state_assert(state);
  return state;
}

static int dealias_ally_queue(const scamper_dealias_t *dealias,
			      dealias_state_t *state,
			      const struct timeval *now, struct timeval *tv)
{
  if(state->ptb_tx.tv_sec == 0)
    return 0;
  timeval_add_s(tv, &state->ptb_tx, 1);
  if(timeval_cmp(tv, now) > 0)
    return 1;
  memset(&state->ptb_tx, 0, sizeof(struct timeval));
  return 0;
}

static void dealias_queue(scamper_task_t *task)
{
  static int (*const func[])(const scamper_dealias_t *, dealias_state_t *,
			     const struct timeval *, struct timeval *) = {
    NULL, /* mercator */
    dealias_ally_queue,
    NULL, /* radargun */
    NULL, /* prefixscan */
    NULL, /* bump */
    NULL, /* midarest */
    NULL, /* midardisc */
  };
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  struct timeval tv, now;
  dealias_probe_t *p;

  if(scamper_task_queue_isdone(task))
    return;

  gettimeofday_wrap(&now);

  for(;;)
    {
      if((p = dlist_head_item(state->recent_probes)) == NULL)
	break;
      timeval_add_s(&tv, &p->probe->tx, 10);
      if(timeval_cmp(&now, &tv) < 0)
	break;
      dlist_node_pop(p->target->probes, p->target_node);
      dlist_head_pop(state->recent_probes);
      free(p);
    }

  if(slist_count(state->ptbq) > 0)
    {
      scamper_task_queue_probe(task);
      return;
    }

  if(func[dealias->method-1] != NULL &&
     func[dealias->method-1](dealias, state, &now, &tv) != 0)
    {
      scamper_task_queue_wait_tv(task, &tv);
      return;
    }

  if(timeval_cmp(&state->next_tx, &now) <= 0)
    {
      scamper_task_queue_probe(task);
      return;
    }

  scamper_task_queue_wait_tv(task, &state->next_tx);
  return;
}

static void dealias_handleerror(scamper_task_t *task, int error)
{
  scamper_task_queue_done(task, 0);
  return;
}

static void dealias_result(scamper_task_t *task, uint8_t result)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
#ifdef HAVE_SCAMPER_DEBUG
  char buf[16];
#endif

  dealias->result = result;

#ifdef HAVE_SCAMPER_DEBUG
  scamper_debug(__func__, "%s",
		scamper_dealias_result_tostr(result, buf, sizeof(buf)));
#endif

  scamper_task_queue_done(task, 0);
  return;
}

static void dealias_ptb_free(dealias_ptb_t *ptb)
{
  if(ptb == NULL)
    return;
  if(ptb->quote != NULL)
    free(ptb->quote);
  free(ptb);
  return;
}

static int dealias_ptb_add(dealias_state_t *state, scamper_dl_rec_t *dl,
			   scamper_dealias_probedef_t *def)
{
  dealias_ptb_t *ptb;

  if((ptb = malloc_zero(sizeof(dealias_ptb_t))) == NULL)
    {
      printerror(__func__, "could not malloc ptb");
      goto err;
    }
  ptb->def = def;
  if(dl->dl_ip_size > 1280-40-8)
    ptb->quote_len = 1280-40-8;
  else
    ptb->quote_len = dl->dl_ip_size;
  if((ptb->quote = memdup(dl->dl_net_raw, ptb->quote_len)) == NULL)
    {
      printerror(__func__, "could not dup ptb quote");
      goto err;
    }

  if(slist_tail_push(state->ptbq, ptb) == NULL)
    {
      printerror(__func__, "could not queue ptb");
      goto err;
    }

  return 0;
 err:
  if(ptb != NULL) dealias_ptb_free(ptb);
  return -1;
}

static int dealias_target_cmp(const dealias_target_t *a,
			      const dealias_target_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static void dealias_target_free(dealias_target_t *tgt)
{
  if(tgt == NULL)
    return;
  if(tgt->probes != NULL)
    dlist_free_cb(tgt->probes, free);
  if(tgt->addr != NULL)
    scamper_addr_free(tgt->addr);
  free(tgt);
  return;
}

static dealias_target_t *dealias_target_find(dealias_state_t *s,
					     scamper_addr_t *addr)
{
  dealias_target_t fm;
  fm.addr = addr;
  return splaytree_find(s->targets, &fm);
}

static dealias_target_t *dealias_target_get(dealias_state_t *state,
					    scamper_addr_t *addr)
{
  dealias_target_t *tgt;
  if((tgt = dealias_target_find(state, addr)) != NULL)
    return tgt;
  if((tgt = malloc_zero(sizeof(dealias_target_t))) == NULL ||
     (tgt->probes = dlist_alloc()) == NULL)
    goto err;
  tgt->addr = scamper_addr_use(addr);
  if(splaytree_insert(state->targets, tgt) == NULL)
    goto err;
  return tgt;

 err:
  dealias_target_free(tgt);
  return NULL;
}

static int dealias_probedef_add(dealias_state_t *state,
				scamper_dealias_probedef_t *def,
				char *errbuf, size_t errlen)
{
  dealias_probedef_t *pd = NULL;
  uint16_t hl;

  /* compute the size of the headers */
  if(SCAMPER_ADDR_TYPE_IS_IPV4(def->dst))
    hl = 20; /* sizeof ipv4 hdr */
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(def->dst))
    hl = 40; /* sizeof ipv6 hdr */
  else
    {
      snprintf(errbuf, errlen, "%s: invalid def->dst", __func__);
      return -1;
    }
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def) ||
     SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    hl += 8; /* sizeof udp/icmp hdr */
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    hl += 20; /* sizeof tcp hdr */
  else
    {
      snprintf(errbuf, errlen, "%s: unknown probedef proto", __func__);
      return -1;
    }

  if((pd = malloc_zero(sizeof(dealias_probedef_t))) == NULL)
    {
      snprintf(errbuf, errlen, "%s: could not malloc pd", __func__);
      goto err;
    }
  pd->def = def;
  if((pd->target = dealias_target_get(state, def->dst)) == NULL)
    {
      snprintf(errbuf, errlen, "%s: could not add target state", __func__);
      goto err;
    }

  /* ensure the probedef size is at least as large as the required headers */
  if(def->size < hl)
    {
      snprintf(errbuf, errlen, "%s: def->size %u < hl %u", __func__, def->size, hl);
      goto err;
    }
  pd->pktbuf_len = def->size - hl;

  if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK &&
     (random_u32(&pd->tcp_seq) != 0 || random_u32(&pd->tcp_ack) != 0))
    {
      snprintf(errbuf, errlen, "%s: could not get random TCP seq/ack", __func__);
      goto err;
    }

  if(array_insert((void ***)&state->pds, &state->pdc, pd, NULL) != 0)
    {
      snprintf(errbuf, errlen, "%s: could not add pd", __func__);
      goto err;
    }

  return 0;

 err:
  if(pd != NULL) free(pd);
  return -1;
}

static void dealias_prefixscan_array_free(scamper_addr_t **addrs, int addrc)
{
  int i;

  if(addrs == NULL)
    return;

  for(i=0; i<addrc; i++)
    if(addrs[i] != NULL)
      scamper_addr_free(addrs[i]);

  free(addrs);
  return;
}

static int dealias_prefixscan_array_add(scamper_dealias_t *dealias,
					scamper_addr_t ***out, size_t *outc,
					struct in_addr *addr)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_addr_t **array = *out;
  scamper_addr_t *sa;

  /* convert the in_addr into something that scamper deals with */
  sa = scamper_addrcache_get(addrcache, SCAMPER_ADDR_TYPE_IPV4, addr);
  if(sa == NULL)
    {
      printerror(__func__, "could not get addr");
      return -1;
    }

  /*
   * don't consider this address if it is the same as the address
   * we are trying to find an alias for, or it is in the exclude list.
   */
  if(scamper_addr_cmp(prefixscan->a, sa) == 0 ||
     scamper_dealias_prefixscan_xs_in(dealias, sa) != 0)
    {
      scamper_addr_free(sa);
      return 0;
    }

  /* add the scamper address to the array */
  if(array_insert((void ***)&array, outc, sa, NULL) != 0)
    {
      printerror(__func__, "could not add addr");
      scamper_addr_free(sa);
      return -1;
    }

  *out = array;
  return 0;
}

/*
 * dealias_prefixscan_array:
 *
 * figure out what the next address to scan will be, based on what the
 * previously probed address was.  below are examples of the order in which
 * addresses should be probed given a starting address.  addresses in
 * prefixes less than /30 could be probed in random order.
 *
 * 00100111 39        00100010 34        00101001 41       00100000 32
 * 00100110 38 /31    00100001 33        00101010 42       00100001 33 /31
 * 00100101 37        00100000 32        00101000 40       00100010 34
 * 00100100 36 /30    00100011 35 /30    00101011 43 /30   00100011 35 /30
 * 00100011 35        00100100 36        00101100 44
 * 00100010 34        00100101 37        00101101 45
 * 00100001 33        00100110 38        00101110 46
 * 00100000 32 /29    00100111 39 /29    00101111 47 /29
 * 00101000 40        00101000 40        00100000 32
 * 00101001 41        00101001 41        00100001 33
 * 00101010 42        00101010 42
 * 00101011 43
 * 00101100 44
 * 00101101 45
 * 00101110 46
 * 00101111 47 /28
 *
 */
static int dealias_prefixscan_array(scamper_dealias_t *dealias,
				    scamper_addr_t ***out, size_t *outc)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_addr_t **array = NULL;
  uint32_t hostid, netid, mask;
  uint32_t slash30[4][3] = {{1, 2, 3}, {2, 0, 3}, {1, 0, 3}, {2, 1, 0}};
  uint32_t cnt[] = {4, 8, 16, 32, 64, 128};
  uint32_t bit;
  struct in_addr a;
  int pre, i;

  memcpy(&a, prefixscan->b->addr, sizeof(a));
  *outc = 0;

  /* if we've been instructed only to try /31 pair */
  if(prefixscan->prefix == 31)
    {
      netid  = ntohl(a.s_addr) & ~0x1;
      hostid = ntohl(a.s_addr) &  0x1;

      if(hostid == 1)
	a.s_addr = htonl(netid | 0);
      else
	a.s_addr = htonl(netid | 1);

      if(dealias_prefixscan_array_add(dealias, &array, outc, &a) != 0)
	goto err;

      *out = array;
      return 0;
    }

  /* when probing a /30 the first three probes have a particular order */
  mask   = 0x3;
  netid  = ntohl(a.s_addr) & ~mask;
  hostid = ntohl(a.s_addr) &  mask;
  for(i=0; i<3; i++)
    {
      a.s_addr = htonl(netid | slash30[hostid][i]);
      if(dealias_prefixscan_array_add(dealias, &array, outc, &a) != 0)
	goto err;
    }

  for(pre = 29; pre >= prefixscan->prefix; pre--)
    {
      bit   = (0x1 << (31-pre));
      mask |= bit;

      memcpy(&a, prefixscan->b->addr, sizeof(a));
      netid = ntohl(a.s_addr) & ~mask;

      if((ntohl(a.s_addr) & bit) != 0)
	bit = 0;

      for(hostid=0; hostid<cnt[29-pre]; hostid++)
	{
	  a.s_addr = htonl(netid | bit | hostid);
	  if(dealias_prefixscan_array_add(dealias, &array, outc, &a) != 0)
	    goto err;
	}
    }

  *out = array;
  return 0;

 err:
  dealias_prefixscan_array_free(array, *outc);
  return -1;
}

static scamper_dealias_probe_t *
dealias_probe_udp_find(dealias_state_t *state, dealias_target_t *tgt,
		       uint16_t ipid, uint16_t sport, uint16_t dport)
{
  scamper_dealias_probedef_t *def;
  dealias_probe_t *dp;
  dlist_node_t *n;

  for(n=dlist_head_node(tgt->probes); n != NULL; n = dlist_node_next(n))
    {
      dp = dlist_node_item(n); def = dp->probe->def;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def) == 0 ||
	 def->un.udp.sport != sport)
	continue;
      if(SCAMPER_ADDR_TYPE_IS_IPV4(tgt->addr) && dp->probe->ipid != ipid)
	continue;

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP)
	{
	  if(def->un.udp.dport == dport)
	    return dp->probe;
	}
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT)
	{
	  if(dp->match_field == dport)
	    return dp->probe;
	}
    }

  return NULL;
}

static scamper_dealias_probe_t *
dealias_probe_tcp_find2(dealias_state_t *state, dealias_target_t *tgt,
			uint16_t sport, uint16_t dport)
{
  scamper_dealias_probedef_t *def;
  dealias_probe_t *dp;
  dlist_node_t *n;

  for(n=dlist_head_node(tgt->probes); n != NULL; n = dlist_node_next(n))
    {
      dp = dlist_node_item(n); def = dp->probe->def;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def) == 0 ||
	 def->un.tcp.dport != dport)
	continue;

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	{
	  if(def->un.tcp.sport == sport)
	    return dp->probe;
	}
      else if(SCAMPER_DEALIAS_PROBEDEF_VARY_TCP_SPORT(def))
	{
	  if(dp->match_field == sport)
	    return dp->probe;
	}
    }

  return NULL;
}

static scamper_dealias_probe_t *
dealias_probe_tcp_find(dealias_state_t *state, dealias_target_t *tgt,
		       uint16_t ipid, uint16_t sport, uint16_t dport)
{
  scamper_dealias_probedef_t *def;
  dealias_probe_t *dp;
  dlist_node_t *n;

  for(n=dlist_head_node(tgt->probes); n != NULL; n = dlist_node_next(n))
    {
      dp = dlist_node_item(n); def = dp->probe->def;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def) == 0 ||
	 def->un.tcp.dport != dport)
	continue;
      if(SCAMPER_ADDR_TYPE_IS_IPV4(tgt->addr) && dp->probe->ipid != ipid)
	continue;

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	{
	  if(def->un.tcp.sport == sport)
	    return dp->probe;
	}
      else if(SCAMPER_DEALIAS_PROBEDEF_VARY_TCP_SPORT(def))
	{
	  if(dp->match_field == sport)
	    return dp->probe;
	}
    }

  return NULL;
}

static scamper_dealias_probe_t *
dealias_probe_icmp_find(dealias_state_t *state, dealias_target_t *tgt,
			uint16_t ipid, uint8_t type, uint8_t code,
			uint16_t id, uint16_t seq)
{
  scamper_dealias_probedef_t *def;
  dealias_probe_t *dp;
  dlist_node_t *n;
  uint8_t method;

  if((SCAMPER_ADDR_TYPE_IS_IPV4(tgt->addr) &&
      type == ICMP_ECHO && code == 0) ||
     (SCAMPER_ADDR_TYPE_IS_IPV6(tgt->addr) &&
      type == ICMP6_ECHO_REQUEST && code == 0))
    method = SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO;
  else
    return NULL;

  for(n=dlist_head_node(tgt->probes); n != NULL; n = dlist_node_next(n))
    {
      dp = dlist_node_item(n); def = dp->probe->def;
      if(SCAMPER_ADDR_TYPE_IS_IPV4(tgt->addr) && dp->probe->ipid != ipid)
	continue;
      if(def->method == method &&
	 def->un.icmp.id == id && dp->match_field == seq)
	return dp->probe;
    }

  return NULL;
}

static scamper_dealias_probe_t *
dealias_probe_echoreq_find(dealias_state_t *state, dealias_target_t *tgt,
			   uint16_t id, uint16_t seq)
{
  scamper_dealias_probedef_t *def;
  dealias_probe_t *dp;
  dlist_node_t *n;

  for(n=dlist_head_node(tgt->probes); n != NULL; n = dlist_node_next(n))
    {
      dp = dlist_node_item(n); def = dp->probe->def;
      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO &&
	 def->un.icmp.id == id && dp->match_field == seq)
	return dp->probe;
    }

  return NULL;
}

static dealias_probedef_t *
dealias_mercator_def(scamper_dealias_t *dealias, dealias_state_t *state)
{
  return state->pds[state->probe];
}

static int dealias_mercator_postprobe(scamper_dealias_t *dealias,
				      dealias_state_t *state)
{
  /* we just wait the specified number of seconds with mercator probes */
  scamper_dealias_mercator_t *mercator = dealias->data;
  timeval_add_tv3(&state->next_tx, &state->last_tx, &mercator->wait_timeout);
  state->round++;
  return 0;
}

static void dealias_mercator_handlereply(scamper_task_t *task,
					 scamper_dealias_probe_t *probe,
					 scamper_dealias_reply_t *reply,
					 scamper_dl_rec_t *dl)
{
  if(SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH_PORT(reply) &&
     scamper_addr_cmp(probe->def->dst, reply->src) != 0)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
    }
  else
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
    }
  return;
}

static void dealias_mercator_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t          *dealias  = dealias_getdata(task);
  scamper_dealias_mercator_t *mercator = dealias->data;

  if(dealias->probec < mercator->attempts)
    dealias_queue(task);
  else
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);

  return;
}

static dealias_probedef_t *
dealias_ally_def(scamper_dealias_t *dealias, dealias_state_t *state)
{
  return state->pds[state->probe];
}

static int dealias_ally_postprobe(scamper_dealias_t *dealias,
				  dealias_state_t *state)
{
  /*
   * we wait a fixed amount of time before we send the next probe with
   * ally.  except when the last probe has been sent, where we wait for
   * some other length of time for any final replies to come in
   */
  scamper_dealias_ally_t *ally = dealias->data;
  if(dealias->probec != ally->attempts)
    timeval_add_tv3(&state->next_tx, &state->last_tx, &ally->wait_probe);
  else
    timeval_add_tv3(&state->next_tx, &state->last_tx, &ally->wait_timeout);
  if(++state->probe == 2)
    {
      state->probe = 0;
      state->round++;
    }
  return 0;
}

static int dealias_ally_allzero(scamper_dealias_t *dealias)
{
  uint32_t i;
  uint16_t j;

  if(dealias->probec == 0)
    return 0;
  if(SCAMPER_ADDR_TYPE_IS_IPV4(dealias->probes[0]->def->dst) == 0)
    return 0;

  for(i=0; i<dealias->probec; i++)
    {
      assert(dealias->probes[i] != NULL);
      for(j=0; j<dealias->probes[i]->replyc; j++)
	{
	  assert(dealias->probes[i]->replies[j] != NULL);
	  if(dealias->probes[i]->replies[j]->ipid != 0)
	    return 0;
	}
    }

  return 1;
}

/*
 * dealias_ally_handlereply_v6
 *
 * process the IPv6 response and signal to the caller what to do next.
 *
 * -1: error, stop probing now.
 *  0: response is not useful, don't process the packet.
 *  1: useful response, continue processing.
 */
static int dealias_ally_handlereply_v6(scamper_task_t *task,
				       scamper_dealias_probe_t *probe,
				       scamper_dealias_reply_t *reply,
				       scamper_dl_rec_t *dl)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  dealias_probedef_t *pd = state->pds[probe->def->id];
  slist_node_t *sn;
  int ptb = 0, discard = 0;
  uint32_t i;

  /* are we in a period where we're waiting for the receiver to get the PTB? */
  if(state->ptb_tx.tv_sec != 0 || slist_count(state->ptbq) > 0)
    ptb = 1;

  /* is the probe going to be discarded? */
  for(sn=slist_head_node(state->discard); sn != NULL; sn=slist_node_next(sn))
    {
      if(slist_node_item(sn) == probe)
	{
	  discard = 1;
	  break;
	}
    }

  /* if the response contains an IP-ID, then we're good for this def */
  if((reply->flags & SCAMPER_DEALIAS_REPLY_FLAG_IPID32) != 0)
    {
      pd->flags |= DEALIAS_PROBEDEF_FLAG_RX_IPID;
      return (discard == 0 && ptb == 0) ? 1 : 0;
    }

  /* should we send a packet too big for this packet? */
  if(probe->def->mtu != 0 && probe->def->mtu < dl->dl_ip_size &&
     (pd->flags & DEALIAS_PROBEDEF_FLAG_TX_PTB) == 0 &&
     (pd->flags & DEALIAS_PROBEDEF_FLAG_RX_IPID) == 0)
    {
      /* all prior probes are going to be discarded, so put them in the list */
      for(i=0; i<dealias->probec; i++)
	{
	  if(slist_head_push(state->discard, dealias->probes[i]) == NULL)
	    return -1;
	  dealias->probes[i] = NULL;
	}
      dealias->probec = 0;
      state->round = 0;

      /* send a PTB */
      pd->flags |= DEALIAS_PROBEDEF_FLAG_TX_PTB;
      if(dealias_ptb_add(state, dl, probe->def) != 0)
	return -1;
      dealias_queue(task);
      return 0;
    }

  /* if we're probing for real and the response is not useful, halt */
  if(ptb == 0 && discard == 0)
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);

  return 0;
}

static void dealias_ally_handlereply(scamper_task_t *task,
				     scamper_dealias_probe_t *probe,
				     scamper_dealias_reply_t *reply,
				     scamper_dl_rec_t *dl)
{
  scamper_dealias_t       *dealias = dealias_getdata(task);
  scamper_dealias_ally_t  *ally    = dealias->data;
  scamper_dealias_probe_t *probes[5];
  uint32_t k;
  int rc, probec = 0;

  /* check to see if the response could be useful for alias resolution */
  if(probe->replyc != 1 ||
     !(SCAMPER_DEALIAS_REPLY_FROM_TARGET(probe, reply) ||
       (SCAMPER_DEALIAS_REPLY_IS_ICMP_TTL_EXP(reply) &&
	probe->def->ttl != 255)))
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  if(SCAMPER_ADDR_TYPE_IS_IPV6(reply->src))
    {
      rc = dealias_ally_handlereply_v6(task, probe, reply, dl);
      if(rc == -1) goto err;
      if(rc == 0) return;
    }

  /* can't make any decision unless at least two probes have been sent */
  if(dealias->probec < 2)
    return;

  /* find the probe in its place */
  for(k=0; k<dealias->probec; k++)
    if(probe == dealias->probes[k])
      break;
  if(k == dealias->probec)
    return;

  if(k >= 1 && dealias->probes[k-1]->replyc == 1)
    {
      if(k >= 2 && dealias->probes[k-2]->replyc == 1)
	probes[probec++] = dealias->probes[k-2];
      probes[probec++] = dealias->probes[k-1];
    }
  probes[probec++] = dealias->probes[k];
  if(k+1 < dealias->probec && dealias->probes[k+1]->replyc == 1)
    {
      probes[probec++] = dealias->probes[k+1];
      if(k+2 < dealias->probec && dealias->probes[k+2]->replyc == 1)
	probes[probec++] = dealias->probes[k+2];
    }

  /* not enough adjacent responses to make a classification */
  if(probec < 2)
    return;

  /* check if the replies are in sequence */
  if(SCAMPER_DEALIAS_ALLY_IS_NOBS(ally))
    rc = scamper_dealias_ipid_inseq(probes, probec, ally->fudge, 0);
  else
    rc = scamper_dealias_ipid_inseq(probes, probec, ally->fudge, 2);
  if(rc == 0)
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NOTALIASES);

  return;

 err:
  dealias_handleerror(task, errno);
  return;
}

static void dealias_ally_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t      *dealias = dealias_getdata(task);
  scamper_dealias_ally_t *ally    = dealias->data;
  uint32_t k;
  int rc;

  /* do a final classification */
  if(dealias->probec == ally->attempts)
    {
      for(k=0; k<dealias->probec; k++)
	if(dealias->probes[k]->replyc != 1)
	  break;

      if(k != dealias->probec)
	{
	  dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
	  return;
	}

      if(SCAMPER_DEALIAS_ALLY_IS_NOBS(ally))
	rc = scamper_dealias_ipid_inseq(dealias->probes, k, ally->fudge, 0);
      else
	rc = scamper_dealias_ipid_inseq(dealias->probes, k, ally->fudge, 3);

      /* check if the replies are in sequence */
      if(rc == 1)
	dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
      else if(dealias_ally_allzero(dealias) != 0)
	dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      else
	dealias_result(task, SCAMPER_DEALIAS_RESULT_NOTALIASES);
    }

  return;
}

static dealias_probedef_t *
dealias_radargun_def(scamper_dealias_t *dealias, dealias_state_t *state)
{
  scamper_dealias_radargun_t *rg = dealias->data;
  dealias_radargun_t *rgstate = state->methodstate;
  if((rg->flags & SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE) == 0)
    return state->pds[state->probe];
  return state->pds[rgstate->order[rgstate->i++]];
}

static int dealias_radargun_postprobe(scamper_dealias_t *dealias,
				      dealias_state_t *state)
{
  scamper_dealias_radargun_t *rg = dealias->data;
  dealias_radargun_t *rgstate = state->methodstate;

  if(state->probe == 0)
    timeval_add_tv3(&rgstate->next_round, &state->last_tx, &rg->wait_round);

  state->probe++;
  timeval_add_tv3(&state->next_tx, &state->last_tx, &rg->wait_probe);

  /* this round is not finished */
  if(state->probe < rg->probedefc)
    return 0;

  /* finished a round, onto the next one */
  state->probe = 0;
  state->round++;

  /* check if we just sent the last probe for the last round */
  if(state->round >= rg->rounds)
    {
      timeval_add_tv3(&state->next_tx, &state->last_tx, &rg->wait_timeout);
      return 0;
    }

  /* wait until the next round may begin, if that is further off */
  if(timeval_cmp(&state->next_tx, &rgstate->next_round) < 0)
    timeval_cpy(&state->next_tx, &rgstate->next_round);

  /* shuffle if requested to */
  if((rg->flags & SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE) != 0)
    {
      if(shuffle32(rgstate->order, rg->probedefc) != 0)
	return -1;
      rgstate->i = 0;
    }

  return 0;
}

static void dealias_radargun_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t          *dealias  = dealias_getdata(task);
  dealias_state_t            *state    = dealias_getstate(task);
  scamper_dealias_radargun_t *radargun = dealias->data;

  /* check to see if we are now finished */
  if(state->round != radargun->rounds)
    dealias_queue(task);
  else
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);

  return;
}

static void dealias_radargun_handlereply(scamper_task_t *task,
					 scamper_dealias_probe_t *probe,
					 scamper_dealias_reply_t *reply,
					 scamper_dl_rec_t *dl)
{
  dealias_state_t *state = dealias_getstate(task);
  if(SCAMPER_ADDR_TYPE_IS_IPV6(probe->def->dst) &&
     (reply->flags & SCAMPER_DEALIAS_REPLY_FLAG_IPID32) == 0 &&
     probe->def->mtu != 0 && probe->def->mtu < dl->dl_ip_size)
    {
      if(dealias_ptb_add(state, dl, probe->def) != 0)
	dealias_handleerror(task, errno);
      else
	dealias_queue(task);
    }
  return;
}

static dealias_probedef_t *
dealias_prefixscan_def(scamper_dealias_t *dealias, dealias_state_t *state)
{
  return state->pds[state->probe];
}

static int dealias_prefixscan_postprobe(scamper_dealias_t *dealias,
					dealias_state_t *state)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  dealias_prefixscan_t *pfstate = state->methodstate;
  scamper_dealias_probedef_t *def = state->probedefs[state->probe];

  if(def->id == 0)
    pfstate->round0++;
  else
    pfstate->round++;
  pfstate->attempt++;
  pfstate->replyc = 0;
  timeval_add_tv3(&state->next_tx, &state->last_tx, &prefixscan->wait_probe);

  return 0;
}

static int dealias_prefixscan_next(scamper_task_t *task)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  dealias_prefixscan_t *pfstate = state->methodstate;
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_dealias_probedef_t *def = &pfstate->probedefs[state->probedefc-1];
  uint32_t *defids = NULL, p;
  char errbuf[256];
  size_t q;

  /*
   * if the address we'd otherwise probe has been observed as an alias of
   * prefixscan->a, then we don't need to bother probing it.
   */
  if(array_find((void **)pfstate->aaliases, pfstate->aaliasc, def->dst,
		(array_cmp_t)scamper_addr_cmp) != NULL)
    {
      prefixscan->ab = scamper_addr_use(def->dst);
      prefixscan->flags |= SCAMPER_DEALIAS_PREFIXSCAN_FLAG_CSA;
      dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
      return 0;
    }

  /* remember the probedef used with each probe */
  if((defids = malloc_zero(sizeof(uint32_t) * dealias->probec)) == NULL)
    {
      printerror(__func__, "could not malloc defids");
      goto err;
    }
  for(p=0; p<dealias->probec; p++)
    defids[p] = dealias->probes[p]->def->id;

  /* add the probedef */
  if(scamper_dealias_prefixscan_probedef_add(dealias, def) != 0)
    {
      printerror(__func__, "could not add probedef");
      goto err;
    }

  /* re-set the pointers to the probedefs */
  for(q=0; q<state->pdc; q++)
    state->pds[q]->def = prefixscan->probedefs[q];
  for(p=0; p<dealias->probec; p++)
    dealias->probes[p]->def = prefixscan->probedefs[defids[p]];
  free(defids); defids = NULL;

  def = prefixscan->probedefs[prefixscan->probedefc-1];
  if(dealias_probedef_add(state, def, errbuf, sizeof(errbuf)) != 0)
    {
      printerror_msg(__func__, "%s", errbuf);
      goto err;
    }

  state->probedefs = prefixscan->probedefs;
  state->probedefc = prefixscan->probedefc;

  return 0;

 err:
  if(defids != NULL) free(defids);
  return -1;
}

static void dealias_prefixscan_handlereply(scamper_task_t *task,
					   scamper_dealias_probe_t *probe,
					   scamper_dealias_reply_t *reply,
					   scamper_dl_rec_t *dl)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  dealias_prefixscan_t *pfstate = state->methodstate;
  scamper_dealias_probe_t **probes = NULL;
  dealias_probedef_t *pd = state->pds[probe->def->id];
  uint32_t defid;
  int p, s, seq;

  /* if the reply is not for the most recently sent probe */
  if(probe != dealias->probes[dealias->probec-1])
    return;

  /* if the reply is not the first reply for this probe */
  if(probe->replyc != 1)
    return;

  if(probe->ipid == reply->ipid && ++pd->echo >= 2)
    {
      if(probe->def->id != 0)
	goto prefixscan_next;
      dealias_result(task, SCAMPER_DEALIAS_RESULT_IPIDECHO);
      return;
    }

  /*
   * if we are currently waiting for our turn to probe, then for now
   * ignore the late response.
   */
  if(scamper_task_queue_isprobe(task))
    return;

  /* check if we should count this reply as a valid response */
  if(SCAMPER_DEALIAS_REPLY_FROM_TARGET(probe, reply))
    pfstate->replyc++;
  else
    return;

  /*
   * if we sent a UDP probe, and got a port unreachable message back from a
   * different interface, then we might be able to use that for alias
   * resolution.
   */
  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(probe->def) &&
     SCAMPER_DEALIAS_REPLY_IS_ICMP_UNREACH_PORT(reply) &&
     scamper_addr_cmp(probe->def->dst, reply->src) != 0)
    {
      if(probe->def->id == 0)
	{
	  /*
	   * if the reply is for prefixscan->a, then keep a record of the
	   * address of the interface used in the response.
	   */
	  if(array_find((void **)pfstate->aaliases, pfstate->aaliasc,
			reply->src, (array_cmp_t)scamper_addr_cmp) == NULL)
	    {
	      if(array_insert((void ***)&pfstate->aaliases, &pfstate->aaliasc,
			      reply->src, (array_cmp_t)scamper_addr_cmp) != 0)
		{
		  printerror(__func__, "could not add to aaliases");
		  goto err;
		}
	      scamper_addr_use(reply->src);
	    }
	}
      else
	{
	  /*
	   * if the address used to reply is probedef->a, or is one of the
	   * aliases previously observed for a, then we infer aliases.
	   */
	  if(scamper_addr_cmp(reply->src, prefixscan->a) == 0 ||
	     array_find((void **)pfstate->aaliases, pfstate->aaliasc,
			reply->src, (array_cmp_t)scamper_addr_cmp) != NULL)
	    {
	      prefixscan->ab = scamper_addr_use(probe->def->dst);
	      prefixscan->flags |= SCAMPER_DEALIAS_PREFIXSCAN_FLAG_CSA;
	      dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
	      return;
	    }
	}
    }

  /*
   * another probe received in sequence.
   * we will probably send another probe, so reset attempts
   */
  seq = ++pfstate->seq;
  pfstate->attempt = 0;

  assert(seq >= 1 && seq <= prefixscan->replyc);

  /*
   * if we don't have a reply from each IP address yet, then keep probing.
   * ideally, this could be optimised to use the previous observed IP-ID
   * for probedef zero if we have probed other probedefs in the interim and
   * have just obtained a reply.
   */
  if(seq < 2)
    {
      if(state->probe != 0)
	{
	  state->probe = 0;
	  return;
	}

      if(state->probedefc == 1)
	{
	  /* figure out what we're going to probe next */
	  if(dealias_prefixscan_next(task) != 0)
	    goto err;

	  /* if it turns out we don't need to probe, handle that */
	  if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
	    return;
	}

      state->probe = state->probedefc-1;
      dealias_queue(task);
      return;
    }

  if((probes = malloc_zero(sizeof(scamper_dealias_probe_t *) * seq)) == NULL)
    {
      printerror(__func__, "could not malloc probes");
      goto err;
    }
  probes[seq-1] = probe;

  /* if the reply was not for the first probe, then skip over earlier probes */
  p = dealias->probec-2; defid = probe->def->id;
  while(p >= 0 && dealias->probes[p]->def->id == defid)
    p--;

  for(s=seq-1; s>0; s--)
    {
      if(p < 0)
	goto err;

      if(probes[s]->def->id == 0)
	defid = state->probedefc - 1;
      else
	defid = 0;

      while(p >= 0)
	{
	  assert(defid == dealias->probes[p]->def->id);

	  /* skip over any unresponded to probes */
	  if(dealias->probes[p]->replyc == 0)
	    {
	      p--;
	      continue;
	    }

	  /* record the probe for this defid */
	  probes[s-1] = dealias->probes[p];

	  /* skip over any probes that proceeded this one with same defid */
	  while(p >= 0 && dealias->probes[p]->def->id == defid)
	    p--;

	  break;
	}
    }

  /*
   * check to see if the sequence of replies indicates an alias.  free
   * the probes array before we check the result, as it is easiest here.
   */
  if(SCAMPER_DEALIAS_PREFIXSCAN_IS_NOBS(prefixscan))
    p = scamper_dealias_ipid_inseq(probes, seq, prefixscan->fudge, 0);
  else
    p = scamper_dealias_ipid_inseq(probes, seq, prefixscan->fudge,
				   seq < prefixscan->replyc ? 2 : 3);
  free(probes); probes = NULL;
  if(p == -1)
    goto err;

  if(p == 1)
    {
      if(seq == prefixscan->replyc)
	{
	  p = state->probedefc-1;
	  prefixscan->ab = scamper_addr_use(prefixscan->probedefs[p]->dst);
	  dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
	  return;
	}

      if(state->probe == 0)
	state->probe = state->probedefc - 1;
      else
	state->probe = 0;

      return;
    }

 prefixscan_next:
  /* if there are no other addresses to try, then finish */
  if(state->probedefc-1 == pfstate->probedefc)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  if(dealias_prefixscan_next(task) != 0)
    goto err;
  if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
    return;

  pfstate->round   = 0;
  pfstate->attempt = 0;
  state->probe     = state->probedefc-1;

  if(dealias->probes[dealias->probec-1]->def->id == 0)
    pfstate->seq = 1;
  else
    pfstate->seq = 0;

  dealias_queue(task);
  return;

 err:
  if(probes != NULL) free(probes);
  dealias_handleerror(task, errno);
  return;
}

static void dealias_prefixscan_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  dealias_prefixscan_t *pfstate = state->methodstate;
  scamper_dealias_prefixscan_t *prefixscan;
  scamper_dealias_probedef_t *def;
  scamper_dealias_probe_t *probe;

  prefixscan = dealias->data;
  probe = dealias->probes[dealias->probec-1];
  def = probe->def;

  if(pfstate->replyc == 0)
    {
      /* if we're allowed to send another attempt, then do so */
      if(pfstate->attempt < prefixscan->attempts)
	{
	  goto done;
	}

      /*
       * if the probed address is unresponsive, and it is not prefixscan->a,
       * and there are other addresses to try, then probe one now
       */
      if(def->id != 0 && state->probedefc-1 < (uint32_t)pfstate->probedefc)
	{
	  if(dealias_prefixscan_next(task) != 0)
	    goto err;

	  /* if it turns out we don't need to probe, handle that */
	  if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
	    return;

	  pfstate->round   = 0;
	  pfstate->seq     = 0;
	  pfstate->attempt = 0;
	  state->probe     = state->probedefc-1;

	  goto done;
	}

      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  /* keep going! */
 done:
  if(state->probe == 0)
    state->round = pfstate->round0;
  else
    state->round = pfstate->round;

  return;

 err:
  dealias_handleerror(task, errno);
  return;
}

static dealias_probedef_t *
dealias_bump_def(scamper_dealias_t *dealias, dealias_state_t *state)
{
  return state->pds[state->probe];
}

static int dealias_bump_postprobe(scamper_dealias_t *dealias,
				  dealias_state_t *state)
{
  scamper_dealias_bump_t *bump = dealias->data;
  timeval_add_tv3(&state->next_tx, &state->last_tx, &bump->wait_probe);
  return 0;
}

static void dealias_bump_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t       *dealias = dealias_getdata(task);
  dealias_state_t         *state   = dealias_getstate(task);
  dealias_bump_t          *bs      = state->methodstate;
  scamper_dealias_bump_t  *bump    = dealias->data;
  scamper_dealias_probe_t *probes[3];
  uint32_t i, x, y;

  if(bs->step < 2)
    {
      bs->step++;
    }
  else if(bs->step == 2)
    {
      /* check if the last set of probes are in sequence */
      for(i=0; i<3; i++)
	if(dealias->probes[dealias->probec-3+i]->replyc == 1)
	  probes[i] = dealias->probes[dealias->probec-3+i];
	else
	  break;

      if(i != 3)
	goto none;

      if(scamper_dealias_ipid_inseq(probes, 3, 0, 0) != 1)
	{
	  dealias_result(task, SCAMPER_DEALIAS_RESULT_NOTALIASES);
	  return;
	}

      if(bs->attempt > bump->attempts)
	{
	  dealias_result(task, SCAMPER_DEALIAS_RESULT_ALIASES);
	  return;
	}

      x = probes[1]->replies[0]->ipid;
      y = probes[2]->replies[0]->ipid;
      if(x < y)
	i = y - x;
      else
	i = 0x10000 + y - x;

      if(i * 2 > 65535)
	goto none;

      bs->bump = i * 2;
      if(bs->bump == 2)
	bs->bump++;

      if(bs->bump > bump->bump_limit)
	goto none;

      bs->step++;
    }
  else if(bs->step == 3)
    {
      if(bs->bump != 0)
	{
	  bs->bump--;
	  return;
	}

      bs->attempt++;
      bs->step = 1;
    }

  if(state->probe == 1)
    state->probe = 0;
  else
    state->probe = 1;

  return;

 none:
  dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
  return;
}

static void dealias_bump_handlereply(scamper_task_t *task,
				     scamper_dealias_probe_t *probe,
				     scamper_dealias_reply_t *reply,
				     scamper_dl_rec_t *dl)
{
  /* check to see if the response could be useful for alias resolution */
  if(SCAMPER_DEALIAS_REPLY_FROM_TARGET(probe,reply) == 0 || probe->replyc != 1)
    {
      dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);
      return;
    }

  return;
}

static int dealias_midarest_shuffle(scamper_dealias_midarest_t *me,
				    dealias_midarest_t *mestate)
{
  uint32_t *defs = NULL;
  uint32_t  defc, i, j;

  defc = me->probedefc / mestate->addrc;
  assert(mestate->addrc * defc == me->probedefc);
  if((defs = malloc_zero(sizeof(uint32_t) * defc)) == NULL)
    {
      printerror(__func__, "could not malloc defs");
      return -1;
    }

  /*
   * shuffle the order of probedefs per address while evenly spacing
   * probes to each address
   */
  for(i=0; i<mestate->addrc; i++)
    {
      for(j=0; j<defc; j++)
	defs[j] = i + (mestate->addrc * j);
      shuffle32(defs, defc);
      for(j=0; j<defc; j++)
	mestate->order[i + (mestate->addrc * j)] = defs[j];
    }

  free(defs);
  return 0;
}

static dealias_probedef_t *
dealias_midarest_def(scamper_dealias_t *dealias, dealias_state_t *state)
{
  dealias_midarest_t *mestate = state->methodstate;
  return state->pds[mestate->order[mestate->i++]];
}

static int dealias_midarest_postprobe(scamper_dealias_t *dealias,
				      dealias_state_t *state)
{
  scamper_dealias_midarest_t *me = dealias->data;
  dealias_midarest_t *mestate = state->methodstate;

  if(state->probe == 0)
    timeval_add_tv3(&mestate->next_round, &state->last_tx, &me->wait_round);

  state->probe++;
  timeval_add_tv3(&state->next_tx, &state->last_tx, &me->wait_probe);

  /* this round is not finished */
  if(state->probe < me->probedefc)
    return 0;

  /* finished a round, onto the next one */
  state->probe = 0;
  state->round++;

  /* check if we just sent the last probe for the last round */
  if(state->round >= me->rounds)
    {
      timeval_add_tv3(&state->next_tx, &state->last_tx, &me->wait_timeout);
      return 0;
    }

  /* wait until the next round may begin, if that is further off */
  if(timeval_cmp(&state->next_tx, &mestate->next_round) < 0)
    timeval_cpy(&state->next_tx, &mestate->next_round);

  /* shuffle */
  mestate->i = 0;
  return dealias_midarest_shuffle(me, mestate);
}

static void dealias_midarest_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t          *dealias  = dealias_getdata(task);
  dealias_state_t            *state    = dealias_getstate(task);
  scamper_dealias_midarest_t *midarest = dealias->data;

  /* check to see if we are now finished */
  if(state->round != midarest->rounds)
    dealias_queue(task);
  else
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);

  return;
}

static dealias_probedef_t *
dealias_midardisc_def(scamper_dealias_t *dealias, dealias_state_t *state)
{
  return state->pds[state->probe];
}

static int dealias_midardisc_postprobe(scamper_dealias_t *dealias,
				       dealias_state_t *state)
{
  scamper_dealias_midardisc_t *md = dealias->data;
  scamper_dealias_midardisc_round_t *r = md->sched[state->round];
  dealias_midardisc_t *mdstate = state->methodstate;
  struct timeval tv;
  int us;

  assert(state->round < md->schedc);

  if(state->probe == 0 && state->round == 0)
    {
      /* figure out when the last probe for the first round should be sent */
      if(r->begin < r->end)
	{
	  us = (md->sched[1]->start.tv_sec * 1000000) + md->sched[1]->start.tv_usec;
	  us /= (r->end - r->begin + 1);
	  us *= (r->end - r->begin);
	  timeval_add_us(&mdstate->finish, &mdstate->start, us);
	}
      else
	{
	  timeval_cpy(&mdstate->finish, &mdstate->start);
	}
    }

  /*
   * if we are in the middle of the round, set the next probe tx
   * according to where we sit within this round
   */
  if(state->probe < r->end)
    {
      state->probe++;
      if((us = timeval_diff_us(&state->last_tx, &mdstate->finish)) <= 0)
	{
	  /* if we were due to finish by now, send the next probe ASAP */
	  timeval_cpy(&state->next_tx, &state->last_tx);
	}
      else if(state->probe < r->end)
	{
	  /* make sure the remaining probes are evenly spaced */
	  us /= (r->end - state->probe + 1);
	  timeval_add_us(&state->next_tx, &state->last_tx, us);
	}
      else
	{
	  /* scheduling for the last probe */
	  timeval_cpy(&state->next_tx, &mdstate->finish);
	}

      return 0;
    }

  /* check if we just sent the last probe for the last round */
  state->round++;
  if(state->round == md->schedc)
    {
      timeval_add_tv3(&state->next_tx, &state->last_tx, &md->wait_timeout);
      return 0;
    }

  /* the next probe goes at the start of the next round */
  r = md->sched[state->round];
  state->probe = r->begin;
  timeval_add_tv3(&state->next_tx, &mdstate->start, &r->start);

  /* figure out the round length */
  if(state->round+1 < md->schedc)
    timeval_diff_tv(&tv, &r->start, &md->sched[state->round+1]->start);
  else
    timeval_diff_tv(&tv, &md->sched[state->round-1]->start, &r->start);

  /* figure out when the last probe for the next round should be sent */
  if(r->begin < r->end)
    {
      us = (tv.tv_sec * 1000000) + tv.tv_usec;
      us /= (r->end - r->begin + 1);
      us *= (r->end - r->begin);
      timeval_add_us(&mdstate->finish, &state->next_tx, us);
    }
  else
    {
      timeval_cpy(&mdstate->finish, &state->next_tx);
    }

  return 0;
}

static void dealias_midardisc_handletimeout(scamper_task_t *task)
{
  scamper_dealias_t           *dealias = dealias_getdata(task);
  dealias_state_t             *state   = dealias_getstate(task);
  scamper_dealias_midardisc_t *md      = dealias->data;

  /* check to see if we are now finished */
  if(state->round != md->schedc)
    dealias_queue(task);
  else
    dealias_result(task, SCAMPER_DEALIAS_RESULT_NONE);

  return;
}

static void do_dealias_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  static void (*const func[])(scamper_task_t *, scamper_dealias_probe_t *,
			      scamper_dealias_reply_t *,
			      scamper_dl_rec_t *) = {
    dealias_mercator_handlereply,
    dealias_ally_handlereply,
    dealias_radargun_handlereply,
    dealias_prefixscan_handlereply,
    dealias_bump_handlereply,
    NULL, /* midarest */
    NULL, /* midardisc */
  };
  scamper_dealias_probe_t *probe = NULL;
  scamper_dealias_reply_t *reply = NULL;
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  dealias_target_t *tgt;
  scamper_addr_t a;
  int v4 = 0;

  /* if we haven't sent a probe yet, then we have nothing to match */
  if(dealias->probec == 0)
    return;

  if(dl->dl_af == AF_INET)
    v4 = 1;
  else if(dl->dl_af != AF_INET6)
    return;

  if(v4 && SCAMPER_DL_IS_TCP(dl))
    {
      if(scamper_dl_rec_src(dl, &a) != 0 ||
	 (tgt = dealias_target_find(state, &a)) == NULL)
	return;
      probe = dealias_probe_tcp_find2(state, tgt, dl->dl_tcp_dport,
				      dl->dl_tcp_sport);
      scamper_dl_rec_tcp_print(dl);
    }
  else if(state->flags & DEALIAS_STATE_FLAG_DL && SCAMPER_DL_IS_ICMP(dl))
    {
      /* if the ICMP type is not something that we care for, then drop it */
      if(SCAMPER_DL_IS_ICMP_TTL_EXP(dl) ||
	 SCAMPER_DL_IS_ICMP_UNREACH(dl) ||
	 SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl))
	{
	  /* the IPID value used is expected to be of the form 0xabab */
	  if(v4 && (dl->dl_icmp_ip_id & 0xff) != (dl->dl_icmp_ip_id >> 8))
	    return;
	  /* get the address to match with */
	  if(scamper_dl_rec_icmp_ip_dst(dl, &a) != 0 ||
	     (tgt = dealias_target_find(state, &a)) == NULL)
	    return;

	  if(dl->dl_icmp_ip_proto == IPPROTO_UDP)
	    probe = dealias_probe_udp_find(state, tgt, dl->dl_icmp_ip_id,
					   dl->dl_icmp_udp_sport,
					   dl->dl_icmp_udp_dport);
	  else if(dl->dl_icmp_ip_proto == IPPROTO_ICMP ||
		  dl->dl_icmp_ip_proto == IPPROTO_ICMPV6)
	    probe = dealias_probe_icmp_find(state, tgt, dl->dl_icmp_ip_id,
					    dl->dl_icmp_icmp_type,
					    dl->dl_icmp_icmp_code,
					    dl->dl_icmp_icmp_id,
					    dl->dl_icmp_icmp_seq);
	  else if(dl->dl_icmp_ip_proto == IPPROTO_TCP)
	    probe = dealias_probe_tcp_find(state, tgt, dl->dl_icmp_ip_id,
					   dl->dl_icmp_tcp_sport,
					   dl->dl_icmp_tcp_dport);
	}
      else if(SCAMPER_DL_IS_ICMP_ECHO_REPLY(dl) != 0)
	{
	  if(scamper_dl_rec_src(dl, &a) != 0 ||
	     (tgt = dealias_target_find(state, &a)) == NULL)
	    return;
	  probe = dealias_probe_echoreq_find(state, tgt,
					     dl->dl_icmp_id, dl->dl_icmp_seq);
	}
      else return;

      scamper_dl_rec_icmp_print(dl);
    }

  if(probe == NULL || scamper_dl_rec_src(dl, &a) != 0)
    return;

  if((reply = scamper_dealias_reply_alloc()) == NULL)
    {
      scamper_debug(__func__, "could not alloc reply");
      goto err;
    }

  if(scamper_addr_cmp(&a, probe->def->dst) == 0)
    {
      reply->src = scamper_addr_use(probe->def->dst);
    }
  else if((reply->src=scamper_addrcache_get(addrcache,a.type,a.addr)) == NULL)
    {
      scamper_debug(__func__, "could not get address from cache");
      goto err;
    }
  timeval_cpy(&reply->rx, &dl->dl_tv);
  reply->ttl       = dl->dl_ip_ttl;
  reply->proto     = dl->dl_ip_proto;
  reply->size      = dl->dl_ip_size;

  if(v4)
    {
      reply->ipid = dl->dl_ip_id;
    }
  else if(SCAMPER_DL_IS_IP_FRAG(dl))
    {
      reply->flags |= SCAMPER_DEALIAS_REPLY_FLAG_IPID32;
      reply->ipid32 = dl->dl_ip6_id;
    }

  if(SCAMPER_DL_IS_TCP(dl))
    {
      reply->tcp_flags = dl->dl_tcp_flags;
    }
  else
    {
      reply->icmp_type = dl->dl_icmp_type;
      reply->icmp_code = dl->dl_icmp_code;
      reply->icmp_q_ttl = dl->dl_icmp_ip_ttl;
    }

  if(scamper_dealias_reply_add(probe, reply) != 0)
    {
      scamper_debug(__func__, "could not add reply to probe");
      goto err;
    }

  if(func[dealias->method-1] != NULL)
    func[dealias->method-1](task, probe, reply, dl);

  return;

 err:
  if(reply != NULL) scamper_dealias_reply_free(reply);
  dealias_handleerror(task, errno);
  return;
}

static void do_dealias_handle_icmp(scamper_task_t *task,scamper_icmp_resp_t *ir)
{
  static void (*const func[])(scamper_task_t *, scamper_dealias_probe_t *,
			      scamper_dealias_reply_t *,
			      scamper_dl_rec_t *) = {
    dealias_mercator_handlereply,
    dealias_ally_handlereply,
    NULL, /* radargun */
    dealias_prefixscan_handlereply,
    dealias_bump_handlereply,
    NULL, /* midarest */
    NULL, /* midardisc */
  };
  scamper_dealias_probe_t *probe = NULL;
  scamper_dealias_reply_t *reply = NULL;
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  dealias_target_t *tgt;
  scamper_addr_t a;

  /* if we haven't sent a probe yet, then we have nothing to match */
  if(dealias->probec == 0)
    return;

  /* are we handling all responses using datalink sockets? */
  if((state->flags & DEALIAS_STATE_FLAG_DL) != 0)
    return;

  /* if the ICMP type is not something that we care for, then drop it */
  if(SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) ||
     SCAMPER_ICMP_RESP_IS_UNREACH(ir) ||
     SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir))
    {
      if(SCAMPER_ICMP_RESP_INNER_IS_SET(ir) == 0 || ir->ir_inner_ip_off != 0)
	return;

      /* the IPID value used is expected to be of the form 0xabab */
      if(ir->ir_af == AF_INET &&
	 (ir->ir_inner_ip_id & 0xff) != (ir->ir_inner_ip_id >> 8))
	return;

      if(scamper_icmp_resp_inner_dst(ir, &a) != 0 ||
	 (tgt = dealias_target_find(state, &a)) == NULL)
	return;

      if(ir->ir_inner_ip_proto == IPPROTO_UDP)
	probe = dealias_probe_udp_find(state, tgt, ir->ir_inner_ip_id,
				       ir->ir_inner_udp_sport,
				       ir->ir_inner_udp_dport);
      else if(ir->ir_inner_ip_proto == IPPROTO_ICMP ||
	      ir->ir_inner_ip_proto == IPPROTO_ICMPV6)
	probe = dealias_probe_icmp_find(state, tgt, ir->ir_inner_ip_id,
					ir->ir_inner_icmp_type,
					ir->ir_inner_icmp_code,
					ir->ir_inner_icmp_id,
					ir->ir_inner_icmp_seq);
      else if(ir->ir_inner_ip_proto == IPPROTO_TCP)
	probe = dealias_probe_tcp_find(state, tgt, ir->ir_inner_ip_id,
				       ir->ir_inner_tcp_sport,
				       ir->ir_inner_tcp_dport);

      if(scamper_icmp_resp_src(ir, &a) != 0)
	return;
    }
  else if(SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir) != 0)
    {
      if(scamper_icmp_resp_src(ir, &a) != 0 ||
	 (tgt = dealias_target_find(state, &a)) == NULL)
	return;
      probe = dealias_probe_echoreq_find(state, tgt,
					 ir->ir_icmp_id, ir->ir_icmp_seq);
    }

  if(probe == NULL)
    return;

  if((reply = scamper_dealias_reply_alloc()) == NULL)
    {
      scamper_debug(__func__, "could not alloc reply");
      goto err;
    }
  if(scamper_addr_cmp(&a, probe->def->dst) == 0)
    {
      reply->src = scamper_addr_use(probe->def->dst);
    }
  else if((reply->src=scamper_addrcache_get(addrcache,a.type,a.addr)) == NULL)
    {
      scamper_debug(__func__, "could not get address from cache");
      goto err;
    }
  timeval_cpy(&reply->rx, &ir->ir_rx);
  reply->ttl           = (uint8_t)ir->ir_ip_ttl;
  reply->size          = ir->ir_ip_size;
  reply->icmp_type     = ir->ir_icmp_type;
  reply->icmp_code     = ir->ir_icmp_code;
  reply->icmp_q_ttl    = ir->ir_inner_ip_ttl;

  if(ir->ir_af == AF_INET)
    {
      reply->ipid  = ir->ir_ip_id;
      reply->proto = IPPROTO_ICMP;
    }
  else
    {
      reply->proto = IPPROTO_ICMPV6;
    }

  if(scamper_dealias_reply_add(probe, reply) != 0)
    {
      scamper_debug(__func__, "could not add reply to probe");
      goto err;
    }

  if(func[dealias->method-1] != NULL)
    func[dealias->method-1](task, probe, reply, NULL);
  return;

 err:
  if(reply != NULL) scamper_dealias_reply_free(reply);
  dealias_handleerror(task, errno);
  return;
}

static void do_dealias_handle_timeout(scamper_task_t *task)
{
  static void (*const func[])(scamper_task_t *) = {
    dealias_mercator_handletimeout,
    dealias_ally_handletimeout,
    dealias_radargun_handletimeout,
    dealias_prefixscan_handletimeout,
    dealias_bump_handletimeout,
    dealias_midarest_handletimeout,
    dealias_midardisc_handletimeout,
  };
  scamper_dealias_t *dealias = dealias_getdata(task);
  func[dealias->method-1](task);
  return;
}

/*
 * dealias_state_probe
 *
 * record the fact that a probe was sent
 */
static int dealias_state_probe(dealias_state_t *state,
			       dealias_probedef_t *pdef,
			       scamper_dealias_probe_t *probe,
			       scamper_probe_t *pr)
{
  dealias_probe_t *dp = NULL;

  /* allocate a structure to record this probe's details */
  if((dp = malloc_zero(sizeof(dealias_probe_t))) == NULL)
    {
      printerror(__func__, "could not malloc dealias_probe_t");
      goto err;
    }
  if(pdef->def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT)
    dp->match_field = pr->pr_udp_dport;
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(pdef->def))
    dp->match_field = pr->pr_icmp_seq;
  else if(SCAMPER_DEALIAS_PROBEDEF_VARY_TCP_SPORT(pdef->def))
    dp->match_field = pr->pr_tcp_sport;

  dp->probe = probe;
  dp->target = pdef->target;

  if((dp->target_node = dlist_head_push(dp->target->probes, dp)) == NULL ||
     dlist_tail_push(state->recent_probes, dp) == NULL)
    {
      printerror(__func__, "could not push to lists");
      goto err;
    }

  return 0;

 err:
  if(dp != NULL) free(dp);
  return -1;
}

static void dealias_prefixscan_free(void *data)
{
  dealias_prefixscan_t *pfstate = data;
  uint32_t j;
  size_t k;

  if(pfstate->probedefs != NULL)
    {
      for(j=0; j<pfstate->probedefc; j++)
	{
	  if(pfstate->probedefs[j].src != NULL)
	    scamper_addr_free(pfstate->probedefs[j].src);
	  if(pfstate->probedefs[j].dst != NULL)
	    scamper_addr_free(pfstate->probedefs[j].dst);
	}
      free(pfstate->probedefs);
    }
  if(pfstate->aaliases != NULL)
    {
      for(k=0; k<pfstate->aaliasc; k++)
	if(pfstate->aaliases[k] != NULL)
	  scamper_addr_free(pfstate->aaliases[k]);
      free(pfstate->aaliases);
    }
  free(pfstate);

  return;
}

static int dealias_prefixscan_alloc(scamper_dealias_t *dealias,
				    dealias_state_t *state)
{
  scamper_dealias_prefixscan_t *pfxscan = dealias->data;
  scamper_dealias_probedef_t pd;
  dealias_prefixscan_t *pfstate = NULL;
  scamper_addr_t      **addrs = NULL;
  size_t                i, addrc = 0;
  char errbuf[256];

  /* figure out the addresses that will be probed */
  if(dealias_prefixscan_array(dealias, &addrs, &addrc) != 0)
    goto err;

  if((pfstate = malloc_zero(sizeof(dealias_prefixscan_t))) == NULL)
    {
      printerror(__func__, "could not malloc pfstate");
      goto err;
    }
  state->methodstate = pfstate;

  pfstate->probedefs = malloc_zero(addrc * sizeof(scamper_dealias_probedef_t));
  if(pfstate->probedefs == NULL)
    {
      printerror(__func__, "could not malloc probedefs");
      goto err;
    }
  pfstate->probedefc = addrc;

  for(i=0; i<addrc; i++)
    {
      memcpy(&pd, pfxscan->probedefs[0], sizeof(pd));
      pd.dst = scamper_addr_use(addrs[i]);
      pd.src = scamper_getsrc(pd.dst, 0, errbuf, sizeof(errbuf));
      memcpy(&pfstate->probedefs[i], &pd, sizeof(pd));
    }

  dealias_prefixscan_array_free(addrs, addrc);
  return 0;

 err:
  if(addrs != NULL) dealias_prefixscan_array_free(addrs, addrc);
  return -1;
}

static void dealias_radargun_free(void *data)
{
  dealias_radargun_t *rgstate = data;
  if(rgstate->order != NULL)
    free(rgstate->order);
  free(rgstate);
  return;
}

static int dealias_radargun_alloc(scamper_dealias_radargun_t *rg,
				  dealias_state_t *state)
{
  dealias_radargun_t *rgstate = NULL;
  uint32_t i;
  size_t size;

  if((rgstate = malloc_zero(sizeof(dealias_radargun_t))) == NULL)
    return -1;

  state->methodstate = rgstate;

  /* if the probe order is to be shuffled, then shuffle it */
  if((rg->flags & SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE))
    {
      size = sizeof(uint32_t) * rg->probedefc;
      if((rgstate->order = malloc_zero(size)) == NULL)
	return -1;
      for(i=0; i<rg->probedefc; i++)
	rgstate->order[i] = i;
      if(shuffle32(rgstate->order, rg->probedefc) != 0)
	return -1;
    }

  return 0;
}

static int dealias_bump_alloc(dealias_state_t *state)
{
  dealias_bump_t *bstate = NULL;
  if((bstate = malloc_zero(sizeof(dealias_bump_t))) == NULL)
    return -1;
  state->methodstate = bstate;
  return 0;
}

static void dealias_bump_free(void *data)
{
  free(data);
  return;
}

static void dealias_midarest_free(void *data)
{
  dealias_midarest_t *mestate = data;
  if(mestate->order != NULL)
    free(mestate->order);
  free(mestate);
  return;
}

static int dealias_midarest_alloc(scamper_dealias_midarest_t *me,
				  dealias_state_t *state)
{
  dealias_midarest_t *mestate = NULL;
  uint32_t i;

  /* allocate memory to store state */
  if((mestate = malloc_zero(sizeof(dealias_midarest_t))) == NULL ||
     (mestate->order = malloc_zero(sizeof(uint32_t) * me->probedefc)) == NULL)
    goto err;

  /*
   * figure out how many unique addresses there are in this run, so
   * that we can work out schedules
   */
  for(i=1; i<me->probedefc; i++)
    if(scamper_addr_cmp(me->probedefs[0]->dst, me->probedefs[i]->dst) == 0)
      break;
  if(i == me->probedefc)
    goto err;
  mestate->addrc = i;

  /* figure out how many probedefs there are per address */
  if(dealias_midarest_shuffle(me, mestate) != 0)
    goto err;

  state->methodstate = mestate;
  return 0;

 err:
  if(mestate != NULL) dealias_midarest_free(mestate);
  return -1;
}

static int dealias_midardisc_alloc(const scamper_dealias_midardisc_t *md,
				   dealias_state_t *state)
{
  dealias_midardisc_t *mdstate = NULL;
  if((mdstate = malloc_zero(sizeof(dealias_midardisc_t))) == NULL)
    return -1;
  state->methodstate = mdstate;
  return 0;
}

static void dealias_midardisc_free(void *data)
{
  free(data);
  return;
}

static void dealias_state_free(scamper_dealias_t *dealias,
			       dealias_state_t *state)
{
  static void (*const func[])(void *data) = {
    NULL, /* mercator */
    NULL, /* ally */
    dealias_radargun_free,
    dealias_prefixscan_free,
    dealias_bump_free,
    dealias_midarest_free,
    dealias_midardisc_free,
  };
  size_t j;

  if(state == NULL)
    return;

  if(state->recent_probes != NULL)
    dlist_free(state->recent_probes);

  if(state->methodstate != NULL)
    {
      assert(func[dealias->method-1] != NULL);
      func[dealias->method-1](state->methodstate);
    }

  if(state->targets != NULL)
    splaytree_free(state->targets, (splaytree_free_t)dealias_target_free);

  if(state->pds != NULL)
    {
      for(j=0; j<state->pdc; j++)
	if(state->pds[j] != NULL)
	  free(state->pds[j]);
      free(state->pds);
    }

  if(state->ptbq != NULL)
    slist_free_cb(state->ptbq, (slist_free_t)dealias_ptb_free);

  if(state->discard != NULL)
    slist_free_cb(state->discard, (slist_free_t)scamper_dealias_probe_free);

  free(state);
  return;
}

static int dealias_midardisc_go(scamper_task_t *task, const struct timeval *now)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  scamper_dealias_midardisc_t *md = dealias->data;
  dealias_midardisc_t *mdstate = state->methodstate;

  /* if there is no specified time to start passed, then go */
  if(md->startat == NULL)
    {
      timeval_cpy(&mdstate->start, now);
      return 1;
    }

  /*
   * if the time to start has passed, then go, noting the time we should
   * have started in the state structure
   */
  if(timeval_cmp(md->startat, now) <= 0)
    {
      timeval_cpy(&mdstate->start, md->startat);
      return 1;
    }

  /* queue until it is time to start */
  scamper_task_queue_wait_tv(task, md->startat);
  return 0;
}

static void do_dealias_probe(scamper_task_t *task)
{
  static int (*const postprobe_func[])(scamper_dealias_t *,
				       dealias_state_t *) = {
    dealias_mercator_postprobe,
    dealias_ally_postprobe,
    dealias_radargun_postprobe,
    dealias_prefixscan_postprobe,
    dealias_bump_postprobe,
    dealias_midarest_postprobe,
    dealias_midardisc_postprobe,
  };
  static dealias_probedef_t *(*const def_func[])(scamper_dealias_t *,
						 dealias_state_t *) = {
    dealias_mercator_def,
    dealias_ally_def,
    dealias_radargun_def,
    dealias_prefixscan_def,
    dealias_bump_def,
    dealias_midarest_def,
    dealias_midardisc_def,
  };
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);
  dealias_probedef_t *pdef;
  scamper_dealias_probedef_t *def;
  scamper_dealias_probe_t *dp = NULL;
  scamper_probe_t probe;
  dealias_ptb_t *ptb = NULL;
  struct timeval tv;
  uint16_t u16;

  if(dealias->probec == 0)
    {
      gettimeofday_wrap(&tv);
      if(dealias->method == SCAMPER_DEALIAS_METHOD_MIDARDISC &&
	 dealias_midardisc_go(task, &tv) == 0)
	return;
      timeval_cpy(&dealias->start, &tv);
    }

  memset(&probe, 0, sizeof(probe));
  if((state->flags & DEALIAS_STATE_FLAG_DL) != 0)
    probe.pr_flags |= SCAMPER_PROBE_FLAG_DL;

  if(slist_count(state->ptbq) > 0)
    {
      ptb = slist_head_pop(state->ptbq); def = ptb->def;
      probe.pr_ip_src = def->src;
      probe.pr_ip_dst = def->dst;
      probe.pr_ip_ttl = 255;
      SCAMPER_PROBE_ICMP_PTB(&probe, def->mtu);
      probe.pr_data   = ptb->quote;
      probe.pr_len    = ptb->quote_len;
      if(scamper_probe_task(&probe, task) != 0)
	{
	  errno = probe.pr_errno;
	  goto err;
	}
      timeval_cpy(&state->ptb_tx, &probe.pr_tx);
      dealias_ptb_free(ptb);
      dealias_queue(task);
      return;
    }

  if((pdef = def_func[dealias->method-1](dealias, state)) == NULL)
    goto err;
  def = pdef->def;

  if(pktbuf_len < state->pds[def->id]->pktbuf_len)
    {
      if(realloc_wrap((void **)&pktbuf, state->pds[def->id]->pktbuf_len) != 0)
	{
	  printerror(__func__, "could not realloc pktbuf");
	  goto err;
	}
      pktbuf_len = state->pds[def->id]->pktbuf_len;
    }

  probe.pr_ip_src    = def->src;
  probe.pr_ip_dst    = def->dst;
  probe.pr_ip_ttl    = def->ttl;
  probe.pr_ip_tos    = def->tos;
  if(state->pds[def->id]->pktbuf_len > 0)
    {
      probe.pr_len   = state->pds[def->id]->pktbuf_len;
      probe.pr_data  = pktbuf;
    }

  if(SCAMPER_ADDR_TYPE_IS_IPV4(def->dst))
    {
      probe.pr_flags |= SCAMPER_PROBE_FLAG_IPID;
      probe.pr_ip_id  = state->id << 8 | state->id;
      probe.pr_ip_off = IP_DF;
    }

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    {
      probe.pr_ip_proto  = IPPROTO_UDP;
      probe.pr_udp_sport = def->un.udp.sport;

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP)
	probe.pr_udp_dport = def->un.udp.dport;
      else if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT)
	probe.pr_udp_dport = def->un.udp.dport + pdef->target->udp_dport++;
      else
	goto err;

      /* hack to get the udp csum to be a particular value, and be valid */
      u16 = htons(dealias->probec + 1);
      memcpy(probe.pr_data, &u16, 2);
      u16 = scamper_udp4_cksum(&probe);
      memcpy(probe.pr_data, &u16, 2);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def))
    {
      SCAMPER_PROBE_ICMP_ECHO(&probe, def->un.icmp.id, state->icmpseq++);

      /* hack to get the icmp csum to be a particular value, and be valid */
      u16 = htons(def->un.icmp.csum);
      memcpy(probe.pr_data, &u16, 2);
      u16 = scamper_icmp4_cksum(&probe);
      memcpy(probe.pr_data, &u16, 2);
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    {
      probe.pr_ip_proto  = IPPROTO_TCP;
      probe.pr_tcp_dport = def->un.tcp.dport;
      probe.pr_tcp_flags = def->un.tcp.flags;

      if(def->method == SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK)
	{
	  probe.pr_tcp_sport = def->un.tcp.sport;
	  probe.pr_tcp_seq   = state->pds[def->id]->tcp_seq;
	  probe.pr_tcp_ack   = state->pds[def->id]->tcp_ack;
	}
      else if(SCAMPER_DEALIAS_PROBEDEF_VARY_TCP_SPORT(def))
	{
	  probe.pr_tcp_sport = def->un.tcp.sport + pdef->target->tcp_sport++;
	  if(random_u32(&probe.pr_tcp_seq) != 0 ||
	     random_u32(&probe.pr_tcp_ack) != 0)
	    goto err;
	}
      else goto err;
    }

  /*
   * allocate a probe record before we try and send the probe as there is no
   * point sending something into the wild that we can't record
   */
  if((dp = scamper_dealias_probe_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc probe");
      goto err;
    }
  dp->def = def;
  dp->ipid = probe.pr_ip_id;
  dp->seq = state->round;

  if(dealias_state_probe(state, pdef, dp, &probe) != 0)
    goto err;

  /* send the probe */
  if(scamper_probe_task(&probe, task) != 0)
    {
      errno = probe.pr_errno;
      goto err;
    }

  /* record details of the probe in the scamper_dealias_t data structures */
  timeval_cpy(&dp->tx, &probe.pr_tx);
  if(scamper_dealias_probe_add(dealias, dp) != 0)
    {
      scamper_debug(__func__, "could not add probe to dealias data");
      goto err;
    }

  /* figure out how long to wait until sending the next probe */
  timeval_cpy(&state->last_tx, &probe.pr_tx);
  if(postprobe_func[dealias->method-1](dealias, state) != 0)
    goto err;

  assert(state->id != 0);
  if(--state->id == 0)
    state->id = 255;

  dealias_queue(task);
  return;

 err:
  if(ptb != NULL) dealias_ptb_free(ptb);
  dealias_handleerror(task, errno);
  return;
}

static void do_dealias_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_file_write_dealias(sf, dealias_getdata(task), task);
  return;
}

static void do_dealias_halt(scamper_task_t *task)
{
  dealias_result(task, SCAMPER_DEALIAS_RESULT_HALTED);
  return;
}

static void do_dealias_free(scamper_task_t *task)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  dealias_state_t *state = dealias_getstate(task);

  if(state != NULL)
    dealias_state_free(dealias, state);

  if(dealias != NULL)
    scamper_dealias_free(dealias);

  return;
}

void scamper_do_dealias_free(void *data)
{
  scamper_dealias_free((scamper_dealias_t *)data);
  return;
}

static int probedef2sig(scamper_task_t *task, scamper_dealias_probedef_t *def,
			char *errbuf, size_t errlen)
{
  scamper_task_sig_t *sig = NULL;

  if(def->src == NULL &&
     (def->src = scamper_getsrc(def->dst, 0, errbuf, errlen)) == NULL)
    goto err;

  /* form a signature */
  if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc task signature");
      goto err;
    }
  sig->sig_tx_ip_src = scamper_addr_use(def->src);
  sig->sig_tx_ip_dst = scamper_addr_use(def->dst);

  switch(def->method)
    {
    case SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO:
      SCAMPER_TASK_SIG_ICMP_ECHO(sig, def->un.icmp.id);
      break;

    case SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK:
      SCAMPER_TASK_SIG_TCP(sig, def->un.tcp.sport, def->un.tcp.dport);
      break;

    case SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP:
      SCAMPER_TASK_SIG_UDP(sig, def->un.udp.sport, def->un.udp.dport);
      break;

    case SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT:
    case SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_SYN_SPORT:
      SCAMPER_TASK_SIG_TCP_SPORT(sig, 0, 65535, def->un.udp.dport);
      break;

    case SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT:
      SCAMPER_TASK_SIG_UDP_DPORT(sig, def->un.udp.sport, 0, 65535);
      break;

    default:
      snprintf(errbuf, errlen, "%s: unhandled probe method %d",
	       __func__, def->method);
      goto err;
    }

  /* add it to the task */
  if(scamper_task_sig_add(task, sig) != 0)
    {
      snprintf(errbuf, errlen, "%s: could not add signature to task", __func__);
      goto err;
    }

  return 0;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  return -1;
}

static int dealias_mercator_init(scamper_task_t *task, dealias_state_t *state,
				 char *errbuf, size_t errlen)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  scamper_dealias_mercator_t *mercator = dealias->data;

  if(probedef2sig(task, mercator->probedef, errbuf, errlen) != 0)
    return -1;
  state->probedefs = &mercator->probedef;
  state->probedefc = 1;

  return 0;
}

static int dealias_ally_init(scamper_task_t *task, dealias_state_t *state,
			     char *errbuf, size_t errlen)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  scamper_dealias_ally_t *ally = dealias->data;

  if(probedef2sig(task, ally->probedefs[0], errbuf, errlen) != 0 ||
     probedef2sig(task, ally->probedefs[1], errbuf, errlen) != 0)
    return -1;
  state->probedefs = ally->probedefs;
  state->probedefc = 2;

  return 0;
}

static int dealias_radargun_init(scamper_task_t *task, dealias_state_t *state,
				 char *errbuf, size_t errlen)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  scamper_dealias_radargun_t *radargun = dealias->data;
  uint32_t p;

  for(p=0; p<radargun->probedefc; p++)
    if(probedef2sig(task, radargun->probedefs[p], errbuf, errlen) != 0)
      return -1;
  state->probedefs = radargun->probedefs;
  state->probedefc = radargun->probedefc;
  if(dealias_radargun_alloc(radargun, state) != 0)
    {
      snprintf(errbuf, errlen, "could not alloc radargun state");
      return -1;
    }

  return 0;
}

static int dealias_prefixscan_init(scamper_task_t *task, dealias_state_t *state,
				   char *errbuf, size_t errlen)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  scamper_dealias_prefixscan_t *pfxscan = dealias->data;
  dealias_prefixscan_t *pfstate;
  uint32_t p;

  if(dealias_prefixscan_alloc(dealias, state) != 0 ||
     probedef2sig(task, pfxscan->probedefs[0], errbuf, errlen) != 0)
    return -1;
  state->probedefs = pfxscan->probedefs;
  state->probedefc = pfxscan->probedefc;
  pfstate = state->methodstate;
  for(p=0; p<pfstate->probedefc; p++)
    if(probedef2sig(task, &pfstate->probedefs[p], errbuf, errlen) != 0)
      return -1;

  return 0;
}

static int dealias_bump_init(scamper_task_t *task, dealias_state_t *state,
			     char *errbuf, size_t errlen)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  scamper_dealias_bump_t *bump = dealias->data;

  if(probedef2sig(task, bump->probedefs[0], errbuf, errlen) != 0 ||
     probedef2sig(task, bump->probedefs[1], errbuf, errlen) != 0)
    return -1;
  state->probedefs = bump->probedefs;
  state->probedefc = 2;
  if(dealias_bump_alloc(state) != 0)
    {
      snprintf(errbuf, errlen, "could not alloc bump state");
      return -1;
    }

  return 0;
}

static int dealias_midarest_init(scamper_task_t *task, dealias_state_t *state,
				 char *errbuf, size_t errlen)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  scamper_dealias_midarest_t *midarest = dealias->data;
  uint16_t p;

  for(p=0; p<midarest->probedefc; p++)
    if(probedef2sig(task, midarest->probedefs[p], errbuf, errlen) != 0)
      return -1;
  state->probedefs = midarest->probedefs;
  state->probedefc = midarest->probedefc;
  if(dealias_midarest_alloc(midarest, state) != 0)
    {
      snprintf(errbuf, errlen, "could not alloc midarest state");
      return -1;
    }

  return 0;
}

static int dealias_midardisc_init(scamper_task_t *task, dealias_state_t *state,
				  char *errbuf, size_t errlen)
{
  scamper_dealias_t *dealias = dealias_getdata(task);
  scamper_dealias_midardisc_t *midardisc = dealias->data;
  uint32_t p;

  for(p=0; p<midardisc->probedefc; p++)
    if(probedef2sig(task, midardisc->probedefs[p], errbuf, errlen) != 0)
      return -1;
  state->probedefs = midardisc->probedefs;
  state->probedefc = midardisc->probedefc;
  if(dealias_midardisc_alloc(midardisc, state) != 0)
    {
      snprintf(errbuf, errlen, "could not alloc midardisc state");
      return -1;
    }

  return 0;
}

scamper_task_t *scamper_do_dealias_alloctask(void *data,
					     scamper_list_t *list,
					     scamper_cycle_t *cycle,
					     char *errbuf, size_t errlen)
{
  static int (*const func[])(scamper_task_t *, dealias_state_t *,
			     char *, size_t) = {
    dealias_mercator_init,
    dealias_ally_init,
    dealias_radargun_init,
    dealias_prefixscan_init,
    dealias_bump_init,
    dealias_midarest_init,
    dealias_midardisc_init,
  };
  scamper_dealias_t             *dealias = (scamper_dealias_t *)data;
  dealias_state_t               *state = NULL;
  scamper_task_t                *task = NULL;
  scamper_dealias_probedef_t    *def;
  uint32_t p;

  /* allocate a state for the task */
  if((task = scamper_task_alloc(dealias, &funcs)) == NULL ||
     (state = malloc_zero(sizeof(dealias_state_t))) == NULL ||
     (state->recent_probes = dlist_alloc()) == NULL ||
     (state->ptbq = slist_alloc()) == NULL ||
     (state->discard = slist_alloc()) == NULL ||
     (state->targets = splaytree_alloc((splaytree_cmp_t)dealias_target_cmp)) == NULL)
    {
      snprintf(errbuf, errlen, "%s: could not malloc state", __func__);
      goto err;
    }
  state->id = 255;

  if(func[dealias->method-1](task, state, errbuf, errlen) != 0)
    goto err;

  for(p=0; p<state->probedefc; p++)
    {
      def = state->probedefs[p];
      if(def->mtu != 0)
	state->flags |= DEALIAS_STATE_FLAG_DL;
      if(dealias_probedef_add(state, def, errbuf, errlen) != 0)
	goto err;
    }

  /* associate the list and cycle with the trace */
  dealias->list  = scamper_list_use(list);
  dealias->cycle = scamper_cycle_use(cycle);

  scamper_task_setstate(task, state);
  return task;

 err:
  if(task != NULL)
    {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
    }
  if(state != NULL) dealias_state_free(dealias, state);
  return NULL;
}

uint32_t scamper_do_dealias_userid(void *data)
{
  return ((scamper_dealias_t *)data)->userid;
}

void scamper_do_dealias_cleanup(void)
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  return;
}

int scamper_do_dealias_init(void)
{
  funcs.probe                  = do_dealias_probe;
  funcs.handle_icmp            = do_dealias_handle_icmp;
  funcs.handle_timeout         = do_dealias_handle_timeout;
  funcs.handle_dl              = do_dealias_handle_dl;
  funcs.write                  = do_dealias_write;
  funcs.task_free              = do_dealias_free;
  funcs.halt                   = do_dealias_halt;

  return 0;
}
