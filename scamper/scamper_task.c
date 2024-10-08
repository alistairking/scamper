/*
 * scamper_task.c
 *
 * $Id: scamper_task.c,v 1.90 2024/08/13 06:07:01 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2016-2023 Matthew Luckie
 * Copyright (C) 2024      The Regents of the University of California
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_debug.h"
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_icmp_resp.h"
#include "scamper_udp_resp.h"
#include "scamper_fds.h"
#include "scamper_task.h"
#include "scamper_queue.h"
#include "scamper_list.h"
#include "scamper_cyclemon.h"
#include "scamper_file.h"
#include "scamper_outfiles.h"
#include "scamper_sources.h"
#include "scamper_rtsock.h"
#include "scamper_dl.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
#include "mjl_patricia.h"
#include "utils.h"

struct scamper_task
{
  /* the data pointer points to the collected data */
  void                     *data;

  /* any state kept during the data collection is kept here */
  void                     *state;

  /* state / details kept internally to the task */
  dlist_t                  *onhold;

  /* various callbacks that scamper uses to handle this task */
  scamper_task_funcs_t     *funcs;

  /* pointer to a queue structure that manages this task in the queues */
  scamper_queue_t          *queue;

  /* pointer to where the task came from */
  scamper_sourcetask_t     *sourcetask;

  /* pointer to cycle monitor structure, if used */
  struct scamper_cyclemon  *cyclemon;

  /* signature of probes sent by this task */
  slist_t                  *siglist;

  /* list of ancillary data */
  dlist_t                  *ancillary;

  /* file descriptors held by the task */
  scamper_fd_t            **fds;
  size_t                    fdc;
};

struct scamper_task_anc
{
  void         *data;
  void        (*freedata)(void *);
  dlist_node_t *node;
};

/*
 * trie_s2t_t
 *
 * a mapping from an address being probed to all of the signatures
 * belonging to the task.  the list contains s2t_t entries.  the code
 * that uses this structure assumes that tasks the s2t_t entries point
 * to appear contiguously.
 */
typedef struct trie_s2t
{
  scamper_addr_t     *addr;
  dlist_t            *list;
  patricia_node_t    *node;
} trie_s2t_t;

/*
 * s2t_t
 *
 * a mapping of a signature to a task.  the node is an element in one
 * of the tries, sniff, or host structures.
 */
typedef struct s2t
{
  scamper_task_sig_t *sig;
  scamper_task_t     *task;
  void               *node;
} s2t_t;

typedef struct task_onhold
{
  void          (*unhold)(void *param);
  void           *param;
} task_onhold_t;

static patricia_t  *tx_ip4 = NULL;
static patricia_t  *tx_ip6 = NULL;
static patricia_t  *tx_nd4 = NULL;
static patricia_t  *tx_nd6 = NULL;
#ifndef DISABLE_SCAMPER_SNIFF
static dlist_t     *sniff = NULL;
#endif
#ifndef DISABLE_SCAMPER_HOST
static splaytree_t *host = NULL;
#endif

static int tx_ip_cmp(const trie_s2t_t *a, const trie_s2t_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static int tx_ip_bit(const trie_s2t_t *ts2t, int bit)
{
  return scamper_addr_bit(ts2t->addr, bit);
}

static int tx_ip_fbd(const trie_s2t_t *a, const trie_s2t_t *b)
{
  return scamper_addr_fbd(a->addr, b->addr);
}

static int tx_nd_cmp(const s2t_t *a, const s2t_t *b)
{
  assert(a->sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_ND);
  assert(b->sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_ND);
  return scamper_addr_cmp(a->sig->sig_tx_nd_ip, b->sig->sig_tx_nd_ip);
}

static int tx_nd_bit(const s2t_t *s2t, int bit)
{
  assert(s2t->sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_ND);
  return scamper_addr_bit(s2t->sig->sig_tx_nd_ip, bit);
}

static int tx_nd_fbd(const s2t_t *a, const s2t_t *b)
{
  assert(a->sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_ND);
  assert(b->sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_ND);
  return scamper_addr_fbd(a->sig->sig_tx_nd_ip, b->sig->sig_tx_nd_ip);
}

#ifndef DISABLE_SCAMPER_HOST
static int host_cmp(const s2t_t *a, const s2t_t *b)
{
  int i;
  assert(a->sig->sig_type == SCAMPER_TASK_SIG_TYPE_HOST);
  assert(b->sig->sig_type == SCAMPER_TASK_SIG_TYPE_HOST);
  if((i = strcasecmp(a->sig->sig_host_name, b->sig->sig_host_name)) != 0)
    return i;
  if(a->sig->sig_host_type < b->sig->sig_host_type)
    return -1;
  if(a->sig->sig_host_type > b->sig->sig_host_type)
    return 1;
  return scamper_addr_cmp(a->sig->sig_host_dst, b->sig->sig_host_dst);
}
#endif

static void trie_s2t_free(trie_s2t_t *ts2t)
{
  if(ts2t->list != NULL) dlist_free(ts2t->list);
  if(ts2t->addr != NULL) scamper_addr_free(ts2t->addr);
  free(ts2t);
  return;
}

static trie_s2t_t *trie_s2t_alloc(scamper_addr_t *addr)
{
  trie_s2t_t *ts2t;
  if((ts2t = malloc_zero(sizeof(trie_s2t_t))) == NULL ||
     (ts2t->list = dlist_alloc()) == NULL)
    goto err;
  ts2t->addr = scamper_addr_use(addr);
  return ts2t;
 err:
  if(ts2t != NULL) trie_s2t_free(ts2t);
  return NULL;
}

static void tx_ip_check(scamper_dl_rec_t *dl)
{
  scamper_addr_t addr, addr2buf, *addr2 = NULL;
  scamper_task_t *last_task = NULL;
  patricia_t *pt;
  trie_s2t_t fm, *ts2t;
  dlist_node_t *dn;
  s2t_t *s2t;
  int i;

  if(SCAMPER_DL_IS_IPV4(dl))
    {
      pt = tx_ip4;
      addr.type = SCAMPER_ADDR_TYPE_IPV4;
    }
  else if(SCAMPER_DL_IS_IPV6(dl))
    {
      pt = tx_ip6;
      addr.type = SCAMPER_ADDR_TYPE_IPV6;
    }
  else return;

  if(dl->dl_ip_off != 0)
    {
      addr.addr = dl->dl_ip_src;
    }
  else if(SCAMPER_DL_IS_TCP(dl))
    {
      if((dl->dl_tcp_flags & TH_SYN) && (dl->dl_tcp_flags & TH_ACK) == 0)
	{
	  addr.addr = dl->dl_ip_dst;
	}
      else
	{
	  addr.addr = dl->dl_ip_src;
	  addr2buf.type = addr.type;
	  addr2buf.addr = dl->dl_ip_dst;
	  addr2 = &addr2buf;
	}
    }
  else if(SCAMPER_DL_IS_ICMP(dl))
    {
      if(SCAMPER_DL_IS_ICMP_ECHO_REQUEST(dl))
	addr.addr = dl->dl_ip_dst;
      else if(SCAMPER_DL_IS_ICMP_ECHO_REPLY(dl))
	addr.addr = dl->dl_ip_src;
      else if(SCAMPER_DL_IS_ICMP_TTL_EXP(dl) ||
	      SCAMPER_DL_IS_ICMP_UNREACH(dl) ||
	      SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl))
	addr.addr = dl->dl_icmp_ip_dst;
      else
	return;
    }
  else if(SCAMPER_DL_IS_UDP(dl))
    {
      addr.addr = dl->dl_ip_dst;
      addr2buf.type = addr.type;
      addr2buf.addr = dl->dl_ip_src;
      addr2 = &addr2buf;
    }
  else
    {
      addr.addr = dl->dl_ip_dst;
    }

  /*
   * make up to two checks in the trie, checking addr2 if we don't
   * find anything with addr
   */
  for(i=0; i<2; i++)
    {
      if(i == 0)
        fm.addr = &addr;
      else if(i == 1 && addr2 != NULL)
	fm.addr = addr2;
      else
	break;
      if((ts2t = patricia_find(pt, &fm)) != NULL)
	{
	  for(dn=dlist_head_node(ts2t->list);dn != NULL;dn=dlist_node_next(dn))
	    {
	      s2t = dlist_node_item(dn);
	      if(s2t->task == last_task)
		continue;
	      last_task = s2t->task;
	      if(s2t->task->funcs->handle_dl != NULL)
		s2t->task->funcs->handle_dl(s2t->task, dl);
	    }
	  break;
	}
    }

  return;
}

static void tx_nd_check(scamper_dl_rec_t *dl)
{
  scamper_task_sig_t sig;
  scamper_addr_t ip;
  struct in_addr ip4;
  struct in6_addr ip6;
  patricia_t *pt;
  s2t_t fm, *s2t;

  if(SCAMPER_DL_IS_ARP_OP_REPLY(dl) && SCAMPER_DL_IS_ARP_PRO_IPV4(dl))
    {
      if(patricia_count(tx_nd4) <= 0)
	return;
      ip.type = SCAMPER_ADDR_TYPE_IPV4;
      memcpy(&ip4, dl->dl_arp_spa, sizeof(ip4));
      ip.addr = &ip4;
      pt = tx_nd4;
    }
  else if(SCAMPER_DL_IS_ICMP6_ND_NADV(dl))
    {
      if(patricia_count(tx_nd6) <= 0)
	return;
      ip.type = SCAMPER_ADDR_TYPE_IPV6;
      memcpy(&ip6, dl->dl_icmp6_nd_target, sizeof(ip6));
      ip.addr = &ip6;
      pt = tx_nd6;
    }
  else return;

  sig.sig_type = SCAMPER_TASK_SIG_TYPE_TX_ND;
  sig.sig_tx_nd_ip = &ip;
  fm.sig = &sig;
  if((s2t = patricia_find(pt, &fm)) == NULL)
    return;

  if(s2t->task->funcs->handle_dl != NULL)
    s2t->task->funcs->handle_dl(s2t->task, dl);

  return;
}

#ifndef DISABLE_SCAMPER_SNIFF
static void sniff_check(scamper_dl_rec_t *dl)
{
  scamper_task_sig_t *sig;
  s2t_t *s2t;
  dlist_node_t *n;
  scamper_addr_t src;
  uint16_t id;

  if(dlist_count(sniff) <= 0)
    return;

  if(SCAMPER_DL_IS_ICMP_ECHO_REPLY(dl))
    id = dl->dl_icmp_id;
  else if(SCAMPER_DL_IS_ICMP_Q_ICMP_ECHO(dl))
    id = dl->dl_icmp_icmp_id;
  else
    return;

  if(SCAMPER_DL_IS_IPV4(dl))
    src.type = SCAMPER_ADDR_TYPE_IPV4;
  else if(SCAMPER_DL_IS_IPV6(dl))
    src.type = SCAMPER_ADDR_TYPE_IPV6;
  else
    return;
  src.addr = dl->dl_ip_dst;

  for(n = dlist_head_node(sniff); n != NULL; n = dlist_node_next(n))
    {
      s2t = dlist_node_item(n); sig = s2t->sig;
      if(sig->sig_sniff_icmp_id != id)
	continue;
      if(scamper_addr_cmp(sig->sig_sniff_src, &src) != 0)
	continue;

      if(s2t->task->funcs->handle_dl != NULL)
	s2t->task->funcs->handle_dl(s2t->task, dl);
    }

  return;
}
#endif

static void s2t_free(s2t_t *s2t)
{
  scamper_task_sig_t *sig = s2t->sig;
  trie_s2t_t fm, *ts2t;
  patricia_t *pt;

  if(s2t == NULL)
    return;

  if(s2t->node != NULL)
    {
      if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_IP)
	{
	  /* get the trie_s2t node that manages this address */
	  fm.addr = sig->sig_tx_ip_dst;
	  if(SCAMPER_ADDR_TYPE_IS_IPV4(sig->sig_tx_ip_dst))
	    pt = tx_ip4;
	  else
	    pt = tx_ip6;
	  ts2t = patricia_find(pt, &fm);
	  assert(ts2t != NULL);

	  /* remove the s2t from the trie_s2t node */
	  dlist_node_pop(ts2t->list, s2t->node);

	  /* if the address no longer has any tasks, remove from trie */
	  if(dlist_count(ts2t->list) == 0)
	    {
	      patricia_remove_node(pt, ts2t->node);
	      trie_s2t_free(ts2t);
	    }
	}
      else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_ND)
	{
	  if(sig->sig_tx_nd_ip->type == SCAMPER_ADDR_TYPE_IPV4)
	    patricia_remove_node(tx_nd4, s2t->node);
	  else
	    patricia_remove_node(tx_nd6, s2t->node);
	}
#ifndef DISABLE_SCAMPER_SNIFF
      else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_SNIFF)
	dlist_node_pop(sniff, s2t->node);
#endif
#ifndef DISABLE_SCAMPER_HOST
      else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_HOST)
	splaytree_remove_node(host, s2t->node);
#endif
    }

  free(s2t);
  return;
}

char *scamper_task_sig_tostr(scamper_task_sig_t *sig, char *buf, size_t len)
{
  char tmp[64];
  size_t off = 0;

  if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_IP)
    {
      string_concat(buf, len, &off, "ip %s",
		    scamper_addr_tostr(sig->sig_tx_ip_dst, tmp, sizeof(tmp)));
      if(sig->sig_tx_ip_proto == IPPROTO_ICMP)
	{
	  if(sig->sig_tx_ip_icmp_type == ICMP_ECHO)
	    string_concat(buf, len, &off, " icmp echo");
	  else if(sig->sig_tx_ip_icmp_type == ICMP_TSTAMP)
	    string_concat(buf, len, &off, " icmp time");
	  else
	    string_concat(buf, len, &off, " icmp");
	  string_concat(buf, len, &off, " id %d", sig->sig_tx_ip_icmp_id);
	}
      else if(sig->sig_tx_ip_proto == IPPROTO_ICMPV6)
	{
	  if(sig->sig_tx_ip_icmp_type == ICMP6_ECHO_REQUEST)
	    string_concat(buf, len, &off, " icmp echo");
	  else
	    string_concat(buf, len, &off, " icmp");
	  string_concat(buf, len, &off, " id %d", sig->sig_tx_ip_icmp_id);
	}
      else if(sig->sig_tx_ip_proto == IPPROTO_UDP)
	{
	  string_concat(buf, len, &off, " udp sport %d",
			sig->sig_tx_ip_udp_sport_x);
	  if(sig->sig_tx_ip_udp_sport_x != sig->sig_tx_ip_udp_sport_y)
	    string_concat(buf, len, &off, "-%d", sig->sig_tx_ip_udp_sport_y);
	  string_concat(buf, len, &off, " dport %d",
			sig->sig_tx_ip_udp_dport_x);
	  if(sig->sig_tx_ip_udp_dport_x != sig->sig_tx_ip_udp_dport_y)
	    string_concat(buf, len, &off, "-%d", sig->sig_tx_ip_udp_dport_y);
	}
      else if(sig->sig_tx_ip_proto == IPPROTO_TCP)
	{
	  string_concat(buf, len, &off, " tcp sport %d",
			sig->sig_tx_ip_tcp_sport_x);
	  if(sig->sig_tx_ip_tcp_sport_x != sig->sig_tx_ip_tcp_sport_y)
	    string_concat(buf, len, &off, "-%d", sig->sig_tx_ip_tcp_sport_y);
	  string_concat(buf, len, &off, " dport %d",
			sig->sig_tx_ip_tcp_dport_x);
	  if(sig->sig_tx_ip_tcp_dport_x != sig->sig_tx_ip_tcp_dport_y)
	    string_concat(buf, len, &off, "-%d", sig->sig_tx_ip_tcp_dport_y);
	}
    }
  else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_ND)
    string_concat(buf, len, &off, "nd %s",
		  scamper_addr_tostr(sig->sig_tx_nd_ip, tmp, sizeof(tmp)));
#ifndef DISABLE_SCAMPER_SNIFF
  else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_SNIFF)
    string_concat(buf, len, &off, "sniff %s icmp-id %04x",
		  scamper_addr_tostr(sig->sig_sniff_src, tmp, sizeof(tmp)),
		  sig->sig_sniff_icmp_id);
#endif
#ifndef DISABLE_SCAMPER_HOST
  else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_HOST)
    string_concat(buf, len, &off, "host %s %u",
		  sig->sig_host_name, sig->sig_host_type);
#endif
  else
    return NULL;

  return buf;
}

scamper_task_sig_t *scamper_task_sig_alloc(uint8_t type)
{
  scamper_task_sig_t *sig;
  if((sig = malloc_zero(sizeof(scamper_task_sig_t))) != NULL)
    sig->sig_type = type;
  return sig;
}

void scamper_task_sig_free(scamper_task_sig_t *sig)
{
  if(sig == NULL)
    return;

  switch(sig->sig_type)
    {
    case SCAMPER_TASK_SIG_TYPE_TX_IP:
      if(sig->sig_tx_ip_dst != NULL) scamper_addr_free(sig->sig_tx_ip_dst);
      if(sig->sig_tx_ip_src != NULL) scamper_addr_free(sig->sig_tx_ip_src);
      break;

    case SCAMPER_TASK_SIG_TYPE_TX_ND:
      if(sig->sig_tx_nd_ip != NULL) scamper_addr_free(sig->sig_tx_nd_ip);
      break;

#ifndef DISABLE_SCAMPER_SNIFF
    case SCAMPER_TASK_SIG_TYPE_SNIFF:
      if(sig->sig_sniff_src != NULL) scamper_addr_free(sig->sig_sniff_src);
      break;
#endif

#ifndef DISABLE_SCAMPER_HOST
    case SCAMPER_TASK_SIG_TYPE_HOST:
      if(sig->sig_host_name != NULL) free(sig->sig_host_name);
      if(sig->sig_host_dst != NULL) scamper_addr_free(sig->sig_host_dst);
      break;
#endif
    }

  free(sig);
  return;
}

scamper_task_anc_t *scamper_task_anc_add(scamper_task_t *task, void *data,
					 void (*freedata)(void *))
{
  scamper_task_anc_t *anc = NULL;
  if(task->ancillary == NULL && (task->ancillary = dlist_alloc()) == NULL)
    return NULL;
  if((anc = malloc_zero(sizeof(scamper_task_anc_t))) == NULL)
    return NULL;
  anc->data = data;
  anc->freedata = freedata;
  if((anc->node = dlist_tail_push(task->ancillary, anc)) == NULL)
    {
      free(anc);
      return NULL;
    }
  return anc;
}

void scamper_task_anc_del(scamper_task_t *task, scamper_task_anc_t *anc)
{
  if(anc == NULL)
    return;
  dlist_node_pop(task->ancillary, anc->node);
  free(anc);
  return;
}

int scamper_task_sig_add(scamper_task_t *task, scamper_task_sig_t *sig)
{
  s2t_t *s2t;
  if((s2t = malloc_zero(sizeof(s2t_t))) == NULL)
    return -1;
  s2t->sig = sig;
  s2t->task = task;
  if(slist_tail_push(task->siglist, s2t) == NULL)
    {
      free(s2t);
      return -1;
    }
  return 0;
}

static int overlap(uint16_t a, uint16_t b, uint16_t x, uint16_t y)
{
  if((a <= x && y <= b) || (a >= x && y >= b) ||
     (a < x && b >= x) || (x < a && y >= a))
    return 1;
  return 0;
}

static int s2t_tx_ip_overlap(scamper_task_sig_t *a, scamper_task_sig_t *b)
{
  if(a->sig_tx_ip_proto != b->sig_tx_ip_proto)
    return 0;
  if(a->sig_tx_ip_proto == IPPROTO_ICMP || a->sig_tx_ip_proto == IPPROTO_ICMPV6)
    {
      if(a->sig_tx_ip_icmp_type != b->sig_tx_ip_icmp_type)
	return 0;
      if(a->sig_tx_ip_icmp_id != b->sig_tx_ip_icmp_id)
	return 0;
      return 1;
    }
  else if(a->sig_tx_ip_proto == IPPROTO_UDP)
    {
      if(overlap(a->sig_tx_ip_udp_sport_x, a->sig_tx_ip_udp_sport_y,
		 b->sig_tx_ip_udp_sport_x, b->sig_tx_ip_udp_sport_y) == 0)
	return 0;
      if(overlap(a->sig_tx_ip_udp_dport_x, a->sig_tx_ip_udp_dport_y,
		 b->sig_tx_ip_udp_dport_x, b->sig_tx_ip_udp_dport_y) == 0)
	return 0;
    }
  else
    {
      assert(a->sig_tx_ip_proto == IPPROTO_TCP);
      if(overlap(a->sig_tx_ip_tcp_sport_x, a->sig_tx_ip_tcp_sport_y,
		 b->sig_tx_ip_tcp_sport_x, b->sig_tx_ip_tcp_sport_y) == 0)
	return 0;
      if(overlap(a->sig_tx_ip_tcp_dport_x, a->sig_tx_ip_tcp_dport_y,
		 b->sig_tx_ip_tcp_dport_x, b->sig_tx_ip_tcp_dport_y) == 0)
	return 0;
    }

  return 1;
}

int scamper_task_sig_sport_used(scamper_addr_t *dst, uint8_t proto,
				uint16_t sport, uint16_t dport)
{
  scamper_task_sig_t sig;
  trie_s2t_t ts2t_fm, *ts2t;
  dlist_node_t *dn;
  s2t_t *s2t = NULL;

  sig.sig_tx_ip_dst = dst;
  if(proto == IPPROTO_TCP)
    SCAMPER_TASK_SIG_TCP(&sig, sport, dport);
  else if(proto == IPPROTO_UDP)
    SCAMPER_TASK_SIG_UDP(&sig, sport, dport);
  else if((proto == IPPROTO_ICMP && SCAMPER_ADDR_TYPE_IS_IPV4(dst)) ||
	  (proto == IPPROTO_ICMPV6 && SCAMPER_ADDR_TYPE_IS_IPV6(dst)))
    SCAMPER_TASK_SIG_ICMP_ECHO(&sig, sport);
  else
    return -1;

  /*
   * if we don't have any measurement to that address, then the port
   * is clear
   */
  ts2t_fm.addr = dst;
  if(SCAMPER_ADDR_TYPE_IS_IPV4(dst))
    ts2t = patricia_find(tx_ip4, &ts2t_fm);
  else
    ts2t = patricia_find(tx_ip6, &ts2t_fm);
  if(ts2t == NULL)
    return 0;

  /* check to see if there's an overlapping signature */
  for(dn=dlist_head_node(ts2t->list); dn != NULL; dn=dlist_node_next(dn))
    {
      s2t = dlist_node_item(dn);
      if(s2t_tx_ip_overlap(&sig, s2t->sig) != 0)
	return 1;
    }

  return 0;
}

scamper_task_t *scamper_task_find(scamper_task_sig_t *sig)
{
  trie_s2t_t ts2t_fm, *ts2t;
  dlist_node_t *dn;
  s2t_t s2t_fm, *s2t = NULL;

  if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_IP)
    {
      ts2t_fm.addr = sig->sig_tx_ip_dst;
      if(SCAMPER_ADDR_TYPE_IS_IPV4(sig->sig_tx_ip_dst))
	ts2t = patricia_find(tx_ip4, &ts2t_fm);
      else
	ts2t = patricia_find(tx_ip6, &ts2t_fm);
      if(ts2t == NULL)
	return NULL;
      for(dn=dlist_head_node(ts2t->list); dn != NULL; dn=dlist_node_next(dn))
	{
	  s2t = dlist_node_item(dn);
	  if(s2t_tx_ip_overlap(sig, s2t->sig) != 0)
	    break;
	}
      if(dn == NULL)
	s2t = NULL;
    }
  else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_ND)
    {
      s2t_fm.sig = sig;
      if(sig->sig_tx_nd_ip->type == SCAMPER_ADDR_TYPE_IPV4)
	s2t = patricia_find(tx_nd4, &s2t_fm);
      else
	s2t = patricia_find(tx_nd6, &s2t_fm);
    }
#ifndef DISABLE_SCAMPER_HOST
  else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_HOST)
    {
      s2t_fm.sig = sig;
      s2t = splaytree_find(host, &s2t_fm);
    }
#endif
#ifndef DISABLE_SCAMPER_SNIFF
  else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_SNIFF)
    {
      return NULL;
    }
#endif

  if(s2t != NULL)
    return s2t->task;
  return NULL;
}

void scamper_task_sig_deinstall(scamper_task_t *task)
{
  s2t_t *s2t;
  scamper_task_sig_t *sig;
  slist_node_t *n;

  for(n=slist_head_node(task->siglist); n != NULL; n = slist_node_next(n))
    {
      s2t = slist_node_item(n); sig = s2t->sig;
      s2t_free(s2t);
      scamper_task_sig_free(sig);
    }

  return;
}

int scamper_task_sig_install(scamper_task_t *task)
{
  scamper_task_sig_t *sig;
  scamper_task_t *tf;
  trie_s2t_t *ts2t, fm;
  patricia_t *pt;
  s2t_t *s2t;
  slist_node_t *n;

#if 0
  if(slist_count(task->siglist) < 1)
    {
      printerror(__func__, "no signatures for task");
      return -1;
    }
#endif

  for(n=slist_head_node(task->siglist); n != NULL; n = slist_node_next(n))
    {
      s2t = slist_node_item(n); sig = s2t->sig;

      /* check if another task has this signature already */
      if((tf = scamper_task_find(sig)) != NULL)
	{
	  if(tf != task)
	    goto err;
	  continue;
	}

      if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_IP)
	{
	  if(sig->sig_tx_ip_dst->type == SCAMPER_ADDR_TYPE_IPV4)
	    pt = tx_ip4;
	  else
	    pt = tx_ip6;
	  fm.addr = sig->sig_tx_ip_dst;
	  if((ts2t = patricia_find(pt, &fm)) == NULL)
	    {
	      if((ts2t = trie_s2t_alloc(sig->sig_tx_ip_dst)) == NULL)
		{
		  scamper_debug(__func__, "could not alloc ts2t");
		  goto err;
		}
	      if((ts2t->node = patricia_insert(pt, ts2t)) == NULL)
		{
		  scamper_debug(__func__, "could not install ts2t");
		  trie_s2t_free(ts2t);
		  goto err;
		}
	    }
	  s2t->node = dlist_head_push(ts2t->list, s2t);

	  /* if we weren't able to insert the s2t, free addr */
	  if(s2t->node == NULL && dlist_count(ts2t->list) == 0)
	    {
	      patricia_remove_node(pt, ts2t->node);
	      trie_s2t_free(ts2t);
	    }
	}
      else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_ND)
	{
	  if(sig->sig_tx_nd_ip->type == SCAMPER_ADDR_TYPE_IPV4)
	    s2t->node = patricia_insert(tx_nd4, s2t);
	  else
	    s2t->node = patricia_insert(tx_nd6, s2t);
	}
#ifndef DISABLE_SCAMPER_SNIFF
      else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_SNIFF)
	s2t->node = dlist_tail_push(sniff, s2t);
#endif
#ifndef DISABLE_SCAMPER_HOST
      else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_HOST)
	s2t->node = splaytree_insert(host, s2t);
#endif

      if(s2t->node == NULL)
	{
	  scamper_debug(__func__, "could not install sig");
	  goto err;
	}
    }

  return 0;

 err:
  scamper_task_sig_deinstall(task);
  return -1;
}

/*
 * scamper_task_sig_block
 *
 * go through the signatures and see if any conflict with other tasks.
 * if there is a conflict, return the task, otherwise return NULL.
 * scamper_task_sig_install assumes that this function has been called.
 */
scamper_task_t *scamper_task_sig_block(scamper_task_t *task)
{
  scamper_task_sig_t *sig;
  scamper_task_t *tf;
  slist_node_t *n;
  s2t_t *s2t;

  for(n=slist_head_node(task->siglist); n != NULL; n = slist_node_next(n))
    {
      s2t = slist_node_item(n); sig = s2t->sig;
      if((tf = scamper_task_find(sig)) != NULL && tf != task)
	return tf;
    }

  return NULL;
}

void *scamper_task_onhold(scamper_task_t *task, void *param,
			  void (*unhold)(void *param))
{
  task_onhold_t *toh = NULL;
  dlist_node_t *cookie;

  if(task->onhold == NULL && (task->onhold = dlist_alloc()) == NULL)
    goto err;
  if((toh = malloc_zero(sizeof(task_onhold_t))) == NULL)
    goto err;
  if((cookie = dlist_tail_push(task->onhold, toh)) == NULL)
    goto err;

  toh->param = param;
  toh->unhold = unhold;

  return cookie;

 err:
  if(toh != NULL) free(toh);
  return NULL;
}

int scamper_task_dehold(scamper_task_t *task, void *cookie)
{
  task_onhold_t *toh;
  assert(task->onhold != NULL);
  if((toh = dlist_node_pop(task->onhold, cookie)) == NULL)
    return -1;
  free(toh);
  return 0;
}

/*
 * scamper_task_alloc
 *
 * allocate and initialise a task object.
 */
scamper_task_t *scamper_task_alloc(void *data, scamper_task_funcs_t *funcs)
{
  scamper_task_t *task;

  assert(data  != NULL);
  assert(funcs != NULL);

  if((task = malloc_zero(sizeof(scamper_task_t))) == NULL)
    {
      printerror(__func__, "could not malloc task");
      goto err;
    }

  if((task->queue = scamper_queue_alloc(task)) == NULL)
    goto err;

  if((task->siglist = slist_alloc()) == NULL)
    goto err;

  task->funcs = funcs;
  task->data = data;

  return task;

 err:
  if(task != NULL) scamper_task_free(task);
  return NULL;
}

/*
 * scamper_task_free
 *
 * free a task structure.
 * this involves freeing the task using the free pointer provided,
 * freeing the queue data structure, unholding any tasks blocked, and
 * finally freeing the task structure itself.
 */
void scamper_task_free(scamper_task_t *task)
{
  scamper_task_anc_t *anc;
  task_onhold_t *toh;
  size_t i;

  if(task->funcs != NULL)
    task->funcs->task_free(task);

  if(task->queue != NULL)
    {
      scamper_queue_free(task->queue);
      task->queue = NULL;
    }

  if(task->onhold != NULL)
    {
      while((toh = dlist_head_pop(task->onhold)) != NULL)
	{
	  toh->unhold(toh->param);
	  free(toh);
	}
      dlist_free(task->onhold);
    }

  if(task->cyclemon != NULL)
    {
      scamper_cyclemon_unuse(task->cyclemon);
      task->cyclemon = NULL;
    }

  if(task->sourcetask != NULL)
    {
      scamper_sourcetask_free(task->sourcetask);
      task->sourcetask = NULL;
    }

  if(task->siglist != NULL)
    {
      scamper_task_sig_deinstall(task);
      slist_free(task->siglist);
    }

  if(task->ancillary != NULL)
    {
      while((anc = dlist_head_pop(task->ancillary)) != NULL)
	{
	  anc->node = NULL;
	  anc->freedata(anc->data);
	  free(anc);
	}
      dlist_free(task->ancillary);
    }

  if(task->fds != NULL)
    {
      for(i=0; i<task->fdc; i++)
	scamper_fd_free(task->fds[i]);
      free(task->fds);
    }

  free(task);
  return;
}

void *scamper_task_getdata(const scamper_task_t *task)
{
  return task->data;
}

void *scamper_task_getstate(const scamper_task_t *task)
{
  return task->state;
}

void scamper_task_setdatanull(scamper_task_t *task)
{
  task->data = NULL;
  return;
}

void scamper_task_setstate(scamper_task_t *task, void *state)
{
  task->state = state;
  return;
}

scamper_source_t *scamper_task_getsource(scamper_task_t *task)
{
  if(task->sourcetask == NULL) return NULL;
  return scamper_sourcetask_getsource(task->sourcetask);
}

scamper_sourcetask_t *scamper_task_getsourcetask(scamper_task_t *task)
{
  return task->sourcetask;
}

void scamper_task_setsourcetask(scamper_task_t *task, scamper_sourcetask_t *st)
{
  assert(task->sourcetask == NULL);
  task->sourcetask = st;
  return;
}

void scamper_task_setcyclemon(scamper_task_t *task, scamper_cyclemon_t *cm)
{
  task->cyclemon = scamper_cyclemon_use(cm);
  return;
}

void scamper_task_write(scamper_task_t *task, scamper_file_t *file)
{
  task->funcs->write(file, task);
  return;
}

void scamper_task_probe(scamper_task_t *task)
{
  task->funcs->probe(task);
  return;
}

void scamper_task_halt(scamper_task_t *task)
{
  task->funcs->halt(task);
  return;
}

void scamper_task_handleicmp(scamper_icmp_resp_t *resp)
{
  scamper_task_t *last_task = NULL;
  trie_s2t_t *ts2t, fm;
  scamper_addr_t addr;
  dlist_node_t *dn;
  patricia_t *pt;
  s2t_t *s2t;
  int print = 0;

  if(SCAMPER_ICMP_RESP_IS_TTL_EXP(resp) ||
     SCAMPER_ICMP_RESP_IS_UNREACH(resp) ||
     SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(resp) ||
     SCAMPER_ICMP_RESP_IS_PARAMPROB(resp))
    {
      /* the probe signature is embedded in the response */
      if(!SCAMPER_ICMP_RESP_INNER_IS_SET(resp))
	return;
      if(scamper_icmp_resp_inner_dst(resp, &addr) != 0)
	return;
    }
  else if(SCAMPER_ICMP_RESP_IS_ECHO_REPLY(resp) ||
	  SCAMPER_ICMP_RESP_IS_TIME_REPLY(resp))
    {
      /* the probe signature is an ICMP echo/ts request */
      if(scamper_icmp_resp_src(resp, &addr) != 0)
	return;
    }
  else
    {
      return;
    }

  fm.addr = &addr;
  if(SCAMPER_ADDR_TYPE_IS_IPV4(&addr))
    pt = tx_ip4;
  else
    pt = tx_ip6;
  if((ts2t = patricia_find(pt, &fm)) == NULL)
    return;

  for(dn=dlist_head_node(ts2t->list); dn != NULL; dn=dlist_node_next(dn))
    {
      s2t = dlist_node_item(dn);
      if(s2t->task == last_task)
	continue;
      last_task = s2t->task;
      if(s2t->task->funcs->handle_icmp != NULL)
	{
	  if(print == 0)
	    {
	      scamper_icmp_resp_print(resp);
	      print = 1;
	    }
	  s2t->task->funcs->handle_icmp(s2t->task, resp);
	}
    }
  return;
}

void scamper_task_handledl(scamper_dl_rec_t *dl)
{
  tx_ip_check(dl);
  tx_nd_check(dl);
#ifndef DISABLE_SCAMPER_SNIFF
  sniff_check(dl);
#endif
  return;
}

void scamper_task_handleudp(scamper_udp_resp_t *ur)
{
  scamper_task_t *last_task = NULL;
  trie_s2t_t *ts2t, fm;
  scamper_addr_t addr;
  dlist_node_t *dn;
  patricia_t *pt;
  s2t_t *s2t;

  fm.addr = &addr;
  addr.addr = ur->addr;
  if(ur->af == AF_INET)
    {
      addr.type = SCAMPER_ADDR_TYPE_IPV4;
      pt = tx_ip4;
    }
  else
    {
      addr.type = SCAMPER_ADDR_TYPE_IPV6;
      pt = tx_ip6;
    }
  if((ts2t = patricia_find(pt, &fm)) == NULL)
    return;

  for(dn=dlist_head_node(ts2t->list); dn != NULL; dn=dlist_node_next(dn))
    {
      s2t = dlist_node_item(dn);
      if(s2t->task == last_task)
	continue;
      last_task = s2t->task;
      if(s2t->task->funcs->handle_udp != NULL)
	{
	  s2t->task->funcs->handle_udp(s2t->task, ur);
	}
    }
  return;
}

void scamper_task_handletimeout(scamper_task_t *task)
{
  if(task->funcs->handle_timeout != NULL)
    task->funcs->handle_timeout(task);
  return;
}

int scamper_task_queue_probe(scamper_task_t *task)
{
  return scamper_queue_probe(task->queue);
}

int scamper_task_queue_probe_head(scamper_task_t *task)
{
  return scamper_queue_probe_head(task->queue);
}

int scamper_task_queue_wait(scamper_task_t *task, int ms)
{
  return scamper_queue_wait(task->queue, ms);
}

int scamper_task_queue_wait_tv(scamper_task_t *task, struct timeval *tv)
{
  return scamper_queue_wait_tv(task->queue, tv);
}

int scamper_task_queue_done(scamper_task_t *task, int ms)
{
  return scamper_queue_done(task->queue, ms);
}

int scamper_task_queue_isprobe(scamper_task_t *task)
{
  return scamper_queue_isprobe(task->queue);
}

int scamper_task_queue_isdone(scamper_task_t *task)
{
  return scamper_queue_isdone(task->queue);
}

static int task_fd_cmp(const scamper_fd_t *a, const scamper_fd_t *b)
{
  if(a < b) return -1;
  if(a > b) return  1;
  return 0;
}

/*
 * task_fd
 *
 * make sure the task has a hold on this fd.
 */
static scamper_fd_t *task_fd(scamper_task_t *t, scamper_fd_t *fd)
{
  if(fd == NULL)
    return NULL;

  if(array_find((void **)t->fds, t->fdc, fd, (array_cmp_t)task_fd_cmp) == NULL)
    {
      if(array_insert((void ***)&t->fds, &t->fdc, fd,
		      (array_cmp_t)task_fd_cmp) != 0)
	{
	  scamper_fd_free(fd);
	  return NULL;
	}
    }
  else
    {
      /* already have a hold of the fd */
      scamper_fd_free(fd);
    }
  return fd;
}

scamper_fd_t *scamper_task_fd_icmp4(scamper_task_t *task, void *addr)
{
  scamper_fd_t *fd = scamper_fd_icmp4(addr);
  return task_fd(task, fd);
}

scamper_fd_t *scamper_task_fd_icmp6(scamper_task_t *task, void *addr)
{
  scamper_fd_t *fd = scamper_fd_icmp6(addr);
  return task_fd(task, fd);
}

scamper_fd_t *scamper_task_fd_udp4(scamper_task_t *task, void *a, uint16_t sp)
{
  if(task_fd(task, scamper_fd_udp4dg(a, sp)) == NULL)
    return NULL;
  return task_fd(task, scamper_fd_udp4raw(a));
}

scamper_fd_t *scamper_task_fd_udp6(scamper_task_t *task, void *a, uint16_t sp)
{
  scamper_fd_t *fd = scamper_fd_udp6(a, sp);
  return task_fd(task, fd);
}

scamper_fd_t *scamper_task_fd_tcp4(scamper_task_t *task, void *a, uint16_t sp)
{
  scamper_fd_t *fd = scamper_fd_tcp4(a, sp);
  return task_fd(task, fd);
}

scamper_fd_t *scamper_task_fd_tcp6(scamper_task_t *task, void *a, uint16_t sp)
{
  scamper_fd_t *fd = scamper_fd_tcp6(a, sp);
  return task_fd(task, fd);
}

scamper_fd_t *scamper_task_fd_dl(scamper_task_t *task, int ifindex)
{
  scamper_fd_t *fd = scamper_fd_dl(ifindex);
  return task_fd(task, fd);
}

scamper_fd_t *scamper_task_fd_ip4(scamper_task_t *task)
{
  scamper_fd_t *fd = scamper_fd_ip4();
  return task_fd(task, fd);
}

#ifndef _WIN32 /* windows does not have a routing socket */
scamper_fd_t *scamper_task_fd_rtsock(scamper_task_t *task)
{
  scamper_fd_t *fd = scamper_fd_rtsock();
  return task_fd(task, fd);
}
#endif

int scamper_task_init(void)
{
  if((tx_ip4 = patricia_alloc((patricia_bit_t)tx_ip_bit,
			      (patricia_cmp_t)tx_ip_cmp,
			      (patricia_fbd_t)tx_ip_fbd)) == NULL)
    return -1;
  if((tx_ip6 = patricia_alloc((patricia_bit_t)tx_ip_bit,
			      (patricia_cmp_t)tx_ip_cmp,
			      (patricia_fbd_t)tx_ip_fbd)) == NULL)
    return -1;
  if((tx_nd4 = patricia_alloc((patricia_bit_t)tx_nd_bit,
			      (patricia_cmp_t)tx_nd_cmp,
			      (patricia_fbd_t)tx_nd_fbd)) == NULL)
    return -1;
  if((tx_nd6 = patricia_alloc((patricia_bit_t)tx_nd_bit,
			      (patricia_cmp_t)tx_nd_cmp,
			      (patricia_fbd_t)tx_nd_fbd)) == NULL)
    return -1;
#ifndef DISABLE_SCAMPER_HOST
  if((host = splaytree_alloc((splaytree_cmp_t)host_cmp)) == NULL)
    return -1;
#endif
#ifndef DISABLE_SCAMPER_SNIFF
  if((sniff = dlist_alloc()) == NULL)
    return -1;
#endif
  return 0;
}

void scamper_task_cleanup(void)
{
  if(tx_ip4 != NULL) { patricia_free(tx_ip4); tx_ip4 = NULL; }
  if(tx_ip6 != NULL) { patricia_free(tx_ip6); tx_ip6 = NULL; }
  if(tx_nd4 != NULL) { patricia_free(tx_nd4); tx_nd4 = NULL; }
  if(tx_nd6 != NULL) { patricia_free(tx_nd6); tx_nd6 = NULL; }
#ifndef DISABLE_SCAMPER_HOST
  if(host != NULL)   { splaytree_free(host, NULL); host = NULL; }
#endif
#ifndef DISABLE_SCAMPER_SNIFF
  if(sniff != NULL)  { dlist_free(sniff); sniff = NULL; }
#endif
  return;
}
