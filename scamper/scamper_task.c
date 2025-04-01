/*
 * scamper_task.c
 *
 * $Id: scamper_task.c,v 1.107 2025/03/31 10:25:38 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2016-2024 Matthew Luckie
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

typedef struct task_onhold
{
  scamper_task_t *blocker; /* the task that is the blocker */
  scamper_task_t *blocked; /* the task that is blocked */
  dlist_node_t   *node;    /* node in blocker->onhold */
} task_onhold_t;

struct scamper_task
{
  /* the data pointer points to the collected data */
  void                     *data;

  /* any state kept during the data collection is kept here */
  void                     *state;

  /* various callbacks that scamper uses to handle this task */
  scamper_task_funcs_t     *funcs;

  /* list of task_onhold_t, if tasks are blocked on this task */
  dlist_t                  *onhold;

  /* if this task is blocked, structure pointing to the blocker */
  task_onhold_t            *toh;

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
 * trie_addr_t
 *
 * a mapping from an address being probed to all of the signatures
 * belonging to the address.
 *
 * the s2t_list contains s2t_t entries.  the code that uses this list
 * assumes that tasks the s2t_t entries point to appear contiguously.
 */
typedef struct trie_addr
{
  scamper_addr_t     *addr;
  dlist_t            *s2t_list;
  dlist_t            *s2x_list;
  patricia_node_t    *node;
} trie_addr_t;

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

/*
 * s2x_t
 *
 * a mapping of a signature to an expiry time.
 */
typedef struct s2x
{
  scamper_task_sig_t *sig;
  struct timeval      expiry;
  dlist_node_t       *node;
} s2x_t;

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
static slist_t     *expire = NULL;

extern int          holdtime;

static int tx_ip_cmp(const trie_addr_t *a, const trie_addr_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static int tx_ip_bit(const trie_addr_t *ta, int bit)
{
  return scamper_addr_bit(ta->addr, bit);
}

static int tx_ip_fbd(const trie_addr_t *a, const trie_addr_t *b)
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

static void trie_addr_free(trie_addr_t *ta)
{
  if(ta->s2t_list != NULL) dlist_free(ta->s2t_list);
  if(ta->s2x_list != NULL) dlist_free(ta->s2x_list);
  if(ta->addr != NULL) scamper_addr_free(ta->addr);
  free(ta);
  return;
}

static trie_addr_t *trie_addr_alloc(scamper_addr_t *addr)
{
  trie_addr_t *ta;
  if((ta = malloc_zero(sizeof(trie_addr_t))) == NULL ||
     (ta->s2t_list = dlist_alloc()) == NULL ||
     (ta->s2x_list = dlist_alloc()) == NULL)
    goto err;
  ta->addr = scamper_addr_use(addr);
  return ta;
 err:
  if(ta != NULL) trie_addr_free(ta);
  return NULL;
}

static void trie_addr_remove(trie_addr_t *ta)
{
  if(SCAMPER_ADDR_TYPE_IS_IPV4(ta->addr))
    patricia_remove_node(tx_ip4, ta->node);
  else
    patricia_remove_node(tx_ip6, ta->node);
  ta->node = NULL;
  return;
}

static trie_addr_t *trie_addr_find(scamper_addr_t *addr)
{
  trie_addr_t fm;
  fm.addr = addr;
  if(SCAMPER_ADDR_TYPE_IS_IPV4(addr))
    return patricia_find(tx_ip4, &fm);
  return patricia_find(tx_ip6, &fm);
}

static int trie_addr_isempty(const trie_addr_t *ta)
{
  if(dlist_count(ta->s2t_list) > 0 || dlist_count(ta->s2x_list) > 0)
    return 0;
  return 1;
}

static void tx_ip_check(scamper_dl_rec_t *dl)
{
  scamper_addr_t addr, addr2buf, *addr2 = NULL;
  scamper_task_t *last_task = NULL;
  patricia_t *pt;
  trie_addr_t fm, *ta;
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
      if((ta = patricia_find(pt, &fm)) != NULL)
	{
	  for(dn=dlist_head_node(ta->s2t_list); dn != NULL;
	      dn=dlist_node_next(dn))
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

char *scamper_task_sig_tostr(scamper_task_sig_t *sig, char *buf, size_t len)
{
  char tmp[64];
  size_t off = 0;

  if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_IP)
    {
      string_concat2(buf, len, &off, "ip ",
		     scamper_addr_tostr(sig->sig_tx_ip_dst, tmp, sizeof(tmp)));
      if(sig->sig_tx_ip_proto == IPPROTO_ICMP)
	{
	  if(sig->sig_tx_ip_icmp_type == ICMP_ECHO)
	    string_concat(buf, len, &off, " icmp echo");
	  else if(sig->sig_tx_ip_icmp_type == ICMP_TSTAMP)
	    string_concat(buf, len, &off, " icmp time");
	  else
	    string_concat(buf, len, &off, " icmp");
	  string_concaf(buf, len, &off, " id %d", sig->sig_tx_ip_icmp_id);
	}
      else if(sig->sig_tx_ip_proto == IPPROTO_ICMPV6)
	{
	  if(sig->sig_tx_ip_icmp_type == ICMP6_ECHO_REQUEST)
	    string_concat(buf, len, &off, " icmp echo");
	  else
	    string_concat(buf, len, &off, " icmp");
	  string_concaf(buf, len, &off, " id %d", sig->sig_tx_ip_icmp_id);
	}
      else if(sig->sig_tx_ip_proto == IPPROTO_UDP)
	{
	  string_concaf(buf, len, &off, " udp sport %d",
			sig->sig_tx_ip_udp_sport_x);
	  if(sig->sig_tx_ip_udp_sport_x != sig->sig_tx_ip_udp_sport_y)
	    string_concaf(buf, len, &off, "-%d", sig->sig_tx_ip_udp_sport_y);
	  string_concaf(buf, len, &off, " dport %d",
			sig->sig_tx_ip_udp_dport_x);
	  if(sig->sig_tx_ip_udp_dport_x != sig->sig_tx_ip_udp_dport_y)
	    string_concaf(buf, len, &off, "-%d", sig->sig_tx_ip_udp_dport_y);
	}
      else if(sig->sig_tx_ip_proto == IPPROTO_TCP)
	{
	  string_concaf(buf, len, &off, " tcp sport %d",
			sig->sig_tx_ip_tcp_sport_x);
	  if(sig->sig_tx_ip_tcp_sport_x != sig->sig_tx_ip_tcp_sport_y)
	    string_concaf(buf, len, &off, "-%d", sig->sig_tx_ip_tcp_sport_y);
	  string_concaf(buf, len, &off, " dport %d",
			sig->sig_tx_ip_tcp_dport_x);
	  if(sig->sig_tx_ip_tcp_dport_x != sig->sig_tx_ip_tcp_dport_y)
	    string_concaf(buf, len, &off, "-%d", sig->sig_tx_ip_tcp_dport_y);
	}
    }
  else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_ND)
    string_concat2(buf, len, &off, "nd ",
		   scamper_addr_tostr(sig->sig_tx_nd_ip, tmp, sizeof(tmp)));
#ifndef DISABLE_SCAMPER_SNIFF
  else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_SNIFF)
    string_concaf(buf, len, &off, "sniff %s icmp-id %04x",
		  scamper_addr_tostr(sig->sig_sniff_src, tmp, sizeof(tmp)),
		  sig->sig_sniff_icmp_id);
#endif
#ifndef DISABLE_SCAMPER_HOST
  else if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_HOST)
    string_concaf(buf, len, &off, "host %s %u",
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
  if((task->siglist == NULL && (task->siglist = slist_alloc()) == NULL) ||
     (s2t = malloc_zero(sizeof(s2t_t))) == NULL)
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

static int sig_tx_ip_overlap(const scamper_task_sig_t *a,
			     const scamper_task_sig_t *b)
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

static int trie_addr_sig_tx_ip_overlap(const scamper_task_sig_t *sig)
{
  trie_addr_t *ta;
  dlist_node_t *dn;
  s2t_t *s2t;
  s2x_t *s2x;

  /*
   * if we don't have any measurement to that address, then the port
   * is clear
   */
  if((ta = trie_addr_find(sig->sig_tx_ip_dst)) == NULL)
    return 0;

  for(dn=dlist_head_node(ta->s2t_list); dn != NULL; dn=dlist_node_next(dn))
    {
      s2t = dlist_node_item(dn);
      if(sig_tx_ip_overlap(sig, s2t->sig) != 0)
	return 1;
    }
  for(dn=dlist_head_node(ta->s2x_list); dn != NULL; dn=dlist_node_next(dn))
    {
      s2x = dlist_node_item(dn);
      if(sig_tx_ip_overlap(sig, s2x->sig) != 0)
	return 1;
    }

  return 0;
}

int scamper_task_sig_icmpid_used(scamper_addr_t *dst, uint8_t type, uint16_t id)
{
  scamper_task_sig_t sig;

  sig.sig_tx_ip_dst = dst;
  if(SCAMPER_ADDR_TYPE_IS_IPV4(dst))
    {
      if(type == ICMP_ECHO)
	SCAMPER_TASK_SIG_ICMP_ECHO(&sig, id);
      else if(type == ICMP_TSTAMP)
	SCAMPER_TASK_SIG_ICMP_TIME(&sig, id);
      else
	return -1;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(dst))
    {
      if(type == ICMP6_ECHO_REQUEST)
	SCAMPER_TASK_SIG_ICMP_ECHO(&sig, id);
      else
	return -1;
    }

  /* check to see if there's an overlapping signature */
  return trie_addr_sig_tx_ip_overlap(&sig);
}

int scamper_task_sig_sport_used(scamper_addr_t *dst, uint8_t proto,
				uint16_t sport, uint16_t dport)
{
  scamper_task_sig_t sig;

  sig.sig_tx_ip_dst = dst;
  if(proto == IPPROTO_TCP)
    SCAMPER_TASK_SIG_TCP(&sig, sport, dport);
  else if(proto == IPPROTO_UDP)
    SCAMPER_TASK_SIG_UDP(&sig, sport, dport);
  else
    return -1;

  /* check to see if there's an overlapping signature */
  return trie_addr_sig_tx_ip_overlap(&sig);
}

scamper_task_t *scamper_task_find(scamper_task_sig_t *sig)
{
  trie_addr_t *ta;
  dlist_node_t *dn;
  s2t_t s2t_fm, *s2t = NULL;

  if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_IP)
    {
      if((ta = trie_addr_find(sig->sig_tx_ip_dst)) == NULL)
	return NULL;
      for(dn=dlist_head_node(ta->s2t_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  s2t = dlist_node_item(dn);
	  if(sig_tx_ip_overlap(sig, s2t->sig) != 0)
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

static void s2t_tx_ip_deinstall(s2t_t *s2t, struct timeval *expiry)
{
  scamper_task_sig_t *sig = s2t->sig;
  trie_addr_t *ta;
  s2x_t *s2x = NULL;

  assert(s2t->node != NULL);

  /* get the trie_addr node that manages this address */
  ta = trie_addr_find(sig->sig_tx_ip_dst);
  assert(ta != NULL);

  /* remove the s2t from the trie_addr node */
  dlist_node_pop(ta->s2t_list, s2t->node);

  /*
   * try to add an expiry entry for the signature.  if we fail,
   * then check if we still need the trie_addr_t.
   */
  if(expiry != NULL &&
     (s2x = malloc_zero(sizeof(s2x_t))) != NULL &&
     (s2x->node = dlist_tail_push(ta->s2x_list, s2x)) != NULL &&
     slist_tail_push(expire, s2x) != NULL)
    {
      timeval_cpy(&s2x->expiry, expiry);
      s2x->sig = sig;
      return;
    }

  /* clean up any attempt to add expiry node */
  if(s2x != NULL)
    {
      if(s2x->node != NULL)
	dlist_node_pop(ta->s2x_list, s2x->node);
      free(s2x);
    }

  /* if the address no longer has any signatures, remove from trie */
  if(trie_addr_isempty(ta))
    {
      trie_addr_remove(ta);
      trie_addr_free(ta);
    }

  scamper_task_sig_free(sig);
  return;
}

static void scamper_task_sig_deinstall(scamper_task_t *task)
{
  scamper_task_sig_t *sig;
  struct timeval expiry;
  int exp_set = 0;
  s2t_t *s2t;

  if(task->siglist == NULL)
    return;

  while((s2t = slist_head_pop(task->siglist)) != NULL)
    {
      sig = s2t->sig;

      if(s2t->node != NULL)
	{
	  if(sig->sig_type == SCAMPER_TASK_SIG_TYPE_TX_IP)
	    {
	      if(exp_set == 0 && holdtime > 0)
		{
		  gettimeofday_wrap(&expiry);
		  expiry.tv_sec += holdtime;
		  exp_set = 1;
		}
	      s2t_tx_ip_deinstall(s2t, holdtime > 0 ? &expiry : NULL);
	      sig = NULL;
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

      if(sig != NULL)
	scamper_task_sig_free(sig);
    }

  return;
}

int scamper_task_sig_install(scamper_task_t *task)
{
  scamper_task_sig_t *sig;
  scamper_task_t *tf;
  trie_addr_t *ta, fm;
  patricia_t *pt;
  s2t_t *s2t;
  slist_node_t *n;

  if(task->siglist == NULL)
    return 0;

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
	  if((ta = patricia_find(pt, &fm)) == NULL)
	    {
	      if((ta = trie_addr_alloc(sig->sig_tx_ip_dst)) == NULL)
		{
		  scamper_debug(__func__, "could not alloc trie_addr");
		  goto err;
		}
	      if((ta->node = patricia_insert(pt, ta)) == NULL)
		{
		  scamper_debug(__func__, "could not install trie_addr");
		  trie_addr_free(ta);
		  goto err;
		}
	    }
	  s2t->node = dlist_head_push(ta->s2t_list, s2t);

	  /*
	   * if we weren't able to insert the s2t, and the trie_addr
	   * is empty because we just created it, free trie_addr
	   */
	  if(s2t->node == NULL && trie_addr_isempty(ta))
	    {
	      patricia_remove_node(pt, ta->node);
	      trie_addr_free(ta);
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

  /* no signatures so nothing to block on */
  if(task->siglist == NULL)
    return NULL;

  for(n=slist_head_node(task->siglist); n != NULL; n = slist_node_next(n))
    {
      s2t = slist_node_item(n); sig = s2t->sig;
      if((tf = scamper_task_find(sig)) != NULL && tf != task)
	return tf;
    }

  return NULL;
}

void scamper_task_sig_prepare(scamper_task_t *task)
{
  if(task->funcs->sigs != NULL)
    task->funcs->sigs(task);
  return;
}

static void s2x_expire(s2x_t *s2x)
{
  trie_addr_t *ta;

  /* find the trie addr struct, remove expiry node from that */
  ta = trie_addr_find(s2x->sig->sig_tx_ip_dst);
  assert(ta != NULL);
  dlist_node_pop(ta->s2x_list, s2x->node);

  /* if the trie_addr struct now has no signatures, remove it */
  if(trie_addr_isempty(ta))
    {
      trie_addr_remove(ta);
      trie_addr_free(ta);
    }

  /* don't need the signature or the expire node anymore */
  scamper_task_sig_free(s2x->sig);
  free(s2x);
  return;
}

void scamper_task_sig_expiry_run(const struct timeval *now)
{
  s2x_t *s2x;

  while((s2x = slist_head_item(expire)) != NULL)
    {
      /* check if the item can be expired */
      if(timeval_cmp(&s2x->expiry, now) > 0)
	break;
      slist_head_pop(expire);
      s2x_expire(s2x);
    }

  return;
}

int scamper_task_onhold(scamper_task_t *blocker, scamper_task_t *blocked)
{
  task_onhold_t *toh = NULL;

  if((blocker->onhold == NULL && (blocker->onhold = dlist_alloc()) == NULL) ||
     (toh = malloc_zero(sizeof(task_onhold_t))) == NULL ||
     (toh->node = dlist_tail_push(blocker->onhold, toh)) == NULL)
    goto err;

  toh->blocker = blocker;
  toh->blocked = blocked;
  blocked->toh = toh;

  return 0;

 err:
  if(toh != NULL) free(toh);
  return -1;
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
      /*
       * pop held tasks off from tail, as scamper_source_task_unhold
       * pushes each task to the front of the list.  this retains
       * ordering.
       */
      while((toh = dlist_tail_pop(task->onhold)) != NULL)
	{
	  toh->blocked->toh = NULL;
	  scamper_source_task_unhold(toh->blocked);
	  free(toh);
	}
      dlist_free(task->onhold);
      task->onhold = NULL;
    }

  if(task->toh != NULL)
    {
      dlist_node_pop(task->toh->blocker->onhold, task->toh->node);
      free(task->toh);
      task->toh = NULL;
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
  trie_addr_t *ta;
  scamper_addr_t addr;
  dlist_node_t *dn;
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

  if((ta = trie_addr_find(&addr)) == NULL)
    return;

  for(dn=dlist_head_node(ta->s2t_list); dn != NULL; dn=dlist_node_next(dn))
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
  trie_addr_t *ta, fm;
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
  if((ta = patricia_find(pt, &fm)) == NULL)
    return;

  for(dn=dlist_head_node(ta->s2t_list); dn != NULL; dn=dlist_node_next(dn))
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
  if((expire = slist_alloc()) == NULL)
    return -1;
  return 0;
}

void scamper_task_cleanup(void)
{
  s2x_t *s2x;

  if(expire != NULL)
    {
      while((s2x = slist_head_pop(expire)) != NULL)
	s2x_expire(s2x);
      slist_free(expire);
      expire = NULL;
    }

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
