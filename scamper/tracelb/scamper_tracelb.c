/*
 * scamper_tracelb.c
 *
 * $Id: scamper_tracelb.c,v 1.80 2024/03/04 19:36:41 mjl Exp $
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_tracelb.h"
#include "scamper_tracelb_int.h"
#include "utils.h"

void
scamper_tracelb_probeset_summary_free(scamper_tracelb_probeset_summary_t *sum)
{
  uint16_t i;
  if(sum->addrs != NULL)
    {
      for(i=0; i<sum->addrc; i++)
	if(sum->addrs[i] != NULL)
	  scamper_addr_free(sum->addrs[i]);
      free(sum->addrs);
    }
  free(sum);
  return;
}

scamper_tracelb_probeset_summary_t *
scamper_tracelb_probeset_summary_alloc(const scamper_tracelb_probeset_t *set)
{
  scamper_tracelb_probeset_summary_t *sum = NULL;
  scamper_tracelb_probe_t *probe;
  scamper_addr_t *addr;
  uint16_t flowid, j;
  size_t addrc;
  int i, x;

  if((sum = malloc_zero(sizeof(scamper_tracelb_probeset_summary_t))) == NULL)
    goto err;

  if(set->probec == 0)
    return sum;

  flowid = set->probes[0]->flowid;
  x = 0;
  for(i=0; i<=set->probec; i++)
    {
      if(i == set->probec)
	{
	  if(x == 0)
	    sum->nullc++;
	  break;
	}

      probe = set->probes[i];
      if(probe->flowid != flowid)
	{
	  /*
	   * if a unique flowid had no response (even with multiple
	   * attempts) then make a note of that.
	   */
	  if(x == 0)
	    sum->nullc++;

	  flowid = probe->flowid;
	  x = 0;
	}

      if(probe->rxc > 0)
	{
	  for(j=0; j<probe->rxc; j++)
	    {
	      addr = probe->rxs[j]->reply_from;
	      addrc = (size_t)sum->addrc;
	      if(array_find((void **)sum->addrs, addrc, addr,
			    (array_cmp_t)scamper_addr_cmp) != NULL)
		continue;
	      if(array_insert((void ***)&sum->addrs, &addrc, addr,
			      (array_cmp_t)scamper_addr_cmp) != 0)
		goto err;
	      sum->addrc = (uint16_t)addrc;
	      scamper_addr_use(addr);
	    }
	  x++;
	}
    }

  return sum;

 err:
  if(sum != NULL) scamper_tracelb_probeset_summary_free(sum);
  return NULL;
}

/*
 * scamper_tracelb_node_cmp
 *
 * function to compare two nodes, taking into account the possibility that
 * the quoted ttl field is present and has a value.
 */
int scamper_tracelb_node_cmp(const scamper_tracelb_node_t *a,
			     const scamper_tracelb_node_t *b)
{
  int i;

  if(a->addr == NULL || b->addr == NULL)
    {
      if(a->addr == NULL && b->addr == NULL)
	return 0;
      else if(a->addr == NULL)
	return -1;
      return 1;
    }

  if((i = scamper_addr_human_cmp(a->addr, b->addr)) != 0)
    return i;

  if(SCAMPER_TRACELB_NODE_QTTL(a) == SCAMPER_TRACELB_NODE_QTTL(b))
    {
      if(SCAMPER_TRACELB_NODE_QTTL(a))
	{
	  if(a->q_ttl < b->q_ttl) return -1;
	  if(a->q_ttl > b->q_ttl) return  1;
	}
      return 0;
    }
  else if(SCAMPER_TRACELB_NODE_QTTL(a))
    {
      return -1;
    }
  return 1;
}

/*
 * scamper_tracelb_link_cmp
 *
 * function to compare two links.  the comparison is based on the nodes
 * present in each link.
 */
int scamper_tracelb_link_cmp(const scamper_tracelb_link_t *a,
			     const scamper_tracelb_link_t *b)
{
  int i;

  if(a == b)
    return 0;

  if((i = scamper_tracelb_node_cmp(a->from, b->from)) != 0)
    return i;

  if(a->to != NULL && b->to != NULL)
    return scamper_tracelb_node_cmp(a->to, b->to);

  if(a->to == NULL && b->to == NULL)
    return 0;
  else if(a->to == NULL)
    return 1;
  else
    return -1;
}

scamper_tracelb_node_t *scamper_tracelb_node_alloc(scamper_addr_t *addr)
{
  scamper_tracelb_node_t *node;
  if((node = malloc_zero(sizeof(scamper_tracelb_node_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  node->refcnt = 1;
#endif
  if(addr != NULL)
    node->addr = scamper_addr_use(addr);
  return node;
}

void scamper_tracelb_node_free(scamper_tracelb_node_t *node)
{
#ifdef BUILDING_LIBSCAMPERFILE
  uint16_t i;
#endif

  if(node == NULL)
    return;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--node->refcnt > 0)
    return;
#endif

  if(node->links != NULL)
    {
#ifdef BUILDING_LIBSCAMPERFILE
      for(i=0; i<node->linkc; i++)
	if(node->links[i] != NULL)
	  scamper_tracelb_link_free(node->links[i]);
#endif
      free(node->links);
    }
  if(node->addr != NULL)
    scamper_addr_free(node->addr);
  if(node->name != NULL)
    free(node->name);
  free(node);
  return;
}

scamper_tracelb_node_t *scamper_tracelb_node_find(scamper_tracelb_t *trace,
						  scamper_tracelb_node_t *node)
{
  uint16_t i;
  for(i=0; i<trace->nodec; i++)
    {
      if(trace->nodes[i]->addr == NULL)
	continue;
      if(scamper_tracelb_node_cmp(trace->nodes[i], node) == 0)
	return trace->nodes[i];
    }
  return NULL;
}

scamper_tracelb_reply_t *scamper_tracelb_reply_alloc(scamper_addr_t *addr)
{
  scamper_tracelb_reply_t *reply;
  if((reply = malloc_zero(sizeof(scamper_tracelb_reply_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  reply->refcnt = 1;
#endif
  if(addr != NULL)
    reply->reply_from = scamper_addr_use(addr);
  return reply;
}

void scamper_tracelb_reply_free(scamper_tracelb_reply_t *reply)
{
  if(reply == NULL)
    return;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--reply->refcnt > 0)
    return;
#endif
  if(reply->reply_from != NULL)
    scamper_addr_free(reply->reply_from);
  if((reply->reply_flags & SCAMPER_TRACELB_REPLY_FLAG_TCP) == 0 &&
     reply->reply_icmp_ext != NULL)
    scamper_icmpext_free(reply->reply_icmp_ext);
  free(reply);
  return;
}

scamper_tracelb_probe_t *scamper_tracelb_probe_alloc(void)
{
  scamper_tracelb_probe_t *probe;
  if((probe = malloc_zero(sizeof(scamper_tracelb_probe_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  probe->refcnt = 1;
#endif
  return probe;
}

void scamper_tracelb_probe_free(scamper_tracelb_probe_t *probe)
{
  uint16_t i;
  if(probe == NULL)
    return;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--probe->refcnt > 0)
    return;
#endif
  if(probe->rxs != NULL)
    {
      for(i=0; i<probe->rxc; i++)
	scamper_tracelb_reply_free(probe->rxs[i]);
      free(probe->rxs);
    }
  free(probe);
  return;
}

int scamper_tracelb_probeset_probes_alloc(scamper_tracelb_probeset_t *set,
					  uint16_t probec)
{
  size_t len = sizeof(scamper_tracelb_probe_t *) * probec;
  if((set->probes = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

int scamper_tracelb_probeset_add(scamper_tracelb_probeset_t *probeset,
				 scamper_tracelb_probe_t *probe)
{
  size_t len = (probeset->probec + 1) * sizeof(scamper_tracelb_probe_t *);
  if(realloc_wrap((void **)&probeset->probes, len) != 0)
    return -1;
  probeset->probes[probeset->probec++] = probe;
  return 0;
}

scamper_tracelb_probeset_t *scamper_tracelb_probeset_alloc(void)
{
  scamper_tracelb_probeset_t *set;
  if((set = malloc_zero(sizeof(scamper_tracelb_probeset_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  set->refcnt = 1;
#endif
  return set;
}

void scamper_tracelb_probeset_free(scamper_tracelb_probeset_t *set)
{
  uint16_t i;
  if(set == NULL)
    return;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--set->refcnt > 0)
    return;
#endif
  if(set->probes != NULL)
    {
      for(i=0; i<set->probec; i++)
	scamper_tracelb_probe_free(set->probes[i]);
      free(set->probes);
    }
  free(set);
  return;
}

scamper_tracelb_link_t *scamper_tracelb_link_alloc(void)
{
  scamper_tracelb_link_t *link;
  if((link = malloc_zero(sizeof(scamper_tracelb_link_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  link->refcnt = 1;
#endif
  return link;
}

void scamper_tracelb_link_free(scamper_tracelb_link_t *link)
{
  uint8_t i;
  if(link == NULL)
    return;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--link->refcnt > 0)
    return;
#endif
  if(link->sets != NULL)
    {
      for(i=0; i<link->hopc; i++)
	scamper_tracelb_probeset_free(link->sets[i]);
      free(link->sets);
    }
  free(link);
  return;
}

int scamper_tracelb_link_probesets_alloc(scamper_tracelb_link_t *link,
					 uint8_t hopc)
{
  size_t len = hopc * sizeof(scamper_tracelb_probeset_t *);
  if((link->sets = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

int scamper_tracelb_link_probeset(scamper_tracelb_link_t *link,
				  scamper_tracelb_probeset_t *set)
{
  size_t len = (link->hopc + 1) * sizeof(scamper_tracelb_probeset_t *);
  if(realloc_wrap((void **)&link->sets, len) != 0)
    return -1;
  link->sets[link->hopc++] = set;
  return 0;
}

int scamper_tracelb_nodes_alloc(scamper_tracelb_t *trace, uint16_t count)
{
  size_t size = sizeof(scamper_tracelb_node_t *) * count;
  if((trace->nodes = malloc_zero(size)) != NULL)
    return 0;
  return -1;
}

int scamper_tracelb_links_alloc(scamper_tracelb_t *trace, uint16_t count)
{
  size_t size = sizeof(scamper_tracelb_link_t *) * count;
  if((trace->links = malloc_zero(size)) != NULL)
    return 0;
  return -1;
}

int scamper_tracelb_node_links_alloc(scamper_tracelb_node_t *node,
				     uint16_t count)
{
  size_t size = sizeof(scamper_tracelb_link_t *) * count;
  if((node->links = malloc_zero(size)) != NULL)
    return 0;
  return -1;
}

int scamper_tracelb_probe_replies_alloc(scamper_tracelb_probe_t *probe,
					uint16_t count)
{
  size_t size = sizeof(scamper_tracelb_reply_t *) * count;
  if((probe->rxs = malloc_zero(size)) != NULL)
    return 0;
  return -1;
}

char *scamper_tracelb_type_tostr(const scamper_tracelb_t *trace,
				 char *buf, size_t len)
{
  static const char *m[] = {
    NULL,
    "udp-dport",
    "icmp-echo",
    "udp-sport",
    "tcp-sport",
    "tcp-ack-sport",
  };

  if(trace->type >= sizeof(m) / sizeof(char *) || trace->type == 0)
    snprintf(buf, len, "%d", trace->type);
  else
    snprintf(buf, len, "%s", m[trace->type]);
  return buf;
}

/*
 * scamper_tracelb_free
 *
 */
void scamper_tracelb_free(scamper_tracelb_t *trace)
{
  uint16_t i;

  if(trace == NULL) return;

  if(trace->links != NULL)
    {
      for(i=0; i<trace->linkc; i++)
	scamper_tracelb_link_free(trace->links[i]);
      free(trace->links);
    }

  if(trace->nodes != NULL)
    {
      for(i=0; i<trace->nodec; i++)
	scamper_tracelb_node_free(trace->nodes[i]);
      free(trace->nodes);
    }

  if(trace->dst != NULL) scamper_addr_free(trace->dst);
  if(trace->src != NULL) scamper_addr_free(trace->src);
  if(trace->rtr != NULL) scamper_addr_free(trace->rtr);

  if(trace->cycle != NULL) scamper_cycle_free(trace->cycle);
  if(trace->list != NULL) scamper_list_free(trace->list);

  free(trace);
  return;
}

/*
 * scamper_tracelb_alloc
 *
 * allocate the trace and all the possibly necessary data fields
 */
scamper_tracelb_t *scamper_tracelb_alloc()
{
  return (scamper_tracelb_t *)malloc_zero(sizeof(scamper_tracelb_t));
}
