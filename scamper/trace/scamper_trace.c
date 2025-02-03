/*
 * scamper_trace.c
 *
 * $Id: scamper_trace.c,v 1.120 2024/10/16 07:01:29 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2003-2011 The University of Waikato
 * Copyright (C) 2008      Alistair King
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2019-2024 Matthew Luckie
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

#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_trace.h"
#include "scamper_trace_int.h"
#include "utils.h"

scamper_trace_pmtud_t *scamper_trace_pmtud_alloc(void)
{
  scamper_trace_pmtud_t *pmtud = malloc_zero(sizeof(scamper_trace_pmtud_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(pmtud != NULL)
    pmtud->refcnt = 1;
#endif
  return pmtud;
}

void scamper_trace_pmtud_free(scamper_trace_pmtud_t *pmtud)
{
  uint8_t u8;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--pmtud->refcnt > 0)
    return;
#endif

  scamper_trace_hops_free(pmtud->hops);

  if(pmtud->notes != NULL)
    {
      for(u8=0; u8<pmtud->notec; u8++)
	scamper_trace_pmtud_n_free(pmtud->notes[u8]);
      free(pmtud->notes);
    }

  free(pmtud);

  return;
}

scamper_trace_pmtud_n_t *scamper_trace_pmtud_n_alloc(void)
{
  scamper_trace_pmtud_n_t *n = malloc_zero(sizeof(scamper_trace_pmtud_n_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(n != NULL)
    n->refcnt = 1;
#endif
  return n;
}

void scamper_trace_pmtud_n_free(scamper_trace_pmtud_n_t *n)
{
#ifdef BUILDING_LIBSCAMPERFILE
  if(--n->refcnt > 0)
    return;
#endif
  free(n);
  return;
}

int scamper_trace_pmtud_n_alloc_c(scamper_trace_pmtud_t *pmtud, uint8_t count)
{
  size_t len = count * sizeof(scamper_trace_pmtud_n_t *);
  if((pmtud->notes = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

int scamper_trace_pmtud_n_add(scamper_trace_pmtud_t *pmtud,
			      scamper_trace_pmtud_n_t *n)
{
  size_t len = (pmtud->notec + 1) * sizeof(scamper_trace_pmtud_n_t *);
  if(realloc_wrap((void **)&pmtud->notes, len) != 0)
    return -1;
  pmtud->notes[pmtud->notec] = n;
  pmtud->notec++;
  return 0;
}

scamper_trace_dtree_t *scamper_trace_dtree_alloc(void)
{
  scamper_trace_dtree_t *dt = malloc_zero(sizeof(scamper_trace_dtree_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(dt != NULL)
    dt->refcnt = 1;
#endif
  return dt;
}

void scamper_trace_dtree_free(scamper_trace_dtree_t *dtree)
{
  uint16_t i;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--dtree->refcnt > 0)
    return;
#endif
  if(dtree->lss_stop != NULL)
    scamper_addr_free(dtree->lss_stop);
  if(dtree->gss_stop != NULL)
    scamper_addr_free(dtree->gss_stop);
  if(dtree->lss != NULL)
    free(dtree->lss);

  if(dtree->gss != NULL)
    {
      for(i=0; i<dtree->gssc; i++)
	if(dtree->gss[i] != NULL)
	  scamper_addr_free(dtree->gss[i]);
      free(dtree->gss);
    }

  free(dtree);
  return;
}

int scamper_trace_dtree_lss_set(scamper_trace_dtree_t *dtree, const char *name)
{
  if((dtree->lss = strdup(name)) == NULL)
    return -1;
  return 0;
}

int scamper_trace_dtree_gss_alloc(scamper_trace_dtree_t *dtree, uint16_t cnt)
{
  if(dtree->gss != NULL)
    return -1;
  if((dtree->gss = malloc_zero(sizeof(scamper_addr_t *) * cnt)) == NULL)
    return -1;
  return 0;
}

scamper_addr_t *scamper_trace_dtree_gss_find(const scamper_trace_dtree_t *dtree,
                                             const scamper_addr_t *iface)
{
  if(dtree == NULL)
    return NULL;
  return array_find((void **)dtree->gss, (size_t)dtree->gssc, iface,
		    (array_cmp_t)scamper_addr_cmp);
}

void scamper_trace_dtree_gss_sort(const scamper_trace_dtree_t *dtree)
{
  if(dtree == NULL)
    return;
  array_qsort((void **)dtree->gss, (size_t)dtree->gssc,
	      (array_cmp_t)scamper_addr_cmp);
  return;
}

void scamper_trace_hops_free(scamper_trace_hop_t *head)
{
  scamper_trace_hop_t *hop = head;
  while(hop != NULL)
    {
      head = hop->hop_next;
      scamper_trace_hop_free(hop);
      hop = head;
    }
  return;
}

int scamper_trace_hops_alloc(scamper_trace_t *trace, uint16_t hops)
{
  size_t size = sizeof(scamper_trace_hop_t *) * hops;
  scamper_trace_hop_t **h;

  if(trace->hops == NULL)
    h = (scamper_trace_hop_t **)malloc_zero(size);
  else
    h = (scamper_trace_hop_t **)realloc(trace->hops, size);

  if(h == NULL)
    return -1;

  trace->hops = h;
  return 0;
}

void scamper_trace_hop_free(scamper_trace_hop_t *hop)
{
  if(hop == NULL)
    return;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--hop->refcnt > 0)
    return;
#endif
  if(hop->hop_name != NULL)
    free(hop->hop_name);
  if(hop->hop_icmpext != NULL)
    scamper_icmpext_free(hop->hop_icmpext);
  if(hop->hop_addr != NULL)
    scamper_addr_free(hop->hop_addr);
  free(hop);
  return;
}

scamper_trace_hop_t *scamper_trace_hop_dup(const scamper_trace_hop_t *in)
{
  scamper_trace_hop_t *out = NULL;

  if((out = memdup(in, sizeof(scamper_trace_hop_t))) == NULL)
    goto err;
  out->hop_addr = NULL;
  out->hop_name = NULL;
  out->hop_icmpext = NULL;
  out->hop_next = NULL;

#ifdef BUILDING_LIBSCAMPERFILE
  out->refcnt = 1;
#endif

  if(in->hop_name != NULL && (out->hop_name = strdup(in->hop_name)))
    goto err;
  if(in->hop_addr != NULL)
    out->hop_addr = scamper_addr_use(in->hop_addr);

  return out;

 err:
  if(out != NULL) scamper_trace_hop_free(out);
  return NULL;
}

#ifndef DMALLOC
scamper_trace_hop_t *scamper_trace_hop_alloc(void)
#else
scamper_trace_hop_t *scamper_trace_hop_alloc_dm(const char *file, int line)
#endif
{
  scamper_trace_hop_t *hop;

#ifndef DMALLOC
  hop = malloc_zero(sizeof(scamper_trace_hop_t));
#else
  hop = malloc_zero_dm(sizeof(scamper_trace_hop_t), file, line);
#endif
#ifdef BUILDING_LIBSCAMPERFILE
  if(hop != NULL)
    hop->refcnt = 1;
#endif
  return hop;
}

#ifdef DMALLOC
#undef scamper_trace_hop_alloc
scamper_trace_hop_t *scamper_trace_hop_alloc(void)
{
  return scamper_trace_hop_alloc_dm(__FILE__, __LINE__);
}
#endif

int scamper_trace_hop_addr_cmp(const scamper_trace_hop_t *a,
			       const scamper_trace_hop_t *b)
{
  assert(a != NULL);
  assert(b != NULL);
  return scamper_addr_cmp(a->hop_addr, b->hop_addr);
}

char *scamper_trace_type_tostr(const scamper_trace_t *trace,
			       char *buf, size_t len)
{
  static const char *m[] = {
    NULL,
    "icmp-echo",
    "udp",
    "tcp",
    "icmp-echo-paris",
    "udp-paris",
    "tcp-ack",
  };
  if(trace->type >= sizeof(m) / sizeof(char *) || trace->type == 0)
    snprintf(buf, len, "%d", trace->type);
  else
    snprintf(buf, len, "%s", m[trace->type]);
  return buf;
}

char *scamper_trace_stop_tostr(const scamper_trace_t *trace,
			       char *buf, size_t len)
{
  static const char *r[] = {
    "NONE",
    "COMPLETED",
    "UNREACH",
    "ICMP",
    "LOOP",
    "GAPLIMIT",
    "ERROR",
    "HOPLIMIT",
    "GSS",
    "HALTED",
    "INPROGRESS",
  };
  if(trace->stop_reason >= sizeof(r) / sizeof(char *))
    snprintf(buf, len, "%d", trace->stop_reason);
  else
    snprintf(buf, len, "%s", r[trace->stop_reason]);
  return buf;
}

char *scamper_trace_gapaction_tostr(const scamper_trace_t *trace,
				    char *buf, size_t len)
{
  static const char *g[] = {
    NULL,
    "stop",
    "lastditch",
  };
  if(trace->gapaction >= sizeof(g) / sizeof(char *) || trace->gapaction == 0)
    snprintf(buf, len, "%d", trace->gapaction);
  else
    snprintf(buf, len, "%s", g[trace->gapaction]);
  return buf;
}

/*
 * scamper_trace_free
 *
 */
void scamper_trace_free(scamper_trace_t *trace)
{
  uint8_t i;

  if(trace == NULL) return;

  /* free hop records */
  if(trace->hops != NULL)
    {
      for(i=0; i<trace->hop_count; i++)
	scamper_trace_hops_free(trace->hops[i]);
      free(trace->hops);
    }

  /* free lastditch hop records */
  scamper_trace_hops_free(trace->lastditch);

  if(trace->payload != NULL) free(trace->payload);

  if(trace->pmtud != NULL) scamper_trace_pmtud_free(trace->pmtud);
  if(trace->dtree != NULL) scamper_trace_dtree_free(trace->dtree);

  if(trace->dst != NULL) scamper_addr_free(trace->dst);
  if(trace->src != NULL) scamper_addr_free(trace->src);
  if(trace->rtr != NULL) scamper_addr_free(trace->rtr);

  if(trace->cycle != NULL) scamper_cycle_free(trace->cycle);
  if(trace->list != NULL) scamper_list_free(trace->list);

  free(trace);
  return;
}

scamper_trace_t *scamper_trace_dup(scamper_trace_t *in)
{
  scamper_trace_t *out = NULL;
  scamper_trace_hop_t *hop_in, *hop_out;
  uint16_t i;

  if((out = memdup(in, sizeof(scamper_trace_t))) == NULL)
    goto err;

  if(in->list != NULL)
    out->list = scamper_list_use(in->list);
  if(in->cycle != NULL)
    out->cycle = scamper_cycle_use(in->cycle);
  if(in->src != NULL)
    out->src = scamper_addr_use(in->src);
  if(in->dst != NULL)
    out->dst = scamper_addr_use(in->dst);
  if(in->rtr != NULL)
    out->rtr = scamper_addr_use(in->rtr);

  /* set everything to NULL that could possibly fail */
  out->payload = NULL;
  out->pmtud = NULL;
  out->lastditch = NULL;
  out->hops = NULL;

  if(in->payload != NULL &&
     (out->payload = memdup(in->payload, in->payload_len)) == NULL)
    goto err;

  if(in->hop_count > 0)
    {
      out->hops = malloc_zero(sizeof(scamper_trace_hop_t *) * in->hop_count);
      if(out->hops == NULL)
	goto err;

      for(i=0; i<in->hop_count; i++)
	{
	  if(in->hops[i] == NULL)
	    continue;
	  if((out->hops[i] = scamper_trace_hop_dup(in->hops[i])) == NULL)
	    goto err;
	  hop_in = in->hops[i]; hop_out = out->hops[i];
	  while(hop_in->hop_next != NULL)
	    {
	      hop_out->hop_next = scamper_trace_hop_dup(hop_in->hop_next);
	      if(hop_out->hop_next == NULL)
		goto err;
	      hop_in = hop_in->hop_next;
	      hop_out = hop_out->hop_next;
	    }
	}
    }

  return out;

 err:
  if(out != NULL) scamper_trace_free(out);
  return NULL;
}

/*
 * scamper_trace_alloc
 *
 * allocate the trace and all the possibly necessary data fields
 */
#ifndef DMALLOC
scamper_trace_t *scamper_trace_alloc(void)
{
  return malloc_zero(sizeof(scamper_trace_t));
}
#else
scamper_trace_t *scamper_trace_alloc_dm(const char *file, int line)
{
  return malloc_zero_dm(sizeof(scamper_trace_t), file, line);
}
#undef scamper_trace_alloc
scamper_trace_t *scamper_trace_alloc(void)
{
  return scamper_trace_alloc_dm(__FILE__, __LINE__);
}
#endif
