/*
 * scamper_trace.c
 *
 * $Id: scamper_trace.c,v 1.136 2025/05/04 23:58:33 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2003-2011 The University of Waikato
 * Copyright (C) 2008      Alistair King
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2019-2025 Matthew Luckie
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

scamper_trace_reply_t *
scamper_trace_lastditch_hopiter_next(const scamper_trace_lastditch_t *ld,
				     scamper_trace_hopiter_t *hi)
{
  scamper_trace_reply_t *hop;
  scamper_trace_probe_t *probe;

  hi->probe = NULL;

  if(ld->probes == NULL)
    return NULL;

  while(hi->p < ld->probec)
    {
      if((probe = ld->probes[hi->p]) != NULL &&
	 probe->replies != NULL && hi->r < probe->replyc)
	{
	  hop = probe->replies[hi->r++];
	  hi->probe = probe;
	  return hop;
	}

      hi->r = 0;
      hi->p++;
    }

  return NULL;
}

scamper_trace_reply_t *
scamper_trace_pmtud_hopiter_next(const scamper_trace_pmtud_t *pmtud,
				 scamper_trace_hopiter_t *hi)
{
  scamper_trace_reply_t *hop;
  scamper_trace_probe_t *probe;

  hi->probe = NULL;

  if(pmtud->probes == NULL)
    return NULL;

  while(hi->p < pmtud->probec)
    {
      if((probe = pmtud->probes[hi->p]) != NULL &&
	 probe->replies != NULL && hi->r < probe->replyc)
	{
	  hop = probe->replies[hi->r++];
	  hi->probe = probe;
	  return hop;
	}

      hi->r = 0;
      hi->p++;
    }

  return NULL;
}

scamper_trace_probe_t *
scamper_trace_hopiter_probe_get(const scamper_trace_hopiter_t *hi)
{
  return hi->probe;
}

scamper_trace_reply_t *
scamper_trace_hopiter_next(const scamper_trace_t *trace,
			   scamper_trace_hopiter_t *hi)
{
  scamper_trace_probettl_t *pttl;
  scamper_trace_probe_t *probe;
  scamper_trace_reply_t *hop;

  hi->probe = NULL;

  while(hi->h < trace->hop_count && (hi->max == 0 || hi->h < hi->max))
    {
      /* if there's no probes at this index, try the next */
      if((pttl = trace->hops[hi->h]) == NULL || pttl->probes == NULL ||
	 hi->p >= pttl->probec)
	{
	  hi->h++;
	  hi->p = 0;
	  hi->r = 0;
	  continue;
	}

      /* if there's no probe or replies, try the next probe */
      if((probe = pttl->probes[hi->p]) == NULL ||
	 probe->replies == NULL || hi->r >= probe->replyc)
	{
	  hi->p++;
	  hi->r = 0;
	  continue;
	}

      /* return the reply, if available */
      if((hop = probe->replies[hi->r++]) != NULL)
	{
	  hi->probe = probe;
	  return hop;
	}
    }

  return NULL;
}

int scamper_trace_hopiter_ttl_set(scamper_trace_hopiter_t *hi,
				  uint8_t ttl, uint8_t max)
{
  if(ttl == 0 || (max != 0 && ttl > max))
    return -1;

  hi->probe = NULL;
  hi->h     = ttl - 1;
  hi->max   = max;
  hi->p     = 0;
  hi->r     = 0;
  return 0;
}

void scamper_trace_hopiter_reset(scamper_trace_hopiter_t *hi)
{
  memset(hi, 0, sizeof(scamper_trace_hopiter_t));
  return;
}

void scamper_trace_reply_free(scamper_trace_reply_t *reply)
{
  if(reply == NULL)
    return;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--reply->refcnt > 0)
    return;
#endif
  if(reply->name != NULL)
    free(reply->name);
  if(reply->icmp_exts != NULL)
    scamper_icmpexts_free(reply->icmp_exts);
  if(reply->addr != NULL)
    scamper_addr_free(reply->addr);
  free(reply);
  return;
}

scamper_trace_reply_t *scamper_trace_reply_dup(const scamper_trace_reply_t *in)
{
  scamper_trace_reply_t *out = NULL;

  if((out = memdup(in, sizeof(scamper_trace_reply_t))) == NULL)
    goto err;

  out->addr = NULL;
  out->name = NULL;
  out->icmp_exts = NULL;

#ifndef BUILDING_LIBSCAMPERFILE
  out->probe = NULL;
#endif

#ifdef BUILDING_LIBSCAMPERFILE
  out->refcnt = 1;
#endif

  if(in->addr != NULL)
    out->addr = scamper_addr_use(in->addr);
  if(in->name != NULL && (out->name = strdup(in->name)))
    goto err;
  if(in->icmp_exts != NULL &&
     (out->icmp_exts = scamper_icmpexts_dup(in->icmp_exts)) != NULL)
    goto err;

  return out;

 err:
  if(out != NULL) scamper_trace_reply_free(out);
  return NULL;
}

#ifndef DMALLOC
scamper_trace_reply_t *scamper_trace_reply_alloc(void)
#else
scamper_trace_reply_t *scamper_trace_reply_alloc_dm(const char *file, int line)
#endif
{
  scamper_trace_reply_t *hop;

#ifndef DMALLOC
  hop = malloc_zero(sizeof(scamper_trace_reply_t));
#else
  hop = malloc_zero_dm(sizeof(scamper_trace_reply_t), file, line);
#endif
#ifdef BUILDING_LIBSCAMPERFILE
  if(hop != NULL)
    hop->refcnt = 1;
#endif
  return hop;
}

#ifdef DMALLOC
#undef scamper_trace_reply_alloc
scamper_trace_reply_t *scamper_trace_reply_alloc(void)
{
  return scamper_trace_reply_alloc_dm(__FILE__, __LINE__);
}
#endif

int scamper_trace_reply_addr_cmp(const scamper_trace_reply_t *a,
			       const scamper_trace_reply_t *b)
{
  assert(a != NULL);
  assert(b != NULL);
  return scamper_addr_cmp(a->addr, b->addr);
}

int scamper_trace_probe_reply_add(scamper_trace_probe_t *probe,
				  scamper_trace_reply_t *hop)
{
  size_t len;

  if(probe->replyc == UINT16_MAX)
    return -1;
  len = (probe->replyc + 1) * sizeof(scamper_trace_reply_t *);
  if(realloc_wrap((void **)&probe->replies, len) != 0)
    return -1;
  probe->replies[probe->replyc++] = hop;

  return 0;
}

void scamper_trace_probe_free(scamper_trace_probe_t *probe)
{
  uint16_t i;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--probe->refcnt > 0)
    return;
#endif

  if(probe->replies != NULL)
    {
      for(i=0; i<probe->replyc; i++)
	if(probe->replies[i] != NULL)
	  scamper_trace_reply_free(probe->replies[i]);
      free(probe->replies);
    }
  free(probe);

  return;
}

scamper_trace_probe_t *scamper_trace_probe_dup(const scamper_trace_probe_t *in)
{
  scamper_trace_probe_t *out = NULL;
  uint16_t i;
  size_t len;

  if((out = memdup(in, sizeof(scamper_trace_probe_t))) == NULL)
    goto err;
  out->replies = NULL;

#ifdef BUILDING_LIBSCAMPERFILE
  out->refcnt = 1;
#endif

  if(in->replyc > 0 && in->replies != NULL)
    {
      len = in->replyc * sizeof(scamper_trace_reply_t *);
      if((out->replies = malloc_zero(len)) == NULL)
	goto err;
      for(i=0; i<in->replyc; i++)
	{
	  if(in->replies[i] == NULL)
	    continue;
	  if((out->replies[i] = scamper_trace_reply_dup(in->replies[i])) == NULL)
	    goto err;
	}
    }

  return out;

 err:
  if(out != NULL) scamper_trace_probe_free(out);
  return NULL;
}

scamper_trace_probe_t *scamper_trace_probe_alloc(void)
{
  scamper_trace_probe_t *probe = malloc_zero(sizeof(scamper_trace_probe_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(probe != NULL)
    probe->refcnt = 1;
#endif
  return probe;
}

scamper_trace_reply_t *scamper_trace_probettl_reply_get(const scamper_trace_probettl_t *pttl)
{
  uint8_t p;
  for(p=0; p<pttl->probec; p++)
    if(pttl->probes[p]->replyc > 0)
      return pttl->probes[p]->replies[0];
  return NULL;
}

int scamper_trace_probettl_probe_add(scamper_trace_probettl_t *pttl,
				     scamper_trace_probe_t *probe)
{
  size_t len;

  if(pttl->probec == UINT8_MAX)
    return -1;
  len = (pttl->probec + 1) * sizeof(scamper_trace_probe_t *);
  if(realloc_wrap((void **)&pttl->probes, len) != 0)
    return -1;
  pttl->probes[pttl->probec++] = probe;

  return 0;
}

void scamper_trace_probettl_free(scamper_trace_probettl_t *pttl)
{
  uint8_t i;
  if(pttl->probes != NULL)
    {
      for(i=0; i<pttl->probec; i++)
	if(pttl->probes[i] != NULL)
	  scamper_trace_probe_free(pttl->probes[i]);
      free(pttl->probes);
    }
  free(pttl);
  return;
}

scamper_trace_probettl_t *
scamper_trace_probettl_dup(const scamper_trace_probettl_t *in)
{
  scamper_trace_probettl_t *out = NULL;
  uint8_t i;
  size_t len;

  if((out = memdup(in, sizeof(scamper_trace_probettl_t))) == NULL)
    goto err;
  out->probes = NULL;
  if(in->probec > 0 && in->probes != NULL)
    {
      len = out->probec * sizeof(scamper_trace_probe_t *);
      if((out->probes = malloc_zero(len)) == NULL)
	goto err;
      for(i=0; i<in->probec; i++)
	{
	  if(in->probes[i] != NULL &&
	     (out->probes[i] = scamper_trace_probe_dup(in->probes[i])) == NULL)
	    goto err;
	}
    }

  return out;

 err:
  if(out != NULL) scamper_trace_probettl_free(out);
  return NULL;
}

scamper_trace_probettl_t *scamper_trace_probettl_alloc(void)
{
  return malloc_zero(sizeof(scamper_trace_probettl_t));
}

char *scamper_trace_pmtud_note_type_tostr(const scamper_trace_pmtud_note_t *n,
					  char *buf, size_t len)
{
  static const char *t[] = {
    NULL,
    "ptb",
    "ptb-bad",
    "silence",
  };
  if(n->type >= sizeof(t) / sizeof(char *) || n->type == 0)
    snprintf(buf, len, "%u", n->type);
  else
    snprintf(buf, len, "%s", t[n->type]);
  return buf;
}

scamper_trace_pmtud_note_t *scamper_trace_pmtud_note_alloc(void)
{
  scamper_trace_pmtud_note_t *n;

  if((n = malloc_zero(sizeof(scamper_trace_pmtud_note_t))) == NULL)
    return NULL;

#ifdef BUILDING_LIBSCAMPERFILE
  n->refcnt = 1;
#endif

  return n;
}

void scamper_trace_pmtud_note_free(scamper_trace_pmtud_note_t *n)
{
#ifdef BUILDING_LIBSCAMPERFILE
  if(--n->refcnt > 0)
    return;
#endif
  free(n);
  return;
}

scamper_trace_pmtud_note_t *
scamper_trace_pmtud_note_dup(const scamper_trace_pmtud_note_t *in)
{
  scamper_trace_pmtud_note_t *out;

  if((out = memdup(in, sizeof(scamper_trace_pmtud_note_t))) == NULL)
    goto err;

  out->reply = NULL;
  out->probe = NULL;

#ifdef BUILDING_LIBSCAMPERFILE
  out->refcnt = 1;
#endif

  return out;

 err:
  if(out != NULL) scamper_trace_pmtud_note_free(out);
  return NULL;
}

int scamper_trace_pmtud_notes_alloc(scamper_trace_pmtud_t *pmtud, uint8_t c)
{
  size_t len = c * sizeof(scamper_trace_pmtud_note_t *);
  if((pmtud->notes = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

int scamper_trace_pmtud_note_add(scamper_trace_pmtud_t *pmtud,
				 scamper_trace_pmtud_note_t *n)
{
  size_t len;

  if(pmtud->notec == UINT8_MAX)
    return -1;
  len = (pmtud->notec + 1) * sizeof(scamper_trace_pmtud_note_t *);
  if(realloc_wrap((void **)&pmtud->notes, len) != 0)
    return -1;
  pmtud->notes[pmtud->notec++] = n;

  return 0;
}

int scamper_trace_pmtud_probes_alloc(scamper_trace_pmtud_t *pmtud, uint16_t c)
{
  if((pmtud->probes = malloc_zero(sizeof(scamper_trace_probe_t *) * c)) == NULL)
    return -1;
  return 0;
}

int scamper_trace_pmtud_probe_add(scamper_trace_pmtud_t *pmtud,
				  scamper_trace_probe_t *probe)
{
  size_t len;

  if(pmtud->probec == UINT16_MAX)
    return -1;
  len = (pmtud->probec + 1) * sizeof(scamper_trace_probe_t *);
  if(realloc_wrap((void **)&pmtud->probes, len) != 0)
    return -1;
  pmtud->probes[pmtud->probec++] = probe;

  return 0;
}

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
  uint16_t p;
  uint8_t n;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--pmtud->refcnt > 0)
    return;
#endif

  if(pmtud->probes != NULL)
    {
      for(p=0; p<pmtud->probec; p++)
	if(pmtud->probes[p] != NULL)
	  scamper_trace_probe_free(pmtud->probes[p]);
      free(pmtud->probes);
    }

  if(pmtud->notes != NULL)
    {
      for(n=0; n<pmtud->notec; n++)
	if(pmtud->notes[n] != NULL)
	  scamper_trace_pmtud_note_free(pmtud->notes[n]);
      free(pmtud->notes);
    }

  free(pmtud);

  return;
}

scamper_trace_pmtud_t *scamper_trace_pmtud_dup(const scamper_trace_pmtud_t *in)
{
  scamper_trace_pmtud_t *out = NULL;
  scamper_trace_probe_t *probe;
  uint16_t p, r;
  uint8_t i;

  if((out = memdup(in, sizeof(scamper_trace_pmtud_t))) == NULL)
    goto err;

  out->notes = NULL;
  out->probes = NULL;

#ifdef BUILDING_LIBSCAMPERFILE
  out->refcnt = 1;
#endif

  if(in->probec > 0 && in->probes != NULL)
    {
      if(scamper_trace_pmtud_probes_alloc(out, in->probec) != 0)
	goto err;
      for(p=0; p<in->probec; p++)
	if((out->probes[p] = scamper_trace_probe_dup(in->probes[p])) == NULL)
	  goto err;
    }

  if(in->notec > 0 && in->notes != NULL)
    {
      if(scamper_trace_pmtud_notes_alloc(out, in->notec) != 0)
	goto err;
      for(i=0; i<in->notec; i++)
	{
	  if(in->notes[i] == NULL)
	    continue;
	  out->notes[i] = scamper_trace_pmtud_note_dup(in->notes[i]);
	  if(out->notes[i] == NULL)
	    goto err;

	  if(in->notes[i]->probe == NULL)
	    continue;

	  for(p=0; p<in->probec; p++)
	    {
	      if((probe = in->probes[p]) == NULL)
		continue;

	      if(probe == in->notes[i]->probe)
		{
		  if(in->notes[i]->reply != NULL)
		    {
		      for(r=0; r<probe->replyc; r++)
			if(probe->replies[r] == in->notes[i]->reply)
			  break;
		      if(r == probe->replyc)
			goto err;
		      out->notes[i]->reply = out->probes[p]->replies[r];
		    }
		  out->notes[i]->probe = out->probes[p];
		  break;
		}
	    }
	  if(p == in->probec)
	    goto err;
	}
    }

  return out;

 err:
  if(out != NULL) scamper_trace_pmtud_free(out);
  return NULL;
}

int scamper_trace_lastditch_probe_add(scamper_trace_lastditch_t *ld,
				      scamper_trace_probe_t *probe)
{
  size_t len;

  if(ld->probec == UINT8_MAX)
    return -1;
  len = (ld->probec + 1) * sizeof(scamper_trace_probe_t *);
  if(realloc_wrap((void **)&ld->probes, len) != 0)
    return -1;
  ld->probes[ld->probec++] = probe;

  return 0;
}

int scamper_trace_lastditch_probes_alloc(scamper_trace_lastditch_t *ld,
					 uint8_t c)
{
  if((ld->probes = malloc_zero(sizeof(scamper_trace_probe_t *) * c)) == NULL)
    return -1;
  return 0;
}

scamper_trace_lastditch_t *scamper_trace_lastditch_alloc(void)
{
  size_t sz = sizeof(scamper_trace_lastditch_t);
  scamper_trace_lastditch_t *ld = malloc_zero(sz);
#ifdef BUILDING_LIBSCAMPERFILE
  if(ld != NULL)
    ld->refcnt = 1;
#endif
  return ld;
}

void scamper_trace_lastditch_free(scamper_trace_lastditch_t *ld)
{
  uint8_t i;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--ld->refcnt > 0)
    return;
#endif
  if(ld->probes != NULL)
    {
      for(i=0; i<ld->probec; i++)
	if(ld->probes[i] != NULL)
	  scamper_trace_probe_free(ld->probes[i]);
      free(ld->probes);
    }
  free(ld);
  return;
}

scamper_trace_lastditch_t *scamper_trace_lastditch_dup(const scamper_trace_lastditch_t *in)
{
  scamper_trace_lastditch_t *out = NULL;
  uint8_t i;

  if((out = memdup(in, sizeof(scamper_trace_lastditch_t))) == NULL)
    goto err;

  out->probes = NULL;

#ifdef BUILDING_LIBSCAMPERFILE
  out->refcnt = 1;
#endif

  if(in->probec > 0 && in->probes != NULL)
    {
      if(scamper_trace_lastditch_probes_alloc(out, in->probec) != 0)
	goto err;
      for(i=0; i<in->probec; i++)
	if((out->probes[i] = scamper_trace_probe_dup(in->probes[i])) == NULL)
	  goto err;
    }

  return out;

 err:
  if(out != NULL) scamper_trace_lastditch_free(out);
  return NULL;
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

int scamper_trace_hops_alloc(scamper_trace_t *trace, uint16_t hops)
{
  size_t size = sizeof(scamper_trace_probettl_t *) * hops;
  scamper_trace_probettl_t **h;

  if(trace->hops == NULL)
    h = (scamper_trace_probettl_t **)malloc_zero(size);
  else
    h = (scamper_trace_probettl_t **)realloc(trace->hops, size);

  if(h == NULL)
    return -1;

  trace->hops = h;
  return 0;
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
  uint16_t i;

  if(trace == NULL) return;

  if(trace->hops != NULL)
    {
      for(i=0; i<trace->hop_count; i++)
	if(trace->hops[i] != NULL)
	  scamper_trace_probettl_free(trace->hops[i]);
      free(trace->hops);
    }

  if(trace->payload != NULL) free(trace->payload);

  if(trace->lastditch != NULL) scamper_trace_lastditch_free(trace->lastditch);
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
  size_t len;
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

  if(in->hop_count > 0 && in->hops != NULL)
    {
      len = sizeof(scamper_trace_probettl_t *) * in->hop_count;
      if((out->hops = malloc_zero(len)) == NULL)
	goto err;

      for(i=0; i<in->hop_count; i++)
	{
	  if(in->hops[i] == NULL)
	    continue;
	  if((out->hops[i] = scamper_trace_probettl_dup(in->hops[i])) == NULL)
	    goto err;
	}
    }

  if(in->lastditch != NULL &&
     (out->lastditch = scamper_trace_lastditch_dup(in->lastditch)) == NULL)
    goto err;

  if(in->pmtud != NULL &&
     (out->pmtud = scamper_trace_pmtud_dup(in->pmtud)) == NULL)
    goto err;

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
