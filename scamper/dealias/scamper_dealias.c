/*
 * scamper_dealias.c
 *
 * $Id: scamper_dealias.c,v 1.74 2024/03/04 19:36:41 mjl Exp $
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Copyright (C) 2012-2013 The Regents of the University of California
 * Copyright (C) 2021-2023 Matthew Luckie
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

#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_dealias.h"
#include "scamper_dealias_int.h"
#include "utils.h"

static const char *probedef_m[] = {
  NULL,
  "icmp-echo",
  "tcp-ack",
  "udp",
  "tcp-ack-sport",
  "udp-dport",
  "tcp-syn-sport",
};
static size_t probedef_mc = sizeof(probedef_m) / sizeof(char *);

int scamper_dealias_probedef_method_fromstr(const char *str, uint8_t *meth)
{
  uint8_t i;
  assert(probedef_mc == (SCAMPER_DEALIAS_PROBEDEF_METHOD_MAX+1));
  for(i=1; i<probedef_mc; i++)
    {
      if(strcasecmp(str, probedef_m[i]) == 0)
	{
	  *meth = i;
	  return 0;
	}
    }
  return -1;
}

char *scamper_dealias_probedef_method_tostr(const scamper_dealias_probedef_t *d,
					    char *buf, size_t len)
{
  assert(probedef_mc == (SCAMPER_DEALIAS_PROBEDEF_METHOD_MAX+1));
  if(d->method >= probedef_mc || probedef_m[d->method] == NULL)
    snprintf(buf, len, "%d", d->method);
  else
    snprintf(buf, len, "%s", probedef_m[d->method]);
  return buf;
}

scamper_dealias_probedef_t *scamper_dealias_probedef_alloc(void)
{
  scamper_dealias_probedef_t *pd;
  pd = malloc_zero(sizeof(scamper_dealias_probedef_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(pd != NULL)
    pd->refcnt = 1;
#endif
  return pd;
}

void scamper_dealias_probedef_free(scamper_dealias_probedef_t *probedef)
{
#ifdef BUILDING_LIBSCAMPERFILE
  if(--probedef->refcnt > 0)
    return;
#endif
  if(probedef->src != NULL)
    scamper_addr_free(probedef->src);
  if(probedef->dst != NULL)
    scamper_addr_free(probedef->dst);
  free(probedef);
  return;
}

scamper_dealias_probe_t *scamper_dealias_probe_alloc(void)
{
  scamper_dealias_probe_t *probe;
  probe = malloc_zero(sizeof(scamper_dealias_probe_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(probe != NULL)
    probe->refcnt = 1;
#endif
  return probe;
}

void scamper_dealias_probe_free(scamper_dealias_probe_t *probe)
{
  uint16_t i;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--probe->refcnt > 0)
    return;
  if(probe->def != NULL)
    scamper_dealias_probedef_free(probe->def);
#endif

  if(probe->replies != NULL)
    {
      for(i=0; i<probe->replyc; i++)
	{
	  if(probe->replies[i] != NULL)
	    scamper_dealias_reply_free(probe->replies[i]);
	}
      free(probe->replies);
    }

  free(probe);
  return;
}

scamper_dealias_reply_t *scamper_dealias_reply_alloc(void)
{
  scamper_dealias_reply_t *reply;
  reply = malloc_zero(sizeof(scamper_dealias_reply_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(reply != NULL)
    reply->refcnt = 1;
#endif
  return reply;
}

void scamper_dealias_reply_free(scamper_dealias_reply_t *reply)
{
#ifdef BUILDING_LIBSCAMPERFILE
  if(--reply->refcnt > 0)
    return;
#endif
  if(reply->src != NULL)
    scamper_addr_free(reply->src);
  free(reply);
  return;
}

uint32_t scamper_dealias_reply_count(const scamper_dealias_t *dealias)
{
  uint32_t rc = 0;
  uint16_t i;
  for(i=0; i<dealias->probec; i++)
    {
      if(dealias->probes[i] != NULL)
	rc += dealias->probes[i]->replyc;
    }
  return rc;
}

static int dealias_probe_tx_cmp(const scamper_dealias_probe_t *a,
				const scamper_dealias_probe_t *b)
{
  return timeval_cmp(&a->tx, &b->tx);
}

static int dealias_probe_seq_cmp(const scamper_dealias_probe_t *a,
				 const scamper_dealias_probe_t *b)
{
  if(a->seq < b->seq)
    return -1;
  if(a->seq > b->seq)
    return 1;
  if(a->def->id < b->def->id)
    return -1;
  if(a->def->id > b->def->id)
    return 1;
  return 0;
}

static int dealias_probe_def_cmp(const scamper_dealias_probe_t *a,
				 const scamper_dealias_probe_t *b)
{
  if(a->def->id < b->def->id)
    return -1;
  if(a->def->id > b->def->id)
    return 1;
  if(a->seq < b->seq)
    return -1;
  if(a->seq > b->seq)
    return 1;
  return 0;
}

void scamper_dealias_probes_sort_tx(scamper_dealias_t *dealias)
{
  array_qsort((void **)dealias->probes, dealias->probec,
	      (array_cmp_t)dealias_probe_tx_cmp);
  return;
}

void scamper_dealias_probes_sort_seq(scamper_dealias_t *dealias)
{
  array_qsort((void **)dealias->probes, dealias->probec,
	      (array_cmp_t)dealias_probe_seq_cmp);
  return;
}

void scamper_dealias_probes_sort_def(scamper_dealias_t *dealias)
{
  array_qsort((void **)dealias->probes, dealias->probec,
	      (array_cmp_t)dealias_probe_def_cmp);
  return;
}

int scamper_dealias_probe_add(scamper_dealias_t *dealias,
			      scamper_dealias_probe_t *probe)
{
  size_t size = (dealias->probec+1) * sizeof(scamper_dealias_probe_t *);
  if(realloc_wrap((void **)&dealias->probes, size) == 0)
    {
      dealias->probes[dealias->probec++] = probe;
      return 0;
    }
  return -1;
}

int scamper_dealias_reply_add(scamper_dealias_probe_t *probe,
			      scamper_dealias_reply_t *reply)
{
  size_t size = (probe->replyc+1) * sizeof(scamper_dealias_reply_t *);
  if(realloc_wrap((void **)&probe->replies, size) == 0)
    {
      probe->replies[probe->replyc++] = reply;
      return 0;
    }
  return -1;
}

scamper_dealias_ally_t *scamper_dealias_ally_alloc(void)
{
  scamper_dealias_ally_t *ally;
  if((ally = malloc_zero(sizeof(scamper_dealias_ally_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  ally->refcnt = 1;
#endif
  if((ally->probedefs[0] = scamper_dealias_probedef_alloc()) == NULL ||
     (ally->probedefs[1] = scamper_dealias_probedef_alloc()) == NULL)
    goto err;
  return ally;

 err:
  if(ally != NULL) scamper_dealias_ally_free(ally);
  return NULL;
}

void scamper_dealias_ally_free(scamper_dealias_ally_t *ally)
{
#ifdef BUILDING_LIBSCAMPERFILE
  if(--ally->refcnt > 0)
    return;
#endif
  if(ally->probedefs[0] != NULL)
    scamper_dealias_probedef_free(ally->probedefs[0]);
  if(ally->probedefs[1] != NULL)
    scamper_dealias_probedef_free(ally->probedefs[1]);
  free(ally);
  return;
}

scamper_dealias_mercator_t *scamper_dealias_mercator_alloc(void)
{
  scamper_dealias_mercator_t *mc;
  mc = malloc_zero(sizeof(scamper_dealias_mercator_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(mc != NULL)
    mc->refcnt = 1;
#endif
  return mc;
}

void scamper_dealias_mercator_free(scamper_dealias_mercator_t *mc)
{
#ifdef BUILDING_LIBSCAMPERFILE
  if(--mc->refcnt > 0)
    return;
#endif
  if(mc->probedef != NULL)
    scamper_dealias_probedef_free(mc->probedef);
  free(mc);
  return;
}

scamper_dealias_radargun_t *scamper_dealias_radargun_alloc(void)
{
  scamper_dealias_radargun_t *rg;
  rg = malloc_zero(sizeof(scamper_dealias_radargun_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(rg != NULL)
    rg->refcnt = 1;
#endif
  return rg;
}

void scamper_dealias_radargun_free(scamper_dealias_radargun_t *radargun)
{
  uint32_t i;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--radargun->refcnt > 0)
    return;
#endif
  if(radargun->probedefs != NULL)
    {
      for(i=0; i<radargun->probedefc; i++)
	if(radargun->probedefs[i] != NULL)
	  scamper_dealias_probedef_free(radargun->probedefs[i]);
      free(radargun->probedefs);
    }
  free(radargun);
  return;
}

scamper_dealias_prefixscan_t *scamper_dealias_prefixscan_alloc(void)
{
  scamper_dealias_prefixscan_t *pf;
  pf = malloc_zero(sizeof(scamper_dealias_prefixscan_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(pf != NULL)
    pf->refcnt = 1;
#endif
  return pf;
}

void scamper_dealias_prefixscan_free(scamper_dealias_prefixscan_t *prefixscan)
{
  uint16_t i;

  if(prefixscan == NULL)
    return;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--prefixscan->refcnt > 0)
    return;
#endif

  if(prefixscan->a  != NULL) scamper_addr_free(prefixscan->a);
  if(prefixscan->b  != NULL) scamper_addr_free(prefixscan->b);
  if(prefixscan->ab != NULL) scamper_addr_free(prefixscan->ab);

  if(prefixscan->xs != NULL)
    {
      for(i=0; i<prefixscan->xc; i++)
	if(prefixscan->xs[i] != NULL)
	  scamper_addr_free(prefixscan->xs[i]);
      free(prefixscan->xs);
    }

  if(prefixscan->probedefs != NULL)
    {
      for(i=0; i<prefixscan->probedefc; i++)
	if(prefixscan->probedefs[i] != NULL)
	  scamper_dealias_probedef_free(prefixscan->probedefs[i]);
      free(prefixscan->probedefs);
    }

  free(prefixscan);

  return;
}

scamper_dealias_bump_t *scamper_dealias_bump_alloc(void)
{
  scamper_dealias_bump_t *bump;
  if((bump = malloc_zero(sizeof(scamper_dealias_bump_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  bump->refcnt = 1;
#endif
  if((bump->probedefs[0] = scamper_dealias_probedef_alloc()) == NULL ||
     (bump->probedefs[1] = scamper_dealias_probedef_alloc()) == NULL)
    goto err;
  return bump;

 err:
  if(bump != NULL) scamper_dealias_bump_free(bump);
  return NULL;
}

void scamper_dealias_bump_free(scamper_dealias_bump_t *bump)
{
#ifdef BUILDING_LIBSCAMPERFILE
  if(--bump->refcnt > 0)
    return;
#endif
  if(bump->probedefs[0] != NULL)
    scamper_dealias_probedef_free(bump->probedefs[0]);
  if(bump->probedefs[1] != NULL)
    scamper_dealias_probedef_free(bump->probedefs[1]);
  free(bump);
  return;
}

scamper_dealias_midarest_t *scamper_dealias_midarest_alloc(void)
{
  scamper_dealias_midarest_t *me;
  me = malloc_zero(sizeof(scamper_dealias_midarest_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(me != NULL)
    me->refcnt = 1;
#endif
  return me;
}

void scamper_dealias_midarest_free(scamper_dealias_midarest_t *me)
{
  uint16_t i;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--me->refcnt > 0)
    return;
#endif
  if(me->probedefs != NULL)
    {
      for(i=0; i<me->probedefc; i++)
	if(me->probedefs[i] != NULL)
	  scamper_dealias_probedef_free(me->probedefs[i]);
      free(me->probedefs);
    }
  free(me);
  return;
}

scamper_dealias_midardisc_round_t *scamper_dealias_midardisc_round_alloc(void)
{
  return malloc_zero(sizeof(scamper_dealias_midardisc_round_t));
}

void scamper_dealias_midardisc_round_free(scamper_dealias_midardisc_round_t *r)
{
  free(r);
  return;
}

scamper_dealias_midardisc_t *scamper_dealias_midardisc_alloc(void)
{
  scamper_dealias_midardisc_t *md;
  md = malloc_zero(sizeof(scamper_dealias_midardisc_t));
#ifdef BUILDING_LIBSCAMPERFILE
  if(md != NULL)
    md->refcnt = 1;
#endif
  return md;
}

void scamper_dealias_midardisc_free(scamper_dealias_midardisc_t *md)
{
  uint32_t i;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--md->refcnt > 0)
    return;
#endif
  if(md->probedefs != NULL)
    {
      for(i=0; i<md->probedefc; i++)
	if(md->probedefs[i] != NULL)
	  scamper_dealias_probedef_free(md->probedefs[i]);
      free(md->probedefs);
    }
  if(md->sched != NULL)
    {
      for(i=0; i<md->schedc; i++)
	if(md->sched[i] != NULL)
	  scamper_dealias_midardisc_round_free(md->sched[i]);
      free(md->sched);
    }
  if(md->startat != NULL)
    free(md->startat);
  free(md);
  return;
}

static uint16_t dealias_ipid16_diff(uint16_t a, uint16_t b)
{
  if(a <= b)
    return b - a;
  return (0xFFFFUL - a) + b + 1;
}

static int dealias_ipid16_inseq2(uint16_t a, uint16_t b, uint16_t fudge)
{
  if(a == b || dealias_ipid16_diff(a, b) > fudge)
    return 0;
  return 1;
}

static int dealias_ipid16_inseq3(uint32_t a,uint32_t b,uint32_t c,uint32_t f)
{
  if(a == b || b == c || a == c)
    return 0;

  if(a > b)
    b += 0x10000;
  if(a > c)
    c += 0x10000;

  if(a > b || b > c)
    return 0;
  if(f != 0 && (b - a > f || c - b > f))
    return 0;

  return 1;
}

static uint32_t dealias_ipid32_diff(uint32_t a, uint32_t b)
{
  if(a <= b)
    return b - a;
  return (0xFFFFFFFFUL - a) + b + 1;
}

static int dealias_ipid32_inseq2(uint32_t a, uint32_t b, uint32_t fudge)
{
  if(a == b || dealias_ipid32_diff(a, b) > fudge)
    return 0;
  return 1;
}

static int dealias_ipid32_inseq3(uint64_t a,uint64_t b,uint64_t c,uint64_t f)
{
  if(a == b || b == c || a == c)
    return 0;

  if(a > b)
    b += 0x100000000ULL;
  if(a > c)
    c += 0x100000000ULL;

  if(a > b || b > c)
    return 0;
  if(f != 0 && (b - a > f || c - b > f))
    return 0;

  return 1;
}

static int dealias_ipid16_bo(scamper_dealias_probe_t **probes, size_t probec)
{
  scamper_dealias_probe_t **s = NULL;
  uint16_t a, b, c = 1, max_bs = 0, max_nobs = 0, u16;
  size_t i;
  int rc = 2;

  if((s = memdup(probes, sizeof(scamper_dealias_probe_t *) * probec)) == NULL)
    return -1;
  array_qsort((void **)s, probec, (array_cmp_t)dealias_probe_def_cmp);

  for(i=0; i<probec; i++)
    {
      if(i+1 == probec || s[i]->def != s[i+1]->def)
	{
	  if(c >= 3)
	    {
	      if(max_nobs < max_bs)
		rc = 0;
	      else if(max_nobs > max_bs)
		rc = 1;
	      if(rc == 0)
		goto done;
	    }
	  c = 1; max_nobs = 0; max_bs = 0;
	}
      else
	{
	  a = s[i]->replies[0]->ipid; b = s[i+1]->replies[0]->ipid;
	  u16 = dealias_ipid16_diff(a, b);
	  if(u16 > max_nobs || max_nobs == 0)
	    max_nobs = u16;
	  u16 = dealias_ipid16_diff(byteswap16(a), byteswap16(b));
	  if(u16 > max_bs || max_bs == 0)
	    max_bs = u16;
	  c++;
	}
    }

 done:
  if(s != NULL) free(s);
  return rc;
}

static int dealias_ipid16_inseq(scamper_dealias_probe_t **probes,
				size_t probec, uint16_t fudge, int bs)
{
  uint16_t a, b, c;
  size_t i;

  /*
   * do a preliminary check to see if the ipids could be in sequence with
   * two samples.
   */
  if(probec == 2)
    {
      /* if it is a strict sequence check, we don't actually know */
      if(fudge == 0)
	return 1;

      a = probes[0]->replies[0]->ipid;
      b = probes[1]->replies[0]->ipid;
      if(bs != 0)
	{
	  a = byteswap16(a);
	  b = byteswap16(b);
	}
      if(dealias_ipid16_inseq2(a, b, fudge) != 0)
	return 1;
      return 0;
    }

  for(i=0; i+2<probec; i++)
    {
      a = probes[i+0]->replies[0]->ipid;
      b = probes[i+1]->replies[0]->ipid;
      c = probes[i+2]->replies[0]->ipid;
      if(bs != 0)
	{
	  a = byteswap16(a);
	  b = byteswap16(b);
	  c = byteswap16(c);
	}
      if(dealias_ipid16_inseq3(a, b, c, fudge) == 0)
	return 0;
    }

  return 1;
}

static int dealias_ipid32_bo(scamper_dealias_probe_t **probes, size_t probec)
{
  scamper_dealias_probe_t **s = NULL;
  uint32_t a, b, c = 1, max_bs = 0, max_nobs = 0, u32;
  size_t i;
  int rc = 2;

  if((s = memdup(probes, sizeof(scamper_dealias_probe_t *) * probec)) == NULL)
    return -1;
  array_qsort((void **)s, probec, (array_cmp_t)dealias_probe_def_cmp);

  for(i=0; i<probec; i++)
    {
      if(i+1 == probec || s[i]->def != s[i+1]->def)
	{
	  if(c >= 3)
	    {
	      if(max_nobs < max_bs)
		rc = 0;
	      else if(max_nobs > max_bs)
		rc = 1;
	      if(rc == 0)
		goto done;
	    }
	  c = 1; max_nobs = 0; max_bs = 0;
	}
      else
	{
	  a = s[i]->replies[0]->ipid32; b = s[i+1]->replies[0]->ipid32;
	  u32 = dealias_ipid32_diff(a, b);
	  if(u32 > max_nobs || max_nobs == 0)
	    max_nobs = u32;
	  u32 = dealias_ipid32_diff(byteswap32(a), byteswap32(b));
	  if(u32 > max_bs || max_bs == 0)
	    max_bs = u32;
	  c++;
	}
    }

 done:
  if(s != NULL) free(s);
  return rc;
}

static int dealias_ipid32_inseq(scamper_dealias_probe_t **probes,
				size_t probec, uint16_t fudge, int bs)
{
  uint32_t a, b, c;
  size_t i;

  /*
   * do a preliminary check to see if the ipids could be in sequence with
   * two samples.
   */
  if(probec == 2)
    {
      /* if it is a strict sequence check, we don't actually know */
      if(fudge == 0)
	return 1;

      a = probes[0]->replies[0]->ipid32;
      b = probes[1]->replies[0]->ipid32;
      if(bs != 0)
	{
	  a = byteswap32(a);
	  b = byteswap32(b);
	}
      if(dealias_ipid32_inseq2(a, b, fudge) != 0)
	return 1;
      return 0;
    }

  for(i=0; i+2<probec; i++)
    {
      a = probes[i+0]->replies[0]->ipid32;
      b = probes[i+1]->replies[0]->ipid32;
      c = probes[i+2]->replies[0]->ipid32;
      if(bs != 0)
	{
	  a = byteswap32(a);
	  b = byteswap32(b);
	  c = byteswap32(c);
	}
      if(dealias_ipid32_inseq3(a, b, c, fudge) == 0)
	return 0;
    }

  return 1;
}

int scamper_dealias_ipid_inseq(scamper_dealias_probe_t **probes,
			       int probec, uint16_t fudge, int bs)
{
  static int (*const inseq[])(scamper_dealias_probe_t **, size_t, uint16_t,
			      int) = {
    dealias_ipid16_inseq,
    dealias_ipid32_inseq,
  };
  static int (*const bo[])(scamper_dealias_probe_t **, size_t) = {
    dealias_ipid16_bo,
    dealias_ipid32_bo,
  };
  int i, x;

  if(probec < 2)
    return -1;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(probes[0]->def->dst))
    x = 0;
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(probes[0]->def->dst))
    x = 1;
  else
    return -1;

  if(bs == 3 && fudge == 0)
    {
      if((i = bo[x](probes, (size_t)probec)) == -1)
	return -1;
      return inseq[x](probes, (size_t)probec, fudge, i);
    }

  if(bs == 2 || bs == 3)
    {
      if(inseq[x](probes, (size_t)probec, fudge, 0) == 1)
	return 1;
      return inseq[x](probes, (size_t)probec, fudge, 1);
    }

  return inseq[x](probes, (size_t)probec, fudge, bs);
}

int scamper_dealias_probes_alloc(scamper_dealias_t *dealias, uint32_t cnt)
{
  size_t size = cnt * sizeof(scamper_dealias_probe_t *);
  if((dealias->probes = malloc_zero(size)) == NULL)
    return -1;
  return 0;
}

int scamper_dealias_replies_alloc(scamper_dealias_probe_t *probe, uint16_t cnt)
{
  size_t size = cnt * sizeof(scamper_dealias_reply_t *);
  if((probe->replies = malloc_zero(size)) == NULL)
    return -1;
  return 0;
}

int scamper_dealias_radargun_probedefs_alloc(scamper_dealias_radargun_t *rg,
					     uint32_t probedefc)
{
  size_t len = probedefc * sizeof(scamper_dealias_probedef_t *);
  if((rg->probedefs = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

int scamper_dealias_midarest_probedefs_alloc(scamper_dealias_midarest_t *me,
					     uint16_t probedefc)
{
  size_t len = probedefc * sizeof(scamper_dealias_probedef_t *);
  if((me->probedefs = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

int scamper_dealias_midardisc_probedefs_alloc(scamper_dealias_midardisc_t *md,
					      uint32_t probedefc)
{
  size_t len = probedefc * sizeof(scamper_dealias_probedef_t *);
  if((md->probedefs = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

int scamper_dealias_midardisc_sched_alloc(scamper_dealias_midardisc_t *md,
					  uint32_t schedc)
{
  size_t len = schedc * sizeof(scamper_dealias_midardisc_round_t *);
  if((md->sched = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

typedef struct dealias_resolv
{
  scamper_dealias_probe_t **probes;
  int                       probec;
  int                       probet;
} dealias_resolv_t;

static int dealias_fudge_inseq(scamper_dealias_probe_t *pr_a,
			       scamper_dealias_probe_t *pr_b,
			       int bs, int fudge)
{
  uint32_t a = pr_a->replies[0]->ipid;
  uint32_t b = pr_b->replies[0]->ipid;

  if(bs != 0)
    {
      a = byteswap16(a);
      b = byteswap16(b);
    }

  if(a > b)
    b += 0x10000;

  if((int)(b - a) > fudge)
    return 0;

  return 1;
}

int scamper_dealias_prefixscan_xs_add(scamper_dealias_t *dealias,
				      scamper_addr_t *addr)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  size_t tmp;

  if(array_find((void **)prefixscan->xs, prefixscan->xc, addr,
		(array_cmp_t)scamper_addr_cmp) != NULL)
    return 0;

  if((tmp = prefixscan->xc) == 65535)
    return -1;

  if(array_insert((void ***)&prefixscan->xs, &tmp, addr,
		  (array_cmp_t)scamper_addr_cmp) != 0)
    return -1;

  scamper_addr_use(addr);
  prefixscan->xc++;
  return 0;
}

int scamper_dealias_prefixscan_xs_in(scamper_dealias_t *dealias,
				     scamper_addr_t *addr)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  if(array_find((void **)prefixscan->xs, prefixscan->xc, addr,
		(array_cmp_t)scamper_addr_cmp) != NULL)
    return 1;
  return 0;
}

int scamper_dealias_prefixscan_xs_alloc(scamper_dealias_prefixscan_t *p,
					uint16_t xc)
{
  if((p->xs = malloc_zero(sizeof(scamper_addr_t *) * xc)) != NULL)
    return 0;
  return -1;
}

int scamper_dealias_prefixscan_probedefs_alloc(scamper_dealias_prefixscan_t *p,
					       uint32_t probedefc)
{
  uint32_t i;
  size_t len;
  len = probedefc * sizeof(scamper_dealias_probedef_t *);
  if((p->probedefs = malloc_zero(len)) == NULL)
    return -1;
  for(i=0; i<probedefc; i++)
    if((p->probedefs[i] = scamper_dealias_probedef_alloc()) == NULL)
      return -1;
  return 0;
}

int scamper_dealias_prefixscan_probedef_add(scamper_dealias_t *dealias,
				    const scamper_dealias_probedef_t *def)
{
  scamper_dealias_prefixscan_t *prefixscan = dealias->data;
  scamper_dealias_probedef_t *d;
  size_t size;

  /* make the probedef array one bigger */
  size = sizeof(scamper_dealias_probedef_t *) * (prefixscan->probedefc+1);
  if(realloc_wrap((void **)&prefixscan->probedefs, size) != 0 ||
     (d = scamper_dealias_probedef_alloc()) == NULL)
    return -1;

  /* add the probedef to the array */
  prefixscan->probedefs[prefixscan->probedefc] = d;
  memcpy(d, def, sizeof(scamper_dealias_probedef_t));

  /* update the probedef with an id, and get references to the addresses */
  d->id = prefixscan->probedefc++;
  scamper_addr_use(d->src);
  scamper_addr_use(d->dst);

  return 0;
}

int scamper_dealias_radargun_fudge(scamper_dealias_t *dealias,
				   scamper_dealias_probedef_t *def,
				   scamper_dealias_probedef_t **defs, int *cnt,
				   int fudge)
{
  scamper_dealias_radargun_t *rg = dealias->data;
  scamper_dealias_probe_t *pr, *pr_a, *pr_b;
  scamper_dealias_reply_t *re, *re_a, *re_b, *re_c;
  dealias_resolv_t *dr = NULL;
  dealias_resolv_t *drd;
  uint32_t pid, x;
  size_t tmp;
  int i, j, k, bs, inseq, d = 0;

  if(dealias->method != SCAMPER_DEALIAS_METHOD_RADARGUN)
    goto err;

  if((dr = malloc_zero(sizeof(dealias_resolv_t) * rg->probedefc)) == NULL)
    goto err;

  for(x=0; x<dealias->probec; x++)
    {
      pr = dealias->probes[x];
      pid = pr->def->id;

      /*
       * if this probedef has already been determined to be useless for
       * alias resolution, skip it
       */
      if(dr[pid].probec < 0)
	continue;

      if(pr->replyc > 1)
	{
	  if(dr[pid].probes != NULL)
	    free(dr[pid].probes);
	  dr[pid].probec = -1;

	  if(pr->def == def)
	    goto done;
	  continue;
	}

      /* total number of probes transmitted */
      dr[pid].probet++;

      if(pr->replyc == 0)
	continue;

      re = pr->replies[0];

      /*
       * with three replies, do some basic checks to see if we should
       * continue considering this probedef.
       */
      if(dr[pid].probec == 2)
	{
	  pr_a = dr[pid].probes[0];
	  pr_b = dr[pid].probes[1];
	  re_a = pr_a->replies[0];
	  re_b = pr_b->replies[0];

	  if((re->ipid == pr->ipid && re_a->ipid == pr_a->ipid &&
	      re_b->ipid == pr_b->ipid) ||
	     (re->ipid == re_a->ipid && re->ipid == re_b->ipid))
	    {
	      free(dr[pid].probes);
	      dr[pid].probec = -1;

	      if(pr->def == def)
		goto done;
	      continue;
	    }
	}

      tmp = dr[pid].probec;
      if(array_insert((void ***)&dr[pid].probes, &tmp, pr, NULL) != 0)
	goto err;
      dr[pid].probec = tmp;
    }

  /* figure out if we should byteswap the ipid sequence */
  if(dr[def->id].probec < 3)
    goto done;
  re_a = dr[def->id].probes[0]->replies[0];
  re_b = dr[def->id].probes[1]->replies[0];
  re_c = dr[def->id].probes[2]->replies[0];
  if(re_a->ipid < re_b->ipid)
    i = re_b->ipid - re_a->ipid;
  else
    i = 0x10000 + re_b->ipid - re_a->ipid;
  if(re_b->ipid < re_c->ipid)
    i += re_c->ipid - re_b->ipid;
  else
    i += 0x10000 + re_c->ipid - re_b->ipid;
  if(byteswap16(re_a->ipid) < byteswap16(re_b->ipid))
    j = byteswap16(re_b->ipid) - byteswap16(re_a->ipid);
  else
    j = 0x10000 + byteswap16(re_b->ipid) - byteswap16(re_a->ipid);
  if(byteswap16(re_b->ipid) < byteswap16(re_c->ipid))
    j += byteswap16(re_c->ipid) - byteswap16(re_b->ipid);
  else
    j += 0x10000 + byteswap16(re_c->ipid) - byteswap16(re_b->ipid);
  if(i < j)
    bs = 0;
  else
    bs = 1;

  /* for each probedef, consider if it could be an alias */
  drd = &dr[def->id]; d = 0;
  for(pid=0; pid<rg->probedefc; pid++)
    {
      if(rg->probedefs[pid] == def || dr[pid].probec < 3)
	continue;

      j = 0; k = 0;

      /* get the first ipid */
      if(timeval_cmp(&drd->probes[j]->tx, &dr[pid].probes[k]->tx) < 0)
	pr_a = drd->probes[j++];
      else
	pr_a = dr[pid].probes[k++];

      for(;;)
	{
	  if(timeval_cmp(&drd->probes[j]->tx, &dr[pid].probes[k]->tx) < 0)
	    pr_b = drd->probes[j++];
	  else
	    pr_b = dr[pid].probes[k++];

	  if((inseq = dealias_fudge_inseq(pr_a, pr_b, bs, fudge)) == 0)
	    break;

	  if(j == drd->probec || k == dr[pid].probec)
	    break;
	}

      /*
       * if the pairs do not appear to have insequence IP-ID values, then
       * abandon
       */
      if(inseq == 0)
	continue;

      defs[d++] = rg->probedefs[pid];
      if(d == *cnt)
	break;
    }

 done:
  *cnt = d;
  for(x=0; x<rg->probedefc; x++)
    if(dr[x].probec > 0)
      free(dr[x].probes);
  free(dr);
  return 0;

 err:
  if(dr != NULL)
    {
      for(x=0; x<rg->probedefc; x++)
	if(dr[x].probec > 0)
	  free(dr[x].probes);
      free(dr);
    }
  return -1;
}

char *scamper_dealias_method_tostr(uint8_t method, char *buf, size_t len)
{
  static const char *m[] = {
    NULL,
    "mercator",
    "ally",
    "radargun",
    "prefixscan",
    "bump",
    "midarest",
    "midardisc",
  };
  if(method >= sizeof(m) / sizeof(char *) || m[method] == NULL)
    snprintf(buf, len, "%d", method);
  else
    snprintf(buf, len, "%s", m[method]);
  return buf;
}

char *scamper_dealias_result_tostr(uint8_t result, char *buf, size_t len)
{
  static const char *t[] = {
    "none",
    "aliases",
    "not-aliases",
    "halted",
    "ipid-echo",
  };
  if(result >= sizeof(t) / sizeof(char *) || t[result] == NULL)
    snprintf(buf, len, "%d", result);
  else
    snprintf(buf, len, "%s", t[result]);
  return buf;
}

void scamper_dealias_free(scamper_dealias_t *dealias)
{
  uint32_t i;

  if(dealias == NULL)
    return;

  if(dealias->probes != NULL)
    {
      for(i=0; i<dealias->probec; i++)
	if(dealias->probes[i] != NULL)
	  scamper_dealias_probe_free(dealias->probes[i]);
      free(dealias->probes);
    }

  if(dealias->cycle != NULL) scamper_cycle_free(dealias->cycle);
  if(dealias->list != NULL)  scamper_list_free(dealias->list);

  if(dealias->data != NULL)
    {
      assert(dealias->method != 0);
      assert(dealias->method <= SCAMPER_DEALIAS_METHOD_MAX);
      if(dealias->method == SCAMPER_DEALIAS_METHOD_MERCATOR)
	scamper_dealias_mercator_free(dealias->data);
      else if(dealias->method == SCAMPER_DEALIAS_METHOD_ALLY)
	scamper_dealias_ally_free(dealias->data);
      else if(dealias->method == SCAMPER_DEALIAS_METHOD_RADARGUN)
	scamper_dealias_radargun_free(dealias->data);
      else if(dealias->method == SCAMPER_DEALIAS_METHOD_PREFIXSCAN)
	scamper_dealias_prefixscan_free(dealias->data);
      else if(dealias->method == SCAMPER_DEALIAS_METHOD_BUMP)
	scamper_dealias_bump_free(dealias->data);
      else if(dealias->method == SCAMPER_DEALIAS_METHOD_MIDAREST)
	scamper_dealias_midarest_free(dealias->data);
      else if(dealias->method == SCAMPER_DEALIAS_METHOD_MIDARDISC)
	scamper_dealias_midardisc_free(dealias->data);
    }

  free(dealias);
  return;
}

scamper_dealias_t *scamper_dealias_alloc(void)
{
  return (scamper_dealias_t *)malloc_zero(sizeof(scamper_dealias_t));
}
