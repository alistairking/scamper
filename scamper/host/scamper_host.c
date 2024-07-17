/*
 * scamper_host
 *
 * $Id: scamper_host.c,v 1.19 2024/04/27 21:11:55 mjl Exp $
 *
 * Copyright (C) 2018-2024 Matthew Luckie
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

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_host.h"
#include "scamper_host_int.h"

#include "utils.h"

int scamper_host_query_counts(scamper_host_query_t *q,
			      uint16_t an, uint16_t ns, uint16_t ar)
{
  q->ancount = an;
  q->nscount = ns;
  q->arcount = ar;

  if(an > 0 && (q->an = malloc_zero(sizeof(scamper_host_rr_t *) * an)) == NULL)
    return -1;
  if(ns > 0 && (q->ns = malloc_zero(sizeof(scamper_host_rr_t *) * ns)) == NULL)
    return -1;
  if(ar > 0 && (q->ar = malloc_zero(sizeof(scamper_host_rr_t *) * ar)) == NULL)
    return -1;

  return 0;
}

void scamper_host_rr_txt_free(scamper_host_rr_txt_t *txt)
{
  uint16_t i;
  if(txt == NULL)
    return;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--txt->refcnt > 0)
    return;
#endif
  if(txt->strs != NULL)
    {
      for(i=0; i<txt->strc; i++)
	if(txt->strs[i] != NULL)
	  free(txt->strs[i]);
      free(txt->strs);
    }
  free(txt);
  return;
}

scamper_host_rr_txt_t *scamper_host_rr_txt_alloc(uint16_t strc)
{
  scamper_host_rr_txt_t *txt;
  if((txt = malloc_zero(sizeof(scamper_host_rr_txt_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  txt->refcnt = 1;
#endif
  if(strc > 0 &&
     (txt->strs = malloc_zero(sizeof(char *) * strc)) == NULL)
    {
      scamper_host_rr_txt_free(txt);
      return NULL;
    }
  txt->strc = strc;
  return txt;
}

void scamper_host_rr_soa_free(scamper_host_rr_soa_t *soa)
{
  if(soa == NULL)
    return;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--soa->refcnt > 0)
    return;
#endif
  if(soa->mname != NULL) free(soa->mname);
  if(soa->rname != NULL) free(soa->rname);
  free(soa);
  return;
}

scamper_host_rr_soa_t *scamper_host_rr_soa_alloc(const char *mn,const char *rn)
{
  scamper_host_rr_soa_t *soa;
  if((soa = malloc_zero(sizeof(scamper_host_rr_soa_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  soa->refcnt = 1;
#endif
  if((soa->mname = strdup(mn)) == NULL ||
     (soa->rname = strdup(rn)) == NULL)
    {
      scamper_host_rr_soa_free(soa);
      return NULL;
    }
  return soa;
}

void scamper_host_rr_mx_free(scamper_host_rr_mx_t *mx)
{
  if(mx == NULL)
    return;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--mx->refcnt > 0)
    return;
#endif
  if(mx->exchange != NULL) free(mx->exchange);
  free(mx);
  return;
}

scamper_host_rr_mx_t *scamper_host_rr_mx_alloc(uint16_t pref, const char *exch)
{
  scamper_host_rr_mx_t *mx;
  if((mx = malloc_zero(sizeof(scamper_host_rr_mx_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  mx->refcnt = 1;
#endif
  if((mx->exchange = strdup(exch)) == NULL)
    {
      scamper_host_rr_mx_free(mx);
      return NULL;
    }
  mx->preference = pref;
  return mx;
}

const char *scamper_host_rr_data_str_typestr(uint16_t class, uint16_t type)
{
  if(class == SCAMPER_HOST_CLASS_IN)
    {
      if(type == SCAMPER_HOST_TYPE_NS) return "nsdname";
      if(type == SCAMPER_HOST_TYPE_CNAME) return "cname";
      if(type == SCAMPER_HOST_TYPE_PTR) return "ptrdname";
    }
  return NULL;
}

int scamper_host_rr_data_type(uint16_t class, uint16_t type)
{
  if(class == SCAMPER_HOST_CLASS_IN)
    {
      switch(type)
	{
	case SCAMPER_HOST_TYPE_NS:
	case SCAMPER_HOST_TYPE_CNAME:
	case SCAMPER_HOST_TYPE_PTR:
	  return SCAMPER_HOST_RR_DATA_TYPE_STR;

	case SCAMPER_HOST_TYPE_A:
	case SCAMPER_HOST_TYPE_AAAA:
	  return SCAMPER_HOST_RR_DATA_TYPE_ADDR;

	case SCAMPER_HOST_TYPE_SOA:
	  return SCAMPER_HOST_RR_DATA_TYPE_SOA;

	case SCAMPER_HOST_TYPE_MX:
	  return SCAMPER_HOST_RR_DATA_TYPE_MX;

	case SCAMPER_HOST_TYPE_TXT:
	  return SCAMPER_HOST_RR_DATA_TYPE_TXT;
	}
    }
  else if(class == SCAMPER_HOST_CLASS_CH)
    {
      switch(type)
	{
	case SCAMPER_HOST_TYPE_TXT:
	  return SCAMPER_HOST_RR_DATA_TYPE_TXT;
	}
    }

  return -1;
}

void scamper_host_rr_free(scamper_host_rr_t *rr)
{
  if(rr == NULL)
    return;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--rr->refcnt > 0)
    return;
#endif

  if(rr->name != NULL)
    free(rr->name);

  switch(scamper_host_rr_data_type(rr->class, rr->type))
    {
    case SCAMPER_HOST_RR_DATA_TYPE_ADDR:
      if(rr->un.addr != NULL) scamper_addr_free(rr->un.addr);
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_STR:
      if(rr->un.str != NULL) free(rr->un.str);
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_SOA:
      if(rr->un.soa != NULL) scamper_host_rr_soa_free(rr->un.soa);
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_MX:
      if(rr->un.mx != NULL) scamper_host_rr_mx_free(rr->un.mx);
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_TXT:
      if(rr->un.txt != NULL) scamper_host_rr_txt_free(rr->un.txt);
      break;
    }

  free(rr);
  return;
}

scamper_host_rr_t *scamper_host_rr_alloc(const char *name, uint16_t class,
					 uint16_t type, uint32_t ttl)
{
  scamper_host_rr_t *rr;
  if((rr = malloc_zero(sizeof(scamper_host_rr_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  rr->refcnt = 1;
#endif
  if((rr->name = strdup(name)) == NULL)
    {
      scamper_host_rr_free(rr);
      return NULL;
    }
  rr->class = class;
  rr->type = type;
  rr->ttl = ttl;
  return rr;
}

void scamper_host_query_free(scamper_host_query_t *query)
{
  int r;

  if(query == NULL)
    return;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--query->refcnt > 0)
    return;
#endif

  if(query->an != NULL)
    {
      for(r=0; r<query->ancount; r++)
	scamper_host_rr_free(query->an[r]);
      free(query->an);
    }
  if(query->ns != NULL)
    {
      for(r=0; r<query->nscount; r++)
	scamper_host_rr_free(query->ns[r]);
      free(query->ns);
    }
  if(query->ar != NULL)
    {
      for(r=0; r<query->arcount; r++)
	scamper_host_rr_free(query->ar[r]);
      free(query->ar);
    }

  free(query);
  return;
}

int scamper_host_queries_alloc(scamper_host_t *host, int n)
{
  size_t len = n * sizeof(scamper_host_query_t *);
  if((host->queries = malloc_zero(len)) == NULL)
    return -1;
  return 0;
}

int scamper_host_query_rr_alloc(scamper_host_query_t *query)
{
  size_t len;
  if(query->ancount > 0)
    {
      len = query->ancount * sizeof(scamper_host_rr_t *);
      if((query->an = malloc_zero(len)) == NULL)
	return -1;
    }
  if(query->nscount > 0)
    {
      len = query->nscount * sizeof(scamper_host_rr_t *);
      if((query->ns = malloc_zero(len)) == NULL)
	return -1;
    }
  if(query->arcount > 0)
    {
      len = query->arcount * sizeof(scamper_host_rr_t *);
      if((query->ar = malloc_zero(len)) == NULL)
	return -1;
    }
  return 0;
}

scamper_host_query_t *scamper_host_query_alloc(void)
{
  scamper_host_query_t *q;
  if((q = malloc_zero(sizeof(scamper_host_query_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  q->refcnt = 1;
#endif
  return q;
}

char *scamper_host_rcode_tostr(uint8_t rcode, char *b, size_t l)
{
  switch(rcode)
    {
    case SCAMPER_HOST_QUERY_RCODE_NOERROR:  snprintf(b, l, "NoError");  break;
    case SCAMPER_HOST_QUERY_RCODE_FORMERR:  snprintf(b, l, "FormErr");  break;
    case SCAMPER_HOST_QUERY_RCODE_SERVFAIL: snprintf(b, l, "ServFail"); break;
    case SCAMPER_HOST_QUERY_RCODE_NXDOMAIN: snprintf(b, l, "NXDomain"); break;
    case SCAMPER_HOST_QUERY_RCODE_NOTIMP:   snprintf(b, l, "NotImp");   break;
    case SCAMPER_HOST_QUERY_RCODE_REFUSED:  snprintf(b, l, "Refused");  break;
    case SCAMPER_HOST_QUERY_RCODE_YXDOMAIN: snprintf(b, l, "YXDomain"); break;
    case SCAMPER_HOST_QUERY_RCODE_YXRRSET:  snprintf(b, l, "YXRRSet");  break;
    case SCAMPER_HOST_QUERY_RCODE_NXRRSET:  snprintf(b, l, "NXRRSet");  break;
    case SCAMPER_HOST_QUERY_RCODE_NOTAUTH:  snprintf(b, l, "NotAuth");  break;
    case SCAMPER_HOST_QUERY_RCODE_NOTZONE:  snprintf(b, l, "NotZone");  break;
    default: snprintf(b, l, "%u", rcode); break;
    }

  return b;
}

char *scamper_host_qtype_tostr(uint16_t qtype, char *b, size_t l)
{
  switch(qtype)
    {
    case SCAMPER_HOST_TYPE_A: snprintf(b, l, "A"); break;
    case SCAMPER_HOST_TYPE_NS: snprintf(b, l, "NS"); break;
    case SCAMPER_HOST_TYPE_CNAME: snprintf(b, l, "CNAME"); break;
    case SCAMPER_HOST_TYPE_SOA: snprintf(b, l, "SOA"); break;
    case SCAMPER_HOST_TYPE_PTR: snprintf(b, l, "PTR"); break;
    case SCAMPER_HOST_TYPE_MX: snprintf(b, l, "MX"); break;
    case SCAMPER_HOST_TYPE_TXT: snprintf(b, l, "TXT"); break;
    case SCAMPER_HOST_TYPE_AAAA: snprintf(b, l, "AAAA"); break;
    case SCAMPER_HOST_TYPE_DS: snprintf(b, l, "DS"); break;
    case SCAMPER_HOST_TYPE_SSHFP: snprintf(b, l, "SSHFP"); break;
    case SCAMPER_HOST_TYPE_RRSIG: snprintf(b, l, "RRSIG"); break;
    case SCAMPER_HOST_TYPE_NSEC: snprintf(b, l, "NSEC"); break;
    case SCAMPER_HOST_TYPE_DNSKEY: snprintf(b, l, "DNSKEY"); break;
    case SCAMPER_HOST_TYPE_OPT: snprintf(b, l, "OPT"); break;
    default: snprintf(b, l, "%u", qtype); break;
    }

  return b;
}

char *scamper_host_qclass_tostr(uint16_t qclass, char *b, size_t l)
{
  if(qclass == SCAMPER_HOST_CLASS_IN)
    snprintf(b, l, "IN");
  else if(qclass == SCAMPER_HOST_CLASS_CH)
    snprintf(b, l, "CH");
  else
    snprintf(b, l, "%u", qclass);
  return b;
}

char *scamper_host_stop_tostr(const scamper_host_t *h, char *b, size_t l)
{
  static const char *r[] = {
    "NONE",
    "DONE",
    "TIMEOUT",
    "HALTED",
    "ERROR",
  };
  if(h->stop >= sizeof(r) / sizeof(char *))
    snprintf(b, l, "%d", h->stop);
  else
    snprintf(b, l, "%s", r[h->stop]);
  return b;

}

void scamper_host_free(scamper_host_t *host)
{
  int q;

  if(host == NULL)
    return;

  if(host->queries != NULL)
    {
      for(q=0; q<host->qcount; q++)
	scamper_host_query_free(host->queries[q]);
      free(host->queries);
    }

  if(host->qname != NULL) free(host->qname);
  if(host->src != NULL) scamper_addr_free(host->src);
  if(host->dst != NULL) scamper_addr_free(host->dst);
  if(host->cycle != NULL) scamper_cycle_free(host->cycle);
  if(host->list != NULL) scamper_list_free(host->list);

  free(host);
  return;
}

scamper_host_t *scamper_host_alloc(void)
{
  return (scamper_host_t *)malloc_zero(sizeof(scamper_host_t));
}
