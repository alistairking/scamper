/*
 * scamper_host
 *
 * $Id: scamper_host.c,v 1.28 2025/02/23 05:38:14 mjl Exp $
 *
 * Copyright (C) 2018-2025 Matthew Luckie
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

void scamper_host_rr_svcb_param_free(scamper_host_rr_svcb_param_t *param)
{
  if(param == NULL)
    return;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--param->refcnt > 0)
    return;
#endif

  if(param->val != NULL)
    free(param->val);
  free(param);
  return;
}

scamper_host_rr_svcb_param_t *
scamper_host_rr_svcb_param_alloc(uint16_t key,uint16_t len,const uint8_t *val)
{
  scamper_host_rr_svcb_param_t *param;

  if((param = malloc_zero(sizeof(scamper_host_rr_svcb_param_t))) == NULL)
    return NULL;

#ifdef BUILDING_LIBSCAMPERFILE
  param->refcnt = 1;
#endif

  if(len > 0)
    {
      if((param->val = malloc(len)) == NULL)
	{
	  free(param);
	  return NULL;
	}
      memcpy(param->val, val, len);
    }

  param->key = key;
  param->len = len;
  return param;
}

void scamper_host_rr_svcb_free(scamper_host_rr_svcb_t *svcb)
{
  uint16_t i;

  if(svcb == NULL)
    return;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--svcb->refcnt > 0)
    return;
#endif

  if(svcb->target != NULL)
    free(svcb->target);

  if(svcb->params != NULL)
    {
      for(i=0; i<svcb->paramc; i++)
        if(svcb->params[i] != NULL)
	  scamper_host_rr_svcb_param_free(svcb->params[i]);
      free(svcb->params);
    }

  free(svcb);
  return;
}

scamper_host_rr_svcb_t *scamper_host_rr_svcb_alloc(uint16_t prio,
						   const char *target,
						   uint16_t paramc)
{
  scamper_host_rr_svcb_t *svcb;
  size_t len;

  if((svcb = malloc_zero(sizeof(scamper_host_rr_svcb_t))) == NULL)
    return NULL;

#ifdef BUILDING_LIBSCAMPERFILE
  svcb->refcnt = 1;
#endif

  len = sizeof(scamper_host_rr_svcb_param_t *) * paramc;
  if((target != NULL && (svcb->target = strdup(target)) == NULL) ||
     (len > 0 && (svcb->params = malloc_zero(len)) == NULL))
    goto err;

  svcb->paramc = paramc;
  svcb->priority = prio;
  return svcb;

 err:
  if(svcb != NULL) scamper_host_rr_svcb_free(svcb);
  return NULL;
}

scamper_host_rr_opt_elem_t *scamper_host_rr_opt_elem_alloc(uint16_t code,
                                                           uint16_t len,
                                                           const uint8_t *data)
{
  scamper_host_rr_opt_elem_t *elem;

  if((elem = malloc_zero(sizeof(scamper_host_rr_opt_elem_t))) == NULL)
    return NULL;

#ifdef BUILDING_LIBSCAMPERFILE
  elem->refcnt = 1;
#endif

  if(len > 0)
    {
      if((elem->data = malloc(len)) == NULL)
	{
	  free(elem);
	  return NULL;
	}
      memcpy(elem->data, data, len);
    }

  elem->code = code;
  elem->len = len;
  return elem;
}

void scamper_host_rr_opt_elem_free(scamper_host_rr_opt_elem_t *elem)
{
  if(elem == NULL)
    return;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--elem->refcnt > 0)
    return;
#endif

  if(elem->data != NULL)
    free(elem->data);
  free(elem);
  return;
}

void scamper_host_rr_opt_free(scamper_host_rr_opt_t *opt)
{
  uint16_t i;

  if(opt == NULL)
    return;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--opt->refcnt > 0)
    return;
#endif

  if(opt->elems != NULL)
    {
      for(i=0; i<opt->elemc; i++)
        if(opt->elems[i] != NULL)
	  scamper_host_rr_opt_elem_free(opt->elems[i]);
      free(opt->elems);
    }

  free(opt);
  return;
}

scamper_host_rr_opt_t *scamper_host_rr_opt_alloc(uint16_t elemc)
{
  scamper_host_rr_opt_t *opt;
  size_t len;

  if((opt = malloc_zero(sizeof(scamper_host_rr_opt_t))) == NULL)
    return NULL;

#ifdef BUILDING_LIBSCAMPERFILE
  opt->refcnt = 1;
#endif

  len = sizeof(scamper_host_rr_opt_elem_t *) * elemc;
  if(len > 0 && (opt->elems = malloc_zero(len)) == NULL)
    {
      scamper_host_rr_opt_free(opt);
      return NULL;
    }

  opt->elemc = elemc;
  return opt;
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

	case SCAMPER_HOST_TYPE_SVCB:
	  return SCAMPER_HOST_RR_DATA_TYPE_SVCB;
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

  if(type == SCAMPER_HOST_TYPE_OPT)
    return SCAMPER_HOST_RR_DATA_TYPE_OPT;

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

    case SCAMPER_HOST_RR_DATA_TYPE_OPT:
      if(rr->un.opt != NULL) scamper_host_rr_opt_free(rr->un.opt);
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_SVCB:
      if(rr->un.svcb != NULL) scamper_host_rr_svcb_free(rr->un.svcb);
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

int scamper_host_queries_alloc(scamper_host_t *host, uint8_t n)
{
  size_t len = n * sizeof(scamper_host_query_t *);
  if(host->queries != NULL ||
     (host->queries = malloc_zero(len)) == NULL)
    return -1;
  host->qcount = n;
  return 0;
}

int scamper_host_query_rr_alloc(scamper_host_query_t *query,
				uint16_t an_c, uint16_t ns_c, uint16_t ar_c)
{
  if(query->an != NULL || query->ns != NULL || query->ar != NULL)
    return -1;
  query->ancount = an_c;
  query->nscount = ns_c;
  query->arcount = ar_c;
  if(an_c > 0 &&
     (query->an = malloc_zero(an_c * sizeof(scamper_host_rr_t *))) == NULL)
    return -1;
  if(ns_c > 0 &&
     (query->ns = malloc_zero(ns_c * sizeof(scamper_host_rr_t *))) == NULL)
    return -1;
  if(ar_c > 0 &&
     (query->ar = malloc_zero(ar_c * sizeof(scamper_host_rr_t *))) == NULL)
    return -1;
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
  static const char *r[] = {
    "NoError", "FormErr", "ServFail", "NXDomain", /*  0 -  3 */
    "NotImp", "Refused", "YXDomain", "YXRRSet",   /*  4 -  7 */
    "NXRRSet", "NotAuth", "NotZone", "DSOTYPENI", /*  8 - 11 */
    NULL, NULL, NULL, NULL,                       /* 12 - 15 */
    "BADVERS", "BADKEY", "BADTIME", "BADMODE"     /* 16 - 19 */
    "BADNAME", "BADALG", "BADTRUNC", "BADCOOKIE", /* 20 - 23 */
  };
  if(rcode >= sizeof(r) / sizeof(char *))
    snprintf(b, l, "%u", rcode);
  else
    snprintf(b, l, "%s", r[rcode]);
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
    case SCAMPER_HOST_TYPE_SVCB: snprintf(b, l, "SVCB"); break;
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
  if(host->ecs != NULL) free(host->ecs);

  free(host);
  return;
}

scamper_host_t *scamper_host_alloc(void)
{
  return (scamper_host_t *)malloc_zero(sizeof(scamper_host_t));
}
