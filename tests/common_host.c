/*
 * common_host : common functions for unit testing host
 *
 * $Id: common_host.c,v 1.9 2026/07/10 22:01:29 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024-2026 Matthew Luckie
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
#include "scamper_file.h"
#include "scamper_host.h"
#include "scamper_host_int.h"

#include "utils.h"

#include "common.h"
#include "common_ok.h"

typedef scamper_host_t * (*scamper_host_makefunc_t)(void);

typedef int (*cmp_func_t)(const void *, const void *);

static int host_soa_cmp(const scamper_host_rr_soa_t *in, const scamper_host_rr_soa_t *out)
{
  if((in->mname == NULL && out->mname != NULL) ||
     (in->mname != NULL && out->mname == NULL) ||
     (in->mname != NULL && strcmp(in->mname, out->mname) != 0) ||
     (in->rname == NULL && out->rname != NULL) ||
     (in->rname != NULL && out->rname == NULL) ||
     (in->rname != NULL && strcmp(in->rname, out->rname) != 0) ||
     in->serial != out->serial ||
     in->refresh != out->refresh ||
     in->retry != out->retry ||
     in->expire != out->expire ||
     in->minimum != out->minimum)
    return -1;
  return 0;
}

static int host_mx_cmp(const scamper_host_rr_mx_t *in, const scamper_host_rr_mx_t *out)
{
  if(in->preference != out->preference ||
     (in->exchange == NULL && out->exchange != NULL) ||
     (in->exchange != NULL && out->exchange == NULL) ||
     (in->exchange != NULL && strcasecmp(in->exchange, out->exchange) != 0))
    return -1;
  return 0;
}

static int host_txt_cmp(const scamper_host_rr_txt_t *in, const scamper_host_rr_txt_t *out)
{
  uint16_t i;

  if(in->strc != out->strc ||
     (in->strs == NULL && out->strs != NULL) ||
     (in->strs != NULL && out->strs == NULL))
    return -1;
  if(in->strs != NULL)
    {
      for(i=0; i<in->strc; i++)
	if(in->strs[i] == NULL || out->strs[i] == NULL ||
	   strcmp(in->strs[i], out->strs[i]) != 0)
	  return -1;
    }

  return 0;
}

static int host_opt_cmp(const scamper_host_rr_opt_t *in, const scamper_host_rr_opt_t *out)
{
  uint16_t i;

  if(in->elemc != out->elemc ||
     (in->elems == NULL && out->elems != NULL) ||
     (in->elems != NULL && out->elems == NULL))
    return -1;
  if(in->elems != NULL)
    {
      for(i=0; i<in->elemc; i++)
	{
	  if(in->elems[i] == NULL || out->elems[i] == NULL ||
	     in->elems[i]->code != out->elems[i]->code ||
	     in->elems[i]->len != out->elems[i]->len)
	    return -1;
	  if(in->elems[i]->len > 0 &&
	     (in->elems[i]->data == NULL || out->elems[i]->data == NULL ||
	      memcmp(in->elems[i]->data, out->elems[i]->data, in->elems[i]->len) != 0))
	    return -1;
	}
    }

  return 0;
}

static int host_svcb_cmp(const scamper_host_rr_svcb_t *in,
			 const scamper_host_rr_svcb_t *out)
{
  uint16_t i;

  if(str_ok(in->target, out->target) != 0 ||
     in->priority != out->priority ||
     in->paramc != out->paramc)
    return -1;

  for(i=0; i<in->paramc; i++)
    {
      if(in->params[i] == NULL || out->params[i] == NULL ||
	 in->params[i]->key != out->params[i]->key ||
	 in->params[i]->len != out->params[i]->len)
	return -1;
      if(in->params[i]->len > 0 &&
	 (in->params[i]->val == NULL || out->params[i]->val == NULL ||
	  memcmp(in->params[i]->val, out->params[i]->val,
		 in->params[i]->len) != 0))
	return -1;
    }

  return 0;
}

static int host_rr_ok(const scamper_host_rr_t *in, const scamper_host_rr_t *out)
{
  static cmp_func_t funcs[] = {
    NULL,
    (cmp_func_t)scamper_addr_cmp,
    (cmp_func_t)strcmp,
    (cmp_func_t)host_soa_cmp,
    (cmp_func_t)host_mx_cmp,
    (cmp_func_t)host_txt_cmp,
    (cmp_func_t)host_opt_cmp,
    (cmp_func_t)host_svcb_cmp,
  };
  size_t funcc = sizeof(funcs) / sizeof(cmp_func_t);
  int rrt;

  if(in->class != out->class ||
     in->type  != out->type  ||
     (in->name == NULL && out->name != NULL) ||
     (in->name != NULL && out->name == NULL) ||
     (in->name != NULL && strcmp(in->name, out->name) != 0) ||
     in->ttl != out->ttl ||
     (in->un.v == NULL && out->un.v != NULL) ||
     (in->un.v != NULL && out->un.v == NULL))
    return -1;

  if(in->un.v != NULL)
    {
      rrt = scamper_host_rr_data_type(in->class, in->type);
      if((size_t)rrt > funcc || funcs[rrt] == NULL)
	return -1;
      if(funcs[rrt](in->un.v, out->un.v) != 0)
	return -1;
    }

  return 0;
}

static int host_query_ok(const scamper_host_query_t *in, const scamper_host_query_t *out)
{
  uint16_t i;

  if(timeval_cmp(&in->tx, &out->tx) != 0 ||
     timeval_cmp(&in->rx, &out->rx) != 0 ||
     in->rcode != out->rcode ||
     in->flags != out->flags ||
     in->id != out->id ||
     in->ancount != out->ancount ||
     in->nscount != out->nscount ||
     in->arcount != out->arcount)
    return -1;

  for(i=0; i<in->ancount; i++)
    if(in->an[i] == NULL || out->an[i] == NULL ||
       host_rr_ok(in->an[i], out->an[i]) != 0)
      return -1;

  for(i=0; i<in->nscount; i++)
    if(in->ns[i] == NULL || out->ns[i] == NULL ||
       host_rr_ok(in->ns[i], out->ns[i]) != 0)
      return -1;

  for(i=0; i<in->arcount; i++)
    if(in->ar[i] == NULL || out->ar[i] == NULL ||
       host_rr_ok(in->ar[i], out->ar[i]) != 0)
      return -1;

  return 0;
}

int host_ok(const scamper_host_t *in, const scamper_host_t *out)
{
  uint8_t i;

  assert(in != NULL);
  if(out == NULL ||
     scamper_addr_cmp(in->src, out->src) != 0 ||
     scamper_addr_cmp(in->dst, out->dst) != 0 ||
     in->userid != out->userid ||
     timeval_cmp(&in->start, &out->start) != 0 ||
     in->flags != out->flags ||
     timeval_cmp(&in->wait_timeout, &out->wait_timeout) != 0 ||
     str_ok(in->errmsg, out->errmsg) != 0 ||
     in->stop != out->stop ||
     in->retries != out->retries ||
     in->qclass != out->qclass ||
     in->qtype != out->qtype ||
     strcmp(in->qname, out->qname) != 0 ||
     in->qcount != out->qcount)
    return -1;

  for(i=0; i<in->qcount; i++)
    if(in->queries[i] == NULL || out->queries[i] == NULL ||
       host_query_ok(in->queries[i], out->queries[i]) != 0)
      return -1;

  return 0;
}

/*
 * host_1:
 *
 * dns_opt_elem_nsid
 */
static scamper_host_t *host_1(void)
{
  scamper_host_t *host = NULL;
  scamper_host_query_t *q;
  scamper_host_rr_t *rr;
  scamper_host_rr_opt_t *opt;
  uint8_t nsid[] = {0xAA, 0xBB, 0xCC, 0xDD};

  if((host = scamper_host_alloc()) == NULL ||
     (host->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (host->dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL ||
     (host->qname = strdup("www.example.com")) == NULL ||
     scamper_host_queries_alloc(host, 1) != 0 ||
     (host->queries[0] = q = scamper_host_query_alloc()) == NULL ||
     scamper_host_query_rr_alloc(q, 0, 1, 1) != 0 ||
     (q->ns[0] = rr = scamper_host_rr_alloc("",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_SOA,
					    86400)) == NULL ||
     (rr->un.soa = scamper_host_rr_soa_alloc("a.root-servers.net",
					     "nstld.verisign-grs.com")) == NULL ||
     (q->ar[0] = rr = scamper_host_rr_alloc("",
					    4096,
					    SCAMPER_HOST_TYPE_OPT,
					    0)) == NULL ||
     (rr->un.opt = opt = scamper_host_rr_opt_alloc(2)) == NULL ||
     (opt->elems[0] = scamper_host_rr_opt_elem_alloc(SCAMPER_HOST_RR_OPT_ELEM_CODE_NSID, 0, NULL)) == NULL ||
     (opt->elems[1] = scamper_host_rr_opt_elem_alloc(SCAMPER_HOST_RR_OPT_ELEM_CODE_NSID, 4, nsid)) == NULL)
    goto err;

  host->userid               = 69;
  host->qclass               = SCAMPER_HOST_CLASS_IN;
  host->qtype                = SCAMPER_HOST_TYPE_A;
  host->stop                 = SCAMPER_HOST_STOP_DONE;
  host->start.tv_sec         = 1724828853;
  host->start.tv_usec        = 123456;
  host->wait_timeout.tv_sec  = 1;
  host->wait_timeout.tv_usec = 0;
  host->flags               |= SCAMPER_HOST_FLAG_NSID;
  host->flags               |= SCAMPER_HOST_FLAG_NORECURSE;
  q->id                      = 1;
  q->tx.tv_sec               = 1724828853;
  q->tx.tv_usec              = 123456;
  q->rx.tv_sec               = 1724828853;
  q->rx.tv_usec              = 223456;
  q->rcode                   = SCAMPER_HOST_QUERY_RCODE_NXDOMAIN;

  rr = q->ns[0];
  rr->un.soa->serial  = 2024090301;
  rr->un.soa->refresh = 1800;
  rr->un.soa->retry   = 900;
  rr->un.soa->expire  = 604800;
  rr->un.soa->minimum = 86400;

  return host;

 err:
  if(host != NULL) scamper_host_free(host);
  return NULL;
}

static scamper_host_t *host_2(void)
{
  scamper_host_t *host = NULL;

  if((host = scamper_host_alloc()) == NULL ||
     (host->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (host->dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL ||
     (host->qname = strdup("www.example.com")) == NULL ||
     (host->errmsg = strdup("hello world")) == NULL)
    goto err;

  host->userid               = 70;
  host->qclass               = SCAMPER_HOST_CLASS_IN;
  host->qtype                = SCAMPER_HOST_TYPE_A;
  host->stop                 = SCAMPER_HOST_STOP_ERROR;
  host->start.tv_sec         = 1724828854;
  host->start.tv_usec        = 123457;
  host->wait_timeout.tv_sec  = 1;
  host->wait_timeout.tv_usec = 0;

  return host;

 err:
  if(host != NULL) scamper_host_free(host);
  return host;
}

static scamper_host_t *host_3(void)
{
  scamper_host_t *host = NULL;
  scamper_host_query_t *q;
  scamper_host_rr_t *rr;

  if((host = scamper_host_alloc()) == NULL ||
     (host->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (host->dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL ||
     (host->qname = strdup("www.example.com")) == NULL ||
     scamper_host_queries_alloc(host, 1) != 0 ||
     (host->queries[0] = q = scamper_host_query_alloc()) == NULL ||
     scamper_host_query_rr_alloc(q, 2, 0, 0) != 0 ||
     (q->an[0] = rr = scamper_host_rr_alloc("www.example.com",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_A,
					    60)) == NULL ||
     (rr->un.addr = scamper_addr_fromstr_ipv4("192.0.2.3")) == NULL ||
     (q->an[1] = rr = scamper_host_rr_alloc("www.example.com",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_A,
					    60)) == NULL ||
     (rr->un.addr = scamper_addr_fromstr_ipv4("192.0.2.4")) == NULL)
    goto err;

  host->userid               = 71;
  host->qclass               = SCAMPER_HOST_CLASS_IN;
  host->qtype                = SCAMPER_HOST_TYPE_A;
  host->stop                 = SCAMPER_HOST_STOP_DONE;
  host->start.tv_sec         = 1724828855;
  host->start.tv_usec        = 123458;
  host->wait_timeout.tv_sec  = 2;
  host->wait_timeout.tv_usec = 0;
  host->retries              = 1;

  q->tx.tv_sec               = 1724828855;
  q->tx.tv_usec              = 123458;
  q->rx.tv_sec               = 1724828855;
  q->rx.tv_usec              = 223458;
  q->id                      = 2;

  return host;

 err:
  if(host != NULL) scamper_host_free(host);
  return host;
}

static scamper_host_t *host_4(void)
{
  scamper_host_t *host = NULL;
  scamper_host_query_t *q;
  scamper_host_rr_t *rr;

  if((host = scamper_host_alloc()) == NULL ||
     (host->src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (host->dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL ||
     (host->qname = strdup("www.example.com")) == NULL ||
     scamper_host_queries_alloc(host, 1) != 0 ||
     (host->queries[0] = q = scamper_host_query_alloc()) == NULL ||
     scamper_host_query_rr_alloc(q, 2, 0, 0) != 0 ||
     (q->an[0] = rr = scamper_host_rr_alloc("www.example.com",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_AAAA,
					    120)) == NULL ||
     (rr->un.addr = scamper_addr_fromstr_ipv6("2001:db8::3")) == NULL ||
     (q->an[1] = rr = scamper_host_rr_alloc("www.example.com",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_AAAA,
					    120)) == NULL ||
     (rr->un.addr = scamper_addr_fromstr_ipv6("2001:db8::4")) == NULL)
    goto err;

  host->userid               = 72;
  host->qclass               = SCAMPER_HOST_CLASS_IN;
  host->qtype                = SCAMPER_HOST_TYPE_AAAA;
  host->stop                 = SCAMPER_HOST_STOP_DONE;
  host->start.tv_sec         = 1724828856;
  host->start.tv_usec        = 123459;
  host->wait_timeout.tv_sec  = 2;
  host->wait_timeout.tv_usec = 0;
  host->retries              = 1;

  q->tx.tv_sec               = 1724828856;
  q->tx.tv_usec              = 123460;
  q->rx.tv_sec               = 1724828856;
  q->rx.tv_usec              = 223460;
  q->id                      = 3;

  return host;

 err:
  if(host != NULL) scamper_host_free(host);
  return host;
}

static scamper_host_t *host_5(void)
{
  scamper_host_t *host = NULL;
  scamper_host_query_t *q;
  scamper_host_rr_t *rr;

  if((host = scamper_host_alloc()) == NULL ||
     (host->src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (host->dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL ||
     (host->qname = strdup("luckie.org.nz")) == NULL ||
     scamper_host_queries_alloc(host, 2) != 0 ||
     (host->queries[0] = scamper_host_query_alloc()) == NULL ||
     (host->queries[1] = q = scamper_host_query_alloc()) == NULL ||
     scamper_host_query_rr_alloc(q, 3, 0, 0) != 0 ||
     (q->an[0] = rr = scamper_host_rr_alloc("luckie.org.nz",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_NS,
					    86400)) == NULL ||
     (rr->un.str = strdup("ns1.metaname.net")) == NULL ||
     (q->an[1] = rr = scamper_host_rr_alloc("luckie.org.nz",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_NS,
					    86400)) == NULL ||
     (rr->un.str = strdup("ns3.metaname.net")) == NULL ||
     (q->an[2] = rr = scamper_host_rr_alloc("luckie.org.nz",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_NS,
					    86400)) == NULL ||
     (rr->un.str = strdup("ns2.metaname.net")) == NULL)
    goto err;

  host->userid               = 73;
  host->qclass               = SCAMPER_HOST_CLASS_IN;
  host->qtype                = SCAMPER_HOST_TYPE_AAAA;
  host->stop                 = SCAMPER_HOST_STOP_DONE;
  host->start.tv_sec         = 1724828857;
  host->start.tv_usec        = 123470;
  host->wait_timeout.tv_sec  = 2;
  host->wait_timeout.tv_usec = 0;
  host->retries              = 1;

  q = host->queries[0];
  q->tx.tv_sec               = 1724828857;
  q->tx.tv_usec              = 123480;
  q->id                      = 4;

  q = host->queries[1];
  q->tx.tv_sec               = 1724828859;
  q->tx.tv_usec              = 123481;
  q->rx.tv_sec               = 1724828859;
  q->rx.tv_usec              = 481481;
  q->id                      = 5;

  return host;

 err:
  if(host != NULL) scamper_host_free(host);
  return host;
}

static scamper_host_t *host_6(void)
{
  scamper_host_t *host = NULL;
  scamper_host_query_t *q;
  scamper_host_rr_t *rr;

  if((host = scamper_host_alloc()) == NULL ||
     (host->src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (host->dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL ||
     (host->qname = strdup("example.com")) == NULL ||
     scamper_host_queries_alloc(host, 1) != 0 ||
     (host->queries[0] = q = scamper_host_query_alloc()) == NULL ||
     scamper_host_query_rr_alloc(q, 2, 0, 0) != 0 ||
     (q->an[0] = rr = scamper_host_rr_alloc("example.com",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_TXT,
					    86400)) == NULL ||
     (rr->un.txt = scamper_host_rr_txt_alloc(2)) == NULL ||
     (rr->un.txt->strs[0] = strdup("foo")) == NULL ||
     (rr->un.txt->strs[1] = strdup("bar")) == NULL ||
     (q->an[1] = rr = scamper_host_rr_alloc("example.com",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_TXT,
					    86400)) == NULL ||
     (rr->un.txt = scamper_host_rr_txt_alloc(1)) == NULL ||
     (rr->un.txt->strs[0] = strdup("baz")) == NULL)
    goto err;

  host->userid               = 73;
  host->qclass               = SCAMPER_HOST_CLASS_IN;
  host->qtype                = SCAMPER_HOST_TYPE_TXT;
  host->stop                 = SCAMPER_HOST_STOP_DONE;
  host->start.tv_sec         = 1724828857;
  host->start.tv_usec        = 123460;
  host->wait_timeout.tv_sec  = 2;
  host->wait_timeout.tv_usec = 0;

  q->tx.tv_sec               = 1724828857;
  q->tx.tv_usec              = 123461;
  q->rx.tv_sec               = 1724828857;
  q->rx.tv_usec              = 223461;
  q->id                      = 4;

  return host;

 err:
  if(host != NULL) scamper_host_free(host);
  return host;
}

static scamper_host_t *host_7(void)
{
  scamper_host_t *host = NULL;
  scamper_host_query_t *q;
  scamper_host_rr_t *rr;
  uint16_t port = htons(443);

  if((host = scamper_host_alloc()) == NULL ||
     (host->src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (host->dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL ||
     (host->qname = strdup("example.com")) == NULL ||
     scamper_host_queries_alloc(host, 1) != 0 ||
     (host->queries[0] = q = scamper_host_query_alloc()) == NULL ||
     scamper_host_query_rr_alloc(q, 1, 0, 0) != 0 ||
     (q->an[0] = rr = scamper_host_rr_alloc("example.com",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_HTTPS,
					    86400)) == NULL ||
     (rr->un.svcb = scamper_host_rr_svcb_alloc(1, ".", 2)) == NULL ||
     (rr->un.svcb->params[0] = /* alpn */
      scamper_host_rr_svcb_param_alloc(1, 2, (const uint8_t *)"h3")) == NULL ||
     (rr->un.svcb->params[1] = /* port */
      scamper_host_rr_svcb_param_alloc(3, 2, (const uint8_t *)&port)) == NULL)
    goto err;

  host->userid               = 74;
  host->qclass               = SCAMPER_HOST_CLASS_IN;
  host->qtype                = SCAMPER_HOST_TYPE_HTTPS;
  host->stop                 = SCAMPER_HOST_STOP_DONE;
  host->start.tv_sec         = 1724828858;
  host->start.tv_usec        = 123461;
  host->wait_timeout.tv_sec  = 2;
  host->wait_timeout.tv_usec = 0;

  q->tx.tv_sec               = 1724828858;
  q->tx.tv_usec              = 123462;
  q->rx.tv_sec               = 1724828858;
  q->rx.tv_usec              = 223462;
  q->id                      = 5;

  return host;

 err:
  if(host != NULL) scamper_host_free(host);
  return host;
}

static scamper_host_t *host_8(void)
{
  scamper_host_t *host = NULL;
  scamper_host_query_t *q;
  scamper_host_rr_t *rr;

  if((host = scamper_host_alloc()) == NULL ||
     (host->src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (host->dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL ||
     (host->qname = strdup("luckie.org.nz")) == NULL ||
     scamper_host_queries_alloc(host, 1) != 0 ||
     (host->queries[0] = q = scamper_host_query_alloc()) == NULL ||
     scamper_host_query_rr_alloc(q, 2, 3, 6) != 0 ||
     (q->an[0] = rr = scamper_host_rr_alloc("luckie.org.nz",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_MX,
					    86400)) == NULL ||
     (rr->un.mx =
      scamper_host_rr_mx_alloc(10, "mx1.sparkbusinessmail.co.nz")) == NULL ||
     (q->an[1] = rr = scamper_host_rr_alloc("luckie.org.nz",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_MX,
					    86400)) == NULL ||
     (rr->un.mx =
      scamper_host_rr_mx_alloc(20, "mx2.sparkbusinessmail.co.nz")) == NULL ||
     (q->ns[0] = rr = scamper_host_rr_alloc("luckie.org.nz",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_NS,
					    3600)) == NULL ||
     (rr->un.str = strdup("ns2.metaname.net")) == NULL ||
     (q->ns[1] = rr = scamper_host_rr_alloc("luckie.org.nz",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_NS,
					    3600)) == NULL ||
     (rr->un.str = strdup("ns1.metaname.net")) == NULL ||
     (q->ns[2] = rr = scamper_host_rr_alloc("luckie.org.nz",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_NS,
					    3600)) == NULL ||
     (rr->un.str = strdup("ns3.metaname.net")) == NULL ||
     (q->ar[0] = rr = scamper_host_rr_alloc("ns1.metaname.net",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_A,
					    3600)) == NULL ||
     (rr->un.addr = scamper_addr_fromstr_ipv4("49.50.242.204")) == NULL ||
     (q->ar[1] = rr = scamper_host_rr_alloc("ns1.metaname.net",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_AAAA,
					    3600)) == NULL ||
     (rr->un.addr =
      scamper_addr_fromstr_ipv6("2001:470:1f09:126e::1")) == NULL ||
     (q->ar[2] = rr = scamper_host_rr_alloc("ns2.metaname.net",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_A,
					    3600)) == NULL ||
     (rr->un.addr = scamper_addr_fromstr_ipv4("103.11.126.252")) == NULL ||
     (q->ar[3] = rr = scamper_host_rr_alloc("ns2.metaname.net",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_AAAA,
					    3600)) == NULL ||
     (rr->un.addr = scamper_addr_fromstr_ipv6("2001:470:67:c8::1")) == NULL ||
     (q->ar[4] = rr = scamper_host_rr_alloc("ns3.metaname.net",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_A,
					    3600)) == NULL ||
     (rr->un.addr = scamper_addr_fromstr_ipv4("103.11.126.244")) == NULL ||
     (q->ar[5] = rr = scamper_host_rr_alloc("ns3.metaname.net",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_AAAA,
					    3600)) == NULL ||
     (rr->un.addr = scamper_addr_fromstr_ipv6("2001:470:1f17:219::1")) == NULL)
    goto err;

  host->userid               = 75;
  host->qclass               = SCAMPER_HOST_CLASS_IN;
  host->qtype                = SCAMPER_HOST_TYPE_MX;
  host->stop                 = SCAMPER_HOST_STOP_DONE;
  host->start.tv_sec         = 1724828859;
  host->start.tv_usec        = 123472;
  host->wait_timeout.tv_sec  = 1;
  host->wait_timeout.tv_usec = 0;

  q->tx.tv_sec               = 1724828859;
  q->tx.tv_usec              = 123472;
  q->rx.tv_sec               = 1724828859;
  q->rx.tv_usec              = 223462;
  q->id                      = 6;

  return host;

 err:
  if(host != NULL) scamper_host_free(host);
  return NULL;
}

static scamper_host_t *host_9(void)
{
  scamper_host_t *host = NULL;
  scamper_host_query_t *q;
  scamper_host_rr_t *rr;

  if((host = scamper_host_alloc()) == NULL ||
     (host->src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (host->dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL ||
     (host->qname = strdup("192.0.2.1")) == NULL ||
     scamper_host_queries_alloc(host, 1) != 0 ||
     (host->queries[0] = q = scamper_host_query_alloc()) == NULL ||
     scamper_host_query_rr_alloc(q, 1, 0, 0) != 0 ||
     (q->an[0] = rr = scamper_host_rr_alloc("1.2.0.192.in-addr.arpa",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_PTR,
					    86400)) == NULL ||
     (rr->un.str = strdup("www.example.com")) == NULL)
    goto err;

  host->userid               = 76;
  host->qclass               = SCAMPER_HOST_CLASS_IN;
  host->qtype                = SCAMPER_HOST_TYPE_PTR;
  host->stop                 = SCAMPER_HOST_STOP_DONE;
  host->start.tv_sec         = 1724828860;
  host->start.tv_usec        = 836726;
  host->wait_timeout.tv_sec  = 2;
  host->wait_timeout.tv_usec = 0;

  q->tx.tv_sec               = 1724828860;
  q->tx.tv_usec              = 836726;
  q->rx.tv_sec               = 1724828861;
  q->rx.tv_usec              = 110968;
  q->id                      = 7;

  return host;

 err:
  if(host != NULL) scamper_host_free(host);
  return host;
}

static scamper_host_t *host_10(void)
{
  scamper_host_t *host = NULL;
  scamper_host_query_t *q;
  scamper_host_rr_t *rr;

  if((host = scamper_host_alloc()) == NULL ||
     (host->src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (host->dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL ||
     (host->qname = strdup("mail.example.com")) == NULL ||
     scamper_host_queries_alloc(host, 1) != 0 ||
     (host->queries[0] = q = scamper_host_query_alloc()) == NULL ||
     scamper_host_query_rr_alloc(q, 2, 0, 0) != 0 ||
     (q->an[0] = rr = scamper_host_rr_alloc("mail.example.com",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_CNAME,
					    600)) == NULL ||
     (rr->un.str = strdup("www.example.com")) == NULL ||
     (q->an[1] = rr = scamper_host_rr_alloc("www.example.com",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_A,
					    600)) == NULL ||
     (rr->un.addr = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL)
    goto err;

  host->userid               = 77;
  host->qclass               = SCAMPER_HOST_CLASS_IN;
  host->qtype                = SCAMPER_HOST_TYPE_A;
  host->stop                 = SCAMPER_HOST_STOP_DONE;
  host->start.tv_sec         = 1724828861;
  host->start.tv_usec        = 890236;
  host->wait_timeout.tv_sec  = 1;
  host->wait_timeout.tv_usec = 0;

  q->tx.tv_sec               = 1724828861;
  q->tx.tv_usec              = 890236;
  q->rx.tv_sec               = 1724828861;
  q->rx.tv_usec              = 910204;
  q->id                      = 8;

  return host;

 err:
  if(host != NULL) scamper_host_free(host);
  return host;
}

static scamper_host_t *host_11(void)
{
  scamper_host_t *host = NULL;
  scamper_host_query_t *q;
  scamper_host_rr_t *rr;
  uint8_t elem[7] = {0x00,0x01,0x18,0x13,0xCB,0x0,0x71};

  if((host = scamper_host_alloc()) == NULL ||
     (host->src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (host->dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL ||
     (host->ecs = strdup("203.0.113.0/24")) == NULL ||
     (host->qname = strdup("www.example.com")) == NULL ||
     scamper_host_queries_alloc(host, 1) != 0 ||
     (host->queries[0] = q = scamper_host_query_alloc()) == NULL ||
     scamper_host_query_rr_alloc(q, 1, 0, 1) != 0 ||
     (q->an[0] = rr = scamper_host_rr_alloc("www.example.com",
					    SCAMPER_HOST_CLASS_IN,
					    SCAMPER_HOST_TYPE_A,
					    600)) == NULL ||
     (rr->un.addr = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (q->ar[0] = rr = scamper_host_rr_alloc("",
					    512, /* udp payload size */
					    SCAMPER_HOST_TYPE_OPT,
					    0)) == NULL || /* edns0, rcode */
     (rr->un.opt = scamper_host_rr_opt_alloc(1)) == NULL ||
     (rr->un.opt->elems[0] = scamper_host_rr_opt_elem_alloc(8,7,elem)) == NULL)
    goto err;

  host->userid               = 78;
  host->qclass               = SCAMPER_HOST_CLASS_IN;
  host->qtype                = SCAMPER_HOST_TYPE_A;
  host->stop                 = SCAMPER_HOST_STOP_DONE;
  host->start.tv_sec         = 1724828862;
  host->start.tv_usec        = 123482;
  host->wait_timeout.tv_sec  = 1;
  host->wait_timeout.tv_usec = 0;

  q->tx.tv_sec               = 1724828862;
  q->tx.tv_usec              = 123482;
  q->rx.tv_sec               = 1724828862;
  q->rx.tv_usec              = 910204;
  q->id                      = 9;

  return host;

 err:
  if(host != NULL) scamper_host_free(host);
  return host;
}

static scamper_host_makefunc_t makers[] = {
  host_1,
  host_2,
  host_3,
  host_4,
  host_5,
  host_6,
  host_7,
  host_8,
  host_9,
  host_10,
  host_11,
};

scamper_host_t *host_makers(size_t i)
{
  if(i >= sizeof(makers) / sizeof(scamper_host_makefunc_t))
    return NULL;
  return makers[i]();
}

size_t host_makerc(void)
{
  return sizeof(makers) / sizeof(scamper_host_makefunc_t);
}
