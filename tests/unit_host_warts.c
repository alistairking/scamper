/*
 * unit_host_warts : unit tests for warts host storage
 *
 * $Id: unit_host_warts.c,v 1.2 2024/09/13 08:22:08 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024 Matthew Luckie
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
#include "mjl_list.h"

#include "common.h"

typedef scamper_host_t * (*test_func_t)(void);
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

static int host_ok(const scamper_host_t *in, const scamper_host_t *out)
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

static scamper_host_t *dns_opt_elem_nsid(void)
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

static int write_file(const char *filename, const scamper_host_t *host)
{
  scamper_file_t *file = NULL;
  int rc = -1;

  if((file = scamper_file_open(filename, 'w', "warts")) == NULL ||
     scamper_file_write_host(file, host, NULL) != 0)
    {
      printf("could not write\n");
      goto done;
    }
  rc = 0;

 done:
  if(file != NULL) scamper_file_close(file);
  return rc;
}

static int check_file(const char *filename, const scamper_host_t *in)
{
  scamper_file_t *file = NULL;
  uint16_t obj_type;
  void *obj_data = NULL;
  int rc = -1;

  if((file = scamper_file_open(filename, 'r', "warts")) == NULL ||
     scamper_file_read(file, NULL, &obj_type, &obj_data) != 0 ||
     obj_type != SCAMPER_FILE_OBJ_HOST ||
     host_ok(in, obj_data) != 0)
    goto done;

  rc = 0;

 done:
  if(obj_data != NULL && obj_type == SCAMPER_FILE_OBJ_HOST)
    scamper_host_free(obj_data);
  if(file != NULL) scamper_file_close(file);
  return rc;  
}

int main(int argc, char *argv[])
{
  static test_func_t tests[] = {
    dns_opt_elem_nsid,
  };
  size_t i, testc = sizeof(tests) / sizeof(test_func_t);
  scamper_host_t *host;
  char filename[128];
  int check = 0;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
#endif

  if(argc != 3 ||
     (strcasecmp(argv[1], "dump") != 0 &&
      strcasecmp(argv[1], "check") != 0))
    return -1;

  if(strcasecmp(argv[1], "check") == 0)
    check = 1;

  for(i=0; i<testc; i++)
    {
      snprintf(filename, sizeof(filename),
	       "%s/host-%03x.warts", argv[2], (int)i);

#ifdef DMALLOC
      if(check != 0)
	dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

      if((host = tests[i]()) == NULL)
	{
	  printf("could not create host %d\n", (int)i);
	  return -1;
	}

      if(write_file(filename, host) != 0)
	{
	  printf("could not write host %d\n", (int)i);
	  return -1;
	}

      if(check != 0 && check_file(filename, host) != 0)
	{
	  printf("fail check %d\n", (int)i);
	  return -1;
	}

      scamper_host_free(host);

#ifdef DMALLOC
      if(check != 0)
	{
	  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
	  if(start_mem != stop_mem)
	    {
	      printf("memory leak: %d\n", (int)i);
	      return -1;
	    }
	}
#endif
    }

  printf("OK\n");
  return 0;
}
