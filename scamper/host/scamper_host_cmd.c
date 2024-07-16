/*
 * scamper_host_cmd
 *
 * $Id: scamper_host_cmd.c,v 1.14 2024/05/02 02:33:38 mjl Exp $
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

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_host.h"
#include "scamper_host_int.h"
#include "scamper_host_cmd.h"
#include "scamper_options.h"
#include "utils.h"

#define HOST_OPT_NORECURSE 1
#define HOST_OPT_RETRIES   2
#define HOST_OPT_SERVER    3
#define HOST_OPT_TYPE      4
#define HOST_OPT_USERID    5
#define HOST_OPT_WAIT      6
#define HOST_OPT_CLASS     7
#define HOST_OPT_TCP       8

static const scamper_option_in_t opts[] = {
  {'c', NULL, HOST_OPT_CLASS,     SCAMPER_OPTION_TYPE_STR},
  {'r', NULL, HOST_OPT_NORECURSE, SCAMPER_OPTION_TYPE_NULL},
  {'R', NULL, HOST_OPT_RETRIES,   SCAMPER_OPTION_TYPE_NUM},
  {'s', NULL, HOST_OPT_SERVER,    SCAMPER_OPTION_TYPE_STR},
  {'t', NULL, HOST_OPT_TYPE,      SCAMPER_OPTION_TYPE_STR},
  {'T', NULL, HOST_OPT_TCP,       SCAMPER_OPTION_TYPE_NULL},
  {'U', NULL, HOST_OPT_USERID,    SCAMPER_OPTION_TYPE_NUM},
  {'W', NULL, HOST_OPT_WAIT,      SCAMPER_OPTION_TYPE_STR},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

#ifdef BUILDING_SCAMPER
extern scamper_addr_t *default_ns;
void etc_resolv(void);
#endif

const char *scamper_do_host_usage(void)
{
  return
    "host [-rT] [-c class] [-R number] [-s server] [-t type] [-U userid] [-W wait] name\n";
}

static int host_arg_param_validate(int optid, char *param, long long *out,
				   char *errbuf, size_t errlen)
{
  scamper_addr_t *addr;
  struct timeval tv;
  long long tmp = 0;

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  switch(optid)
    {
    case HOST_OPT_TCP:
    case HOST_OPT_NORECURSE:
      return 0;

    case HOST_OPT_RETRIES:
      if(string_tollong(param, &tmp, NULL, 10) != 0 || tmp < 0 || tmp > 3)
	{
	  snprintf(errbuf, errlen, "retries must be within 0 - 3");
	  goto err;
	}
      break;

    case HOST_OPT_SERVER:
      if((addr = scamper_addr_fromstr_ipv4(param)) == NULL)
	{
	  snprintf(errbuf, errlen, "server must be an IPv4 address");
	  goto err;
	}
      scamper_addr_free(addr);
      break;

    case HOST_OPT_CLASS:
      if(strcasecmp(param, "IN") == 0)
	tmp = SCAMPER_HOST_CLASS_IN;
      else if(strcasecmp(param, "CH") == 0 || strcasecmp(param, "CHAOS") == 0)
	tmp = SCAMPER_HOST_CLASS_CH;
      else
	{
	  snprintf(errbuf, errlen, "unsupported query class");
	  goto err;
	}
      break;

    case HOST_OPT_TYPE:
      if(strcasecmp(param, "A") == 0)
	tmp = SCAMPER_HOST_TYPE_A;
      else if(strcasecmp(param, "AAAA") == 0)
	tmp = SCAMPER_HOST_TYPE_AAAA;
      else if(strcasecmp(param, "PTR") == 0)
	tmp = SCAMPER_HOST_TYPE_PTR;
      else if(strcasecmp(param, "MX") == 0)
	tmp = SCAMPER_HOST_TYPE_MX;
      else if(strcasecmp(param, "NS") == 0)
	tmp = SCAMPER_HOST_TYPE_NS;
      else if(strcasecmp(param, "SOA") == 0)
	tmp = SCAMPER_HOST_TYPE_SOA;
      else if(strcasecmp(param, "TXT") == 0)
	tmp = SCAMPER_HOST_TYPE_TXT;
      else
	{
	  snprintf(errbuf, errlen, "unsupported query type");
	  goto err;
	}
      break;

    case HOST_OPT_WAIT:
      if(timeval_fromstr(&tv, param, 1000000) != 0)
	{
	  snprintf(errbuf, errlen, "malformed timeout");
	  goto err;
	}
      if((tv.tv_usec % 1000) != 0)
	{
	  snprintf(errbuf, errlen, "timeout granularity limited to 1ms");
	  goto err;
	}
      if(timeval_cmp_lt(&tv, 1, 0) || timeval_cmp_gt(&tv, 5, 0))
	{
	  snprintf(errbuf, errlen, "timeout must be within 1s - 5s");
	  goto err;
	}
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    case HOST_OPT_USERID:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < 0 || tmp > UINT32_MAX)
	{
	  snprintf(errbuf, errlen, "userid must be within %u - %u", 0,
		   UINT32_MAX);
	  goto err;
	}
      break;

    default:
      goto err;
    }

  /* valid parameter */
  assert(errbuf[0] == '\0');
  if(out != NULL)
    *out = tmp;
  return 0;

 err:
  assert(errbuf[0] != '\0');
  return -1;
}

int scamper_do_host_arg_validate(int argc, char *argv[], int *stop,
				 char *errbuf, size_t errlen)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  errbuf, errlen, host_arg_param_validate);
}

void *scamper_do_host_alloc(char *str, char *errbuf, size_t errlen)
{
  scamper_host_t *host = NULL;
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_addr_t *server = NULL;
  scamper_addr_t *name_addr = NULL;
  char *name = NULL;
  uint8_t retries = 0;
  uint32_t userid = 0;
  uint16_t flags = 0;
  uint16_t qclass = 1;
  uint16_t qtype = 0;
  long long tmp = 0;
  struct timeval wait_timeout;
  uint32_t optids = 0;
  char buf[256];

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &name) != 0)
    {
      snprintf(errbuf, errlen, "could not parse host command");
      goto err;
    }

  if(name == NULL)
    {
      snprintf(errbuf, errlen, "expected name to query");
      goto err;
    }

  wait_timeout.tv_sec = 5;
  wait_timeout.tv_usec = 0;

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 host_arg_param_validate(opt->id, opt->str, &tmp,
				 buf, sizeof(buf)) != 0)
	{
	  snprintf(errbuf, errlen, "-%c failed: %s",
		   scamper_options_id2c(opts, opts_cnt, opt->id), buf);
	  goto err;
	}

      if((optids & (0x1 << opt->id)) != 0)
	{
	  snprintf(errbuf, errlen, "repeated option -%c",
		   scamper_options_id2c(opts, opts_cnt, opt->id));
	  goto err;
	}
      optids |= (0x1 << opt->id);

      switch(opt->id)
	{
	case HOST_OPT_NORECURSE:
	  flags |= SCAMPER_HOST_FLAG_NORECURSE;
	  break;

	case HOST_OPT_TCP:
	  flags |= SCAMPER_HOST_FLAG_TCP;
	  break;

	case HOST_OPT_RETRIES:
	  retries = (uint8_t)tmp;
	  break;

	case HOST_OPT_SERVER:
	  if((server = scamper_addr_fromstr_ipv4(opt->str)) == NULL)
	    {
	      snprintf(errbuf, errlen, "server must be an IPv4 address");
	      goto err;
	    }
	  break;

	case HOST_OPT_CLASS:
	  qclass = (uint16_t)tmp;
	  break;

	case HOST_OPT_TYPE:
	  qtype = (uint16_t)tmp;
	  break;

	case HOST_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case HOST_OPT_WAIT:
	  wait_timeout.tv_sec  = tmp / 1000000;
	  wait_timeout.tv_usec = tmp % 1000000;
	  break;

	default:
	  snprintf(errbuf, errlen, "unhandled option %d", opt->id);
	  goto err;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if(qtype == 0)
    {
      /*
       * if the user did not specify query type, auto detect name vs
       * IP lookup.
       */
      if((name_addr = scamper_addr_fromstr_unspec(name)) != NULL)
	qtype = SCAMPER_HOST_TYPE_PTR;
      else
	qtype = SCAMPER_HOST_TYPE_A;
    }
  else if(qtype == SCAMPER_HOST_TYPE_A || qtype == SCAMPER_HOST_TYPE_AAAA ||
	  qtype == SCAMPER_HOST_TYPE_MX || qtype == SCAMPER_HOST_TYPE_NS ||
	  qtype == SCAMPER_HOST_TYPE_SOA)
    {
      /*
       * for A, AAAA, MX, NS, SOA, the name to look up MUST NOT be an
       * IP address
       */
      if((name_addr = scamper_addr_fromstr_unspec(name)) != NULL)
	{
	  snprintf(errbuf, errlen, "query cannot be for an IP address");
	  goto err;
	}
    }
  else if(qtype == SCAMPER_HOST_TYPE_PTR)
    {
      /* for a PTR the name to look up MUST be an IP address */
      if((name_addr = scamper_addr_fromstr_unspec(name)) == NULL)
	{
	  snprintf(errbuf, errlen, "query must be for an IP address");
	  goto err;
	}
    }
  else if(qtype != SCAMPER_HOST_TYPE_TXT)
    {
      snprintf(errbuf, errlen, "unhandled qtype %d", qtype);
      goto err;
    }

  if((flags & SCAMPER_HOST_FLAG_TCP) && retries > 0)
    {
      snprintf(errbuf, errlen, "no retry with TCP");
      goto err;
    }

  /* don't need the name_addr anymore, if we have one */
  if(name_addr != NULL)
    {
      scamper_addr_free(name_addr);
      name_addr = NULL;
    }

  if((host = scamper_host_alloc()) == NULL ||
     (host->qname = strdup(name)) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc host");
      goto err;
    }

  host->userid  = userid;
  host->flags  |= flags;
  host->retries = retries;
  host->qtype   = qtype;
  host->qclass  = qclass;

  timeval_cpy(&host->wait_timeout, &wait_timeout);

  if(server != NULL)
    {
      host->dst = server;
      server = NULL;
    }
#ifdef BUILDING_SCAMPER
  else
    {
      if(default_ns == NULL)
	{
	  etc_resolv();
	  if(default_ns == NULL)
	    {
	      snprintf(errbuf, errlen, "no nameserver to query");
	      goto err;
	    }
	}
      host->dst = scamper_addr_use(default_ns);
    }
#endif

  return host;

 err:
  assert(errbuf[0] != '\0');
  if(host != NULL) scamper_host_free(host);
  if(name_addr != NULL) scamper_addr_free(name_addr);
  if(server != NULL) scamper_addr_free(server);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}
