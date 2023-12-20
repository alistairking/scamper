/*
 * scamper_host_cmd
 *
 * $Id: scamper_host_cmd.c,v 1.1 2023/06/04 04:41:53 mjl Exp $
 *
 * Copyright (C) 2018-2023 Matthew Luckie
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
#include "scamper_options.h"
#include "scamper_debug.h"
#include "utils.h"

#define HOST_OPT_NORECURSE 1
#define HOST_OPT_RETRIES   2
#define HOST_OPT_SERVER    3
#define HOST_OPT_TYPE      4
#define HOST_OPT_USERID    5
#define HOST_OPT_WAIT      6

static const scamper_option_in_t opts[] = {
  {'r', NULL, HOST_OPT_NORECURSE, SCAMPER_OPTION_TYPE_NULL},
  {'R', NULL, HOST_OPT_RETRIES,   SCAMPER_OPTION_TYPE_NUM},
  {'s', NULL, HOST_OPT_SERVER,    SCAMPER_OPTION_TYPE_STR},
  {'t', NULL, HOST_OPT_TYPE,      SCAMPER_OPTION_TYPE_STR},
  {'U', NULL, HOST_OPT_USERID,    SCAMPER_OPTION_TYPE_NUM},
  {'W', NULL, HOST_OPT_WAIT,      SCAMPER_OPTION_TYPE_NUM},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

#ifndef FUZZ_HOST
extern scamper_addr_t *default_ns;
void etc_resolv(void);
#endif

const char *scamper_do_host_usage(void)
{
  return
    "host [-r] [-R number] [-s server] [-t type] [-U userid] [-W wait] name\n";
}

static int host_arg_param_validate(int optid, char *param, long long *out)
{
  scamper_addr_t *addr;
  long tmp = 0;

  switch(optid)
    {
    case HOST_OPT_NORECURSE:
      return 0;

    case HOST_OPT_RETRIES:
      if(string_tolong(param, &tmp) != 0 || tmp < 0 || tmp > 3)
	return -1;
      break;

    case HOST_OPT_SERVER:
      if((addr = scamper_addr_resolve(AF_INET, param)) == NULL)
	return -1;
      scamper_addr_free(addr);
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
      else return -1;
      break;

    case HOST_OPT_WAIT:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 5)
	return -1;
      tmp *= 1000;
      break;
    }

  if(out != NULL)
    *out = (long long)tmp;

  return 0;
}

int scamper_do_host_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  host_arg_param_validate);
}

void *scamper_do_host_alloc(char *str, uint32_t *id)
{
  scamper_host_t *host = NULL;
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_addr_t *server = NULL;
  scamper_addr_t *name_addr = NULL;
  char *name = NULL;
  uint8_t retries = 0;
  uint32_t userid = 0;
  uint16_t wait = 5000;
  uint16_t flags = 0;
  uint16_t qclass = 1;
  uint16_t qtype = 0;
  long long tmp = 0;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &name) != 0)
    {
      scamper_debug(__func__, "could not parse command");
      goto err;
    }

  if(name == NULL)
    goto err;

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 host_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
	{
	case HOST_OPT_NORECURSE:
	  flags |= SCAMPER_HOST_FLAG_NORECURSE;
	  break;

	case HOST_OPT_RETRIES:
	  retries = (uint8_t)tmp;
	  break;

	case HOST_OPT_SERVER:
	  if(server != NULL)
	    goto err;
	  if((server = scamper_addr_resolve(AF_INET, opt->str)) == NULL)
	    goto err;
	  break;

	case HOST_OPT_TYPE:
	  qtype = (uint16_t)tmp;
	  break;

	case HOST_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case HOST_OPT_WAIT:
	  wait = (uint16_t)tmp;
	  break;

	default:
	  scamper_debug(__func__, "unhandled option %d", opt->id);
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
      if((name_addr = scamper_addr_resolve(AF_UNSPEC, name)) != NULL)
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
      if((name_addr = scamper_addr_resolve(AF_UNSPEC, name)) != NULL)
	goto err;
    }
  else if(qtype == SCAMPER_HOST_TYPE_PTR)
    {
      /* for a PTR the name to look up MUST be an IP address */
      if((name_addr = scamper_addr_resolve(AF_UNSPEC, name)) == NULL)
	goto err;
    }
  else goto err;

  if((host = scamper_host_alloc()) == NULL ||
     (host->qname = strdup(name)) == NULL)
    goto err;

  host->userid  = *id = userid;
  host->flags  |= flags;
  host->wait    = wait;
  host->retries = retries;
  host->qtype   = qtype;
  host->qclass  = qclass;

  if(server != NULL)
    {
      host->dst = server;
      server = NULL;
    }
#ifndef FUZZ_HOST
  else
    {
      if(default_ns == NULL)
	{
	  etc_resolv();
	  if(default_ns == NULL)
	    goto err;
	}
      host->dst = scamper_addr_use(default_ns);
    }
#endif

  return host;

 err:
  if(host != NULL) scamper_host_free(host);
  if(name_addr != NULL) scamper_addr_free(name_addr);
  if(server != NULL) scamper_addr_free(server);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}
