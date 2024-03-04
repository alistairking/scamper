/*
 * scamper_neighbourdisc_cmd
 *
 * $Id: scamper_neighbourdisc_cmd.c,v 1.5 2024/02/15 20:34:51 mjl Exp $
 *
 * Copyright (C) 2009-2023 Matthew Luckie
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
#include "scamper_neighbourdisc.h"
#include "scamper_neighbourdisc_int.h"
#include "scamper_neighbourdisc_cmd.h"
#include "scamper_options.h"
#include "utils.h"

extern scamper_addrcache_t *addrcache;

#define ND_OPT_FIRSTRESPONSE     1
#define ND_OPT_IFNAME            2
#define ND_OPT_REPLYC            3
#define ND_OPT_ATTEMPTS          4
#define ND_OPT_ALLATTEMPTS       5
#define ND_OPT_WAIT              6
#define ND_OPT_SRCADDR           7
#define ND_OPT_USERID            8

static const scamper_option_in_t opts[] = {
  {'F', NULL, ND_OPT_FIRSTRESPONSE, SCAMPER_OPTION_TYPE_NULL},
  {'i', NULL, ND_OPT_IFNAME,        SCAMPER_OPTION_TYPE_STR},
  {'o', NULL, ND_OPT_REPLYC,        SCAMPER_OPTION_TYPE_NUM},
  {'q', NULL, ND_OPT_ATTEMPTS,      SCAMPER_OPTION_TYPE_NUM},
  {'Q', NULL, ND_OPT_ALLATTEMPTS,   SCAMPER_OPTION_TYPE_NULL},
  {'S', NULL, ND_OPT_SRCADDR,       SCAMPER_OPTION_TYPE_STR},
  {'U', NULL, ND_OPT_USERID,        SCAMPER_OPTION_TYPE_NUM},
  {'w', NULL, ND_OPT_WAIT,          SCAMPER_OPTION_TYPE_STR},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_neighbourdisc_usage(void)
{
  return "neighbourdisc [-FQ] [-i if] [-o replyc] [-q attempts] [-S srcaddr] [-U userid] [-w wait]\n";
}

static int nd_arg_param_validate(int optid, char *param, long long *out,
				 char *errbuf, size_t errlen)
{
  struct timeval tv;
  long long tmp = 0;

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  switch(optid)
    {
    case ND_OPT_IFNAME:
    case ND_OPT_ALLATTEMPTS:
    case ND_OPT_SRCADDR:
      break;

    case ND_OPT_ATTEMPTS:
      if(string_tollong(param, &tmp, NULL, 0) != 0 || tmp < 1 || tmp > 65535)
	{
	  snprintf(errbuf, errlen, "attempts must be within 1 - 65535");
	  goto err;
	}
      break;

    case ND_OPT_REPLYC:
      if(string_tollong(param, &tmp, NULL, 0) != 0 || tmp < 0 || tmp > 65535)
	{
	  snprintf(errbuf, errlen, "replyc must be within 0 - 65535");
	  goto err;
	}
      break;

    case ND_OPT_USERID:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < 0 || tmp < UINT32_MAX)
	{
	  snprintf(errbuf, errlen, "userid must be within 0 - %u", UINT32_MAX);
	  goto err;
	}
      break;

    case ND_OPT_WAIT:
      if(timeval_fromstr(&tv, param, 1000) != 0)
	{
	  snprintf(errbuf, errlen, "malformed wait-time");
	  goto err;
	}
      if((tv.tv_usec % 1000) != 0)
	{
	  snprintf(errbuf, errlen, "wait-time granularity limited to 1ms");
	  goto err;
	}
      if(timeval_cmp_lt(&tv, 0, 100000) || timeval_cmp_gt(&tv, 65, 535000))
	{
	  snprintf(errbuf, errlen, "wait-time must be between 0.1s and 65s");
	  goto err;
	}
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    default:
      goto err;
    }

  assert(errbuf[0] == '\0');
  if(out != NULL)
    *out = tmp;
  return 0;

 err:
  assert(errbuf[0] != '\0');
  return -1;
}

int scamper_do_neighbourdisc_arg_validate(int argc, char *argv[], int *stop,
					  char *errbuf, size_t errlen)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  errbuf, errlen, nd_arg_param_validate);
}

void *scamper_do_neighbourdisc_alloc(char *str, char *errbuf, size_t errlen)
{
  scamper_neighbourdisc_t *nd = NULL;
  scamper_option_out_t *opts_out = NULL, *opt;
  char    *ifname   = NULL;
  uint16_t attempts = 1;
  uint16_t replyc   = 0;
  uint8_t  flags    = 0;
  uint32_t userid   = 0;
  char    *dst      = NULL;
  char    *src      = NULL;
  long long tmp     = 0;
  uint32_t optids   = 0;
  struct timeval wait;
  char buf[256];

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  wait.tv_sec = 1; wait.tv_usec = 0;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &dst) != 0)
    {
      snprintf(errbuf, errlen, "could not parse neighbourdisc command");
      goto err;
    }

  if(dst == NULL)
    {
      snprintf(errbuf, errlen, "expected address to discover");
      goto err;
    }

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 nd_arg_param_validate(opt->id, opt->str, &tmp, buf, sizeof(buf)) != 0)
	{
	  snprintf(errbuf, errlen, "-%c %s failed: %s",
		   scamper_options_id2c(opts, opts_cnt, opt->id),
		   opt->str, buf);
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
	case ND_OPT_FIRSTRESPONSE:
	  flags |= SCAMPER_NEIGHBOURDISC_FLAG_FIRSTRESPONSE;
	  break;

	case ND_OPT_IFNAME:
	  ifname = opt->str;
	  break;

	case ND_OPT_ATTEMPTS:
	  attempts = (uint16_t)tmp;
	  break;

	case ND_OPT_REPLYC:
	  replyc = (uint16_t)tmp;
	  break;

	case ND_OPT_ALLATTEMPTS:
	  flags |= SCAMPER_NEIGHBOURDISC_FLAG_ALLATTEMPTS;
	  break;

	case ND_OPT_WAIT:
	  wait.tv_sec = tmp / 1000000;
	  wait.tv_usec = tmp % 1000000;
	  break;

	case ND_OPT_SRCADDR:
	  src = opt->str;
	  break;

	case ND_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	default:
	  goto err;
	}
    }

  scamper_options_free(opts_out); opts_out = NULL;

  if(ifname == NULL)
    {
      snprintf(errbuf, errlen, "missing ifname parameter");
      goto err;
    }

  /*
   * if we only want the first response, then we can't want more than
   * one reply
   */
  if((flags & SCAMPER_NEIGHBOURDISC_FLAG_FIRSTRESPONSE) != 0 &&
     (replyc > 1 || (flags & SCAMPER_NEIGHBOURDISC_FLAG_ALLATTEMPTS) != 0))
    {
      snprintf(errbuf, errlen, "cannot set both -F and solicit responses");
      goto err;
    }

  /*
   * if we have asked for all attempts to be sent, but we have limited the
   * number of replies we want to less than the number of probes we will send,
   * then these arguments are conflicting
   */
  if(replyc < attempts && replyc != 0 &&
     (flags & SCAMPER_NEIGHBOURDISC_FLAG_ALLATTEMPTS) != 0)
    {
      snprintf(errbuf, errlen, "cannot set -Q and have replyc < attempts");
      goto err;
    }

  if((nd = scamper_neighbourdisc_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc neighbourdisc");
      goto err;
    }

  if((nd->dst_ip = scamper_addrcache_resolve(addrcache,AF_UNSPEC,dst)) == NULL)
    {
      snprintf(errbuf, errlen, "invalid destination address");
      goto err;
    }

  if(SCAMPER_ADDR_TYPE_IS_IPV4(nd->dst_ip))
    nd->method = SCAMPER_NEIGHBOURDISC_METHOD_ARP;
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(nd->dst_ip))
    nd->method = SCAMPER_NEIGHBOURDISC_METHOD_ND_NSOL;
  else
    {
      snprintf(errbuf, errlen, "unhandled address type");
      goto err;
    }

  if(src != NULL)
    {
      if(SCAMPER_ADDR_TYPE_IS_IPV6(nd->dst_ip) == 0)
	{
	  snprintf(errbuf, errlen, "source address only valid with IPv6");
	  goto err;
	}
      nd->src_ip = scamper_addrcache_resolve(addrcache, AF_INET6, src);
      if(nd->src_ip == NULL)
	{
	  snprintf(errbuf, errlen, "invalid source address");
	  goto err;
	}
    }

  if(scamper_neighbourdisc_ifname_set(nd, ifname) != 0)
    {
      snprintf(errbuf, errlen, "could not set ifname");
      goto err;
    }

  nd->flags    = flags;
  nd->attempts = attempts;
  nd->replyc   = replyc;
  nd->userid   = userid;
  timeval_cpy(&nd->wait_timeout, &wait);

  assert(errbuf[0] == '\0');
  return nd;

 err:
  assert(errbuf[0] != '\0');
  if(nd != NULL) scamper_neighbourdisc_free(nd);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}
