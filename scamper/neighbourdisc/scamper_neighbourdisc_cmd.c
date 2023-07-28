/*
 * scamper_neighbourdisc_cmd
 *
 * $Id: scamper_neighbourdisc_cmd.c,v 1.1 2023/06/04 04:52:48 mjl Exp $
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

//#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_neighbourdisc.h"
#include "scamper_neighbourdisc_int.h"
#include "scamper_options.h"
#include "scamper_debug.h"
#include "utils.h"

extern scamper_addrcache_t *addrcache;

#define ND_OPT_FIRSTRESPONSE     1
#define ND_OPT_IFNAME            2
#define ND_OPT_REPLYC            3
#define ND_OPT_ATTEMPTS          4
#define ND_OPT_ALLATTEMPTS       5
#define ND_OPT_WAIT              6
#define ND_OPT_SRCADDR           7

static const scamper_option_in_t opts[] = {
  {'F', NULL, ND_OPT_FIRSTRESPONSE, SCAMPER_OPTION_TYPE_NULL},
  {'i', NULL, ND_OPT_IFNAME,        SCAMPER_OPTION_TYPE_STR},
  {'o', NULL, ND_OPT_REPLYC,        SCAMPER_OPTION_TYPE_NUM},
  {'q', NULL, ND_OPT_ATTEMPTS,      SCAMPER_OPTION_TYPE_NUM},
  {'Q', NULL, ND_OPT_ALLATTEMPTS,   SCAMPER_OPTION_TYPE_NULL},
  {'S', NULL, ND_OPT_SRCADDR,       SCAMPER_OPTION_TYPE_STR},
  {'w', NULL, ND_OPT_WAIT,          SCAMPER_OPTION_TYPE_NUM},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_neighbourdisc_usage(void)
{
  return "neighbourdisc [-FQ] [-i if] [-o replyc] [-q attempts] [-S srcaddr] [-w wait]\n";
}

static int nd_arg_param_validate(int optid, char *param, long long *out)
{
  long tmp;

  switch(optid)
    {
    case ND_OPT_IFNAME:
    case ND_OPT_ALLATTEMPTS:
    case ND_OPT_SRCADDR:
      return 0;

    case ND_OPT_ATTEMPTS:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
       return -1;
      break;

    case ND_OPT_REPLYC:
      if(string_tolong(param, &tmp) != 0 || tmp < 0 || tmp > 65535)
	return -1;
      break;

    case ND_OPT_WAIT:
      if(string_tolong(param, &tmp) != 0 || tmp < 100 || tmp > 65535)
	return -1;
      break;

    default:
      return -1;
    }

  if(out != NULL)
    *out = (long long)tmp;

  return 0;
}

int scamper_do_neighbourdisc_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  nd_arg_param_validate);
}

void *scamper_do_neighbourdisc_alloc(char *str)
{
  scamper_neighbourdisc_t *nd = NULL;
  scamper_option_out_t *opts_out = NULL, *opt;
  char    *ifname   = NULL;
  uint16_t attempts = 1;
  uint16_t replyc   = 0;
  uint16_t wait     = 1000;
  uint8_t  flags    = 0;
  char    *dst      = NULL;
  char    *src      = NULL;
  long long tmp     = 0;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &dst) != 0)
    {
      scamper_debug(__func__, "could not parse command");
      goto err;
    }

  if(dst == NULL)
    goto err;

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 nd_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

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
	  wait = (uint16_t)tmp;
	  break;

	case ND_OPT_SRCADDR:
	  if(src != NULL)
	    goto err;
	  src = opt->str;
	  break;

	default:
	  scamper_debug(__func__, "unhandled option %d", opt->id);
	  goto err;
	}
    }

  scamper_options_free(opts_out); opts_out = NULL;

  if(ifname == NULL)
    goto err;

  if((nd = scamper_neighbourdisc_alloc()) == NULL)
    goto err;

  if((nd->dst_ip = scamper_addrcache_resolve(addrcache,AF_UNSPEC,dst)) == NULL)
    goto err;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(nd->dst_ip))
    nd->method = SCAMPER_NEIGHBOURDISC_METHOD_ARP;
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(nd->dst_ip))
    nd->method = SCAMPER_NEIGHBOURDISC_METHOD_ND_NSOL;
  else
    goto err;

  if(src != NULL)
    {
      if(SCAMPER_ADDR_TYPE_IS_IPV6(nd->dst_ip) == 0)
	goto err;
      nd->src_ip = scamper_addrcache_resolve(addrcache, AF_INET6, src);
      if(nd->src_ip == NULL)
	goto err;
    }

  if(scamper_neighbourdisc_ifname_set(nd, ifname) != 0)
    goto err;

  /*
   * if we only want the first response, then we can't want more than
   * one reply
   */
  if((flags & SCAMPER_NEIGHBOURDISC_FLAG_FIRSTRESPONSE) != 0 &&
     (replyc > 1 || (flags & SCAMPER_NEIGHBOURDISC_FLAG_ALLATTEMPTS) != 0))
    {
      scamper_debug(__func__, "invalid combination of arguments");
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
      scamper_debug(__func__, "invalid combination of arguments");
      goto err;
    }

  nd->flags    = flags;
  nd->attempts = attempts;
  nd->replyc   = replyc;
  nd->wait     = wait;

  return nd;

 err:
  if(nd != NULL) scamper_neighbourdisc_free(nd);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}
