/*
 * scamper_tracelb_cmd.c
 *
 * $Id: scamper_tracelb_cmd.c,v 1.1 2023/06/04 07:24:32 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
 * Copyright (C) 2016-2023 Matthew Luckie
 * Author: Matthew Luckie
 *
 * MDA traceroute technique authored by
 * Brice Augustin, Timur Friedman, Renata Teixeira; "Measuring Load-balanced
 *  Paths in the Internet", in Proc. Internet Measurement Conference 2007.
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
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_icmpext.h"
#include "scamper_icmpext_int.h"
#include "scamper_tracelb.h"
#include "scamper_tracelb_int.h"
#include "scamper_tracelb_cmd.h"
#include "scamper_options.h"
#include "scamper_debug.h"
#include "utils.h"

#define SCAMPER_DO_TRACELB_ATTEMPTS_MIN    1
#define SCAMPER_DO_TRACELB_ATTEMPTS_DEF    2
#define SCAMPER_DO_TRACELB_ATTEMPTS_MAX    5

#define SCAMPER_DO_TRACELB_PORT_MIN        1
#define SCAMPER_DO_TRACELB_PORT_MAX        65535

#define SCAMPER_DO_TRACELB_DPORT_DEF       (32768+666+1)

#define SCAMPER_DO_TRACELB_FIRSTHOP_MIN    1
#define SCAMPER_DO_TRACELB_FIRSTHOP_DEF    1
#define SCAMPER_DO_TRACELB_FIRSTHOP_MAX    254

#define SCAMPER_DO_TRACELB_GAPLIMIT_MIN    1
#define SCAMPER_DO_TRACELB_GAPLIMIT_DEF    3
#define SCAMPER_DO_TRACELB_GAPLIMIT_MAX    5

#define SCAMPER_DO_TRACELB_PROBECMAX_MIN   50
#define SCAMPER_DO_TRACELB_PROBECMAX_DEF   3000
#define SCAMPER_DO_TRACELB_PROBECMAX_MAX   65535

#define SCAMPER_DO_TRACELB_TOS_MIN         0
#define SCAMPER_DO_TRACELB_TOS_DEF         0
#define SCAMPER_DO_TRACELB_TOS_MAX         255

#define SCAMPER_DO_TRACELB_WAITPROBE_MIN   15
#define SCAMPER_DO_TRACELB_WAITPROBE_DEF   25
#define SCAMPER_DO_TRACELB_WAITPROBE_MAX   200

#define SCAMPER_DO_TRACELB_WAITTIMEOUT_MIN 1
#define SCAMPER_DO_TRACELB_WAITTIMEOUT_DEF 5
#define SCAMPER_DO_TRACELB_WAITTIMEOUT_MAX 10

#define TRACE_OPT_CONFIDENCE   1
#define TRACE_OPT_DPORT        2
#define TRACE_OPT_FIRSTHOP     3
#define TRACE_OPT_GAPLIMIT     4
#define TRACE_OPT_OPTION       5
#define TRACE_OPT_PROTOCOL     6
#define TRACE_OPT_ATTEMPTS     7
#define TRACE_OPT_PROBECMAX    8
#define TRACE_OPT_SPORT        9
#define TRACE_OPT_TOS          10
#define TRACE_OPT_USERID       11
#define TRACE_OPT_WAITTIMEOUT  12
#define TRACE_OPT_WAITPROBE    13
#define TRACE_OPT_RTRADDR      14

static const scamper_option_in_t opts[] = {
  {'c', NULL, TRACE_OPT_CONFIDENCE,  SCAMPER_OPTION_TYPE_NUM},
  {'d', NULL, TRACE_OPT_DPORT,       SCAMPER_OPTION_TYPE_NUM},
  {'f', NULL, TRACE_OPT_FIRSTHOP,    SCAMPER_OPTION_TYPE_NUM},
  {'g', NULL, TRACE_OPT_GAPLIMIT,    SCAMPER_OPTION_TYPE_NUM},
  {'O', NULL, TRACE_OPT_OPTION,      SCAMPER_OPTION_TYPE_STR},
  {'P', NULL, TRACE_OPT_PROTOCOL,    SCAMPER_OPTION_TYPE_STR},
  {'q', NULL, TRACE_OPT_ATTEMPTS,    SCAMPER_OPTION_TYPE_NUM},
  {'Q', NULL, TRACE_OPT_PROBECMAX,   SCAMPER_OPTION_TYPE_NUM},
  {'r', NULL, TRACE_OPT_RTRADDR,     SCAMPER_OPTION_TYPE_STR},
  {'s', NULL, TRACE_OPT_SPORT,       SCAMPER_OPTION_TYPE_NUM},
  {'t', NULL, TRACE_OPT_TOS,         SCAMPER_OPTION_TYPE_NUM},
  {'U', NULL, TRACE_OPT_USERID,      SCAMPER_OPTION_TYPE_NUM},
  {'w', NULL, TRACE_OPT_WAITTIMEOUT, SCAMPER_OPTION_TYPE_NUM},
  {'W', NULL, TRACE_OPT_WAITPROBE,   SCAMPER_OPTION_TYPE_NUM},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_tracelb_usage(void)
{
  return "tracelb [-c confidence] [-d dport] [-f firsthop] [-g gaplimit]\n"
         "        [-O option] [-P method] [-q attempts] [-Q maxprobec]\n"
         "        [-r rtraddr] [-s sport] [-t tos] [-U userid]\n"
         "        [-w wait-timeout] [-W wait-probe]";
}

static int tracelb_arg_param_validate(int optid, char *param, long long *out)
{
  long tmp = 0;

  switch(optid)
    {
    case TRACE_OPT_CONFIDENCE:
      if(string_tolong(param, &tmp) != 0 || (tmp != 95 && tmp != 99))
	{
	  goto err;
	}
      break;

    case TRACE_OPT_SPORT:
    case TRACE_OPT_DPORT:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_PORT_MIN ||
	 tmp > SCAMPER_DO_TRACELB_PORT_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_FIRSTHOP:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_FIRSTHOP_MIN ||
	 tmp > SCAMPER_DO_TRACELB_FIRSTHOP_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_GAPLIMIT:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_GAPLIMIT_MIN ||
	 tmp > SCAMPER_DO_TRACELB_GAPLIMIT_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_OPTION:
      if(strcasecmp(param, "ptr") != 0)
	goto err;
      break;

    case TRACE_OPT_PROTOCOL:
      if(strcasecmp(param, "udp-dport") == 0)
	tmp = SCAMPER_TRACELB_TYPE_UDP_DPORT;
      else if(strcasecmp(param, "icmp-echo") == 0)
	tmp = SCAMPER_TRACELB_TYPE_ICMP_ECHO;
      else if(strcasecmp(param, "udp-sport") == 0)
	tmp = SCAMPER_TRACELB_TYPE_UDP_SPORT;
      else if(strcasecmp(param, "tcp-sport") == 0)
	tmp = SCAMPER_TRACELB_TYPE_TCP_SPORT;
      else if(strcasecmp(param, "tcp-ack-sport") == 0)
	tmp = SCAMPER_TRACELB_TYPE_TCP_ACK_SPORT;
      else
	goto err;
      break;

    case TRACE_OPT_TOS:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_TOS_MIN || tmp > SCAMPER_DO_TRACELB_TOS_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_ATTEMPTS:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_ATTEMPTS_MIN ||
	 tmp > SCAMPER_DO_TRACELB_ATTEMPTS_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_PROBECMAX:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_PROBECMAX_MIN ||
	 tmp > SCAMPER_DO_TRACELB_PROBECMAX_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_WAITPROBE:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_WAITPROBE_MIN ||
	 tmp > SCAMPER_DO_TRACELB_WAITPROBE_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_WAITTIMEOUT:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_TRACELB_WAITTIMEOUT_MIN ||
	 tmp > SCAMPER_DO_TRACELB_WAITTIMEOUT_MAX)
	{
	  goto err;
	}
      break;

      /* these parameters are validated at execution time */
    case TRACE_OPT_RTRADDR:
      break;

    default:
      return -1;
    }

  /* valid parameter */
  if(out != NULL)
    *out = (long long)tmp;
  return 0;

 err:
  return -1;
}

/*
 * scamper_do_tracelb_alloc
 *
 * given a string representing a traceroute task, parse the parameters and
 * assemble a trace.  return the trace structure so that it is all ready to
 * go.
 */
void *scamper_do_tracelb_alloc(char *str)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_tracelb_t *trace = NULL;
  uint8_t  type         = SCAMPER_TRACELB_TYPE_UDP_DPORT;
  uint16_t sport        = scamper_sport_default();
  uint8_t  confidence   = 95;
  uint16_t dport        = SCAMPER_DO_TRACELB_DPORT_DEF;
  uint8_t  attempts     = SCAMPER_DO_TRACELB_ATTEMPTS_DEF;
  uint8_t  firsthop     = SCAMPER_DO_TRACELB_FIRSTHOP_DEF;
  uint8_t  wait_timeout = SCAMPER_DO_TRACELB_WAITTIMEOUT_DEF;
  uint8_t  wait_probe   = SCAMPER_DO_TRACELB_WAITPROBE_DEF;
  uint8_t  tos          = SCAMPER_DO_TRACELB_TOS_DEF;
  uint32_t probec_max   = SCAMPER_DO_TRACELB_PROBECMAX_DEF;
  uint8_t  gaplimit     = SCAMPER_DO_TRACELB_GAPLIMIT_DEF;
  uint32_t userid       = 0;
  uint8_t  flags        = 0;
  char *rtr = NULL, *addr;
  long long tmp = 0;
  int af;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      goto err;
    }

  /* if there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      goto err;
    }

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 tracelb_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      switch(opt->id)
	{
	case TRACE_OPT_CONFIDENCE:
	  confidence = (uint8_t)tmp;
	  break;

	case TRACE_OPT_DPORT:
	  dport = (uint16_t)tmp;
	  break;

	case TRACE_OPT_FIRSTHOP:
	  firsthop = (uint8_t)tmp;
	  break;

	case TRACE_OPT_GAPLIMIT:
	  gaplimit = (uint8_t)tmp;
	  break;

	case TRACE_OPT_OPTION:
	  if(strcasecmp(opt->str, "ptr") == 0)
	    flags |= SCAMPER_TRACELB_FLAG_PTR;
	  else
	    {
	      scamper_debug(__func__, "unknown option %s", opt->str);
	      goto err;
	    }
	  break;

	case TRACE_OPT_PROTOCOL:
	  type = (uint8_t)tmp;
	  break;

	case TRACE_OPT_TOS:
	  tos = (uint8_t)tmp;
	  break;

	case TRACE_OPT_ATTEMPTS:
	  attempts = (uint8_t)tmp;
	  break;

	case TRACE_OPT_PROBECMAX:
	  probec_max = (uint32_t)tmp;
	  break;

	case TRACE_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case TRACE_OPT_WAITPROBE:
	  wait_probe = (uint8_t)tmp;
	  break;

	case TRACE_OPT_WAITTIMEOUT:
	  wait_timeout = (uint8_t)tmp;
	  break;

	case TRACE_OPT_RTRADDR:
	  if(rtr != NULL)
	    goto err;
	  rtr = opt->str;
	  break;
	}
    }

  scamper_options_free(opts_out); opts_out = NULL;

  if((trace = scamper_tracelb_alloc()) == NULL)
    {
      goto err;
    }

  if((trace->dst = scamper_addr_resolve(AF_UNSPEC, addr)) == NULL)
    {
      goto err;
    }

  if(trace->dst->type == SCAMPER_ADDR_TYPE_IPV6 &&
     SCAMPER_TRACELB_TYPE_IS_TCP(trace))
    {
      goto err;
    }

  af = scamper_addr_af(trace->dst);
  if(af != AF_INET && af != AF_INET6)
    goto err;

  if(rtr != NULL &&
     (trace->rtr = scamper_addr_resolve(af, rtr)) == NULL)
    goto err;

  trace->sport        = sport;
  trace->dport        = dport;
  trace->tos          = tos;
  trace->firsthop     = firsthop;
  trace->wait_timeout = wait_timeout;
  trace->wait_probe   = wait_probe;
  trace->attempts     = attempts;
  trace->confidence   = confidence;
  trace->type         = type;
  trace->probec_max   = probec_max;
  trace->gaplimit     = gaplimit;
  trace->userid       = userid;
  trace->flags        = flags;

  switch(trace->dst->type)
    {
    case SCAMPER_ADDR_TYPE_IPV4:
      if(SCAMPER_TRACELB_TYPE_IS_TCP(trace))
	trace->probe_size = 40;
      else
	trace->probe_size = 44;
      break;

    case SCAMPER_ADDR_TYPE_IPV6:
      trace->probe_size = 60;
      break;

    default:
      goto err;
    }

  return trace;

 err:
  if(trace != NULL) scamper_tracelb_free(trace);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

/*
 * scamper_do_tracelb_arg_validate
 *
 *
 */
int scamper_do_tracelb_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  tracelb_arg_param_validate);
}
