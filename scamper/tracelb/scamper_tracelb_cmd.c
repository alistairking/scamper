/*
 * scamper_tracelb_cmd.c
 *
 * $Id: scamper_tracelb_cmd.c,v 1.8 2024/05/02 02:33:38 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
 * Copyright (C) 2016-2023 Matthew Luckie
 * Copyright (C) 2024      The Regents of the University of California
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
#include "utils.h"

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
  {'w', NULL, TRACE_OPT_WAITTIMEOUT, SCAMPER_OPTION_TYPE_STR},
  {'W', NULL, TRACE_OPT_WAITPROBE,   SCAMPER_OPTION_TYPE_STR},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

typedef struct opt_limit
{
  char      *name;
  long long  min;
  long long  max;
} opt_limit_t;

static const opt_limit_t limits[] = {
  {NULL, 0, 0}, /* zero unused */
  {NULL, 0, 0}, /* -c confidence */
  {"dport", 1, 65535},
  {"firsthop", 1, 254},
  {"gaplimit", 1, 5},
  {NULL, 0, 0}, /* -O options */
  {NULL, 0, 0}, /* -P method */
  {"attempts", 1, 5},
  {"max-probec", 50, 65535},
  {NULL, 0, 0}, /* -r rtr */
  {"sport", 1, 65535},
  {"tos", 0, 255},
  {"userid", 0, UINT32_MAX},
  {NULL, 0, 0}, /* -w wait-timeout */
  {NULL, 0, 0}, /* -W wait-probe */
};

const char *scamper_do_tracelb_usage(void)
{
  return "tracelb [-c confidence] [-d dport] [-f firsthop] [-g gaplimit]\n"
         "        [-O option] [-P method] [-q attempts] [-Q maxprobec]\n"
         "        [-r rtraddr] [-s sport] [-t tos] [-U userid]\n"
         "        [-w wait-timeout] [-W wait-probe]";
}

static int tracelb_arg_param_validate(int optid, char *param, long long *out,
				      char *errbuf, size_t errlen)
{
  struct timeval tv;
  long long tmp = 0;

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  switch(optid)
    {
    case TRACE_OPT_SPORT:
    case TRACE_OPT_DPORT:
    case TRACE_OPT_FIRSTHOP:
    case TRACE_OPT_GAPLIMIT:
    case TRACE_OPT_TOS:
    case TRACE_OPT_ATTEMPTS:
    case TRACE_OPT_PROBECMAX:
    case TRACE_OPT_USERID:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < limits[optid].min || tmp > limits[optid].max)
	{
	  snprintf(errbuf, errlen, "%s must be within %lld - %lld",
		   limits[optid].name, limits[optid].min, limits[optid].max);
	  goto err;
	}
      break;

    case TRACE_OPT_CONFIDENCE:
      if(string_tollong(param, &tmp, NULL, 10) != 0 || (tmp != 95 && tmp != 99))
	{
	  snprintf(errbuf, errlen, "confidence must be 95 or 99");
	  goto err;
	}
      break;

    case TRACE_OPT_OPTION:
      if(strcasecmp(param, "ptr") == 0)
	{
#ifndef DISABLE_SCAMPER_HOST
	  tmp = SCAMPER_TRACELB_FLAG_PTR;
#else
	  snprintf(errbuf, errlen, "scamper not built with host support");
	  goto err;
#endif
	}
      else
	{
	  snprintf(errbuf, errlen, "unknown option");
	  goto err;
	}
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
	{
	  snprintf(errbuf, errlen, "invalid tracelb method");
	  goto err;
	}
      break;

    case TRACE_OPT_WAITPROBE:
      if(timeval_fromstr(&tv, param, 10000) != 0)
	{
	  snprintf(errbuf, errlen, "malformed inter-probe delay");
	  goto err;
	}
      if((tv.tv_usec % 10000) != 0)
	{
	  snprintf(errbuf, errlen, "inter-probe granularity limited to 10ms");
	  goto err;
	}
      if(timeval_cmp_lt(&tv, 0, 150000) || timeval_cmp_gt(&tv, 2, 0))
	{
	  snprintf(errbuf, errlen, "inter-probe delay must be within 0.15s - 2s");
	  goto err;
	}
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    case TRACE_OPT_WAITTIMEOUT:
      if(timeval_fromstr(&tv, param, 1000000) != 0)
	{
	  snprintf(errbuf, errlen, "malformed timeout");
	  goto err;
	}
      if(tv.tv_usec != 0)
	{
	  snprintf(errbuf, errlen, "timeout cannot have fractions of second");
	  goto err;
	}
      if(timeval_cmp_lt(&tv, 1, 0) || timeval_cmp_gt(&tv, 10, 0))
	{
	  snprintf(errbuf, errlen, "timeout must be within 1s - 10s");
	  goto err;
	}
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

      /* these parameters are validated at execution time */
    case TRACE_OPT_RTRADDR:
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

/*
 * scamper_do_tracelb_alloc
 *
 * given a string representing a traceroute task, parse the parameters and
 * assemble a trace.  return the trace structure so that it is all ready to
 * go.
 */
void *scamper_do_tracelb_alloc(char *str, char *errbuf, size_t errlen)
{
  struct timeval wait_timeout, wait_probe;
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_tracelb_t *trace = NULL;
  uint8_t  type         = SCAMPER_TRACELB_TYPE_UDP_DPORT;
  uint16_t sport        = scamper_sport_default();
  uint8_t  confidence   = 95;
  uint16_t dport        = (32768+666+1);
  uint8_t  attempts     = 2;
  uint8_t  firsthop     = 1;
  uint8_t  tos          = 0;
  uint32_t probec_max   = 3000;
  uint8_t  gaplimit     = 3;
  uint32_t userid       = 0;
  uint8_t  flags        = 0;
  char *rtr = NULL, *addr;
  long long tmp = 0;
  uint32_t optids = 0;
  char buf[256];

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      snprintf(errbuf, errlen, "could not parse tracelb command");
      goto err;
    }

  /* if there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      snprintf(errbuf, errlen, "expected address to trace");
      goto err;
    }

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 tracelb_arg_param_validate(opt->id, opt->str, &tmp,
				    buf, sizeof(buf)) != 0)
	{
	  snprintf(errbuf, errlen, "-%c failed: %s",
		   scamper_options_id2c(opts, opts_cnt, opt->id), buf);
	  goto err;
	}

      if((optids & (0x1 << opt->id)) != 0 &&
	 opt->id != TRACE_OPT_OPTION)
	{
	  snprintf(errbuf, errlen, "repeated option -%c",
		   scamper_options_id2c(opts, opts_cnt, opt->id));
	  goto err;
	}
      optids |= (0x1 << opt->id);

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
	  flags |= (uint8_t)tmp;
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
	  wait_probe.tv_sec  = tmp / 1000000;
	  wait_probe.tv_usec = tmp % 1000000;
	  break;

	case TRACE_OPT_WAITTIMEOUT:
	  wait_timeout.tv_sec  = tmp / 1000000;
	  wait_timeout.tv_usec = tmp % 1000000;
	  break;

	case TRACE_OPT_RTRADDR:
	  rtr = opt->str;
	  break;
	}
    }

  scamper_options_free(opts_out); opts_out = NULL;

  if((optids & (0x1 << TRACE_OPT_WAITPROBE)) == 0)
    {
      wait_probe.tv_sec = 0;
      wait_probe.tv_usec = 250000;
    }

  if((optids & (0x1 << TRACE_OPT_WAITTIMEOUT)) == 0)
    {
      wait_timeout.tv_sec = 5;
      wait_timeout.tv_usec = 0;
    }

  if((trace = scamper_tracelb_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc tracelb");
      goto err;
    }

  if((trace->dst = scamper_addr_fromstr_unspec(addr)) == NULL)
    {
      snprintf(errbuf, errlen, "invalid destination address");
      goto err;
    }

  if(SCAMPER_ADDR_TYPE_IS_IPV6(trace->dst) &&
     SCAMPER_TRACELB_TYPE_IS_TCP(trace))
    {
      snprintf(errbuf, errlen, "cannot do IPv6 TCP MDA traceroutes");
      goto err;
    }

  if(rtr != NULL &&
     (trace->rtr = scamper_addr_fromstr(trace->dst->type, rtr)) == NULL)
    {
      snprintf(errbuf, errlen, "invalid router address");
      goto err;
    }

  trace->sport        = sport;
  trace->dport        = dport;
  trace->tos          = tos;
  trace->firsthop     = firsthop;
  trace->attempts     = attempts;
  trace->confidence   = confidence;
  trace->type         = type;
  trace->probec_max   = probec_max;
  trace->gaplimit     = gaplimit;
  trace->userid       = userid;
  trace->flags        = flags;

  timeval_cpy(&trace->wait_timeout, &wait_timeout);
  timeval_cpy(&trace->wait_probe, &wait_probe);

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
      snprintf(errbuf, errlen, "invalid destination address type");
      goto err;
    }

  assert(errbuf[0] == '\0');
  return trace;

 err:
  assert(errbuf[0] != '\0');
  if(trace != NULL) scamper_tracelb_free(trace);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

/*
 * scamper_do_tracelb_arg_validate
 *
 *
 */
int scamper_do_tracelb_arg_validate(int argc, char *argv[], int *stop,
				    char *errbuf, size_t errlen)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  errbuf, errlen, tracelb_arg_param_validate);
}
