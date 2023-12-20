/*
 * scamper_trace_cmd.c
 *
 * $Id: scamper_trace_cmd.c,v 1.12 2024/01/18 04:03:13 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2008      Alistair King
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2015      The University of Waikato
 * Copyright (C) 2019-2023 Matthew Luckie
 *
 * Authors: Matthew Luckie
 *          Doubletree implementation by Alistair King
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
#include "scamper_trace.h"
#include "scamper_trace_int.h"
#include "scamper_debug.h"
#include "scamper_options.h"

#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "utils.h"

#define SCAMPER_DO_TRACE_ATTEMPTS_MIN  1
#define SCAMPER_DO_TRACE_ATTEMPTS_DEF  2
#define SCAMPER_DO_TRACE_ATTEMPTS_MAX  20

#define SCAMPER_DO_TRACE_DPORT_MIN     1
#define SCAMPER_DO_TRACE_DPORT_DEF     (32768+666+1) /* probe_id starts at 0 */
#define SCAMPER_DO_TRACE_DPORT_MAX     65535

#define SCAMPER_DO_TRACE_FIRSTHOP_MIN  1
#define SCAMPER_DO_TRACE_FIRSTHOP_DEF  1
#define SCAMPER_DO_TRACE_FIRSTHOP_MAX  255

#define SCAMPER_DO_TRACE_GAPLIMIT_MIN  1
#define SCAMPER_DO_TRACE_GAPLIMIT_DEF  5
#define SCAMPER_DO_TRACE_GAPLIMIT_MAX  255

#define SCAMPER_DO_TRACE_GAPACTION_MIN 1
#define SCAMPER_DO_TRACE_GAPACTION_DEF SCAMPER_TRACE_GAPACTION_STOP
#define SCAMPER_DO_TRACE_GAPACTION_MAX 2

#define SCAMPER_DO_TRACE_HOPLIMIT_MIN  0
#define SCAMPER_DO_TRACE_HOPLIMIT_DEF  0
#define SCAMPER_DO_TRACE_HOPLIMIT_MAX  255

#define SCAMPER_DO_TRACE_LOOPS_MIN     0
#define SCAMPER_DO_TRACE_LOOPS_DEF     1 /* stop on the first loop found */
#define SCAMPER_DO_TRACE_LOOPS_MAX     255

#define SCAMPER_DO_TRACE_OFFSET_MIN 0
#define SCAMPER_DO_TRACE_OFFSET_DEF 0
#define SCAMPER_DO_TRACE_OFFSET_MAX 8190

#define SCAMPER_DO_TRACE_SPORT_MIN     0
#define SCAMPER_DO_TRACE_SPORT_MAX     65535

#define SCAMPER_DO_TRACE_SQUERIES_MIN  1
#define SCAMPER_DO_TRACE_SQUERIES_DEF  1
#define SCAMPER_DO_TRACE_SQUERIES_MAX  255

#define SCAMPER_DO_TRACE_TOS_MIN 0
#define SCAMPER_DO_TRACE_TOS_DEF 0
#define SCAMPER_DO_TRACE_TOS_MAX 255

#define SCAMPER_DO_TRACE_WAITTIMEOUT_MIN   1
#define SCAMPER_DO_TRACE_WAITTIMEOUT_DEF   5
#define SCAMPER_DO_TRACE_WAITTIMEOUT_MAX   10

#define SCAMPER_DO_TRACE_WAITPROBE_MIN 0
#define SCAMPER_DO_TRACE_WAITPROBE_DEF 0
#define SCAMPER_DO_TRACE_WAITPROBE_MAX 200 /* 2 seconds */

#define TRACE_OPT_DPORT       1
#define TRACE_OPT_FIRSTHOP    2
#define TRACE_OPT_GAPLIMIT    3
#define TRACE_OPT_GAPACTION   4
#define TRACE_OPT_LOOPS       5
#define TRACE_OPT_MAXTTL      7
#define TRACE_OPT_PMTUD       8
#define TRACE_OPT_PAYLOAD     9
#define TRACE_OPT_PROTOCOL    10
#define TRACE_OPT_ATTEMPTS    11
#define TRACE_OPT_ALLATTEMPTS 12
#define TRACE_OPT_SPORT       13
#define TRACE_OPT_TOS         14
#define TRACE_OPT_TTLDST      15
#define TRACE_OPT_USERID      16
#define TRACE_OPT_WAITTIMEOUT 17
#define TRACE_OPT_SRCADDR     18
#define TRACE_OPT_CONFIDENCE  19
#define TRACE_OPT_WAITPROBE   20
#define TRACE_OPT_GSSENTRY    21
#define TRACE_OPT_LSSNAME     22
#define TRACE_OPT_OFFSET      23
#define TRACE_OPT_OPTION      24
#define TRACE_OPT_RTRADDR     25
#define TRACE_OPT_SQUERIES    26

static const scamper_option_in_t opts[] = {
  {'c', NULL, TRACE_OPT_CONFIDENCE,  SCAMPER_OPTION_TYPE_NUM},
  {'d', NULL, TRACE_OPT_DPORT,       SCAMPER_OPTION_TYPE_STR},
  {'f', NULL, TRACE_OPT_FIRSTHOP,    SCAMPER_OPTION_TYPE_NUM},
  {'g', NULL, TRACE_OPT_GAPLIMIT,    SCAMPER_OPTION_TYPE_NUM},
  {'G', NULL, TRACE_OPT_GAPACTION,   SCAMPER_OPTION_TYPE_NUM},
  {'l', NULL, TRACE_OPT_LOOPS,       SCAMPER_OPTION_TYPE_NUM},
  {'m', NULL, TRACE_OPT_MAXTTL,      SCAMPER_OPTION_TYPE_NUM},
  {'M', NULL, TRACE_OPT_PMTUD,       SCAMPER_OPTION_TYPE_NULL},
  {'N', NULL, TRACE_OPT_SQUERIES,    SCAMPER_OPTION_TYPE_NUM},
  {'o', NULL, TRACE_OPT_OFFSET,      SCAMPER_OPTION_TYPE_NUM},
  {'O', NULL, TRACE_OPT_OPTION,      SCAMPER_OPTION_TYPE_STR},
  {'p', NULL, TRACE_OPT_PAYLOAD,     SCAMPER_OPTION_TYPE_STR},
  {'P', NULL, TRACE_OPT_PROTOCOL,    SCAMPER_OPTION_TYPE_STR},
  {'q', NULL, TRACE_OPT_ATTEMPTS,    SCAMPER_OPTION_TYPE_NUM},
  {'Q', NULL, TRACE_OPT_ALLATTEMPTS, SCAMPER_OPTION_TYPE_NULL},
  {'r', NULL, TRACE_OPT_RTRADDR,     SCAMPER_OPTION_TYPE_STR},
  {'s', NULL, TRACE_OPT_SPORT,       SCAMPER_OPTION_TYPE_NUM},
  {'S', NULL, TRACE_OPT_SRCADDR,     SCAMPER_OPTION_TYPE_STR},
  {'t', NULL, TRACE_OPT_TOS,         SCAMPER_OPTION_TYPE_NUM},
  {'T', NULL, TRACE_OPT_TTLDST,      SCAMPER_OPTION_TYPE_NULL},
  {'U', NULL, TRACE_OPT_USERID,      SCAMPER_OPTION_TYPE_NUM},
  {'w', NULL, TRACE_OPT_WAITTIMEOUT, SCAMPER_OPTION_TYPE_STR},
  {'W', NULL, TRACE_OPT_WAITPROBE,   SCAMPER_OPTION_TYPE_STR},
  {'z', NULL, TRACE_OPT_GSSENTRY,    SCAMPER_OPTION_TYPE_STR},
  {'Z', NULL, TRACE_OPT_LSSNAME,     SCAMPER_OPTION_TYPE_STR},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

extern scamper_addrcache_t *addrcache;

const char *scamper_do_trace_usage(void)
{
  return
    "trace [-MQT] [-c confidence] [-d dport] [-f firsthop]\n"
    "      [-g gaplimit] [-G gapaction] [-l loops] [-m maxttl] [-N squeries]\n"
    "      [-o offset] [-O options] [-p payload] [-P method] [-q attempts]\n"
    "      [-r rtraddr] [-s sport] [-S srcaddr] [-t tos] [-U userid]\n"
    "      [-w wait-timeout] [-W wait-probe] [-z gss-entry] [-Z lss-name]";
}

static int trace_arg_param_validate(int optid, char *param, long long *out)
{
  struct timeval tv;
  long tmp = 0;
  int i;

  switch(optid)
    {
    case TRACE_OPT_DPORT:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_TRACE_DPORT_MIN ||
	 tmp > SCAMPER_DO_TRACE_DPORT_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_FIRSTHOP:
      if(string_tolong(param, &tmp) == -1    ||
	 tmp < SCAMPER_DO_TRACE_FIRSTHOP_MIN ||
	 tmp > SCAMPER_DO_TRACE_FIRSTHOP_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_GAPLIMIT:
      if(string_tolong(param, &tmp) == -1    ||
	 tmp < SCAMPER_DO_TRACE_GAPLIMIT_MIN ||
	 tmp > SCAMPER_DO_TRACE_GAPLIMIT_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_GAPACTION:
      if(string_tolong(param, &tmp) == -1     ||
	 tmp < SCAMPER_DO_TRACE_GAPACTION_MIN ||
	 tmp > SCAMPER_DO_TRACE_GAPACTION_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_LOOPS:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_TRACE_LOOPS_MIN ||
	 tmp > SCAMPER_DO_TRACE_LOOPS_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_OFFSET:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_TRACE_OFFSET_MIN ||
	 tmp > SCAMPER_DO_TRACE_OFFSET_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_OPTION:
      if(strcasecmp(param, "dl") != 0 &&
	 strcasecmp(param, "const-payload") != 0 &&
	 strcasecmp(param, "dtree-noback") != 0 &&
	 strcasecmp(param, "ptr") != 0)
	goto err;
      break;

    case TRACE_OPT_MAXTTL:
      if(string_tolong(param, &tmp) == -1    ||
	 tmp < SCAMPER_DO_TRACE_HOPLIMIT_MIN ||
	 tmp > SCAMPER_DO_TRACE_HOPLIMIT_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_PAYLOAD:
      for(i=0; param[i] != '\0'; i++)
	if(ishex(param[i]) == 0)
	  goto err;
      if(i == 0 || (i % 2) != 0)
	goto err;
      tmp = i;
      break;

    case TRACE_OPT_PROTOCOL:
      if(strcasecmp(param, "UDP") == 0)
	tmp = SCAMPER_TRACE_TYPE_UDP;
      else if(strcasecmp(param, "TCP") == 0)
	tmp = SCAMPER_TRACE_TYPE_TCP;
      else if(strcasecmp(param, "ICMP") == 0)
	tmp = SCAMPER_TRACE_TYPE_ICMP_ECHO;
      else if(strcasecmp(param, "ICMP-paris") == 0)
	tmp = SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS;
      else if(strcasecmp(param, "UDP-paris") == 0)
	tmp = SCAMPER_TRACE_TYPE_UDP_PARIS;
      else if(strcasecmp(param, "TCP-ack") == 0)
	tmp = SCAMPER_TRACE_TYPE_TCP_ACK;
      else goto err;
      break;

    case TRACE_OPT_ATTEMPTS:
      if(string_tolong(param, &tmp) == -1    ||
	 tmp < SCAMPER_DO_TRACE_ATTEMPTS_MIN ||
	 tmp > SCAMPER_DO_TRACE_ATTEMPTS_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_SPORT:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_TRACE_SPORT_MIN ||
	 tmp > SCAMPER_DO_TRACE_SPORT_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_SQUERIES:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_TRACE_SQUERIES_MIN ||
	 tmp > SCAMPER_DO_TRACE_SQUERIES_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_TOS:
      if(string_tolong(param, &tmp) == -1 ||
	 tmp < SCAMPER_DO_TRACE_TOS_MIN ||
	 tmp > SCAMPER_DO_TRACE_TOS_MAX)
	{
	  goto err;
	}
      break;

    case TRACE_OPT_WAITTIMEOUT:
      if(timeval_fromstr(&tv, param, 1000000) != 0 || tv.tv_usec != 0 ||
	 timeval_cmp_lt(&tv, 1, 0) || timeval_cmp_gt(&tv, 10, 0))
	goto err;
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    case TRACE_OPT_CONFIDENCE:
      if(string_tolong(param, &tmp) != 0 || (tmp != 95 && tmp != 99))
	goto err;
      break;

    case TRACE_OPT_WAITPROBE:
      if(timeval_fromstr(&tv, param, 10000) != 0 ||
	 (tv.tv_usec % 10000) != 0 || timeval_cmp_gt(&tv, 2, 0))
	goto err;
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    case TRACE_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	goto err;
      break;

    case TRACE_OPT_SRCADDR:
    case TRACE_OPT_GSSENTRY:
    case TRACE_OPT_LSSNAME:
    case TRACE_OPT_RTRADDR:
      /* these parameters are validated at execution time */
      break;

    case TRACE_OPT_PMTUD:
    case TRACE_OPT_ALLATTEMPTS:
    case TRACE_OPT_TTLDST:
      /* these options don't have parameters */
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

int scamper_do_trace_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  trace_arg_param_validate);
}

static int trace_gss_add(scamper_trace_dtree_t *dtree, scamper_addr_t *addr)
{
  dtree->gss[dtree->gssc++] = scamper_addr_use(addr);
  return 0;
}

/*
 * scamper_do_trace_alloc
 *
 * given a string representing a traceroute task, parse the parameters and
 * assemble a trace.  return the trace structure so that it is all ready to
 * go.
 */
void *scamper_do_trace_alloc(char *str, uint32_t *id)
{
  /* default values of various trace parameters */
#ifndef _WIN32 /* use ICMP echo paris traceroute on windows by default */
  uint8_t  type        = SCAMPER_TRACE_TYPE_UDP_PARIS;
#else
  uint8_t  type        = SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS;
#endif
  uint32_t flags       = 0;
  uint8_t  attempts    = SCAMPER_DO_TRACE_ATTEMPTS_DEF;
  uint8_t  firsthop    = SCAMPER_DO_TRACE_FIRSTHOP_DEF;
  uint8_t  gaplimit    = SCAMPER_DO_TRACE_GAPLIMIT_DEF;
  uint8_t  gapaction   = SCAMPER_DO_TRACE_GAPACTION_DEF;
  uint8_t  hoplimit    = SCAMPER_DO_TRACE_HOPLIMIT_DEF;
  uint8_t  squeries    = SCAMPER_DO_TRACE_SQUERIES_DEF;
  uint8_t  tos         = SCAMPER_DO_TRACE_TOS_DEF;
  uint8_t  loops       = SCAMPER_DO_TRACE_LOOPS_DEF;
  uint8_t  confidence  = 0;
  uint8_t  dtree_flags = 0;
  int      sport       = -1;
  uint16_t dport       = SCAMPER_DO_TRACE_DPORT_DEF;
  uint16_t offset      = SCAMPER_DO_TRACE_OFFSET_DEF;
  uint8_t *payload     = NULL;
  uint16_t payload_len = 0;
  uint32_t userid      = 0;
  char    *lss         = NULL;
  slist_t *gss         = NULL;
  struct timeval wait_timeout, wait_probe;
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_trace_t *trace = NULL;
  splaytree_t *gss_tree = NULL;
  scamper_addr_t *sa = NULL;
  char *addr;
  long long i, tmp = 0;
  char *src = NULL, *rtr = NULL;
  int af, x;
  uint32_t optids = 0;
  uint16_t u16;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    goto err;

  /* if there is no IP address after the options string, then stop now */
  if(addr == NULL)
    goto err;

  /* parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 trace_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      /* only allow -O and -z duplicates: prevents payload memory leak */
      if((optids & (0x1 << opt->id)) != 0 &&
	 opt->id != TRACE_OPT_OPTION && opt->id != TRACE_OPT_GSSENTRY)
	{
	  scamper_debug(__func__, "repeated optid %d", opt->id);
	  goto err;
	}
      optids |= (0x1 << opt->id);

      switch(opt->id)
	{
	case TRACE_OPT_DPORT:
	  dport = (uint16_t)tmp;
	  break;

	case TRACE_OPT_FIRSTHOP:
	  firsthop = (uint8_t)tmp;
	  break;

	case TRACE_OPT_GAPLIMIT:
	  gaplimit = (uint8_t)tmp;
	  break;

	case TRACE_OPT_GAPACTION:
	  gapaction = (uint8_t)tmp;
	  break;

	case TRACE_OPT_LOOPS:
	  loops = (uint8_t)tmp;
	  break;

	case TRACE_OPT_MAXTTL:
	  hoplimit = (uint8_t)tmp;
	  break;

	case TRACE_OPT_OFFSET:
	  offset = (uint16_t)tmp;
	  break;

	case TRACE_OPT_OPTION:
	  if(strcasecmp(opt->str, "dl") == 0)
	    flags |= SCAMPER_TRACE_FLAG_DL;
	  else if(strcasecmp(opt->str, "const-payload") == 0)
	    flags |= SCAMPER_TRACE_FLAG_CONSTPAYLOAD;
	  else if(strcasecmp(opt->str, "dtree-noback") == 0)
	    dtree_flags |= SCAMPER_TRACE_DTREE_FLAG_NOBACK;
	  else if(strcasecmp(opt->str, "ptr") == 0)
	    {
#ifndef DISABLE_SCAMPER_HOST
	      flags |= SCAMPER_TRACE_FLAG_PTR;
#else
	      printerror_msg(__func__, "scamper not built with host support");
	      goto err;
#endif
	    }
	  break;

	case TRACE_OPT_PAYLOAD:
	  assert(payload == NULL); /* silence clang static analysis */
	  if((payload = malloc_zero(tmp/2)) == NULL)
	    {
	      printerror(__func__, "could not malloc payload");
	      goto err;
	    }
	  payload_len = 0;
	  for(i=0; i<tmp; i+=2)
	    payload[payload_len++] = hex2byte(opt->str[i], opt->str[i+1]);
	  break;

	case TRACE_OPT_PMTUD:
	  flags |= SCAMPER_TRACE_FLAG_PMTUD;
	  break;

	case TRACE_OPT_PROTOCOL:
	  type = (uint8_t)tmp;
	  break;

	case TRACE_OPT_ATTEMPTS:
	  attempts = (uint8_t)tmp;
	  break;

	case TRACE_OPT_ALLATTEMPTS:
	  flags |= SCAMPER_TRACE_FLAG_ALLATTEMPTS;
	  break;

	case TRACE_OPT_SPORT:
	  sport = (int)tmp;
	  break;

	case TRACE_OPT_SQUERIES:
	  squeries = (uint8_t)tmp;
	  break;

	case TRACE_OPT_TOS:
	  tos = (uint8_t)tmp;
	  break;

	case TRACE_OPT_TTLDST:
	  flags |= SCAMPER_TRACE_FLAG_IGNORETTLDST;
	  break;

	case TRACE_OPT_WAITTIMEOUT:
	  wait_timeout.tv_sec  = tmp / 1000000;
	  wait_timeout.tv_usec = tmp % 1000000;
	  break;

	case TRACE_OPT_RTRADDR:
	  if(rtr != NULL)
	    goto err;
	  rtr = opt->str;
	  break;

	case TRACE_OPT_SRCADDR:
	  if(src != NULL)
	    goto err;
	  src = opt->str;
	  break;

	case TRACE_OPT_CONFIDENCE:
	  confidence = (uint8_t)tmp;
	  break;

	case TRACE_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case TRACE_OPT_WAITPROBE:
	  wait_probe.tv_sec  = tmp / 1000000;
	  wait_probe.tv_usec = tmp % 1000000;
	  break;

	case TRACE_OPT_LSSNAME:
	  lss = opt->str;
	  break;

	case TRACE_OPT_GSSENTRY:
	  if((gss == NULL && (gss = slist_alloc()) == NULL) ||
	     slist_tail_push(gss, opt->str) == NULL)
	    {
	      goto err;
	    }
	  break;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if((optids & (0x1 << TRACE_OPT_WAITPROBE)) == 0)
    {
      wait_probe.tv_sec = SCAMPER_DO_TRACE_WAITPROBE_DEF;
      wait_probe.tv_usec = 0;
    }

  if((optids & (0x1 << TRACE_OPT_WAITTIMEOUT)) == 0)
    {
      wait_timeout.tv_sec = SCAMPER_DO_TRACE_WAITTIMEOUT_DEF;
      wait_timeout.tv_usec = 0;
    }

  /* sanity check that we don't begin beyond our probe hoplimit */
  if(firsthop > hoplimit && hoplimit != 0)
    goto err;

  /* can't really do pmtud properly without all of the path */
  if((flags & SCAMPER_TRACE_FLAG_PMTUD) != 0 &&
     (firsthop > 1 || gss != NULL || lss != NULL))
    goto err;

  /* cannot specify both a confidence value and tell it to send all attempts */
  if(confidence != 0 && (flags & SCAMPER_TRACE_FLAG_ALLATTEMPTS))
    goto err;

  /* can't really do pmtud properly without a UDP traceroute method */
  if((flags & SCAMPER_TRACE_FLAG_PMTUD) != 0 &&
     type != SCAMPER_TRACE_TYPE_UDP && type != SCAMPER_TRACE_TYPE_UDP_PARIS)
    goto err;

  if(sport == -1)
    sport = scamper_sport_default();
  else if(sport == 0)
    {
      random_u16(&u16);
      sport = u16 | 0x8000;
    }

  if((trace = scamper_trace_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc trace");
      goto err;
    }
  if((trace->dst= scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr)) == NULL)
    goto err;

  trace->type        = type;
  trace->flags       = flags;
  trace->attempts    = attempts;
  trace->hoplimit    = hoplimit;
  trace->squeries    = squeries;
  trace->gaplimit    = gaplimit;
  trace->gapaction   = gapaction;
  trace->firsthop    = firsthop;
  trace->tos         = tos;
  trace->loops       = loops;
  trace->sport       = sport;
  trace->dport       = dport;
  trace->payload     = payload; payload = NULL;
  trace->payload_len = payload_len;
  trace->confidence  = confidence;
  trace->offset      = offset;
  trace->userid      = *id = userid;

  timeval_cpy(&trace->wait_timeout, &wait_timeout);
  timeval_cpy(&trace->wait_probe, &wait_probe);

  /* to start with, we are this far into the path */
  trace->hop_count = firsthop - 1;

  /* don't allow tcptraceroute to have a payload */
  if(SCAMPER_TRACE_TYPE_IS_TCP(trace) && trace->payload_len > 0)
    goto err;

  /* don't allow fragment traceroute with IPv4 for now */
  if(trace->offset != 0 && trace->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    goto err;

  /* do not allow more outstanding probes than gaplimit allows */
  if(trace->squeries > trace->gaplimit)
    goto err;

  switch(trace->dst->type)
    {
    case SCAMPER_ADDR_TYPE_IPV4:
      if(SCAMPER_TRACE_TYPE_IS_TCP(trace))
	trace->probe_size = 40;
      else if(trace->payload_len == 0)
	trace->probe_size = 44;
      else
	trace->probe_size = 20 + 8 + trace->payload_len;
      break;

    case SCAMPER_ADDR_TYPE_IPV6:
      if(trace->offset != 0)
	trace->probe_size = 40 + 8 + 4 + trace->payload_len;
      else if(trace->payload_len == 0 || SCAMPER_TRACE_TYPE_IS_TCP(trace))
	trace->probe_size = 60;
      else
	trace->probe_size = 40 + 8 + trace->payload_len;
      break;

    default:
      goto err;
    }

  af = scamper_addr_af(trace->dst);
  if(af != AF_INET && af != AF_INET6)
    goto err;

  if(src != NULL &&
     (trace->src = scamper_addrcache_resolve(addrcache, af, src)) == NULL)
    goto err;

  if(rtr != NULL &&
     (trace->rtr = scamper_addrcache_resolve(addrcache, af, rtr)) == NULL)
    goto err;

  /*
   * if icmp paris traceroute is being used, say that the csum used can be
   * found in the trace->dport value.
   */
  if(trace->type == SCAMPER_TRACE_TYPE_ICMP_ECHO_PARIS)
    {
      trace->flags |= SCAMPER_TRACE_FLAG_ICMPCSUMDP;
      if((optids & (0x1 << TRACE_OPT_DPORT)) == 0)
	trace->dport = scamper_sport_default();
    }

  /* handle doubletree */
  if(gss != NULL || lss != NULL)
    {
      if((trace->dtree = scamper_trace_dtree_alloc()) == NULL)
	goto err;
      trace->flags |= SCAMPER_TRACE_FLAG_DOUBLETREE;
      trace->dtree->firsthop = trace->firsthop;
      trace->dtree->flags = dtree_flags;

      /* the local stop set name, if we're using a local stop set */
      if(lss != NULL && scamper_trace_dtree_lss_set(trace->dtree, lss) != 0)
	goto err;

      /* add the nodes to the global stop set for this trace */
      if(gss != NULL)
	{
	  gss_tree = splaytree_alloc((splaytree_cmp_t)scamper_addr_cmp);
	  if(gss_tree == NULL)
	    goto err;
	  while((addr = slist_head_pop(gss)) != NULL)
	    {
	      if((sa = scamper_addrcache_resolve(addrcache,af,addr)) == NULL ||
		 splaytree_find(gss_tree, sa) != NULL ||
		 splaytree_insert(gss_tree, sa) == NULL)
		goto err;
	      sa = NULL;
	    }
	  slist_free(gss);
	  gss = NULL;

	  if((x = splaytree_count(gss_tree)) >= 65535 ||
	     scamper_trace_dtree_gss_alloc(trace->dtree, x) != 0)
	    goto err;
	  splaytree_inorder(gss_tree, (splaytree_inorder_t)trace_gss_add,
			    trace->dtree);
	  splaytree_free(gss_tree, (splaytree_free_t)scamper_addr_free);
	  gss_tree = NULL;
	  scamper_trace_dtree_gss_sort(trace->dtree);
	}
    }

  return trace;

 err:
  if(sa != NULL) scamper_addr_free(sa);
  if(payload != NULL) free(payload);
  if(gss != NULL) slist_free(gss);
  if(gss_tree != NULL)
    splaytree_free(gss_tree, (splaytree_free_t)scamper_addr_free);
  if(trace != NULL) scamper_trace_free(trace);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}
