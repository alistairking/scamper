/*
 * scamper_ping_cmd.c
 *
 * $Id: scamper_ping_cmd.c,v 1.12 2023/12/30 19:11:52 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2016-2023 Matthew Luckie
 * Author: Matthew Luckie
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
#include "scamper_ping.h"
#include "scamper_ping_int.h"
#include "scamper_debug.h"
#include "scamper_options.h"
#include "utils.h"

#define SCAMPER_DO_PING_PROBECOUNT_MIN    1
#define SCAMPER_DO_PING_PROBECOUNT_DEF    4
#define SCAMPER_DO_PING_PROBECOUNT_MAX    65535

#define SCAMPER_DO_PING_PROBEWAIT_US_MIN  1000
#define SCAMPER_DO_PING_PROBEWAIT_DEF     1
#define SCAMPER_DO_PING_PROBEWAIT_MAX     20

#define SCAMPER_DO_PING_PROBETTL_MIN      1
#define SCAMPER_DO_PING_PROBETTL_DEF      64
#define SCAMPER_DO_PING_PROBETTL_MAX      255

#define SCAMPER_DO_PING_PROBETOS_MIN      0
#define SCAMPER_DO_PING_PROBETOS_DEF      0
#define SCAMPER_DO_PING_PROBETOS_MAX      255

#define SCAMPER_DO_PING_PROBEMETHOD_DEF   SCAMPER_PING_METHOD_ICMP_ECHO

#define SCAMPER_DO_PING_PROBEDPORT_MIN    0
#define SCAMPER_DO_PING_PROBEDPORT_MAX    65535

#define SCAMPER_DO_PING_PROBESPORT_MIN    0
#define SCAMPER_DO_PING_PROBESPORT_MAX    65535

#define SCAMPER_DO_PING_REPLYCOUNT_MIN    0
#define SCAMPER_DO_PING_REPLYCOUNT_DEF    0
#define SCAMPER_DO_PING_REPLYCOUNT_MAX    65535

#define SCAMPER_DO_PING_REPLYPMTU_MIN     0
#define SCAMPER_DO_PING_REPLYPMTU_DEF     0
#define SCAMPER_DO_PING_REPLYPMTU_MAX     65535

#define SCAMPER_DO_PING_PATTERN_MIN       1
#define SCAMPER_DO_PING_PATTERN_DEF       0
#define SCAMPER_DO_PING_PATTERN_MAX       32

#define SCAMPER_DO_PING_PROBETIMEOUT_US_MIN 1000
#define SCAMPER_DO_PING_PROBETIMEOUT_DEF    1
#define SCAMPER_DO_PING_PROBETIMEOUT_MAX    255

#define PING_OPT_PAYLOAD      1
#define PING_OPT_PROBECOUNT   2
#define PING_OPT_PROBEICMPSUM 3
#define PING_OPT_PROBESPORT   4
#define PING_OPT_PROBEDPORT   5
#define PING_OPT_PROBEWAIT    6
#define PING_OPT_PROBETTL     7
#define PING_OPT_REPLYCOUNT   8
#define PING_OPT_OPTION       9
#define PING_OPT_PATTERN      10
#define PING_OPT_PROBEMETHOD  11
#define PING_OPT_RECORDROUTE  12
#define PING_OPT_USERID       13
#define PING_OPT_PROBESIZE    14
#define PING_OPT_SRCADDR      15
#define PING_OPT_TIMESTAMP    16
#define PING_OPT_PROBETOS     17
#define PING_OPT_REPLYPMTU    18
#define PING_OPT_PROBETIMEOUT 19
#define PING_OPT_PROBETCPACK  20
#define PING_OPT_RTRADDR      21
#define PING_OPT_PAYLOADSIZE  22

#define PING_MODE_PROBE       0
#define PING_MODE_PTB         1

static const scamper_option_in_t opts[] = {
  {'A', NULL, PING_OPT_PROBETCPACK,  SCAMPER_OPTION_TYPE_NUM},
  {'b', NULL, PING_OPT_PAYLOADSIZE,  SCAMPER_OPTION_TYPE_NUM},
  {'B', NULL, PING_OPT_PAYLOAD,      SCAMPER_OPTION_TYPE_STR},
  {'c', NULL, PING_OPT_PROBECOUNT,   SCAMPER_OPTION_TYPE_NUM},
  {'C', NULL, PING_OPT_PROBEICMPSUM, SCAMPER_OPTION_TYPE_STR},
  {'d', NULL, PING_OPT_PROBEDPORT,   SCAMPER_OPTION_TYPE_NUM},
  {'F', NULL, PING_OPT_PROBESPORT,   SCAMPER_OPTION_TYPE_NUM},
  {'i', NULL, PING_OPT_PROBEWAIT,    SCAMPER_OPTION_TYPE_STR},
  {'m', NULL, PING_OPT_PROBETTL,     SCAMPER_OPTION_TYPE_NUM},
  {'M', NULL, PING_OPT_REPLYPMTU,    SCAMPER_OPTION_TYPE_NUM},
  {'o', NULL, PING_OPT_REPLYCOUNT,   SCAMPER_OPTION_TYPE_NUM},
  {'O', NULL, PING_OPT_OPTION,       SCAMPER_OPTION_TYPE_STR},
  {'p', NULL, PING_OPT_PATTERN,      SCAMPER_OPTION_TYPE_STR},
  {'P', NULL, PING_OPT_PROBEMETHOD,  SCAMPER_OPTION_TYPE_STR},
  {'r', NULL, PING_OPT_RTRADDR,      SCAMPER_OPTION_TYPE_STR},
  {'R', NULL, PING_OPT_RECORDROUTE,  SCAMPER_OPTION_TYPE_NULL},
  {'s', NULL, PING_OPT_PROBESIZE,    SCAMPER_OPTION_TYPE_NUM},
  {'S', NULL, PING_OPT_SRCADDR,      SCAMPER_OPTION_TYPE_STR},
  {'T', NULL, PING_OPT_TIMESTAMP,    SCAMPER_OPTION_TYPE_STR},
  {'U', NULL, PING_OPT_USERID,       SCAMPER_OPTION_TYPE_NUM},
  {'W', NULL, PING_OPT_PROBETIMEOUT, SCAMPER_OPTION_TYPE_STR},
  {'z', NULL, PING_OPT_PROBETOS,     SCAMPER_OPTION_TYPE_NUM},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_ping_usage(void)
{
  return
    "ping [-R] [-A tcp-ack] [-b payload-size] [-B payload] [-c count]\n"
    "     [-C icmp-sum] [-d dport] [-F sport] [-i wait-probe] [-m ttl]\n"
    "     [-M pmtu] [-o reply-count] [-O option] [-p pattern] [-P method]\n"
    "     [-r rtraddr] [-s probe-size] [-S srcaddr]\n"
    "     [-T timestamp-option] [-U userid] [-W timeout] [-z tos]";
}

static int ping_arg_param_validate(int optid, char *param, long long *out)
{
  struct timeval tv;
  long long tmp = 0;
  int i;

  switch(optid)
    {
    case PING_OPT_PROBETCPACK:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < 0 || tmp > TCP_MAX_SEQNUM)
	goto err;
      break;

    case PING_OPT_PAYLOAD:
      for(i=0; param[i] != '\0'; i++)
	if(ishex(param[i]) == 0)
	  goto err;
      if(i == 0 || (i % 2) != 0 || i/2 > 1000)
	goto err;
      tmp = i;
      break;

    case PING_OPT_PROBECOUNT:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < SCAMPER_DO_PING_PROBECOUNT_MIN ||
	 tmp > SCAMPER_DO_PING_PROBECOUNT_MAX)
	{
	  goto err;
	}
      break;

    case PING_OPT_PROBEICMPSUM:
      if(string_tollong(param, &tmp, NULL, 0) != 0 || tmp < 0 || tmp > 65535)
	goto err;
      break;

    case PING_OPT_PROBEDPORT:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < SCAMPER_DO_PING_PROBEDPORT_MIN ||
	 tmp > SCAMPER_DO_PING_PROBEDPORT_MAX)
	{
	  goto err;
	}
      break;

    case PING_OPT_PROBESPORT:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < SCAMPER_DO_PING_PROBESPORT_MIN ||
	 tmp > SCAMPER_DO_PING_PROBESPORT_MAX)
	{
	  goto err;
	}
      break;

    case PING_OPT_PROBEMETHOD:
      if(strcasecmp(param, "icmp-echo") == 0)
	tmp = SCAMPER_PING_METHOD_ICMP_ECHO;
      else if(strcasecmp(param, "tcp-ack") == 0)
	tmp = SCAMPER_PING_METHOD_TCP_ACK;
      else if(strcasecmp(param, "tcp-ack-sport") == 0)
	tmp = SCAMPER_PING_METHOD_TCP_ACK_SPORT;
      else if(strcasecmp(param, "udp") == 0)
	tmp = SCAMPER_PING_METHOD_UDP;
      else if(strcasecmp(param, "udp-dport") == 0)
	tmp = SCAMPER_PING_METHOD_UDP_DPORT;
      else if(strcasecmp(param, "icmp-time") == 0)
	tmp = SCAMPER_PING_METHOD_ICMP_TIME;
      else if(strcasecmp(param, "tcp-syn") == 0)
	tmp = SCAMPER_PING_METHOD_TCP_SYN;
      else if(strcasecmp(param, "tcp-synack") == 0)
	tmp = SCAMPER_PING_METHOD_TCP_SYNACK;
      else if(strcasecmp(param, "tcp-rst") == 0)
	tmp = SCAMPER_PING_METHOD_TCP_RST;
      else if(strcasecmp(param, "tcp-syn-sport") == 0)
	tmp = SCAMPER_PING_METHOD_TCP_SYN_SPORT;
      else
	goto err;
      break;

    /* how long to wait between sending probes */
    case PING_OPT_PROBEWAIT:
      if(timeval_fromstr(&tv, param, 1000000) != 0 ||
	 timeval_cmp_lt(&tv, 0, 1000) || timeval_cmp_gt(&tv, 20, 0))
	goto err;
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    /* the ttl to probe with */
    case PING_OPT_PROBETTL:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < SCAMPER_DO_PING_PROBETTL_MIN  ||
	 tmp > SCAMPER_DO_PING_PROBETTL_MAX)
	{
	  goto err;
	}
      break;

    /* how many unique replies are required before the ping completes */
    case PING_OPT_REPLYCOUNT:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < SCAMPER_DO_PING_REPLYCOUNT_MIN ||
	 tmp > SCAMPER_DO_PING_REPLYCOUNT_MAX)
	{
	  goto err;
	}
      break;

    case PING_OPT_REPLYPMTU:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < SCAMPER_DO_PING_REPLYPMTU_MIN ||
	 tmp > SCAMPER_DO_PING_REPLYPMTU_MAX)
	{
	  goto err;
	}
      break;

    case PING_OPT_OPTION:
      if(strcasecmp(param, "spoof") != 0 && strcasecmp(param, "dl") != 0 &&
	 strcasecmp(param, "tbt") != 0 && strcasecmp(param, "nosrc") != 0)
	goto err;
      break;

    case PING_OPT_PATTERN:
      /*
       * sanity check that only hex characters are present, and that
       * the pattern string is not too long.
       */
      for(i=0; i<SCAMPER_DO_PING_PATTERN_MAX; i++)
	{
	  if(param[i] == '\0') break;
	  if(ishex(param[i]) == 0) goto err;
	}
      if(i == SCAMPER_DO_PING_PATTERN_MAX) goto err;
      break;

    /* the size of each probe */
    case PING_OPT_PROBESIZE:
    case PING_OPT_PAYLOADSIZE:
      if(string_tollong(param, &tmp, NULL, 0) != 0 || tmp < 0 || tmp > 65535)
	{
	  goto err;
	}
      break;

    case PING_OPT_USERID:
      if(string_tollong(param, &tmp, NULL, 0) != 0 || tmp < 0)
	goto err;
      break;

    case PING_OPT_SRCADDR:
    case PING_OPT_TIMESTAMP:
    case PING_OPT_RTRADDR:
      break;

    /* the tos bits to include in each probe */
    case PING_OPT_PROBETOS:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < SCAMPER_DO_PING_PROBETOS_MIN  ||
	 tmp > SCAMPER_DO_PING_PROBETOS_MAX)
	{
	  goto err;
	}
      break;

    case PING_OPT_PROBETIMEOUT:
      if(timeval_fromstr(&tv, param, 1000000) != 0 ||
	 timeval_cmp_lt(&tv, 0, 1000) || timeval_cmp_gt(&tv, 255, 0))
	goto err;
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    default:
      return -1;
    }

  /* valid parameter */
  if(out != NULL)
    *out = tmp;
  return 0;

 err:
  return -1;
}

/*
 * scamper_do_ping_arg_validate
 *
 *
 */
int scamper_do_ping_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  ping_arg_param_validate);
}

static int ping_tsopt(scamper_ping_t *ping, uint32_t *flags, char *tsopt)
{
  scamper_ping_v4ts_t *ts = NULL;
  char *ips[4], *ptr = tsopt;
  int i = 0;

  while(*ptr != '=' && *ptr != '\0')
    ptr++;

  if(strncasecmp(tsopt, "tsprespec", 9) == 0 && *ptr == '=')
    {
      ptr++;
      for(;;)
	{
	  if(i == 4)
	    return -1;

	  ips[i++] = ptr;

	  while(isdigit((int)*ptr) || *ptr == '.')
	    ptr++;

	  if(*ptr == '\0')
	    break;
	  if(*ptr != ',')
	    return -1;

	  *ptr = '\0';
	  ptr++;
	}

      if((ts = scamper_ping_v4ts_alloc(i)) == NULL)
	return -1;

      i--;
      while(i>=0)
	{
	  if((ts->ips[i] = scamper_addr_fromstr_ipv4(ips[i])) == NULL)
	    {
	      scamper_ping_v4ts_free(ts);
	      return -1;
	    }
	  i--;
	}

      ping->probe_tsps = ts;
    }
  else if(*ptr == '\0' && strcasecmp(tsopt, "tsonly") == 0)
    {
      *flags |= SCAMPER_PING_FLAG_TSONLY;
    }
  else if(*ptr == '\0' && strcasecmp(tsopt, "tsandaddr") == 0)
    {
      *flags |= SCAMPER_PING_FLAG_TSANDADDR;
    }
  else
    {
      return -1;
    }

  return 0;
}

/*
 * scamper_do_ping_alloc
 *
 * given a string representing a ping task, parse the parameters and assemble
 * a ping.  return the ping structure so that it is all ready to go.
 *
 */
void *scamper_do_ping_alloc(char *str, uint32_t *id)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_ping_t *ping = NULL;
  uint16_t  probe_count   = SCAMPER_DO_PING_PROBECOUNT_DEF;
  struct timeval wait_timeout, wait_probe;
  uint8_t   probe_ttl     = SCAMPER_DO_PING_PROBETTL_DEF;
  uint8_t   probe_tos     = SCAMPER_DO_PING_PROBETOS_DEF;
  uint8_t   probe_method  = SCAMPER_DO_PING_PROBEMETHOD_DEF;
  int       probe_sport   = -1;
  int       probe_dport   = -1;
  uint16_t  reply_count   = SCAMPER_DO_PING_REPLYCOUNT_DEF;
  uint16_t  reply_pmtu    = SCAMPER_DO_PING_REPLYPMTU_DEF;
  uint16_t  probe_size    = 0; /* unset */
  int       payload_size  = -1; /* unset */
  uint16_t  pattern_len   = 0;
  uint16_t  probe_icmpsum = 0;
  uint32_t  probe_tcpack  = 0;
  uint8_t   pattern[SCAMPER_DO_PING_PATTERN_MAX/2];
  uint16_t  payload_len   = 0;
  uint8_t  *payload       = NULL;
  uint32_t  userid        = 0;
  uint32_t  flags         = 0;
  char     *src           = NULL;
  char     *rtr           = NULL;
  char     *tsopt         = NULL;
  uint16_t cmps = 0; /* calculated minimum probe size */
  char *addr;
  size_t size;
  long long j, tmp = 0;
  int i, A = 0;
  uint16_t u16;
  uint32_t optids = 0;

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

  /* parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 ping_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      if((optids & (0x1 << opt->id)) != 0 && opt->id != PING_OPT_OPTION)
	{
	  scamper_debug(__func__, "repeated optid %d", opt->id);
	  goto err;
	}
      optids |= (0x1 << opt->id);

      switch(opt->id)
	{
	case PING_OPT_PROBETCPACK:
	  probe_tcpack = (uint32_t)tmp;
	  A = 1;
	  break;

	case PING_OPT_PAYLOADSIZE:
	  payload_size = (int)tmp;
	  break;

	case PING_OPT_PAYLOAD:
	  assert(payload == NULL);
	  if((payload = malloc(tmp/2)) == NULL)
	    {
	      printerror(__func__, "could not malloc payload");
	      goto err;
	    }
	  payload_len = 0;
	  for(j=0; j<tmp; j+=2)
	    payload[payload_len++] = hex2byte(opt->str[j], opt->str[j+1]);
	  flags |= SCAMPER_PING_FLAG_PAYLOAD;
	  break;

	case PING_OPT_PROBECOUNT:
	  probe_count = (uint16_t)tmp;
	  break;

	case PING_OPT_PROBEDPORT:
	  probe_dport = (uint16_t)tmp;
	  break;

	case PING_OPT_PROBESPORT:
	  probe_sport = (int)tmp;
	  break;

	case PING_OPT_PROBEMETHOD:
	  probe_method = (uint8_t)tmp;
	  break;

	/* how long to wait between sending probes */
	case PING_OPT_PROBEWAIT:
	  wait_probe.tv_sec = tmp / 1000000;
	  wait_probe.tv_usec = tmp % 1000000;
	  break;

	/* the ttl to probe with */
	case PING_OPT_PROBETTL:
	  probe_ttl = (uint8_t)tmp;
	  break;

	case PING_OPT_PROBEICMPSUM:
	  probe_icmpsum = (uint16_t)tmp;
	  flags |= SCAMPER_PING_FLAG_ICMPSUM;
	  break;

	/* how many unique replies are required before the ping completes */
	case PING_OPT_REPLYCOUNT:
	  reply_count = (uint16_t)tmp;
	  break;

	case PING_OPT_REPLYPMTU:
	  reply_pmtu = (uint16_t)tmp;
	  flags |= SCAMPER_PING_FLAG_DL;
	  break;

	case PING_OPT_OPTION:
	  if(strcasecmp(opt->str, "spoof") == 0)
	    flags |= SCAMPER_PING_FLAG_SPOOF;
	  else if(strcasecmp(opt->str, "dl") == 0)
	    flags |= SCAMPER_PING_FLAG_DL;
	  else if(strcasecmp(opt->str, "tbt") == 0)
	    flags |= SCAMPER_PING_FLAG_TBT;
	  else if(strcasecmp(opt->str, "nosrc") == 0)
	    flags |= SCAMPER_PING_FLAG_NOSRC;
	  else
	    {
	      scamper_debug(__func__, "unknown option %s", opt->str);
	      goto err;
	    }
	  break;

	/* the pattern to fill each probe with */
	case PING_OPT_PATTERN:
	  size = strlen(opt->str);
	  if((size % 2) == 0)
	    {
	      pattern_len = size/2;
	      for(i=0; i<pattern_len; i++)
		pattern[i] = hex2byte(opt->str[i*2], opt->str[(i*2)+1]);
	    }
	  else
	    {
	      pattern_len = (size/2) + 1;
	      pattern[0] = hex2byte('0', opt->str[0]);
	      for(i=1; i<pattern_len; i++)
		pattern[i] = hex2byte(opt->str[(i*2)-1], opt->str[i*2]);
	    }
	  break;

	/* the size of each probe */
	case PING_OPT_PROBESIZE:
	  probe_size = (uint16_t)tmp;
	  break;

	case PING_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case PING_OPT_RTRADDR:
	  rtr = opt->str;
	  break;

	case PING_OPT_RECORDROUTE:
	  flags |= SCAMPER_PING_FLAG_V4RR;
	  break;

	case PING_OPT_SRCADDR:
	  src = opt->str;
	  break;

	case PING_OPT_TIMESTAMP:
	  tsopt = opt->str;
	  break;

	/* the tos bits to include in each probe */
	case PING_OPT_PROBETOS:
	  probe_tos = (uint8_t)tmp;
	  break;

	case PING_OPT_PROBETIMEOUT:
	  wait_timeout.tv_sec = tmp / 1000000;
	  wait_timeout.tv_usec = tmp % 1000000;
	  break;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if((optids & (0x1 << PING_OPT_PROBEWAIT)) == 0)
    {
      wait_probe.tv_sec = SCAMPER_DO_PING_PROBEWAIT_DEF;
      wait_probe.tv_usec = 0;
    }

  if((optids & (0x1 << PING_OPT_PROBETIMEOUT)) == 0)
    {
      if(wait_probe.tv_sec >= 1)
	{
	  wait_timeout.tv_sec = wait_probe.tv_sec;
	  wait_timeout.tv_usec = wait_probe.tv_usec;
	}
      else
	{
	  wait_timeout.tv_sec = SCAMPER_DO_PING_PROBETIMEOUT_DEF;
	  wait_timeout.tv_usec = 0;
	}
    }

  /* allocate the ping object and determine the address to probe */
  if((ping = scamper_ping_alloc()) == NULL)
    {
      goto err;
    }
  if((ping->dst = scamper_addr_fromstr_unspec(addr)) == NULL)
    {
      goto err;
    }
  ping->probe_method = probe_method;

  /* only one of pattern or payload should be specified */
  if(countbits32(optids & ((0x1 << PING_OPT_PATTERN) |
			   (0x1 << PING_OPT_PAYLOAD))) > 1)
    goto err;

  /*
   * if the user specified the payload size, then make sure it is
   * consistent with payload if they also specified the payload
   */
  if(countbits32(optids & ((0x1 << PING_OPT_PAYLOAD) |
			   (0x1 << PING_OPT_PAYLOADSIZE))) == 2 &&
     (int)payload_len != payload_size)
    goto err;

  if(payload_size == -1 && payload_len != 0)
    payload_size = payload_len;

  /*
   * put together the timestamp option now so we can judge how large the
   * options will be
   */
  if(tsopt != NULL)
    {
      /* TS option only valid with IPv4 probes */
      if(ping->dst->type != SCAMPER_ADDR_TYPE_IPV4)
	goto err;

      /* cannot do RR and TS options in the same ping */
      if((flags & SCAMPER_PING_FLAG_V4RR) != 0)
	goto err;

      if(ping_tsopt(ping, &flags, tsopt) != 0)
	goto err;
    }

  /* calculate the size of the IP header, with options */
  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      cmps = 20;
      if(flags & SCAMPER_PING_FLAG_V4RR)
	cmps += 40;
      else if(ping->probe_tsps != NULL)
	cmps += (8 * ping->probe_tsps->ipc) + 4;
      else if(flags & SCAMPER_PING_FLAG_TSONLY)
	cmps += 40;
      else if(flags & SCAMPER_PING_FLAG_TSANDADDR)
	cmps += 36;
      if((flags & SCAMPER_PING_FLAG_SPOOF) != 0 &&
	 (flags & SCAMPER_PING_FLAG_NOSRC) == 0 &&
	 probe_method != SCAMPER_PING_METHOD_TCP_SYNACK &&
	 probe_method != SCAMPER_PING_METHOD_TCP_RST)
	cmps += 4;
    }
  else if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      cmps = 40;
      if((flags & SCAMPER_PING_FLAG_SPOOF) != 0 &&
	 (flags & SCAMPER_PING_FLAG_NOSRC) == 0 &&
	 probe_method != SCAMPER_PING_METHOD_TCP_SYNACK &&
	 probe_method != SCAMPER_PING_METHOD_TCP_RST)
	cmps += 16;
    }
  else goto err;

  /* include the size of the headers */
  if(SCAMPER_PING_METHOD_IS_ICMP(ping))
    {
      /* 8 bytes for the base ICMP header */
      cmps += 8;

      /* 12 bytes for the additional space required for the ICMP time header */
      if(SCAMPER_PING_METHOD_IS_ICMP_TIME(ping))
	cmps += 12;
    }
  else if(SCAMPER_PING_METHOD_IS_TCP(ping))
    {
      /* 20 bytes for TCP header */
      cmps += 20;
    }
  else if(SCAMPER_PING_METHOD_IS_UDP(ping))
    {
      /* 8 bytes for UDP header */
      cmps += 8;
    }
  else goto err;

  /*
   * if the user specified the probe size to use, ensure that the
   * calculated minimum probe size is not larger
   */
  if(probe_size != 0 && probe_size < cmps)
    goto err;

  /* defaults for payload size */
  if(payload_size == -1)
    {
      if(probe_size != 0)
	payload_size = probe_size - cmps;
      else if(SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping))
	payload_size = 56;
      else if(SCAMPER_PING_METHOD_IS_UDP(ping))
	payload_size = 12;
      else if(SCAMPER_PING_METHOD_IS_ICMP_TIME(ping))
	payload_size = 44;
      else
	payload_size = 0;
    }

  if(probe_size == 0)
    probe_size = cmps + payload_size;
  else if(probe_size != cmps + payload_size)
    goto err;

  if(flags & SCAMPER_PING_FLAG_ICMPSUM)
    {
      /* the icmp-sum parameter is only valid for ICMP probe method */
      if(SCAMPER_PING_METHOD_IS_ICMP(ping) == 0)
	goto err;

      /*
       * do not include the 2 bytes of payload we require to
       * manipulate the ICMP checksum in the probe_size.  instead
       * ensure that if the user included a probe size, that it is
       * large enough to allow for checksum manipulation.
       */
      if(payload_size < 2)
	goto err;
    }

  /* TBT method is about getting IPv6 fragments */
  if(flags & SCAMPER_PING_FLAG_TBT)
    {
      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	goto err;
      if(reply_pmtu == 0 || probe_size <= reply_pmtu)
	goto err;
    }

  if(src != NULL &&
     (ping->src = scamper_addr_fromstr(ping->dst->type, src)) == NULL)
    goto err;

  if(rtr != NULL &&
     (ping->rtr = scamper_addr_fromstr(ping->dst->type, rtr)) == NULL)
    goto err;

  /* copy in the data bytes, if any */
  if(pattern_len != 0)
    {
      if((ping->probe_data = memdup(pattern, pattern_len)) == NULL)
	goto err;
      ping->probe_datalen = pattern_len;
    }
  else if(payload_len != 0)
    {
      ping->probe_data = payload; payload = NULL;
      ping->probe_datalen = payload_len;
    }

  if(SCAMPER_PING_METHOD_IS_ICMP(ping))
    {
      if(probe_sport == -1)
	probe_sport = scamper_pid_u16();
      else if(probe_sport == 0)
	{
	  random_u16(&u16);
	  probe_sport = u16 | 0x8000;
	}
    }
  else if(probe_sport == -1 || probe_sport == 0)
    {
      if(probe_sport == -1)
	probe_sport = scamper_sport_default();
      else if(probe_sport == 0)
	{
	  random_u16(&u16);
	  probe_sport = u16 | 0x8000;
	}

      /*
       * if scamper generates the starting sport value, make sure it
       * won't wrap to zero.
       */
      if(SCAMPER_PING_METHOD_IS_VARY_SPORT(ping) &&
	 65535 - probe_sport < probe_count-1 && probe_count < 32768)
	{
	  probe_sport -= probe_count;
	  if(probe_sport < 0x8000)
	    probe_sport = 0x8000;
	}
    }

  /* make sure probe_sport + probe_count <= 65535 */
  if(SCAMPER_PING_METHOD_IS_VARY_SPORT(ping) &&
     65535 - probe_sport < probe_count - 1)
    {
      scamper_debug(__func__, "invalid probe_sport %u given probe_count %u",
		    probe_sport, probe_count);
      goto err;
    }

  if(probe_dport == -1)
    {
      if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	probe_dport = 0;
      else
	probe_dport = 33435;
    }

  /* make sure probe_dport + probe_count <= 65535 */
  if(SCAMPER_PING_METHOD_IS_VARY_DPORT(ping) &&
     65535 - probe_dport < probe_count - 1)
    {
      scamper_debug(__func__, "invalid probe_dport %u given probe_count %u",
		    probe_dport, probe_count);
      goto err;
    }

  timeval_cpy(&ping->wait_probe, &wait_probe);
  timeval_cpy(&ping->wait_timeout, &wait_timeout);

  ping->probe_count      = probe_count;
  ping->probe_size       = probe_size;
  ping->probe_ttl        = probe_ttl;
  ping->probe_tos        = probe_tos;
  ping->probe_sport      = probe_sport;
  ping->probe_dport      = probe_dport;
  ping->probe_icmpsum    = probe_icmpsum;
  ping->reply_count      = reply_count;
  ping->reply_pmtu       = reply_pmtu;
  ping->userid           = *id = userid;
  ping->flags            = flags;

  if(SCAMPER_PING_METHOD_IS_TCP(ping))
    {
      if(A == 0 && random_u32(&probe_tcpack) != 0)
	goto err;

      if(ping->probe_method == SCAMPER_PING_METHOD_TCP_SYN ||
	 ping->probe_method == SCAMPER_PING_METHOD_TCP_SYN_SPORT ||
	 ping->probe_method == SCAMPER_PING_METHOD_TCP_RST)
	{
	  ping->probe_tcpseq = probe_tcpack;
	  ping->probe_tcpack = 0;
	}
      else
	{
	  ping->probe_tcpack = probe_tcpack;
	  if(random_u32(&ping->probe_tcpseq) != 0)
	    goto err;
	}
    }

  return ping;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  if(payload != NULL) free(payload);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}
