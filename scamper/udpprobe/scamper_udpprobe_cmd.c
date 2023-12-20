/*
 * scamper_udpprobe_cmd.c
 *
 * $Id: scamper_udpprobe_cmd.c,v 1.7 2024/01/16 06:26:56 mjl Exp $
 *
 * Copyright (C) 2023-2024 The Regents of the University of California
 *
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
#include "scamper_udpprobe.h"
#include "scamper_udpprobe_int.h"
#include "scamper_options.h"
#include "scamper_debug.h"
#include "utils.h"

/* options that udpprobe supports */
#define UDPPROBE_OPT_USERID  1
#define UDPPROBE_OPT_PAYLOAD 2
#define UDPPROBE_OPT_DPORT   3
#define UDPPROBE_OPT_TIMEOUT 4
#define UDPPROBE_OPT_OPTION  5

static const scamper_option_in_t opts[] = {
  {'d', NULL, UDPPROBE_OPT_DPORT, SCAMPER_OPTION_TYPE_NUM},
  {'O', NULL, UDPPROBE_OPT_OPTION, SCAMPER_OPTION_TYPE_STR},
  {'p', NULL, UDPPROBE_OPT_PAYLOAD, SCAMPER_OPTION_TYPE_STR},
  {'U', NULL, UDPPROBE_OPT_USERID, SCAMPER_OPTION_TYPE_NUM},
  {'w', NULL, UDPPROBE_OPT_TIMEOUT, SCAMPER_OPTION_TYPE_STR},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_udpprobe_usage(void)
{
  return
    "udpprobe [-d dport] [-O option] [-p payload] [-U userid] [-w wait-timeout]";
}

static int udpprobe_arg_param_validate(int optid, char *param, long long *out)
{
  struct timeval tv;
  long tmp;
  int i;

  switch(optid)
    {
    case UDPPROBE_OPT_DPORT:
      if(string_tolong(param, &tmp) == -1 || tmp < 1 || tmp > 65535)
	 goto err;
      break;

    case UDPPROBE_OPT_OPTION:
      if(strcasecmp(param, "exitfirst") != 0)
	goto err;
      tmp = 0;
      break;

    case UDPPROBE_OPT_PAYLOAD:
      for(i=0; param[i] != '\0'; i++)
	if(ishex(param[i]) == 0)
	  goto err;
      if(i == 0 || (i % 2) != 0 || i/2 > 1000)
	goto err;
      tmp = i;
      break;

    case UDPPROBE_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	goto err;
      break;

    case UDPPROBE_OPT_TIMEOUT:
      if(timeval_fromstr(&tv, param, 1000000) != 0 ||
	 timeval_cmp_lt(&tv, 0, 500000) || timeval_cmp_gt(&tv, 5, 0))
	goto err;
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    default:
      goto err;
    }

  /* valid parameter */
  if(out != NULL)
    *out = (long long)tmp;
  return 0;

 err:
  return -1;
}

int scamper_do_udpprobe_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  udpprobe_arg_param_validate);
}

void *scamper_do_udpprobe_alloc(char *str, uint32_t *id)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_udpprobe_t *up = NULL;
  struct timeval timeout;
  uint8_t *payload = NULL;
  uint32_t userid = 0;
  char *addr = NULL;
  long long j, tmp = 0;
  uint16_t dport = 0, payload_len = 0;
  uint8_t flags = 0;
  uint32_t optids = 0;

  /* Parse the options */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      scamper_debug(__func__, "could not parse options");
      goto err;
    }

  /* If there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      scamper_debug(__func__, "no address parameter");
      goto err;
    }

  timeout.tv_sec = 2;
  timeout.tv_usec = 0;

  /* Parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 udpprobe_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
	  goto err;
	}

      if((optids & (0x1 << opt->id)) != 0 && opt->id != UDPPROBE_OPT_OPTION)
	{
	  scamper_debug(__func__, "repeated optid %d", opt->id);
	  goto err;
	}
      optids |= (0x1 << opt->id);

      switch(opt->id)
	{
	case UDPPROBE_OPT_DPORT:
	  dport = (uint16_t)tmp;
	  break;

	case UDPPROBE_OPT_OPTION:
	  if(strcasecmp(opt->str, "exitfirst") == 0)
	    flags |= SCAMPER_UDPPROBE_FLAG_EXITFIRST;
	  else
	    {
	      scamper_debug(__func__, "unknown option %s", opt->str);
	      goto err;
	    }
	  break;

	case UDPPROBE_OPT_PAYLOAD:
	  assert(payload == NULL);
	  if((payload = malloc(tmp/2)) == NULL)
	    {
	      printerror(__func__, "could not malloc payload");
	      goto err;
	    }
	  payload_len = 0;
	  for(j=0; j<tmp; j+=2)
	    payload[payload_len++] = hex2byte(opt->str[j], opt->str[j+1]);
	  break;

	case UDPPROBE_OPT_USERID:
	  userid = *id = (uint32_t)tmp;
	  break;

	case UDPPROBE_OPT_TIMEOUT:
	  timeout.tv_sec = tmp / 1000000;
	  timeout.tv_usec = tmp % 1000000;
	  break;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if(payload == NULL || payload_len == 0 || dport == 0)
    {
      goto err;
    }

  if((up = scamper_udpprobe_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc udpprobe");
      goto err;
    }

  if((up->dst = scamper_addr_fromstr_unspec(addr)) == NULL)
    {
      printerror(__func__, "could not resolve %s", addr);
      goto err;
    }

  up->userid = userid;
  up->dport = dport;
  up->data = payload; payload = NULL;
  up->len = payload_len;
  up->flags = flags;
  timeval_cpy(&up->wait_timeout, &timeout);

  return up;

 err:
  if(payload != NULL) free(payload);
  if(opts_out != NULL) scamper_options_free(opts_out);
  if(up != NULL) scamper_udpprobe_free(up);
  return NULL;
}
