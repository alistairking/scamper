/*
 * scamper_udpprobe_cmd.c
 *
 * $Id: scamper_udpprobe_cmd.c,v 1.10 2024/02/21 04:58:05 mjl Exp $
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
#include "scamper_udpprobe_cmd.h"
#include "scamper_options.h"
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

static int udpprobe_arg_param_validate(int optid, char *param, long long *out,
				       char *errbuf, size_t errlen)
{
  struct timeval tv;
  long long tmp = 0;
  int i;

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  switch(optid)
    {
    case UDPPROBE_OPT_DPORT:
      if(string_tollong(param, &tmp, NULL, 0) == -1 || tmp < 1 || tmp > 65535)
	{
	  snprintf(errbuf, errlen, "dport must be within 1 - 65535");
	  goto err;
	}
      break;

    case UDPPROBE_OPT_OPTION:
      if(strcasecmp(param, "exitfirst") == 0)
	tmp = SCAMPER_UDPPROBE_FLAG_EXITFIRST;
      else
	{
	  snprintf(errbuf, errlen, "-O %s unknown", param);
	  goto err;
	}
      break;

    case UDPPROBE_OPT_PAYLOAD:
      if((i = string_ishex(param)) == 0)
	{
	  snprintf(errbuf, errlen, "payload must be specified in hex");
	  goto err;
	}
      if((i % 2) != 0)
	{
	  snprintf(errbuf, errlen, "expected even number of hex characters");
	  goto err;
	}
      if(i/2 > 1000)
	{
	  snprintf(errbuf, errlen, "payload limit is 1000 bytes");
	  goto err;
	}
      assert(i > 0);
      tmp = i;
      break;

    case UDPPROBE_OPT_USERID:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < 0 || tmp > UINT32_MAX)
	{
	  snprintf(errbuf, errlen, "userid must be within %u - %u", 0,
		   UINT32_MAX);
	  goto err;
	}
      break;

    case UDPPROBE_OPT_TIMEOUT:
      if(timeval_fromstr(&tv, param, 1000000) != 0)
	{
	  snprintf(errbuf, errlen, "malformed timeout");
	  goto err;
	}
      if(timeval_cmp_lt(&tv, 0, 500000) || timeval_cmp_gt(&tv, 5, 0))
	{
	  snprintf(errbuf, errlen, "timeout must be within 0.5s - 5s");
	  goto err;
	}
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
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

int scamper_do_udpprobe_arg_validate(int argc, char *argv[], int *stop,
				     char *errbuf, size_t errlen)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  errbuf, errlen, udpprobe_arg_param_validate);
}

void *scamper_do_udpprobe_alloc(char *str, char *errbuf, size_t errlen)
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
  char buf[256];

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  /* Parse the options */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      snprintf(errbuf, errlen, "could not parse udpprobe command");
      goto err;
    }

  /* If there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      snprintf(errbuf, errlen, "expected address to probe");
      goto err;
    }

  timeout.tv_sec = 2;
  timeout.tv_usec = 0;

  /* Parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 udpprobe_arg_param_validate(opt->id, opt->str, &tmp,
				     buf, sizeof(buf)) != 0)
	{
	  snprintf(errbuf, errlen, "-%c %s failed: %s",
		   scamper_options_id2c(opts, opts_cnt, opt->id),
		   opt->str, buf);
	  goto err;
	}

      if((optids & (0x1 << opt->id)) != 0 && opt->id != UDPPROBE_OPT_OPTION)
	{
	  snprintf(errbuf, errlen, "repeated option -%c",
		   scamper_options_id2c(opts, opts_cnt, opt->id));
	  goto err;
	}
      optids |= (0x1 << opt->id);

      switch(opt->id)
	{
	case UDPPROBE_OPT_DPORT:
	  dport = (uint16_t)tmp;
	  break;

	case UDPPROBE_OPT_OPTION:
	  flags |= (uint8_t)tmp;
	  break;

	case UDPPROBE_OPT_PAYLOAD:
	  assert(payload == NULL);
	  if((payload = malloc(tmp/2)) == NULL)
	    {
	      snprintf(errbuf, errlen, "could not malloc payload");
	      goto err;
	    }
	  payload_len = 0;
	  for(j=0; j<tmp; j+=2)
	    payload[payload_len++] = hex2byte(opt->str[j], opt->str[j+1]);
	  break;

	case UDPPROBE_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case UDPPROBE_OPT_TIMEOUT:
	  timeout.tv_sec = tmp / 1000000;
	  timeout.tv_usec = tmp % 1000000;
	  break;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if(payload_len == 0)
    {
      snprintf(errbuf, errlen, "missing payload parameter");
      goto err;
    }
  if(dport == 0)
    {
      snprintf(errbuf, errlen, "missing destination port parameter");
      goto err;
    }

  if((up = scamper_udpprobe_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc udpprobe");
      goto err;
    }

  if((up->dst = scamper_addr_fromstr_unspec(addr)) == NULL)
    {
      snprintf(errbuf, errlen, "invalid destination address");
      goto err;
    }

  up->userid = userid;
  up->dport = dport;
  up->data = payload; payload = NULL;
  up->len = payload_len;
  up->flags = flags;
  up->sport = scamper_sport_default();
  timeval_cpy(&up->wait_timeout, &timeout);

  assert(errbuf[0] == '\0');
  return up;

 err:
  assert(errbuf[0] != '\0');
  if(payload != NULL) free(payload);
  if(opts_out != NULL) scamper_options_free(opts_out);
  if(up != NULL) scamper_udpprobe_free(up);
  return NULL;
}
