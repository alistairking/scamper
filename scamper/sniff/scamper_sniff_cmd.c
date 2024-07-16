/*
 * scamper_sniff_do.c
 *
 * $Id: scamper_sniff_cmd.c,v 1.6 2024/05/02 02:33:38 mjl Exp $
 *
 * Copyright (C) 2011      The University of Waikato
 * Copyright (C) 2022-2023 Matthew Luckie
 * Copyright (C) 2024      The Regents of the University of California
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

#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_sniff.h"
#include "scamper_sniff_int.h"
#include "scamper_sniff_cmd.h"
#include "scamper_options.h"
#include "utils.h"

/* Address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

#define SNIFF_OPT_LIMIT_PKTC   1
#define SNIFF_OPT_LIMIT_TIME   2
#define SNIFF_OPT_SRCADDR      3
#define SNIFF_OPT_USERID       4

static const scamper_option_in_t opts[] = {
  {'c', NULL, SNIFF_OPT_LIMIT_PKTC, SCAMPER_OPTION_TYPE_NUM},
  {'G', NULL, SNIFF_OPT_LIMIT_TIME, SCAMPER_OPTION_TYPE_STR},
  {'S', NULL, SNIFF_OPT_SRCADDR,    SCAMPER_OPTION_TYPE_STR},
  {'U', NULL, SNIFF_OPT_USERID,     SCAMPER_OPTION_TYPE_NUM},
};

static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

const char *scamper_do_sniff_usage(void)
{
  return "sniff [-c limit-pktc] [-G limit-time] [-S ipaddr] [-U userid] <expression>\n";
}

static int sniff_arg_param_validate(int optid, char *param, long long *out,
				    char *errbuf, size_t errlen)
{
  struct timeval tv;
  long long tmp = 0;

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  switch(optid)
    {
    case SNIFF_OPT_SRCADDR:
      break;

    case SNIFF_OPT_LIMIT_PKTC:
      if(string_tollong(param, &tmp, NULL, 0) != 0 || tmp < 1 || tmp > 5000)
	{
	  snprintf(errbuf, errlen, "limit-pktc must be within 1 - 5000");
	  goto err;
	}
      break;

    case SNIFF_OPT_LIMIT_TIME:
      if(timeval_fromstr(&tv, param, 1000000) != 0)
	{
	  snprintf(errbuf, errlen, "malformed limit-time");
	  goto err;
	}
      if(tv.tv_usec != 0)
	{
	  snprintf(errbuf, errlen, "limit-time cannot have fractions of second");
	  goto err;
	}
      if(timeval_cmp_lt(&tv, 1, 0) || timeval_cmp_gt(&tv, 1200, 0))
	{
	  snprintf(errbuf, errlen, "limit-time must be within 1s - 1200s");
	  goto err;
	}
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    case SNIFF_OPT_USERID:
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

  assert(errbuf[0] == '\0');
  if(out != NULL)
    *out = tmp;
  return 0;

 err:
  assert(errbuf[0] != '\0');
  return -1;
}

int scamper_do_sniff_arg_validate(int argc, char *argv[], int *stop,
				  char *errbuf, size_t errlen)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  errbuf, errlen, sniff_arg_param_validate);
}

void *scamper_do_sniff_alloc(char *str, char *errbuf, size_t errlen)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_sniff_t *sniff = NULL;
  struct timeval limit_time;
  uint32_t userid = 0;
  uint32_t limit_pktc = 100;
  long icmpid = -1;
  char *expr = NULL;
  char *src = NULL;
  long long tmp = 0;
  char buf[256];

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &expr) != 0)
    {
      snprintf(errbuf, errlen, "could not parse sniff command");
      goto err;
    }

  if(expr == NULL)
    {
      snprintf(errbuf, errlen, "expected expression");
      goto err;
    }

  if(strncasecmp(expr, "icmp[icmpid] == ", 16) != 0 ||
     string_isnumber(expr+16) == 0 ||
     string_tolong(expr+16, &icmpid) != 0 ||
     icmpid < 0 || icmpid > 65535)
    {
      snprintf(errbuf, errlen, "icmp[icmpid] not supplied");
      goto err;
    }

  /* default time limit of 60 seconds */
  limit_time.tv_sec = 60; limit_time.tv_usec = 0;

  /* parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 sniff_arg_param_validate(opt->id, opt->str, &tmp,
				  buf, sizeof(buf)) != 0)
	{
	  snprintf(errbuf, errlen, "-%c failed: %s",
		   scamper_options_id2c(opts, opts_cnt, opt->id), buf);
	  goto err;
	}

      switch(opt->id)
	{
	case SNIFF_OPT_SRCADDR:
	  src = opt->str;
	  break;

	case SNIFF_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case SNIFF_OPT_LIMIT_TIME:
	  limit_time.tv_sec = tmp / 1000000;
	  limit_time.tv_usec = tmp % 1000000;
	  break;

	case SNIFF_OPT_LIMIT_PKTC:
	  limit_pktc = (uint32_t)tmp;
	  break;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if(src == NULL)
    {
      snprintf(errbuf, errlen, "missing source address parameter");
      goto err;
    }

  if((sniff = scamper_sniff_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc sniff");
      goto err;
    }

  if((sniff->src = scamper_addrcache_resolve(addrcache,AF_UNSPEC,src)) == NULL)
    {
      snprintf(errbuf, errlen, "invalid source address");
      goto err;
    }

  sniff->limit_pktc = limit_pktc;
  sniff->userid     = userid;
  sniff->icmpid     = (uint16_t)icmpid;
  timeval_cpy(&sniff->limit_time, &limit_time);

  assert(errbuf[0] == '\0');
  return sniff;

 err:
  assert(errbuf[0] != '\0');
  if(sniff != NULL) scamper_sniff_free(sniff);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}
