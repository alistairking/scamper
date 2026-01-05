/*
 * scamper_owamp_cmd.c
 *
 * $Id: scamper_owamp_cmd.c,v 1.4 2026/01/04 19:19:15 mjl Exp $
 *
 * Copyright (C) 2025-2026 The Regents of the University of California
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
#include "scamper_owamp.h"
#include "scamper_owamp_int.h"
#include "scamper_owamp_cmd.h"
#include "scamper_options.h"
#include "scamper_dnp.h"
#include "mjl_list.h"
#include "utils.h"

/* options that owamp supports */
#define OWAMP_OPT_COUNT        1
#define OWAMP_OPT_DIR          2
#define OWAMP_OPT_DSCP         3
#define OWAMP_OPT_SCHED        4
#define OWAMP_OPT_TTL          5
#define OWAMP_OPT_OPTION       6
#define OWAMP_OPT_SIZE         7
#define OWAMP_OPT_USERID       8
#define OWAMP_OPT_WAIT_TIMEOUT 9
#define OWAMP_OPT_STARTAT      10

static const scamper_option_in_t opts[] = {
  {'c', NULL, OWAMP_OPT_COUNT,        SCAMPER_OPTION_TYPE_NUM},
  {'d', NULL, OWAMP_OPT_DIR,          SCAMPER_OPTION_TYPE_STR},
  {'D', NULL, OWAMP_OPT_DSCP,         SCAMPER_OPTION_TYPE_NUM},
  {'i', NULL, OWAMP_OPT_SCHED,        SCAMPER_OPTION_TYPE_STR},
  {'m', NULL, OWAMP_OPT_TTL,          SCAMPER_OPTION_TYPE_NUM},
  {'O', NULL, OWAMP_OPT_OPTION,       SCAMPER_OPTION_TYPE_STR},
  {'s', NULL, OWAMP_OPT_SIZE,         SCAMPER_OPTION_TYPE_NUM},
  {'U', NULL, OWAMP_OPT_USERID,       SCAMPER_OPTION_TYPE_NUM},
  {'w', NULL, OWAMP_OPT_WAIT_TIMEOUT, SCAMPER_OPTION_TYPE_STR},
  {'@', NULL, OWAMP_OPT_STARTAT,      SCAMPER_OPTION_TYPE_STR},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

typedef struct opt_limit
{
  char      *name;
  long long  min;
  long long  max;
} opt_limit_t;

static const opt_limit_t limits[] = {
  {NULL, 0, 0},              /* zero unused */
  {"attempts", 1, 65535},    /* -c count */
  {NULL, 0, 0},              /* -d dir */
  {"dscp", 0, 63},           /* -D dscp */
  {NULL, 0, 0},              /* -i sched */
  {"ttl", 1, 255},           /* -m ttl */
  {NULL, 0, 0},              /* -O option */
  {"size", 0, 65535},        /* -s size */
  {"userid", 0, UINT32_MAX}, /* -U userid */
  {NULL, 0, 0},              /* -w wait-timeout */
  {NULL, 0, 0},              /* -@ startat */
};

/* Address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

const char *scamper_do_owamp_usage(void)
{
  return
    "owamp [-c count] [-d dir] [-D dscp] [-i sched] [-m ttl] [-O option]\n"
    "      [-s size] [-U userid] [-w wait-timeout] [-@ startat]";
}

static scamper_owamp_sched_t *sched_alloc(struct timeval *tv, char type)
{
  scamper_owamp_sched_t *sched;

  if((sched = scamper_owamp_sched_alloc()) == NULL)
    return NULL;
  timeval_cpy(&sched->tv, tv);
  if(type == 'f')
    sched->type = SCAMPER_OWAMP_SCHED_TYPE_FIXED;
  else
    sched->type = SCAMPER_OWAMP_SCHED_TYPE_EXP;
  return sched;
}

static int sched_parse(slist_t *list, const char *param)
{
  scamper_owamp_sched_t *sched;
  char *dup = NULL;
  char *in, *next;
  struct timeval tv;
  size_t len;
  char type;
  int rc = -1;

  if((dup = strdup(param)) == NULL)
    goto done;
  in = dup;

  do
    {
      if((len = string_nullterm_char(in, ',', &next)) == 0)
	goto done;

      type = in[len-1];
      if(type == 'e' || type == 'f')
	{
	  if(len == 1)
	    goto done;
	  len--;
	  in[len] = '\0';
	}
      else type = 'f';

      if(timeval_fromstr(&tv, in, 1000000) != 0)
	goto done;

      if(list != NULL &&
	 ((sched = sched_alloc(&tv, type)) == NULL ||
	  slist_tail_push(list, sched) == NULL))
	{
	  if(sched != NULL)
	    scamper_owamp_sched_free(sched);
	  goto done;
	}

      in = next;
    }
  while(in != NULL);
  rc = 0;

 done:
  if(dup != NULL) free(dup);
  return rc;
}

static int owamp_arg_param_validate(int optid, char *param, long long *out,
				    char *errbuf, size_t errlen)
{
  struct timeval tv;
  long long tmp = 0;

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  switch(optid)
    {
    case OWAMP_OPT_COUNT:
    case OWAMP_OPT_DSCP:
    case OWAMP_OPT_SIZE:
    case OWAMP_OPT_USERID:
    case OWAMP_OPT_TTL:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < limits[optid].min || tmp > limits[optid].max)
	{
	  snprintf(errbuf, errlen, "%s must be within %lld - %lld",
		   limits[optid].name, limits[optid].min, limits[optid].max);
	  goto err;
	}
      break;

    case OWAMP_OPT_DIR:
      if(strcasecmp(param, "tx") == 0)
	tmp = SCAMPER_OWAMP_DIR_TX;
      else if(strcasecmp(param, "rx") == 0)
	tmp = SCAMPER_OWAMP_DIR_RX;
      else
	{
	  snprintf(errbuf, errlen, "invalid direction");
	  goto err;
	}
      break;

    case OWAMP_OPT_OPTION:
      if(strcasecmp(param, "zero") == 0)
	tmp = SCAMPER_OWAMP_FLAG_ZERO;
      else
	{
	  snprintf(errbuf, errlen, "invalid option");
	  goto err;
	}
      break;

    case OWAMP_OPT_SCHED:
      if(sched_parse(NULL, param) != 0)
	{
	  snprintf(errbuf, errlen, "invalid schedule");
	  goto err;
	}
      break;

    case OWAMP_OPT_WAIT_TIMEOUT:
      if(timeval_fromstr(&tv, param, 1000000) != 0 || tv.tv_usec != 0 ||
	 timeval_cmp_lt(&tv, 1, 0) || timeval_cmp_gt(&tv, 20, 0))
	{
	  snprintf(errbuf, errlen, "wait-timeout must be within 1s - 20s");
	  goto err;
	}
      tmp = tv.tv_sec * 1000000;
      break;

    case OWAMP_OPT_STARTAT:
      if(timeval_fromstr(&tv, param, 1000000) != 0)
	{
	  snprintf(errbuf, errlen, "invalid startat time");
	  goto err;
	}
      tmp = ((long long)tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    default:
      goto err;
    }

  /* valid parameter */
  if(out != NULL)
    *out = tmp;
  return 0;

 err:
  assert(errbuf[0] != '\0');
  return -1;
}
  
int scamper_do_owamp_arg_validate(int argc, char *argv[], int *stop,
				  char *errbuf, size_t errlen)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  errbuf, errlen, owamp_arg_param_validate);
}

void *scamper_do_owamp_alloc(char *str, char *errbuf, size_t errlen)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_owamp_t *owamp = NULL;
  scamper_owamp_sched_t *sched;
  slist_t *sched_list = NULL;
  long long tmp = 0;
  struct timeval wait_timeout, startat, now, tv;
  uint16_t dport = 861;
  uint32_t userid = 0;
  uint8_t dir = SCAMPER_OWAMP_DIR_TX;
  uint8_t dscp = 0;
  uint8_t ttl = 255;
  uint32_t attempts = 10;
  uint16_t pktsize = 0;
  uint16_t flags = 0;
  char *addr = NULL;
  char buf[256];
  size_t len;

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  /* Parse the options */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      snprintf(errbuf, errlen, "could not parse owamp command");
      goto err;
    }

  /* If there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      snprintf(errbuf, errlen, "expected address to connect to");
      goto err;
    }

  wait_timeout.tv_sec = 2;
  wait_timeout.tv_usec = 0;
  startat.tv_sec = 0;
  startat.tv_usec = 0;

  /* Parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 owamp_arg_param_validate(opt->id, opt->str, &tmp,
				  buf, sizeof(buf)) != 0)
	{
	  snprintf(errbuf, errlen, "-%c failed: %s",
		   scamper_options_id2c(opts, opts_cnt, opt->id), buf);
	  goto err;
	}

      switch(opt->id)
	{
	case OWAMP_OPT_COUNT:
	  attempts = (uint32_t)tmp;
	  break;

	case OWAMP_OPT_DIR:
	  dir = (uint8_t)tmp;
	  break;

	case OWAMP_OPT_DSCP:
	  dscp = (uint8_t)tmp;
	  break;

	case OWAMP_OPT_SCHED:
	  if(sched_list != NULL)
	    {
	      snprintf(errbuf, errlen, "duplicate schedules");
	      goto err;
	    }
	  if((sched_list = slist_alloc()) == NULL ||
	     sched_parse(sched_list, opt->str) != 0)
	    {
	      snprintf(errbuf, errlen, "could not parse schedule");
	      goto err;
	    }
	  break;

	case OWAMP_OPT_TTL:
	  ttl = (uint8_t)tmp;
	  break;

	case OWAMP_OPT_OPTION:
	  if(tmp != 0)
	    {
	      flags |= (uint16_t)tmp;
	    }
	  else
	    {
	      snprintf(errbuf, errlen, "uncaught option");
	      goto err;
	    }
	  break;

	case OWAMP_OPT_SIZE:
	  pktsize = (uint16_t)tmp;
	  break;

	case OWAMP_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case OWAMP_OPT_WAIT_TIMEOUT:
	  wait_timeout.tv_sec = tmp / 1000000;
	  wait_timeout.tv_usec = tmp % 1000000;
	  break;

	case OWAMP_OPT_STARTAT:
	  startat.tv_sec = tmp / 1000000;
	  startat.tv_usec = tmp % 1000000;
	  break;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if((owamp = scamper_owamp_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc owamp");
      goto err;
    }

  if((owamp->dst = scamper_addrcache_resolve_unspec(addrcache,addr)) == NULL ||
     SCAMPER_ADDR_TYPE_IS_IP(owamp->dst) == 0)
    {
      snprintf(errbuf, errlen, "invalid destination address");
      goto err;
    }

  if(pktsize == 0)
    {
      if(SCAMPER_ADDR_TYPE_IS_IPV4(owamp->dst))
	pktsize = 20 + 8 + 14;
      else
	pktsize = 40 + 8 + 14;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV4(owamp->dst))
    {
      if(pktsize < 20 + 8 + 14)
	{
	  snprintf(errbuf, errlen, "ipv4 packet size too small");
	  goto err;
	}
    }
  else
    {
      if(pktsize < 40 + 8 + 14)
	{
	  snprintf(errbuf, errlen, "ipv6 packet size too small");
	  goto err;
	}
    }

  if(timeval_iszero(&startat) == 0)
    {
      /*
       * if the startat time has passed, reject the command outright
       * if it passed more than a second ago.  otherwise, reject the
       * command if the startat time is more than 10 seconds away.
       */
      gettimeofday_wrap(&now);
      if(timeval_cmp(&startat, &now) < 0)
	{
	  timeval_diff_tv(&tv, &startat, &now);
	  if(timeval_cmp_lt(&tv, 1, 0) == 0)
	    {
	      snprintf(errbuf, errlen, "startat passed > 1 second ago");
	      goto err;
	    }
	}
      else
	{
	  timeval_diff_tv(&tv, &now, &startat);
	  if(timeval_cmp_lt(&tv, 10, 0) == 0)
	    {
	      snprintf(errbuf, errlen, "startat > 10 seconds away");
	      goto err;
	    }
	}
    }

  owamp->attempts = attempts;
  owamp->dir = dir;
  owamp->dscp = dscp;
  owamp->ttl = ttl;
  owamp->pktsize = pktsize;
  owamp->userid = userid;
  owamp->dport = dport;
  owamp->flags = flags;
  timeval_cpy(&owamp->wait_timeout, &wait_timeout);
  timeval_cpy(&owamp->startat, &startat);

  if(sched_list != NULL)
    {
      assert(slist_count(sched_list) > 0);
      if(scamper_owamp_scheds_alloc(owamp,
				    (uint32_t)slist_count(sched_list)) != 0)
	{
	  snprintf(errbuf, errlen, "could not alloc sched");
	  goto err;
	}
      while((sched = slist_head_pop(sched_list)) != NULL)
	owamp->sched[owamp->schedc++] = sched;
      slist_free(sched_list); sched_list = NULL;
    }
  else
    {
      len = sizeof(scamper_owamp_sched_t *) * 1;
      if((owamp->sched = malloc_zero(len)) == NULL ||
	 (sched = scamper_owamp_sched_alloc()) == NULL)
	{
	  snprintf(errbuf, errlen, "could not alloc sched");
	  goto err;
	}
      sched->tv.tv_sec = 0;
      sched->tv.tv_usec = 100000;
      sched->type = SCAMPER_OWAMP_SCHED_TYPE_FIXED;
      owamp->sched[owamp->schedc++] = sched;
    }

  timeval_cpy(&owamp->wait_timeout, &wait_timeout);

  return owamp;

 err:
  assert(errbuf[0] != '\0');
  if(sched_list != NULL)
    slist_free_cb(sched_list, (slist_free_t)scamper_owamp_sched_free);
  if(owamp != NULL) scamper_owamp_free(owamp);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}
