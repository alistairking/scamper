/*
 * scamper_sting_cmd.c
 *
 * $Id: scamper_sting_cmd.c,v 1.7 2024/05/02 02:33:38 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
 * Copyright (C) 2022-2023 Matthew Luckie
 * Copyright (C) 2024      The Regents of the University of California
 * Author: Matthew Luckie
 *
 * This file implements algorithms described in the sting-0.7 source code,
 * as well as the paper:
 *
 *  Sting: a TCP-based Network Measurement Tool
 *  by Stefan Savage
 *  1999 USENIX Symposium on Internet Technologies and Systems
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
#include "scamper_sting.h"
#include "scamper_sting_int.h"
#include "scamper_sting_cmd.h"
#include "scamper_options.h"
#include "utils.h"

/*
 * how many packets to send in data phase:
 *   freebsd net.inet.tcp.reass.maxqlen = 48
 *   note that this value is different to the hard-coded sting-0.7 default
 *   of 100.
 */
#define SCAMPER_DO_STING_COUNT_DEF 48

/*
 * mean rate at which to send packets in data phase:
 *   100ms is the hard-coded number in sting-0.7
 */
#define SCAMPER_DO_STING_MEAN_DEF  100

/*
 * inter-phase delay between data seeding and hole filling.
 *   2000ms is the hard-coded number in sting-0.7
 */
#define SCAMPER_DO_STING_INTER_DEF  2000

/*
 * distribution to apply when determining when to send the next packet
 *  3 corresponds to uniform distribution
 */
#define SCAMPER_DO_STING_DIST_DEF  3

/*
 * how many times to retransmit a syn packet before deciding the host is down
 *  3 is the hard-coded number in sting-0.7
 */
#define SCAMPER_DO_STING_SYNRETX_DEF 3

/*
 * number of times to retransmit data packets
 *  5 is the default number in sting-0.7
 */
#define SCAMPER_DO_STING_DATARETX_DEF 5

/*
 * size of the first hole in the sequence number space
 *  3 is the default number in sting-0.7
 */
#define SCAMPER_DO_STING_SEQSKIP_DEF 3

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

#define STING_OPT_COUNT  1
#define STING_OPT_DPORT  2
#define STING_OPT_DIST   3
#define STING_OPT_REQ    4
#define STING_OPT_HOLE   5
#define STING_OPT_INTER  6
#define STING_OPT_MEAN   7
#define STING_OPT_SPORT  8
#define STING_OPT_USERID 9

static const scamper_option_in_t opts[] = {
  {'c', NULL, STING_OPT_COUNT,  SCAMPER_OPTION_TYPE_NUM},
  {'d', NULL, STING_OPT_DPORT,  SCAMPER_OPTION_TYPE_NUM},
  {'f', NULL, STING_OPT_DIST,   SCAMPER_OPTION_TYPE_STR},
  {'h', NULL, STING_OPT_REQ,    SCAMPER_OPTION_TYPE_STR},
  {'H', NULL, STING_OPT_HOLE,   SCAMPER_OPTION_TYPE_NUM},
  {'i', NULL, STING_OPT_INTER,  SCAMPER_OPTION_TYPE_STR},
  {'m', NULL, STING_OPT_MEAN,   SCAMPER_OPTION_TYPE_STR},
  {'s', NULL, STING_OPT_SPORT,  SCAMPER_OPTION_TYPE_NUM},
  {'U', NULL, STING_OPT_USERID, SCAMPER_OPTION_TYPE_NUM},
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
  {"count", 2, 65535},
  {"dport", 1, 65535},
  {"dist", 1, 3},
  {NULL, 0, 0}, /* -h req */
  {"hole", 1, 255},
  {"inter-phase-delay", 1, 10000},
  {"mean", 1, 1000},
  {"sport", 1, 65535},
  {"userid", 0, UINT32_MAX},
};

/*
 * this is the default request used when none is specified.  it is the same
 * default request found in sting-0.7, except it uses <CR><LF> not
 * just <LF> as per the HTTP specification.
 */
static const char *defaultrequest =
  "GET / HTTP/1.0\r\n"
  "Accept: text/plain\r\n"
  "Accept: */*\r\n"
  "User-Agent: Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; Sting)\r\n"
  "\r\n";

const char *scamper_do_sting_usage(void)
{
  return "sting [-c count] [-d dport] [-f distribution] [-h request]\n"
         "      [-H hole] [-i inter] [-m mean] [-s sport] [-U userid]";
}

static int sting_arg_param_validate(int optid, char *param, long long *out,
				    char *errbuf, size_t errlen)
{
  struct timeval tv;
  long long tmp = 0;

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  switch(optid)
    {
    case STING_OPT_COUNT:
    case STING_OPT_SPORT:
    case STING_OPT_DPORT:
    case STING_OPT_DIST:
    case STING_OPT_HOLE:
    case STING_OPT_USERID:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < limits[optid].min || tmp > limits[optid].max)
	{
	  snprintf(errbuf, errlen, "%s must be within %lld - %lld",
		   limits[optid].name, limits[optid].min, limits[optid].max);
	  goto err;
	}
      break;

    case STING_OPT_REQ:
      snprintf(errbuf, errlen, "request not implemented");
      goto err;

    case STING_OPT_MEAN:
      if(timeval_fromstr(&tv, param, 1000) != 0)
	{
	  snprintf(errbuf, errlen, "malformed mean delay");
	  goto err;
	}
      if((tv.tv_usec % 1000) != 0)
	{
	  snprintf(errbuf, errlen, "mean delay granularity limited to 1ms");
	  goto err;
	}
      if(timeval_cmp_lt(&tv, 0, 1000) || timeval_cmp_gt(&tv, 1, 0))
	{
	  snprintf(errbuf, errlen, "mean delay must be within 1ms - 1s");
	  goto err;
	}
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    case STING_OPT_INTER:
      if(timeval_fromstr(&tv, param, 1000) != 0)
	{
	  snprintf(errbuf, errlen, "malformed inter-phase delay");
	  goto err;
	}
      if((tv.tv_usec % 1000) != 0)
	{
	  snprintf(errbuf, errlen, "inter-phase delay granularity limited to 1ms");
	  goto err;
	}
      if(timeval_cmp_lt(&tv, 0, 1000) || timeval_cmp_gt(&tv, 10, 0))
	{
	  snprintf(errbuf, errlen, "inter-phase delay must be within 1ms - 10s");
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

/*
 * scamper_do_sting_alloc
 *
 * given a string representing a sting task, parse the parameters and
 * assemble a sting.  return the sting structure so that it is all ready to
 * go.
 */
void *scamper_do_sting_alloc(char *str, char *errbuf, size_t errlen)
{
  uint16_t sport    = scamper_sport_default();
  uint16_t dport    = 80;
  uint16_t count    = SCAMPER_DO_STING_COUNT_DEF;
  uint8_t  seqskip  = SCAMPER_DO_STING_SEQSKIP_DEF;
  uint8_t  dist     = SCAMPER_DO_STING_DIST_DEF;
  uint8_t  synretx  = SCAMPER_DO_STING_SYNRETX_DEF;
  uint8_t  dataretx = SCAMPER_DO_STING_DATARETX_DEF;
  uint32_t userid   = 0;
  struct timeval mean, inter;
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_sting_t *sting = NULL;
  char *addr;
  long long tmp = 0;
  char buf[256];

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  mean.tv_sec = 0;
  mean.tv_usec = 100000;
  inter.tv_sec = 2;
  inter.tv_usec = 0;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      snprintf(errbuf, errlen, "could not parse sting command");
      goto err;
    }

  /* if there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      snprintf(errbuf, errlen, "expected address to sting");
      goto err;
    }

  /* parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 sting_arg_param_validate(opt->id, opt->str, &tmp,
				  buf, sizeof(buf)) != 0)
	{
	  snprintf(errbuf, errlen, "-%c failed: %s",
		   scamper_options_id2c(opts, opts_cnt, opt->id), buf);
	  goto err;
	}

      switch(opt->id)
	{
	case STING_OPT_DPORT:
	  dport = (uint16_t)tmp;
	  break;

	case STING_OPT_SPORT:
	  sport = (uint16_t)tmp;
	  break;

	case STING_OPT_COUNT:
	  count = (uint16_t)tmp;
	  break;

	case STING_OPT_MEAN:
	  mean.tv_sec = tmp / 1000000;
	  mean.tv_usec = tmp % 1000000;
	  break;

	case STING_OPT_DIST:
	  dist = (uint8_t)tmp;
	  break;

	case STING_OPT_HOLE:
	  seqskip = (uint8_t)tmp;
	  break;

	case STING_OPT_INTER:
	  inter.tv_sec = tmp / 1000000;
	  inter.tv_usec = tmp % 1000000;
	  break;

	case STING_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	default:
	  goto err;
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if((sting = scamper_sting_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc sting");
      goto err;
    }
  if((sting->dst=scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr)) == NULL)
    {
      snprintf(errbuf, errlen, "invalid destination address");
      goto err;
    }

  sting->sport    = sport;
  sting->dport    = dport;
  sting->count    = count;
  sting->dist     = dist;
  sting->synretx  = synretx;
  sting->dataretx = dataretx;
  sting->seqskip  = seqskip;
  sting->userid   = userid;
  timeval_cpy(&sting->mean, &mean);
  timeval_cpy(&sting->inter, &inter);

  /* take a copy of the data to be used in the measurement */
  if(scamper_sting_data_set(sting, (const uint8_t *)defaultrequest,
			    seqskip + count) != 0)
    {
      snprintf(errbuf, errlen, "could not set default request");
      goto err;
    }

  assert(errbuf[0] == '\0');
  return sting;

 err:
  assert(errbuf[0] != '\0');
  if(sting != NULL) scamper_sting_free(sting);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

/*
 * scamper_do_sting_arg_validate
 *
 *
 */
int scamper_do_sting_arg_validate(int argc, char *argv[], int *stop,
				  char *errbuf, size_t errlen)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  errbuf, errlen, sting_arg_param_validate);
}
