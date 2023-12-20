/*
 * scamper_sting_cmd.c
 *
 * $Id: scamper_sting_cmd.c,v 1.4 2023/12/30 19:11:52 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
 * Copyright (C) 2022-2023 Matthew Luckie
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
#include "scamper_options.h"
#include "scamper_debug.h"
#include "utils.h"

/*
 * how many packets to send in data phase:
 *   freebsd net.inet.tcp.reass.maxqlen = 48
 *   note that this value is different to the hard-coded sting-0.7 default
 *   of 100.
 */
#define SCAMPER_DO_STING_COUNT_MIN 2
#define SCAMPER_DO_STING_COUNT_DEF 48
#define SCAMPER_DO_STING_COUNT_MAX 65535

/*
 * mean rate at which to send packets in data phase:
 *   100ms is the hard-coded number in sting-0.7
 */
#define SCAMPER_DO_STING_MEAN_MIN  1
#define SCAMPER_DO_STING_MEAN_DEF  100
#define SCAMPER_DO_STING_MEAN_MAX  1000

/*
 * inter-phase delay between data seeding and hole filling.
 *   2000ms is the hard-coded number in sting-0.7
 */
#define SCAMPER_DO_STING_INTER_MIN  1
#define SCAMPER_DO_STING_INTER_DEF  2000
#define SCAMPER_DO_STING_INTER_MAX  10000

/*
 * distribution to apply when determining when to send the next packet
 *  3 corresponds to uniform distribution
 */
#define SCAMPER_DO_STING_DIST_MIN  1
#define SCAMPER_DO_STING_DIST_DEF  3
#define SCAMPER_DO_STING_DIST_MAX  3

/*
 * how many times to retransmit a syn packet before deciding the host is down
 *  3 is the hard-coded number in sting-0.7
 */
#define SCAMPER_DO_STING_SYNRETX_MIN 0
#define SCAMPER_DO_STING_SYNRETX_DEF 3
#define SCAMPER_DO_STING_SYNRETX_MAX 5

/*
 * number of times to retransmit data packets
 *  5 is the default number in sting-0.7
 */
#define SCAMPER_DO_STING_DATARETX_MIN 0
#define SCAMPER_DO_STING_DATARETX_DEF 5
#define SCAMPER_DO_STING_DATARETX_MAX 10

/*
 * size of the first hole in the sequence number space
 *  3 is the default number in sting-0.7
 */
#define SCAMPER_DO_STING_SEQSKIP_MIN 1
#define SCAMPER_DO_STING_SEQSKIP_DEF 3
#define SCAMPER_DO_STING_SEQSKIP_MAX 255

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

static int sting_arg_param_validate(int optid, char *param, long long *out)
{
  struct timeval tv;
  long tmp;

  switch(optid)
    {
    case STING_OPT_COUNT:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_STING_COUNT_MIN ||
	 tmp > SCAMPER_DO_STING_COUNT_MAX)
	{
	  goto err;
	}
      break;

    case STING_OPT_SPORT:
    case STING_OPT_DPORT:
      if(string_tolong(param, &tmp) != 0 || tmp < 0 || tmp > 65535)
	goto err;
      break;

    case STING_OPT_DIST:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_STING_DIST_MIN ||
	 tmp > SCAMPER_DO_STING_DIST_MAX)
	goto err;
      break;

    case STING_OPT_REQ:
      return -1;

    case STING_OPT_MEAN:
      if(timeval_fromstr(&tv, param, 1000) != 0 || (tv.tv_usec % 1000) != 0 ||
	 timeval_cmp_lt(&tv, 0, 1000) || timeval_cmp_gt(&tv, 1, 0))
	goto err;
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    case STING_OPT_HOLE:
      if(string_tolong(param, &tmp) != 0 ||
	 tmp < SCAMPER_DO_STING_SEQSKIP_MIN ||
	 tmp > SCAMPER_DO_STING_SEQSKIP_MAX)
	goto err;
      break;

    case STING_OPT_INTER:
      if(timeval_fromstr(&tv, param, 1000) != 0 || (tv.tv_usec % 1000) != 0 ||
	 timeval_cmp_lt(&tv, 0, 1000) || timeval_cmp_gt(&tv, 10, 0))
	goto err;
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    case STING_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	goto err;
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
 * scamper_do_sting_alloc
 *
 * given a string representing a sting task, parse the parameters and
 * assemble a sting.  return the sting structure so that it is all ready to
 * go.
 */
void *scamper_do_sting_alloc(char *str, uint32_t *id)
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

  mean.tv_sec = 0;
  mean.tv_usec = 100000;
  inter.tv_sec = 2;
  inter.tv_usec = 0;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      scamper_debug(__func__, "could not parse options");
      goto err;
    }

  /* if there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      scamper_debug(__func__, "no address parameter");
      goto err;
    }

  /* parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 sting_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
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
	}
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if((sting = scamper_sting_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc sting");
      goto err;
    }
  if((sting->dst=scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr)) == NULL)
    {
      printerror(__func__, "could not resolve %s", addr);
      goto err;
    }

  sting->sport    = sport;
  sting->dport    = dport;
  sting->count    = count;
  sting->dist     = dist;
  sting->synretx  = synretx;
  sting->dataretx = dataretx;
  sting->seqskip  = seqskip;
  sting->userid   = *id = userid;
  timeval_cpy(&sting->mean, &mean);
  timeval_cpy(&sting->inter, &inter);

  /* take a copy of the data to be used in the measurement */
  if(scamper_sting_data_set(sting, (const uint8_t *)defaultrequest,
			    seqskip + count) != 0)
    {
      goto err;
    }

  return sting;

 err:
  if(sting != NULL) scamper_sting_free(sting);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}

/*
 * scamper_do_sting_arg_validate
 *
 *
 */
int scamper_do_sting_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  sting_arg_param_validate);
}
