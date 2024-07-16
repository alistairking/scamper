/*
 * scamper_tbit_cmd.c
 *
 * $Id: scamper_tbit_cmd.c,v 1.7 2024/05/02 02:33:38 mjl Exp $
 *
 * Copyright (C) 2009-2010 Ben Stasiewicz
 * Copyright (C) 2009-2010 Stephen Eichler
 * Copyright (C) 2010-2011 University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2017      University of Waikato
 * Copyright (C) 2022-2023 Matthew Luckie
 * Copyright (C) 2024      The Regents of the University of California
 *
 * Authors: Matthew Luckie, Ben Stasiewicz, Stephen Eichler, Tiange Wu,
 *          Robert Beverly
 *
 * Some of the algorithms implemented in this file are described in the
 * tbit-1.0 source code, as well as the papers:
 *
 *  "On Inferring TCP Behaviour"
 *      by Jitendra Padhye and Sally Floyd
 *  "Measuring the Evolution of Transport Protocols in the Internet" by
 *      by Alberto Medina, Mark Allman, and Sally Floyd.
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
#include "scamper_tbit.h"
#include "scamper_options.h"
#include "scamper_tbit_int.h"
#include "scamper_tbit_cmd.h"
#include "utils.h"

typedef struct tbit_options
{
  uint8_t   app;
  uint8_t   type;
  uint8_t   attempts;
  uint8_t   fo_cookielen;
  uint8_t   fo_cookie[16];
  uint16_t  options;
  uint16_t  mss;
  uint16_t  mtu;
  uint16_t  sport;
  uint16_t  dport;
  char     *url;
  char     *ptbsrc;
  char     *src;
  int32_t   offset;
  uint16_t  asn;
} tbit_options_t;

/* Address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

/* Options that tbit supports */
#define TBIT_OPT_DPORT       1
#define TBIT_OPT_MSS         2
#define TBIT_OPT_MTU         3
#define TBIT_OPT_OPTION      4
#define TBIT_OPT_APP         5
#define TBIT_OPT_PTBSRC      6
#define TBIT_OPT_SPORT       7
#define TBIT_OPT_TYPE        8
#define TBIT_OPT_URL         9
#define TBIT_OPT_USERID      10
#define TBIT_OPT_SRCADDR     11
#define TBIT_OPT_FO          12
#define TBIT_OPT_WSCALE      13
#define TBIT_OPT_ATTEMPTS    14
#define TBIT_OPT_OFFSET      15
#define TBIT_OPT_ASN         16
#define TBIT_OPT_TTL         17

typedef struct opt_limit
{
  char      *name;
  long long  min;
  long long  max;
} opt_limit_t;

static const opt_limit_t limits[] = {
  {NULL, 0, 0}, /* zero unused */
  {"dport", 1, 65535},
  {"mss", 0, 65535},
  {"mtu", 0, 65535},
  {NULL, 0, 0}, /* -O option */
  {NULL, 0, 0}, /* -p application */
  {NULL, 0, 0}, /* -P ptb-src */
  {"sport", 1, 65535},
  {NULL, 0, 0}, /* -t type */
  {NULL, 0, 0}, /* -u URL */
  {"userid", 0, UINT32_MAX},
  {NULL, 0, 0}, /* -S src-addr */
  {NULL, 0, 0}, /* fo-cookie */
  {"wscale", 0, 14},
  {"attempts", 1, 4},
  {"offset", -2147483647, 2147483647},
  {"asn", 0, 65535},
  {"ttl", 1, 255},
};

/* bits for the tbit_option.options field */
#define TBIT_OPT_OPTION_BLACKHOLE  0x0001
#define TBIT_OPT_OPTION_TCPTS      0x0002
#define TBIT_OPT_OPTION_IPTS_SYN   0x0004
#define TBIT_OPT_OPTION_IPRR_SYN   0x0008
#define TBIT_OPT_OPTION_IPQS_SYN   0x0010
#define TBIT_OPT_OPTION_SACK       0x0020
#define TBIT_OPT_OPTION_FO         0x0040
#define TBIT_OPT_OPTION_FO_EXP     0x0080

/* we only support one IP option on a SYN packet */
#define TBIT_OPT_OPTION_IPOPT_SYN_MASK \
 (TBIT_OPT_OPTION_IPTS_SYN | TBIT_OPT_OPTION_IPRR_SYN | \
  TBIT_OPT_OPTION_IPQS_SYN)

/* types of tbit probe packets */
#define TBIT_PROBE_TYPE_TCP 1
#define TBIT_PROBE_TYPE_PTB 2

static const scamper_option_in_t opts[] = {
  {'b', NULL, TBIT_OPT_ASN,      SCAMPER_OPTION_TYPE_NUM},
  {'d', NULL, TBIT_OPT_DPORT,    SCAMPER_OPTION_TYPE_NUM},
  {'f', NULL, TBIT_OPT_FO,       SCAMPER_OPTION_TYPE_STR},
  {'m', NULL, TBIT_OPT_MSS,      SCAMPER_OPTION_TYPE_NUM},
  {'M', NULL, TBIT_OPT_MTU,      SCAMPER_OPTION_TYPE_NUM},
  {'o', NULL, TBIT_OPT_OFFSET,   SCAMPER_OPTION_TYPE_NUM},
  {'O', NULL, TBIT_OPT_OPTION,   SCAMPER_OPTION_TYPE_STR},
  {'p', NULL, TBIT_OPT_APP,      SCAMPER_OPTION_TYPE_STR},
  {'P', NULL, TBIT_OPT_PTBSRC,   SCAMPER_OPTION_TYPE_STR},
  {'q', NULL, TBIT_OPT_ATTEMPTS, SCAMPER_OPTION_TYPE_NUM},
  {'s', NULL, TBIT_OPT_SPORT,    SCAMPER_OPTION_TYPE_NUM},
  {'S', NULL, TBIT_OPT_SRCADDR,  SCAMPER_OPTION_TYPE_STR},
  {'t', NULL, TBIT_OPT_TYPE,     SCAMPER_OPTION_TYPE_STR},
  {'T', NULL, TBIT_OPT_TTL,      SCAMPER_OPTION_TYPE_NUM},
  {'u', NULL, TBIT_OPT_URL,      SCAMPER_OPTION_TYPE_STR},
  {'U', NULL, TBIT_OPT_USERID,   SCAMPER_OPTION_TYPE_NUM},
  {'w', NULL, TBIT_OPT_WSCALE,   SCAMPER_OPTION_TYPE_NUM},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

/* Note : URL is only valid for HTTP tests. */
const char *scamper_do_tbit_usage(void)
{
  return
    "tbit [-t type] [-p app] [-d dport] [-s sport] [-b asn] [-f cookie]\n"
    "     [-m mss] [-M mtu] [-o offset] [-O option] [-U userid]\n"
    "     [-P ptbsrc] [-q attempts] [-S srcaddr] [-T ttl] [-u url]";
}

static int tbit_arg_param_validate(int optid, char *param, long long *out,
				   char *errbuf, size_t errlen)
{
  long long tmp = 0;
  int i;

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  switch(optid)
    {
    case TBIT_OPT_TYPE:
      if(strcasecmp(param, "pmtud") == 0)
	tmp = SCAMPER_TBIT_TYPE_PMTUD;
      else if(strcasecmp(param, "ecn") == 0)
	tmp = SCAMPER_TBIT_TYPE_ECN;
      else if(strcasecmp(param, "null") == 0)
	tmp = SCAMPER_TBIT_TYPE_NULL;
      else if(strcasecmp(param, "sack-rcvr") == 0)
	tmp = SCAMPER_TBIT_TYPE_SACK_RCVR;
      else if(strcasecmp(param, "icw") == 0)
	tmp = SCAMPER_TBIT_TYPE_ICW;
      else if(strcasecmp(param, "blind-data") == 0)
	tmp = SCAMPER_TBIT_TYPE_BLIND_DATA;
      else if(strcasecmp(param, "blind-rst") == 0)
	tmp = SCAMPER_TBIT_TYPE_BLIND_RST;
      else if(strcasecmp(param, "blind-syn") == 0)
	tmp = SCAMPER_TBIT_TYPE_BLIND_SYN;
      else if(strcasecmp(param, "blind-fin") == 0)
	tmp = SCAMPER_TBIT_TYPE_BLIND_FIN;
      else
	{
	  snprintf(errbuf, errlen, "unknown tbit type");
	  goto err;
	}
      break;

    case TBIT_OPT_APP:
      if(strcasecmp(param, "http") == 0)
	tmp = SCAMPER_TBIT_APP_HTTP;
      else if(strcasecmp(param, "bgp") == 0)
	tmp = SCAMPER_TBIT_APP_BGP;
      else
	{
	  snprintf(errbuf, errlen, "unknown tbit application");
	  goto err;
	}
      break;

    case TBIT_OPT_SPORT:
    case TBIT_OPT_DPORT:
    case TBIT_OPT_MSS:
    case TBIT_OPT_MTU:
    case TBIT_OPT_ASN:
    case TBIT_OPT_USERID:
    case TBIT_OPT_WSCALE:
    case TBIT_OPT_ATTEMPTS:
    case TBIT_OPT_OFFSET:
    case TBIT_OPT_TTL:
      if(string_tollong(param, &tmp, NULL, 0) != 0 ||
	 tmp < limits[optid].min || tmp > limits[optid].max)
	{
	  snprintf(errbuf, errlen, "%s must be within %lld - %lld",
		   limits[optid].name, limits[optid].min, limits[optid].max);
	  goto err;
	}
      break;

    case TBIT_OPT_FO:
      if((i = string_ishex(param)) == 0)
	{
	  snprintf(errbuf, errlen, "fo-cookie must be specified in hex");
	  goto err;
	}
      if((i % (4*2)) != 0)
	{
	  snprintf(errbuf, errlen, "fo-cookie must be a multiple of 4 bytes");
	  goto err;
	}
      if(i < (4*2) || i > (16*2))
	{
	  snprintf(errbuf, errlen, "fo-cookie must be 4 - 16 bytes");
	  goto err;
	}
      tmp = i;
      break;

    case TBIT_OPT_OPTION:
      if(strcasecmp(param, "blackhole") == 0)
	tmp = TBIT_OPT_OPTION_BLACKHOLE;
      else if(strcasecmp(param, "tcpts") == 0)
	tmp = TBIT_OPT_OPTION_TCPTS;
      else if(strcasecmp(param, "ipts-syn") == 0)
	tmp = TBIT_OPT_OPTION_IPTS_SYN;
      else if(strcasecmp(param, "iprr-syn") == 0)
	tmp = TBIT_OPT_OPTION_IPRR_SYN;
      else if(strcasecmp(param, "ipqs-syn") == 0)
	tmp = TBIT_OPT_OPTION_IPQS_SYN;
      else if(strcasecmp(param, "sack") == 0)
	tmp = TBIT_OPT_OPTION_SACK;
      else if(strcasecmp(param, "fo") == 0)
	tmp = TBIT_OPT_OPTION_FO;
      else if(strcasecmp(param, "fo-exp") == 0)
	tmp = TBIT_OPT_OPTION_FO_EXP;
      else
	{
	  snprintf(errbuf, errlen, "unknown option");
	  goto err;
	}
      break;

    case TBIT_OPT_PTBSRC:
    case TBIT_OPT_URL:
    case TBIT_OPT_SRCADDR:
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

int scamper_do_tbit_arg_validate(int argc, char *argv[], int *stop,
				 char *errbuf, size_t errlen)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  errbuf, errlen, tbit_arg_param_validate);
}

static int tbit_app_smtp(scamper_tbit_t *tbit, tbit_options_t *o,
			 char *errbuf, size_t errlen)
{
  if(tbit->dport == 0)
    tbit->dport = 25;
  return 0;
}

static int tbit_app_dns(scamper_tbit_t *tbit, tbit_options_t *o,
			char *errbuf, size_t errlen)
{
  if(tbit->dport == 0)
    tbit->dport = 53;
  return 0;
}

static int tbit_app_ftp(scamper_tbit_t *tbit, tbit_options_t *o,
			char *errbuf, size_t errlen)
{
  if(tbit->dport == 0)
    tbit->dport = 21;
  return 0;
}

static int tbit_app_bgp(scamper_tbit_t *tbit, tbit_options_t *o,
			char *errbuf, size_t errlen)
{
  scamper_tbit_app_bgp_t *bgp;
  if((bgp = scamper_tbit_app_bgp_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc bgp");
      return -1;
    }
  if(o->asn == 0)
    bgp->asn = 1;
  else
    bgp->asn = o->asn;
  tbit->app_data = bgp;
  if(tbit->dport == 0)
    tbit->dport = 179;
  return 0;
}

static int tbit_app_http(scamper_tbit_t *tbit, tbit_options_t *o,
			 char *errbuf, size_t errlen)
{
  uint8_t type = SCAMPER_TBIT_APP_HTTP_TYPE_HTTP;
  char *file = NULL, *host = NULL, *scheme = NULL;
  uint16_t dport = 0;
  int rc = -1;

  /* parse a URL if provided */
  if(o->url != NULL)
    {
      if(url_parse(o->url, &dport, &scheme, &host, &file) != 0)
	{
	  snprintf(errbuf, errlen, "could not parse url");
	  goto done;
	}

      if(tbit->dport != 0 && dport != 0 && tbit->dport != dport)
	{
	  snprintf(errbuf, errlen, "dport specified inconsistently");
	  goto done;
	}

      if(strcasecmp(scheme, "https") == 0)
	{
#ifdef BUILDING_SCAMPER
#ifndef HAVE_OPENSSL
	  snprintf(errbuf, errlen, "scamper not built with openssl");
	  goto done;
#else
	  if(scamper_option_notls() != 0)
	    {
	      snprintf(errbuf, errlen, "scamper run with -O notls");
	      goto done;
	    }
#endif /* HAVE_OPENSSL */
#endif /* BUILDING_SCAMPER */
	  type = SCAMPER_TBIT_APP_HTTP_TYPE_HTTPS;
	}
    }

  if(tbit->dport == 0)
    {
      if(dport == 0)
	{
	  if(type == SCAMPER_TBIT_APP_HTTP_TYPE_HTTP)
	    dport = 80;
	  else
	    dport = 443;
	}
      tbit->dport = dport;
    }

  tbit->app_data = scamper_tbit_app_http_alloc(type, host,
					       file != NULL ? file : "/");
  if(tbit->app_data == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc http");
      goto done;
    }
  rc = 0;

 done:
  if(scheme != NULL) free(scheme);
  if(host != NULL) free(host);
  if(file != NULL) free(file);
  return rc;
}

static int tbit_alloc_pmtud(scamper_tbit_t *tbit, tbit_options_t *o,
			    char *errbuf, size_t errlen)
{
  scamper_tbit_pmtud_t *pmtud;
  int af;

  if((pmtud = scamper_tbit_pmtud_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc pmtud");
      return -1;
    }
  tbit->data = pmtud;

  if(o->mtu == 0)
    pmtud->mtu = 1280;
  else
    pmtud->mtu = o->mtu;

  if(o->ptbsrc != NULL)
    {
      af = scamper_addr_af(tbit->dst);
      assert(af == AF_INET || af == AF_INET6);
      pmtud->ptbsrc = scamper_addrcache_resolve(addrcache, af, o->ptbsrc);
      if(pmtud->ptbsrc == NULL)
	{
	  snprintf(errbuf, errlen, "invalid ptbsrc");
	  return -1;
	}
      assert(pmtud->ptbsrc->type == tbit->dst->type);
    }

  /* if we're in blackhole mode, we don't send PTB messages */
  if(o->options & TBIT_OPT_OPTION_BLACKHOLE)
    pmtud->options |= SCAMPER_TBIT_PMTUD_OPTION_BLACKHOLE;
  else if(o->attempts == 0)
    pmtud->ptb_retx = 4;
  else
    pmtud->ptb_retx = o->attempts;

  return 0;
}

static int tbit_alloc_icw(scamper_tbit_t *tbit, tbit_options_t *o,
			  char *errbuf, size_t errlen)
{
  if((tbit->data = scamper_tbit_icw_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc icw");
      return -1;
    }
  if(o->options & TBIT_OPT_OPTION_TCPTS)
    tbit->options |= SCAMPER_TBIT_OPTION_TCPTS;
  if(o->options & TBIT_OPT_OPTION_SACK)
    tbit->options |= SCAMPER_TBIT_OPTION_SACK;
  return 0;
}

static int tbit_alloc_blind(scamper_tbit_t *tbit, tbit_options_t *o,
			    char *errbuf, size_t errlen)
{
  scamper_tbit_blind_t *blind;

  if((blind = scamper_tbit_blind_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc blind");
      return -1;
    }
  tbit->data = blind;

  if(o->attempts == 0)
    blind->retx = 3;
  else
    blind->retx = o->attempts;

  if(o->offset == 0)
    {
      if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_SYN ||
	 tbit->type == SCAMPER_TBIT_TYPE_BLIND_RST)
	blind->off = 10;
      else if(tbit->type == SCAMPER_TBIT_TYPE_BLIND_DATA ||
	      tbit->type == SCAMPER_TBIT_TYPE_BLIND_FIN)
	blind->off = -70000;
      else
	{
	  snprintf(errbuf, errlen, "unhandled blind test type");
	  return -1;
	}
    }
  else
    blind->off = o->offset;

  return 0;
}

static int tbit_alloc_null(scamper_tbit_t *tbit, tbit_options_t *o,
			   char *errbuf, size_t errlen)
{
  scamper_tbit_null_t *null;
  uint16_t u;

  /* ensure that only one IP option is set on the SYN packet */
  u = (o->options & TBIT_OPT_OPTION_IPOPT_SYN_MASK);
  if(u != 0 && countbits32(u) != 1)
    {
      snprintf(errbuf, errlen, "more than one IP option provided");
      return -1;
    }

  if((null = scamper_tbit_null_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc null");
      return -1;
    }
  tbit->data = null;

  if(o->options & TBIT_OPT_OPTION_TCPTS)
    tbit->options |= SCAMPER_TBIT_OPTION_TCPTS;
  if(o->options & TBIT_OPT_OPTION_SACK)
    tbit->options |= SCAMPER_TBIT_OPTION_SACK;
  if(o->options & TBIT_OPT_OPTION_IPQS_SYN)
    null->options |= SCAMPER_TBIT_NULL_OPTION_IPQS_SYN;

  if(o->options & TBIT_OPT_OPTION_FO)
    null->options |= SCAMPER_TBIT_NULL_OPTION_FO;
  else if(o->options & TBIT_OPT_OPTION_FO_EXP)
    null->options |= SCAMPER_TBIT_NULL_OPTION_FO_EXP;

  if(o->fo_cookielen > 0)
    {
      if(scamper_tbit_client_fo_cookie_set(tbit,
					   o->fo_cookie, o->fo_cookielen) != 0)
	{
	  snprintf(errbuf, errlen, "could not set TCP fo-cookie");
	  return -1;
	}
      if((o->options & (TBIT_OPT_OPTION_FO|TBIT_OPT_OPTION_FO_EXP)) == 0)
	null->options = SCAMPER_TBIT_NULL_OPTION_FO;
    }

  if(o->options & (TBIT_OPT_OPTION_IPTS_SYN | TBIT_OPT_OPTION_IPRR_SYN))
    {
      if(SCAMPER_ADDR_TYPE_IS_IPV4(tbit->dst) == 0)
	{
	  snprintf(errbuf, errlen, "IP options only valid for IPv4 destination");
	  return -1;
	}

      if(o->options & TBIT_OPT_OPTION_IPTS_SYN)
	null->options |= SCAMPER_TBIT_NULL_OPTION_IPTS_SYN;
      if(o->options & TBIT_OPT_OPTION_IPRR_SYN)
	null->options |= SCAMPER_TBIT_NULL_OPTION_IPRR_SYN;
    }

  return 0;
}

/*
 * scamper_do_tbit_alloc
 *
 * Given a string representing a tbit task, parse the parameters and assemble
 * a tbit. Return the tbit structure so that it is all ready to go.
 */
void *scamper_do_tbit_alloc(char *str, char *errbuf, size_t errlen)
{
  static int (* const type_func[])(scamper_tbit_t *, tbit_options_t *,
				   char *, size_t) = {
    NULL,
    tbit_alloc_pmtud, /* pmtud */
    NULL,             /* ecn */
    tbit_alloc_null,  /* null */
    NULL,             /* sack-rcvr */
    tbit_alloc_icw,   /* icw */
    NULL,             /* abc */
    tbit_alloc_blind, /* blind-data */
    tbit_alloc_blind, /* blind-rst */
    tbit_alloc_blind, /* blind-syn */
    tbit_alloc_blind, /* blind-fin */
  };
  static int (* const app_func[])(scamper_tbit_t *, tbit_options_t *,
				  char *, size_t) = {
    NULL,
    tbit_app_http,
    tbit_app_smtp,
    tbit_app_dns,
    tbit_app_ftp,
    tbit_app_bgp,
  };
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_tbit_t *tbit = NULL;
  tbit_options_t o;
  uint8_t type = SCAMPER_TBIT_TYPE_NULL;
  uint8_t wscale = 0;
  uint8_t ttl = 255;
  uint32_t userid = 0;
  char *addr;
  long long i, tmp = 0;
  char buf[256];
  int af;

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  memset(&o, 0, sizeof(o));

  /* Parse the options */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &addr) != 0)
    {
      snprintf(errbuf, errlen, "could not parse tbit command");
      goto err;
    }

  /* If there is no IP address after the options string, then stop now */
  if(addr == NULL)
    {
      snprintf(errbuf, errlen, "expected address to tbit");
      goto err;
    }

  /* Parse the options, do preliminary sanity checks */
  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 tbit_arg_param_validate(opt->id, opt->str, &tmp,
				 buf, sizeof(buf)) != 0)
	{
	  snprintf(errbuf, errlen, "-%c failed: %s",
		   scamper_options_id2c(opts, opts_cnt, opt->id), buf);
	  goto err;
	}

      switch(opt->id)
        {
	case TBIT_OPT_TYPE:
	  type = (uint8_t)tmp;
	  break;

	case TBIT_OPT_APP:
	  o.app = (uint8_t)tmp;
	  break;

	case TBIT_OPT_DPORT:
	  o.dport = (uint16_t)tmp;
	  break;

	case TBIT_OPT_SPORT:
	  o.sport = (uint16_t)tmp;
	  break;

	case TBIT_OPT_MSS:
	  o.mss = (uint16_t)tmp;
	  break;

	case TBIT_OPT_MTU:
	  o.mtu = (uint16_t)tmp;
	  break;

	case TBIT_OPT_SRCADDR:
	  o.src = opt->str;
	  break;

	case TBIT_OPT_URL:
	  o.url = opt->str;
	  break;

	case TBIT_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case TBIT_OPT_PTBSRC:
	  o.ptbsrc = opt->str;
	  break;

	case TBIT_OPT_FO:
	  o.fo_cookielen = 0;
	  for(i=0; i<tmp; i+=2)
	    o.fo_cookie[o.fo_cookielen++] = hex2byte(opt->str[i],opt->str[i+1]);
	  break;

	case TBIT_OPT_WSCALE:
	  wscale = (uint8_t)tmp;
	  break;

	case TBIT_OPT_ATTEMPTS:
	  o.attempts = (uint8_t)tmp;
	  break;

	case TBIT_OPT_OFFSET:
	  o.offset = (int32_t)tmp;
	  break;

	case TBIT_OPT_ASN:
	  o.asn = (uint16_t)tmp;
	  break;

	case TBIT_OPT_TTL:
	  ttl = (uint8_t)tmp;
	  break;

	case TBIT_OPT_OPTION:
	  o.options |= (uint16_t)tmp;
	  break;
        }
    }
  scamper_options_free(opts_out); opts_out = NULL;

  if((tbit = scamper_tbit_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc tbit");
      goto err;
    }
  if((tbit->dst = scamper_addrcache_resolve(addrcache,AF_UNSPEC,addr)) == NULL)
    {
      snprintf(errbuf, errlen, "invalid destination address");
      goto err;
    }
  af = scamper_addr_af(tbit->dst);
  if(af != AF_INET && af != AF_INET6)
    {
      snprintf(errbuf, errlen, "invalid destination address");
      goto err;
    }

  tbit->type            = type;
  tbit->userid          = userid;
  tbit->client_wscale   = wscale;
  tbit->client_ipttl    = ttl;
  tbit->client_mss      = o.mss;
  tbit->dport           = o.dport;
  tbit->sport           = (o.sport != 0) ? o.sport : scamper_sport_default();
  tbit->client_syn_retx = 3;
  if(type == SCAMPER_TBIT_TYPE_SACK_RCVR)
    tbit->client_dat_retx = 1;
  else
    tbit->client_dat_retx = 3;

  if(o.src != NULL &&
     (tbit->src = scamper_addrcache_resolve(addrcache, af, o.src)) == NULL)
    {
      snprintf(errbuf, errlen, "invalid source address");
      goto err;
    }

  if(o.app == 0) o.app = SCAMPER_TBIT_APP_HTTP;
  tbit->app_proto = o.app;
  if(app_func[o.app] != NULL && app_func[o.app](tbit, &o, errbuf, errlen) != 0)
    goto err;

  if(type_func[type] != NULL && type_func[type](tbit, &o, errbuf, errlen) != 0)
    goto err;

  assert(errbuf[0] == '\0');
  return tbit;

 err:
  assert(errbuf[0] != '\0');
  if(tbit != NULL) scamper_tbit_free(tbit);
  if(opts_out != NULL) scamper_options_free(opts_out);
  return NULL;
}
