/*
 * scamper_dealias_cmd.c
 *
 * $Id: scamper_dealias_cmd.c,v 1.30 2024/05/02 02:33:38 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012-2013 Matthew Luckie
 * Copyright (C) 2012-2014 The Regents of the University of California
 * Copyright (C) 2016-2023 Matthew Luckie
 * Copyright (C) 2023-2024 The Regents of the University of California
 * Author: Matthew Luckie
 *
 * This code implements alias resolution techniques published by others
 * which require the network to be probed; the author of each technique
 * is detailed with its data structures.
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
#include "scamper_dealias.h"
#include "scamper_dealias_int.h"
#include "scamper_dealias_cmd.h"
#include "scamper_options.h"
#include "scamper.h"
#include "mjl_list.h"
#include "utils.h"

typedef struct dealias_options
{
  char                        *addr;
  uint8_t                      attempts;
  uint8_t                      replyc;
  struct timeval               wait_timeout;
  struct timeval               wait_probe;
  struct timeval               wait_round;
  struct timeval               startat;
  uint16_t                     fudge;
  slist_t                     *probedefs;
  slist_t                     *xs;
  slist_t                     *sched;
  int                          nobs;
  int                          shuffle;
  int                          inseq;
} dealias_options_t;

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

#define DEALIAS_OPT_FUDGE        1
#define DEALIAS_OPT_METHOD       2
#define DEALIAS_OPT_REPLYC       3
#define DEALIAS_OPT_OPTION       4
#define DEALIAS_OPT_PROBEDEF     5
#define DEALIAS_OPT_ATTEMPTS     6
#define DEALIAS_OPT_WAIT_ROUND   7
#define DEALIAS_OPT_USERID       8
#define DEALIAS_OPT_WAIT_TIMEOUT 9
#define DEALIAS_OPT_WAIT_PROBE   10
#define DEALIAS_OPT_EXCLUDE      11
#define DEALIAS_OPT_SCHED        12
#define DEALIAS_OPT_STARTAT      13

static const scamper_option_in_t opts[] = {
  {'f', NULL, DEALIAS_OPT_FUDGE,        SCAMPER_OPTION_TYPE_NUM},
  {'m', NULL, DEALIAS_OPT_METHOD,       SCAMPER_OPTION_TYPE_STR},
  {'o', NULL, DEALIAS_OPT_REPLYC,       SCAMPER_OPTION_TYPE_NUM},
  {'O', NULL, DEALIAS_OPT_OPTION,       SCAMPER_OPTION_TYPE_STR},
  {'p', NULL, DEALIAS_OPT_PROBEDEF,     SCAMPER_OPTION_TYPE_STR},
  {'q', NULL, DEALIAS_OPT_ATTEMPTS,     SCAMPER_OPTION_TYPE_NUM},
  {'r', NULL, DEALIAS_OPT_WAIT_ROUND,   SCAMPER_OPTION_TYPE_STR},
  {'S', NULL, DEALIAS_OPT_SCHED,        SCAMPER_OPTION_TYPE_STR},
  {'U', NULL, DEALIAS_OPT_USERID,       SCAMPER_OPTION_TYPE_NUM},
  {'w', NULL, DEALIAS_OPT_WAIT_TIMEOUT, SCAMPER_OPTION_TYPE_STR},
  {'W', NULL, DEALIAS_OPT_WAIT_PROBE,   SCAMPER_OPTION_TYPE_STR},
  {'x', NULL, DEALIAS_OPT_EXCLUDE,      SCAMPER_OPTION_TYPE_STR},
  {'@', NULL, DEALIAS_OPT_STARTAT,      SCAMPER_OPTION_TYPE_STR},
};
static const size_t opts_cnt = SCAMPER_OPTION_COUNT(opts);

#define DEALIAS_PROBEDEF_OPT_CSUM  1
#define DEALIAS_PROBEDEF_OPT_DPORT 2
#define DEALIAS_PROBEDEF_OPT_IP    3
#define DEALIAS_PROBEDEF_OPT_PROTO 4
#define DEALIAS_PROBEDEF_OPT_SPORT 5
#define DEALIAS_PROBEDEF_OPT_TTL   6
#define DEALIAS_PROBEDEF_OPT_SIZE  7
#define DEALIAS_PROBEDEF_OPT_MTU   8

static const scamper_option_in_t probedef_opts[] = {
  {'c', NULL, DEALIAS_PROBEDEF_OPT_CSUM,  SCAMPER_OPTION_TYPE_STR},
  {'d', NULL, DEALIAS_PROBEDEF_OPT_DPORT, SCAMPER_OPTION_TYPE_NUM},
  {'F', NULL, DEALIAS_PROBEDEF_OPT_SPORT, SCAMPER_OPTION_TYPE_NUM},
  {'i', NULL, DEALIAS_PROBEDEF_OPT_IP,    SCAMPER_OPTION_TYPE_STR},
  {'P', NULL, DEALIAS_PROBEDEF_OPT_PROTO, SCAMPER_OPTION_TYPE_STR},
  {'s', NULL, DEALIAS_PROBEDEF_OPT_SIZE,  SCAMPER_OPTION_TYPE_NUM},
  {'t', NULL, DEALIAS_PROBEDEF_OPT_TTL,   SCAMPER_OPTION_TYPE_NUM},
  {'M', NULL, DEALIAS_PROBEDEF_OPT_MTU,   SCAMPER_OPTION_TYPE_NUM},
};
static const size_t probedef_opts_cnt = SCAMPER_OPTION_COUNT(probedef_opts);

const char *scamper_do_dealias_usage(void)
{
  return
    "dealias [-@ start-time] [-f fudge] [-m method] [-o replyc] [-O option]\n"
    "        [-p '[-c sum] [-d dp] [-F sp] [-i ip] [-M mtu] [-P meth] [-s size] [-t ttl]']\n"
    "        [-q attempts] [-r wait-round] [-S sched]\n"
    "        [-U userid] [-w wait-timeout] [-W wait-probe] [-x exclude]\n";
}

static int dealias_arg_param_validate(int optid, char *param,
				      long long *out, char *errbuf, size_t len)
{
  struct timeval tv;
  long long tmp;

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  switch(optid)
    {
    case DEALIAS_OPT_OPTION:
    case DEALIAS_OPT_PROBEDEF:
    case DEALIAS_OPT_EXCLUDE:
    case DEALIAS_OPT_SCHED:
      tmp = 0;
      break;

    case DEALIAS_OPT_STARTAT:
      if(timeval_fromstr(&tv, param, 1000000) != 0)
	{
	  snprintf(errbuf, len, "invalid startat time");
	  goto err;
	}
      tmp = ((long long)tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    case DEALIAS_OPT_FUDGE:
      if(string_tollong(param, &tmp, NULL, 0) != 0 || tmp < 1 || tmp > 65535)
	{
	  snprintf(errbuf, len, "fudge must be within 1-65535");
	  goto err;
	}
      break;

    case DEALIAS_OPT_METHOD:
      if(strcasecmp(param, "mercator") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_MERCATOR;
      else if(strcasecmp(param, "ally") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_ALLY;
      else if(strcasecmp(param, "radargun") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_RADARGUN;
      else if(strcasecmp(param, "prefixscan") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_PREFIXSCAN;
      else if(strcasecmp(param, "bump") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_BUMP;
      else if(strcasecmp(param, "midarest") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_MIDAREST;
      else if(strcasecmp(param, "midardisc") == 0)
	tmp = SCAMPER_DEALIAS_METHOD_MIDARDISC;
      else
	{
	  snprintf(errbuf, len, "invalid method");
	  goto err;
	}
      break;

    case DEALIAS_OPT_ATTEMPTS:
      if(string_tollong(param, &tmp, NULL, 0) != 0 || tmp < 1 || tmp > 500)
	{
	  snprintf(errbuf, len, "attempts must be within 1-500");
	  goto err;
	}
      break;

    case DEALIAS_OPT_USERID:
      if(string_tollong(param, &tmp, NULL, 0) != 0 || tmp < 0)
	{
	  snprintf(errbuf, len, "userid must be >= 0");
	  goto err;
	}
      break;

    case DEALIAS_OPT_WAIT_TIMEOUT:
      if(timeval_fromstr(&tv, param, 1000000) != 0 || tv.tv_usec != 0 ||
	 timeval_cmp_lt(&tv, 1, 0) || timeval_cmp_gt(&tv, 255, 0))
	{
	  snprintf(errbuf, len, "timeout must be within 1s - 255s");
	  goto err;
	}
      tmp = tv.tv_sec * 1000000;
      break;

    case DEALIAS_OPT_WAIT_PROBE:
      if(timeval_fromstr(&tv, param, 1000) != 0 || (tv.tv_usec % 1000) != 0 ||
	 timeval_cmp_lt(&tv, 0, 1000) || timeval_cmp_gt(&tv, 65, 535000))
	{
	  snprintf(errbuf, len, "inter-probe delay must be within 1ms - 65s");
	  goto err;
	}
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    case DEALIAS_OPT_WAIT_ROUND:
      if(timeval_fromstr(&tv, param, 1000) != 0 || (tv.tv_usec % 1000) != 0 ||
	 timeval_cmp_lt(&tv, 0, 1000) || timeval_cmp_gt(&tv, 180, 0))
	{
	  snprintf(errbuf, len, "round time must be within 1ms - 180s");
	  goto err;
	}
      tmp = (tv.tv_sec * 1000000) + tv.tv_usec;
      break;

    case DEALIAS_OPT_REPLYC:
      if(string_tollong(param, &tmp, NULL, 0) != 0 || tmp < 3 || tmp > 255)
	{
	  snprintf(errbuf, len, "replyc must be within 3-255");
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

#ifndef DMALLOC
static int dealias_probedef_args(scamper_dealias_probedef_t *def, char *str,
				 char *errbuf, size_t errlen)
#else
static int dealias_probedef_args_dm(scamper_dealias_probedef_t *def, char *str,
				    char *errbuf, size_t errlen,
				    const char *file, const int line)
#define dealias_probedef_args(def, str, errbuf, errlen)	\
  dealias_probedef_args_dm((def), (str), (errbuf), (errlen), __FILE__, __LINE__)
#endif
{
  scamper_option_out_t *opts_out = NULL, *opt;
  uint16_t dport = 33435;
  uint16_t sport = scamper_sport_default();
  uint16_t csum  = 0;
  uint16_t options = 0;
  uint8_t  ttl   = 0;
  uint8_t  tos   = 0;
  uint16_t size  = 0;
  uint16_t mtu   = 0;
  char *end;
  long tmp;

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  /* try and parse the string passed in */
  if(scamper_options_parse(str, probedef_opts, probedef_opts_cnt,
			   &opts_out, &end) != 0)
    {
      snprintf(errbuf, errlen, "could not parse probedef options");
      goto err;
    }

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      /* check for an option being used multiple times */
      if(options & (1<<(opt->id-1)))
	{
	  snprintf(errbuf, errlen, "-%c repeated in probedef",
		   scamper_options_id2c(probedef_opts, probedef_opts_cnt,
					opt->id));
	  goto err;
	}

      options |= (1 << (opt->id-1));

      switch(opt->id)
	{
	case DEALIAS_PROBEDEF_OPT_CSUM:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 0 || tmp > 65535)
	    {
	      snprintf(errbuf, errlen, "csum must be within 0-65535");
	      goto err;
	    }
	  csum = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_DPORT:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 65535)
	    {
	      snprintf(errbuf, errlen, "dport must be within 1-65535");
	      goto err;
	    }
	  dport = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_IP:
#ifndef DMALLOC
	  def->dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, opt->str);
#else
	  def->dst = scamper_addrcache_resolve_dm(addrcache, AF_UNSPEC,
						  opt->str, file, line);
#endif
	  if(def->dst == NULL)
	    {
	      snprintf(errbuf, errlen, "invalid destination in probedef");
	      goto err;
	    }
	  break;

	case DEALIAS_PROBEDEF_OPT_MTU:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 100 || tmp > 65535)
	    {
	      snprintf(errbuf, errlen, "mtu size must be within 100-65535");
	      goto err;
	    }
	  mtu = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_PROTO:
	  if(scamper_dealias_probedef_method_fromstr(opt->str,&def->method)!=0)
	    {
	      snprintf(errbuf, errlen, "invalid probedef method");
	      goto err;
	    }
	  break;

	case DEALIAS_PROBEDEF_OPT_SIZE:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 20+8 || tmp > 65535)
	    {
	      snprintf(errbuf, errlen, "probe size must be within 28-65535");
	      goto err;
	    }
	  size = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_SPORT:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 65535)
	    {
	      snprintf(errbuf, errlen, "sport must be within 1-65535");
	      goto err;
	    }
	  sport = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_TTL:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 255)
	    {
	      snprintf(errbuf, errlen, "ttl must be within 1-255");
	      goto err;
	    }
	  ttl = (uint8_t)tmp;
	  break;

	default:
	  goto err;
	}
    }

  scamper_options_free(opts_out); opts_out = NULL;

  /*
   * if there is something at the end of the option string, then this
   * probedef is not valid
   */
  if(end != NULL)
    {
      snprintf(errbuf, errlen, "invalid option string");
      goto err;
    }

  /* record the ttl, tos, size */
  def->ttl  = ttl;
  def->tos  = tos;
  def->size = size;
  def->mtu  = mtu;

  /* if no protocol type is defined, choose UDP */
  if((options & (1<<(DEALIAS_PROBEDEF_OPT_PROTO-1))) == 0)
    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    {
      /* don't provide the choice of the checksum value in a UDP probe */
      if(options & (1<<(DEALIAS_PROBEDEF_OPT_CSUM-1)))
	{
	  snprintf(errbuf, errlen, "csum option not permitted for udp");
	  goto err;
	}

      def->un.udp.dport = dport;
      def->un.udp.sport = sport;
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def))
    {
      /* ICMP probes don't have source or destination ports */
      if(options & (1<<(DEALIAS_PROBEDEF_OPT_SPORT-1)))
	{
	  snprintf(errbuf, errlen, "sport option not permitted for icmp");
	  goto err;
	}
      if(options & (1<<(DEALIAS_PROBEDEF_OPT_DPORT-1)))
	{
	  snprintf(errbuf, errlen, "dport option not permitted for icmp");
	  goto err;
	}
      def->un.icmp.csum = csum;
      def->un.icmp.id   = scamper_sport_default();
    }
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    {
      /* don't provide the choice of the checksum value in a TCP probe */
      if(options & (1<<(DEALIAS_PROBEDEF_OPT_CSUM-1)))
	{
	  snprintf(errbuf, errlen, "csum option not permitted for tcp");
	  goto err;
	}

      def->un.tcp.dport = dport;
      def->un.tcp.sport = sport;
      if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP_ACK(def))
	def->un.tcp.flags = TH_ACK;
      else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP_SYN(def))
	def->un.tcp.flags = TH_SYN;
      else
	{
	  snprintf(errbuf, errlen, "unhandled flags for method %d",def->method);
	  goto err;
	}
    }
  else
    {
      snprintf(errbuf, errlen, "unhandled method %d", def->method);
      goto err;
    }

  assert(errbuf[0] == '\0');
  return 0;

 err:
  assert(errbuf[0] != '\0');
  if(opts_out != NULL) scamper_options_free(opts_out);
  return -1;
}

static int probedef_size_check(scamper_dealias_probedef_t *def,
			       char *errbuf, size_t errlen)
{
  uint16_t cmps;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(def->dst))
    cmps = 20; /* sizeof ipv4 hdr */
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(def->dst))
    cmps = 40; /* sizeof ipv6 hdr */
  else
    {
      snprintf(errbuf, errlen, "invalid destination in probedef");
      return -1;
    }

  if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_ICMP(def) ||
     SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_UDP(def))
    cmps += (8 + 2); /* sizeof udp/icmp hdr + 2 bytes of payload */
  else if(SCAMPER_DEALIAS_PROBEDEF_PROTO_IS_TCP(def))
    cmps += 20; /* sizeof tcp hdr */
  else
    {
      snprintf(errbuf, errlen, "invalid protocol type in probedef");
      return -1;
    }

  if(def->size == 0)
    def->size = cmps;
  else if(def->size < cmps)
    {
      snprintf(errbuf, errlen, "probedef size %u too small", def->size);
      return -1;
    }
  return 0;
}

static int dealias_alloc_mercator(scamper_dealias_t *d, dealias_options_t *o,
				  char *errbuf, size_t errlen)
{
  static const char *meth = "mercator";
  scamper_dealias_mercator_t *mc = NULL;
  scamper_addr_t *dst = NULL;
  char *pdstr;

  /* if there is no IP address after the options string, then stop now */
  if(o->addr == NULL)
    {
      snprintf(errbuf, errlen, "expected target address for %s", meth);
      goto err;
    }
  if((dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, o->addr)) == NULL)
    {
      snprintf(errbuf, errlen, "invalid target address");
      goto err;
    }

  if((o->probedefs != NULL && slist_count(o->probedefs) > 1) ||
     o->xs != NULL || o->sched != NULL ||
     timeval_iszero(&o->wait_probe) == 0 || timeval_iszero(&o->startat) == 0 ||
     o->fudge != 0 || o->attempts > 3 || o->nobs != 0 || o->replyc != 0 ||
     o->shuffle != 0 || o->inseq != 0)
    {
      snprintf(errbuf, errlen, "invalid parameters for %s", meth);
      goto err;
    }
  if(o->attempts == 0) o->attempts = 3;
  if(timeval_iszero(&o->wait_timeout))
    o->wait_timeout.tv_sec = 5;

  if((mc = scamper_dealias_mercator_alloc()) == NULL ||
     (mc->probedef = scamper_dealias_probedef_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc %s structure", meth);
      goto err;
    }
  mc->attempts = o->attempts;
  timeval_cpy(&mc->wait_timeout, &o->wait_timeout);

  if(o->probedefs == NULL)
    {
      mc->probedef->ttl          = 255;
      mc->probedef->method       = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
      mc->probedef->un.udp.sport = scamper_sport_default();
      mc->probedef->un.udp.dport = 33435;
    }
  else
    {
      pdstr = (char *)slist_head_item(o->probedefs);
      if(dealias_probedef_args(mc->probedef, pdstr, errbuf, errlen) != 0)
	goto err;
      if(mc->probedef->method != SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP)
	{
	  snprintf(errbuf, errlen, "expected UDP probedef method for %s", meth);
	  goto err;
	}
      if(mc->probedef->dst != NULL)
	{
	  snprintf(errbuf, errlen, "unexpected dst in %s probedef", meth);
	  goto err;
	}
      if(mc->probedef->ttl == 0)
	mc->probedef->ttl = 255;
    }
  mc->probedef->id = 0;
  mc->probedef->dst = dst; dst = NULL;
  if(probedef_size_check(mc->probedef, errbuf, errlen) != 0)
    goto err;

  d->data = mc;
  return 0;

 err:
  if(mc != NULL) scamper_dealias_mercator_free(mc);
  if(dst != NULL) scamper_addr_free(dst);
  return -1;
}

static int dealias_alloc_ally(scamper_dealias_t *d, dealias_options_t *o,
			      char *errbuf, size_t errlen)
{
  static const char *meth = "ally";
  scamper_dealias_ally_t *ally = NULL;
  scamper_dealias_probedef_t pd[2];
  int i, probedefc = 0;
  slist_node_t *sn;
  uint8_t flags = 0;
  char *addr2, *pdstr;

  memset(&pd, 0, sizeof(pd));

  if(o->probedefs != NULL)
    probedefc = slist_count(o->probedefs);

  if(probedefc > 2 || o->xs != NULL || o->sched != NULL ||
     timeval_iszero(&o->startat) == 0 ||
     o->replyc != 0 || o->shuffle != 0 || (o->inseq != 0 && o->fudge != 0))
    {
      snprintf(errbuf, errlen, "invalid parameters for %s", meth);
      goto err;
    }

  if(timeval_iszero(&o->wait_probe))
    o->wait_probe.tv_usec = 150000;
  if(timeval_iszero(&o->wait_timeout))
    o->wait_timeout.tv_sec = 5;
  if(o->attempts == 0)
    o->attempts = 5;
  if(o->fudge == 0 && o->inseq == 0)
    o->fudge = 200;

  if(probedefc > 0)
    {
      i = 0;
      for(sn=slist_head_node(o->probedefs); sn != NULL; sn=slist_node_next(sn))
	{
	  pdstr = (char *)slist_node_item(sn);
	  if(dealias_probedef_args(&pd[i], pdstr, errbuf, errlen) != 0)
	    goto err;
	  if(pd[i].ttl == 0)
	    pd[i].ttl = 255;
	  i++;
	}
    }

  if(probedefc == 0)
    {
      for(i=0; i<2; i++)
	{
	  pd[i].ttl          = 255;
	  pd[i].method       = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
	  pd[i].un.udp.sport = scamper_sport_default();
	  pd[i].un.udp.dport = 33435;
	}
    }
  else if(probedefc == 1)
    {
      if(pd[0].dst != NULL || o->addr == NULL)
	{
	  snprintf(errbuf, errlen, "dst IP specified incorrectly");
	  goto err;
	}
      memcpy(&pd[1], &pd[0], sizeof(scamper_dealias_probedef_t));
    }

  if(o->addr == NULL)
    {
      if(pd[0].dst == NULL || pd[1].dst == NULL)
	{
	  snprintf(errbuf, errlen, "expected dst in %s probedef", meth);
	  goto err;
	}
    }
  else
    {
      if(pd[0].dst != NULL || pd[1].dst != NULL)
	{
	  snprintf(errbuf, errlen, "unexpected dst in %s probedef", meth);
	  goto err;
	}

      /* make sure there are two addresses specified */
      if((addr2 = string_nextword(o->addr)) == NULL)
	{
	  snprintf(errbuf, errlen, "expected second address");
	  goto err;
	}

      /* resolve each address */
      pd[0].dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, o->addr);
      if(pd[0].dst == NULL)
	{
	  snprintf(errbuf, errlen, "could not resolve address");
	  goto err;
	}
      pd[1].dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, addr2);
      if(pd[1].dst == NULL)
	{
	  snprintf(errbuf, errlen, "could not resolve address");
	  goto err;
	}
    }

  if(pd[0].dst->type != pd[1].dst->type ||
     SCAMPER_ADDR_TYPE_IS_IP(pd[0].dst) == 0 ||
     SCAMPER_ADDR_TYPE_IS_IP(pd[1].dst) == 0)
    {
      snprintf(errbuf, errlen, "dst IP specified incorrectly");
      goto err;
    }

  if(o->nobs != 0 || SCAMPER_ADDR_TYPE_IS_IPV6(pd[0].dst))
    flags |= SCAMPER_DEALIAS_ALLY_FLAG_NOBS;

  for(i=0; i<2; i++)
    {
      if(probedef_size_check(&pd[i], errbuf, errlen) != 0)
	goto err;
      pd[i].id = i;
    }

  if((ally = scamper_dealias_ally_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc %s structure", meth);
      goto err;
    }
  ally->attempts     = o->attempts;
  ally->fudge        = o->fudge;
  ally->flags        = flags;
  timeval_cpy(&ally->wait_probe, &o->wait_probe);
  timeval_cpy(&ally->wait_timeout, &o->wait_timeout);

  memcpy(ally->probedefs[0], &pd[0], sizeof(scamper_dealias_probedef_t));
  memcpy(ally->probedefs[1], &pd[1], sizeof(scamper_dealias_probedef_t));

  d->data = ally;

  return 0;

 err:
  if(ally != NULL) scamper_dealias_ally_free(ally);
  if(pd[0].dst != NULL) scamper_addr_free(pd[0].dst);
  if(pd[1].dst != NULL) scamper_addr_free(pd[1].dst);
  return -1;
}

static int dealias_alloc_radargun(scamper_dealias_t *d, dealias_options_t *o,
				  char *errbuf, size_t errlen)
{
  static const char *meth = "radargun";
  scamper_dealias_radargun_t *rg = NULL;
  scamper_dealias_probedef_t *pd = NULL, pd0;
  scamper_addr_t *addr = NULL;
  slist_t *pd_list = NULL, *addrs = NULL;
  slist_node_t *sn, *s2;
  uint32_t i, probedefc;
  uint8_t flags = 0;
  char *a1, *a2, *pdstr;

  memset(&pd0, 0, sizeof(pd0));

  if(o->xs != NULL || o->sched != NULL || timeval_iszero(&o->startat) == 0 ||
     o->nobs != 0 || o->replyc != 0 || o->inseq != 0)
    {
      snprintf(errbuf, errlen, "invalid parameters for %s", meth);
      goto err;
    }

  if(o->attempts == 0)
    o->attempts = 30;
  if(timeval_iszero(&o->wait_probe))
    o->wait_probe.tv_usec = 150000;
  if(timeval_iszero(&o->wait_timeout))
    o->wait_timeout.tv_sec = 5;
  if(o->shuffle != 0)
    flags |= SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE;

  /* get the addresses to probe, if supplied */
  if(o->addr != NULL)
    {
      if((addrs = slist_alloc()) == NULL)
	{
	  snprintf(errbuf, errlen, "could not alloc addrs list");
	  goto err;
	}
      a1 = o->addr;
      for(;;)
	{
	  a2 = string_nextword(a1);
	  if((addr = scamper_addrcache_resolve(addrcache,AF_UNSPEC,a1)) == NULL)
	    {
	      snprintf(errbuf, errlen, "could not resolve address");
	      goto err;
	    }
	  if(slist_tail_push(addrs, addr) == NULL)
	    {
	      snprintf(errbuf, errlen, "could not add address to list");
	      goto err;
	    }
	  addr = NULL;
	  if(a2 == NULL)
	    break;
	  a1 = a2;
	}
    }

  /* get the probedefs */
  if((pd_list = slist_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc pd_list");
      goto err;
    }
  if(o->probedefs == NULL)
    {
      if(addrs == NULL || slist_count(addrs) < 2)
	{
	  snprintf(errbuf, errlen, "expected at least two addresses");
	  goto err;
	}
      for(sn=slist_head_node(addrs); sn != NULL; sn=slist_node_next(sn))
	{
	  if((pd = scamper_dealias_probedef_alloc()) == NULL ||
	     slist_tail_push(pd_list, pd) == NULL)
	    {
	      snprintf(errbuf, errlen, "could not create default %s def", meth);
	      goto err;
	    }
	  pd->dst          = scamper_addr_use(slist_node_item(sn));
	  pd->ttl          = 255;
	  pd->method       = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
	  pd->un.udp.sport = scamper_sport_default();
	  pd->un.udp.dport = 33435;
	  pd = NULL;
	}
    }
  else if(addrs != NULL)
    {
      if(slist_count(addrs) < 2 && slist_count(o->probedefs) == 1)
	{
	  snprintf(errbuf, errlen, "expected at least two addresses");
	  goto err;
	}
      for(sn=slist_head_node(o->probedefs); sn != NULL; sn=slist_node_next(sn))
	{
	  pdstr = (char *)slist_node_item(sn);
	  if(dealias_probedef_args(&pd0, pdstr, errbuf, errlen) != 0)
	    goto err;
	  if(pd0.dst != NULL)
	    {
	      snprintf(errbuf, errlen, "unexpected dst in %s probedef", meth);
	      goto err;
	    }
	  if(pd0.ttl == 0)
	    pd0.ttl = 255;
	  for(s2=slist_head_node(addrs); s2 != NULL; s2=slist_node_next(s2))
	    {
	      if((pd = memdup(&pd0, sizeof(pd0))) == NULL ||
		 slist_tail_push(pd_list, pd) == NULL)
		{
		  snprintf(errbuf, errlen, "could not alloc %s probedef", meth);
		  goto err;
		}
	      pd->dst = scamper_addr_use(slist_node_item(s2));
	      pd = NULL;
	    }
	}
    }
  else
    {
      if(slist_count(o->probedefs) < 2)
	{
	  snprintf(errbuf, errlen, "expected at least two probedefs");
	  goto err;
	}
      for(sn=slist_head_node(o->probedefs); sn != NULL; sn=slist_node_next(sn))
	{
	  pdstr = (char *)slist_node_item(sn);
	  if((pd = scamper_dealias_probedef_alloc()) == NULL)
	    {
	      snprintf(errbuf, errlen, "could not alloc %s probedef", meth);
	      goto err;
	    }
	  if(dealias_probedef_args(pd, pdstr, errbuf, errlen) != 0)
	    goto err;
	  if(pd->dst == NULL)
	    {
	      snprintf(errbuf, errlen, "expected dst in %s probedef", meth);
	      goto err;
	    }
	  if(slist_tail_push(pd_list, pd) == NULL)
	    {
	      snprintf(errbuf, errlen, "could not add %s probedef", meth);
	      goto err;
	    }
	  if(pd->ttl == 0)
	    pd->ttl = 255;
	  pd = NULL;
	}
    }

  if(addrs != NULL)
    {
      slist_free_cb(addrs, (slist_free_t)scamper_addr_free);
      addrs = NULL;
    }

  probedefc = slist_count(pd_list);
  if((rg = scamper_dealias_radargun_alloc()) == NULL ||
     scamper_dealias_radargun_probedefs_alloc(rg, probedefc) != 0)
    {
      snprintf(errbuf, errlen, "could not alloc %s structure", meth);
      goto err;
    }

  rg->rounds       = o->attempts;
  rg->probedefc    = probedefc;
  rg->flags        = flags;
  timeval_cpy(&rg->wait_probe, &o->wait_probe);
  timeval_cpy(&rg->wait_timeout, &o->wait_timeout);
  if(timeval_iszero(&o->wait_round))
    {
      i = ((o->wait_probe.tv_sec * 1000000)+o->wait_probe.tv_usec) * probedefc;
      o->wait_round.tv_sec = i / 1000000;
      o->wait_round.tv_usec = i % 1000000;
    }
  timeval_cpy(&rg->wait_round, &o->wait_round);

  i=0;
  while((pd = slist_head_pop(pd_list)) != NULL)
    {
      if(probedef_size_check(pd, errbuf, errlen) != 0)
	goto err;
      pd->id = i;
      if(i != 0 && rg->probedefs[0]->dst->type != pd->dst->type)
	{
	  snprintf(errbuf, errlen, "mixed address families");
	  goto err;
	}
      rg->probedefs[i++] = pd; pd = NULL;
    }
  slist_free(pd_list);

  d->data = rg;
  return 0;

 err:
  if(addr != NULL)
    scamper_addr_free(addr);
  if(addrs != NULL)
    slist_free_cb(addrs, (slist_free_t)scamper_addr_free);
  if(rg != NULL)
    scamper_dealias_radargun_free(rg);
  if(pd != NULL)
    scamper_dealias_probedef_free(pd);
  if(pd_list != NULL)
    slist_free_cb(pd_list, (slist_free_t)scamper_dealias_probedef_free);
  if(pd0.dst != NULL)
    scamper_addr_free(pd0.dst);
  return -1;
}

static int dealias_alloc_prefixscan(scamper_dealias_t *d, dealias_options_t *o,
				    char *errbuf, size_t errlen)
{
  static const char *meth = "prefixscan";
  scamper_dealias_prefixscan_t *prefixscan = NULL;
  scamper_dealias_probedef_t pd0;
  scamper_addr_t *dst = NULL;
  slist_node_t *sn;
  uint8_t flags = 0;
  uint8_t prefix;
  char *addr2 = NULL, *pfxstr, *xs, *pdstr;
  long tmp;
  int af;

  memset(&pd0, 0, sizeof(pd0));

  /* check the sanity of various parameters */
  if(o->probedefs == NULL || slist_count(o->probedefs) != 1 ||
     o->addr == NULL || o->sched != NULL || timeval_iszero(&o->startat) == 0 ||
     o->shuffle != 0 || (o->inseq != 0 && o->fudge != 0))
    {
      snprintf(errbuf, errlen, "invalid parameters for %s", meth);
      goto err;
    }

  if(o->attempts == 0)
    o->attempts = 2;
  if(o->replyc == 0)
    o->replyc = 5;
  if(timeval_iszero(&o->wait_probe))
    o->wait_probe.tv_sec = 1;
  if(timeval_iszero(&o->wait_timeout))
    o->wait_timeout.tv_sec = 5;
  if(o->nobs != 0)
    flags |= SCAMPER_DEALIAS_PREFIXSCAN_FLAG_NOBS;
  if(o->fudge == 0 && o->inseq == 0)
    o->fudge = 200;

  /*
   * we need `a' and `b' to traceroute.  parse the `addr' string.
   * start by getting the second address.
   *
   * skip over the first address until we get to whitespace.
   */
  if((addr2 = string_nextword(o->addr)) == NULL)
    {
      snprintf(errbuf, errlen, "expected second address");
      goto err;
    }

  string_nullterm_char(addr2, '/', &pfxstr);
  if(pfxstr == NULL)
    {
      snprintf(errbuf, errlen, "expected prefix");
      goto err;
    }

  if(string_tolong(pfxstr, &tmp) != 0 || tmp < 24 || tmp >= 32)
    {
      snprintf(errbuf, errlen, "invalid prefix");
      goto err;
    }
  prefix = (uint8_t)tmp;

  /* check the sanity of the probedef */
  pdstr = (char *)slist_head_item(o->probedefs);
  memset(&pd0, 0, sizeof(pd0));
  if(dealias_probedef_args(&pd0, pdstr, errbuf, errlen) != 0)
    goto err;
  if(pd0.dst != NULL)
    {
      snprintf(errbuf, errlen, "unexpected dst in %s probedef", meth);
      goto err;
    }
  if(pd0.ttl == 0)
    pd0.ttl = 255;

  if((prefixscan = scamper_dealias_prefixscan_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc %s structure", meth);
      goto err;
    }

  prefixscan->attempts     = o->attempts;
  prefixscan->fudge        = o->fudge;
  prefixscan->replyc       = o->replyc;
  prefixscan->prefix       = prefix;
  prefixscan->flags        = flags;
  timeval_cpy(&prefixscan->wait_probe, &o->wait_probe);
  timeval_cpy(&prefixscan->wait_timeout, &o->wait_timeout);

  /* resolve the two addresses now */
  prefixscan->a = scamper_addrcache_resolve(addrcache, AF_UNSPEC, o->addr);
  if(prefixscan->a == NULL)
    {
      snprintf(errbuf, errlen, "could not resolve address");
      goto err;
    }
  af = scamper_addr_af(prefixscan->a);
  prefixscan->b = scamper_addrcache_resolve(addrcache, af, addr2);
  if(prefixscan->b == NULL)
    {
      snprintf(errbuf, errlen, "could not resolve address");
      goto err;
    }

  /* add the first probedef */
  if(scamper_dealias_prefixscan_probedefs_alloc(prefixscan, 1) != 0)
    {
      snprintf(errbuf, errlen, "could not alloc %s probedefs", meth);
      goto err;
    }
  memcpy(prefixscan->probedefs[0], &pd0, sizeof(pd0));
  prefixscan->probedefs[0]->dst = scamper_addr_use(prefixscan->a);
  prefixscan->probedefs[0]->id  = 0;
  prefixscan->probedefc         = 1;

  if(probedef_size_check(prefixscan->probedefs[0], errbuf, errlen) != 0)
    goto err;

  /* resolve any addresses to exclude in the scan */
  if(o->xs != NULL)
    {
      for(sn = slist_head_node(o->xs); sn != NULL; sn = slist_node_next(sn))
	{
	  xs = slist_node_item(sn);
	  if((dst = scamper_addrcache_resolve(addrcache, af, xs)) == NULL)
	    {
	      snprintf(errbuf, errlen, "could not resolve address");
	      goto err;
	    }
	  if(scamper_dealias_prefixscan_xs_add(d, dst) != 0)
	    {
	      snprintf(errbuf, errlen, "could not add address to xs");
	      goto err;
	    }
	  scamper_addr_free(dst); dst = NULL;
	}
    }

  d->data = prefixscan;
  return 0;

 err:
  if(prefixscan != NULL)
    scamper_dealias_prefixscan_free(prefixscan);
  if(dst != NULL)
    scamper_addr_free(dst);
  if(pd0.dst != NULL)
    scamper_addr_free(pd0.dst);
  return -1;
}

static int dealias_alloc_bump(scamper_dealias_t *d, dealias_options_t *o,
			      char *errbuf, size_t errlen)
{
  static const char *meth = "bump";
  scamper_dealias_bump_t *bump = NULL;
  scamper_dealias_probedef_t pd[2];
  slist_node_t *sn;
  char *pdstr;
  int i;

  memset(&pd, 0, sizeof(pd));

  if(o->probedefs == NULL || slist_count(o->probedefs) != 2 ||
     o->xs != NULL || o->sched != NULL || timeval_iszero(&o->startat) == 0 ||
     o->replyc != 0 || o->shuffle != 0 || o->addr != NULL ||
     timeval_iszero(&o->wait_timeout) == 0 ||
     (o->inseq != 0 && o->fudge != 0))
    {
      snprintf(errbuf, errlen, "invalid parameters for %s", meth);
      goto err;
    }

  if(o->attempts == 0)
    o->attempts = 3;
  if(o->fudge == 0)
    o->fudge = 30; /* bump limit */
  if(timeval_iszero(&o->wait_probe))
    o->wait_probe.tv_sec = 1;

  i = 0;
  for(sn = slist_head_node(o->probedefs); sn != NULL; sn = slist_node_next(sn))
    {
      pdstr = (char *)slist_node_item(sn);
      if(dealias_probedef_args(&pd[i], pdstr, errbuf, errlen) != 0)
	goto err;
      if(pd[i].dst == NULL || SCAMPER_ADDR_TYPE_IS_IPV4(pd[i].dst) == 0)
	{
	  snprintf(errbuf, errlen, "expected IPv4 dst in probedef %d", i);
	  goto err;
	}
      if(probedef_size_check(&pd[i], errbuf, errlen) != 0)
	goto err;
      if(pd[i].ttl == 0)
	pd[i].ttl = 255;
      pd[i].id = i;
      i++;
    }

  if((bump = scamper_dealias_bump_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc %s structure", meth);
      goto err;
    }

  bump->attempts     = o->attempts;
  bump->bump_limit   = o->fudge;
  timeval_cpy(&bump->wait_probe, &o->wait_probe);

  memcpy(bump->probedefs[0], &pd[0], sizeof(scamper_dealias_probedef_t));
  memcpy(bump->probedefs[1], &pd[1], sizeof(scamper_dealias_probedef_t));

  d->data = bump;

  return 0;

 err:
  if(pd[0].dst != NULL) scamper_addr_free(pd[0].dst);
  if(pd[1].dst != NULL) scamper_addr_free(pd[1].dst);
  return -1;
}

/*
 * dealias_alloc_midarest
 *
 * process a midarest measurement definition.  midarest assumes at least
 * two probedefs and one address.
 */
static int dealias_alloc_midarest(scamper_dealias_t *d, dealias_options_t *o,
				  char *errbuf, size_t errlen)
{
  static const char *meth = "midarest";
  scamper_dealias_midarest_t *me = NULL;
  scamper_dealias_probedef_t *pd = NULL, *pd0;
  scamper_addr_t *addr = NULL, *addr0;
  slist_t *addrs = NULL, *pd_list = NULL;
  slist_node_t *sn, *s2;
  struct timeval tv;
  char *a1, *a2, *pdstr;
  uint32_t id;
  uint32_t u32;
  int probedefc;

  /*
   * process a midarest measurement definition.  midarest assumes at least
   * two probedefs and one address.
   */
  if(o->probedefs == NULL || slist_count(o->probedefs) < 2 ||
     o->addr == NULL || o->xs != NULL || o->sched != NULL ||
     timeval_iszero(&o->startat) == 0 ||
     o->nobs != 0 || o->replyc != 0 || o->inseq != 0)
    {
      snprintf(errbuf, errlen, "invalid parameters for %s", meth);
      goto err;
    }

  if(o->attempts == 0)
    o->attempts = 30;
  if(timeval_iszero(&o->wait_timeout))
    o->wait_timeout.tv_sec = 1;

  /* get the probedefs */
  if((pd_list = slist_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc pd_list");
      goto err;
    }
  for(sn=slist_head_node(o->probedefs); sn != NULL; sn=slist_node_next(sn))
    {
      /* for now, do not support indir method */
      pdstr = (char *)slist_node_item(sn);
      if((pd = scamper_dealias_probedef_alloc()) == NULL)
	{
	  snprintf(errbuf, errlen, "could not alloc %s probedef", meth);
	  goto err;
	}
      if(dealias_probedef_args(pd, pdstr, errbuf, errlen) != 0)
	goto err;
      if(pd->dst != NULL)
	{
	  snprintf(errbuf, errlen, "unexpected dst in %s probedef", meth);
	  goto err;
	}
      if(slist_tail_push(pd_list, pd) == NULL)
	{
	  snprintf(errbuf, errlen, "could not add %s probedef", meth);
	  goto err;
	}
      if(pd->ttl == 0)
	pd->ttl = 64;
      pd = NULL;
    }

  /* get the addresses to probe */
  if((addrs = slist_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc addrs list");
      goto err;
    }
  a1 = o->addr;
  for(;;)
    {
      a2 = string_nextword(a1);
      if((addr = scamper_addrcache_resolve(addrcache, AF_INET, a1)) == NULL)
	{
	  snprintf(errbuf, errlen, "could not resolve IPv4 address");
	  goto err;
	}
      if(slist_tail_push(addrs, addr) == NULL)
	{
	  snprintf(errbuf, errlen, "could not add address to list");
	  goto err;
	}
      addr = NULL;
      if(a2 == NULL)
	break;
      a1 = a2;
    }

  if(slist_count(addrs) < 1)
    {
      snprintf(errbuf, errlen, "no addresses to probe");
      goto err;
    }

  probedefc = slist_count(addrs) * slist_count(pd_list);
  if((me = scamper_dealias_midarest_alloc()) == NULL ||
     scamper_dealias_midarest_probedefs_alloc(me, probedefc) != 0)
    {
      snprintf(errbuf, errlen, "could not alloc %s structure", meth);
      goto err;
    }
  me->probedefc = probedefc;

  id = 0;
  for(sn=slist_head_node(pd_list); sn != NULL; sn=slist_node_next(sn))
    {
      pd0 = slist_node_item(sn);
      for(s2=slist_head_node(addrs); s2 != NULL; s2=slist_node_next(s2))
	{
	  addr0 = slist_node_item(s2);
	  if((pd = memdup(pd0, sizeof(scamper_dealias_probedef_t))) == NULL)
	    {
	      snprintf(errbuf, errlen, "could not alloc %s probedef", meth);
	      goto err;
	    }
	  /* need to set dst before calling probedef_size_check */
	  pd->dst = scamper_addr_use(addr0);
	  if(probedef_size_check(pd, errbuf, errlen) != 0)
	    goto err;
	  pd->id = id;
	  me->probedefs[id++] = pd;
	  pd = NULL;
	}
    }

  me->rounds = o->attempts;
  timeval_cpy(&me->wait_timeout, &o->wait_timeout);

  if(timeval_iszero(&o->wait_probe))
    {
      if(timeval_iszero(&o->wait_round))
	{
	  me->wait_round.tv_sec = 10;
	  me->wait_round.tv_usec = 0;
	}
      else
	{
	  timeval_cpy(&me->wait_round, &o->wait_round);
	}
      u32 = (me->wait_round.tv_sec * 1000000) + me->wait_round.tv_usec;
      u32 /= me->probedefc;
      me->wait_probe.tv_sec = u32 / 1000000;
      me->wait_probe.tv_usec = u32 % 1000000;
    }
  else
    {
      timeval_cpy(&me->wait_probe, &o->wait_probe);
      u32 = (me->wait_probe.tv_sec * 1000000) + me->wait_probe.tv_usec;
      u32 *= me->probedefc;
      if(timeval_iszero(&o->wait_round))
	{
	  me->wait_round.tv_sec = u32 / 1000000;
	  me->wait_round.tv_usec = u32 % 1000000;
	}
      else
	{
	  tv.tv_sec = u32 / 1000000;
	  tv.tv_usec = u32 % 1000000;
	  timeval_cpy(&me->wait_round, &o->wait_round);
	  if(timeval_cmp(&tv, &me->wait_round) > 0)
	    {
	      snprintf(errbuf, errlen, "invalid wait_round given wait_probe");
	      goto err;
	    }
	}
    }

  d->data = me;

  slist_free_cb(pd_list, (slist_free_t)scamper_dealias_probedef_free);
  slist_free_cb(addrs, (slist_free_t)scamper_addr_free);
  return 0;

 err:
  if(me != NULL)
    scamper_dealias_midarest_free(me);
  if(pd_list != NULL)
    slist_free_cb(pd_list, (slist_free_t)scamper_dealias_probedef_free);
  if(addrs != NULL)
    slist_free_cb(addrs, (slist_free_t)scamper_addr_free);
  if(addr != NULL)
    scamper_addr_free(addr);
  if(pd != NULL)
    scamper_dealias_probedef_free(pd);
  return -1;
}

static int dealias_midardisc_round_args(scamper_dealias_midardisc_round_t *r,
					char *str, uint32_t probedefc)
{
  char *eptr;
  long long ll;

  if(str == NULL)
    return -1;

  /*
   * find the first colon, where the 'begin' parameter starts, and
   * convert the string prior to the colon to a timeval
   */
  string_nullterm_char(str, ':', &eptr);
  if(eptr == NULL)
    return -1;
  if(timeval_fromstr(&r->start, str, 1000000) != 0)
    return -1;

  /*
   * convert the next string to the 'begin' index value, ensuring the
   * index is terminated with a ':'
   */
  str = eptr;
  if(string_tollong(str, &ll, &eptr, 10) != 0 ||
     *eptr != ':' || ll < 0 || ll >= probedefc)
    return -1;
  eptr++;
  r->begin = (uint32_t)ll;

  /*
   * convert the next string to the 'end' index value, ensuring the
   * index is terminated with a '\0' and that the index is larger
   * than the begin index
   */
  str = eptr;
  if(string_tollong(str, &ll, &eptr, 10) != 0 ||
     *eptr != '\0' || ll < r->begin || ll > probedefc)
    return -1;
  r->end = (uint32_t)ll;

  return 0;
}

/*
 * dealias_alloc_midardisc
 *
 * process a midardisc measurement definition.  midardisc assumes at least
 * two probedefs and two rounds.
 */
static int dealias_alloc_midardisc(scamper_dealias_t *d, dealias_options_t *o,
				   char *errbuf, size_t errlen)
{
  static const char *meth = "midardisc";
  scamper_dealias_midardisc_t *md = NULL;
  scamper_dealias_probedef_t *pd = NULL;
  scamper_dealias_midardisc_round_t *round = NULL;
  slist_node_t *sn;
  uint32_t i;
  char *pdstr;
  int probedefc;

  if(o->probedefs == NULL || slist_count(o->probedefs) < 2 ||
     o->sched == NULL || slist_count(o->sched) < 2 ||
     o->addr != NULL || o->xs != NULL ||
     o->nobs != 0 || o->replyc != 0 || o->inseq != 0 ||
     timeval_iszero(&o->wait_probe) == 0 ||
     timeval_iszero(&o->wait_round) == 0)
    {
      snprintf(errbuf, errlen, "invalid parameters for %s", meth);
      goto err;
    }

  if(timeval_iszero(&o->wait_timeout))
    o->wait_timeout.tv_sec = 1;

  probedefc = slist_count(o->probedefs);
  if((md = scamper_dealias_midardisc_alloc()) == NULL ||
     scamper_dealias_midardisc_probedefs_alloc(md, probedefc) != 0)
    {
      snprintf(errbuf, errlen, "could not alloc %s structure", meth);
      goto err;
    }
  md->probedefc = probedefc;

  i = 0;
  for(sn=slist_head_node(o->probedefs); sn != NULL; sn=slist_node_next(sn))
    {
      /* for now, do not support indir method */
      pdstr = (char *)slist_node_item(sn);
      if((pd = scamper_dealias_probedef_alloc()) == NULL)
	{
	  snprintf(errbuf, errlen, "could not alloc %s probedef", meth);
	  goto err;
	}
      if(dealias_probedef_args(pd, pdstr, errbuf, errlen) != 0)
	goto err;
      if(pd->dst == NULL)
	{
	  snprintf(errbuf, errlen, "expected dst in %s probedef", meth);
	  goto err;
	}
      if(probedef_size_check(pd, errbuf, errlen) != 0)
	goto err;

      if(pd->ttl == 0)
	pd->ttl = 64;
      md->probedefs[i] = pd;
      pd->id = i++;
      pd = NULL;
    }

  /* get the schedule */
  md->schedc = slist_count(o->sched);
  if(scamper_dealias_midardisc_sched_alloc(md, md->schedc) != 0)
    {
      snprintf(errbuf, errlen, "could not alloc %s schedule", meth);
      goto err;
    }
  i = 0;
  for(sn=slist_head_node(o->sched); sn != NULL; sn=slist_node_next(sn))
    {
      if((round = scamper_dealias_midardisc_round_alloc()) == NULL)
	{
	  snprintf(errbuf, errlen, "could not alloc %s round item", meth);
	  goto err;
	}
      if(dealias_midardisc_round_args(round, (char *)slist_node_item(sn),
				      md->probedefc) != 0)
	{
	  snprintf(errbuf, errlen, "malformed %s round %u", meth, i);
	  goto err;
	}
      if(i > 0 && (md->sched[i-1]->begin > round->begin ||
		   md->sched[i-1]->end > round->end ||
		   timeval_cmp(&md->sched[i-1]->start, &round->start) >= 0))
	{
	  snprintf(errbuf, errlen, "invalid round given round %u", i);
	  goto err;
	}
      md->sched[i++] = round;
      round = NULL;
    }

  if(timeval_iszero(&o->startat) == 0 &&
     (md->startat = memdup(&o->startat, sizeof(struct timeval))) == NULL)
    {
      snprintf(errbuf, errlen, "could not set startat time");
      goto err;
    }
  timeval_cpy(&md->wait_timeout, &o->wait_timeout);
  d->data = md;

  return 0;

 err:
  if(pd != NULL)
    scamper_dealias_probedef_free(pd);
  if(round != NULL)
    scamper_dealias_midardisc_round_free(round);
  if(md != NULL)
    scamper_dealias_midardisc_free(md);
  return -1;
}

/*
 * scamper_do_dealias_alloc
 *
 * given a string representing a dealias task, parse the parameters and
 * assemble a dealias.  return the dealias structure so that it is all ready
 * to go.
 */
void *scamper_do_dealias_alloc(char *str, char *errbuf, size_t errlen)
{
  static int (*const alloc_func[])(scamper_dealias_t *, dealias_options_t *,
				   char *, size_t) = {
    dealias_alloc_mercator,
    dealias_alloc_ally,
    dealias_alloc_radargun,
    dealias_alloc_prefixscan,
    dealias_alloc_bump,
    dealias_alloc_midarest,
    dealias_alloc_midardisc,
  };
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_dealias_t *dealias = NULL;
  dealias_options_t o;
  uint8_t  method = SCAMPER_DEALIAS_METHOD_MERCATOR;
  uint32_t userid = 0;
  long long tmp = 0;
  char buf[256];

#ifndef NDEBUG
  errbuf[0] = '\0';
#endif

  memset(&o, 0, sizeof(o));

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &o.addr) != 0)
    {
      snprintf(errbuf, errlen, "could not parse command");
      goto err;
    }

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 dealias_arg_param_validate(opt->id, opt->str, &tmp,
				    buf, sizeof(buf)) != 0)
	{
	  snprintf(errbuf, errlen, "-%c failed: %s",
		   scamper_options_id2c(opts, opts_cnt, opt->id), buf);
	  goto err;
	}

      switch(opt->id)
	{
	case DEALIAS_OPT_METHOD:
	  method = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_USERID:
	  userid = (uint32_t)tmp;
	  break;

	case DEALIAS_OPT_OPTION:
	  if(strcasecmp(opt->str, "nobs") == 0)
	    o.nobs = 1;
	  else if(strcasecmp(opt->str, "shuffle") == 0)
	    o.shuffle = 1;
	  else if(strcasecmp(opt->str, "inseq") == 0)
	    o.inseq = 1;
	  else
	    {
	      snprintf(errbuf, errlen, "unknown option");
	      goto err;
	    }
	  break;

	case DEALIAS_OPT_ATTEMPTS:
	  o.attempts = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_FUDGE:
	  o.fudge = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_PROBEDEF:
	  if((o.probedefs == NULL && (o.probedefs = slist_alloc()) == NULL) ||
	     slist_tail_push(o.probedefs, opt->str) == NULL)
	    {
	      snprintf(errbuf, errlen, "could not record probedef");
	      goto err;
	    }
	  break;

	case DEALIAS_OPT_WAIT_TIMEOUT:
	  o.wait_timeout.tv_sec = tmp / 1000000;
	  o.wait_timeout.tv_usec = tmp % 1000000;
	  break;

	case DEALIAS_OPT_WAIT_PROBE:
	  o.wait_probe.tv_sec = tmp / 1000000;
	  o.wait_probe.tv_usec = tmp % 1000000;
	  break;

	case DEALIAS_OPT_WAIT_ROUND:
	  o.wait_round.tv_sec = tmp / 1000000;
	  o.wait_round.tv_usec = tmp % 1000000;
	  break;

	case DEALIAS_OPT_STARTAT:
	  o.startat.tv_sec = tmp / 1000000;
	  o.startat.tv_usec = tmp % 1000000;
	  break;

	case DEALIAS_OPT_EXCLUDE:
	  if((o.xs == NULL && (o.xs = slist_alloc()) == NULL) ||
	     slist_tail_push(o.xs, opt->str) == NULL)
	    {
	      snprintf(errbuf, errlen, "could not record exclude option");
	      goto err;
	    }
	  break;

	case DEALIAS_OPT_SCHED:
	  if((o.sched == NULL && (o.sched = slist_alloc()) == NULL) ||
	     slist_tail_push(o.sched, opt->str) == NULL)
	    {
	      snprintf(errbuf, errlen, "could not record schedule item");
	      goto err;
	    }
	  break;

	case DEALIAS_OPT_REPLYC:
	  o.replyc = (uint8_t)tmp;
	  break;

	default:
	  goto err;
	}
    }

  scamper_options_free(opts_out);
  opts_out = NULL;

  if((dealias = scamper_dealias_alloc()) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc dealias structure");
      goto err;
    }
  dealias->method = method;
  dealias->userid = userid;

  assert(method >= 1 && method <= SCAMPER_DEALIAS_METHOD_MAX);
  if(alloc_func[method-1](dealias, &o, errbuf, errlen) != 0)
    goto err;

  if(o.sched != NULL)
    slist_free(o.sched);
  if(o.probedefs != NULL)
    slist_free(o.probedefs);
  if(o.xs != NULL)
    slist_free(o.xs);

  assert(errbuf[0] == '\0');
  return dealias;

 err:
  assert(errbuf[0] != '\0');
  if(opts_out != NULL) scamper_options_free(opts_out);
  if(o.probedefs != NULL) slist_free(o.probedefs);
  if(o.sched != NULL) slist_free(o.sched);
  if(dealias != NULL) scamper_dealias_free(dealias);
  if(o.xs != NULL) slist_free(o.xs);
  return NULL;
}

/*
 * scamper_do_dealias_arg_validate
 *
 *
 */
int scamper_do_dealias_arg_validate(int argc, char *argv[], int *stop,
				    char *errbuf, size_t errlen)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  errbuf, errlen, dealias_arg_param_validate);
}
