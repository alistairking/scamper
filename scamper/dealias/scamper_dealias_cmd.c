/*
 * scamper_dealias_cmd.c
 *
 * $Id: scamper_dealias_cmd.c,v 1.1.4.1 2023/08/07 22:48:51 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012-2013 Matthew Luckie
 * Copyright (C) 2012-2014 The Regents of the University of California
 * Copyright (C) 2016-2023 Matthew Luckie
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
#include "scamper_options.h"
#include "scamper_debug.h"
#include "scamper.h"
#include "mjl_list.h"
#include "utils.h"

typedef struct dealias_options
{
  char                        *addr;
  uint8_t                      attempts;
  uint8_t                      replyc;
  uint8_t                      wait_timeout;
  uint16_t                     wait_probe;
  uint32_t                     wait_round;
  uint16_t                     sport;
  uint16_t                     dport;
  uint8_t                      ttl;
  uint16_t                     fudge;
  slist_t                     *probedefs;
  slist_t                     *xs;
  int                          nobs;
  int                          shuffle;
  int                          inseq;
} dealias_options_t;

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

#define DEALIAS_OPT_DPORT        1
#define DEALIAS_OPT_FUDGE        2
#define DEALIAS_OPT_METHOD       3
#define DEALIAS_OPT_REPLYC       4
#define DEALIAS_OPT_OPTION       5
#define DEALIAS_OPT_PROBEDEF     6
#define DEALIAS_OPT_ATTEMPTS     7
#define DEALIAS_OPT_WAIT_ROUND   8
#define DEALIAS_OPT_SPORT        9
#define DEALIAS_OPT_TTL          10
#define DEALIAS_OPT_USERID       11
#define DEALIAS_OPT_WAIT_TIMEOUT 12
#define DEALIAS_OPT_WAIT_PROBE   13
#define DEALIAS_OPT_EXCLUDE      14

static const scamper_option_in_t opts[] = {
  {'d', NULL, DEALIAS_OPT_DPORT,        SCAMPER_OPTION_TYPE_NUM},
  {'f', NULL, DEALIAS_OPT_FUDGE,        SCAMPER_OPTION_TYPE_NUM},
  {'m', NULL, DEALIAS_OPT_METHOD,       SCAMPER_OPTION_TYPE_STR},
  {'o', NULL, DEALIAS_OPT_REPLYC,       SCAMPER_OPTION_TYPE_NUM},
  {'O', NULL, DEALIAS_OPT_OPTION,       SCAMPER_OPTION_TYPE_STR},
  {'p', NULL, DEALIAS_OPT_PROBEDEF,     SCAMPER_OPTION_TYPE_STR},
  {'q', NULL, DEALIAS_OPT_ATTEMPTS,     SCAMPER_OPTION_TYPE_NUM},
  {'r', NULL, DEALIAS_OPT_WAIT_ROUND,   SCAMPER_OPTION_TYPE_NUM},
  {'s', NULL, DEALIAS_OPT_SPORT,        SCAMPER_OPTION_TYPE_NUM},
  {'t', NULL, DEALIAS_OPT_TTL,          SCAMPER_OPTION_TYPE_NUM},
  {'U', NULL, DEALIAS_OPT_USERID,       SCAMPER_OPTION_TYPE_NUM},
  {'w', NULL, DEALIAS_OPT_WAIT_TIMEOUT, SCAMPER_OPTION_TYPE_NUM},
  {'W', NULL, DEALIAS_OPT_WAIT_PROBE,   SCAMPER_OPTION_TYPE_NUM},
  {'x', NULL, DEALIAS_OPT_EXCLUDE,      SCAMPER_OPTION_TYPE_STR},
};
static const int opts_cnt = SCAMPER_OPTION_COUNT(opts);

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
static const int probedef_opts_cnt = SCAMPER_OPTION_COUNT(probedef_opts);

const char *scamper_do_dealias_usage(void)
{
  return
    "dealias [-d dport] [-f fudge] [-m method] [-o replyc] [-O option]\n"
    "        [-p '[-c sum] [-d dp] [-F sp] [-i ip] [-M mtu] [-P meth] [-s size] [-t ttl]']\n"
    "        [-q attempts] [-r wait-round] [-s sport] [-t ttl]\n"
    "        [-U userid] [-w wait-timeout] [-W wait-probe] [-x exclude]\n";
}

static int dealias_arg_param_validate(int optid, char *param, long long *out)
{
  long tmp;

  switch(optid)
    {
    case DEALIAS_OPT_OPTION:
    case DEALIAS_OPT_PROBEDEF:
    case DEALIAS_OPT_EXCLUDE:
      tmp = 0;
      break;

    case DEALIAS_OPT_DPORT:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_FUDGE:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
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
      else
	return -1;
      break;

    case DEALIAS_OPT_ATTEMPTS:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 500)
	return -1;
      break;

    case DEALIAS_OPT_SPORT:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_TTL:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 255)
	return -1;
      break;

    case DEALIAS_OPT_USERID:
      if(string_tolong(param, &tmp) != 0 || tmp < 0)
	return -1;
      break;

    case DEALIAS_OPT_WAIT_TIMEOUT:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 255)
	return -1;
      break;

    case DEALIAS_OPT_WAIT_PROBE:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 65535)
	return -1;
      break;

    case DEALIAS_OPT_WAIT_ROUND:
      if(string_tolong(param, &tmp) != 0 || tmp < 1 || tmp > 180000)
	return -1;
      break;

    case DEALIAS_OPT_REPLYC:
      if(string_tolong(param, &tmp) != 0 || tmp < 3 || tmp > 255)
	return -1;
      break;

    default:
      scamper_debug(__func__, "unhandled optid %d", optid);
      return -1;
    }

  if(out != NULL)
    *out = (long long)tmp;
  return 0;
}

static int dealias_probedef_args(scamper_dealias_probedef_t *def, char *str)
{
  scamper_option_out_t *opts_out = NULL, *opt;
  uint16_t dport = 33435;
  uint16_t sport = scamper_sport_default();
  uint16_t csum  = 0;
  uint16_t options = 0;
  uint8_t  ttl   = 255;
  uint8_t  tos   = 0;
  uint16_t size  = 0;
  uint16_t mtu   = 0;
  char *end;
  long tmp;

  /* try and parse the string passed in */
  if(scamper_options_parse(str, probedef_opts, probedef_opts_cnt,
			   &opts_out, &end) != 0)
    {
      scamper_debug(__func__, "could not parse options");
      goto err;
    }

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      /* check for an option being used multiple times */
      if(options & (1<<(opt->id-1)))
	{
	  scamper_debug(__func__,"option %d specified multiple times",opt->id);
	  goto err;
	}

      options |= (1 << (opt->id-1));

      switch(opt->id)
	{
	case DEALIAS_PROBEDEF_OPT_CSUM:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 0 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid csum %s", opt->str);
	      goto err;
	    }
	  csum = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_DPORT:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid dport %s", opt->str);
	      goto err;
	    }
	  dport = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_IP:
	  def->dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, opt->str);
	  if(def->dst == NULL)
	    {
	      scamper_debug(__func__, "invalid dst ip %s", opt->str);
	      goto err;
	    }
	  break;

	case DEALIAS_PROBEDEF_OPT_MTU:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 100 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid mtu size %s", opt->str);
	      goto err;
	    }
	  mtu = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_PROTO:
	  if(strcasecmp(opt->str, "udp") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
	  else if(strcasecmp(opt->str, "tcp-ack") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK;
	  else if(strcasecmp(opt->str, "icmp-echo") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO;
	  else if(strcasecmp(opt->str, "tcp-ack-sport") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT;
	  else if(strcasecmp(opt->str, "udp-dport") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT;
	  else if(strcasecmp(opt->str, "tcp-syn-sport") == 0)
	    def->method = SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_SYN_SPORT;
	  else
	    {
	      scamper_debug(__func__, "invalid probe type %s", opt->str);
	      goto err;
	    }
	  break;

	case DEALIAS_PROBEDEF_OPT_SIZE:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 100 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid probe size %s", opt->str);
	      goto err;
	    }
	  size = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_SPORT:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 65535)
	    {
	      scamper_debug(__func__, "invalid sport %s", opt->str);
	      goto err;
	    }
	  sport = (uint16_t)tmp;
	  break;

	case DEALIAS_PROBEDEF_OPT_TTL:
	  if(string_tolong(opt->str, &tmp) != 0 || tmp < 1 || tmp > 255)
	    {
	      scamper_debug(__func__, "invalid ttl %s", opt->str);
	      goto err;
	    }
	  ttl = (uint8_t)tmp;
	  break;

	default:
	  scamper_debug(__func__, "unhandled optid %d", opt->id);
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
      scamper_debug(__func__, "invalid option string");
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
	  scamper_debug(__func__, "csum option not permitted for udp");
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
	  scamper_debug(__func__, "sport option not permitted for icmp");
	  goto err;
	}
      if(options & (1<<(DEALIAS_PROBEDEF_OPT_DPORT-1)))
	{
	  scamper_debug(__func__, "dport option not permitted for icmp");
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
	  scamper_debug(__func__, "csum option not permitted for tcp");
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
	  scamper_debug(__func__,"unhandled flags for method %d",def->method);
	  goto err;
	}
    }
  else
    {
      scamper_debug(__func__, "unhandled method %d", def->method);
      goto err;
    }

  return 0;

 err:
  if(opts_out != NULL) scamper_options_free(opts_out);
  return -1;
}

static int dealias_alloc_mercator(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_mercator_t *mercator;
  scamper_addr_t *dst = NULL;

  /* if there is no IP address after the options string, then stop now */
  if(o->addr == NULL)
    {
      scamper_debug(__func__, "missing target address for mercator");
      goto err;
    }
  if((dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, o->addr)) == NULL)
    {
      scamper_debug(__func__, "unable to resolve address for mercator");
      goto err;
    }

  if(o->probedefs != NULL || o->xs != NULL || o->wait_probe != 0 ||
     o->fudge != 0 || o->attempts > 3 || o->nobs != 0 || o->replyc != 0 ||
     o->shuffle != 0 || o->inseq != 0)
    {
      scamper_debug(__func__, "invalid parameters for mercator");
      goto err;
    }
  if(o->attempts == 0) o->attempts = 3;
  if(o->dport == 0)    o->dport    = 33435;
  if(o->sport == 0)    o->sport    = scamper_sport_default();
  if(o->ttl == 0)      o->ttl      = 255;

  if(scamper_dealias_mercator_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc mercator structure");
      goto err;
    }
  mercator = d->data;
  mercator->attempts              = o->attempts;
  mercator->wait_timeout          = o->wait_timeout;
  mercator->probedef.id           = 0;
  mercator->probedef.dst          = dst; dst = NULL;
  mercator->probedef.ttl          = o->ttl;
  mercator->probedef.method       = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
  mercator->probedef.un.udp.sport = o->sport;
  mercator->probedef.un.udp.dport = o->dport;

  return 0;

 err:
  if(dst != NULL) scamper_addr_free(dst);
  return -1;
}

static int dealias_alloc_ally(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_ally_t *ally = NULL;
  scamper_dealias_probedef_t pd[2];
  int i, probedefc = 0;
  slist_node_t *sn;
  uint8_t flags = 0;
  char *addr2;

  memset(&pd, 0, sizeof(pd));
  
  if(o->probedefs != NULL)
    probedefc = slist_count(o->probedefs);

  if(probedefc > 2 || o->xs != NULL || o->dport != 0 || o->sport != 0 ||
     o->ttl != 0 || o->replyc != 0 || o->shuffle != 0 ||
     (o->inseq != 0 && o->fudge != 0))
    {
      scamper_debug(__func__, "invalid parameters for ally");
      goto err;
    }

  if(o->wait_probe == 0) o->wait_probe = 150;
  if(o->attempts == 0)   o->attempts   = 5;

  if(o->fudge == 0 && o->inseq == 0)
    o->fudge = 200;

  if(probedefc > 0)
    {
      i = 0;
      for(sn=slist_head_node(o->probedefs); sn != NULL; sn=slist_node_next(sn))
	{
	  if(dealias_probedef_args(&pd[i], (char *)slist_node_item(sn)) != 0)
	    {
	      scamper_debug(__func__, "could not read ally probedef %d", i);
	      goto err;
	    }
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
	  scamper_debug(__func__, "dst IP specified incorrectly");
	  goto err;
	}
      memcpy(&pd[1], &pd[0], sizeof(scamper_dealias_probedef_t));
    }

  if(o->addr == NULL)
    {
      if(pd[0].dst == NULL || pd[1].dst == NULL)
	{
	  scamper_debug(__func__, "missing destination IP address");
	  goto err;
	}
    }
  else
    {
      if(pd[0].dst != NULL || pd[1].dst != NULL)
	{
	  scamper_debug(__func__, "dst IP specified inconsistently");
	  goto err;
	}

      /* make sure there are two addresses specified */
      if((addr2 = string_nextword(o->addr)) == NULL)
	{
	  scamper_debug(__func__, "missing second address");
	  goto err;
	}

      /* resolve each address */
      pd[0].dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, o->addr);
      if(pd[0].dst == NULL)
	{
	  printerror(__func__, "could not resolve %s", o->addr);
	  goto err;
	}
      pd[1].dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, addr2);
      if(pd[1].dst == NULL)
	{
	  printerror(__func__, "could not resolve %s", addr2);
	  goto err;
	}
    }

  if(pd[0].dst->type != pd[1].dst->type ||
     SCAMPER_ADDR_TYPE_IS_IP(pd[0].dst) == 0 ||
     SCAMPER_ADDR_TYPE_IS_IP(pd[1].dst) == 0)
    {
      scamper_debug(__func__, "dst IP specified incorrectly");
      goto err;
    }

  if(o->nobs != 0 || SCAMPER_ADDR_TYPE_IS_IPV6(pd[0].dst))
    flags |= SCAMPER_DEALIAS_ALLY_FLAG_NOBS;

  if(scamper_dealias_ally_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc ally structure");
      goto err;
    }
  ally = d->data;

  ally->attempts     = o->attempts;
  ally->wait_probe   = o->wait_probe;
  ally->wait_timeout = o->wait_timeout;
  ally->fudge        = o->fudge;
  ally->flags        = flags;

  for(i=0; i<2; i++)
    pd[i].id = i;

  memcpy(ally->probedefs, pd, sizeof(ally->probedefs));

  return 0;

 err:
  if(pd[0].dst != NULL) scamper_addr_free(pd[0].dst);
  if(pd[1].dst != NULL) scamper_addr_free(pd[1].dst);
  return -1;
}

static int dealias_alloc_radargun(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_radargun_t *rg;
  scamper_dealias_probedef_t *pd = NULL, pd0;
  slist_t *pd_list = NULL;
  slist_node_t *sn;
  uint32_t i, probedefc;
  uint8_t flags = 0;
  char *a1, *a2;
  int j, pdc = 0;

  memset(&pd0, 0, sizeof(pd0));

  if(o->xs != NULL || o->dport != 0 || o->sport != 0 ||
     o->ttl != 0 || o->nobs != 0 || o->replyc != 0 || o->inseq != 0)
    {
      scamper_debug(__func__, "invalid parameters for radargun");
      goto err;
    }

  if(o->probedefs != NULL)
    pdc = slist_count(o->probedefs);
  if(o->wait_probe == 0) o->wait_probe   = 150;
  if(o->attempts == 0)   o->attempts     = 30;
  if(o->wait_round == 0) o->wait_round   = pdc * o->wait_probe;
  if(o->shuffle != 0)
    flags |= SCAMPER_DEALIAS_RADARGUN_FLAG_SHUFFLE;

  if(pdc == 0)
    {
      pd0.ttl          = 255;
      pd0.method       = SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP;
      pd0.un.udp.sport = scamper_sport_default();
      pd0.un.udp.dport = 33435;
    }
  else if(pdc == 1)
    {
      if(dealias_probedef_args(&pd0, (char *)slist_head_item(o->probedefs))!=0)
	{
	  scamper_debug(__func__, "could not parse radargun probedef 0");
	  goto err;
	}
      if(pd0.dst != NULL || o->addr == NULL)
	{
	  scamper_debug(__func__, "dst addrs are specified after def");
	  goto err;
	}
    }

  if(pdc >= 2 && o->addr == NULL)
    {
      if((pd = malloc_zero(pdc * sizeof(scamper_dealias_probedef_t))) == NULL)
	{
	  scamper_debug(__func__, "could not malloc radargun pd");
	  goto err;
	}

      i = 0;
      for(sn=slist_head_node(o->probedefs); sn != NULL; sn=slist_node_next(sn))
	{
	  if(dealias_probedef_args(&pd[i], (char *)slist_node_item(sn)) != 0 ||
	     pd[i].dst == NULL)
	    {
	      scamper_debug(__func__, "could not parse radargun def %d", i);
	      goto err;
	    }
	  if(i != 0 && pd[0].dst->type != pd[i].dst->type)
	    {
	      scamper_debug(__func__, "mixed address families");
	      goto err;
	    }
	  pd[i].id = i;
	  i++;
	}
      probedefc = i;
    }
  else if(pdc < 2 && o->addr != NULL)
    {
      if((pd_list = slist_alloc()) == NULL)
	{
	  printerror(__func__, "could not alloc pd_list");
	  goto err;
	}
      a1 = o->addr; i = 0;
      for(;;)
	{
	  a2 = string_nextword(a1);
	  pd0.dst = scamper_addrcache_resolve(addrcache, AF_UNSPEC, a1);
	  if(pd0.dst == NULL)
	    goto err;
	  pd0.id = i++;
	  if((pd = memdup(&pd0, sizeof(pd0))) == NULL ||
	     slist_tail_push(pd_list, pd) == NULL)
	    goto err;
	  pd0.dst = NULL;
	  if(a2 == NULL)
	    break;
	  a1 = a2;
	}
      probedefc = slist_count(pd_list);
    }
  else goto err;

  if(scamper_dealias_radargun_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc radargun structure");
      goto err;
    }
  rg = d->data;

  if(scamper_dealias_radargun_probedefs_alloc(rg, probedefc) != 0)
    {
      scamper_debug(__func__, "could not alloc radargun probedefs");
      goto err;
    }

  rg->attempts     = o->attempts;
  rg->wait_probe   = o->wait_probe;
  rg->wait_timeout = o->wait_timeout;
  rg->wait_round   = o->wait_round;
  rg->probedefc    = probedefc;
  rg->flags        = flags;

  if(pd_list == NULL)
    {
      for(j=0; j<pdc; j++)
	memcpy(&rg->probedefs[j], &pd[j], sizeof(scamper_dealias_probedef_t));
    }
  else
    {
      i=0;
      while((pd = slist_head_pop(pd_list)) != NULL)
	{
	  memcpy(&rg->probedefs[i], pd, sizeof(scamper_dealias_probedef_t));
	  free(pd);
	  i++;
	}
      slist_free(pd_list); pd_list = NULL;
    }

  return 0;

 err:
  if(pd != NULL)
    {
      for(j=0; j<pdc; j++)
	if(pd[j].dst != NULL)
	  scamper_addr_free(pd[j].dst);
      free(pd);
    }
  if(pd_list != NULL)
    slist_free_cb(pd_list, (slist_free_t)scamper_dealias_probedef_free);
  if(pd0.dst != NULL)
    scamper_addr_free(pd0.dst);
  return -1;
}

static int dealias_alloc_prefixscan(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_prefixscan_t *prefixscan;
  scamper_dealias_probedef_t pd0;
  scamper_addr_t *dst = NULL;
  slist_node_t *sn;
  uint8_t flags = 0;
  uint8_t prefix;
  char *addr2 = NULL, *pfxstr, *xs;
  long tmp;
  int af;

  /* check the sanity of various parameters */
  if(o->probedefs == NULL || slist_count(o->probedefs) != 1 ||
     o->addr == NULL || o->dport != 0 || o->sport != 0 || o->ttl != 0 ||
     o->shuffle != 0 || (o->inseq != 0 && o->fudge != 0))
    {
      scamper_debug(__func__, "invalid parameters for prefixscan");
      goto err;
    }

  if(o->ttl == 0)        o->ttl        = 255;
  if(o->wait_probe == 0) o->wait_probe = 1000;
  if(o->attempts == 0)   o->attempts   = 2;
  if(o->replyc == 0)     o->replyc     = 5;

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
      scamper_debug(__func__, "missing second address");
      goto err;
    }

  string_nullterm_char(addr2, '/', &pfxstr);
  if(pfxstr == NULL)
    {
      scamper_debug(__func__, "missing prefix");
      goto err;
    }

  if(string_tolong(pfxstr, &tmp) != 0 || tmp < 24 || tmp >= 32)
    {
      scamper_debug(__func__, "invalid prefix %s", pfxstr);
      goto err;
    }
  prefix = (uint8_t)tmp;

  /* check the sanity of the probedef */
  memset(&pd0, 0, sizeof(pd0));
  if(dealias_probedef_args(&pd0, (char *)slist_head_item(o->probedefs)) != 0)
    {
      scamper_debug(__func__, "could not parse prefixscan probedef");
      goto err;
    }
  if(pd0.dst != NULL)
    {
      scamper_debug(__func__, "prefixscan ip address spec. in probedef");
      scamper_addr_free(pd0.dst); pd0.dst = NULL;
      goto err;
    }

  if(scamper_dealias_prefixscan_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc prefixscan structure");
      goto err;
    }
  prefixscan = d->data;

  prefixscan->attempts     = o->attempts;
  prefixscan->fudge        = o->fudge;
  prefixscan->wait_probe   = o->wait_probe;
  prefixscan->wait_timeout = o->wait_timeout;
  prefixscan->replyc       = o->replyc;
  prefixscan->prefix       = prefix;
  prefixscan->flags        = flags;

  /* resolve the two addresses now */
  prefixscan->a = scamper_addrcache_resolve(addrcache, AF_UNSPEC, o->addr);
  if(prefixscan->a == NULL)
    {
      scamper_debug(__func__, "could not resolve %s", o->addr);
      goto err;
    }
  af = scamper_addr_af(prefixscan->a);
  prefixscan->b = scamper_addrcache_resolve(addrcache, af, addr2);
  if(prefixscan->b == NULL)
    {
      scamper_debug(__func__, "could not resolve %s", addr2);
      goto err;
    }

  /* add the first probedef */
  if(scamper_dealias_prefixscan_probedefs_alloc(prefixscan, 1) != 0)
    {
      scamper_debug(__func__, "could not alloc prefixscan probedefs");
      goto err;
    }
  memcpy(prefixscan->probedefs, &pd0, sizeof(pd0));
  prefixscan->probedefs[0].dst = scamper_addr_use(prefixscan->a);
  prefixscan->probedefs[0].id  = 0;
  prefixscan->probedefc        = 1;

  /* resolve any addresses to exclude in the scan */
  if(o->xs != NULL)
    {
      for(sn = slist_head_node(o->xs); sn != NULL; sn = slist_node_next(sn))
	{
	  xs = slist_node_item(sn);
	  if((dst = scamper_addrcache_resolve(addrcache, af, xs)) == NULL)
	    {
	      scamper_debug(__func__, "could not resolve %s", xs);
	      goto err;
	    }
	  if(scamper_dealias_prefixscan_xs_add(d, dst) != 0)
	    {
	      scamper_debug(__func__, "could not add %s to xs", xs);
	      goto err;
	    }
	  scamper_addr_free(dst); dst = NULL;
	}
    }

  return 0;

 err:
  return -1;
}

static int dealias_alloc_bump(scamper_dealias_t *d, dealias_options_t *o)
{
  scamper_dealias_bump_t *bump = NULL;
  scamper_dealias_probedef_t pd[2];
  slist_node_t *sn;
  int i;

  memset(&pd, 0, sizeof(pd));

  if(o->probedefs == NULL || slist_count(o->probedefs) != 2 ||
     o->xs != NULL || o->dport != 0 || o->sport != 0 || o->ttl != 0 ||
     o->replyc != 0 || o->shuffle != 0 || o->addr != NULL ||
     (o->inseq != 0 && o->fudge != 0))
    {
      scamper_debug(__func__, "invalid parameters for bump");
      goto err;
    }

  if(o->wait_probe == 0) o->wait_probe = 1000;
  if(o->attempts == 0)   o->attempts   = 3;
  if(o->fudge == 0)      o->fudge      = 30; /* bump limit */

  i = 0;
  for(sn = slist_head_node(o->probedefs); sn != NULL; sn = slist_node_next(sn))
    {
      if(dealias_probedef_args(&pd[i], (char *)slist_node_item(sn)) != 0)
	{
	  scamper_debug(__func__, "could not read bump probedef %d", i);
	  goto err;
	}
      if(pd[i].dst == NULL)
	{
	  scamper_debug(__func__, "missing dst address in probedef %d", i);
	  goto err;
	}
      if(pd[i].dst->type != SCAMPER_ADDR_TYPE_IPV4)
	{
	  scamper_debug(__func__, "dst address not IPv4 in probedef %d", i);
	  goto err;
	}
      pd[i].id = i;
      i++;
    }

  if(scamper_dealias_bump_alloc(d) != 0)
    {
      scamper_debug(__func__, "could not alloc bump structure");
      goto err;
    }
  bump = d->data;

  bump->attempts     = o->attempts;
  bump->wait_probe   = o->wait_probe;
  bump->bump_limit   = o->fudge;
  memcpy(bump->probedefs, pd, sizeof(bump->probedefs));

  return 0;

 err:
  if(pd[0].dst != NULL) scamper_addr_free(pd[0].dst);
  if(pd[1].dst != NULL) scamper_addr_free(pd[1].dst);
  return -1;
}


/*
 * scamper_do_dealias_alloc
 *
 * given a string representing a dealias task, parse the parameters and
 * assemble a dealias.  return the dealias structure so that it is all ready
 * to go.
 */
void *scamper_do_dealias_alloc(char *str)
{
  static int (*const alloc_func[])(scamper_dealias_t *, dealias_options_t *) = {
    dealias_alloc_mercator,
    dealias_alloc_ally,
    dealias_alloc_radargun,
    dealias_alloc_prefixscan,
    dealias_alloc_bump,
  };
  scamper_option_out_t *opts_out = NULL, *opt;
  scamper_dealias_t *dealias = NULL;
  dealias_options_t o;
  uint8_t  method = SCAMPER_DEALIAS_METHOD_MERCATOR;
  uint32_t userid = 0;
  long long tmp = 0;

  memset(&o, 0, sizeof(o));

  /* try and parse the string passed in */
  if(scamper_options_parse(str, opts, opts_cnt, &opts_out, &o.addr) != 0)
    {
      scamper_debug(__func__, "could not parse command");
      goto err;
    }

  for(opt = opts_out; opt != NULL; opt = opt->next)
    {
      if(opt->type != SCAMPER_OPTION_TYPE_NULL &&
	 dealias_arg_param_validate(opt->id, opt->str, &tmp) != 0)
	{
	  scamper_debug(__func__, "validation of optid %d failed", opt->id);
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
	      scamper_debug(__func__, "unknown option %s", opt->str);
	      goto err;
	    }
	  break;

	case DEALIAS_OPT_ATTEMPTS:
	  o.attempts = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_DPORT:
	  o.dport = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_SPORT:
	  o.sport = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_FUDGE:
	  o.fudge = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_TTL:
	  o.ttl = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_PROBEDEF:
	  if(o.probedefs == NULL && (o.probedefs = slist_alloc()) == NULL)
	    {
	      printerror(__func__, "could not alloc probedefs");
	      goto err;
	    }
	  if(slist_tail_push(o.probedefs, opt->str) == NULL)
	    {
	      printerror(__func__, "could not push probedef");
	      goto err;
	    }
	  break;

	case DEALIAS_OPT_WAIT_TIMEOUT:
	  o.wait_timeout = (uint8_t)tmp;
	  break;

	case DEALIAS_OPT_WAIT_PROBE:
	  o.wait_probe = (uint16_t)tmp;
	  break;

	case DEALIAS_OPT_WAIT_ROUND:
	  o.wait_round = (uint32_t)tmp;
	  break;

	case DEALIAS_OPT_EXCLUDE:
	  if(o.xs == NULL && (o.xs = slist_alloc()) == NULL)
	    {
	      printerror(__func__, "could not alloc xs");
	      goto err;
	    }
	  if(slist_tail_push(o.xs, opt->str) == NULL)
	    {
	      printerror(__func__, "could not push xs");
	      goto err;
	    }
	  break;

	case DEALIAS_OPT_REPLYC:
	  o.replyc = (uint8_t)tmp;
	  break;

	default:
	  scamper_debug(__func__, "unhandled option %d", opt->id);
	  goto err;
	}
    }

  scamper_options_free(opts_out);
  opts_out = NULL;

  if(o.wait_timeout == 0)
    o.wait_timeout = 5;

  if((dealias = scamper_dealias_alloc()) == NULL)
    {
      scamper_debug(__func__, "could not alloc dealias structure");
      goto err;
    }
  dealias->method = method;
  dealias->userid = userid;

  assert(method >= 1 && method <= 5);
  if(alloc_func[method-1](dealias, &o) != 0)
    goto err;

  if(o.probedefs != NULL)
    slist_free(o.probedefs);
  if(o.xs != NULL)
    slist_free(o.xs);

  return dealias;

 err:
  if(opts_out != NULL) scamper_options_free(opts_out);
  if(o.probedefs != NULL) slist_free(o.probedefs);
  if(dealias != NULL) scamper_dealias_free(dealias);
  return NULL;
}

/*
 * scamper_do_dealias_arg_validate
 *
 *
 */
int scamper_do_dealias_arg_validate(int argc, char *argv[], int *stop)
{
  return scamper_options_validate(opts, opts_cnt, argc, argv, stop,
				  dealias_arg_param_validate);
}
