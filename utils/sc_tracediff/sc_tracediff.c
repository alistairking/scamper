/*
 * sc_tracediff
 *
 * $Id: sc_tracediff.c,v 1.17 2023/08/27 06:39:31 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2011 The University of Waikato
 * Copyright (C) 2023 Matthew Luckie
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

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_file.h"
#include "trace/scamper_trace.h"
#include "mjl_splaytree.h"
#include "utils.h"

#define OPT_NAMES    0x0001
#define OPT_ALLPAIRS 0x0002

#define MATCH_DST       0
#define MATCH_USERID    1
#define MATCH_DSTUSERID 2

typedef struct tracepair
{
  scamper_trace_t  *traces[2];
  int               tracec;
  splaytree_node_t *node;
} tracepair_t;

static splaytree_t  *pairs = NULL;
static char        **files = NULL;
static int           filec = 0;
static uint32_t      options = 0;
static int           match = MATCH_DST;

static void usage(void)
{
  fprintf(stderr,
	  "usage: sc_tracediff [-an] [-m <match>] file1.warts file2.warts\n");
  return;
}

static int check_options(int argc, char *argv[])
{
  int i;

  while((i = getopt(argc, argv, "am:n?")) != -1)
    {
      switch(i)
	{
	case 'a':
	  options |= OPT_ALLPAIRS;
	  break;

	case 'm':
	  if(strcasecmp(optarg, "dst") == 0)
	    match = MATCH_DST;
	  else if(strcasecmp(optarg, "userid") == 0)
	    match = MATCH_USERID;
	  else if(strcasecmp(optarg, "dstuserid") == 0)
	    match = MATCH_DSTUSERID;
	  else
	    return -1;
	  break;

	case 'n':
	  options |= OPT_NAMES;
	  break;

	case '?':
	default:
	  usage();
	  return -1;
	}
    }

  filec = argc - optind;
  if(filec != 2)
    {
      usage();
      return -1;
    }
  files = argv + optind;

  return 0;
}

static char *addr_toname(const scamper_addr_t *addr, char *buf, size_t len)
{
  const void *va = scamper_addr_addr_get(addr);
  struct sockaddr *sa = NULL;
  struct sockaddr_in in4;
  struct sockaddr_in6 in6;
  socklen_t sl;

  if(scamper_addr_isipv4(addr))
    {
      sockaddr_compose((struct sockaddr *)&in4, AF_INET, va, 0);
      sa = (struct sockaddr *)&in4;
    }
  else if(scamper_addr_isipv6(addr))
    {
      sockaddr_compose((struct sockaddr *)&in6, AF_INET6, va, 0);
      sa = (struct sockaddr *)&in6;
    }

  if(sa == NULL)
    return NULL;
  sl = sockaddr_len(sa);

  if(getnameinfo(sa, sl, buf, len, NULL, 0, NI_NAMEREQD) != 0)
    return NULL;

  return buf;
}

static char *hop_tostr(const scamper_trace_t *trace, int i,
		       char *buf, size_t *len_out)
{
  const scamper_trace_hop_t *hop;
  scamper_addr_t *hop_addr;
  char addr[128];
  size_t len = *len_out, off = 0;
  uint8_t icmp_type, icmp_code;

  if(i < scamper_trace_firsthop_get(trace)-1 ||
     scamper_trace_hop_count_get(trace) <= i)
    {
      string_concat(buf, len, &off, "-");
      goto done;
    }
  else if((hop = scamper_trace_hop_get(trace, i)) == NULL)
    {
      string_concat(buf, len, &off, "*");
      goto done;
    }

  hop_addr = scamper_trace_hop_addr_get(hop);
  if((options & OPT_NAMES) == 0 ||
     addr_toname(hop_addr, addr, sizeof(addr)) == NULL)
    scamper_addr_tostr(hop_addr, addr, sizeof(addr));

  string_concat(buf, len, &off, "%s", addr);

  if(scamper_trace_hop_is_icmp_ttl_exp(hop) ||
     scamper_trace_hop_is_icmp_echo_reply(hop) ||
     scamper_trace_hop_is_tcp(hop))
    {
      goto done;
    }

  icmp_type = scamper_trace_hop_icmp_type_get(hop);
  icmp_code = scamper_trace_hop_icmp_code_get(hop);
  if(scamper_addr_isipv4(hop_addr))
    {
      if(icmp_type == ICMP_UNREACH)
	{
	  if(icmp_code == ICMP_UNREACH_FILTER_PROHIB)
	    string_concat(buf, len, &off, " !X");
	  else if(icmp_code == ICMP_UNREACH_HOST)
	    string_concat(buf, len, &off, " !H");
	  else if(icmp_code == ICMP_UNREACH_NEEDFRAG)
	    string_concat(buf, len, &off, " !F");
	  else if(icmp_code == ICMP_UNREACH_SRCFAIL)
	    string_concat(buf, len, &off, " !S");
	  else if(icmp_code == ICMP_UNREACH_PROTOCOL)
	    string_concat(buf, len, &off, " !P");
	  else if(icmp_code == ICMP_UNREACH_NET)
	    string_concat(buf, len, &off, " !N");
	  else if(icmp_code != ICMP_UNREACH_PORT)
	    string_concat(buf, len, &off, " !<%d>", icmp_code);
	}
      else
	{
	  string_concat(buf, len, &off, " !<%d,%d>", icmp_type, icmp_code);
	}
    }
  else if(scamper_addr_isipv6(hop_addr))
    {
      if(icmp_type == ICMP6_DST_UNREACH)
	{
	  if(icmp_code == ICMP6_DST_UNREACH_ADDR)
	    string_concat(buf, len, &off, " !A");
	  else if(icmp_code == ICMP6_DST_UNREACH_BEYONDSCOPE)
	    string_concat(buf, len, &off, " !S");
	  else if(icmp_code == ICMP6_DST_UNREACH_ADMIN)
	    string_concat(buf, len, &off, " !P");
	  else if(icmp_code == ICMP6_DST_UNREACH_NOROUTE)
	    string_concat(buf, len, &off, " !N");
	  else if(icmp_code != ICMP6_DST_UNREACH_NOPORT)
	    string_concat(buf, len, &off, " !<%d>", icmp_code);
	}
      else if(icmp_type == ICMP6_PACKET_TOO_BIG)
	{
	  string_concat(buf, len, &off, " !F");
	}
      else
	{
	  string_concat(buf, len, &off, " !<%d,%d>", icmp_type, icmp_code);
	}
    }

 done:
  *len_out = off;
  return buf;
}

static void tracepair_onremove(tracepair_t *pair)
{
  pair->node = NULL;
  return;
}

static void tracepair_free(tracepair_t *pair)
{
  int i;

  for(i=0; i<filec; i++)
    if(pair->traces[i] != NULL)
      scamper_trace_free(pair->traces[i]);
  free(pair);

  return;
}

static int match_dst(const scamper_trace_t *a, const scamper_trace_t *b)
{
  return scamper_addr_cmp(scamper_trace_dst_get(a), scamper_trace_dst_get(b));
}

static int match_userid(const scamper_trace_t *a, const scamper_trace_t *b)
{
  uint32_t au = scamper_trace_userid_get(a);
  uint32_t bu = scamper_trace_userid_get(b);
  if(au < bu) return -1;
  if(au > bu) return  1;
  return 0;
}

static int match_dstuserid(const scamper_trace_t *a, const scamper_trace_t *b)
{
  int i;
  if((i = match_dst(a, b)) != 0)
    return i;
  return match_userid(a, b);
}

static int tracepair_cmp(const tracepair_t *tpa, const tracepair_t *tpb)
{
  static int (*const mf[])(const scamper_trace_t *,const scamper_trace_t *) = {
    match_dst,
    match_userid,
    match_dstuserid,
  };
  const scamper_trace_t *a = NULL, *b = NULL;
  int i;

  for(i=0; i<filec; i++)
    {
      if(tpa->traces[i] != NULL)
	{
	  a = tpa->traces[i];
	  break;
	}
    }
  assert(i != filec);
  assert(a != NULL);

  for(i=0; i<filec; i++)
    {
      if(tpb->traces[i] != NULL)
	{
	  b = tpb->traces[i];
	  break;
	}
    }
  assert(i != filec);
  assert(b != NULL);

  return mf[match](a, b);
}

static void tracepair_dump(const tracepair_t *pair)
{
  const struct timeval *tv;
  scamper_trace_t *trace;
  scamper_addr_t *dst;
  struct tm *tm;
  time_t tt;
  uint8_t min_ttl, max_ttl, firsthop;
  uint16_t hop_count;
  int i, k;
  size_t w, ws[2];
  char fs[32], a[256], b[256];

  /* there needs to be two traces for a pairwise comparison */
  if(pair->tracec != 2)
    return;

  /* print the header of the traceroute */
  trace = pair->traces[0];
  dst = scamper_trace_dst_get(trace);
  for(i=1; i<pair->tracec; i++)
    if(scamper_addr_cmp(dst, scamper_trace_dst_get(pair->traces[i])) != 0)
      break;
  w = 0;
  string_concat(a, sizeof(a), &w, "traceroute ");
  if(i == pair->tracec)
    string_concat(a, sizeof(a), &w, "from %s ",
		  scamper_addr_tostr(scamper_trace_src_get(trace),b,sizeof(b)));
  string_concat(a, sizeof(a), &w, "to %s",
		scamper_addr_tostr(dst, b, sizeof(b)));
  if(options & OPT_NAMES && addr_toname(dst, b, sizeof(b)) != NULL)
    string_concat(a, sizeof(a), &w, " (%s)", b);
  printf("%s\n", a);

  max_ttl = 0;
  min_ttl = 0;
  for(k=0; k<pair->tracec; k++)
    {
      trace = pair->traces[k];
      hop_count = scamper_trace_hop_count_get(trace);
      if(max_ttl < hop_count)
	max_ttl = hop_count;
      firsthop = scamper_trace_firsthop_get(trace);
      if(min_ttl == 0 || min_ttl > firsthop)
	min_ttl = firsthop;
    }

  for(k=0; k<pair->tracec; k++)
    {
      ws[k] = 8;
      trace = pair->traces[0];
      hop_count = scamper_trace_hop_count_get(trace);
      for(i=0; i<hop_count; i++)
	{
	  w = sizeof(a);
	  hop_tostr(trace, i, a, &w);
	  if(w > ws[k])
	    ws[k] = w;
	}
    }

  snprintf(fs, sizeof(fs), "   %%-%ds %%-%ds\n", (int)ws[0], (int)ws[1]);
  tv = scamper_trace_start_get(pair->traces[0]);
  tt = tv->tv_sec; tm = localtime(&tt);
  snprintf(a, sizeof(a), "%02d:%02d:%02d",tm->tm_hour,tm->tm_min,tm->tm_sec);
  tv = scamper_trace_start_get(pair->traces[1]);
  tt = tv->tv_sec; tm = localtime(&tt);
  snprintf(b, sizeof(b), "%02d:%02d:%02d",tm->tm_hour,tm->tm_min,tm->tm_sec);
  printf(fs, a, b);

  snprintf(fs, sizeof(fs), "%%2d %%-%ds %%-%ds\n", (int)ws[0], (int)ws[1]);
  for(i=min_ttl-1; i<max_ttl; i++)
    {
      ws[0] = sizeof(a); ws[1] = sizeof(b);
      printf(fs, i+1,
	     hop_tostr(pair->traces[0], i, a, &ws[0]),
	     hop_tostr(pair->traces[1], i, b, &ws[1]));
    }

  return;
}

static int tracepair_isdiff(const tracepair_t *pair)
{
  const scamper_trace_hop_t *a_hop, *b_hop;
  scamper_trace_t *a = pair->traces[0];
  scamper_trace_t *b = pair->traces[1];
  scamper_trace_t *x = NULL;
  uint16_t a_hopc = scamper_trace_hop_count_get(a);
  uint16_t b_hopc = scamper_trace_hop_count_get(b);
  uint16_t x_hopc;
  int i, hopc;

  if(a_hopc < b_hopc)
    hopc = a_hopc;
  else
    hopc = b_hopc;

  for(i=0; i<hopc; i++)
    {
      if((a_hop = scamper_trace_hop_get(a, i)) == NULL ||
	 (b_hop = scamper_trace_hop_get(b, i)) == NULL)
	continue;
      if(scamper_trace_hop_addr_cmp(a_hop, b_hop) != 0)
	return 1;
    }

  if(hopc < a_hopc)
    x = a;
  else if(hopc < b_hopc)
    x = b;

  if(x != NULL)
    {
      x_hopc = scamper_trace_hop_count_get(x);
      for(i=hopc; i<x_hopc; i++)
	if(scamper_trace_hop_get(x, i) != NULL)
	  return 1;
    }

  return 0;
}

static void tracepair_process(const tracepair_t *pair)
{
  if((options & OPT_ALLPAIRS) || tracepair_isdiff(pair))
    tracepair_dump(pair);
  return;
}

int main(int argc, char *argv[])
{
  scamper_file_t *file[2];
  scamper_file_filter_t *filter;
  scamper_trace_t *trace;
  tracepair_t *pair, fm;
  uint16_t type = SCAMPER_FILE_OBJ_TRACE;
  char buf[256];
  int i, filec_open;

#ifdef HAVE_WSASTARTUP
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2,2), &wsaData);
#endif

  if(check_options(argc, argv) != 0)
    goto err;

  if((filter = scamper_file_filter_alloc(&type, 1)) == NULL)
    {
      fprintf(stderr, "could not allocate filter\n");
      goto err;
    }

  memset(file, 0, sizeof(file));
  for(i=0; i<filec; i++)
    {
      if((file[i] = scamper_file_open(files[i], 'r', NULL)) == NULL)
	{
	  fprintf(stderr, "could not open %s\n", files[i]);
	  goto err;
	}
    }
  filec_open = filec;

  if((pairs = splaytree_alloc((splaytree_cmp_t)tracepair_cmp)) == NULL)
    {
      fprintf(stderr, "could not alloc tracepair tree\n");
      goto err;
    }
  splaytree_onremove(pairs, (splaytree_onremove_t)tracepair_onremove);

  while(filec_open != 0)
    {
      for(i=0; i<filec; i++)
	{
	  if(file[i] == NULL)
	    continue;

	  if(scamper_file_read(file[i], filter, &type, (void *)&trace) != 0)
	    {
	      fprintf(stderr, "could not read from %s\n", files[i]);
	      goto err;
	    }

	  if(trace == NULL)
	    {
	      filec_open--;
	      scamper_file_close(file[i]);
	      file[i] = NULL;
	      continue;
	    }
	  assert(type == SCAMPER_FILE_OBJ_TRACE);

	  fm.tracec = 1;
	  fm.traces[0] = trace;

	  if((pair = splaytree_find(pairs, &fm)) == NULL)
	    {
	      if((pair = malloc_zero(sizeof(tracepair_t))) == NULL)
		goto err;
	      pair->traces[i] = trace;
	      pair->tracec = 1;
	      if((pair->node = splaytree_insert(pairs, pair)) == NULL)
		goto err;
	    }
	  else
	    {
	      if(pair->traces[i] != NULL)
		{
		  scamper_addr_tostr(scamper_trace_dst_get(trace),
				     buf, sizeof(buf));
		  fprintf(stderr, "repeated trace for %s\n", buf);
		  goto err;
		}
	      pair->traces[i] = trace;
	      pair->tracec++;
	    }

	  if(pair->tracec != filec)
	    continue;

	  splaytree_remove_node(pairs, pair->node);
	  tracepair_process(pair);
	  tracepair_free(pair);
	}
    }

  return 0;

 err:
  return -1;
}
