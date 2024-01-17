/*
 * sc_ttlexp: dump all unique source IP addresses in TTL expired messages
 *
 * $Id: sc_ttlexp.c,v 1.14 2023/08/27 06:39:31 mjl Exp $
 *
 *         Matthew Luckie
 *         mjl@luckie.org.nz
 *
 * Copyright (C) 2017-2023 Matthew Luckie
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
#include "scamper_list.h"
#include "trace/scamper_trace.h"
#include "tracelb/scamper_tracelb.h"
#include "scamper_file.h"
#include "mjl_splaytree.h"

static splaytree_t *st_ip4 = NULL;
static splaytree_t *st_ip6 = NULL;
static int         no_dst = 0;
static int         no_reserved = 0;
static char      **files  = NULL;
static int         filec  = 0;

static void usage(void)
{
  fprintf(stderr,
	  "usage: sc_ttlexp [-O options] file1 .. fileN\n");

  fprintf(stderr, "   -O options\n");
  fprintf(stderr, "      nodst: do not include IP if same as dst probed\n");
  fprintf(stderr, "      noreserved: do not include reserved IP addresses\n");
  return;
}

static int check_options(int argc, char *argv[])
{
  int ch;
  char *opts = "?O:";

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'O':
	  if(strcasecmp(optarg, "nodst") == 0)
	    no_dst = 1;
	  else if(strcasecmp(optarg, "noreserved") == 0)
	    no_reserved = 1;
	  else
	    return -1;
	  break;

	case '?':
	  usage();
	  return -1;

	default:
	  return -1;
	}
    }

  files = argv + optind;
  filec = argc - optind;

  return 0;
}

static int dump_addr(scamper_addr_t *addr)
{
  scamper_addr_t *a = NULL;
  char b[128];
  int rc = -1;

  if(no_reserved != 0 && scamper_addr_isreserved(addr) == 1)
    return 0;

  if(scamper_addr_isipv4(addr))
    {
      if(splaytree_find(st_ip4, addr) != NULL)
	return 0;
      printf("%s\n", scamper_addr_tostr(addr, b, sizeof(b)));
      a = scamper_addr_use(addr);
      if(splaytree_insert(st_ip4, a) == NULL)
	goto done;
    }
  else if(scamper_addr_isipv6(addr))
    {
      if(splaytree_find(st_ip6, addr) != NULL)
	return 0;
      printf("%s\n", scamper_addr_tostr(addr, b, sizeof(b)));
      a = scamper_addr_use(addr);
      if(splaytree_insert(st_ip6, a) == NULL)
	goto done;
    }
  rc = 0;

 done:
  if(rc != 0 && a != NULL) scamper_addr_free(a);
  return rc;
}

static int dump_tracelb(scamper_tracelb_t *trace)
{
  const scamper_tracelb_link_t *link;
  const scamper_tracelb_node_t *node;
  const scamper_tracelb_probe_t *probe;
  const scamper_tracelb_reply_t *reply;
  const scamper_tracelb_probeset_t *set;
  scamper_addr_t *dst, *from;
  uint16_t i, j, k, l, m, nodec, linkc, hopc, probec, rxc;
  int rc = -1;

  nodec = scamper_tracelb_nodec_get(trace);
  dst = scamper_tracelb_dst_get(trace);
  for(i=0; i<nodec; i++)
    {
      node = scamper_tracelb_node_get(trace, i);
      linkc = scamper_tracelb_node_linkc_get(node);
      for(j=0; j<linkc; j++)
	{
	  link = scamper_tracelb_node_link_get(node, j);
	  hopc = scamper_tracelb_link_hopc_get(link);
	  for(k=0; k<hopc; k++)
	    {
	      set = scamper_tracelb_link_probeset_get(link, k);
	      probec = scamper_tracelb_probeset_probec_get(set);
	      for(l=0; l<probec; l++)
		{
		  probe = scamper_tracelb_probeset_probe_get(set, l);
		  rxc = scamper_tracelb_probe_rxc_get(probe);
		  for(m=0; m<rxc; m++)
		    {
		      reply = scamper_tracelb_probe_rx_get(probe, m);
		      from = scamper_tracelb_reply_from_get(reply);
		      if(scamper_tracelb_reply_is_icmp_ttl_exp(reply) == 0 ||
			 (no_dst != 0 && scamper_addr_cmp(from, dst) == 0))
			continue;
		      if(dump_addr(from) != 0)
			goto done;
		    }
		}
	    }
	}
    }
  rc = 0;

 done:
  scamper_tracelb_free(trace);
  return rc;
}

static int dump_trace(scamper_trace_t *trace)
{
  const scamper_trace_hop_t *hop;
  scamper_addr_t *dst, *hop_addr;
  uint16_t u16, hop_count;
  int rc = -1;

  hop_count = scamper_trace_hop_count_get(trace);
  dst = scamper_trace_dst_get(trace);
  for(u16=0; u16<hop_count; u16++)
    {
      for(hop = scamper_trace_hop_get(trace, u16); hop != NULL;
	  hop = scamper_trace_hop_next_get(hop))
	{
	  hop_addr = scamper_trace_hop_addr_get(hop);
	  if(scamper_trace_hop_is_icmp_ttl_exp(hop) == 0 ||
	     (no_dst != 0 && scamper_addr_cmp(hop_addr, dst) == 0))
	    continue;
	  if(dump_addr(hop_addr) != 0)
	    goto done;
	}
    }
  rc = 0;

 done:
  scamper_trace_free(trace);
  return rc;
}

static void cleanup(void)
{
  if(st_ip4 != NULL)
    {
      splaytree_free(st_ip4, (splaytree_free_t)scamper_addr_free);
      st_ip4 = NULL;
    }

  if(st_ip6 != NULL)
    {
      splaytree_free(st_ip6, (splaytree_free_t)scamper_addr_free);
      st_ip6 = NULL;
    }

  return;
}

int main(int argc, char *argv[])
{
  scamper_file_t        *file;
  scamper_file_filter_t *filter;
  uint16_t filter_types[] = {
    SCAMPER_FILE_OBJ_TRACE,
    SCAMPER_FILE_OBJ_TRACELB,
  };
  uint16_t filter_cnt = sizeof(filter_types)/sizeof(uint16_t);

  void     *data;
  uint16_t  type;
  int       f;

#ifdef HAVE_WSASTARTUP
  WSADATA wsaData;
  WSAStartup(MAKEWORD(2,2), &wsaData);
#endif

#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    return -1;

  if((st_ip4 = splaytree_alloc((splaytree_cmp_t)scamper_addr_cmp)) == NULL ||
     (st_ip6 = splaytree_alloc((splaytree_cmp_t)scamper_addr_cmp)) == NULL)
    return -1;

  if((filter = scamper_file_filter_alloc(filter_types, filter_cnt)) == NULL)
    {
      fprintf(stderr, "could not alloc filter\n");
      return -1;
    }

  for(f=0; f<=filec; f++)
    {
      if(filec == 0)
	{
	  if((file=scamper_file_openfd(STDIN_FILENO,"-",'r',"warts")) == NULL)
	    {
	      usage();
	      fprintf(stderr, "could not use stdin\n");
	      return -1;
	    }
	}
      else if(f < filec)
	{
	  if((file = scamper_file_open(files[f], 'r', NULL)) == NULL)
	    {
	      usage();
	      fprintf(stderr, "could not open %s\n", files[f]);
	      return -1;
	    }
	}
      else break;

      while(scamper_file_read(file, filter, &type, &data) == 0)
	{
	  /* hit eof */
	  if(data == NULL)
	    break;

	  switch(type)
	    {
	    case SCAMPER_FILE_OBJ_TRACE:
	      dump_trace(data);
	      break;

	    case SCAMPER_FILE_OBJ_TRACELB:
	      dump_tracelb(data);
	      break;
	    }
	}

      scamper_file_close(file);
    }

  scamper_file_filter_free(filter);
  return 0;
}
