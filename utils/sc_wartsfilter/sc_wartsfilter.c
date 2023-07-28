/*
 * sc_wartsfilter
 *
 * $Id: sc_wartsfilter.c,v 1.21 2023/05/29 21:22:27 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2019-2020 The University of Waikato
 * Copyright (C) 2022-2023 Matthew Luckie
 * Copyright (C) 2023      The Regents of the University of California
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

#include "scamper_file.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "dealias/scamper_dealias.h"
#include "ping/scamper_ping.h"
#include "tbit/scamper_tbit.h"
#include "trace/scamper_trace.h"
#include "tracelb/scamper_tracelb.h"
#include "mjl_list.h"
#include "mjl_prefixtree.h"
#include "utils.h"

#define OPT_OUTFILE 0x0001
#define OPT_INFILE  0x0002
#define OPT_ADDR    0x0004
#define OPT_TYPE    0x0008

static scamper_file_t        *infile   = NULL;
static scamper_file_t        *outfile  = NULL;
static char                  *outfile_type = "warts";
static prefixtree_t          *addr_pt4 = NULL;
static prefixtree_t          *addr_pt6 = NULL;
static int                    addrc    = 0;
static scamper_file_filter_t *filter   = NULL;
static int                    check_hops = 0;

static void usage(uint32_t opts)
{
  fprintf(stderr,
          "usage: sc_wartsfilter [-a address] [-i infile] [-o outfile]\n"
	  "                      [-O options] [-t type]\n");
  return;
}

static int check_options(int argc, char *argv[])
{
  char *opt_infile = NULL, *opt_outfile = NULL;
  uint32_t type_mask = 0;
  slist_t *addrs = NULL;
  slist_node_t *sn;
  char *opts = "a:i:o:O:t:?";
  char *addr, *ptr, *dup = NULL;
  prefix4_t *pfx4 = NULL;
  prefix6_t *pfx6 = NULL;
  struct in_addr in4;
  struct in6_addr in6;
  uint16_t types_def[] = {
    SCAMPER_FILE_OBJ_DEALIAS,
    SCAMPER_FILE_OBJ_PING,
    SCAMPER_FILE_OBJ_TBIT,
    SCAMPER_FILE_OBJ_TRACE,
    SCAMPER_FILE_OBJ_TRACELB,
  };
  uint16_t *types = NULL;
  int i, typec;
  long lo;
  int ch;

  if((addrs = slist_alloc()) == NULL)
    {
      fprintf(stderr, "%s: could not alloc addrs\n", __func__);
      goto err;
    }

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
        {
        case 'a':
	  if((dup = strdup(optarg)) == NULL ||
	     slist_tail_push(addrs, dup) == NULL)
	    {
	      fprintf(stderr, "%s: error handling -a\n", __func__);
	      goto err;
	    }
	  dup = NULL;
	  break;

	case 'i':
	  opt_infile = optarg;
	  break;

	case 'o':
	  opt_outfile = optarg;
	  break;

	case 'O':
	  if(strcasecmp(optarg, "check-hops") == 0)
	    check_hops = 1;
	  else
	    {
	      fprintf(stderr, "%s: unknown -O %s\n", __func__, optarg);
	      goto err;
	    }
	  break;

	case 't':
	  if(strcasecmp(optarg, "dealias") == 0)
	    type_mask |= (1 << SCAMPER_FILE_OBJ_DEALIAS);
	  else if(strcasecmp(optarg, "ping") == 0)
	    type_mask |= (1 << SCAMPER_FILE_OBJ_PING);
	  else if(strcasecmp(optarg, "tbit") == 0)
	    type_mask |= (1 << SCAMPER_FILE_OBJ_TBIT);
	  else if(strcasecmp(optarg, "trace") == 0)
	    type_mask |= (1 << SCAMPER_FILE_OBJ_TRACE);
	  else if(strcasecmp(optarg, "tracelb") == 0)
	    type_mask |= (1 << SCAMPER_FILE_OBJ_TRACELB);
	  else
	    {
	      usage(0);
	      goto err;
	    }
	  break;

	case '?':
          usage(0xffffffff);
	  goto err;

        default:
          usage(0);
	  goto err;
	}
    }

  /* make sure there is some filter */
  if((addrc = slist_count(addrs)) == 0 && type_mask == 0)
    {
      usage(OPT_ADDR | OPT_TYPE);
      goto err;
    }

  /* go through the filter types */
  if(type_mask == 0)
    {
      typec = sizeof(types_def) / sizeof(uint16_t);
      if((filter = scamper_file_filter_alloc(types_def, typec)) == NULL)
	{
	  fprintf(stderr, "%s: could not alloc default filter\n", __func__);
	  goto err;
	}
    }
  else
    {
      typec = countbits32(type_mask);
      if((types = malloc(sizeof(uint16_t) * typec)) == NULL)
	{
	  fprintf(stderr, "%s: could not malloc %d types\n", __func__, typec);
	  goto err;
	}
      i = 0;
      if(type_mask & (1 << SCAMPER_FILE_OBJ_DEALIAS))
	types[i++] = SCAMPER_FILE_OBJ_DEALIAS;
      if(type_mask & (1 << SCAMPER_FILE_OBJ_PING))
	types[i++] = SCAMPER_FILE_OBJ_PING;
      if(type_mask & (1 << SCAMPER_FILE_OBJ_TBIT))
	types[i++] = SCAMPER_FILE_OBJ_TBIT;
      if(type_mask & (1 << SCAMPER_FILE_OBJ_TRACE))
	types[i++] = SCAMPER_FILE_OBJ_TRACE;
      if(type_mask & (1 << SCAMPER_FILE_OBJ_TRACELB))
	types[i++] = SCAMPER_FILE_OBJ_TRACELB;
      assert(i == typec);
      if((filter = scamper_file_filter_alloc(types, typec)) == NULL)
	{
	  fprintf(stderr, "%s: could not alloc filter\n", __func__);
	  goto err;
	}
      free(types); types = NULL;
    }

  /* go through the list of addresses */
  for(sn=slist_head_node(addrs); sn != NULL; sn=slist_node_next(sn))
    {
      addr = slist_node_item(sn);

      /* if address is not a prefix, install a specific /32 or /128 */
      if((ptr = string_firstof_char(addr, '/')) == NULL)
	{
	  if(inet_pton(AF_INET, addr, &in4) == 1)
	    {
	      if((pfx4 = prefix4_alloc(&in4, 32, NULL)) == NULL ||
		 prefixtree_insert4(addr_pt4, pfx4) == NULL)
		{
		  fprintf(stderr, "%s: could not alloc prefix for %s\n",
			  __func__, addr);
		  goto err;
		}
	    }
	  else if(inet_pton(AF_INET6, addr, &in6) == 1)
	    {
	      if((pfx6 = prefix6_alloc(&in6, 128, NULL)) == NULL ||
		 prefixtree_insert6(addr_pt6, pfx6) == NULL)
		{
		  fprintf(stderr, "%s: could not alloc prefix for %s\n",
			  __func__, addr);
		  goto err;
		}
	    }
	  else
	    {
	      fprintf(stderr, "%s: could not parse addr %s\n", __func__, addr);
	      goto err;
	    }
	  continue;
	}

      *ptr = '\0'; ptr++;
      if(string_tolong(ptr, &lo) != 0 || lo < 1)
	{
	  fprintf(stderr, "%s: invalid prefix length %s\n", __func__, ptr);
	  goto err;
	}
      if(inet_pton(AF_INET, addr, &in4) == 1)
	{
	  if(lo > 32)
	    {
	      fprintf(stderr, "%s: invalid IPv4 prefix length %ld\n",
		      __func__, lo);
	      goto err;
	    }
	  if((pfx4 = prefix4_alloc(&in4, lo, NULL)) == NULL)
	    {
	      fprintf(stderr, "%s: could not alloc IPv4 prefix\n", __func__);
	      goto err;
	    }
	  pfx4->ptr = pfx4;
	  if(prefixtree_insert4(addr_pt4, pfx4) == NULL)
	    {
	      fprintf(stderr, "%s: could not insert IPv4 prefix\n", __func__);
	      goto err;
	    }
	}
      else if(inet_pton(AF_INET6, addr, &in6) == 1)
	{
	  if(lo > 128)
	    {
	      fprintf(stderr, "%s: invalid IPv6 prefix length %ld\n",
		      __func__, lo);
	      goto err;
	    }
	  if((pfx6 = prefix6_alloc(&in6, lo, NULL)) == NULL)
	    {
	      fprintf(stderr, "%s: could not alloc IPv6 prefix\n", __func__);
	      goto err;
	    }
	  pfx6->ptr = pfx6;
	  if(prefixtree_insert6(addr_pt6, pfx6) == NULL)
	    {
	      fprintf(stderr, "%s: could not insert IPv6 prefix\n", __func__);
	      goto err;
	    }
	}
      else
	{
	  fprintf(stderr, "%s: could not parse prefix %s/%s\n",
		  __func__, addr, ptr);
	  goto err;
	}
    }
  slist_free_cb(addrs, free); addrs = NULL;

  /* determine where to read the warts file */
  if(opt_infile == NULL)
    {
      if((infile = scamper_file_openfd(STDIN_FILENO,"-",'r',"warts")) == NULL)
	{
	  fprintf(stderr, "could not open stdin\n");
	  goto err;
	}
    }
  else
    {
      if((infile = scamper_file_open(opt_infile, 'r', "warts")) == NULL)
	{
	  fprintf(stderr, "could not open %s\n", opt_infile);
	  goto err;
	}
    }

  /* determine where to write the filtered records */
  if(opt_outfile == NULL || string_isdash(opt_outfile) != 0)
    {
#ifdef HAVE_ISATTY
      /* writing to stdout; don't dump a binary structure to a tty. */
      if(isatty(STDOUT_FILENO) != 0)
        {
          fprintf(stderr, "not going to dump warts to a tty\n");
	  goto err;
        }
#endif

      if((outfile = scamper_file_openfd(STDOUT_FILENO,"-",'w',"warts")) == NULL)
        {
          fprintf(stderr, "could not open stdout\n");
	  goto err;
        }
    }
  else
    {
      if(string_endswith(opt_outfile, ".gz") != 0)
	{
#ifdef HAVE_ZLIB
	  outfile_type = "warts.gz";
#else
	  usage(OPT_OUTFILE);
	  fprintf(stderr, "cannot write to %s: did not link against zlib\n",
		  opt_outfile);
	  goto err;
#endif
	}
      else if(string_endswith(opt_outfile, ".bz2") != 0)
	{
#ifdef HAVE_LIBBZ2
	  outfile_type = "warts.bz2";
#else
	  usage(OPT_OUTFILE);
	  fprintf(stderr, "cannot write to %s: did not link against libbz2\n",
		  opt_outfile);
	  goto err;
#endif
	}
      else if(string_endswith(opt_outfile, ".xz") != 0)
	{
#ifdef HAVE_LIBLZMA
	  outfile_type = "warts.xz";
#else
	  usage(OPT_OUTFILE);
	  fprintf(stderr, "cannot write to %s: did not link against liblzma\n",
		  opt_outfile);
	  goto err;
#endif
	}

      if((outfile = scamper_file_open(opt_outfile, 'w', outfile_type)) == NULL)
        {
          usage(OPT_OUTFILE);
	  goto err;
        }
    }

  return 0;

 err:
  if(dup != NULL) free(dup);
  if(types != NULL) free(types);
  if(addrs != NULL) slist_free_cb(addrs, free);
  return -1;
}

static int addr_matched(scamper_addr_t *addr)
{
  if(scamper_addr_isipv4(addr))
    {
      if(prefixtree_find_ip4(addr_pt4, scamper_addr_addr_get(addr)) == NULL)
	return 0;
    }
  else if(scamper_addr_isipv6(addr))
    {
      if(prefixtree_find_ip6(addr_pt6, scamper_addr_addr_get(addr)) == NULL)
	return 0;
    }
  else return 0;
  return 1;
}

static void process_dealias(scamper_dealias_t *dealias)
{
  const scamper_dealias_mercator_t *mc;
  const scamper_dealias_ally_t *ally;
  const scamper_dealias_radargun_t *rg;
  const scamper_dealias_prefixscan_t *pfs;
  const scamper_dealias_probedef_t *def, *def1;
  uint32_t i, probedefc;

  if(addrc > 0)
    {
      if((mc = scamper_dealias_mercator_get(dealias)) != NULL)
	{
	  def = scamper_dealias_mercator_def_get(mc);
	  if(addr_matched(scamper_dealias_probedef_dst_get(def)) == 0)
	    goto done;
	}
      else if((ally = scamper_dealias_ally_get(dealias)) != NULL)
	{
	  def = scamper_dealias_ally_def0_get(ally);
	  def1 = scamper_dealias_ally_def1_get(ally);
	  if(addr_matched(scamper_dealias_probedef_dst_get(def)) == 0 &&
	     addr_matched(scamper_dealias_probedef_dst_get(def1)) == 0)
	    goto done;
	}
      else if((rg = scamper_dealias_radargun_get(dealias)) != NULL)
	{
	  probedefc = scamper_dealias_radargun_defc_get(rg);
	  for(i=0; i<probedefc; i++)
	    {
	      def = scamper_dealias_radargun_def_get(rg, i);
	      if(addr_matched(scamper_dealias_probedef_dst_get(def)) != 0)
		break;
	    }
	  if(i == probedefc)
	    goto done;
	}
      else if((pfs = scamper_dealias_prefixscan_get(dealias)) != NULL)
	{
	  probedefc = scamper_dealias_prefixscan_defc_get(pfs);
	  for(i=0; i<probedefc; i++)
	    {
	      def = scamper_dealias_prefixscan_def_get(pfs, i);
	      if(addr_matched(scamper_dealias_probedef_dst_get(def)) != 0)
		break;
	    }
	  if(i == probedefc)
	    goto done;
	}
      else goto done;
    }
  scamper_file_write_dealias(outfile, dealias, NULL);

 done:
  scamper_dealias_free(dealias);
  return;
}

static void process_ping(scamper_ping_t *ping)
{
  if(addrc > 0 && addr_matched(scamper_ping_dst_get(ping)) == 0)
    goto done;
  scamper_file_write_ping(outfile, ping, NULL);

 done:
  scamper_ping_free(ping);
  return;
}

static void process_tbit(scamper_tbit_t *tbit)
{
  if(addrc > 0 && addr_matched(scamper_tbit_dst_get(tbit)) == 0)
    goto done;
  scamper_file_write_tbit(outfile, tbit, NULL);

 done:
  scamper_tbit_free(tbit);
  return;
}

static void process_trace(scamper_trace_t *trace)
{
  const scamper_trace_hop_t *hop;
  scamper_addr_t *addr;
  uint16_t i, hop_count;

  if(addrc == 0)
    {
      scamper_file_write_trace(outfile, trace, NULL);
      goto done;
    }
  addr = scamper_trace_dst_get(trace);
  if(addr_matched(addr) != 0)
    {
      scamper_file_write_trace(outfile, trace, NULL);
      goto done;
    }

  if(check_hops != 0)
    {
      hop_count = scamper_trace_hop_count_get(trace);
      for(i=0; i<hop_count; i++)
	{
	  for(hop = scamper_trace_hop_get(trace, i); hop != NULL;
	      hop = scamper_trace_hop_next_get(hop))
	    {
	      addr = scamper_trace_hop_addr_get(hop);
	      if(addr_matched(addr) != 0)
		{
		  scamper_file_write_trace(outfile, trace, NULL);
		  goto done;
		}
	    }
	}
    }

 done:
  scamper_trace_free(trace);
  return;
}

static int process_tracelb(scamper_tracelb_t *tracelb)
{
  const scamper_tracelb_node_t *node, *to;
  const scamper_tracelb_link_t *link;
  const scamper_tracelb_probeset_t *set;
  const scamper_tracelb_probe_t *probe;
  const scamper_tracelb_reply_t *reply;
  uint16_t i, j, l, m, rxc, nodec, linkc, probec;
  scamper_addr_t *addr;
  uint8_t k, hopc;

  if(addrc == 0)
    {
      scamper_file_write_tracelb(outfile, tracelb, NULL);
      goto done;
    }
  else if(addr_matched(scamper_tracelb_dst_get(tracelb)) != 0)
    {
      scamper_file_write_tracelb(outfile, tracelb, NULL);
      goto done;
    }
  else if(check_hops != 0)
    {
      nodec = scamper_tracelb_nodec_get(tracelb);
      for(i=0; i<nodec; i++)
	{
	  node = scamper_tracelb_node_get(tracelb, i);
	  if((addr = scamper_tracelb_node_addr_get(node)) != NULL &&
	     addr_matched(addr) != 0)
	    {
	      scamper_file_write_tracelb(outfile, tracelb, NULL);
	      goto done;
	    }
	  linkc = scamper_tracelb_node_linkc_get(node);
	  for(j=0; j<linkc; j++)
	    {
	      link = scamper_tracelb_node_link_get(node, j);
	      if((to = scamper_tracelb_link_to_get(link)) != NULL &&
		 addr_matched(scamper_tracelb_node_addr_get(to)) != 0)
		{
		  scamper_file_write_tracelb(outfile, tracelb, NULL);
		  goto done;
		}
	      if((hopc = scamper_tracelb_link_hopc_get(link)) < 1)
		continue;
	      for(k=0; k<hopc-1; k++)
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
			  addr = scamper_tracelb_reply_from_get(reply);
			  if(addr_matched(addr) != 0)
			    {
			      scamper_file_write_tracelb(outfile,tracelb,NULL);
			      goto done;
			    }
			}
		    }
		}
	    }
	}
    }

 done:
  scamper_tracelb_free(tracelb);
  return 0;
}

static void cleanup(void)
{
  if(infile != NULL)
    {
      scamper_file_close(infile);
      infile = NULL;
    }

  if(filter != NULL)
    {
      scamper_file_filter_free(filter);
      filter = NULL;
    }

  if(outfile != NULL)
    {
      scamper_file_close(outfile);
      outfile = NULL;
    }

  if(addr_pt4 != NULL)
    {
      prefixtree_free_cb(addr_pt4, (prefix_free_t)prefix4_free);
      addr_pt4 = NULL;
    }

  if(addr_pt6 != NULL)
    {
      prefixtree_free_cb(addr_pt6, (prefix_free_t)prefix6_free);
      addr_pt6 = NULL;
    }

  return;
}

int main(int argc, char *argv[])
{
  uint16_t type;
  void *data;

#ifdef DMALLOC
  free(malloc(1));
#endif

  atexit(cleanup);

  if((addr_pt4 = prefixtree_alloc(AF_INET)) == NULL ||
     (addr_pt6 = prefixtree_alloc(AF_INET6)) == NULL)
    {
      fprintf(stderr, "%s: could not alloc prefixtrees\n", __func__);
      goto err;
    }

  if(check_options(argc, argv) != 0)
    goto err;

  while(scamper_file_read(infile, filter, &type, (void *)&data) == 0)
    {
      if(data == NULL)
	break; /* EOF */

      if(type == SCAMPER_FILE_OBJ_DEALIAS)
	process_dealias(data);
      else if(type == SCAMPER_FILE_OBJ_PING)
	process_ping(data);
      else if(type == SCAMPER_FILE_OBJ_TRACE)
	process_trace(data);
      else if(type == SCAMPER_FILE_OBJ_TBIT)
	process_tbit(data);
      else if(type == SCAMPER_FILE_OBJ_TRACELB)
	process_tracelb(data);
    }

  return 0;

 err:
  return -1;
}
