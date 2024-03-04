/*
 * sc_speedtrap
 *
 * $Id: sc_speedtrap.c,v 1.86 2024/02/29 00:56:45 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2013-2015 The Regents of the University of California
 * Copyright (C) 2016,2020 The University of Waikato
 * Copyright (C) 2022-2023 Matthew Luckie
 * Copyright (C) 2023-2024 The Regents of the University of California
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

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#include "scamper_addr.h"
#include "scamper_list.h"
#include "ping/scamper_ping.h"
#include "dealias/scamper_dealias.h"
#include "lib/libscamperctrl/libscamperctrl.h"
#include "scamper_file.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
#include "mjl_heap.h"
#include "mjl_threadpool.h"
#include "utils.h"

#define OPT_HELP        0x0001
#define OPT_ADDRFILE    0x0002
#define OPT_OUTFILE     0x0004
#define OPT_PORT        0x0008
#define OPT_STOP        0x0010
#define OPT_LOG         0x0020
#define OPT_UNIX        0x0040
#define OPT_DUMP        0x0200
#define OPT_INCR        0x0400
#define OPT_THREADC     0x0800
#define OPT_ALL         0xffff

typedef struct sc_targetipid sc_targetipid_t;
typedef struct sc_targetset sc_targetset_t;

/*
 * sc_target
 *
 * keep a set of IPID samples for a given interface address.
 */
typedef struct sc_target
{
  scamper_addr_t     *addr;      /* the interface being probed */
  slist_t            *samples;   /* collected samples */
  uint32_t            last;      /* last IPID sample */
  sc_targetset_t     *ts;        /* pointer to ts that has probing lock */
  int                 attempt;   /* how many times we've tried this probe */
  splaytree_node_t   *tree_node;
} sc_target_t;

/*
 * sc_targetipid
 *
 * an IPID sample, including tx and rx timestamps.
 */
struct sc_targetipid
{
  sc_target_t        *target;
  struct timeval      tx, rx;
  uint32_t            ipid;
};

/*
 * sc_targetset
 *
 * state kept when probing a set of addresses.
 */
struct sc_targetset
{
  slist_t            *targets;
  slist_node_t       *next;     /* next is used in mode overlap */
  struct timeval      min, max; /* min + max are used in mode overlap */
  slist_t            *blocked;  /* blocked is used in mode overlap and ally */
  dlist_node_t       *node;
  int                 attempt;  /* attempt is used in mode ally */
};

typedef struct sc_wait
{
  struct timeval      tv;
  union
  {
    void             *ptr;
    sc_target_t      *target;
    sc_targetset_t   *targetset;
  } un;
} sc_wait_t;

/*
 * sc_router_t
 *
 * collect a set of interfaces mapped to a router
 */
typedef struct sc_router
{
  slist_t            *addrs;
  dlist_node_t       *node;
} sc_router_t;

/*
 * sc_addr2router_t
 *
 * map an address to a router.
 */
typedef struct sc_addr2router
{
  scamper_addr_t     *addr;
  sc_router_t        *router;
} sc_addr2router_t;

typedef struct sc_addr2ptr
{
  scamper_addr_t     *addr;
  void               *ptr;
} sc_addr2ptr_t;

typedef struct sc_pairwise
{
  sc_target_t        *ta;    /* the node to consider */
  slist_node_t       *sb;    /* other nodes after ta in the list */
} sc_pairwise_t;

typedef struct sc_notaliases
{
  sc_router_t        *r;
  splaytree_node_t   *tree_node;
  splaytree_t        *tree;
} sc_notaliases_t;

typedef struct sc_dump
{
  char  *descr;
  int  (*proc_ping)(const scamper_ping_t *ping);
  int  (*proc_ally)(const scamper_dealias_t *dealias);
  void (*finish)(void);
} sc_dump_t;

/* declare dump functions used for dump_funcs[] below */
static int  process_1_ping(const scamper_ping_t *);
static int  process_1_ally(const scamper_dealias_t *);
static void finish_1(void);
static int  process_2_ping(const scamper_ping_t *);
static int  process_3_ping(const scamper_ping_t *);
static int  process_3_ally(const scamper_dealias_t *);
static void finish_3(void);
static int  process_4_ping(const scamper_ping_t *);
static void finish_4(void);

static uint32_t               options       = 0;
static char                  *addressfile   = NULL;
static scamper_ctrl_t        *scamper_ctrl  = NULL;
static scamper_inst_t        *scamper_inst  = NULL;
static char                  *dst_addr      = NULL;
static int                    dst_port      = 0;
static char                  *unix_name     = NULL;
static splaytree_t           *targets       = NULL;
static splaytree_t           *addr2routers  = NULL;
static dlist_t               *routers       = NULL;
static splaytree_t           *notaliases    = NULL;
static slist_t               *probelist     = NULL;
static heap_t                *probeheap     = NULL;
static slist_t               *incr          = NULL; /* descend and overlap */
static heap_t                *waiting       = NULL;
static char                  *outfile_name  = NULL;
static char                  *outfile_type  = "warts";
static scamper_file_t        *outfile       = NULL;
static scamper_file_filter_t *ffilter       = NULL;
static scamper_file_t        *decode_sf     = NULL;
static scamper_file_readbuf_t *decode_rb    = NULL;
static int                    more          = 0;
static int                    probing       = 0;
static int                    blocked       = 0;
static int                    mode          = 0;
static int                    error         = 0;
static int                    done          = 0;
static long                   threadc       = -1;
static struct timeval         now;
static FILE                  *logfile       = NULL;
static uint32_t               fudge         = 65535;
static slist_t               *descend       = NULL;
static dlist_t               *overlap_act   = NULL;
static slist_t               *candidates    = NULL;
static const char            *step_names[] = {"classify","descend","overlap",
					      "descend2","ally"};
static int                    step_namec = sizeof(step_names)/sizeof(char *);
static char                  *stop_stepname = NULL;
static int                    stop_stepid   = 0;

static uint32_t              *pairwise_uint32 = NULL;
static sc_targetipid_t      **pairwise_tipid  = NULL;
static size_t                 pairwise_max    = 0;

#ifdef HAVE_PTHREAD
static pthread_mutex_t        candidates_mutex;
#endif

static int                    dump_id       = 0;
static int                    dump_stop     = 0;
static char                 **dump_files;
static int                    dump_filec    = 0;
static const sc_dump_t        dump_funcs[] = {
  {NULL, NULL, NULL, NULL},
  {"dump transitive closure from ally probes",
   process_1_ping, process_1_ally, finish_1},
  {"dump interface classification",
   process_2_ping, NULL,           NULL},
  {"summary table of per-stage statistics",
   process_3_ping, process_3_ally, finish_3},
  {"dump transitive closure from descend and overlap stages",
   process_4_ping, NULL,           finish_4},
};
static int dump_funcc = sizeof(dump_funcs) / sizeof(sc_dump_t);

#define MODE_CLASSIFY   0
#define MODE_DESCEND    1
#define MODE_OVERLAP    2
#define MODE_DESCEND2   3
#define MODE_ALLY       4

static void usage(uint32_t opt_mask)
{
  int i;

  fprintf(stderr,
    "usage: sc_speedtrap [-a addr-file] [-o outfile] [-p [ip:]port] [-U unix]\n"
    "                    [-I] [-l log] [-s stop]\n"
#ifdef HAVE_PTHREAD
    "                    [-t thread-count]\n"
#endif
    "\n"
    "       sc_speedtrap [-d dump] file1.warts .. fileN.warts\n"
    "\n");

  if(opt_mask == 0)
    fprintf(stderr, "       sc_speedtrap -?\n\n");

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "     -? give an overview of the usage of sc_speedtrap\n");

  if(opt_mask & OPT_ADDRFILE)
    fprintf(stderr, "     -a input addressfile\n");

  if(opt_mask & OPT_DUMP)
    {
      fprintf(stderr, "     -d dump selection\n");
      for(i=1; i<dump_funcc; i++)
	  printf("        %2d : %s\n", i, dump_funcs[i].descr);
    }

  if(opt_mask & OPT_INCR)
    fprintf(stderr, "     -I input addresses increment, skip classify step\n");

  if(opt_mask & OPT_LOG)
    fprintf(stderr, "     -l output logfile\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "     -o output warts file\n");

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -p [ip:]port to find scamper on\n");

  if(opt_mask & OPT_STOP)
    {
      fprintf(stderr,
	      "     -s step to halt on completion of\n"
	      "        [%s", step_names[0]);
      for(i=1; i<step_namec; i++)
	fprintf(stderr, "|%s", step_names[i]);
      fprintf(stderr, "]\n");
    }

#ifdef HAVE_PTHREAD
  if(opt_mask & OPT_THREADC)
    fprintf(stderr, "     -t number of threads to infer candidate sets\n");
#endif

  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "     -U unix domain to find scamper on\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  long lo;
  char *opts = "?a:d:Il:o:p:s:"
#ifdef HAVE_PTHREAD
    "t:"
#endif
    "U:w:";
  char *opt_port = NULL, *opt_unix = NULL, *opt_log = NULL, *opt_dump = NULL;
  int i, ch;

#ifdef HAVE_PTHREAD
  char *opt_threadc = NULL;
#endif

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'a':
	  options |= OPT_ADDRFILE;
	  addressfile = optarg;
	  break;

	case 'd':
	  options |= OPT_DUMP;
	  opt_dump = optarg;
	  break;

	case 'I':
	  options |= OPT_INCR;
	  break;

	case 'l':
	  options |= OPT_LOG;
	  opt_log = optarg;
	  break;

	case 'o':
	  options |= OPT_OUTFILE;
	  outfile_name = optarg;
	  break;

	case 'p':
	  options |= OPT_PORT;
	  opt_port = optarg;
	  break;

	case 's':
	  options |= OPT_STOP;
	  stop_stepname = optarg;
	  break;

#ifdef HAVE_PTHREAD
	case 't':
	  options |= OPT_THREADC;
	  opt_threadc = optarg;
	  break;
#endif

	case 'U':
	  options |= OPT_UNIX;
	  opt_unix = optarg;
	  break;

	case '?':
	  usage(OPT_ALL);
	  return -1;

	default:
	  usage(0);
	  return -1;
	}
    }

  if((options & (OPT_ADDRFILE|OPT_OUTFILE|OPT_DUMP)) != (OPT_ADDRFILE|OPT_OUTFILE) &&
     (options & (OPT_ADDRFILE|OPT_OUTFILE|OPT_DUMP)) != OPT_DUMP)
    {
      usage(0);
      return -1;
    }

  if(options & (OPT_ADDRFILE|OPT_OUTFILE))
    {
      if((options & (OPT_PORT|OPT_UNIX)) == 0 ||
	 (options & (OPT_PORT|OPT_UNIX)) == (OPT_PORT|OPT_UNIX) ||
	 argc - optind > 0)
	{
	  usage(OPT_ADDRFILE|OPT_OUTFILE|OPT_PORT|OPT_UNIX);
	  return -1;
	}

      if(string_endswith(outfile_name, ".gz") != 0)
	{
#ifdef HAVE_ZLIB
	  outfile_type = "warts.gz";
#else
	  usage(OPT_OUTFILE);
	  fprintf(stderr, "cannot write to %s: did not link against zlib\n",
		  outfile_name);
	  return -1;
#endif
	}
      else if(string_endswith(outfile_name, ".bz2") != 0)
	{
#ifdef HAVE_LIBBZ2
	  outfile_type = "warts.bz2";
#else
	  usage(OPT_OUTFILE);
	  fprintf(stderr, "cannot write to %s: did not link against libbz2\n",
		  outfile_name);
	  return -1;
#endif
	}
      else if(string_endswith(outfile_name, ".xz") != 0)
	{
#ifdef HAVE_LIBLZMA
	  outfile_type = "warts.xz";
#else
	  usage(OPT_OUTFILE);
	  fprintf(stderr, "cannot write to %s: did not link against liblzma\n",
		  outfile_name);
	  return -1;
#endif
	}

      if(options & OPT_PORT)
	{
	  if(string_addrport(opt_port, &dst_addr, &dst_port) != 0)
            {
              usage(OPT_PORT);
              return -1;
            }
	}
      else if(options & OPT_UNIX)
	{
	  unix_name = opt_unix;
	}

#ifdef HAVE_PTHREAD
      if(opt_threadc != NULL)
	{
	  if(string_tolong(opt_threadc, &lo) != 0 || lo < 0)
	    {
	      usage(OPT_THREADC);
	      return -1;
	    }
	  threadc = lo;
	}
#endif

      if(stop_stepname != NULL)
	{
	  for(i=0; i<step_namec; i++)
	    {
	      if(strcasecmp(stop_stepname, step_names[i]) == 0)
		{
		  stop_stepid = i;
		  break;
		}
	    }
	  if(i == step_namec)
	    {
	      usage(OPT_STOP);
	      return -1;
	    }
	}

      if(opt_log != NULL)
	{
	  if(string_isdash(opt_log) != 0)
	    {
	      logfile = stdout;
	    }
	  else if((logfile = fopen(opt_log, "w")) == NULL)
	    {
	      usage(OPT_LOG);
	      fprintf(stderr, "could not open %s\n", opt_log);
	      return -1;
	    }
	}
    }
  else
    {
      if(argc - optind < 1)
	{
	  usage(0);
	  return -1;
	}
      if(string_tolong(opt_dump, &lo) != 0 || lo < 1 || lo > dump_funcc)
	{
	  usage(OPT_DUMP);
	  return -1;
	}
      dump_id    = lo;
      dump_files = argv + optind;
      dump_filec = argc - optind;
    }

  return 0;
}

static int mode_ok(int m)
{
  if(stop_stepname == NULL)
    return 1;
  if(m > stop_stepid)
    return 0;
  return 1;
}

static int ptrcmp(const void *a, const void *b)
{
  if(a < b) return -1;
  if(a > b) return  1;
  return 0;
}

static int tree_to_slist(void *ptr, void *entry)
{
  slist_tail_push((slist_t *)ptr, entry);
  return 0;
}

static void hms(int x, int *h, int *m, int *s)
{
  *s = x % 60; x -= *s; x /= 60;
  *m = x % 60; x -= *m;
  *h = x / 60;
  return;
}

#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
static void logprint(int st, char *format, ...)
  __attribute__((format(printf, 2, 3)));
#endif

static void logprint(int st, char *format, ...)
{
  va_list ap;
  char msg[131072];
  int pl;

  if(logfile != NULL)
    {
      if(st != 0)
	{
	  if(probeheap != NULL && heap_count(probeheap) > 0)
	    pl = heap_count(probeheap);
	  else
	    pl = slist_count(probelist);
	  fprintf(logfile, "%ld: p %d, w %d, l %d, b %d : ",
		  (long int)now.tv_sec,
		  probing, heap_count(waiting), pl, blocked);
	}

      va_start(ap, format);
      vsnprintf(msg, sizeof(msg), format, ap);
      va_end(ap);
      fprintf(logfile, "%s", msg);
      fflush(logfile);
    }

  return;
}

static int uint32_cmp(const void *va, const void *vb)
{
  const uint32_t a = *((uint32_t *)va);
  const uint32_t b = *((uint32_t *)vb);
  if(a < b) return -1;
  if(a > b) return  1;
  return 0;
}

static int uint32_find(uint32_t *a, size_t len, uint32_t u32)
{
  if(bsearch(&u32, a, len, sizeof(uint32_t), uint32_cmp) != NULL)
    return 1;
  return 0;
}

static int ipid_inseq3(uint64_t a, uint64_t b, uint64_t c)
{
  if(a == b || b == c || a == c)
    return 0;
  if(a > b)
    b += 0x100000000ULL;
  if(a > c)
    c += 0x100000000ULL;
  if(a > b || b > c)
    return 0;
  if(fudge != 0 && (b - a > fudge || c - b > fudge))
    return 0;
  return 1;
}

static int ipid_incr(uint32_t *ipids, int ipidc)
{
  int i;
  if(ipidc < 3)
    return 0;
  for(i=2; i<ipidc; i++)
    if(ipid_inseq3(ipids[i-2], ipids[i-1], ipids[i]) == 0)
      return 0;
  return 1;
}

static int sc_addr2router_human_cmp(sc_addr2router_t *a, sc_addr2router_t *b)
{
  return scamper_addr_human_cmp(a->addr, b->addr);
}

static int sc_addr2router_cmp(sc_addr2router_t *a, sc_addr2router_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static void sc_addr2router_free(sc_addr2router_t *a2r)
{
  if(a2r->addr != NULL) scamper_addr_free(a2r->addr);
  free(a2r);
  return;
}

static sc_addr2router_t *sc_addr2router_find(scamper_addr_t *addr)
{
  sc_addr2router_t fm; fm.addr = addr;
  return splaytree_find(addr2routers, &fm);
}

static sc_addr2router_t *sc_addr2router_alloc(scamper_addr_t *a, sc_router_t *r)
{
  sc_addr2router_t *a2r = NULL;
  if((a2r = malloc_zero(sizeof(sc_addr2router_t))) == NULL)
    goto err;
  a2r->addr = scamper_addr_use(a);
  a2r->router = r;
  if(splaytree_insert(addr2routers, a2r) == NULL)
    goto err;
  return a2r;

 err:
  if(a2r != NULL) sc_addr2router_free(a2r);
  return NULL;
}

static int sc_router_cmp(const sc_router_t *a, const sc_router_t *b)
{
  int al = slist_count(a->addrs), bl = slist_count(b->addrs);
  sc_addr2router_t *aa, *ab;
  if(al > bl) return -1;
  if(al < bl) return  1;
  aa = slist_head_item(a->addrs);
  ab = slist_head_item(b->addrs);
  return scamper_addr_human_cmp(aa->addr, ab->addr);
}

static void sc_router_free(sc_router_t *r)
{
  if(r->node != NULL) dlist_node_pop(routers, r->node);
  if(r->addrs != NULL) slist_free(r->addrs);
  free(r);
  return;
}

static int sc_router_node_setnull(sc_router_t *r, void *param)
{
  r->node = NULL;
  return 0;
}

static sc_router_t *sc_router_alloc(void)
{
  sc_router_t *r;
  if((r = malloc_zero(sizeof(sc_router_t))) == NULL ||
     (r->addrs = slist_alloc()) == NULL ||
     (r->node = dlist_tail_push(routers, r)) == NULL)
    goto err;
  return r;

 err:
  if(r != NULL) sc_router_free(r);
  return NULL;
}

static int sc_notaliases_cmp(sc_notaliases_t *a, sc_notaliases_t *b)
{
  return ptrcmp(a->r, b->r);
}

static sc_notaliases_t *sc_notaliases_find(sc_router_t *r)
{
  sc_notaliases_t fm; fm.r = r;
  return splaytree_find(notaliases, &fm);
}

static void sc_notaliases_free(sc_notaliases_t *na)
{
  if(na->tree != NULL) splaytree_free(na->tree, NULL);
  free(na);
  return;
}

static sc_notaliases_t *sc_notaliases_alloc(sc_router_t *r)
{
  sc_notaliases_t *na;
  if((na = malloc_zero(sizeof(sc_notaliases_t))) == NULL ||
     (na->tree = splaytree_alloc(ptrcmp)) == NULL)
    goto err;
  na->r = r;
  if((na->tree_node = splaytree_insert(notaliases, na)) == NULL)
    goto err;
  return na;
 err:
  if(na != NULL) sc_notaliases_free(na);
  return NULL;
}

/*
 * sc_notaliases_add
 *
 * two routers are inferred to not be aliases, record that.
 */
static int sc_notaliases_add(sc_router_t *a, sc_router_t *b)
{
  sc_notaliases_t *na;

  /*
   * get a notaliases node for router a.
   * if b is already known to be not alias, move on.
   * otherwise, record the not-alias information.
   */
  if((na = sc_notaliases_find(a)) == NULL &&
     (na = sc_notaliases_alloc(a)) == NULL)
    return -1;
  if(splaytree_find(na->tree, b) == NULL &&
     splaytree_insert(na->tree, b) == NULL)
    return -1;

  /*
   * get a notaliases node for router b.
   * if a is already known to be not alias, move on.
   * otherwise, record the not-alias information.
   */
  if((na = sc_notaliases_find(b)) == NULL &&
     (na = sc_notaliases_alloc(b)) == NULL)
    return -1;
  if(splaytree_find(na->tree, a) == NULL &&
     splaytree_insert(na->tree, a) == NULL)
    return -1;

  return 0;
}

/*
 * sc_notaliases_merge_r
 *
 * merge c into na, and update c's notaliases by replacing b with a.
 */
static int sc_notaliases_merge_r(sc_notaliases_t *na,
				 sc_router_t *b, sc_router_t *c)
{
  sc_notaliases_t *nc;

  /* add c to na */
  if(splaytree_find(na->tree, c) == NULL &&
     splaytree_insert(na->tree, c) == NULL)
    return -1;

  /* remove b, replace with a */
  if((nc = sc_notaliases_find(c)) == NULL ||
     splaytree_remove_item(nc->tree, b) != 0)
    return -1;
  if(splaytree_find(nc->tree, na->r) == NULL &&
     splaytree_insert(nc->tree, na->r) == NULL)
    return -1;

  return 0;
}

/*
 * sc_notaliases_merge
 *
 * two routers (a and b) are inferred to be aliases.  merge their
 * notalias state and free b.
 */
static int sc_notaliases_merge(sc_router_t *a, sc_router_t *b)
{
  slist_t *list = NULL;
  sc_notaliases_t *na, *nb;
  sc_router_t *c;
  int rc = -1;

  /* if we haven't got "not aliases" nodes for b, move on */
  if((nb = sc_notaliases_find(b)) == NULL)
    return 0;

  if((list = slist_alloc()) == NULL ||
     ((na = sc_notaliases_find(a)) == NULL &&
      (na = sc_notaliases_alloc(a)) == NULL))
    goto done;

  splaytree_inorder(nb->tree, tree_to_slist, list);
  while((c = slist_head_pop(list)) != NULL)
    {
      if(sc_notaliases_merge_r(na, b, c) != 0)
	goto done;
    }
  splaytree_remove_node(notaliases, nb->tree_node);
  sc_notaliases_free(nb);
  rc = 0;

 done:
  if(list != NULL) slist_free(list);
  return rc;
}

/*
 * sc_notaliases_check
 *
 * check to see if two routers are already known to not be aliases
 */
static int sc_notaliases_check(sc_router_t *a, sc_router_t *b)
{
  sc_notaliases_t *na;
  if((na = sc_notaliases_find(a)) == NULL ||
     splaytree_find(na->tree, b) == NULL)
    return 0;
  return 1;
}

static int sc_wait_target(struct timeval *tv, sc_target_t *target)
{
  sc_wait_t *w;
  if((w = malloc_zero(sizeof(sc_wait_t))) == NULL)
    return -1;
  timeval_cpy(&w->tv, tv);
  w->un.target = target;
  if(heap_insert(waiting, w) == NULL)
    return -1;
  return 0;
}

static int sc_wait_targetset(struct timeval *tv, sc_targetset_t *targetset)
{
  sc_wait_t *w;
  if((w = malloc_zero(sizeof(sc_wait_t))) == NULL)
    return -1;
  timeval_cpy(&w->tv, tv);
  w->un.targetset = targetset;
  if(heap_insert(waiting, w) == NULL)
    return -1;
  return 0;
}

static void sc_wait_free(sc_wait_t *w)
{
  free(w);
  return;
}

static int sc_wait_cmp(const sc_wait_t *a, const sc_wait_t *b)
{
  return timeval_cmp(&b->tv, &a->tv);
}

static int sc_target_addr_cmp(const sc_target_t *a, const sc_target_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static int sc_target_ipid_cmp(const sc_target_t *a, const sc_target_t *b)
{
  if(a->last > b->last) return -1;
  if(a->last < b->last) return  1;
  return 0;
}

static sc_target_t *sc_target_findtree(scamper_addr_t *addr)
{
  sc_target_t fm;
  fm.addr = addr;
  return splaytree_find(targets, &fm);
}

static void sc_target_detachtree(sc_target_t *tg)
{
  if(tg->tree_node != NULL)
    {
      splaytree_remove_node(targets, tg->tree_node);
      tg->tree_node = NULL;
    }
  return;
}

static sc_targetipid_t *sc_target_sample(sc_target_t *tg, sc_targetipid_t *x)
{
  sc_targetipid_t *ti;
  if((ti = memdup(x, sizeof(sc_targetipid_t))) == NULL)
    {
      fprintf(stderr, "%s: could not memdup sample: %s\n",
	      __func__, strerror(errno));
      return NULL;
    }
  ti->target = tg;
  if(slist_tail_push(tg->samples, ti) == NULL)
    {
      fprintf(stderr, "%s: could not push sample: %s\n",
	      __func__, strerror(errno));
      free(ti);
      return NULL;
    }
  tg->last = ti->ipid;
  return ti;
}

static void sc_target_free(sc_target_t *tg)
{
  if(tg == NULL)
    return;

  if(tg->samples != NULL)
    slist_free_cb(tg->samples, free);
  if(tg->tree_node != NULL)
    splaytree_remove_node(targets, tg->tree_node);
  if(tg->addr != NULL)
    scamper_addr_free(tg->addr);

  free(tg);
  return;
}

static sc_target_t *sc_target_alloc(scamper_addr_t *addr)
{
  sc_target_t *target = NULL;

  if((target = malloc_zero(sizeof(sc_target_t))) == NULL ||
     (target->samples = slist_alloc()) == NULL)
    goto err;
  target->addr = scamper_addr_use(addr);
  return target;

 err:
  if(target != NULL) sc_target_free(target);
  return NULL;
}

static int sc_targetipid_tx_cmp(const sc_targetipid_t *a,
				const sc_targetipid_t *b)
{
  return timeval_cmp(&a->tx, &b->tx);
}

static void sc_targetset_logprint(const sc_targetset_t *ts)
{
  sc_target_t *tg;
  slist_node_t *ss;
  size_t off = 0;
  char a[64], buf[131072];
  string_concat(buf, sizeof(buf), &off, "%p:", ts);
  for(ss=slist_head_node(ts->targets); ss != NULL; ss=slist_node_next(ss))
    {
      tg = slist_node_item(ss);
      string_concat(buf, sizeof(buf), &off, " %s",
		    scamper_addr_tostr(tg->addr, a, sizeof(a)));
    }
  logprint(0, "%s\n", buf);
  return;
}

static int sc_targetset_targetc_asc_cmp(const sc_targetset_t *a,
					const sc_targetset_t *b)
{
  int ac = slist_count(a->targets);
  int bc = slist_count(b->targets);
  if(ac < bc) return -1;
  if(ac > bc) return  1;
  return 0;
}

static int sc_targetset_targetc_desc_cmp(const sc_targetset_t *a,
					 const sc_targetset_t *b)
{
  int ac = slist_count(a->targets);
  int bc = slist_count(b->targets);
  if(ac > bc) return -1;
  if(ac < bc) return  1;
  return 0;
}

static int sc_targetset_length_cmp(const sc_targetset_t *a,
				   const sc_targetset_t *b)
{
  struct timeval a_len, b_len;
  timeval_diff_tv(&a_len, &a->min, &a->max);
  timeval_diff_tv(&b_len, &b->min, &b->max);
  return timeval_cmp(&b_len, &a_len);
}

static void sc_targetset_free(sc_targetset_t *ts)
{
  if(ts == NULL)
    return;
  if(ts->targets != NULL) slist_free(ts->targets);
  if(ts->blocked != NULL) slist_free(ts->blocked);
  free(ts);
  return;
}

static sc_targetset_t *sc_targetset_alloc(void)
{
  sc_targetset_t *ts;
  if((ts = malloc_zero(sizeof(sc_targetset_t))) == NULL ||
     (ts->targets = slist_alloc()) == NULL ||
     (ts->blocked = slist_alloc()) == NULL)
    {
      sc_targetset_free(ts);
      return NULL;
    }
  return ts;
}

static int timeval_overlap(const struct timeval *a1, const struct timeval *a2,
			   const struct timeval *b1, const struct timeval *b2)
{
  int rc = timeval_cmp(a1, b1);

  if(rc < 0)
    {
      if(timeval_cmp(a2, b1) < 0)
	return 0; /* a=0,1 b=2,3 */
      else
	return 1; /* a=1,3 b=2,4 + a=0,6 b=1,5 */
    }
  else if(rc > 0)
    {
      if(timeval_cmp(b2, a1) < 0)
	return 0; /* a=2,3 b=0,1 */
      else
	return 1; /* a=2,4 b=1,3 + a=1,5 b=0,6 */
    }

  return 1;
}

static int sample_overlap(const sc_targetipid_t *a, const sc_targetipid_t *b)
{
  return timeval_overlap(&a->tx, &a->rx, &b->tx, &b->rx);
}

static int pairwise_test(sc_targetipid_t **tis, int tc, uint32_t *pairwise_u32)
{
  sc_targetipid_t *ti, *st[2][2];
  sc_target_t *x = tis[0]->target;
  int si, sj, ipidc = 0;
  int i, rc = 0;

  st[0][0] = NULL; st[0][1] = NULL;
  st[1][0] = NULL; st[1][1] = NULL;

  for(i=0; i<tc; i++)
    {
      /* first, check if this IPID has already been observed */
      ti = tis[i];
      if(uint32_find(pairwise_u32, ipidc, ti->ipid) != 0)
	return 0;
      pairwise_u32[ipidc++] = ti->ipid;
      qsort(pairwise_u32, ipidc, sizeof(uint32_t), uint32_cmp);

      if(ti->target == x) { si = 0; sj = 1; }
      else                { si = 1; sj = 0; }

      if(st[si][1] == NULL || st[sj][1] == NULL)
	goto next;

      if(timeval_cmp(&st[si][1]->tx, &st[sj][1]->tx) > 0)
	{
	  if(ipid_inseq3(st[sj][1]->ipid, st[si][1]->ipid, ti->ipid) == 0 &&
	     sample_overlap(st[sj][1], st[si][1]) == 0 &&
	     sample_overlap(st[si][1], ti) == 0)
	    return 0;
	  goto next;
	}

      if(sample_overlap(st[si][1], st[sj][1]) || sample_overlap(st[sj][1], ti))
	{
	  if(sample_overlap(st[sj][1], ti) && st[sj][0] != NULL &&
	     timeval_cmp(&st[si][1]->tx, &st[sj][0]->tx) < 0 &&
	     sample_overlap(st[si][1], st[sj][0]) == 0 &&
	     ipid_inseq3(st[si][1]->ipid, st[sj][0]->ipid, ti->ipid) == 0)
	    return 0;
	  goto next;
	}

      if(ipid_inseq3(st[si][1]->ipid, st[sj][1]->ipid, ti->ipid) == 1)
	rc = 1;
      else
	return 0;

    next:
      st[si][0] = st[si][1];
      st[si][1] = ti;
    }

  return rc;
}

static int pairwise(sc_target_t *ta, sc_target_t *tb)
{
  slist_node_t *ss;
  size_t len;
  size_t tc;
  int tac, tbc;

  if((tac=slist_count(ta->samples)) < 0 || (tbc=slist_count(tb->samples)) < 0)
    return -1;

  tc = (size_t)(tac + tbc);
  if(tc > pairwise_max)
    {
      len = tc * sizeof(sc_targetipid_t *);
      if(realloc_wrap((void **)&pairwise_tipid, len) != 0)
	return -1;
      len = tc * sizeof(uint32_t);
      if(realloc_wrap((void **)&pairwise_uint32, len) != 0)
	return -1;
      pairwise_max = tc;
    }

  tc = 0;
  for(ss=slist_head_node(ta->samples); ss!=NULL; ss=slist_node_next(ss))
    pairwise_tipid[tc++] = slist_node_item(ss);
  for(ss=slist_head_node(tb->samples); ss!=NULL; ss=slist_node_next(ss))
    pairwise_tipid[tc++] = slist_node_item(ss);
  array_qsort((void **)pairwise_tipid, tc, (array_cmp_t)sc_targetipid_tx_cmp);

  return pairwise_test(pairwise_tipid, tc, pairwise_uint32);
}

static void pairwise_all_thread(void *param)
{
  sc_pairwise_t *pw = param;
  sc_targetipid_t **pwt_tipid = NULL;
  sc_targetset_t *ts = NULL;
  uint32_t *pwt_uint32 = NULL;
  size_t pwt_max = 0;
  slist_node_t *sb, *ss;
  sc_target_t *ta = pw->ta, *tb;
  slist_t *list = NULL;
  size_t len;
  size_t tc;
  int tac, tbc;

#if defined(HAVE_PTHREAD)
  int candidates_mutex_held = 0;
#endif

  if((tac = slist_count(ta->samples)) <= 0 || (list = slist_alloc()) == NULL)
    goto done;

  for(sb=pw->sb; sb != NULL; sb=slist_node_next(sb))
    {
      tb = slist_node_item(sb);
      if((tbc = slist_count(tb->samples)) <= 0)
	continue;

      tc = (size_t)(tac + tbc);
      if(tc > pwt_max)
	{
	  len = tc * sizeof(sc_targetipid_t *);
	  if(realloc_wrap((void **)&pwt_tipid, len) != 0)
	    goto done;
	  len = tc * sizeof(uint32_t);
	  if(realloc_wrap((void **)&pwt_uint32, len) != 0)
	    goto done;
	  pwt_max = tc;
	}

      tc = 0;
      for(ss=slist_head_node(ta->samples); ss!=NULL; ss=slist_node_next(ss))
	pwt_tipid[tc++] = slist_node_item(ss);
      for(ss=slist_head_node(tb->samples); ss!=NULL; ss=slist_node_next(ss))
	pwt_tipid[tc++] = slist_node_item(ss);
      array_qsort((void **)pwt_tipid, tc, (array_cmp_t)sc_targetipid_tx_cmp);

      if(pairwise_test(pwt_tipid, tc, pwt_uint32) != 0 &&
	 slist_tail_push(list, tb) == NULL)
	goto done;
    }

  if(slist_count(list) > 0)
    {
      /* merge the addresses into a targetset */
      if((ts = sc_targetset_alloc()) == NULL ||
	 slist_tail_push(ts->targets, ta) == NULL)
	goto done;
      slist_concat(ts->targets, list);

#if defined(HAVE_PTHREAD)
      pthread_mutex_lock(&candidates_mutex);
      candidates_mutex_held = 1;
#endif
      if(slist_tail_push(candidates, ts) == NULL)
	goto done;
      ts = NULL;
#if defined(HAVE_PTHREAD)
      pthread_mutex_unlock(&candidates_mutex);
      candidates_mutex_held = 0;
#endif
    }

 done:
#if defined(HAVE_PTHREAD)
  if(candidates_mutex_held != 0)
    pthread_mutex_unlock(&candidates_mutex);
#endif
  if(pwt_tipid != NULL)
    free(pwt_tipid);
  if(pwt_uint32 != NULL)
    free(pwt_uint32);
  if(list != NULL)
    slist_free(list);
  if(ts != NULL)
    sc_targetset_free(ts);
  free(pw);
  return;
}

static int pairwise_all(slist_t *tgtlist)
{
  sc_pairwise_t *pw = NULL;
  threadpool_t *tp = NULL;
  slist_node_t *sa;
  sc_target_t *ta;
  int rc = -1;

#if defined(HAVE_PTHREAD)
  int candidates_mutex_ok = 0;
#endif

  if((tp = threadpool_alloc(threadc)) == NULL)
    goto done;

#if defined(HAVE_PTHREAD)
  if(pthread_mutex_init(&candidates_mutex, NULL) != 0)
    goto done;
  candidates_mutex_ok = 1;
#endif

  for(sa=slist_head_node(tgtlist); sa != NULL; sa=slist_node_next(sa))
    {
      ta = slist_node_item(sa);
      if(slist_count(ta->samples) <= 0)
	continue;
      if((pw = malloc(sizeof(sc_pairwise_t))) == NULL)
	goto done;
      pw->sb = slist_node_next(sa);
      pw->ta = ta;
      if(threadpool_tail_push(tp, pairwise_all_thread, pw) != 0)
	goto done;
      pw = NULL;
    }

  threadpool_join(tp); tp = NULL;
  rc = 0;

 done:
#if defined(HAVE_PTHREAD)
  if(candidates_mutex_ok != 0)
    pthread_mutex_destroy(&candidates_mutex);
#endif

  return rc;
}

static int test_ping6(sc_target_t *target, char *cmd, size_t len)
{
  size_t off = 0;
  char buf[64];
  string_concat(cmd, len, &off,
		"ping -U %d -c 6 -s 1300 -M 1280 %s",
		mode, scamper_addr_tostr(target->addr, buf, sizeof(buf)));
  return off;
}

static int test_ping1(sc_target_t *target, char *cmd, size_t len)
{
  size_t off = 0;
  char buf[64];
  string_concat(cmd, len, &off,
		"ping -O tbt -U %d -c 2 -o 1 -s 1300 -M 1280 %s",
		mode, scamper_addr_tostr(target->addr, buf, sizeof(buf)));
  return off;
}

static sc_target_t *target_classify(void)
{
  return slist_head_pop(probelist);
}

static sc_target_t *target_descend(void)
{
  return slist_head_pop(probelist);
}

static sc_target_t *target_overlap(void)
{
  sc_targetset_t *ts, *tt;
  sc_target_t *tg;
  dlist_node_t *dn;
  slist_node_t *sn;

  for(;;)
    {
      if((ts = slist_head_pop(probelist)) == NULL)
	return NULL;
      for(dn=dlist_head_node(overlap_act); dn != NULL; dn=dlist_node_next(dn))
	{
	  tt = dlist_node_item(dn);
	  if(timeval_overlap(&ts->min, &ts->max, &tt->min, &tt->max) != 0)
	    break;
	}
      if(dn == NULL)
	break;
      if(slist_tail_push(tt->blocked, ts) == NULL)
	return NULL;
      blocked++;
    }

  if((ts->node = dlist_tail_push(overlap_act, ts)) == NULL)
    return NULL;

  slist_qsort(ts->targets, (slist_cmp_t)sc_target_ipid_cmp);
  sn = slist_head_node(ts->targets);
  tg = slist_node_item(sn);
  tg->attempt = 0;
  tg->ts = ts;
  ts->next = slist_node_next(sn);

  return tg;
}

static sc_target_t *target_descend2(void)
{
  return slist_head_pop(probelist);
}

static sc_targetset_t *targetset_ally(void)
{
  sc_addr2router_t *a2r_a, *a2r_b;
  sc_targetset_t *ts;
  slist_node_t *sn;
  sc_target_t *tg;
  char addr[256];

  while((ts = heap_remove(probeheap)) != NULL)
    {
      /*
       * check if something else is already probing an overlap of
       * these addresses
       */
      for(sn=slist_head_node(ts->targets); sn != NULL; sn=slist_node_next(sn))
	{
	  tg = slist_node_item(sn);
	  if(splaytree_find(targets, tg) != NULL)
	    break;
	}

      /*
       * if there is something else probing an address in this targetset,
       * we block this targetset and move onto the next
       */
      if(sn != NULL)
	{
	  tg = slist_node_item(sn);
	  if(slist_tail_push(tg->ts->blocked, ts) == NULL)
	    {
	      fprintf(stderr, "could not block on %s\n",
		      scamper_addr_tostr(tg->addr, addr, sizeof(addr)));
	      return NULL;
	    }
	  blocked++;
	  continue;
	}

      /* check to see if we already know the answers for this set */
      tg = slist_head_item(ts->targets);
      a2r_a = sc_addr2router_find(tg->addr); assert(a2r_a != NULL);
      sn = slist_node_next(slist_head_node(ts->targets)); assert(sn != NULL);
      while(sn != NULL)
	{
	  tg = slist_node_item(sn);
	  a2r_b = sc_addr2router_find(tg->addr); assert(a2r_b != NULL);
	  if(a2r_a->router != a2r_b->router &&
	     sc_notaliases_check(a2r_a->router, a2r_b->router) == 0)
	    break;
	  sn = slist_node_next(sn);
	}

      /* if we already know the answer, we free the targetset and move on */
      if(sn == NULL)
	{
	  sc_targetset_free(ts);
	  continue;
	}
      break;
    }
  if(ts == NULL)
    return NULL;

  /* install all of the addresses into the targets tree */
  for(sn=slist_head_node(ts->targets); sn != NULL; sn=slist_node_next(sn))
    {
      tg = slist_node_item(sn);
      if((tg->tree_node = splaytree_insert(targets, tg)) == NULL)
	{
	  fprintf(stderr, "could not add %s to tree\n",
		  scamper_addr_tostr(tg->addr, addr, sizeof(addr)));
	  return NULL;
	}
      tg->ts = ts;
    }

  ts->next = slist_node_next(slist_head_node(ts->targets));
  ts->attempt = 0;
  return ts;
}

static int do_method_ping(void)
{
  static int (*const test_func[])(sc_target_t *, char *, size_t) = {
    test_ping6,
    test_ping1,
    test_ping1,
    test_ping1,
  };
  static sc_target_t * (*const target_func[])(void) = {
    target_classify,
    target_descend,
    target_overlap,
    target_descend2,
  };

  sc_target_t *tg;
  sc_wait_t *w;
  char buf[128];

  if((w = heap_head_item(waiting)) != NULL && timeval_cmp(&now, &w->tv) >= 0)
    {
      heap_remove(waiting);
      tg = w->un.target;
      sc_wait_free(w);
    }
  else if((tg = target_func[mode]()) == NULL)
    return 0;

  if((tg->tree_node = splaytree_insert(targets, tg)) == NULL)
    {
      fprintf(stderr, "could not add %s to tree\n",
	      scamper_addr_tostr(tg->addr, buf, sizeof(buf)));
      return -1;
    }

  if(test_func[mode](tg, buf, sizeof(buf)) == -1)
    {
      fprintf(stderr, "something went wrong\n");
      return -1;
    }

  if(scamper_inst_do(scamper_inst, buf, NULL) == NULL)
    {
      fprintf(stderr, "could not send %s\n", buf);
      return -1;
    }

  probing++;
  more--;

  logprint(1, "%s\n", buf);
  return 0;
}

static int do_method_ally(void)
{
  sc_targetset_t *ts;
  sc_target_t *tg;
  sc_wait_t *w;
  char cmd[192], addr[64];
  size_t off = 0;

  if((w = heap_head_item(waiting)) != NULL && timeval_cmp(&now, &w->tv) >= 0)
    {
      heap_remove(waiting);
      ts = w->un.targetset;
      sc_wait_free(w);
    }
  else if((ts = targetset_ally()) == NULL)
    return 0;

  tg = slist_head_item(ts->targets);
  string_concat(cmd, sizeof(cmd), &off,
		"dealias -U %d -m ally -f %u -w 2 -W 1000 -p '%s' %s",
		mode, fudge, "-P icmp-echo -s 1300 -M 1280",
		scamper_addr_tostr(tg->addr, addr, sizeof(addr)));
  tg = slist_node_item(ts->next);
  string_concat(cmd, sizeof(cmd), &off, " %s",
		scamper_addr_tostr(tg->addr, addr, sizeof(addr)));

  if(scamper_inst_do(scamper_inst, cmd, NULL) == NULL)
    {
      fprintf(stderr, "could not send %s\n", cmd);
      return -1;
    }

  probing++;
  more--;

  logprint(1, "%s\n", cmd);
  return 0;
}

static int do_method(void)
{
  int rc;
  if(more < 1)
    return 0;
  if(mode != MODE_ALLY)
    rc = do_method_ping();
  else
    rc = do_method_ally();
  return rc;
}

static int isdone(void)
{
  if(splaytree_count(targets) != 0 || slist_count(probelist) != 0 ||
     heap_count(waiting) != 0)
    return 0;
  return 1;
}

static int finish_classify(void)
{
  slist_node_t *sn;
  sc_target_t *target;

  /*
   * can only move beyond classification stage if there is nothing
   * left to probe
   */
  if(isdone() == 0)
    return 0;

  /*
   * can only move into descend mode if speedtrap is told to continue
   * after classification stage
   */
  if(mode_ok(MODE_DESCEND) == 0)
    return 0;
  mode = MODE_DESCEND;

  /* put all the targets on the probelist, with their state re-set */
  for(sn=slist_head_node(incr); sn != NULL; sn=slist_node_next(sn))
    {
      target = slist_node_item(sn);
      target->attempt = 0;
      target->ts = NULL;
      slist_tail_push(probelist, target);
    }

  /* probe in order of IPIDs observed */
  slist_qsort(probelist, (slist_cmp_t)sc_target_ipid_cmp);
  if((descend = slist_alloc()) == NULL)
    return -1;
  return 0;
}

static int reply_classify(sc_target_t *target, sc_targetipid_t *p,
			  uint16_t ipidc, uint16_t rxd)
{
  char addr[64];
  uint16_t u16;

  scamper_addr_tostr(target->addr, addr, sizeof(addr));

  /* no responses at all: unresponsive */
  if(rxd == 0)
    {
      logprint(1, "%s unresponsive\n", addr);
      sc_target_free(target);
      goto done;
    }

  /* less than three IPID samples, sort of unresponsive */
  if(ipidc < 3)
    {
      logprint(1, "%s ipidc %d\n", addr, ipidc);
      sc_target_free(target);
      goto done;
    }

  /* check for an incrementing sequence: any break and we're done */
  for(u16=0; u16+2 < ipidc; u16++)
    {
      if(ipid_inseq3(p[u16].ipid, p[u16+1].ipid, p[u16+2].ipid) == 0)
	{
	  logprint(1, "%s not inseq %d\n", addr, u16);
	  sc_target_free(target);
	  goto done;
	}
    }

  logprint(1, "%s incr\n", addr);
  target->last = p[ipidc-1].ipid;
  slist_tail_push(incr, target);

 done:
  return finish_classify();
}

static int finish_descend(void)
{
  sc_targetipid_t *ti;
  sc_targetset_t *ts;
  struct timeval tv;

  /* can only move beyond descend stage if there is nothing left to probe */
  if(isdone() == 0)
    return 0;

  /*
   * can only move into descend mode if speedtrap is told to continue
   * after descend stage
   */
  if(mode_ok(MODE_OVERLAP) == 0)
    return 0;
  mode = MODE_OVERLAP;

  slist_qsort(descend, (slist_cmp_t)sc_targetipid_tx_cmp);
  ts = NULL;
  while((ti = slist_head_pop(descend)) != NULL)
    {
      if(ts == NULL || timeval_cmp(&tv, &ti->tx) <= 0)
	{
	  timeval_cpy(&tv, &ti->rx);
	  if((ts = sc_targetset_alloc()) == NULL ||
	     slist_tail_push(probelist, ts) == NULL)
	    return -1;
	  timeval_cpy(&ts->min, &ti->tx);
	  timeval_cpy(&ts->max, &ti->rx);
	}
      else
	{
	  if(timeval_cmp(&ts->max, &ti->rx) < 0)
	    timeval_cpy(&ts->max, &ti->rx);
	}
      slist_tail_push(ts->targets, ti->target);
    }
  slist_free(descend); descend = NULL;

  /*
   * sort the probelist so that longer-length target sets are probed
   * first in an attempt to reduce the overall runtime
   */
  slist_qsort(probelist, (slist_cmp_t)sc_targetset_length_cmp);
  return 0;
}

static int reply_descend(sc_target_t *target, sc_targetipid_t *ipids,
			 uint16_t ipidc, uint16_t rxd)
{
  sc_targetipid_t *ti;
  struct timeval tv;

  if(ipidc == 0)
    {
      if(target->attempt >= 2)
	goto done;
      target->attempt++;
      timeval_add_s(&tv, &now, 1);
      if(sc_wait_target(&tv, target) != 0)
	return -1;
      return 0;
    }

  if((ti = sc_target_sample(target, &ipids[0])) == NULL)
    return -1;
  if(slist_tail_push(descend, ti) == NULL)
    return -1;

 done:
  return finish_descend();
}

static int finish_overlap(void)
{
  sc_target_t *target;
  slist_node_t *sn;

  /* can only move beyond overlap stage if there is nothing left to probe */
  if(isdone() == 0)
    return 0;

  /*
   * can only move into descend2 mode if speedtrap is told to continue
   * after overlap stage
   */
  if(mode_ok(MODE_DESCEND2) == 0)
    return 0;
  mode = MODE_DESCEND2;
  for(sn=slist_head_node(incr); sn != NULL; sn=slist_node_next(sn))
    {
      target = slist_node_item(sn);
      target->attempt = 0;
      target->ts = NULL;
      slist_tail_push(probelist, target);
    }
  slist_qsort(probelist, (slist_cmp_t)sc_target_ipid_cmp);
  return 0;
}

static int reply_overlap(sc_target_t *target, sc_targetipid_t *ipids,
			 uint16_t ipidc, uint16_t rxd)
{
  sc_targetset_t *ts, *tsb;
  sc_target_t *tg;
  struct timeval tv;

  if(ipidc == 0)
    {
      if(target->attempt >= 2)
	goto done;
      target->attempt++;
      timeval_add_s(&tv, &now, 1);
      if(sc_wait_target(&tv, target) != 0)
	return -1;
      return 0;
    }

  if(sc_target_sample(target, &ipids[0]) == NULL)
    return -1;

 done:
  ts = target->ts;
  if(ts->next != NULL)
    {
      tg = slist_node_item(ts->next);
      tg->attempt = 0;
      tg->ts = ts;
      ts->next = slist_node_next(ts->next);
      timeval_add_s(&tv, &now, 1);
      if(sc_wait_target(&tv, tg) != 0)
	return -1;
    }
  else
    {
      while((tsb = slist_head_pop(ts->blocked)) != NULL)
	{
	  /* put the blocked items at the front of the probelist */
	  if(slist_head_push(probelist, tsb) == NULL)
	    return -1;
	  blocked--;
	}

      dlist_node_pop(overlap_act, ts->node);
      sc_targetset_free(ts);
    }

  return finish_overlap();
}

static int finish_descend2(void)
{
  slist_node_t *sa, *sb;
  sc_router_t *r;
  sc_addr2router_t *a2r;
  sc_targetset_t *ts;
  sc_target_t *tg;

  if(isdone() == 0)
    return 0;

  if(mode_ok(MODE_ALLY) == 0)
    return 0;
  mode = MODE_ALLY;

  if(pairwise_all(incr) != 0)
    return -1;
  slist_qsort(candidates, (slist_cmp_t)sc_targetset_targetc_asc_cmp);

  /* create router nodes for all addresses to probe */
  for(sa=slist_head_node(candidates); sa != NULL; sa=slist_node_next(sa))
    {
      ts = slist_node_item(sa);
      sc_targetset_logprint(ts);
      for(sb=slist_head_node(ts->targets); sb != NULL; sb=slist_node_next(sb))
	{
	  tg = slist_node_item(sb);
	  if(sc_addr2router_find(tg->addr) != NULL)
	    continue;
	  if((r = sc_router_alloc()) == NULL ||
	     (a2r = sc_addr2router_alloc(tg->addr, r)) == NULL ||
	     slist_tail_push(r->addrs, a2r) == NULL)
	    return -1;
	}
    }

  if((probeheap=heap_alloc((heap_cmp_t)sc_targetset_targetc_desc_cmp)) == NULL)
    return -1;
  while((ts = slist_head_pop(candidates)) != NULL)
    {
      if(heap_insert(probeheap, ts) == NULL)
	return -1;
    }

  return 0;
}

static int reply_descend2(sc_target_t *target, sc_targetipid_t *ipids,
			  uint16_t ipidc, uint16_t rxd)
{
  struct timeval tv;

  if(ipidc == 0 && target->attempt < 2)
    {
      target->attempt++;
      timeval_add_s(&tv, &now, 1);
      if(sc_wait_target(&tv, target) != 0)
	return -1;
      return 0;
    }

  if(ipidc > 0 && sc_target_sample(target, &ipids[0]) == NULL)
    return -1;

  return finish_descend2();
}

static int do_decoderead_ping(scamper_ping_t *ping)
{
  static int (*const func[])(sc_target_t *, sc_targetipid_t *,
			     uint16_t, uint16_t) = {
    reply_classify,
    reply_descend,
    reply_overlap,
    reply_descend2,
  };
  const scamper_ping_reply_t *reply;
  const struct timeval   *tx;
  sc_target_t            *target;
  char                    buf[64];
  int                     rc = -1;
  sc_targetipid_t         p[6];
  uint16_t                u16, ping_sent;
  uint16_t                probes_rxd = 0;
  uint16_t                ipids_rxd = 0;
  scamper_addr_t         *dst;

  dst = scamper_ping_dst_get(ping);
  if((target = sc_target_findtree(dst)) == NULL)
    {
      fprintf(stderr, "do_decoderead: could not find dst %s\n",
	      scamper_addr_tostr(dst, buf, sizeof(buf)));
      goto done;
    }
  sc_target_detachtree(target);

  ping_sent = scamper_ping_sent_get(ping);
  for(u16=0; u16<ping_sent; u16++)
    {
      if((reply = scamper_ping_reply_get(ping, u16)) == NULL ||
	 scamper_ping_reply_is_icmp_echo_reply(reply) == 0)
	continue;
      probes_rxd++;
      if(scamper_ping_reply_flag_is_reply_ipid(reply))
	{
	  tx = scamper_ping_reply_tx_get(reply);
	  timeval_cpy(&p[ipids_rxd].tx, tx);
	  timeval_add_tv3(&p[ipids_rxd].rx, tx,
			  scamper_ping_reply_rtt_get(reply));
	  p[ipids_rxd].ipid = scamper_ping_reply_ipid32_get(reply);
	  ipids_rxd++;
	}
    }
  scamper_ping_free(ping); ping = NULL;

  rc = func[mode](target, p, ipids_rxd, probes_rxd);

 done:
  if(ping != NULL) scamper_ping_free(ping);
  return rc;
}

static int do_decoderead_dealias(scamper_dealias_t *dealias)
{
  const scamper_dealias_ally_t *ally = scamper_dealias_ally_get(dealias);
  const scamper_dealias_probedef_t *def;
  sc_addr2router_t *a2r_a, *a2r_b, *a2r_c;
  scamper_addr_t *a, *b;
  sc_targetset_t *ts;
  sc_target_t *tg;
  struct timeval tv;
  char ab[64], bb[64], r[16];
  slist_node_t *sn;
  slist_t *list;
  int rc = -1;
  uint8_t result;

  assert(ally != NULL);

  result = scamper_dealias_result_get(dealias);

  def = scamper_dealias_ally_def0_get(ally);
  a = scamper_dealias_probedef_dst_get(def);
  scamper_addr_tostr(a, ab, sizeof(ab));

  def = scamper_dealias_ally_def1_get(ally);
  b = scamper_dealias_probedef_dst_get(def);
  scamper_addr_tostr(b, bb, sizeof(bb));

  a2r_a = sc_addr2router_find(a);
  assert(a2r_a != NULL); assert(a2r_a->router != NULL);
  a2r_b = sc_addr2router_find(b);
  assert(a2r_b != NULL); assert(a2r_b->router != NULL);

  if((tg = sc_target_findtree(a)) == NULL)
    {
      fprintf(stderr, "do_decoderead: could not find dst %s\n", ab);
      goto done;
    }
  ts = tg->ts;

  logprint(1, "%s %s %s\n", ab, bb,
	   scamper_dealias_result_tostr(result, r, sizeof(r)));

  if(result == SCAMPER_DEALIAS_RESULT_ALIASES)
    {
      /* merge two routers together */
      if(a2r_a->router != a2r_b->router)
	{
	  /* merge the sets of "not aliases" together */
	  if(sc_notaliases_merge(a2r_a->router, a2r_b->router) != 0)
	    goto done;

	  /* copy across b's aliases into a */
	  list = a2r_b->router->addrs; a2r_b->router->addrs = NULL;
	  sc_router_free(a2r_b->router); a2r_b->router = NULL;
	  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
	    {
	      a2r_c = slist_node_item(sn);
	      a2r_c->router = a2r_a->router;
	    }
	  slist_concat(a2r_a->router->addrs, list);
	  slist_free(list);
	  assert(a2r_b->router == a2r_a->router);
	}
    }
  else if(result == SCAMPER_DEALIAS_RESULT_NOTALIASES)
    {
      /* mark these routers as not being aliases to save further probing */
      if(a2r_a->router != a2r_b->router)
	{
	  if(sc_notaliases_add(a2r_a->router, a2r_b->router) != 0)
	    goto done;
	}
    }
  else if(result == SCAMPER_DEALIAS_RESULT_NONE && ts->attempt < 2)
    {
      ts->attempt++;
      timeval_add_s(&tv, &now, 1);
      if(sc_wait_targetset(&tv, ts) == 0)
	rc = 0;
      goto done;
    }

  for(;;)
    {
      /*
       * if we are at the end of the list of targets for this set, free
       * the targetset and move on.
       */
      if((ts->next = slist_node_next(ts->next)) == NULL)
	{
	  while((tg = slist_head_pop(ts->targets)) != NULL)
	    {
	      tg->ts = NULL;
	      sc_target_detachtree(tg);
	    }
	  while((tg = slist_head_pop(ts->blocked)) != NULL)
	    {
	      if(heap_insert(probeheap, tg) == NULL)
		goto done;
	      blocked--;
	    }

	  sc_targetset_free(ts);
	  rc = 0;
	  goto done;
	}

      /* skip over if the transitive closure implies we know the answer */
      tg = slist_node_item(ts->next);
      a2r_c = sc_addr2router_find(tg->addr); assert(a2r_c != NULL);
      if(a2r_a->router == a2r_c->router ||
	 sc_notaliases_check(a2r_a->router, a2r_c->router) == 1)
	continue;

      /* probe this address */
      break;
    }
  ts->attempt = 0;
  timeval_cpy(&tv, &now);
  if(sc_wait_targetset(&tv, ts) == 0)
    rc = 0;

 done:
  if(dealias != NULL) scamper_dealias_free(dealias);
  return rc;
}

static void ctrlcb(scamper_inst_t *inst, uint8_t type, scamper_task_t *task,
		   const void *data, size_t len)
{
  uint16_t obj_type;
  void *obj_data;

  gettimeofday_wrap(&now);

  if(type == SCAMPER_CTRL_TYPE_MORE)
    {
      more++;
      do_method();
    }
  else if(type == SCAMPER_CTRL_TYPE_DATA)
    {
      if(scamper_file_readbuf_add(decode_rb, data, len) != 0 ||
	 scamper_file_read(decode_sf, ffilter, &obj_type, &obj_data) != 0)
	{
	  fprintf(stderr, "%s: could not read\n", __func__);
	  goto err;
	}

      if(obj_data == NULL)
	return;

      if(scamper_file_write_obj(outfile, obj_type, obj_data) != 0)
	{
	  fprintf(stderr, "%s: could not write obj %d\n", __func__, obj_type);
	  goto err;
	}

      if(obj_type == SCAMPER_FILE_OBJ_CYCLE_START ||
	 obj_type == SCAMPER_FILE_OBJ_CYCLE_STOP)
	{
	  scamper_cycle_free(obj_data);
	  return;
	}

      probing--;
      if((obj_type == SCAMPER_FILE_OBJ_PING &&
	  do_decoderead_ping(obj_data) != 0) ||
	 (obj_type == SCAMPER_FILE_OBJ_DEALIAS &&
	  do_decoderead_dealias(obj_data) != 0))
	goto err;
    }
  else if(type == SCAMPER_CTRL_TYPE_ERR)
    {
      /* XXX: handle a "command not accepted" more gracefully */
      goto err;
    }
  else if(type == SCAMPER_CTRL_TYPE_EOF)
    {
      scamper_inst_free(scamper_inst);
      scamper_inst = NULL;
    }
  else if(type == SCAMPER_CTRL_TYPE_FATAL)
    {
      logprint(1, "fatal: %s", scamper_ctrl_strerror(scamper_ctrl));
      goto err;
    }
  return;

 err:
  error = 1;
  return;
}

static int addressfile_line(char *addr, void *param)
{
  splaytree_t *tree = param;
  scamper_addr_t *a = NULL;

  if(addr[0] == '#' || addr[0] == '\0')
    return 0;

  if((a = scamper_addr_fromstr_ipv6(addr)) == NULL)
    {
      fprintf(stderr, "could not resolve '%s'\n", addr);
      return -1;
    }

  /*
   * make sure the address is in 2000::/3
   * and is not already in the probelist
   */
  if(scamper_addr_isunicast(a) != 1 || splaytree_find(tree, a) != NULL)
    {
      scamper_addr_free(a);
      return 0;
    }

  /* make a note that the address is in the list to be probed */
  if(splaytree_insert(tree, a) == NULL)
    {
      scamper_addr_free(a);
      return -1;
    }

  return 0;
}

static int do_addressfile(void)
{
  scamper_addr_t *addr = NULL;
  splaytree_t *tree = NULL;
  slist_t *list = NULL;
  sc_target_t *target = NULL;
  int rc = -1;

  if((tree = splaytree_alloc((splaytree_cmp_t)scamper_addr_cmp)) == NULL ||
     (list = slist_alloc()) == NULL ||
     file_lines(addressfile, addressfile_line, tree) != 0)
    goto done;

  splaytree_inorder(tree, tree_to_slist, list);
  splaytree_free(tree, NULL); tree = NULL;

  while((addr = slist_head_pop(list)) != NULL)
    {
      if((target = sc_target_alloc(addr)) == NULL)
	goto done;
      scamper_addr_free(addr); addr = NULL;

      if(slist_tail_push(probelist, target) == NULL ||
	 ((options & OPT_INCR) && slist_tail_push(incr, target) == NULL))
	{
	  fprintf(stderr, "could push target\n");
	  goto done;
	}
    }

  rc = 0;

 done:
  if(tree != NULL) splaytree_free(tree, (splaytree_free_t)scamper_addr_free);
  if(list != NULL) slist_free_cb(list, (slist_free_t)scamper_addr_free);
  return rc;
}

/*
 * do_scamperconnect
 *
 * allocate socket and connect to scamper process listening on the port
 * specified.
 */
static int do_scamperconnect(void)
{
  const char *type = "unknown";

  if((scamper_ctrl = scamper_ctrl_alloc(ctrlcb)) == NULL)
    {
      fprintf(stderr, "could not alloc scamper_ctrl\n");
      return -1;
    }

  if(options & OPT_PORT)
    {
      type = "port";
      scamper_inst = scamper_inst_inet(scamper_ctrl, NULL, dst_addr, dst_port);
    }
#ifdef HAVE_SOCKADDR_UN
  else if(options & OPT_UNIX)
    {
      type = "unix";
      scamper_inst = scamper_inst_unix(scamper_ctrl, NULL, unix_name);
    }
#endif

  if(scamper_inst == NULL)
    {
      fprintf(stderr, "could not alloc %s inst\n", type);
      return -1;
    }
  return 0;
}

static int speedtrap_data(void)
{
  struct timeval tv, *tv_ptr;
  sc_wait_t *w;

  if((targets = splaytree_alloc((splaytree_cmp_t)sc_target_addr_cmp)) == NULL ||
     (waiting = heap_alloc((heap_cmp_t)sc_wait_cmp)) == NULL ||
     (probelist = slist_alloc()) == NULL ||
     (incr = slist_alloc()) == NULL ||
     (candidates = slist_alloc()) == NULL ||
     (notaliases = splaytree_alloc((splaytree_cmp_t)sc_notaliases_cmp))==NULL||
     (overlap_act = dlist_alloc()) == NULL ||
     do_addressfile() != 0 || do_scamperconnect() != 0 ||
     (outfile = scamper_file_open(outfile_name, 'w', outfile_type)) == NULL ||
     (decode_sf = scamper_file_opennull('r', "warts")) == NULL ||
     (decode_rb = scamper_file_readbuf_alloc()) == NULL)
    return -1;

  scamper_file_setreadfunc(decode_sf, decode_rb, scamper_file_readbuf_read);
  random_seed();
  slist_shuffle(probelist);

  if(options & OPT_INCR)
    {
      mode = MODE_DESCEND;
      if((descend = slist_alloc()) == NULL)
	return -1;
    }

  while(scamper_ctrl_isdone(scamper_ctrl) == 0)
    {
      /*
       * need to set a timeout on select if scamper's processing window is
       * not full and there is a task in the waiting queue.
       */
      tv_ptr = NULL;
      gettimeofday_wrap(&now);

      if(more > 0)
	{
	  /*
	   * if there is something ready to probe now, then try and
	   * do it.
	   */
	  w = heap_head_item(waiting);
	  if(slist_count(probelist) > 0 ||
	     (probeheap != NULL && heap_count(probeheap) > 0) ||
	     (w != NULL && timeval_cmp(&w->tv, &now) <= 0))
	    {
	      if(do_method() != 0)
		return -1;
	    }

	  /*
	   * if we could not send a new command just yet, but scamper
	   * wants one, then wait for an appropriate length of time.
	   */
	  w = heap_head_item(waiting);
	  if(more > 0 && w != NULL)
	    {
	      tv_ptr = &tv;
	      if(timeval_cmp(&w->tv, &now) > 0)
		timeval_diff_tv(&tv, &now, &w->tv);
	      else
		memset(&tv, 0, sizeof(tv));
	    }
	}

      if(splaytree_count(targets) == 0 && slist_count(probelist) == 0 &&
	 (probeheap == NULL || heap_count(probeheap) == 0) &&
	 heap_count(waiting) == 0 && done == 0)
	{
	  scamper_inst_done(scamper_inst);
	  done = 1;
	  logprint(1, "done\n");
	}

      scamper_ctrl_wait(scamper_ctrl, tv_ptr);

      if(error != 0)
	break;
    }

  return 0;
}

static int ping_read(const scamper_ping_t *ping, uint32_t *ipids,
		     int *ipidc, int *replyc)
{
  const scamper_ping_reply_t *reply;
  uint16_t i, ping_sent;
  int maxipidc = *ipidc;

  *ipidc = 0;
  *replyc = 0;

  ping_sent = scamper_ping_sent_get(ping);
  for(i=0; i<ping_sent; i++)
    {
      if((reply = scamper_ping_reply_get(ping, i)) == NULL)
	continue;
      if(scamper_ping_reply_is_icmp_echo_reply(reply) == 0)
	continue;
      (*replyc)++;
      if(scamper_ping_reply_flag_is_reply_ipid(reply))
	{
	  if(*ipidc == maxipidc)
	    return -1;
	  ipids[*ipidc] = scamper_ping_reply_ipid32_get(reply);
	  (*ipidc)++;
	}
    }

  return 0;
}

static int process_1_ping(const scamper_ping_t *ping)
{
  sc_router_t *r;
  sc_addr2router_t *a2r;
  scamper_addr_t *dst;
  uint32_t ipids[10];
  int ipidc, replyc;

  if(scamper_ping_userid_get(ping) != 0)
    return 0;

  ipidc = sizeof(ipids) / sizeof(uint32_t);
  if(ping_read(ping, ipids, &ipidc, &replyc) != 0)
    return -1;
  if(ipid_incr(ipids, ipidc) == 0)
    return 0;

  dst = scamper_ping_dst_get(ping);
  if(sc_addr2router_find(dst) != NULL)
    return 0;

  if((r = sc_router_alloc()) == NULL ||
     (a2r = sc_addr2router_alloc(dst, r)) == NULL ||
     slist_tail_push(r->addrs, a2r) == NULL)
    return -1;
  return 0;
}

static int process_1_ally(const scamper_dealias_t *dealias)
{
  const scamper_dealias_ally_t *ally = scamper_dealias_ally_get(dealias);
  const scamper_dealias_probedef_t *def;
  sc_addr2router_t *a2r_a, *a2r_b, *a2r_c;
  slist_t *list;
  sc_router_t *r;
  slist_node_t *sn;
  scamper_addr_t *a, *b;

  if(scamper_dealias_result_get(dealias) != SCAMPER_DEALIAS_RESULT_ALIASES)
    return 0;

  def = scamper_dealias_ally_def0_get(ally);
  a = scamper_dealias_probedef_dst_get(def);
  def = scamper_dealias_ally_def1_get(ally);
  b = scamper_dealias_probedef_dst_get(def);

  a2r_a = sc_addr2router_find(a);
  a2r_b = sc_addr2router_find(b);

  if(a2r_a != NULL && a2r_b != NULL)
    {
      if(a2r_a->router != a2r_b->router)
	{
	  list = a2r_b->router->addrs; a2r_b->router->addrs = NULL;
	  sc_router_free(a2r_b->router); a2r_b->router = NULL;
	  for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
	    {
	      a2r_c = slist_node_item(sn);
	      a2r_c->router = a2r_a->router;
	    }
	  slist_concat(a2r_a->router->addrs, list);
	  slist_free(list);
	}
    }
  else if(a2r_a != NULL)
    {
      r = a2r_a->router;
      if((a2r_b = sc_addr2router_alloc(b, r)) == NULL ||
	 slist_tail_push(a2r_a->router->addrs, a2r_b) == NULL)
	goto err;
    }
  else if(a2r_b != NULL)
    {
      r = a2r_b->router;
      if((a2r_a = sc_addr2router_alloc(a, r)) == NULL ||
	 slist_tail_push(a2r_b->router->addrs, a2r_a) == NULL)
	goto err;
    }
  else
    {
      if((r = sc_router_alloc()) == NULL ||
	 (a2r_a = sc_addr2router_alloc(a, r)) == NULL ||
	 slist_tail_push(r->addrs, a2r_a) == NULL ||
	 (a2r_b = sc_addr2router_alloc(b, r)) == NULL ||
	 slist_tail_push(r->addrs, a2r_b) == NULL)
	goto err;
    }

  return 0;

 err:
  return -1;
}

static void finish_1(void)
{
  sc_addr2router_t *a2r;
  dlist_node_t *dn;
  slist_node_t *sn;
  sc_router_t *r;
  char buf[128];
  int x;

  for(dn=dlist_head_node(routers); dn != NULL; dn=dlist_node_next(dn))
    {
      r = dlist_node_item(dn);
      slist_qsort(r->addrs, (slist_cmp_t)sc_addr2router_human_cmp);
    }
  dlist_qsort(routers, (dlist_cmp_t)sc_router_cmp);
  for(dn=dlist_head_node(routers); dn != NULL; dn=dlist_node_next(dn))
    {
      r = dlist_node_item(dn); x = 0;
      for(sn=slist_head_node(r->addrs); sn != NULL; sn=slist_node_next(sn))
	{
	  a2r = slist_node_item(sn);
	  if(x != 0) printf(" ");
	  printf("%s", scamper_addr_tostr(a2r->addr, buf, sizeof(buf)));
	  x++;
	}
      printf("\n");
    }

  return;
}

static int process_2_ping(const scamper_ping_t *ping)
{
  uint32_t ipids[10];
  int ipidc, replyc;
  char buf[64];

  if(scamper_ping_userid_get(ping) != 0)
    {
      dump_stop = 1;
      return 0;
    }

  ipidc = sizeof(ipids) / sizeof(uint32_t);
  if(ping_read(ping, ipids, &ipidc, &replyc) != 0)
    return -1;

  scamper_addr_tostr(scamper_ping_dst_get(ping), buf, sizeof(buf));
  if(ipidc == 0)
    {
      if(replyc == 0)
	printf("%s unresponsive\n", buf);
      else if(replyc == 1)
	printf("%s gone-silent\n", buf);
      else
	printf("%s no-frags\n", buf);
    }
  else if(ipidc < 3)
    printf("%s insuff-ipids\n", buf);
  else if(ipid_incr(ipids, ipidc) == 0)
    printf("%s random\n", buf);
  else
    printf("%s incr\n", buf);

  return 0;
}

static int            d3_states_probec[6];
static struct timeval d3_states_first[6];
static struct timeval d3_states_last[6];

static int process_3_ping(const scamper_ping_t *ping)
{
  const struct timeval *start = scamper_ping_start_get(ping);
  uint32_t id = scamper_ping_userid_get(ping);

  if(timeval_cmp(&d3_states_first[id], start) > 0 ||
     d3_states_first[id].tv_sec == 0)
    timeval_cpy(&d3_states_first[id], start);
  if(timeval_cmp(&d3_states_last[id], start) < 0)
    timeval_cpy(&d3_states_last[id], start);
  d3_states_probec[id] += scamper_ping_sent_get(ping);
  return 0;
}

static int process_3_ally(const scamper_dealias_t *dealias)
{
  uint32_t id = scamper_dealias_userid_get(dealias);
  const struct timeval *start = scamper_dealias_start_get(dealias);

  d3_states_probec[id] += scamper_dealias_probec_get(dealias);
  if(timeval_cmp(&d3_states_first[id], start) > 0 ||
     d3_states_first[id].tv_sec == 0)
    timeval_cpy(&d3_states_first[id], start);
  if(timeval_cmp(&d3_states_last[id], start) < 0)
    timeval_cpy(&d3_states_last[id], start);

  return 0;
}

static void finish_3(void)
{
  int h, m, s, i, sum_time = 0, sum_probes = 0;
  struct timeval tv;

  for(i=0; i<6; i++)
    {
      if(d3_states_probec[i] == 0)
	continue;
      timeval_diff_tv(&tv, &d3_states_first[i], &d3_states_last[i]);
      hms(tv.tv_sec, &h, &m, &s);
      assert((h * 3600) + (m * 60) + s == tv.tv_sec);
      printf("%d: %d %d:%02d:%02d\n", i, d3_states_probec[i], h, m, s);
      sum_time += tv.tv_sec;
      sum_probes += d3_states_probec[i];
    }
  hms(sum_time, &h, &m, &s);
  printf("total: %d %d:%02d:%02d\n", sum_probes, h, m, s);

  return;
}

static int process_4_ping(const scamper_ping_t *ping)
{
  const scamper_ping_reply_t *reply;
  const struct timeval *tx;
  sc_target_t *target;
  sc_targetipid_t ti;
  uint32_t userid;
  uint16_t u16, ping_sent;
  scamper_addr_t *dst;

  /* only interested in the first three stages */
  userid = scamper_ping_userid_get(ping);
  if(userid != MODE_DESCEND &&
     userid != MODE_OVERLAP &&
     userid != MODE_DESCEND2)
    return 0;

  if(targets == NULL &&
     (targets = splaytree_alloc((splaytree_cmp_t)sc_target_addr_cmp)) == NULL)
    return -1;

  dst = scamper_ping_dst_get(ping);
  if((target = sc_target_findtree(dst)) == NULL)
    {
      if((target = sc_target_alloc(dst)) == NULL ||
	 (target->tree_node = splaytree_insert(targets, target)) == NULL)
	return -1;
    }

  ping_sent = scamper_ping_sent_get(ping);
  for(u16=0; u16<ping_sent; u16++)
    {
      if((reply = scamper_ping_reply_get(ping, u16)) == NULL ||
	 scamper_ping_reply_is_icmp_echo_reply(reply) == 0 ||
	 scamper_ping_reply_flag_is_reply_ipid(reply) == 0)
	continue;

      /* record the response */
      ti.target = target;
      ti.ipid = scamper_ping_reply_ipid32_get(reply);
      tx = scamper_ping_reply_tx_get(reply);
      timeval_cpy(&ti.tx, tx);
      timeval_add_tv3(&ti.rx, tx, scamper_ping_reply_rtt_get(reply));
      if(sc_target_sample(target, &ti) == NULL)
	return -1;
    }

  return 0;
}

static void finish_4(void)
{
  slist_t *tg_list = NULL, *sets = NULL;
  slist_node_t *sa, *sb;
  sc_target_t *ta, *tb;
  sc_targetset_t *ts;
  char ba[128], bb[128];
  int i = 0;

  if((candidates = slist_alloc()) == NULL)
    goto done;
  if((tg_list = slist_alloc()) == NULL || (sets = slist_alloc()) == NULL)
    goto done;
  splaytree_inorder(targets, tree_to_slist, tg_list);
  if(pairwise_all(tg_list) != 0)
    goto done;
  slist_qsort(candidates, (slist_cmp_t)sc_targetset_targetc_asc_cmp);

  while((ts = slist_head_pop(candidates)) != NULL)
    {
      if(i > 0)
	printf("\n");

      sa = slist_head_node(ts->targets);
      ta = slist_node_item(sa);

      for(sb=slist_node_next(sa); sb != NULL; sb=slist_node_next(sb))
	{
	  tb = slist_node_item(sb);
	  if(pairwise(ta, tb) == 1)
	    printf("%s %s\n",
		   scamper_addr_tostr(ta->addr, ba, sizeof(ba)),
		   scamper_addr_tostr(tb->addr, bb, sizeof(bb)));
	}

      sc_targetset_free(ts);
      i++;
    }

 done:
  if(tg_list != NULL) slist_free(tg_list);
  if(sets != NULL) slist_free_cb(sets, (slist_free_t)sc_targetset_free);
  return;
}

static int speedtrap_read(void)
{
  scamper_file_t *in;
  char *filename;
  uint16_t type;
  void *data;
  int i, stdin_used=0;

  for(i=0; i<dump_filec; i++)
    {
      filename = dump_files[i]; dump_stop = 0;

      if(string_isdash(filename) != 0)
	{
	  if(stdin_used == 1)
	    {
	      fprintf(stderr, "stdin already used\n");
	      return -1;
	    }
	  stdin_used++;
	  in = scamper_file_openfd(STDIN_FILENO, "-", 'r', "warts");
	}
      else
	{
	  in = scamper_file_open(filename, 'r', NULL);
	}

      if(in == NULL)
	{
	  fprintf(stderr,"could not open %s: %s\n", filename, strerror(errno));
	  return -1;
	}

      while(scamper_file_read(in, ffilter, &type, &data) == 0)
	{
	  /* EOF */
	  if(data == NULL)
	    break;

	  if(type == SCAMPER_FILE_OBJ_PING)
	    {
	      if(dump_funcs[dump_id].proc_ping != NULL)
		dump_funcs[dump_id].proc_ping(data);
	      scamper_ping_free(data);
	    }
	  else if(type == SCAMPER_FILE_OBJ_DEALIAS)
	    {
	      if(dump_funcs[dump_id].proc_ally != NULL)
		dump_funcs[dump_id].proc_ally(data);
	      scamper_dealias_free(data);
	    }

	  if(dump_stop != 0)
	    break;
	}

      scamper_file_close(in);
    }

  if(dump_funcs[dump_id].finish != NULL)
    dump_funcs[dump_id].finish();

  return 0;
}

static int speedtrap_init(void)
{
  uint16_t types[4];
  int typec = 0;

#ifdef HAVE_PTHREAD
  int i;
#endif

  types[typec++] = SCAMPER_FILE_OBJ_PING;
  types[typec++] = SCAMPER_FILE_OBJ_DEALIAS;
  if(options & OPT_OUTFILE)
    {
      types[typec++] = SCAMPER_FILE_OBJ_CYCLE_START;
      types[typec++] = SCAMPER_FILE_OBJ_CYCLE_STOP;
    }
  if((ffilter = scamper_file_filter_alloc(types, typec)) == NULL)
    return -1;

#ifdef HAVE_PTHREAD
  if(threadc == -1)
    {
      threadc = 1;
#ifdef _SC_NPROCESSORS_ONLN
      if((i = sysconf(_SC_NPROCESSORS_ONLN)) > 1)
	threadc = i;
#endif
    }
#else
  threadc = 0;
#endif

  if((addr2routers =
      splaytree_alloc((splaytree_cmp_t)sc_addr2router_cmp)) == NULL ||
     (routers = dlist_alloc()) == NULL)
    return -1;

  return 0;
}

static void cleanup(void)
{
  if(dst_addr != NULL)
    {
      free(dst_addr);
      dst_addr = NULL;
    }

  if(addr2routers != NULL)
    {
      splaytree_free(addr2routers, (splaytree_free_t)sc_addr2router_free);
      addr2routers = NULL;
    }

  if(routers != NULL)
    {
      dlist_foreach(routers, (dlist_foreach_t)sc_router_node_setnull, NULL);
      dlist_free_cb(routers, (dlist_free_t)sc_router_free);
      routers = NULL;
    }

  if(pairwise_uint32 != NULL)
    {
      free(pairwise_uint32);
      pairwise_uint32 = NULL;
    }

  if(pairwise_tipid != NULL)
    {
      free(pairwise_tipid);
      pairwise_tipid = NULL;
    }

  if(notaliases != NULL)
    {
      splaytree_free(notaliases, (splaytree_free_t)sc_notaliases_free);
      notaliases = NULL;
    }

  if(descend != NULL)
    {
      slist_free(descend);
      descend = NULL;
    }

  if(incr != NULL)
    {
      slist_free_cb(incr, (slist_free_t)sc_target_free);
      incr = NULL;
    }

  if(targets != NULL)
    {
      splaytree_free(targets, NULL);
      targets = NULL;
    }

  if(candidates != NULL)
    {
      slist_free(candidates);
      candidates = NULL;
    }

  if(overlap_act != NULL)
    {
      dlist_free(overlap_act);
      overlap_act = NULL;
    }

  if(probelist != NULL)
    {
      slist_free(probelist);
      probelist = NULL;
    }

  if(probeheap != NULL)
    {
      heap_free(probeheap, NULL);
      probeheap = NULL;
    }

  if(waiting != NULL)
    {
      heap_free(waiting, NULL);
      waiting = NULL;
    }

  if(outfile != NULL)
    {
      scamper_file_close(outfile);
      outfile = NULL;
    }

  if(ffilter != NULL)
    {
      scamper_file_filter_free(ffilter);
      ffilter = NULL;
    }

  if(decode_rb != NULL)
    {
      scamper_file_readbuf_free(decode_rb);
      decode_rb = NULL;
    }

  if(decode_sf != NULL)
    {
      scamper_file_close(decode_sf);
      decode_sf = NULL;
    }

  if(scamper_inst != NULL)
    {
      scamper_inst_free(scamper_inst);
      scamper_inst = NULL;
    }

  if(scamper_ctrl != NULL)
    {
      scamper_ctrl_free(scamper_ctrl);
      scamper_ctrl = NULL;
    }

  if(logfile != NULL)
    {
      fclose(logfile);
      logfile = NULL;
    }

  return;
}

int main(int argc, char *argv[])
{
#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    return -1;

  if(speedtrap_init() != 0)
    return -1;

  if(options & OPT_DUMP)
    return speedtrap_read();

  return speedtrap_data();
}
