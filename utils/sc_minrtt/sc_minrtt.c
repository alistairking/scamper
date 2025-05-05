/*
 * sc_minrtt: dump RTT values by node for use by sc_hoiho
 *
 * $Id: sc_minrtt.c,v 1.23 2025/04/21 03:24:13 mjl Exp $
 *
 *         Matthew Luckie
 *         mjl@luckie.org.nz
 *
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

#include <sqlite3.h>

#ifdef HAVE_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#else
#include <pcre.h>
#endif

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

#include <assert.h>

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_ping.h"
#include "scamper_dealias.h"
#include "scamper_file.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
#include "mjl_threadpool.h"
#include "mjl_heap.h"
#include "utils.h"

#define OPT_HELP        0x0001
#define OPT_DBFILE      0x0002
#define OPT_CREATE      0x0004
#define OPT_IMPORT      0x0008
#define OPT_PROCESS     0x0010
#define OPT_REGEX       0x0020
#define OPT_THREADC     0x0040
#define OPT_VPLOCFILE   0x0080
#define OPT_RTRFILE     0x0100
#define OPT_BATCHC      0x0200

#ifdef PACKAGE_VERSION
#define OPT_VERSION     0x0400
#endif

/* this is the same order that sc_pinger uses */
#define RTT_METHOD_ICMP_ECHO  1
#define RTT_METHOD_UDP        2
#define RTT_METHOD_TCP_ACK_SP 3

/*
 * blob size consists of 150 samples and a 2 byte index.  each sample
 * contains:
 * - 1 byte method,
 * - 2 byte VP id,
 * - 1 byte reply TTL,
 * - 4 byte RTT
 */
#define SAMPLE_SIZE (1 + 2 + 1 + 4)
#define BLOB_SIZE_MIN ((SAMPLE_SIZE * 150) + 2)

typedef struct sc_vp sc_vp_t;

typedef struct sc_dst
{
  scamper_addr_t *addr;
  sqlite3_int64   id;
  sqlite3_int64   samples_rowid;
  uint8_t         flags;
} sc_dst_t;

typedef struct sc_vpmeth
{
  sc_vp_t        *vp;
  uint8_t         meth;
  uint16_t        pc;
  uint32_t        bad, total;
} sc_vpmeth_t;

struct sc_vp
{
  char           *name;
  sqlite3_int64   id;
  double          lat, lng;   /* lag / lng */
  double          latr, lngr; /* radians */
  uint8_t         loc;
  uint8_t         bad[4][256];
  sc_vpmeth_t     meth[4];
};

typedef struct sc_sample
{
  sc_vp_t        *vp;      /* the VP that collected the sample */
  scamper_addr_t *addr;    /* the address probed */
  uint8_t         method;  /* which method obtained this sample */
  uint8_t         skip;    /* should skip this sample */
  uint8_t         rx_ttl;  /* ttl field of the reply */
  uint32_t        rtt;     /* rtt, in microseconds */
  struct timeval  tx;      /* transit time */
  uint16_t        bad;     /* number of VPs disagreeing with sample */
} sc_sample_t;

typedef struct sc_rxsec
{
  time_t          sec;     /* sec for bucketing samples */
  slist_t        *list;    /* list of samples */
} sc_rxsec_t;

typedef struct sc_dstlist
{
  scamper_addr_t *addr;    /* the address probed */
  slist_t        *list;    /* list of samples */
} sc_dstlist_t;

typedef struct sc_router
{
  uint32_t        id;      /* router id */
  slist_t        *addrs;   /* list of scamper_addr_t */
} sc_router_t;

typedef struct sc_routerload
{
  slist_t        *routers; /* list of sc_router_t */
  slist_t        *addrs;   /* list of scamper_addr_t */
  uint32_t        id;      /* node id */
  uint8_t         gotid;   /* is node id set */
} sc_routerload_t;

typedef struct sc_filedata
{
  slist_t        *samples;
  sc_vp_t        *vp;
  uint32_t        runlens[4][256];
  char           *filename;
} sc_filedata_t;

typedef struct sc_fdheap
{
  scamper_addr_t *addr;
  sc_filedata_t  *fd;
} sc_fdheap_t;

static uint32_t        options  = 0;
static splaytree_t    *dst_tree = NULL;
static slist_t        *dst_list = NULL;
static splaytree_t    *vp_tree  = NULL;
static sc_vp_t       **vp_array = NULL;
static int             vp_c     = 0;
static const char     *dbfile   = NULL;
static sqlite3        *db       = NULL;
static const char     *vp_regex = NULL;
static char          **opt_args = NULL;
static int             opt_argc = 0;
static threadpool_t   *tp       = NULL;
static long            threadc  = -1;
static long            batchc   = -1;
static const char     *vplocfile = NULL;
static int             proc_x   = 0;
static const char     *rtrfile  = NULL;
static int             import_ok = 1;
static uint8_t        *blob_buf = NULL;
static uint16_t        blob_buflen = 0;

#ifdef HAVE_PTHREAD
static pthread_mutex_t db_mutex;
static uint8_t         db_mutex_o = 0;
static pthread_mutex_t data_mutex;
static uint8_t         data_mutex_o = 0;
#endif

#ifdef HAVE_PCRE2
static pcre2_code     *vp_pcre = NULL;
#else
static pcre           *vp_pcre = NULL;
#endif

static sqlite3_stmt   *st_vp_ins = NULL;
static sqlite3_stmt   *st_dst_ins = NULL;
static sqlite3_stmt   *st_dst_upd = NULL;
static sqlite3_stmt   *st_runlen_ins = NULL;
static sqlite3_stmt   *st_sample_ins = NULL;
static sqlite3_stmt   *st_sample_sel = NULL;
static sqlite3_stmt   *st_filename_sel = NULL;
static sqlite3_stmt   *st_filename_ins = NULL;
static sqlite3_blob   *blob = NULL;

static void usage(uint32_t opt_mask)
{
  const char *v = "";
  const char *t = "";

#ifdef OPT_VERSION
  v = "v";
#endif

#ifdef HAVE_PTHREAD
  t = " [-t threadc]";
#endif
  
  fprintf(stderr,
    "usage: sc_minrtt [-c] [-d dbfile]\n"
    "\n");
  fprintf(stderr,
    "       sc_minrtt [-i] [-b batchc] [-d dbfile] [-R regex]%s\n"
    "                 in1.warts .. inN.warts\n"
    "\n", t);
  fprintf(stderr,
    "       sc_minrtt [-p mode] [-d dbfile] [-r rtrfile]%s\n"
    "                 [-V vploc]\n"
    "\n", t);

  if(opt_mask == 0)
    fprintf(stderr, "       sc_minrtt -?%s\n\n", v);

  return;
}

static int check_options(int argc, char *argv[])
{
  char opts[32], *opt_batchc = NULL;
  size_t off = 0;
  uint32_t u32;
  long lo;
  int ch;

#ifdef HAVE_PTHREAD
  char *opt_threadc = NULL;
#endif

  string_concat(opts, sizeof(opts), &off, "?b:cd:ip:r:R:V:");
#ifdef HAVE_PTHREAD
  string_concat(opts, sizeof(opts), &off, "t:");
#endif
#ifdef OPT_VERSION
  string_concatc(opts, sizeof(opts), &off, 'v');
#endif

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'b':
	  options |= OPT_BATCHC;
	  opt_batchc = optarg;
	  break;

	case 'c':
	  options |= OPT_CREATE;
	  break;

	case 'd':
	  options |= OPT_DBFILE;
	  dbfile = optarg;
	  break;

	case 'i':
	  options |= OPT_IMPORT;
	  break;

	case 'p':
	  options |= OPT_PROCESS;
	  if(string_tolong(optarg, &lo) != 0 || lo < 1 || lo > 2)
	    {
	      usage(OPT_PROCESS);
	      return -1;
	    }
	  proc_x = lo;
	  break;

	case 'r':
	  options |= OPT_RTRFILE;
	  rtrfile = optarg;
	  break;

	case 'R':
	  options |= OPT_REGEX;
	  vp_regex = optarg;
	  break;

#ifdef HAVE_PTHREAD
	case 't':
	  options |= OPT_THREADC;
	  opt_threadc = optarg;
	  break;
#endif

#ifdef OPT_VERSION
	case 'v':
	  options |= OPT_VERSION;
	  return 0;
#endif

	case 'V':
	  options |= OPT_VPLOCFILE;
	  vplocfile = optarg;
	  break;

	default:
	  usage(0);
	  return -1;
	}
    }

  if(options == 0)
    {
      usage(0);
      return -1;
    }

  opt_args = argv + optind;
  opt_argc = argc - optind;

  /* the database file has to be specified */
  if((options & OPT_DBFILE) == 0)
    {
      usage(OPT_DBFILE);
      return -1;
    }

  u32 = OPT_CREATE | OPT_IMPORT | OPT_PROCESS;
  if(countbits32(options & u32) != 1)
    {
      usage(0);
      return -1;
    }

  if(options & OPT_IMPORT)
    {
      if(vp_regex == NULL)
	{
	  usage(OPT_IMPORT | OPT_REGEX);
	  return -1;
	}
    }

  if(options & OPT_PROCESS)
    {
      if(vplocfile == NULL)
	{
	  usage(OPT_PROCESS | OPT_VPLOCFILE);
	  return -1;
	}
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

  if(opt_batchc != NULL)
    {
      if(string_tolong(opt_batchc, &lo) != 0 || lo < 1)
	{
	  usage(OPT_BATCHC);
	  return -1;
	}
#ifdef HAVE_PTHREAD
      if(threadc != -1 && threadc > batchc)
	{
	  usage(OPT_BATCHC | OPT_THREADC);
	  fprintf(stderr, "batch size should not be smaller than thread count");
	  return -1;
	}
#endif
      batchc = lo;
    }

  return 0;
}

static int tree_to_slist(void *ptr, void *entry)
{
  if(slist_tail_push((slist_t *)ptr, entry) != NULL)
    return 0;
  return -1;
}

static const char *method_str(uint8_t method)
{
  static const char *tbl[] = {"", "icmp-echo", "udp-dport", "tcp-ack-sport"};
  if(method > 3)
    return "";
  return tbl[method];
}

/*
 * vp_dist
 *
 * return the distance, in meters, between two vantage points.
 */
static double vp_dist(sc_vp_t *a, sc_vp_t *b)
{
  double radius = 6371008.8, ave_lat, ave_lon, squared;
  ave_lat = (b->latr - a->latr) / 2.0;
  ave_lon = (b->lngr - a->lngr) / 2.0;
  squared =
    pow(sin(ave_lat), 2) + cos(a->latr) * cos(b->latr) * pow(sin(ave_lon), 2);
  return 2 * radius * asin(sqrt(squared));
}

/*
 * dist2rtt
 *
 * return the minimum RTT, in microseconds, expected for the distance,
 * in meters.
 */
static uint32_t dist2rtt(double dist)
{
  double d = floor((dist * 2) / 204.190477);
  return ((uint32_t)d);
}

/*
 * rtt2dist
 *
 * return the distance limit, in meters, implied by the RTT value,
 * in microseconds.
 */
static double rtt2dist(uint32_t rtt)
{
  return (204.190477 * rtt) / 2;
}

static char *percentage(char *buf, size_t len, uint32_t x, uint32_t y)
{
  if(y == 0)
    snprintf(buf, len, "-");
  else
    snprintf(buf, len, "%.1f%%", (float)(x * 100) / y);
  return buf;
}

static char *filename_nopath(char *filename)
{
  char *ptr;
  if((ptr = string_lastof_char(filename, '/')) == NULL)
    return filename;
  else if(ptr[1] != '\0')
    return ptr + 1;
  return NULL;
}

static char *filename_vpname(const char *filename)
{
  #ifdef HAVE_PCRE2
  pcre2_match_data *md = NULL;
  PCRE2_SIZE *ovector = NULL;
#else
  int ovector[6];
#endif

  size_t len = strlen(filename);
  char *vp_name = NULL;
  int x;

#ifdef HAVE_PCRE2
  if((md = pcre2_match_data_create(2, NULL)) == NULL)
    goto done;
  if(pcre2_match(vp_pcre, (PCRE2_SPTR)filename, len, 0, 0, md, NULL) <= 0)
    {
      fprintf(stderr, "%s: regex %s did not match %s\n",
	      __func__, vp_regex, filename);
      goto done;
    }
  ovector = pcre2_get_ovector_pointer(md);
#else
  if(pcre_exec(vp_pcre, NULL, filename, len, 0, 0, ovector, 6) <= 0)
    {
      fprintf(stderr, "%s: regex %s did not match %s\n",
	      __func__, vp_regex, filename);
      goto done;
    }
#endif

  len = ovector[2+1] - ovector[2] + 1;
  if((vp_name = malloc(len)) == NULL)
    {
      fprintf(stderr, "%s: could not malloc %d bytes\n", __func__,
	      (int)len);
      goto done;
    }
  x = ovector[2+1] - ovector[2];
  memcpy(vp_name, filename + ovector[2], x);
  vp_name[x] = '\0';

 done:
#ifdef HAVE_PCRE2
  if(md != NULL) pcre2_match_data_free(md);
#endif
  return vp_name;
}

static void sc_router_free(sc_router_t *rtr)
{
  if(rtr->addrs != NULL)
    slist_free_cb(rtr->addrs, (slist_free_t)scamper_addr_free);
  free(rtr);
  return;
}

static int sc_router_finish(sc_routerload_t *rl)
{
  sc_router_t *rtr = NULL;

  if(rl->gotid == 0 || slist_count(rl->addrs) == 0)
    {
      slist_empty_cb(rl->addrs, (slist_free_t)scamper_addr_free);
      return 0;
    }

  if((rtr = malloc_zero(sizeof(sc_router_t))) == NULL ||
     (rtr->addrs = slist_alloc()) == NULL ||
     slist_tail_push(rl->routers, rtr) == NULL)
    goto err;

  slist_concat(rtr->addrs, rl->addrs);
  rtr->id = rl->id;
  rl->gotid = 0;
  return 0;

 err:
  if(rtr != NULL) sc_router_free(rtr);
  return -1;
}

static int rtrfile_line(char *line, void *param)
{
  sc_routerload_t *rl = param;
  scamper_addr_t *addr = NULL;
  long long ll;
  char *ip, *ptr;

  if(line[0] == '#')
    {
      ptr = line + 1;
      while(*ptr == ' ')
	ptr++;
      if(strncasecmp(ptr, "node2id:", 8) == 0)
	{
	  ptr += 8;
	  while(*ptr == ' ')
	    ptr++;
	  if(string_tollong(ptr, &ll, NULL, 10) == 0)
	    {
	      rl->id = ll;
	      rl->gotid = 1;
	    }
	}
      return 0;
    }

  if(line[0] == '\0')
    {
      if(sc_router_finish(rl) != 0)
	return -1;
      return 0;
    }

  ip = line;
  ptr = line;
  while(*ptr != '\0' && isspace((unsigned char)*ptr) == 0)
    ptr++;
  *ptr = '\0';

  if((addr = scamper_addr_fromstr_unspec(ip)) == NULL ||
     slist_tail_push(rl->addrs, addr) == NULL)
    goto err;

  return 0;

 err:
  return -1;
}

static int sc_vp_cmp(const sc_vp_t *a, const sc_vp_t *b)
{
  return strcasecmp(a->name, b->name);
}

static int sc_vp_id_cmp(const sc_vp_t *a, const sc_vp_t *b)
{
  if(a->id < b->id) return -1;
  if(a->id > b->id) return  1;
  return 0;
}

static sc_vp_t *sc_vp_find(const char *name)
{
  sc_vp_t fm; fm.name = (char *)name;
  return (sc_vp_t *)splaytree_find(vp_tree, &fm);
}

static sc_vp_t *sc_vp_find_id(uint32_t id)
{
  sc_vp_t fm; fm.id = id;
  return array_find((void **)vp_array, vp_c, &fm, (array_cmp_t)sc_vp_id_cmp);
}

static void sc_vp_free(sc_vp_t *vp)
{
  if(vp->name != NULL) free(vp->name);
  free(vp);
  return;
}

static sc_vp_t *sc_vp_alloc(sqlite3_int64 id, const char *name)
{
  sc_vp_t *vp;
  if((vp = malloc_zero(sizeof(sc_vp_t))) == NULL ||
     (vp->name = strdup(name)) == NULL)
    {
      if(vp != NULL) sc_vp_free(vp);
      return NULL;
    }
  vp->id = id;
  return vp;
}

static int sc_vp_insert(sc_vp_t *vp)
{
  if(splaytree_insert(vp_tree, vp) == NULL)
    return -1;
  return 0;
}

static int sc_vpmeth_cmp(sc_vpmeth_t *a, sc_vpmeth_t *b)
{
  if(a->pc > b->pc) return -1;
  if(a->pc < b->pc) return  1;
  return 0;
}

static int sc_dst_cmp(const sc_dst_t *a, const sc_dst_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static sc_dst_t *sc_dst_find(const scamper_addr_t *addr)
{
  sc_dst_t fm; fm.addr = (scamper_addr_t *)addr;
  return (sc_dst_t *)splaytree_find(dst_tree, &fm);
}

static sc_dst_t *sc_dst_alloc(sqlite3_int64 id, scamper_addr_t *addr)
{
  sc_dst_t *dst;
  if((dst = malloc_zero(sizeof(sc_dst_t))) == NULL)
    return NULL;
  dst->addr = addr;
  dst->id = id;
  return dst;
}

static void sc_dst_free(sc_dst_t *dst)
{
  if(dst->addr != NULL)
    scamper_addr_free(dst->addr);
  free(dst);
  return;
}

static void sc_sample_free(sc_sample_t *sample)
{
  if(sample->addr != NULL) scamper_addr_free(sample->addr);
  free(sample);
  return;
}

static sc_sample_t *sc_sample_alloc(scamper_addr_t *addr, sc_vp_t *vp,
				    uint8_t method, uint8_t rxttl, uint32_t rtt)
{
  sc_sample_t *sample;
  if((sample = malloc_zero(sizeof(sc_sample_t))) == NULL)
    return NULL;
  if(addr != NULL)
    sample->addr = scamper_addr_use(addr);
  sample->vp = vp;
  sample->method = method;
  sample->rx_ttl = rxttl;
  sample->rtt    = rtt;
  return sample;
}

static sc_sample_t *sc_sample_add(slist_t *list, sc_vp_t *vp,
				  scamper_addr_t *addr, uint8_t method,
				  uint8_t rx_ttl, uint32_t rtt)
{
  sc_sample_t *sample = NULL;
  if((sample = malloc_zero(sizeof(sc_sample_t))) == NULL ||
     slist_tail_push(list, sample) == NULL)
    {
      if(sample != NULL)
	free(sample);
      return NULL;
    }
  sample->vp = vp;
  sample->method = method;
  sample->rtt = rtt;
  sample->rx_ttl = rx_ttl;
  if(addr != NULL)
    sample->addr = scamper_addr_use(addr);
  return sample;
}

static int sc_sample_ins_cmp(const sc_sample_t *a, const sc_sample_t *b)
{
  if(a->vp->id < b->vp->id) return -1;
  if(a->vp->id > b->vp->id) return  1;
  if(a->method < b->method) return -1;
  if(a->method > b->method) return  1;
  if(a->rx_ttl < b->rx_ttl) return -1;
  if(a->rx_ttl > b->rx_ttl) return  1;
  if(a->rtt    < b->rtt)    return -1;
  if(a->rtt    > b->rtt)    return  1;
  return 0;
}

static int sc_sample_rx_cmp(const sc_sample_t *a, const sc_sample_t *b)
{
  struct timeval rx_a, rx_b;
  timeval_add_us(&rx_a, &a->tx, a->rtt);
  timeval_add_us(&rx_b, &b->tx, b->rtt);
  return timeval_cmp(&rx_a, &rx_b);
}

static int sc_sample_bad_cmp(const sc_sample_t *a, const sc_sample_t *b)
{
  if(a->bad > b->bad) return -1;
  if(a->bad < b->bad) return  1;
  return 0;
}

static int sc_sample_badskip_cmp(const sc_sample_t *a, const sc_sample_t *b)
{
  if(a->skip < b->skip) return -1;
  if(a->skip > b->skip) return  1;
  if(a->bad > b->bad) return -1;
  if(a->bad < b->bad) return  1;
  return 0;
}

/*
 * sc_sample_prune_cmp
 *
 * sort samples by minimum RTT, then by VP name (for a repeatable sort).
 * we use this ordering when pruning.
 */
static int sc_sample_prune_cmp(const sc_sample_t *a, const sc_sample_t *b)
{
  if(a->rtt < b->rtt) return -1;
  if(a->rtt > b->rtt) return  1;
  return strcasecmp(a->vp->name, b->vp->name);
}

static int sc_sample_bad_zero(sc_sample_t *item, void *param)
{
  if(item->skip == 0)
    item->bad = 0;
  return 0;
}

static int sc_sample_intersect(sc_sample_t *a, sc_sample_t *b)
{
  double distance, radius1, radius2;
  double epsilon = 1e-9; // Define a small epsilon value

  /* two circles do not intersect if their centers are close */
  if(fabs(a->vp->lat - b->vp->lat) < epsilon &&
     fabs(a->vp->lng - b->vp->lng) < epsilon)
    return 0;

  /*
   * calculate the distance between the VPs, and the radius implied by
   * the samples from each VP
   */
  radius1 = rtt2dist(a->rtt);
  radius2 = rtt2dist(b->rtt);
  distance = vp_dist(a->vp, b->vp);

  /*
   * the distance between the VPs is more than the distance implied by
   * the RTTs, so the circles cannot intersect
   */
  if(distance > radius1 + radius2)
    return 0;

  /* the larger circle entirely encloses the smaller circle */
  if(distance + fmin(radius1, radius2) < fmax(radius1, radius2))
    return 0;

  /* the circles intersect */
  return 1;
}

/*
 * sc_fdheap_cmp
 *
 * order entries in a heap by their address.  note inverted parameters
 * to scamper_addr_cmp.
 */
static int sc_fdheap_cmp(const sc_fdheap_t *a, const sc_fdheap_t *b)
{
  return scamper_addr_cmp(b->addr, a->addr);
}

static void sc_filedata_free(sc_filedata_t *fd)
{
  if(fd->samples != NULL)
    slist_free_cb(fd->samples, (slist_free_t)sc_sample_free);
  free(fd);
  return;
}

static sc_filedata_t *sc_filedata_alloc(void)
{
  sc_filedata_t *fd;
  if((fd = malloc_zero(sizeof(sc_filedata_t))) == NULL ||
     (fd->samples = slist_alloc()) == NULL)
    goto err;
  return fd;

 err:
  if(fd != NULL) sc_filedata_free(fd);
  return NULL;
}

static void sc_dstlist_free(sc_dstlist_t *dst)
{
  if(dst->addr != NULL) scamper_addr_free(dst->addr);
  if(dst->list != NULL) slist_free_cb(dst->list, (slist_free_t)sc_sample_free);
  free(dst);
  return;
}

static int sc_dstlist_cmp(const sc_dstlist_t *a, const sc_dstlist_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static sc_dstlist_t *sc_dstlist_get(splaytree_t *tree, scamper_addr_t *addr)
{
  sc_dstlist_t fm, *dst;

  fm.addr = addr;
  if((dst = splaytree_find(tree, &fm)) == NULL)
    {
      if((dst = malloc_zero(sizeof(sc_dstlist_t))) == NULL)
	return NULL;
      dst->addr = scamper_addr_use(addr);
      if((dst->list = slist_alloc()) == NULL ||
	 splaytree_insert(tree, dst) == NULL)
	{
	  sc_dstlist_free(dst);
	  return NULL;
	}
    }

  return dst;
}

static void sc_rxsec_free(sc_rxsec_t *rxs)
{
  if(rxs->list != NULL) slist_free(rxs->list);
  free(rxs);
  return;
}

static int sc_rxsec_cmp(const sc_rxsec_t *a, const sc_rxsec_t *b)
{
  if(a->sec < b->sec) return -1;
  if(a->sec > b->sec) return  1;
  return 0;
}

static slist_t *sc_rxsec_tolist(splaytree_t *tree)
{
  slist_t *out = NULL, *list = NULL;
  sc_rxsec_t *rxs;

  if((out = slist_alloc()) == NULL || (list = slist_alloc()) == NULL)
    goto err;

  splaytree_inorder(tree, tree_to_slist, list);
  while((rxs = slist_head_pop(list)) != NULL)
    {
      slist_qsort(rxs->list, (slist_cmp_t)sc_sample_rx_cmp);
      slist_concat(out, rxs->list);
    }

  slist_free(list);
  return out;

 err:
  if(out != NULL) slist_free(out);
  if(list != NULL) slist_free(list);
  return NULL;
}

static int sc_rxsec_add(splaytree_t **trees, sc_sample_t *sample)
{
  sc_rxsec_t fm, *rxsec;
  struct timeval rx;

  timeval_add_us(&rx, &sample->tx, sample->rtt);
  fm.sec = rx.tv_sec;
  if((rxsec = splaytree_find(trees[sample->method], &fm)) == NULL)
    {
      if((rxsec = malloc_zero(sizeof(sc_rxsec_t))) == NULL)
	return -1;
      rxsec->sec = rx.tv_sec;
      if(splaytree_insert(trees[sample->method], rxsec) == NULL ||
	 (rxsec->list = slist_alloc()) == NULL)
	{
	  sc_rxsec_free(rxsec);
	  return -1;
	}
    }

  if(slist_tail_push(rxsec->list, sample) == NULL)
    return -1;
  return 0;
}

slist_t *do_rtrfile_read(void)
{
  sc_routerload_t rl;

  memset(&rl, 0, sizeof(rl));
  if((rl.addrs = slist_alloc()) == NULL ||
     (rl.routers = slist_alloc()) == NULL ||
     file_lines(rtrfile, rtrfile_line, &rl) != 0 ||
     (slist_count(rl.addrs) > 0 && sc_router_finish(&rl) != 0))
    {
      fprintf(stderr, "could not read %s\n", rtrfile);
      goto err;
    }

  slist_free(rl.addrs);
  return rl.routers;

 err:
  if(rl.addrs != NULL)
    slist_free_cb(rl.addrs, (slist_free_t)scamper_addr_free);
  if(rl.routers != NULL)
    slist_free_cb(rl.routers, (slist_free_t)sc_router_free);
  return NULL;
}

static void do_stmt_final(void)
{
  if(st_filename_sel != NULL)
    {
      sqlite3_finalize(st_filename_sel);
      st_filename_sel = NULL;
    }
  if(st_filename_ins != NULL)
    {
      sqlite3_finalize(st_filename_ins);
      st_filename_ins = NULL;
    }
  if(st_sample_sel != NULL)
    {
      sqlite3_finalize(st_sample_sel);
      st_sample_sel = NULL;
    }
  if(st_sample_ins != NULL)
    {
      sqlite3_finalize(st_sample_ins);
      st_sample_ins = NULL;
    }
  if(st_runlen_ins != NULL)
    {
      sqlite3_finalize(st_runlen_ins);
      st_runlen_ins = NULL;
    }
  if(st_dst_upd != NULL)
    {
      sqlite3_finalize(st_dst_upd);
      st_dst_upd = NULL;
    }
  if(st_dst_ins != NULL)
    {
      sqlite3_finalize(st_dst_ins);
      st_dst_ins = NULL;
    }
  if(st_vp_ins != NULL)
    {
      sqlite3_finalize(st_vp_ins);
      st_vp_ins = NULL;
    }

  return;
}

static int do_dsts_read(void)
{
  const char *sql = "select id, addr, samples_rowid from dsts";
  scamper_addr_t *sa = NULL;
  sqlite3_stmt *stmt = NULL;
  sqlite3_int64 id;
  sqlite3_int64 samples_rowid;
  sc_dst_t *dst = NULL;
  const unsigned char *addr;
  int x, rc = -1;

  if((x = sqlite3_prepare_v2(db,sql,strlen(sql)+1,&stmt,NULL)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n", __func__,
	      sqlite3_errstr(x));
      goto done;
    }
  while(sqlite3_step(stmt) == SQLITE_ROW)
    {
      id   = sqlite3_column_int64(stmt, 0);
      addr = sqlite3_column_text(stmt, 1);
      samples_rowid = sqlite3_column_int64(stmt, 2);

      if((sa = scamper_addr_fromstr(AF_UNSPEC, (const char *)addr)) == NULL)
	{
	  fprintf(stderr, "%s: could not resolve %s\n", __func__, addr);
	  continue;
	}

      /* create state so we can map an addr to an id */
      if((dst = sc_dst_alloc(id, sa)) == NULL)
	goto done;
      sa = NULL;
      dst->samples_rowid = samples_rowid;

      assert(dst_tree != NULL || dst_list != NULL);
      if(dst_tree != NULL)
	{
	  if(splaytree_insert(dst_tree, dst) == NULL)
	    {
	      fprintf(stderr, "%s: could not insert %s\n", __func__, addr);
	      goto done;
	    }
	}
      else if(dst_list != NULL)
	{
	  if(slist_tail_push(dst_list, dst) == NULL)
	    {
	      fprintf(stderr, "%s: could not insert %s\n", __func__, addr);
	      goto done;
	    }
	}

      dst = NULL;
    }

  rc = 0;

 done:
  if(stmt != NULL) sqlite3_finalize(stmt);
  if(sa != NULL) scamper_addr_free(sa);
  if(dst != NULL) sc_dst_free(dst);
  return rc;
}

static int do_vps_read(void)
{
  const char *sql = "select id, name from vps";
  const unsigned char *name;
  sqlite3_stmt *stmt = NULL;
  sqlite3_int64 id;
  sc_vp_t *vp = NULL;
  int x, rc = -1;

  if((x = sqlite3_prepare_v2(db,sql,strlen(sql)+1,&stmt,NULL)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n", __func__,
	      sqlite3_errstr(x));
      goto done;
    }
  while(sqlite3_step(stmt) == SQLITE_ROW)
    {
      /* create state so we can map an name to an id */
      id   = sqlite3_column_int64(stmt, 0);
      name = sqlite3_column_text(stmt, 1);
      if((vp = sc_vp_alloc(id, (char *)name)) == NULL)
	goto done;
      if(sc_vp_insert(vp) != 0)
	{
	  fprintf(stderr, "%s: could not insert %s\n", __func__, name);
	  goto done;
	}
      vp = NULL;
    }

  rc = 0;

 done:
  if(stmt != NULL) sqlite3_finalize(stmt);
  if(vp != NULL) sc_vp_free(vp);
  return rc;
}

/*
 * do_sqlite_open
 *
 * open the database specified in dbfile.  Ensure the database file
 * exists before opening if OPT_CREATE is not set.
 */
static int do_sqlite_open(void)
{
  struct stat sb;
  int rc;

  /*
   * before opening the database file, check if it exists.
   * if the file does not exist, only create the dbfile if we've been told.
   */
  assert(dbfile != NULL);
  rc = stat(dbfile, &sb);
  if(options & OPT_CREATE)
    {
      if(rc == 0 || errno != ENOENT)
	{
	  fprintf(stderr,
		  "%s: will not create db called %s: it already exists\n",
		  __func__, dbfile);
	  return -1;
	}
    }
  else
    {
      if(rc != 0)
	{
	  fprintf(stderr, "%s: db %s does not exist, use -c\n",
		  __func__, dbfile);
	  return -1;
	}
    }

  if((rc = sqlite3_open(dbfile, &db)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not open %s: %s\n",
	      __func__, dbfile, sqlite3_errstr(rc));
      return -1;
    }

  return 0;
}

static int do_create(void)
{
  static const char *create_sql[] = {
    /* VP table */
    ("create table \"vps\" ("
     "\"id\" INTEGER PRIMARY KEY, "
     "\"name\" TEXT UNIQUE NOT NULL)"),
    /* addresses table */
    ("create table \"dsts\" ("
     "\"id\" INTEGER PRIMARY KEY, "
     "\"addr\" STRING NOT NULL, "
     "\"samples_rowid\" INTEGER NOT NULL)"),
    /* samples table */
    ("create table \"samples\" ("
     "\"id\" INTEGER PRIMARY KEY, "
     "\"dst_id\" INTEGER NOT NULL, "
     "\"data\" BLOB NOT NULL)"),
    /* runlens table */
    ("create table \"runlens\" ("
     "\"vp_id\" INTEGER NOT NULL, "
     "\"meth_id\" INTEGER NOT NULL, "
     "\"reply_ttl\" INTEGER NOT NULL, "
     "\"run_len\" INTEGER NOT NULL)"),
    /* files table */
    ("create table \"files\" ("
     "\"filename\" TEXT UNIQUE NOT NULL)"),
  };
  char *errmsg;
  size_t i;

  for(i=0; i<sizeof(create_sql) / sizeof(char *); i++)
    {
      if(sqlite3_exec(db, create_sql[i], NULL, NULL, &errmsg) != SQLITE_OK)
	{
	  fprintf(stderr, "%s: could not execute sql: %s\n",
		  __func__, errmsg);
	  return -1;
	}
    }

  return 0;
}

/*
 * do_import_samplemin
 *
 * iterate through the samples for each destination, only keeping
 * the shortest RTT value for each vp/method/reply_ttl tuple
 */
static int do_import_samplemin(slist_t *samples, slist_t *out)
{
  sc_sample_t *ins = NULL, *sample;

  slist_qsort(samples, (slist_cmp_t)sc_sample_ins_cmp);
  while((sample = slist_head_pop(samples)) != NULL)
    {
      if(ins != NULL &&
	 sample->method == ins->method &&
	 sample->rx_ttl == ins->rx_ttl &&
	 sample->vp->id == ins->vp->id)
	{
	  sc_sample_free(sample);
	}
      else
	{
	  if(slist_tail_push(out, sample) == NULL)
	    {
	      sc_sample_free(sample);
	      return -1;
	    }
	  ins = sample;
	}
    }

  return 0;
}

static int do_import_emptyblob(sc_dst_t *dst)
{
  int x;

  /* insert an empty blob into the database */
  sqlite3_bind_int64(st_sample_ins, 1, dst->id);
  if((x = sqlite3_step(st_sample_ins)) != SQLITE_DONE)
    {
      fprintf(stderr, "%s: could not insert sample: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }
  dst->samples_rowid = sqlite3_last_insert_rowid(db);
  sqlite3_clear_bindings(st_sample_ins);
  sqlite3_reset(st_sample_ins);

  /* update the dst entry with the sample rowid */
  sqlite3_bind_int64(st_dst_upd, 1, dst->samples_rowid);
  sqlite3_bind_int64(st_dst_upd, 2, dst->id);
  if((x = sqlite3_step(st_dst_upd)) != SQLITE_DONE)
    {
      fprintf(stderr, "%s: could not update dst: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }
  sqlite3_clear_bindings(st_dst_upd);
  sqlite3_reset(st_dst_upd);

  return 0;
}

static int do_import_runlen(sc_vp_t *vp, uint8_t m, uint8_t rxttl, uint32_t len)
{
  int x;
  sqlite3_bind_int64(st_runlen_ins, 1, vp->id);
  sqlite3_bind_int64(st_runlen_ins, 2, m);
  sqlite3_bind_int64(st_runlen_ins, 3, rxttl);
  sqlite3_bind_int64(st_runlen_ins, 4, len);
  if((x = sqlite3_step(st_runlen_ins)) != SQLITE_DONE)
    {
      fprintf(stderr, "%s: could not insert runlen: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }
  sqlite3_clear_bindings(st_runlen_ins);
  sqlite3_reset(st_runlen_ins);
  return 0;
}

static int do_import_dst(sc_dst_t *dst)
{
  char buf[128];
  int x;

  /* insert the address into the database */
  scamper_addr_tostr(dst->addr, buf, sizeof(buf));
  sqlite3_bind_text(st_dst_ins, 1, buf, strlen(buf), SQLITE_STATIC);
  if((x = sqlite3_step(st_dst_ins)) != SQLITE_DONE)
    {
      fprintf(stderr, "%s: could not insert dst %s: %s\n",
	      __func__, buf, sqlite3_errstr(x));
      return -1;
    }
  dst->id = sqlite3_last_insert_rowid(db);
  sqlite3_clear_bindings(st_dst_ins);
  sqlite3_reset(st_dst_ins);

  return do_import_emptyblob(dst);
}

static int do_import_blobleft(sc_dst_t *dst, uint16_t *b_off, uint16_t *b_size)
{
  uint8_t buf[2];
  uint16_t blob_off;
  int x, blob_size;

  /* get the blob */
  if(blob != NULL)
    x = sqlite3_blob_reopen(blob, dst->samples_rowid);
  else
    x = sqlite3_blob_open(db, "main", "samples", "data",
			  dst->samples_rowid, 1, &blob);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not open blob: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }

  /* find out how much space is left */
  blob_size = sqlite3_blob_bytes(blob);
  if((x = sqlite3_blob_read(blob, buf, 2, 0)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not read 2 bytes at offset 0: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }

  if((blob_off = bytes_ntohs(buf)) == 0)
    blob_off = 2;

  if(blob_off > blob_size)
    {
      fprintf(stderr, "%s: blob_off > blob_size : %u > %d\n",
	      __func__, blob_off, blob_size);
      return -1;
    }

  *b_off = blob_off;
  *b_size = (uint16_t)blob_size;
  return 0;
}

/*
 * do_import_dst_samples
 *
 * uint8_t  method
 * uint16_t vp_id
 * uint8_t  reply_ttl
 * uint32_t rtt
 */
static int do_import_dst_samples(scamper_addr_t *addr, slist_t *samples)
{
  sc_dst_t *dst;
  sc_sample_t *sample;
  uint16_t b_off, b_size, b_x;
  int x;

  /* get dst record from database */
  if((dst = sc_dst_find(addr)) == NULL)
    {
      if((dst = sc_dst_alloc(0, addr)) == NULL)
	{
	  fprintf(stderr, "%s: could not malloc dst\n", __func__);
	  return -1;
	}
      scamper_addr_use(dst->addr);
      if(splaytree_insert(dst_tree, dst) == NULL)
	{
	  fprintf(stderr, "%s: could not insert dst\n", __func__);
	  sc_dst_free(dst);
	  return -1;
	}

      if(do_import_dst(dst) != 0)
	return -1;
    }

  while(slist_head_item(samples) != NULL)
    {
      if(do_import_blobleft(dst, &b_off, &b_size) != 0)
	return -1;
      if(b_size - b_off < SAMPLE_SIZE)
	{
	  if(do_import_emptyblob(dst) != 0)
	    return -1;
	  continue;
	}

      /* increase the size of the blob_buf if necessary */
      if(b_size - b_off > blob_buflen)
	{
	  if(realloc_wrap((void **)&blob_buf, b_size - b_off) != 0)
	    return -1;
	  blob_buflen = b_size - b_off;
	}

      b_x = 0;
      while(b_size - (b_off + b_x) >= SAMPLE_SIZE)
	{
	  if((sample = slist_head_pop(samples)) == NULL)
	    break;
	  blob_buf[b_x + 0] = sample->method;
	  bytes_htons(blob_buf + b_x + 1, sample->vp->id);
	  blob_buf[b_x + 3] = sample->rx_ttl;
	  bytes_htonl(blob_buf + b_x + 4, sample->rtt);
	  sc_sample_free(sample);
	  b_x += SAMPLE_SIZE;
	}

      if((x = sqlite3_blob_write(blob, blob_buf, b_x, b_off)) != SQLITE_OK)
	{
	  fprintf(stderr, "%s: could not write %d bytes at %d: %s\n",
		  __func__, b_x, b_off, sqlite3_errstr(x));
	  return -1;
	}

      bytes_htons(blob_buf, b_off + b_x);
      if((x = sqlite3_blob_write(blob, blob_buf, 2, 0)) != SQLITE_OK)
	{
	  fprintf(stderr, "%s: could not update offset: %s\n",
		  __func__, sqlite3_errstr(x));
	  return -1;
	}
    }

  return 0;
}

static int do_file_read_ping(scamper_ping_t *ping, sc_filedata_t *fd)
{
  scamper_ping_probe_t *probe;
  scamper_ping_reply_t *reply;
  const struct timeval *reply_rtt, *probe_tx;
  scamper_addr_t *ping_dst;
  sc_sample_t *sample;
  uint8_t reply_ttl, method;
  uint16_t i, ping_count;
  uint32_t rtt;
  int rc = -1;

  ping_dst = scamper_ping_dst_get(ping);
  ping_count = scamper_ping_sent_get(ping);

  for(i=0; i<ping_count; i++)
    {
      if((probe = scamper_ping_probe_get(ping, i)) == NULL ||
	 (reply = scamper_ping_probe_reply_get(probe, 0)) == NULL ||
	 scamper_ping_reply_is_from_target(ping, reply) == 0 ||
	 (probe_tx = scamper_ping_probe_tx_get(probe)) == NULL ||
	 (reply_rtt = scamper_ping_reply_rtt_get(reply)) == NULL)
	continue;

      reply_ttl = scamper_ping_reply_ttl_get(reply);
      switch(scamper_ping_method_get(ping))
	{
	case SCAMPER_PING_METHOD_UDP:
	case SCAMPER_PING_METHOD_UDP_DPORT:
	  method = RTT_METHOD_UDP;
	  break;

	case SCAMPER_PING_METHOD_ICMP_ECHO:
	  method = RTT_METHOD_ICMP_ECHO;
	  break;

	case SCAMPER_PING_METHOD_TCP_ACK_SPORT:
	  method = RTT_METHOD_TCP_ACK_SP;
	  break;

	default:
	  continue;
	}

      rtt = (reply_rtt->tv_sec * 1000000) + reply_rtt->tv_usec;
      if((sample = sc_sample_alloc(ping_dst, fd->vp, method,
				   reply_ttl, rtt)) == NULL ||
	 slist_tail_push(fd->samples, sample) == NULL)
	{
	  if(sample != NULL) sc_sample_free(sample);
	  goto done;
	}
      timeval_cpy(&sample->tx, probe_tx);
    }

  rc = 0;

 done:
  scamper_ping_free(ping);
  return rc;
}

static int do_file_read_dealias(scamper_dealias_t *dealias, sc_filedata_t *fd)
{
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply;
  scamper_dealias_probedef_t *def;
  const struct timeval *tx, *rx;
  scamper_addr_t *dst;
  struct timeval tv;
  sc_sample_t *sample;
  uint32_t i, probec, rtt;
  uint8_t reply_ttl, method;
  int rc = -1;

  probec = scamper_dealias_probec_get(dealias);
  for(i=0; i<probec; i++)
    {
      /* check that any reply is from the target */
      probe = scamper_dealias_probe_get(dealias, i);
      reply = scamper_dealias_probe_reply_get(probe, 0);
      if(reply == NULL ||
	 scamper_dealias_reply_from_target(probe, reply) == 0)
	continue;

      /* reply should not have a negative RTT */
      tx = scamper_dealias_probe_tx_get(probe);
      rx = scamper_dealias_reply_rx_get(reply);
      if(timeval_cmp(rx, tx) < 0)
	continue;

      /* fill out the sample record */
      def = scamper_dealias_probe_def_get(probe);
      switch(scamper_dealias_probedef_method_get(def))
	{
	case SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP:
	case SCAMPER_DEALIAS_PROBEDEF_METHOD_UDP_DPORT:
	  method = RTT_METHOD_UDP;
	  break;

	case SCAMPER_DEALIAS_PROBEDEF_METHOD_ICMP_ECHO:
	  method = RTT_METHOD_ICMP_ECHO;
	  break;

	case SCAMPER_DEALIAS_PROBEDEF_METHOD_TCP_ACK_SPORT:
	  method = RTT_METHOD_TCP_ACK_SP;
	  break;

	default:
	  continue;
	}

      reply_ttl = scamper_dealias_reply_ttl_get(reply);
      dst = scamper_dealias_probedef_dst_get(def);
      timeval_diff_tv(&tv, tx, rx);
      rtt = (tv.tv_sec * 1000000) + tv.tv_usec;
      if((sample = sc_sample_alloc(dst, fd->vp, method,
				   reply_ttl, rtt)) == NULL ||
	 slist_tail_push(fd->samples, sample) == NULL)
	{
	  if(sample != NULL) sc_sample_free(sample);
	  goto done;
	}
      timeval_cpy(&sample->tx, tx);
    }

  rc = 0;

 done:
  scamper_dealias_free(dealias);
  return rc;
}

/*
 * do_file_read
 *
 * this function loads the samples out of a specified file, and does
 * some basic run-length processing.  it does not import to the
 * database.
 */
static void do_file_read(sc_filedata_t *fd)
{
  scamper_file_t *file = NULL;
  scamper_file_filter_t *ffilter = NULL;
  splaytree_t *rxs_trees[4], *dl_tree = NULL, *addr_tree = NULL;
  slist_t *rxs_list = NULL, *dl_list = NULL;
  uint16_t filter_types[] = {
    SCAMPER_FILE_OBJ_PING,
    SCAMPER_FILE_OBJ_DEALIAS,
  };
  uint16_t type, filter_cnt = sizeof(filter_types) / sizeof(uint16_t);
  sc_sample_t *rxttl, *start, *sample = NULL;
  sc_dstlist_t *dl;
  slist_node_t *sn;
  uint32_t runlen;
  void *data;
  int i, ok = 0;

  /* don't proceed further */
  if(import_ok == 0)
    return;

  memset(rxs_trees, 0, sizeof(rxs_trees));

  /* read the samples out of the file */
  if((file = scamper_file_open(fd->filename, 'r', NULL)) == NULL)
    {
      fprintf(stderr, "%s: could not open %s\n", __func__, fd->filename);
      goto done;
    }
  if((ffilter = scamper_file_filter_alloc(filter_types, filter_cnt)) == NULL)
    {
      fprintf(stderr, "%s: could not alloc filter\n", __func__);
      goto done;
    }
  while(scamper_file_read(file, ffilter, &type, &data) == 0)
    {
      if(data == NULL)
	break;
      if(type == SCAMPER_FILE_OBJ_PING)
	{
	  if(do_file_read_ping(data, fd) != 0)
	    goto done;
	}
      else if(type == SCAMPER_FILE_OBJ_DEALIAS)
	{
	  if(do_file_read_dealias(data, fd) != 0)
	    goto done;
	}
    }
  scamper_file_filter_free(ffilter); ffilter = NULL;
  scamper_file_close(file); file = NULL;

  /*
   * order the received packets by their receive time, per method, and
   * then look for runs of the same received TTL value.  identify the
   * longest run lengths for each received TTL value.
   */
  if((rxs_trees[1] = splaytree_alloc((splaytree_cmp_t)sc_rxsec_cmp)) == NULL ||
     (rxs_trees[2] = splaytree_alloc((splaytree_cmp_t)sc_rxsec_cmp)) == NULL ||
     (rxs_trees[3] = splaytree_alloc((splaytree_cmp_t)sc_rxsec_cmp)) == NULL)
    goto done;
  for(sn=slist_head_node(fd->samples); sn != NULL; sn=slist_node_next(sn))
    if(sc_rxsec_add(rxs_trees, slist_node_item(sn)) != 0)
      goto done;
  if((addr_tree = splaytree_alloc((splaytree_cmp_t)scamper_addr_cmp)) == NULL)
    goto done;
  for(i=1; i<4; i++)
    {
      if((rxs_list = sc_rxsec_tolist(rxs_trees[i])) == NULL)
	goto done;

      start = NULL;
      for(sn=slist_head_node(rxs_list); sn != NULL; sn=slist_node_next(sn))
	{
	  rxttl = slist_node_item(sn);
	  if(start == NULL || start->rx_ttl != rxttl->rx_ttl)
	    {
	      runlen = splaytree_count(addr_tree);
	      if(start != NULL && fd->runlens[i][start->rx_ttl] < runlen)
		fd->runlens[i][start->rx_ttl] = runlen;
	      start = rxttl;
	      splaytree_empty(addr_tree, NULL);
	    }
	  if(splaytree_find(addr_tree, rxttl->addr) == NULL &&
	     splaytree_insert(addr_tree, rxttl->addr) == NULL)
	    goto done;
	}
      runlen = splaytree_count(addr_tree);
      if(start != NULL && fd->runlens[i][start->rx_ttl] < runlen)
	fd->runlens[i][start->rx_ttl] = runlen;

      /* cleanup this state */
      splaytree_empty(addr_tree, NULL);
      slist_free(rxs_list); rxs_list = NULL;
      splaytree_free(rxs_trees[i], (splaytree_free_t)sc_rxsec_free);
      rxs_trees[i] = NULL;
    }

  /*
   * order samples by destination address to make batch merging
   * easier.
   */
  if((dl_tree = splaytree_alloc((splaytree_cmp_t)sc_dstlist_cmp)) == NULL ||
     (dl_list = slist_alloc()) == NULL)
    goto done;
  while((sample = slist_head_pop(fd->samples)) != NULL)
    {
      if((dl = sc_dstlist_get(dl_tree, sample->addr)) == NULL ||
	 slist_tail_push(dl->list, sample) == NULL)
	goto done;
    }
  splaytree_inorder(dl_tree, tree_to_slist, dl_list);
  splaytree_free(dl_tree, NULL); dl_tree = NULL;

  /* minimize samples */
  for(sn=slist_head_node(dl_list); sn != NULL; sn=slist_node_next(sn))
    {
      dl = slist_node_item(sn);
      if(do_import_samplemin(dl->list, fd->samples) != 0)
	goto done;
    }

  ok = 1;

 done:
  if(ok == 0) import_ok = 0;
  if(sample != NULL) sc_sample_free(sample);
  if(ffilter != NULL) scamper_file_filter_free(ffilter);
  if(file != NULL) scamper_file_close(file);
  if(addr_tree != NULL)
    splaytree_free(addr_tree, NULL);
  if(dl_tree != NULL)
    splaytree_free(dl_tree, (splaytree_free_t)sc_dstlist_free);
  for(i=1; i<4; i++)
    if(rxs_trees[i] != NULL)
      splaytree_free(rxs_trees[i], (splaytree_free_t)sc_rxsec_free);
  if(dl_list != NULL)
    slist_free_cb(dl_list, (slist_free_t)sc_dstlist_free);
  if(rxs_list != NULL)
    slist_free(rxs_list);
  return;
}

static sc_vp_t *do_import_getvp(const char *filename)
{
  char *vp_name = NULL;
  sc_vp_t *vp = NULL;
  int ok = 0;
  int x;

  /* make sure we get a VP name out of the filename */
  if((vp_name = filename_vpname(filename)) == NULL)
    goto done;

  /* if we already have a record, we're done */
  if((vp = sc_vp_find(vp_name)) != NULL)
    {
      ok = 1;
      goto done;
    }
  
  /* import a new VP record into the database */
  if((vp = sc_vp_alloc(0, vp_name)) == NULL)
    {
      fprintf(stderr, "%s: could not malloc vp\n", __func__);
      goto done;
    }
  sqlite3_bind_text(st_vp_ins, 1, vp_name, strlen(vp_name), SQLITE_STATIC);
  if((x = sqlite3_step(st_vp_ins)) != SQLITE_DONE)
    {
      fprintf(stderr, "%s: could not insert vp %s: %s\n",
	      __func__, vp_name, sqlite3_errstr(x));
      goto done;
    }
  vp->id = sqlite3_last_insert_rowid(db);
  sqlite3_clear_bindings(st_vp_ins);
  sqlite3_reset(st_vp_ins);
  if(sc_vp_insert(vp) != 0)
    {
      fprintf(stderr, "%s: could not insert vp\n", __func__);
      goto done;
    }

  ok = 1;

 done:
  if(vp_name != NULL) free(vp_name);
  if(ok == 0)
    {
      if(vp != NULL)
	sc_vp_free(vp);
      vp = NULL;
    }
  return vp;
}

/*
 * do_import_checkimport
 *
 * check to see if we have already inserted this file.  returns 1 if
 * the file is already in the database.  return -1 if bad filename, or
 * sqlite3 error.  returns zero otherwise
 */
static int do_import_checkimport(char *filename)
{
  char *ptr;
  int x;

  if((ptr = filename_nopath(filename)) == NULL)
    {
      fprintf(stderr, "%s: invalid filename %s\n", __func__, filename);
      return -1;
    }

  sqlite3_clear_bindings(st_filename_sel);
  sqlite3_reset(st_filename_sel);
  sqlite3_bind_text(st_filename_sel, 1, ptr, strlen(ptr), SQLITE_STATIC);
  if((x = sqlite3_step(st_filename_sel)) != SQLITE_DONE)
    {
      if(x == SQLITE_ROW)
	{
	  fprintf(stderr, "%s: %s already inserted\n", __func__, ptr);
	  return 1;
	}
      fprintf(stderr, "%s: %s bad\n", __func__, ptr);
      return -1;
    }

  return 0;
}

static int do_import_filename(char *filename)
{
  char *ptr;
  int x;

  if((ptr = filename_nopath(filename)) == NULL)
    return -1;

  /* insert the filename */
  sqlite3_bind_text(st_filename_ins, 1, ptr, strlen(ptr), SQLITE_STATIC);
  if((x = sqlite3_step(st_filename_ins)) != SQLITE_DONE)
    {
      fprintf(stderr, "%s: could not insert filename %s: %s\n",
	      __func__, ptr, sqlite3_errstr(x));
      return -1;
    }
  sqlite3_clear_bindings(st_filename_ins);
  sqlite3_reset(st_filename_ins);

  return 0;
}

static int do_import_filenames(slist_t *fd_list)
{
  slist_node_t *sn;
  sc_filedata_t *fd;

  for(sn=slist_head_node(fd_list); sn != NULL; sn=slist_node_next(sn))
    {
      fd = slist_node_item(sn);
      if(do_import_filename(fd->filename) != 0)
	return -1;
    }

  return 0;
}

static int do_import_samples(slist_t *fd_list)
{
  slist_t *samples_in = NULL, *samples_out = NULL;
  sc_sample_t *sample = NULL;
  scamper_addr_t *addr = NULL;
  heap_t *fdheap = NULL;
  sc_fdheap_t *fdh = NULL;
  sc_filedata_t *fd;
  slist_node_t *sn;
  int rc = -1;

  /*
   * the samples for each of the filedata structures are sorted by
   * destination address before this function gets called.  set up a
   * heap, sorted by the address of the next sample to process, that
   * allows us to collate all samples by destination address and then
   * import them in one go.
   */
  if((fdheap = heap_alloc((heap_cmp_t)sc_fdheap_cmp)) == NULL)
    goto done;
  for(sn=slist_head_node(fd_list); sn != NULL; sn=slist_node_next(sn))
    {
      /* skip over files with no samples */
      fd = slist_node_item(sn);
      if((sample = slist_head_item(fd->samples)) == NULL)
	continue;

      /*
       * allocate a record for the file, with the next address to
       * process from that file.
       */
      if((fdh = malloc(sizeof(sc_fdheap_t))) == NULL)
	goto done;
      fdh->fd = fd;
      fdh->addr = sample->addr;
      if(heap_insert(fdheap, fdh) == NULL)
	goto done;
      fdh = NULL;
    }

  /* collate samples per-address across all of the filedata structures */
  if((samples_in = slist_alloc()) == NULL ||
     (samples_out = slist_alloc()) == NULL)
    goto done;
  addr = NULL;
  while((fdh = heap_remove(fdheap)) != NULL)
    {
      fd = fdh->fd; assert(fd != NULL);
      sample = slist_head_pop(fd->samples); assert(sample != NULL);

      /*
       * if we're onto a new address, then finish up the samples for
       * the previous address.
       */
      if(addr != NULL && scamper_addr_cmp(sample->addr, addr) != 0)
	{
	  if(do_import_samplemin(samples_in, samples_out) != 0 ||
	     do_import_dst_samples(addr, samples_out) != 0)
	    goto done;
	}

      /* add the samples to the list that we're collecting for this address */
      addr = sample->addr;
      if(slist_tail_push(samples_in, sample) == NULL)
	goto done;

      /*
       * update the filedata structure with the address of the next
       * sample, if there is one.
       */
      if((sample = slist_head_item(fd->samples)) != NULL)
	{
	  fdh->addr = sample->addr; sample = NULL;
	  if(heap_insert(fdheap, fdh) == NULL)
	    goto done;
	}
      else free(fdh);
    }

  if(slist_count(samples_in) > 0 && addr != NULL &&
     (do_import_samplemin(samples_in, samples_out) != 0 ||
      do_import_dst_samples(addr, samples_out) != 0))
     goto done;

  rc = 0;

 done:
  if(fdheap != NULL) heap_free(fdheap, free);
  if(sample != NULL) sc_sample_free(sample);
  if(samples_in != NULL)
    slist_free_cb(samples_in, (slist_free_t)sc_sample_free);
  if(samples_out != NULL)
    slist_free_cb(samples_out, (slist_free_t)sc_sample_free);
  return rc;
}

static int do_import_runlens(slist_t *fd_list)
{
  sc_filedata_t *fd;
  slist_node_t *sn;
  int i, j;

  for(sn=slist_head_node(fd_list); sn != NULL; sn=slist_node_next(sn))
    {
      fd = slist_node_item(sn);
      for(i=1; i<4; i++)
	{
	  for(j=0; j<256; j++)
	    {
	      if(fd->runlens[i][j] > 0 &&
		 do_import_runlen(fd->vp, i, j, fd->runlens[i][j]) != 0)
		return -1;
	    }
	}
    }

  return 0;
}

static int do_import_pcre(void)
{
#ifdef HAVE_PCRE2
  uint32_t n;
  PCRE2_SIZE erroffset;
  int errnumber;
#else
  const char *error;
  int erroffset, n;
#endif

#ifdef HAVE_PCRE2
  if((vp_pcre = pcre2_compile((PCRE2_SPTR)vp_regex, PCRE2_ZERO_TERMINATED, 0,
			      &errnumber, &erroffset, NULL)) == NULL ||
     pcre2_pattern_info(vp_pcre, PCRE2_INFO_CAPTURECOUNT, &n) != 0)
    {
      fprintf(stderr, "could not compile regex\n");
      return -1;
    }
#else
  if((vp_pcre = pcre_compile(vp_regex, 0, &error, &erroffset, NULL)) == NULL ||
     pcre_fullinfo(vp_pcre, NULL, PCRE_INFO_CAPTURECOUNT, &n) != 0)
    {
      fprintf(stderr, "could not compile regex\n");
      return -1;
    }
#endif

  /* make sure the regex has one capture element */
  if(n != 1)
    {
      fprintf(stderr, "%s: regex has %d capture element, expect 1\n",
	      __func__, n);
      return -1;
    }

  return 0;
}

static int do_import_prepare(void)
{
  const char *sql;
  char buf[128];
  int x;

  sql = "insert into dsts(addr, samples_rowid) values(?, 0)";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_dst_ins, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare dst_ins sql: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }

  sql = "update dsts set samples_rowid=? where id=?";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_dst_upd, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }

  sql = "insert into vps(name) values(?)";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_vp_ins, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare vp_ins sql: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }

  snprintf(buf, sizeof(buf), "insert into samples(dst_id, data)"
	   " values(?, zeroblob(%d))", BLOB_SIZE_MIN);
  x = sqlite3_prepare_v2(db, buf, strlen(buf)+1, &st_sample_ins, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sample_ins sql: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }

  sql = "select filename from files where filename=?";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_filename_sel, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }

  sql = "insert into files(filename) values(?)";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_filename_ins, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }

  sql = "insert into runlens(vp_id, meth_id, reply_ttl, run_len)"
    " values(?,?,?,?)";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_runlen_ins, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n",
	      __func__, sqlite3_errstr(x));
      return -1;
    }

  return 0;
}

static int do_import_data(slist_t *fd_list)
{
  int begun = 0, rc = -1;

  sqlite3_exec(db, "begin", NULL, NULL, NULL); begun = 1;

  if(do_import_filenames(fd_list) != 0 ||
     do_import_runlens(fd_list) != 0 ||
     do_import_samples(fd_list) != 0)
    goto done;

  sqlite3_blob_close(blob);
  blob = NULL;

  sqlite3_exec(db, "commit", NULL, NULL, NULL); begun = 0;
  rc = 0;

 done:
  if(begun != 0) sqlite3_exec(db, "rollback", NULL, NULL, NULL);
  return rc;
}

static int do_import(void)
{
  char *filename;
  slist_t *fd_list = NULL;
  slist_node_t *sn;
  sc_filedata_t *fd = NULL;
  int f, x;
  int rc = -1;

#ifdef HAVE_PTHREAD
  long onln = 1;

  if(threadc == -1)
    {
#ifdef _SC_NPROCESSORS_ONLN
      if((onln = sysconf(_SC_NPROCESSORS_ONLN)) < 1)
	onln = 1;
#endif
      if(batchc <= onln && batchc > 0)
	threadc = batchc;
      else
	threadc = onln;
    }
  fprintf(stderr, "using %ld threads\n", threadc);
#else
  threadc = 0;
#endif

  if(batchc == -1)
    batchc = (threadc > 0 ? threadc : 1);

  if((dst_tree = splaytree_alloc((splaytree_cmp_t)sc_dst_cmp)) == NULL ||
     (vp_tree = splaytree_alloc((splaytree_cmp_t)sc_vp_cmp)) == NULL ||
     (fd_list = slist_alloc()) == NULL ||
     do_dsts_read() != 0 || do_vps_read() != 0 ||
     do_import_pcre() != 0 || do_import_prepare() != 0)
    goto done;

  for(f=0; f<opt_argc; f++)
    {
      filename = opt_args[f];
      fprintf(stderr, "%s\n", filename);
      if((x = do_import_checkimport(filename)) < 0)
	goto done;
      if(x == 1) /* already in database, skip over */
	continue;

      if((fd = sc_filedata_alloc()) == NULL ||
	 slist_tail_push(fd_list, fd) == NULL ||
	 (fd->vp = do_import_getvp(filename)) == NULL)
	goto done;
      fd->filename = filename;

      /*
       * if we have more space in batch, and there's more files to
       * import, then get another one
       */
      if(slist_count(fd_list) < batchc && opt_argc - f > 1)
	continue;

      tp = threadpool_alloc(threadc);
      for(sn=slist_head_node(fd_list); sn != NULL; sn=slist_node_next(sn))
	threadpool_tail_push(tp, (threadpool_func_t)do_file_read,
			     slist_node_item(sn));
      threadpool_join(tp); tp = NULL;

      /* check if its OK to continue */
      fprintf(stderr, "importing\n");
      if(import_ok == 0 || do_import_data(fd_list) != 0)
	goto done;
      slist_empty_cb(fd_list, (slist_free_t)sc_filedata_free);
    }

  rc = 0;

 done:
  do_stmt_final();
  if(fd_list != NULL)
    slist_free_cb(fd_list, (slist_free_t)sc_filedata_free);
  return rc;
}

static int vploc_file_line(char *line, void *param)
{
  double lat = 0.0, lng = 0.0;
  char *ptr, *end;
  sc_vp_t *vp;

  if(*line == '#')
    return 0;

  if(strncasecmp(line, "vp ", 3) == 0)
    {
      line = line + 3;
      while(*line != '\0' && isspace((unsigned char)*line) != 0)
	line++;
      if(*line == '\0')
	goto err;
    }

  /* VP name */
  ptr = line;
  while(*ptr != '\0' && isspace((unsigned char)*ptr) == 0)
    ptr++;
  if(*ptr == '\0')
    goto err;
  *ptr = '\0';
  ptr++;

  /* do we have this VP? */
  if((vp = sc_vp_find(line)) == NULL)
    return 0;

  /* lat */
  while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
    ptr++;
  if(*ptr == '\0')
    goto err;
  lat = strtod(ptr, &end);
  if(ptr == end || (*end != '\0' && isspace((unsigned char)*end) == 0))
    goto err;
  ptr = end;

  /* lng */
  while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
    ptr++;
  if(*ptr == '\0')
    goto err;
  lng = strtod(ptr, &end);

  vp->lat = lat;
  vp->lng = lng;
  vp->latr = lat * (M_PI / 180.0);
  vp->lngr = lng * (M_PI / 180.0);
  vp->loc = 1;

  return 0;

 err:
  fprintf(stderr, "malformed line %s\n", line);
  return -1;
}

static slist_t *do_read_dst_samples(sc_dst_t *dst)
{
  slist_t *samples = NULL;
  sqlite3_int64 sample_id;
  uint16_t blob_off, blob_len;
  int blob_size, blob_bytec = 0;
  sc_vp_t *vp;
  uint8_t method, reply_ttl;
  uint8_t *u8 = NULL;
  uint32_t rtt, vp_id;
  char buf[128];
  int x;

  if((samples = slist_alloc()) == NULL)
    goto err;

  scamper_addr_tostr(dst->addr, buf, sizeof(buf));

  sqlite3_bind_int64(st_sample_sel, 1, dst->id);
  while(sqlite3_step(st_sample_sel) == SQLITE_ROW)
    {
      sample_id = sqlite3_column_int64(st_sample_sel, 0);

      if(blob != NULL)
	x = sqlite3_blob_reopen(blob, sample_id);
      else
	x = sqlite3_blob_open(db, "main", "samples", "data",
			      sample_id, 0, &blob);
      if(x != SQLITE_OK)
	{
	  fprintf(stderr, "%s: could not open blob %lld for %s: %s\n",
		  __func__, sample_id, buf, sqlite3_errstr(x));
	  goto err;
	}
      if((blob_size = sqlite3_blob_bytes(blob)) > blob_bytec)
	{
	  if(realloc_wrap((void **)&u8, blob_size) != 0)
	    {
	      fprintf(stderr, "%s: could not realloc %d bytes for %s: %s\n",
		      __func__, blob_size, buf, strerror(errno));
	      goto err;
	    }
	  blob_bytec = blob_size;
	}

      if((x = sqlite3_blob_read(blob, u8, blob_size, 0)) != SQLITE_OK)
	{
	  fprintf(stderr, "%s: could not read blob: %s\n",
		  __func__, sqlite3_errstr(x));
	  goto err;
	}

      blob_off = 2;
      blob_len = bytes_ntohs(u8);
      if(blob_len < blob_off)
	{
	  fprintf(stderr, "%s: really short blob %u\n", __func__, blob_len);
	  goto err;
	}

      for(;;)
	{
	  if(blob_off == blob_len)
	    break;
	  if(blob_len - blob_off < SAMPLE_SIZE)
	    {
	      fprintf(stderr, "%s: short blob: %u\n", __func__,
		      blob_len - blob_off);
	      goto err;
	    }

	  method = u8[blob_off];
	  vp_id = bytes_ntohs(u8 + blob_off + 1);
	  reply_ttl = u8[blob_off + 3];
	  rtt = bytes_ntohl(u8 + blob_off + 4);
	  blob_off += SAMPLE_SIZE;

	  if((vp = sc_vp_find_id(vp_id)) == NULL ||
	     vp->bad[method][reply_ttl] != 0)
	    continue;
	  if(sc_sample_add(samples, vp, NULL, method, reply_ttl, rtt) == NULL)
	    goto err;
	}
    }

  if(u8 != NULL) free(u8);

  sqlite3_clear_bindings(st_sample_sel);
  sqlite3_reset(st_sample_sel);

  return samples;

 err:
  if(samples != NULL) slist_free_cb(samples, (slist_free_t)sc_sample_free);
  if(u8 != NULL) free(u8);
  sqlite3_clear_bindings(st_sample_sel);
  sqlite3_reset(st_sample_sel);
  return NULL;
}

static int do_samples_create_index(void)
{
  char *errmsg;
  size_t i;
  int rc = -1;

  static const char *create_sql[] = {
     "create index if not exists samples_dst_id on samples(dst_id)",
  };
  for(i=0; i<sizeof(create_sql) / sizeof(char *); i++)
    {
      if(sqlite3_exec(db, create_sql[i], NULL, NULL, &errmsg) != SQLITE_OK)
	{
	  fprintf(stderr, "%s: could not execute sql: %s\n",
		  __func__, errmsg);
	  goto done;
	}
    }

  rc = 0;

 done:
  return rc;
}

static int do_vps_array(void)
{
  slist_t *list = NULL;
  sc_vp_t *vp;
  int i, rc = -1;

  if((list = slist_alloc()) == NULL)
    goto done;

  splaytree_inorder(vp_tree, tree_to_slist, list);
  if(slist_count(list) == 0 ||
     (vp_array = malloc_zero(sizeof(sc_vp_t *) * slist_count(list))) == NULL)
    goto done;
  i = 0;
  while((vp = slist_head_pop(list)) != NULL)
    {
      if(vp->loc == 0)
	{
	  fprintf(stderr, "no loc for %s\n", vp->name);
	  goto done;
	}
      vp_array[i++] = vp;
    }
  vp_c = i;
  array_qsort((void **)vp_array, vp_c, (array_cmp_t)sc_vp_id_cmp);
  rc = 0;

 done:
  slist_free(list);
  return rc;
}

static int do_runlens_read(void)
{
  const char *sql =
    "select vp_id, meth_id, reply_ttl, run_len"
    " from runlens where run_len >= 50";
  sqlite3_stmt *stmt = NULL;
  sqlite3_int64 vp_id, meth_id, reply_ttl, run_len;
  sc_vp_t *vp;
  int x, rc = -1;

  if((x = sqlite3_prepare_v2(db,sql,strlen(sql)+1,&stmt,NULL)) != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n", __func__,
	      sqlite3_errstr(x));
      goto done;
    }

  while(sqlite3_step(stmt) == SQLITE_ROW)
    {
      vp_id     = sqlite3_column_int64(stmt, 0);
      meth_id   = sqlite3_column_int64(stmt, 1);
      reply_ttl = sqlite3_column_int64(stmt, 2);
      run_len   = sqlite3_column_int64(stmt, 3);
      if(meth_id < 1 || meth_id > 3 || reply_ttl < 0 || reply_ttl > 255 ||
	 (vp = sc_vp_find_id(vp_id)) == NULL)
	{
	  fprintf(stderr, "%s: invalid runlen\n", __func__);
	  goto done;
	}
      vp->bad[meth_id][reply_ttl] = 1;
      fprintf(stderr, "filtering %s %s ttl %d run %d\n", vp->name,
	      method_str(meth_id), (int)reply_ttl, (int)run_len);
    }
  rc = 0;

 done:
  if(stmt != NULL) sqlite3_finalize(stmt);
  return rc;
}

static void do_process_1_dst(sc_dst_t *dst)
{
  slist_t *samples = NULL;
  slist_node_t *sn1, *sn2;
  sc_sample_t *s1, *s2;
  double dist;
  uint16_t rtt;
  char buf[256];

#ifdef HAVE_PTHREAD
  pthread_mutex_lock(&db_mutex);
#endif

  samples = do_read_dst_samples(dst);

#ifdef HAVE_PTHREAD
  pthread_mutex_unlock(&db_mutex);
#endif

  if(samples == NULL || slist_count(samples) == 0)
    goto done;

  for(;;)
    {
      for(sn1=slist_head_node(samples); sn1 != NULL; sn1=slist_node_next(sn1))
	{
	  s1 = slist_node_item(sn1);
	  if(s1->skip != 0)
	    continue;
	  for(sn2=slist_node_next(sn1); sn2 != NULL; sn2=slist_node_next(sn2))
	    {
	      s2 = slist_node_item(sn2);
	      if(s2->skip != 0)
		continue;

	      dist = vp_dist(s1->vp, s2->vp);
	      rtt = dist2rtt(dist);
	      if(s1->rtt + s2->rtt >= rtt)
		continue;
	      s1->bad++;
	      s2->bad++;
	    }
	}

      slist_qsort(samples, (slist_cmp_t)sc_sample_badskip_cmp);
      s1 = slist_head_item(samples);
      if(s1->bad <= 2)
	break;
      for(sn2=slist_head_node(samples); sn2 != NULL; sn2=slist_node_next(sn2))
	{
	  s2 = slist_node_item(sn2);
	  if(s2->bad < s1->bad)
	    break;
	  s2->skip = 1;
	}
      /* if all samples conflict, then we're done */
      if(sn2 == NULL)
	break;
      slist_foreach(samples, (slist_foreach_t)sc_sample_bad_zero, NULL);
    }

  slist_qsort(samples, (slist_cmp_t)sc_sample_bad_cmp);

#ifdef HAVE_PTHREAD
  pthread_mutex_lock(&data_mutex);
#endif

  scamper_addr_tostr(dst->addr, buf, sizeof(buf));
  for(sn1=slist_head_node(samples); sn1 != NULL; sn1=slist_node_next(sn1))
    {
      s1 = slist_node_item(sn1);
      s1->vp->meth[s1->method].total++;
      if(s1->skip != 0)
	{
	  printf("%s %s %d %s %.3f:%d\n", buf,
		 s1->vp->name, s1->bad, method_str(s1->method),
		 ((double)s1->rtt) / 1000, s1->rx_ttl);
	  s1->vp->meth[s1->method].bad++;
	}
    }

#ifdef HAVE_PTHREAD
  pthread_mutex_unlock(&data_mutex);
#endif

 done:
  slist_free_cb(samples, (slist_free_t)sc_sample_free);
  return;
}

static int do_process_1(void)
{
  const char *sql;
  slist_t *list = NULL;
  slist_node_t *sn;
  sc_dst_t *dst;
  sc_vp_t *vp;
  sc_vpmeth_t *worst, *vpm;
  int i, k, x, rc = -1;
  char a[8], b[8], c[8];

#ifdef HAVE_PTHREAD
  if(pthread_mutex_init(&data_mutex, NULL) != 0)
    return -1;
  data_mutex_o = 1;
  if(threadc == -1)
    {
      threadc = 1;
#ifdef _SC_NPROCESSORS_ONLN
      if((i = sysconf(_SC_NPROCESSORS_ONLN)) > 1)
	threadc = i;
#endif
    }
  fprintf(stderr, "using %ld threads\n", threadc);
#else
  threadc = 0;
#endif

  if((vp_tree = splaytree_alloc((splaytree_cmp_t)sc_vp_cmp)) == NULL ||
     do_vps_read() != 0 || file_lines(vplocfile, vploc_file_line, NULL) != 0 ||
     do_vps_array() != 0 ||
     do_runlens_read() != 0 ||
     (dst_list = slist_alloc()) == NULL || do_dsts_read() != 0 ||
     do_samples_create_index() != 0)
    goto done;

  sql = "select id from samples where dst_id=?";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_sample_sel, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n", __func__,
	      sqlite3_errstr(x));
      goto done;
    }

  /*
   * create a list that we're going to use to figure out which VP/methods
   * are returning spurious results
   */
  if((list = slist_alloc()) == NULL)
    goto done;
  for(i=0; i<vp_c; i++)
    {
      vp = vp_array[i];
      for(k=1; k<=3; k++)
	{
	  vp->meth[k].vp = vp;
	  vp->meth[k].meth = k;
	  vp->meth[k].pc = 0;
	  if(slist_tail_push(list, &vp->meth[k]) == NULL)
	    goto done;
	}
    }

  for(;;)
    {
      tp = threadpool_alloc(threadc);
      for(sn=slist_head_node(dst_list); sn != NULL; sn=slist_node_next(sn))
	{
	  dst = slist_node_item(sn);
	  threadpool_tail_push(tp, (threadpool_func_t)do_process_1_dst, dst);
	}
      threadpool_join(tp); tp = NULL;

      for(i=0; i<vp_c; i++)
	{
	  vp = vp_array[i];
	  percentage(a, sizeof(a), vp->meth[1].bad, vp->meth[1].total);
	  percentage(b, sizeof(b), vp->meth[2].bad, vp->meth[2].total);
	  percentage(c, sizeof(c), vp->meth[3].bad, vp->meth[3].total);
	  printf("%s %u/%u %s | %u/%u %s | %u/%u %s\n", vp->name,
		 vp->meth[1].bad, vp->meth[1].total, a,
		 vp->meth[2].bad, vp->meth[2].total, b,
		 vp->meth[3].bad, vp->meth[3].total, c);

	  for(k=1; k<=3; k++)
	    {
	      vp->meth[k].pc = 0;
	      if(vp->meth[k].total > 0)
		vp->meth[k].pc = (vp->meth[k].bad * 1000) / vp->meth[k].total;
	    }
	}

      slist_qsort(list, (slist_cmp_t)sc_vpmeth_cmp);
      for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
	{
	  vpm = slist_node_item(sn);
	  if(vpm->pc == 0)
	    break;
	  printf("%s %s %.1f @@@\n", vpm->vp->name, method_str(vpm->meth),
		 ((float)vpm->pc) / 10);
	}

      worst = slist_head_item(list);
      if(worst->pc < 1) /* 0.1% */
	break;

      for(sn=slist_head_node(list); sn != NULL; sn=slist_node_next(sn))
	{
	  vpm = slist_node_item(sn);
	  if(worst->pc > vpm->pc)
	    break;
	  for(i=0; i<256; i++)
	    vpm->vp->bad[vpm->meth][i] = 1;
	  printf("%s %s %.1f bad\n", vpm->vp->name, method_str(vpm->meth),
		 ((float)vpm->pc) / 10);
	}

      for(i=0; i<vp_c; i++)
	{
	  vp = vp_array[i];
	  for(k=1; k<=3; k++)
	    vp->meth[k].pc = vp->meth[k].bad = vp->meth[k].total = 0;
	}
    }

  rc = 0;

 done:
  if(blob != NULL)
    {
      sqlite3_blob_close(blob);
      blob = NULL;
    }
  if(list != NULL) slist_free(list);
  return rc;
}

static int do_process_2_prune(slist_t *pruned, slist_t *samples)
{
  slist_node_t *sn, *sn2;
  sc_sample_t *sample, *m;

  if(slist_count(samples) == 0)
    return 0;

  /* order samples by RTT, then by VP */
  slist_qsort(samples, (slist_cmp_t)sc_sample_prune_cmp);
  for(sn=slist_head_node(samples); sn != NULL; sn=slist_node_next(sn))
    {
      /*
       * determine if the sample at hand intersects with all of the
       * samples in the pruned list.
       */
      sample = slist_node_item(sn);
      for(sn2=slist_head_node(pruned); sn2 != NULL; sn2=slist_node_next(sn2))
	{
	  m = slist_node_item(sn2);
	  if(sc_sample_intersect(sample, m) == 0)
	    break;
	}

      /* if it doesn't intersect with all, then add to the pruned list */
      if(sn2 == NULL && slist_tail_push(pruned, sample) == NULL)
	return -1;
    }

  return 0;
}

static int do_process_2(void)
{
  slist_t *samples = NULL;
  slist_t *pruned = NULL;
  slist_t *rtr_list = NULL, *rtr_samples = NULL;
  slist_node_t *sn, *sn2;
  const char *sql;
  scamper_addr_t *addr;
  sc_router_t *rtr;
  sc_dst_t *dst;
  sc_sample_t *sample;
  int x, rc = -1;
  char buf[256];

  if((vp_tree = splaytree_alloc((splaytree_cmp_t)sc_vp_cmp)) == NULL ||
     do_vps_read() != 0 || file_lines(vplocfile, vploc_file_line, NULL) != 0 ||
     do_vps_array() != 0 ||
     do_runlens_read() != 0 ||
     do_samples_create_index() != 0 ||
     (pruned = slist_alloc()) == NULL)
    goto done;

  sql = "select id from samples where dst_id=?";
  x = sqlite3_prepare_v2(db, sql, strlen(sql)+1, &st_sample_sel, NULL);
  if(x != SQLITE_OK)
    {
      fprintf(stderr, "%s: could not prepare sql: %s\n", __func__,
	      sqlite3_errstr(x));
      goto done;
    }

  if(rtrfile != NULL)
    {
      if((rtr_list = do_rtrfile_read()) == NULL ||
	 (rtr_samples = slist_alloc()) == NULL ||
	 (dst_tree = splaytree_alloc((splaytree_cmp_t)sc_dst_cmp)) == NULL ||
	 do_dsts_read() != 0)
	goto done;

      for(sn=slist_head_node(rtr_list); sn != NULL; sn=slist_node_next(sn))
	{
	  rtr = slist_node_item(sn);
	  for(sn2=slist_head_node(rtr->addrs); sn2 != NULL;
	      sn2=slist_node_next(sn2))
	    {
	      addr = slist_node_item(sn2);
	      if((dst = sc_dst_find(addr)) == NULL)
		continue;
	      if((samples = do_read_dst_samples(dst)) == NULL)
		goto done;
	      slist_concat(rtr_samples, samples);
	      slist_free(samples); samples = NULL;
	    }

	  if(do_process_2_prune(pruned, rtr_samples) != 0)
	    goto done;

	  while((sample = slist_head_pop(pruned)) != NULL)
	    printf("N%d %s %d\n", rtr->id, sample->vp->name,
		   (sample->rtt / 1000) + 1);

	  slist_empty_cb(rtr_samples, (slist_free_t)sc_sample_free);
	}
    }
  else
    {
      if((dst_list = slist_alloc()) == NULL || do_dsts_read() != 0)
	goto done;

      for(sn=slist_head_node(dst_list); sn != NULL; sn=slist_node_next(sn))
	{
	  dst = slist_node_item(sn);
	  if((samples = do_read_dst_samples(dst)) == NULL ||
	     do_process_2_prune(pruned, samples) != 0)
	    goto done;

	  scamper_addr_tostr(dst->addr, buf, sizeof(buf));
	  while((sample = slist_head_pop(pruned)) != NULL)
	    printf("%s %s %s %d\n", buf, sample->vp->name,
		   method_str(sample->method), (sample->rtt / 1000) + 1);

	  slist_free_cb(samples, (slist_free_t)sc_sample_free);
	  samples = NULL;
	}
    }

  rc = 0;

 done:
  if(pruned != NULL) slist_free(pruned);
  if(samples != NULL) slist_free_cb(samples, (slist_free_t)sc_sample_free);
  if(rtr_samples != NULL)
    slist_free_cb(rtr_samples, (slist_free_t)sc_sample_free);
  if(rtr_list != NULL)
    slist_free_cb(rtr_list, (slist_free_t)sc_router_free);
  return rc;
}

static void cleanup(void)
{
  if(dst_tree != NULL)
    {
      splaytree_free(dst_tree, (splaytree_free_t)sc_dst_free);
      dst_tree = NULL;
    }

  if(dst_list != NULL)
    {
      slist_free_cb(dst_list, (slist_free_t)sc_dst_free);
      dst_list = NULL;
    }

  if(vp_tree != NULL)
    {
      splaytree_free(vp_tree, (splaytree_free_t)sc_vp_free);
      vp_tree = NULL;
    }

  if(vp_array != NULL)
    {
      free(vp_array);
      vp_array = NULL;
    }

#ifdef HAVE_PTHREAD
  if(db_mutex_o != 0)
    {
      pthread_mutex_destroy(&db_mutex);
      db_mutex_o = 0;
    }

  if(data_mutex_o != 0)
    {
      pthread_mutex_destroy(&data_mutex);
      data_mutex_o = 0;
    }
#endif

  if(vp_pcre != NULL)
    {
#ifdef HAVE_PCRE2
      pcre2_code_free(vp_pcre);
#else
      pcre_free(vp_pcre);
#endif
      vp_pcre = NULL;
    }

  do_stmt_final();

  if(blob != NULL)
    {
      sqlite3_blob_close(blob);
      blob = NULL;
    }

  if(db != NULL)
    {
      sqlite3_close(db);
      db = NULL;
    }

  if(blob_buf != NULL)
    {
      free(blob_buf);
      blob_buf = NULL;
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

#ifdef OPT_VERSION
  if(options & OPT_VERSION)
    {
      printf("sc_minrtt version %s\n", PACKAGE_VERSION);
      return 0;
    }
#endif

  if(do_sqlite_open() != 0)
    return -1;

  if(options & OPT_CREATE)
    return do_create();

#ifdef HAVE_PTHREAD
  if(pthread_mutex_init(&db_mutex, NULL) != 0)
    return -1;
  db_mutex_o = 1;
#endif

  if(options & OPT_IMPORT)
    return do_import();
  if(options & OPT_PROCESS)
    {
      switch(proc_x)
	{
	case 1: return do_process_1(); /* look for conflicting RTTs */
	case 2: return do_process_2(); /* dump RTT constraints */
	}
    }

  return 0;
}
