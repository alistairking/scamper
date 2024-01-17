/*
 * sc_prefixscan : scamper driver to collect evidence of pt2pt links
 *                 using the prefixscan method
 *
 * $Id: sc_prefixscan.c,v 1.24 2023/09/24 22:35:02 mjl Exp $
 *
 * Copyright (C) 2011,2016 The University of Waikato
 * Copyright (C) 2019-2023 Matthew Luckie
 * Author: Matthew Luckie
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
#include "ping/scamper_ping.h"
#include "dealias/scamper_dealias.h"
#include "scamper_file.h"
#include "lib/libscamperctrl/libscamperctrl.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
#include "mjl_heap.h"
#include "utils.h"

#define TEST_PING     1
#define TEST_SCAN     2

#define IPID_NONE   0
#define IPID_INCR   1
#define IPID_RAND   2
#define IPID_ECHO   3
#define IPID_CONST  4
#define IPID_UNRESP 5

#define OPT_HELP        0x0001
#define OPT_INFILE      0x0002
#define OPT_OUTFILE     0x0004
#define OPT_PORT        0x0008
#define OPT_WAIT        0x0010
#define OPT_LOG         0x0020
#define OPT_DAEMON      0x0040
#define OPT_UNIX        0x0080
#define OPT_READ        0x0100
#define OPT_PREFIXLEN   0x0200

static uint32_t               options       = 0;
static char                  *infile        = NULL;
static unsigned int           port          = 0;
static char                  *unix_name     = NULL;
static char                  *outfile_name  = NULL;
static char                  *outfile_type  = "warts";
static scamper_file_t        *outfile       = NULL;
static char                  *datafile      = NULL;
static FILE                  *text          = NULL;
static splaytree_t           *targets       = NULL;
static splaytree_t           *ipidseqs      = NULL;
static slist_t               *virgin        = NULL;
static heap_t                *waiting       = NULL;
static int                    error         = 0;
static int                    more          = 0;
static int                    probing       = 0;
static unsigned int           waittime      = 5;
static uint8_t                prefix_len    = 0;
static scamper_file_filter_t *ffilter       = NULL;
static scamper_ctrl_t        *scamper_ctrl  = NULL;
static scamper_inst_t        *scamper_inst  = NULL;
static scamper_file_t        *decode_sf     = NULL;
static scamper_file_readbuf_t *decode_rb    = NULL;
static struct timeval         now;

/*
 * sc_ipidseq
 *
 * given a particular address, list the methods that allow aliases to be
 * tested by way of IPID.
 */
typedef struct sc_ipidseq
{
  scamper_addr_t   *addr;
  uint8_t           udp;
  uint8_t           tcp;
  uint8_t           icmp;
} sc_ipidseq_t;

typedef struct sc_test
{
  int               type;
  void             *data;
} sc_test_t;

typedef struct sc_waittest
{
  struct timeval    tv;
  sc_test_t        *test;
} sc_waittest_t;

typedef struct sc_target
{
  scamper_addr_t   *addr;
  sc_test_t        *test;
  splaytree_node_t *node;
  slist_t          *blocked;
} sc_target_t;

typedef struct sc_scantest
{
  scamper_addr_t   *a;
  scamper_addr_t   *b;
  int               pfx;
  int               step;
  sc_target_t      *tg;
} sc_scantest_t;

typedef struct sc_pingtest
{
  scamper_addr_t   *addr;
  int               step;
  sc_target_t      *tg;
} sc_pingtest_t;

typedef struct sc_prefixscan
{
  scamper_addr_t *a;
  scamper_addr_t *b;
  scamper_addr_t *ab;
} sc_prefixscan_t;

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
	  "usage: sc_prefixscan [-D] [-i infile] [-o outfile] [-p port]\n"
	  "                     [-l log] [-U unix] [-w wait] [-x prefixlen]\n"
	  "\n"
	  "       sc_prefixscan [-r data-file] [-x prefixlen]\n"
	  "\n");

  if(opt_mask == 0)
    {
      fprintf(stderr, "       sc_prefixscan -?\n\n");
      return;
    }

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "     -? give an overview of the usage of sc_prefixscan\n");

  if(opt_mask & OPT_DAEMON)
    fprintf(stderr, "     -D start as daemon\n");

  if(opt_mask & OPT_INFILE)
    fprintf(stderr, "     -i input links file\n");

  if(opt_mask & OPT_LOG)
    fprintf(stderr, "     -l log\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "     -o output warts file\n");

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -p port to find scamper on\n");

  if(opt_mask & OPT_READ)
    fprintf(stderr, "     -r input warts data file\n");

  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "     -U unix domain to find scamper on\n");

  if(opt_mask & OPT_WAIT)
    fprintf(stderr, "     -w number of seconds to wait between methods\n");

  if(opt_mask & OPT_PREFIXLEN)
    fprintf(stderr, "     -x maximum size of prefix to consider\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  int       ch;
  long      lo;
  char     *opts = "Di:l:o:p:r:U:w:x:?";
  char     *opt_port = NULL, *opt_wait = NULL, *opt_log = NULL;
  char     *opt_unix = NULL, *opt_prefixlen = NULL;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'D':
	  options |= OPT_DAEMON;
	  break;

	case 'i':
	  options |= OPT_INFILE;
	  infile = optarg;
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

	case 'r':
	  options |= OPT_READ;
	  datafile = optarg;
	  break;

	case 'U':
	  options |= OPT_UNIX;
	  opt_unix = optarg;
	  break;

	case 'w':
	  options |= OPT_WAIT;
	  opt_wait = optarg;
	  break;

	case 'x':
	  options |= OPT_PREFIXLEN;
	  opt_prefixlen = optarg;
	  break;

	case '?':
	default:
	  usage(0xffffffff);
	  return -1;
	}
    }

  if(options == 0)
    {
      usage(0);
      return -1;
    }

  /* check if the prefix length was specified on the command line */
  if(options & OPT_PREFIXLEN)
    {
      if(string_tolong(opt_prefixlen, &lo) != 0 || lo < 24 || lo > 31)
	{
	  usage(OPT_PREFIXLEN);
	  return -1;
	}
      prefix_len = lo;
    }

  /* if there were no options specified, then list the most important ones */
  if((options & (OPT_INFILE|OPT_OUTFILE|OPT_PORT|OPT_UNIX|OPT_READ)) == 0)
    {
      usage(OPT_INFILE|OPT_OUTFILE|OPT_PORT|OPT_UNIX|OPT_READ);
      return -1;
    }

  /* if we are reading a previously collected datafile, then we're done */
  if(options & OPT_READ)
    {
      if(options & ~(OPT_READ|OPT_PREFIXLEN))
	{
	  usage(OPT_READ|OPT_PREFIXLEN);
	  return -1;
	}
      return 0;
    }

  if((options & (OPT_INFILE|OPT_OUTFILE)) != (OPT_INFILE|OPT_OUTFILE) ||
     (options & (OPT_PORT|OPT_UNIX)) == 0 ||
     (options & (OPT_PORT|OPT_UNIX)) == (OPT_PORT|OPT_UNIX))
    {
      usage(OPT_INFILE|OPT_OUTFILE|OPT_PORT|OPT_UNIX);
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
      if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
	{
	  usage(OPT_PORT);
	  return -1;
	}
      port = lo;
    }
  else if(options & OPT_UNIX)
    {
      unix_name = opt_unix;
    }

  /* find out how long to wait in between traceroute methods */
  if(opt_wait != NULL)
    {
      if(string_tolong(opt_wait, &lo) != 0 || lo < 0)
	{
	  usage(OPT_WAIT);
	  return -1;
	}
      waittime = lo;
    }

  if(opt_log != NULL)
    {
      if((text = fopen(opt_log, "w")) == NULL)
	{
	  usage(OPT_LOG);
	  fprintf(stderr, "could not open %s\n", opt_log);
	  return -1;
	}
    }

  if(prefix_len == 0)
    prefix_len = 30;

  return 0;
}

static int tree_to_slist(void *ptr, void *entry)
{
  slist_tail_push((slist_t *)ptr, entry);
  return 0;
}

static char *class_tostr(char *str, size_t len, uint8_t class)
{
  char *ptr;

  switch(class)
    {
    case IPID_NONE:   ptr = "none"; break;
    case IPID_INCR:   ptr = "incr"; break;
    case IPID_RAND:   ptr = "rand"; break;
    case IPID_ECHO:   ptr = "echo"; break;
    case IPID_CONST:  ptr = "const"; break;
    case IPID_UNRESP: ptr = "unresp"; break;
    default:
      snprintf(str, len, "class %d", class);
      return str;
    }

  snprintf(str, len, "%s", ptr);
  return str;
}

#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
static void print(char *format, ...) __attribute__((format(printf, 1, 2)));
#endif

static void print(char *format, ...)
{
  va_list ap;
  char msg[512];

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  printf("%ld: %s", (long int)now.tv_sec, msg);

  if(text != NULL)
    {
      fprintf(text, "%ld: %s", (long int)now.tv_sec, msg);
      fflush(text);
    }

  return;
}

#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
static void status(char *format, ...) __attribute__((format(printf, 1, 2)));
#endif

static void status(char *format, ...)
{
  va_list ap;
  char pref[32];
  char msg[512];

  snprintf(pref, sizeof(pref), "p %d, w %d, v %d",
	   probing, heap_count(waiting), slist_count(virgin));

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  print("%s : %s\n", pref, msg);
  return;
}

static void sc_ipidseq_free(sc_ipidseq_t *seq)
{
  if(seq == NULL)
    return;

  if(seq->addr != NULL)
    scamper_addr_free(seq->addr);
  free(seq);
  return;
}

static int sc_ipidseq_cmp(const void *a, const void *b)
{
  return scamper_addr_cmp(((sc_ipidseq_t *)a)->addr,((sc_ipidseq_t *)b)->addr);
}

static sc_ipidseq_t *sc_ipidseq_alloc(scamper_addr_t *addr)
{
  sc_ipidseq_t *seq;

  if((seq = malloc_zero(sizeof(sc_ipidseq_t))) == NULL)
    return NULL;

  seq->addr = scamper_addr_use(addr);

  if(splaytree_insert(ipidseqs, seq) == NULL)
    {
      scamper_addr_free(seq->addr);
      free(seq);
      return NULL;
    }

  return seq;
}

static sc_ipidseq_t *sc_ipidseq_get(scamper_addr_t *addr)
{
  sc_ipidseq_t findme;
  findme.addr = addr;
  return splaytree_find(ipidseqs, &findme);
}

static sc_test_t *sc_test_alloc(int type, void *data)
{
  sc_test_t *test;

  if((test = malloc_zero(sizeof(sc_test_t))) == NULL)
    {
      fprintf(stderr, "could not malloc test\n");
      return NULL;
    }

  test->type = type;
  test->data = data;
  return test;
}

static void sc_test_free(sc_test_t *test)
{
  if(test == NULL)
    return;
  free(test);
  return;
}

static int sc_waittest_cmp(const void *va, const void *vb)
{
  const sc_waittest_t *a = va;
  const sc_waittest_t *b = vb;
  return timeval_cmp(&b->tv, &a->tv);
}

static int sc_waittest(sc_test_t *test)
{
  sc_waittest_t *wt;

  if((wt = malloc_zero(sizeof(sc_waittest_t))) == NULL)
    return -1;

  timeval_add_s(&wt->tv, &now, waittime);
  wt->test = test;

  if(heap_insert(waiting, wt) == NULL)
    return -1;

  return 0;
}

static sc_target_t *sc_target_add(scamper_addr_t *addr, sc_test_t *test)
{
  sc_target_t *tg = malloc_zero(sizeof(sc_target_t));
  if(tg == NULL)
    {
      fprintf(stderr, "could not malloc target\n");
      return NULL;
    }
  tg->addr = scamper_addr_use(addr);
  tg->test = test;

  if((tg->node = splaytree_insert(targets, tg)) == NULL)
    {
      fprintf(stderr, "could not add target to tree\n");
      scamper_addr_free(tg->addr);
      free(tg);
      return NULL;
    }

  return tg;
}

static void sc_target_detach(sc_target_t *tg)
{
  sc_test_t *test;

  if(tg == NULL)
    return;

  if(tg->node != NULL)
    {
      splaytree_remove_node(targets, tg->node);
      tg->node = NULL;
    }

  if(tg->blocked != NULL)
    {
      while((test = slist_head_pop(tg->blocked)) != NULL)
	sc_waittest(test);
      slist_free(tg->blocked);
      tg->blocked = NULL;
    }

  return;
}

static void sc_target_free(sc_target_t *tg)
{
  if(tg == NULL)
    return;

  sc_target_detach(tg);

  if(tg->addr != NULL)
    scamper_addr_free(tg->addr);

  free(tg);
  return;
}

static int sc_target_cmp(const void *a, const void *b)
{
  return scamper_addr_cmp(((sc_target_t *)a)->addr, ((sc_target_t *)b)->addr);
}

static int sc_target_block(sc_target_t *target, sc_test_t *block)
{
  if(target->blocked == NULL && (target->blocked = slist_alloc()) == NULL)
    {
      fprintf(stderr, "could not alloc target->blocked list\n");
      return -1;
    }

  if(slist_tail_push(target->blocked, block) == NULL)
    {
      fprintf(stderr, "could not add test to blocked list\n");
      return -1;
    }

  return 0;
}

static sc_target_t *sc_target_find(sc_target_t *target)
{
  return splaytree_find(targets, target);
}

static sc_target_t *sc_target_findaddr(scamper_addr_t *addr)
{
  sc_target_t findme;
  findme.addr = addr;
  return sc_target_find(&findme);
}

static void sc_pingtest_free(sc_pingtest_t *pt)
{
  if(pt == NULL)
    return;
  if(pt->addr != NULL)
    scamper_addr_free(pt->addr);
  if(pt->tg != NULL)
    sc_target_free(pt->tg);
  free(pt);
  return;
}

static sc_test_t *sc_pingtest_new(scamper_addr_t *addr)
{
  sc_pingtest_t *pt = NULL;
  sc_test_t *test = NULL;

  assert(addr != NULL);

  if((pt = malloc_zero(sizeof(sc_pingtest_t))) == NULL)
    {
      fprintf(stderr, "could not malloc pingtest\n");
      goto err;
    }
  pt->addr = scamper_addr_use(addr);

  /* create a generic test structure which we put in a list of tests */
  if((test = sc_test_alloc(TEST_PING, pt)) == NULL)
    goto err;

  return test;

 err:
  if(pt != NULL) sc_pingtest_free(pt);
  if(test != NULL) sc_test_free(test);
  return NULL;
}

static void sc_scantest_free(sc_scantest_t *ps)
{
  if(ps == NULL)
    return;
  if(ps->a != NULL) scamper_addr_free(ps->a);
  if(ps->b != NULL) scamper_addr_free(ps->b);
  if(ps->tg != NULL) sc_target_free(ps->tg);
  free(ps);
  return;
}

static int sc_prefixscan_cmp(const sc_prefixscan_t *a, const sc_prefixscan_t *b)
{
  int i;
  if((i = scamper_addr_cmp(a->a, b->a)) != 0) return i;
  if((i = scamper_addr_cmp(a->b, b->b)) != 0) return i;
  return scamper_addr_cmp(a->ab, b->ab);
}

static int sc_prefixscan_human_cmp(const sc_prefixscan_t *a,
				   const sc_prefixscan_t *b)
{
  int i;
  if((i = scamper_addr_human_cmp(a->a, b->a)) != 0) return i;
  if((i = scamper_addr_human_cmp(a->b, b->b)) != 0) return i;
  return scamper_addr_human_cmp(a->ab, b->ab);
}

static void sc_prefixscan_free(sc_prefixscan_t *pfs)
{
  if(pfs == NULL)
    return;
  if(pfs->a != NULL) scamper_addr_free(pfs->a);
  if(pfs->b != NULL) scamper_addr_free(pfs->b);
  if(pfs->ab != NULL) scamper_addr_free(pfs->ab);
  free(pfs);
  return;
}

static int infile_line(char *str, void *param)
{
  static int line = 0;
  sc_scantest_t *ps = NULL;
  sc_test_t *test = NULL;
  char *ptr;

  line++;

  if(str[0] == '#' || str[0] == '\0')
    return 0;
  if((ptr = string_nextword(str)) == NULL || string_nextword(ptr) != NULL)
    {
      fprintf(stderr, "malformed line %d: expected two IP addresses\n", line);
      return -1;
    }

  if((ps = malloc_zero(sizeof(sc_scantest_t))) == NULL ||
     (ps->a = scamper_addr_fromstr_unspec(str)) == NULL ||
     (ps->b = scamper_addr_fromstr_unspec(ptr)) == NULL ||
     (test = sc_test_alloc(TEST_SCAN, ps)) == NULL ||
     slist_tail_push(virgin, test) == NULL)
    goto err;

  ps->pfx = prefix_len;
  return 0;

 err:
  fprintf(stderr, "malformed line %d: expected two IP addresses\n", line);
  if(ps != NULL) sc_scantest_free(ps);
  if(test != NULL) sc_test_free(test);
  return -1;
}

static int process_ping(scamper_ping_t *ping)
{
  sc_target_t *target, findme;
  sc_pingtest_t *pt;
  sc_ipidseq_t *seq;
  const scamper_ping_reply_t *r[4], *rx;
  sc_test_t *test;
  uint32_t u32;
  char addr[64], icmp[10], tcp[10], udp[10];
  int class, i, j, rc;
  int samples[65536];
  uint8_t stop_reason;
  uint16_t ping_sent, r_ipid, r1_ipid;

  assert(ping != NULL);

  probing--;

  findme.addr = scamper_ping_dst_get(ping);
  if((target = splaytree_find(targets, &findme)) == NULL)
    {
      fprintf(stderr, "%s: could not find dst %s\n", __func__,
	      scamper_addr_tostr(findme.addr, addr, sizeof(addr)));
      goto err;
    }
  test = target->test;
  pt = test->data;

  if((seq = sc_ipidseq_get(pt->addr)) == NULL &&
     (seq = sc_ipidseq_alloc(pt->addr)) == NULL)
    {
      return -1;
    }

  stop_reason = scamper_ping_stop_reason_get(ping);
  if(stop_reason == SCAMPER_PING_STOP_NONE ||
     stop_reason == SCAMPER_PING_STOP_ERROR)
    {
      class = IPID_UNRESP;
      goto done;
    }

  rc = 0;
  ping_sent = scamper_ping_sent_get(ping);
  for(j=0; j<ping_sent && rc < 4; j++)
    {
      if((rx = scamper_ping_reply_get(ping, j)) == NULL)
	continue;
      if(scamper_ping_reply_is_from_target(ping, rx))
	r[rc++] = rx;
    }

  if(rc < 4)
    {
      class = IPID_UNRESP;
      goto done;
    }

  /*
   * if at least two of four samples have the same ipid as what was sent,
   * then declare it echos.  this handles the observed case where some
   * responses echo but others increment.
   */
  u32 = 0;
  for(i=0; i<4; i++)
    {
      if(scamper_ping_reply_probe_ipid_get(r[i]) ==
	 scamper_ping_reply_ipid_get(r[i]))
	u32++;
    }
  if(u32 > 1)
    {
      class = IPID_ECHO;
      goto done;
    }

  u32 = 0;
  memset(samples, 0, sizeof(samples));
  for(i=0; i<4; i++)
    {
      r_ipid = scamper_ping_reply_ipid_get(r[i]);
      samples[r_ipid]++;
      if(samples[r_ipid] > 1)
	u32++;
    }
  if(u32 > 1)
    {
      class = IPID_CONST;
      goto done;
    }

  for(i=0; i<3; i++)
    {
      r_ipid  = scamper_ping_reply_ipid_get(r[i]);
      r1_ipid = scamper_ping_reply_ipid_get(r[i+1]);
      if(r_ipid < r1_ipid)
	u32 = r1_ipid - r_ipid;
      else
	u32 = (r1_ipid + 0x10000) - r_ipid;

      if(u32 > 5000)
	break;
    }

  if(i == 3)
    class = IPID_INCR;
  else
    class = IPID_RAND;

 done:
  if(scamper_ping_method_is_udp(ping))
    seq->udp = class;
  else if(scamper_ping_method_is_tcp(ping))
    seq->tcp = class;
  else if(scamper_ping_method_is_icmp(ping))
    seq->icmp = class;

  scamper_addr_tostr(pt->addr, addr, sizeof(addr));
  scamper_ping_free(ping); ping = NULL;

  pt->step++;

  if(pt->step < 3)
    {
      if(sc_waittest(test) != 0)
	goto err;

      status("wait ping %s step %d", addr, pt->step);
      return 0;
    }

  status("done ping %s udp %s tcp %s icmp %s", addr,
	 class_tostr(udp, sizeof(udp), seq->udp),
	 class_tostr(tcp, sizeof(tcp), seq->tcp),
	 class_tostr(icmp, sizeof(icmp), seq->icmp));

  sc_pingtest_free(pt);
  sc_test_free(test);

  return 0;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  return -1;
}

static int process_scan(scamper_dealias_t *dealias)
{
  const scamper_dealias_prefixscan_t *scan =
    scamper_dealias_prefixscan_get(dealias);
  scamper_addr_t *a, *b, *ab;
  sc_target_t *target, findme;
  sc_scantest_t *ps;
  sc_test_t *test;
  char abuf[64], bbuf[64], abbuf[64];
  int done = 0;

  probing--;

  a = scamper_dealias_prefixscan_a_get(scan);
  scamper_addr_tostr(a, abuf, sizeof(abuf));

  findme.addr = a;
  if((target = splaytree_find(targets, &findme)) == NULL)
    {
      fprintf(stderr, "%s: could not find dst %s\n", __func__, abuf);
      goto err;
    }
  test = target->test;
  ps = test->data;

  b = scamper_dealias_prefixscan_b_get(scan);
  scamper_addr_tostr(b, bbuf, sizeof(bbuf));

  if((ab = scamper_dealias_prefixscan_ab_get(scan)) != NULL)
    {
      status("done scan %s %s/%d %s", abuf, bbuf, ps->pfx,
	     scamper_addr_tostr(ab, abbuf, sizeof(abbuf)));
      done = 1;
    }

  scamper_dealias_free(dealias); dealias = NULL;
  if(done != 0)
    goto done;

  ps->step++;
  if(ps->step < 3)
    {
      if(sc_waittest(test) != 0)
	return -1;

      status("wait scan %s %s/%d step %d", abuf, bbuf, ps->pfx, ps->step);
      return 0;
    }

 done:
  sc_scantest_free(ps);
  sc_test_free(test);
  return 0;

 err:
  if(dealias != NULL) scamper_dealias_free(dealias);
  return -1;
}

static int sc_test_ping(sc_test_t *test, char *cmd, size_t len)
{
  sc_pingtest_t *pt = test->data;
  scamper_addr_t *dst = pt->addr;
  sc_target_t *tg;
  size_t off = 0;
  char buf[64];

  assert(pt->step >= 0);
  assert(pt->step <= 2);

  /* first, check to see if the test is runnable. if not block */
  if((tg = sc_target_findaddr(dst)) != NULL && tg->test != test)
    {
      if(sc_target_block(tg, test) != 0)
	return -1;
      return 0;
    }
  else if(tg == NULL)
    {
      if((pt->tg = sc_target_add(dst, test)) == NULL)
	return -1;
    }

  string_concat(cmd, len, &off, "ping -P ");

  if(pt->step == 0)
    string_concat(cmd, len, &off, "udp-dport");
  else if(pt->step == 1)
    string_concat(cmd, len, &off, "icmp-echo");
  else if(pt->step == 2)
    string_concat(cmd, len, &off, "tcp-ack-sport");
  else
    return -1;

  string_concat(cmd, len, &off, " -c 6 -o 4 %s",
		scamper_addr_tostr(dst, buf, sizeof(buf)));

  return off;
}

static int sc_test_scan(sc_test_t *test, char *cmd, size_t len)
{
  sc_scantest_t *ps = test->data;
  sc_pingtest_t *pt;
  sc_test_t *test2;
  sc_ipidseq_t *seq;
  sc_target_t *tg;
  size_t off = 0;
  uint8_t ipid;
  char a[64], b[64], *meth;

  /* first, check to see if the test is runnable. if not block */
  if((tg = sc_target_findaddr(ps->a)) != NULL && tg->test != test)
    {
      if(sc_target_block(tg, test) != 0)
	return -1;
      return 0;
    }

  /* check if we know the available probe methods for the A address */
  if((seq = sc_ipidseq_get(ps->a)) == NULL)
    {
      if((test2 = sc_pingtest_new(ps->a)) == NULL)
	return -1;
      pt = test2->data;
      if((pt->tg = sc_target_add(ps->a, test2)) == NULL)
	return -1;
      if(sc_target_block(pt->tg, test) != 0)
	return -1;
      return sc_test_ping(test2, cmd, len);
    }

  /* add a pointer to the test in the target tree */
  if(tg == NULL && (ps->tg = sc_target_add(ps->a, test)) == NULL)
    return -1;

  while(ps->step <= 2)
    {
      if(ps->step == 0) ipid = seq->udp;
      else if(ps->step == 1) ipid = seq->tcp;
      else ipid = seq->icmp;

      if(ipid == IPID_INCR)
	break;

      ps->step++;
    }

  if(ps->step > 2)
    {
      sc_scantest_free(ps);
      sc_test_free(test);
      return 0;
    }

  if(ps->step == 0) meth = "udp";
  else if(ps->step == 1) meth = "tcp-ack-sport";
  else meth = "icmp-echo";

  string_concat(cmd, len, &off,
		"dealias -m prefixscan -f 1000 -p '-P %s' %s %s/%d",
		meth,
		scamper_addr_tostr(ps->a, a, sizeof(a)),
		scamper_addr_tostr(ps->b, b, sizeof(b)),
		ps->pfx);

  return off;
}

static int do_method(void)
{
  static int (*const func[])(sc_test_t *, char *, size_t) = {
    sc_test_ping, /* TEST_PING */
    sc_test_scan, /* TEST_SCAN */
  };
  sc_waittest_t *wt;
  sc_test_t *test;
  char cmd[512];
  int off;

  if(more < 1)
    return 0;

  for(;;)
    {
      if((wt = heap_head_item(waiting)) != NULL &&
	 timeval_cmp(&now, &wt->tv) >= 0)
	{
	  test = wt->test;
	  heap_remove(waiting);
	  free(wt);
	}
      else if((test = slist_head_pop(virgin)) == NULL)
	{
	  return 0;
	}

      /* something went wrong */
      if((off = func[test->type-1](test, cmd, sizeof(cmd))) == -1)
	{
	  fprintf(stderr, "something went wrong\n");
	  error = 1;
	  return -1;
	}

      /* got a command, send it */
      if(off != 0)
	{
	  if(scamper_inst_do(scamper_inst, cmd, NULL) == NULL)
	    {
	      fprintf(stderr, "could not send %s\n", cmd);
	      return -1;
	    }
	  probing++;
	  more--;

	  print("p %d, w %d, v %d : %s\n", probing, heap_count(waiting),
		slist_count(virgin), cmd);

	  break;
	}
    }

  return 0;
}

static void ctrlcb(scamper_inst_t *inst, uint8_t type, scamper_task_t *task,
		   const void *data, size_t len)
{
  uint16_t obj_type;
  void *obj_data;

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

      if(obj_type == SCAMPER_FILE_OBJ_PING)
	{
	  if(process_ping((scamper_ping_t *)obj_data) != 0)
	    goto err;
	}
      else if(obj_type == SCAMPER_FILE_OBJ_DEALIAS)
	{
	  if(process_scan((scamper_dealias_t *)obj_data) != 0)
	    goto err;
	}
      else if(obj_type == SCAMPER_FILE_OBJ_CYCLE_START ||
	      obj_type == SCAMPER_FILE_OBJ_CYCLE_STOP)
	{
	  scamper_cycle_free(obj_data);
	}
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
      fprintf(stderr, "%s: fatal: %s\n", __func__,
	      scamper_ctrl_strerror(scamper_ctrl));
      goto err;
    }
  return;

 err:
  error = 1;
  return;
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
      scamper_inst = scamper_inst_inet(scamper_ctrl, NULL, NULL, port);
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

static int pf_data(void)
{
  uint16_t types[] = {
    SCAMPER_FILE_OBJ_CYCLE_START,
    SCAMPER_FILE_OBJ_CYCLE_STOP,
    SCAMPER_FILE_OBJ_PING,
    SCAMPER_FILE_OBJ_DEALIAS
  };
  int typec = sizeof(types) / sizeof(uint16_t);
  struct timeval tv, *tv_ptr;
  sc_waittest_t *wait;
  int done = 0;

  /* global data structures used to keep track of the set of traceset */
  if((targets = splaytree_alloc(sc_target_cmp)) == NULL ||
     (ipidseqs = splaytree_alloc(sc_ipidseq_cmp)) == NULL ||
     (virgin = slist_alloc()) == NULL ||
     (waiting = heap_alloc(sc_waittest_cmp)) == NULL ||
     (ffilter = scamper_file_filter_alloc(types, typec)) == NULL ||
     (decode_sf = scamper_file_opennull('r', "warts")) == NULL ||
     (decode_rb = scamper_file_readbuf_alloc()) == NULL)
    return -1;
  scamper_file_setreadfunc(decode_sf, decode_rb, scamper_file_readbuf_read);
  if(file_lines(infile, infile_line, NULL) != 0)
    {
      fprintf(stderr, "could not read %s\n", infile);
      return -1;
    }

  /*
   * connect to the scamper process
   */
  if(do_scamperconnect() != 0)
    return -1;

  if((outfile = scamper_file_open(outfile_name, 'w', outfile_type)) == NULL)
    {
      fprintf(stderr, "%s: could not open output file\n", __func__);
      return -1;
    }

  while(error == 0 && scamper_ctrl_isdone(scamper_ctrl) == 0)
    {
      /*
       * need to set a timeout on select if scamper's processing window is
       * not full and there is a trace in the waiting queue.
       */
      tv_ptr = NULL;
      if(more > 0)
	{
	  gettimeofday_wrap(&now);

	  /*
	   * if there is something ready to probe now, then try and
	   * do it.
	   */
	  wait = heap_head_item(waiting);
	  if(slist_count(virgin) > 0 ||
	     (wait != NULL && timeval_cmp(&wait->tv, &now) <= 0))
	    {
	      if(do_method() != 0)
		return -1;
	    }

	  /*
	   * if we could not send a new command just yet, but scamper
	   * wants one, then wait for an appropriate length of time.
	   */
	  wait = heap_head_item(waiting);
	  if(more > 0 && wait != NULL)
	    {
	      tv_ptr = &tv;
	      if(timeval_cmp(&wait->tv, &now) > 0)
		timeval_diff_tv(&tv, &now, &wait->tv);
	      else
		memset(&tv, 0, sizeof(tv));
	    }
	}

      if(splaytree_count(targets) == 0 && slist_count(virgin) == 0 &&
	 heap_count(waiting) == 0 && done == 0)
	{
	  scamper_inst_done(scamper_inst);
	  done = 1;
	}

      scamper_ctrl_wait(scamper_ctrl, tv_ptr);
    }

  return 0;
}

static int pf_read(void)
{
  splaytree_t *tree = NULL;
  slist_t *list = NULL;
  scamper_file_t *in = NULL;
  scamper_dealias_t *dealias;
  const scamper_dealias_prefixscan_t *ps;
  scamper_addr_t *b, *ab;
  char abuf[64], bbuf[64], abbuf[64];
  sc_prefixscan_t *pfs;
  uint16_t type;
  uint8_t x;
  void *data;

  if(string_isdash(datafile) != 0)
    in = scamper_file_openfd(STDIN_FILENO, "-", 'r', "warts");
  else
    in = scamper_file_open(datafile, 'r', NULL);
  if(in == NULL)
    {
      fprintf(stderr, "could not open %s: %s\n", datafile, strerror(errno));
      goto err;
    }

  type = SCAMPER_FILE_OBJ_DEALIAS;
  if((ffilter = scamper_file_filter_alloc(&type, 1)) == NULL)
    goto err;

  if((tree = splaytree_alloc((splaytree_cmp_t)sc_prefixscan_cmp)) == NULL)
    goto err;

  while(scamper_file_read(in, ffilter, &type, &data) == 0)
    {
      if(data == NULL)
	break;

      dealias = data;
      if((ps = scamper_dealias_prefixscan_get(dealias)) != NULL)
	{
	  b = scamper_dealias_prefixscan_b_get(ps);
	  x = scamper_dealias_prefixscan_prefix_get(ps);
	  if((ab = scamper_dealias_prefixscan_ab_get(ps)) != NULL &&
	     scamper_addr_prefixhosts(b, ab) >= (prefix_len == 0 ? x : 30))
	    {
	      if((pfs = malloc_zero(sizeof(sc_prefixscan_t))) == NULL)
		{
		  fprintf(stderr, "could not record scan result\n");
		  goto err;
		}
	      pfs->a = scamper_addr_use(scamper_dealias_prefixscan_a_get(ps));
	      pfs->b = scamper_addr_use(b);
	      pfs->ab = scamper_addr_use(ab);
	      if(splaytree_insert(tree, pfs) == NULL)
		{
		  fprintf(stderr, "could not add scan result\n");
		  goto err;
		}
	    }
	}
      scamper_dealias_free(dealias);
    }
  scamper_file_close(in); in = NULL;

  if((list = slist_alloc()) == NULL)
    {
      fprintf(stderr, "could not alloc list: %s\n", strerror(errno));
      goto err;
    }
  splaytree_inorder(tree, tree_to_slist, list);
  splaytree_free(tree, NULL); tree = NULL;
  slist_qsort(list, (slist_cmp_t)sc_prefixscan_human_cmp);
  while((pfs = slist_head_pop(list)) != NULL)
    {
      printf("%s %s %s/%d\n",
	     scamper_addr_tostr(pfs->a, abuf, sizeof(abuf)),
	     scamper_addr_tostr(pfs->b, bbuf, sizeof(bbuf)),
	     scamper_addr_tostr(pfs->ab, abbuf, sizeof(abbuf)),
	     scamper_addr_prefixhosts(pfs->b, pfs->ab));
      sc_prefixscan_free(pfs);
    }
  slist_free(list);

  return 0;

 err:
  return -1;
}

static void cleanup(void)
{
  if(virgin != NULL)
    {
      slist_free(virgin);
      virgin = NULL;
    }

  if(waiting != NULL)
    {
      heap_free(waiting, NULL);
      waiting = NULL;
    }

  if(targets != NULL)
    {
      splaytree_free(targets, NULL);
      targets = NULL;
    }

  if(ipidseqs != NULL)
    {
      splaytree_free(ipidseqs, (splaytree_free_t)sc_ipidseq_free);
      ipidseqs = NULL;
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

  if(text != NULL)
    {
      fclose(text);
      text = NULL;
    }

  if(outfile != NULL)
    {
      scamper_file_close(outfile);
      outfile = NULL;
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

  /* start a daemon if asked to */
#ifdef HAVE_DAEMON
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    return -1;
#endif

  if((options & OPT_READ) != 0)
    return pf_read();

  return pf_data();
}
