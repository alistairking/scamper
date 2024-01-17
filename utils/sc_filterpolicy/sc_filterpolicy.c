/*
 * sc_filterpolicy : check filter congruity of different addresses for the
 *                 : same device
 *
 * Authors         : Matthew Luckie, Jakub Czyz
 *
 * Copyright (C) 2014-2015 The Regents of the University of California
 * Copyright (C) 2015-2023 Matthew Luckie
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
#include "trace/scamper_trace.h"
#include "scamper_file.h"
#include "lib/libscamperctrl/libscamperctrl.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
#include "mjl_heap.h"
#include "utils.h"

#define OPT_HELP        0x0001
#define OPT_INFILE      0x0002
#define OPT_OUTFILE     0x0004
#define OPT_PORT        0x0008
#define OPT_LOG         0x0020
#define OPT_OPTIONS     0x0080
#define OPT_TYPE        0x0100
#define OPT_READ        0x0200
#define OPT_TEST        0x0400
#define OPT_ALL         0xffff

#ifdef HAVE_DAEMON
#define OPT_DAEMON      0x0040
#endif
#ifdef HAVE_SOCKADDR_UN
#define OPT_UNIX        0x0010
#endif

#define FLAG_IMPATIENT   0x0001
#define FLAG_TRACEROUTE  0x0002
#define FLAG_TUPLES      0x0004
#define FLAG_INCONGRUENT 0x0008

typedef struct sc_iditem
{
  scamper_addr_t *addr;
  uint32_t        tests;
  uint32_t        results;
} sc_iditem_t;

typedef struct sc_idset
{
  uint32_t        userid;
  uint32_t        tests;
  sc_iditem_t   **items;
  size_t          itemc;
} sc_idset_t;

typedef struct sc_name2ips
{
  uint32_t          id;
  char             *name;
  slist_t          *addrs;
  slist_t          *methods;
  splaytree_node_t *tree_node;
  sc_idset_t       *set;
} sc_name2ips_t;

typedef struct sc_ip2n2i
{
  scamper_addr_t   *ip;
  sc_name2ips_t    *n2i;
  splaytree_node_t *tree_node;
} sc_ip2n2i_t;

typedef struct sc_wait
{
  struct timeval  tv;
  sc_name2ips_t  *n2i;
} sc_wait_t;

typedef struct sc_policytest
{
  const char     *name;
  size_t          namelen;
  const uint32_t  id;
  const char     *payload;
  const uint16_t  port;
  uint8_t         flags;
} sc_policytest_t;

#define PT_FLAG_TCP    0x01
#define PT_FLAG_ICMP   0x02
#define PT_FLAG_UDP    0x04
#define PT_FLAG_ROUTER 0x08
#define PT_FLAG_SERVER 0x10
#define PT_FLAG_USE    0x20

static splaytree_t           *n2i_tree      = NULL;
static slist_t               *n2i_list      = NULL;
static uint32_t               n2i_id        = 1;
static sc_name2ips_t         *n2i_last      = NULL;
static uint32_t               options       = 0;
static unsigned int           port          = 0;
#ifdef HAVE_SOCKADDR_UN
static char                  *unix_name     = NULL;
#endif
static scamper_ctrl_t        *scamper_ctrl  = NULL;
static scamper_inst_t        *scamper_inst  = NULL;
static scamper_file_t        *decode_sf     = NULL;
static scamper_file_readbuf_t *decode_rb    = NULL;
static char                  *infile        = NULL;
static char                  *datafile      = NULL;
static char                  *outfile_name  = NULL;
static char                  *outfile_type  = "warts";
static scamper_file_t        *outfile       = NULL;
static scamper_file_filter_t *ffilter       = NULL;
static int                    more          = 0;
static int                    probing       = 0;
static int                    flags         = 0;
static int                    error         = 0;
static int                    done          = 0;
static struct timeval         now;
static FILE                  *logfile       = NULL;
static heap_t                *waiting       = NULL;

#define PT_METHOD_ICMP    1
#define PT_METHOD_NETBIOS 2
#define PT_METHOD_MSSQL   3
#define PT_METHOD_FTP     4
#define PT_METHOD_SSH     5
#define PT_METHOD_TELNET  6
#define PT_METHOD_MYSQL   7
#define PT_METHOD_RDP     8
#define PT_METHOD_HTTPS   9
#define PT_METHOD_SMB     10
#define PT_METHOD_VNC     11
#define PT_METHOD_HTTP    12
#define PT_METHOD_BGP     13
#define PT_METHOD_NTP     14
#define PT_METHOD_DNS     15
#define PT_METHOD_SNMP    16

#define PT_METHOD_MAX     16

static sc_policytest_t methods[] = {
  {"ICMP", 4, PT_METHOD_ICMP,
   NULL, 0, PT_FLAG_ICMP | PT_FLAG_SERVER | PT_FLAG_ROUTER},
  {"NetBIOS", 7, PT_METHOD_NETBIOS,
   NULL, 139, PT_FLAG_TCP},
  {"MSSQL", 5, PT_METHOD_MSSQL,
   NULL, 1433, PT_FLAG_TCP},
  {"FTP", 3, PT_METHOD_FTP,
   NULL, 21, PT_FLAG_TCP | PT_FLAG_SERVER},
  {"SSH", 3, PT_METHOD_SSH,
   NULL, 22, PT_FLAG_TCP | PT_FLAG_SERVER | PT_FLAG_ROUTER},
  {"Telnet", 6, PT_METHOD_TELNET,
   NULL, 23, PT_FLAG_TCP | PT_FLAG_SERVER | PT_FLAG_ROUTER},
  {"MySQL", 5, PT_METHOD_MYSQL,
   NULL, 3306, PT_FLAG_TCP | PT_FLAG_SERVER},
  {"RDP", 3, PT_METHOD_RDP,
   NULL, 3389, PT_FLAG_TCP | PT_FLAG_SERVER},
  {"HTTPS", 5, PT_METHOD_HTTPS,
   NULL, 443, PT_FLAG_TCP | PT_FLAG_SERVER | PT_FLAG_ROUTER},
  {"SMB", 3, PT_METHOD_SMB,
   NULL, 445, PT_FLAG_TCP | PT_FLAG_SERVER},
  {"VNC", 3, PT_METHOD_VNC,
   NULL, 5900, PT_FLAG_TCP},
  {"HTTP", 4, PT_METHOD_HTTP,
   NULL, 80, PT_FLAG_TCP | PT_FLAG_SERVER | PT_FLAG_ROUTER},
  {"BGP", 3, PT_METHOD_BGP,
   NULL, 179, PT_FLAG_TCP | PT_FLAG_ROUTER},
  {"NTP", 3, PT_METHOD_NTP,
   "160200010000000000000000",
  123, PT_FLAG_UDP | PT_FLAG_SERVER | PT_FLAG_ROUTER},
  {"DNS", 3, PT_METHOD_DNS,
   "a980010000010000000000000377777706676f6f676c6503636f6d0000010001",
   53, PT_FLAG_UDP | PT_FLAG_SERVER | PT_FLAG_ROUTER},
  {"SNMP", 4, PT_METHOD_SNMP,
   "302902010104067075626c6963a01c02046aebe0a002"
   "0100020100300e300c06082b060102010105000500",
   161, PT_FLAG_UDP | PT_FLAG_SERVER | PT_FLAG_ROUTER},
};
static const int methodc = sizeof(methods) / sizeof(sc_policytest_t);

static void usage(uint32_t opt_mask)
{
  int i;

  fprintf(stderr, "usage: sc_filterpolicy");

#ifdef HAVE_DAEMON
  fprintf(stderr, " [-D]");
#endif
  fprintf(stderr, " [-a infile] [-o outfile] [-p port]");
#ifdef HAVE_SOCKADDR_UN
  fprintf(stderr, " [-U unix]\n");
#else
  fprintf(stderr, "\n");
#endif
  fprintf(stderr,
    "                       [-l log] [-O options] [-t type] [-T test]\n"
    "\n"
    "       sc_filterpolicy [-r datafile]\n"
    "\n");

  if(opt_mask == 0)
    {
      fprintf(stderr, "       sc_filterpolicy -?\n\n");
      return;
    }

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "   -? give an overview of the usage of sc_filterpolicy\n");

  if(opt_mask & OPT_INFILE)
    fprintf(stderr, "   -a input file\n");

#ifdef HAVE_DAEMON
  if(opt_mask & OPT_DAEMON)
    fprintf(stderr, "   -D run as a daemon\n");
#endif

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "   -o output warts data file\n");

  if(opt_mask & OPT_OPTIONS)
    fprintf(stderr, "   -O options [impatient | incongruent | trace | tuples]\n");

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "   -p port to find scamper on\n");

  if(opt_mask & OPT_LOG)
    fprintf(stderr, "   -l output logfile\n");

  if(opt_mask & OPT_READ)
    fprintf(stderr, "   -r input warts data file\n");

  if(opt_mask & OPT_TYPE)
    fprintf(stderr, "   -t type of probes: router, server, or all\n");

  if(opt_mask & OPT_TEST)
    {
      fprintf(stderr, "   -T adjust test schedule; e.g. -http or +vnc\n");
      for(i=0; i<methodc; i++)
	{
	  if((i % 4) == 0)
	    {
	      if(i != 0) printf(",\n");
	      printf("     ");
	    }
	  else printf(",");
	  printf(" %s", methods[i].name);
	  if(methods[i].flags & PT_FLAG_TCP)
	    printf(" (tcp/%u)", methods[i].port);
	  else if(methods[i].flags & PT_FLAG_UDP)
	    printf(" (udp/%u)", methods[i].port);
	}
      printf("\n");
    }

#ifdef HAVE_SOCKADDR_UN
  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "   -U unix domain to find scamper on\n");
#endif

  return;
}

static int check_options(int argc, char *argv[])
{
  char opts[32];
  size_t off = 0;
  char *opt_port = NULL, *opt_log = NULL, *opt_type = NULL;
  slist_t *test_list = NULL;
  uint32_t u32;
  char *test;
  int i, ch;
  long lo;

#ifdef HAVE_SOCKADDR_UN
  char *opt_unix = NULL;
#endif

  string_concat(opts, sizeof(opts), &off, "?a:");
#ifdef HAVE_DAEMON
  opts[off++] = 'D';
#endif
  string_concat(opts, sizeof(opts), &off, "l:o:O:p:r:t:T:");
#ifdef HAVE_SOCKADDR_UN
  string_concat(opts, sizeof(opts), &off, "U:");
#endif

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'a':
	  options |= OPT_INFILE;
	  infile = optarg;
	  break;

#ifdef HAVE_DAEMON
	case 'D':
	  options |= OPT_DAEMON;
	  break;
#endif

	case 'l':
	  options |= OPT_LOG;
	  opt_log = optarg;
	  break;

	case 'o':
	  options |= OPT_OUTFILE;
	  outfile_name = optarg;
	  break;

	case 'O':
	  if(strcasecmp(optarg, "impatient") == 0)
	    flags |= FLAG_IMPATIENT;
	  else if(strcasecmp(optarg, "incongruent") == 0)
	    flags |= FLAG_INCONGRUENT;
	  else if(strcasecmp(optarg, "trace") == 0)
	    flags |= FLAG_TRACEROUTE;
	  else if(strcasecmp(optarg, "tuples") == 0)
	    flags |= FLAG_TUPLES;
	  else
	    {
	      usage(OPT_OPTIONS);
	      goto err;
	    }
	  break;

	case 'p':
	  options |= OPT_PORT;
	  opt_port = optarg;
	  break;

	case 'r':
	  options |= OPT_READ;
	  datafile = optarg;
	  break;

	case 't':
	  options |= OPT_TYPE;
	  opt_type = optarg;
	  break;

	case 'T':
	  options |= OPT_TEST;
	  if(test_list == NULL && (test_list = slist_alloc()) == NULL)
	    {
	      fprintf(stderr, "could not alloc test_list\n");
	      goto err;
	    }
	  if(slist_tail_push(test_list, optarg) == NULL)
	    {
	      fprintf(stderr, "could not push %s to test_list\n", optarg);
	      goto err;
	    }
	  break;

#ifdef HAVE_SOCKADDR_UN
	case 'U':
	  options |= OPT_UNIX;
	  opt_unix = optarg;
	  break;
#endif

	case '?':
	default:
	  usage(OPT_ALL);
	  goto err;
	}
    }

  u32 = options & (OPT_INFILE|OPT_OUTFILE|OPT_READ);
  if(u32 != OPT_READ &&
     u32 != (OPT_INFILE|OPT_OUTFILE))
    {
      usage(0);
      goto err;
    }

  if(options & (OPT_INFILE|OPT_OUTFILE))
    {
#ifdef HAVE_SOCKADDR_UN
      if((options & (OPT_PORT|OPT_UNIX)) == 0 ||
	 (options & (OPT_PORT|OPT_UNIX)) == (OPT_PORT|OPT_UNIX) ||
	 argc - optind > 0)
	{
	  usage(OPT_INFILE|OPT_OUTFILE|OPT_PORT|OPT_UNIX);
	  goto err;
	}
#else
      if((options & OPT_PORT) == 0 || argc - optind > 0)
	{
	  usage(OPT_INFILE|OPT_OUTFILE|OPT_PORT);
	  goto err;
	}
#endif

      if(string_endswith(outfile_name, ".gz") != 0)
	{
#ifdef HAVE_ZLIB
	  outfile_type = "warts.gz";
#else
	  usage(OPT_OUTFILE);
	  fprintf(stderr, "cannot write to %s: did not link against zlib\n",
		  outfile_name);
	  goto err;
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
	  goto err;
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
	  goto err;
#endif
	}

      if(options & OPT_PORT)
	{
	  if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
	    {
	      usage(OPT_PORT);
	      goto err;
	    }
	  port = lo;
	}
#ifdef HAVE_SOCKADDR_UN
      else if(options & OPT_UNIX)
	{
	  unix_name = opt_unix;
	}
#endif

      /* validate the -t parameter */
      if(opt_type != NULL)
	{
	  if(strcasecmp(opt_type, "router") == 0)
	    {
	      for(i=0; i<methodc; i++)
		if(methods[i].flags & PT_FLAG_ROUTER)
		  methods[i].flags |= PT_FLAG_USE;
	    }
	  else if(strcasecmp(opt_type, "server") == 0)
	    {
	      for(i=0; i<methodc; i++)
		if(methods[i].flags & PT_FLAG_SERVER)
		  methods[i].flags |= PT_FLAG_USE;
	    }
	  else if(strcasecmp(opt_type, "all") == 0)
	    {
	      for(i=0; i<methodc; i++)
		methods[i].flags |= PT_FLAG_USE;
	    }
	}

      /*
       * if the user adjusted the test schedule, incorporate
       * their changes now
       */
      if(test_list != NULL)
	{
	  while((test = slist_head_pop(test_list)) != NULL)
	    {
	      if(test[0] != '+' && test[0] != '-')
		{
		  usage(OPT_TEST);
		  goto err;
		}
	      for(i=0; i<methodc; i++)
		if(strcasecmp(methods[i].name, test+1) == 0)
		  break;
	      if(i == methodc)
		{
		  usage(OPT_TEST);
		  fprintf(stderr, "unknown test %s\n", test+1);
		  goto err;
		}

	      if(test[0] == '+')
		methods[i].flags |= PT_FLAG_USE;
	      else
		methods[i].flags &= (~PT_FLAG_USE);
	    }
	}

      /* check that at least one protocol will be tested */
      for(i=0; i<methodc; i++)
	if(methods[i].flags & PT_FLAG_USE)
	  break;
      if(i == methodc)
	{
	  usage(OPT_TYPE|OPT_TEST);
	  goto err;
	}

      if(opt_log != NULL)
	{
	  if((logfile = fopen(opt_log, "w")) == NULL)
	    {
	      usage(OPT_LOG);
	      fprintf(stderr, "could not open %s\n", opt_log);
	      goto err;
	    }
	}
    }
  else
    {
      u32 = (OPT_PORT|OPT_LOG|OPT_TYPE|OPT_TEST);
#ifdef HAVE_DAEMON
      u32 |= OPT_DAEMON;
#endif
#ifdef HAVE_SOCKADDR_UN
      u32 |= OPT_UNIX;
#endif
      if((options & u32) != 0 ||
	 (flags & (FLAG_TRACEROUTE|FLAG_IMPATIENT|FLAG_TUPLES)) != 0)
	{
	  usage(OPT_READ);
	  goto err;
	}
    }

  if(test_list != NULL) slist_free(test_list);
  return 0;

 err:
  if(test_list != NULL) slist_free(test_list);
  return -1;
}

#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
static void logprint(char *format, ...) __attribute__((format(printf, 1, 2)));
#endif

static void logprint(char *format, ...)
{
  va_list ap;
  char msg[131072];

  if(logfile == NULL)
    return;

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  fprintf(logfile, "%ld: %s\n", (long int)now.tv_sec, msg);
  fflush(logfile);

  return;
}

static sc_policytest_t *ping_to_method(const scamper_ping_t *ping)
{
  uint32_t id = 0;
  uint8_t probe_method = scamper_ping_probe_method_get(ping);

  if(probe_method == SCAMPER_PING_METHOD_ICMP_ECHO)
    {
      id = PT_METHOD_ICMP;
    }
  else if(probe_method == SCAMPER_PING_METHOD_TCP_SYN)
    {
      switch(scamper_ping_probe_dport_get(ping))
	{
	case 21:   id = PT_METHOD_FTP;     break;
	case 22:   id = PT_METHOD_SSH;     break;
	case 23:   id = PT_METHOD_TELNET;  break;
	case 80:   id = PT_METHOD_HTTP;    break;
	case 139:  id = PT_METHOD_NETBIOS; break;
	case 179:  id = PT_METHOD_BGP;     break;
	case 443:  id = PT_METHOD_HTTPS;   break;
	case 445:  id = PT_METHOD_SMB;     break;
	case 1433: id = PT_METHOD_MSSQL;   break;
	case 3306: id = PT_METHOD_MYSQL;   break;
	case 3389: id = PT_METHOD_RDP;     break;
	case 5900: id = PT_METHOD_VNC;     break;
	}
    }
  else if(probe_method == SCAMPER_PING_METHOD_UDP)
    {
      switch(scamper_ping_probe_dport_get(ping))
	{
	case 53:   id = PT_METHOD_DNS;  break;
	case 123:  id = PT_METHOD_NTP;  break;
	case 161:  id = PT_METHOD_SNMP; break;
	}
    }

  if(id == 0)
    return NULL;

  return &methods[id-1];
}

static int ping_r(const sc_policytest_t *method, const scamper_ping_t *ping)
{
  const scamper_ping_reply_t *r;
  uint16_t i, ping_sent;

  ping_sent = scamper_ping_sent_get(ping);
  for(i=0; i<ping_sent; i++)
    {
      for(r = scamper_ping_reply_get(ping, i); r != NULL;
	  r = scamper_ping_reply_next_get(r))
	{
	  if(method->flags & PT_FLAG_TCP)
	    {
	      if(scamper_ping_reply_is_tcp(r) &&
		 (scamper_ping_reply_tcp_flags_get(r) & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))
		return 1;
	    }
	  else if(method->flags & PT_FLAG_UDP)
	    {
	      if(scamper_ping_reply_is_udp(r))
		return 1;
	    }
	  else if(method->flags & PT_FLAG_ICMP)
	    {
	      if(scamper_ping_reply_is_icmp_echo_reply(r))
		return 1;
	    }
	  else return -1;
	}
    }

  return 0;
}

static int sc_wait_cmp(const void *a, const void *b)
{
  return timeval_cmp(&((sc_wait_t *)b)->tv, &((sc_wait_t *)a)->tv);
}

static int sc_wait(struct timeval *tv, sc_name2ips_t *n2i)
{
  sc_wait_t *w;
  if((w = malloc_zero(sizeof(sc_wait_t))) == NULL)
    return -1;
  timeval_cpy(&w->tv, tv);
  w->n2i = n2i;
  if(heap_insert(waiting, w) == NULL)
    return -1;
  return 0;
}

static int sc_iditem_cmp(const sc_iditem_t *a, const sc_iditem_t *b)
{
  return scamper_addr_cmp(a->addr, b->addr);
}

static void sc_iditem_free(sc_iditem_t *item)
{
  if(item == NULL)
    return;
  if(item->addr != NULL) scamper_addr_free(item->addr);
  free(item);
  return;
}

static sc_iditem_t *sc_iditem_get(sc_idset_t *set, scamper_addr_t *addr)
{
  sc_iditem_t fm, *item;

  fm.addr = addr;
  if((item = array_find((void **)set->items, set->itemc, &fm,
			(array_cmp_t)sc_iditem_cmp)) != NULL)
    return item;

  if((item = malloc_zero(sizeof(sc_iditem_t))) == NULL)
    return NULL;
  item->addr = scamper_addr_use(addr);
  if(array_insert((void ***)&set->items, &set->itemc, item,
		  (array_cmp_t)sc_iditem_cmp) != 0)
    {
      sc_iditem_free(item);
      return NULL;
    }

  return item;
}

static int sc_idset_cmp(const sc_idset_t *a, const sc_idset_t *b)
{
  if(a->userid < b->userid) return -1;
  if(a->userid > b->userid) return  1;
  return 0;
}

static void sc_idset_free(sc_idset_t *set)
{
  size_t i;

  if(set == NULL)
    return;

  if(set->items != NULL)
    {
      for(i=0; i<set->itemc; i++)
	sc_iditem_free(set->items[i]);
      free(set->items);
    }
  free(set);
  return;
}

static sc_idset_t *sc_idset_get(splaytree_t *tree, uint32_t id)
{
  sc_idset_t fm, *set; fm.userid = id;

  /* see if we already have a collection for this id */
  if((set = splaytree_find(tree, &fm)) != NULL)
    return set;

  /* no collection, alloc a new one */
  if((set = malloc_zero(sizeof(sc_idset_t))) == NULL)
    return NULL;
  set->userid = id;

  /* add it to the tree.  if it fails, free the memory */
  if(splaytree_insert(tree, set) == NULL)
    {
      free(set);
      return NULL;
    }

  return set;
}

static int sc_idset_incongruent(const sc_idset_t *set)
{
  sc_iditem_t *first, *item;
  size_t i;

  first = set->items[0];
  for(i=1; i<set->itemc; i++)
    {
      item = set->items[i];
      if(first->results != item->results)
	return 1;
    }

  return 0;
}

static void sc_idset_print(const sc_idset_t *set)
{
  char fsaddr[30], buf[128];
  size_t maxaddr, max, len;
  sc_policytest_t *pt;
  sc_iditem_t *item;
  uint32_t o;
  size_t i;
  int j;

  /* should we print this at all? */
  if((flags & FLAG_INCONGRUENT) != 0 && sc_idset_incongruent(set) == 0)
    return;

  /*
   * first, figure out the maximum width IP address in the set, and
   * which protocols are open at all
   */
  maxaddr = 0; o = 0;
  for(i=0; i<set->itemc; i++)
    {
      item = set->items[i];
      scamper_addr_tostr(item->addr, buf, sizeof(buf));
      if((len = strlen(buf)) > maxaddr)
	maxaddr = len;
      o |= item->results;
    }
  snprintf(fsaddr, sizeof(fsaddr), "%%%ds :", (int)maxaddr);

  /* next, figure out the maximum width protocol name tested */
  max = 0;
  for(j=0; j<PT_METHOD_MAX; j++)
    {
      if((set->tests & (1 << j)) == 0)
	continue;
      pt = &methods[j];
      if(pt->namelen > max)
	max = pt->namelen;
    }

  /* print the header that goes at the top of the router's results */
  for(len=0; len<max; len++)
    {
      printf(fsaddr, "");
      for(j=0; j<PT_METHOD_MAX; j++)
	{
	  if((set->tests & (1 << j)) == 0)
	    continue;
	  pt = &methods[j];
	  if(len < max - pt->namelen)
	    {
	      printf("   ");
	      continue;
	    }
	  printf("  %c", pt->name[len-(max-pt->namelen)]);
	}
      printf("\n");
    }

  /* print a line under the header */
  for(len=0; len<maxaddr; len++)
    printf("=");
  printf("==");
  for(j=0; j<PT_METHOD_MAX; j++)
    {
      if((set->tests & (1 << j)) == 0)
	continue;
      printf("===");
    }
  printf("\n");

  /* report the open ports */
  for(i=0; i<set->itemc; i++)
    {
      item = set->items[i];
      printf(fsaddr, scamper_addr_tostr(item->addr, buf, sizeof(buf)));
      for(j=0; j<PT_METHOD_MAX; j++)
	{
	  if((set->tests & (1 << j)) == 0)
	    continue;
	  if(item->results & (1 << j))
	    printf("  O");
	  else if((item->tests & (1 << j)) == 0)
	    printf("  ?");
	  else if(o & (1 << j))
	    printf("  X");
	  else
	    printf("   ");
	}
      printf("\n");
    }
  printf("\n");

  return;
}

static int sc_ip2n2i_cmp(const sc_ip2n2i_t *a, const sc_ip2n2i_t *b)
{
  return scamper_addr_cmp(a->ip, b->ip);
}

static void sc_ip2n2i_free(sc_ip2n2i_t *ip2n2i)
{
  if(ip2n2i == NULL)
    return;
  if(ip2n2i->tree_node != NULL)
    splaytree_remove_node(n2i_tree, ip2n2i->tree_node);
  if(ip2n2i->ip != NULL)
    scamper_addr_free(ip2n2i->ip);
  free(ip2n2i);
  return;
}

static sc_ip2n2i_t *sc_ip2n2i_find(scamper_addr_t *ip)
{
  sc_ip2n2i_t fm; fm.ip = ip;
  return splaytree_find(n2i_tree, &fm);
}

static sc_ip2n2i_t *sc_ip2n2i_get(scamper_addr_t *ip, sc_name2ips_t *n2i)
{
  sc_ip2n2i_t *ip2n2i;

  if((ip2n2i = sc_ip2n2i_find(ip)) != NULL)
    {
      assert(ip2n2i->n2i == n2i);
      return ip2n2i;
    }

  if((ip2n2i = malloc_zero(sizeof(sc_ip2n2i_t))) == NULL)
    return NULL;
  ip2n2i->ip = scamper_addr_use(ip);
  ip2n2i->n2i = n2i;
  if((ip2n2i->tree_node = splaytree_insert(n2i_tree, ip2n2i)) == NULL)
    {
      sc_ip2n2i_free(ip2n2i);
      return NULL;
    }

  return ip2n2i;
}

static void sc_name2ips_methods(sc_name2ips_t *n2i)
{
  int i;
  slist_empty(n2i->methods);
  for(i=0; i<methodc; i++)
    if(methods[i].flags & PT_FLAG_USE)
      slist_tail_push(n2i->methods, &methods[i]);
  slist_shuffle(n2i->methods);
  return;
}

static int sc_name2ips_name_cmp(const sc_name2ips_t *a, const sc_name2ips_t *b)
{
  return strcmp(a->name, b->name);
}

static int sc_name2ips_addr_cmp(const sc_name2ips_t *a, const sc_name2ips_t *b)
{
  int ac = slist_count(a->addrs);
  int bc = slist_count(b->addrs);
  if(ac > bc) return -1;
  if(ac < bc) return  1;
  return 0;
}

static void sc_name2ips_free(sc_name2ips_t *n2i)
{
  scamper_addr_t *addr;
  if(n2i == NULL) return;
  if(n2i->tree_node != NULL)
    splaytree_remove_node(n2i_tree, n2i->tree_node);
  if(n2i->addrs != NULL)
    {
      while((addr = slist_head_pop(n2i->addrs)) != NULL)
	scamper_addr_free(addr);
      slist_free(n2i->addrs);
    }
  if(n2i->methods != NULL)
    slist_free(n2i->methods);
  if(n2i->name != NULL)
    free(n2i->name);
  if(n2i->set != NULL)
    sc_idset_free(n2i->set);
  free(n2i);
  return;
}

static sc_name2ips_t *sc_name2ips_get(char *name)
{
  sc_name2ips_t fm, *n2i = NULL;

  fm.name = name;
  if((n2i = splaytree_find(n2i_tree, &fm)) != NULL)
    return n2i;

  if((n2i = malloc_zero(sizeof(sc_name2ips_t))) == NULL ||
     (name != NULL && (n2i->name = strdup(name)) == NULL) ||
     (n2i->addrs = slist_alloc()) == NULL ||
     (n2i->methods = slist_alloc()) == NULL ||
     (n2i->tree_node = splaytree_insert(n2i_tree, n2i)) == NULL ||
     slist_tail_push(n2i_list, n2i) == NULL)
    {
      fprintf(stderr, "sc_name2ips_get: could not alloc node\n");
      goto err;
    }
  n2i->id = n2i_id++;

  return n2i;

 err:
  if(n2i != NULL) sc_name2ips_free(n2i);
  return NULL;
}

static int do_method(void)
{
  scamper_addr_t *addr;
  sc_name2ips_t *n2i;
  sc_policytest_t *pt;
  sc_wait_t *w;
  char buf[128], cmd[512];
  size_t off = 0;

  if(more < 1)
    return 0;

  if((w = heap_head_item(waiting)) != NULL && timeval_cmp(&now, &w->tv) >= 0)
    {
      heap_remove(waiting);
      n2i = w->n2i;
      free(w);
    }
  else if((n2i = slist_head_pop(n2i_list)) != NULL)
    {
      sc_name2ips_methods(n2i);
    }
  else return 0;

  addr = slist_head_item(n2i->addrs);
  scamper_addr_tostr(addr, buf, sizeof(buf));

  if(sc_ip2n2i_get(addr, n2i) == NULL)
    {
      logprint("%s: could not sc_ip2n2i_get %s", __func__, buf);
      return -1;
    }

  pt = slist_head_pop(n2i->methods);
  if(flags & FLAG_TRACEROUTE)
    {
      string_concat(cmd, sizeof(cmd), &off, "trace -q 1 -U %u", n2i->id);
      if(pt->flags & PT_FLAG_ICMP)
	string_concat(cmd, sizeof(cmd), &off, " -P icmp-paris");
      else if(pt->flags & PT_FLAG_TCP)
	string_concat(cmd, sizeof(cmd), &off, " -P tcp -d %u", pt->port);
      else if(pt->flags & PT_FLAG_UDP)
	string_concat(cmd, sizeof(cmd), &off,
		      " -P udp-paris -O dl -O const-payload -d %u -p %s",
		      pt->port, pt->payload);
      else
	return -1;
      string_concat(cmd, sizeof(cmd), &off, " %s", buf);
    }
  else
    {
      string_concat(cmd, sizeof(cmd), &off, "ping -i 5 -U %u -c 1", n2i->id);
      if(pt->flags & PT_FLAG_ICMP)
	string_concat(cmd, sizeof(cmd), &off, " -P icmp-echo");
      else if(pt->flags & PT_FLAG_TCP)
	string_concat(cmd, sizeof(cmd), &off, " -P tcp-syn -d %u", pt->port);
      else if(pt->flags & PT_FLAG_UDP)
	string_concat(cmd, sizeof(cmd), &off,
		      " -P udp -O dl -d %u -B %s",
		      pt->port, pt->payload);
      string_concat(cmd, sizeof(cmd), &off, " %s", buf);
    }

  if(scamper_inst_do(scamper_inst, cmd, NULL) == NULL)
    {
      fprintf(stderr, "could not send %s\n", cmd);
      return -1;
    }
  n2i_last = n2i;

  probing++;
  more--;

  logprint("p %d, w %d, l %d : %s", probing, heap_count(waiting),
	   slist_count(n2i_list), cmd);
  return 0;
}

/*
 * infile_tuples_line
 *
 * read the input file, which contains <name, ip> tuples.
 */
static int infile_tuples_line(char *line, void *param)
{
  splaytree_t *addrtree = param;
  scamper_addr_t *addr = NULL;
  sc_name2ips_t *n2i = NULL;
  char *name, *ip;

  if(line[0] == '#' || line[0] == '\0')
    return 0;

  name = line;
  if((ip = string_nextword(line)) == NULL ||
     (addr = scamper_addr_fromstr_unspec(ip)) == NULL)
    {
      fprintf(stderr, "malformed line in input file\n");
      goto err;
    }

  if(splaytree_find(addrtree, addr) != NULL)
    {
      fprintf(stderr, "%s in list multiple times, aborting\n", ip);
      goto err;
    }

  if(splaytree_insert(addrtree, scamper_addr_use(addr)) == NULL ||
     (n2i = sc_name2ips_get(name)) == NULL ||
     slist_tail_push(n2i->addrs, addr) == NULL)
    {
      fprintf(stderr, "could not stuff %s:%s\n", name, ip);
      goto err;
    }

  return 0;

 err:
  if(addr != NULL) scamper_addr_free(addr);
  return -1;
}

static int infile_rows_line(char *line, void *param)
{
  splaytree_t *addrtree = param;
  scamper_addr_t *addr = NULL;
  sc_name2ips_t *n2i = NULL;
  char *name, *ip, *ptr;

  if(line[0] == '#' || line[0] == '\0')
    return 0;

  name = line;
  if((ip = string_nextword(line)) == NULL)
    {
      fprintf(stderr, "malformed line in input file\n");
      goto err;
    }

  if((addr = scamper_addr_fromstr_unspec(name)) != NULL)
    n2i = sc_name2ips_get(name);
  else
    n2i = sc_name2ips_get(NULL);
  if(n2i == NULL)
    goto err;

  if(addr != NULL)
    {
      if(splaytree_find(addrtree, addr) != NULL)
	{
	  fprintf(stderr, "%s in list multiple times, aborting\n", ip);
	  goto err;
	}
      if(splaytree_insert(addrtree, scamper_addr_use(addr)) == NULL ||
	 slist_tail_push(n2i->addrs, addr) == NULL)
	{
	  fprintf(stderr, "could not stuff %s:%s\n", name, ip);
	  goto err;
	}
    }
  ptr = string_nextword(ip);

  for(;;)
    {
      if((addr = scamper_addr_fromstr_unspec(ip)) == NULL)
	{
	  fprintf(stderr, "%s is not an IP address\n", ip);
	  goto err;
	}
      if(splaytree_find(addrtree, addr) != NULL)
	{
	  fprintf(stderr, "%s in list multiple times, aborting\n", ip);
	  goto err;
	}
      if(splaytree_insert(addrtree, scamper_addr_use(addr)) == NULL ||
	 slist_tail_push(n2i->addrs, addr) == NULL)
	{
	  fprintf(stderr, "could not stuff %s:%s\n", name, ip);
	  goto err;
	}
      if((ip = ptr) == NULL)
	break;
      ptr = string_nextword(ip);
    }

  return 0;

 err:
  if(addr != NULL) scamper_addr_free(addr);
  return -1;
}

static int do_infile(void)
{
  splaytree_t *addrtree;
  slist_node_t *node;
  sc_name2ips_t *n2i;

  if((addrtree = splaytree_alloc((splaytree_cmp_t)scamper_addr_cmp)) == NULL)
    {
      fprintf(stderr, "could not alloc addrtree\n");
      return -1;
    }

  if(flags & FLAG_TUPLES)
    {
      if(file_lines(infile, infile_tuples_line, addrtree) != 0)
	goto err;
    }
  else
    {
      if(file_lines(infile, infile_rows_line, addrtree) != 0)
	goto err;
    }
  splaytree_free(addrtree, (splaytree_free_t)scamper_addr_free);
  addrtree = NULL;

  for(node=slist_head_node(n2i_list); node != NULL; node=slist_node_next(node))
    {
      n2i = slist_node_item(node);
      slist_shuffle(n2i->addrs);
      n2i->tree_node = NULL;
    }
  splaytree_free(n2i_tree, NULL);

  if(flags & FLAG_IMPATIENT)
    slist_qsort(n2i_list, (slist_cmp_t)sc_name2ips_addr_cmp);
  else
    slist_shuffle(n2i_list);

  if((n2i_tree = splaytree_alloc((splaytree_cmp_t)sc_ip2n2i_cmp)) == NULL)
    {
      fprintf(stderr, "could not alloc n2i_tree\n");
      return -1;
    }

  return 0;

 err:
  if(addrtree != NULL)
    splaytree_free(addrtree, (splaytree_free_t)scamper_addr_free);
  return -1;
}

static sc_name2ips_t *sc_name2ips_find(scamper_addr_t *dst)
{
  sc_ip2n2i_t *ip2n2i;
  if((ip2n2i = sc_ip2n2i_find(dst)) == NULL)
    return NULL;
  return ip2n2i->n2i;
}

static int do_decoderead_addr(scamper_addr_t *dst)
{
  scamper_addr_t *addr;
  struct timeval tv;
  sc_ip2n2i_t *ip2n2i;
  sc_name2ips_t *n2i;
  char buf[128];

  if((ip2n2i = sc_ip2n2i_find(dst)) == NULL)
    {
      logprint("%s: could not find %s", __func__,
	       scamper_addr_tostr(dst, buf, sizeof(buf)));
      return -1;
    }
  n2i = ip2n2i->n2i;

  if(slist_count(n2i->methods) == 0)
    {
      sc_ip2n2i_free(ip2n2i);
      addr = slist_head_pop(n2i->addrs);
      scamper_addr_free(addr);
      if(slist_count(n2i->addrs) == 0)
	{
	  if(n2i->set != NULL)
	    sc_idset_print(n2i->set);
	  sc_name2ips_free(n2i);
	  n2i = NULL;
	}
      else
	{
	  sc_name2ips_methods(n2i);
	}
    }

  if(n2i != NULL)
    {
      timeval_add_s(&tv, &now, 1);
      if(sc_wait(&tv, n2i) != 0)
	{
	  logprint("%s: could not wait", __func__);
	  return -1;
	}
    }

  return 0;
}

static int do_decoderead_ping(scamper_ping_t *ping)
{
  scamper_addr_t *dst = scamper_ping_dst_get(ping);
  sc_policytest_t *method;
  sc_name2ips_t *n2i;
  char buf[128];
  sc_iditem_t *item;
  int rc, code;

#ifdef HAVE_DAEMON
  if((options & OPT_DAEMON) != 0)
    goto done;
#endif

  if((n2i = sc_name2ips_find(dst)) == NULL)
    {
      logprint("%s: could not find %s", __func__,
	       scamper_addr_tostr(dst, buf, sizeof(buf)));
      goto err;
    }

  if(n2i->set == NULL &&
     (n2i->set = malloc_zero(sizeof(sc_idset_t))) == NULL)
    {
      logprint("%s: could not malloc idset: %s", __func__, strerror(errno));
      goto err;
    }

  if((method = ping_to_method(ping)) == NULL)
    {
      logprint("%s: unhandled method", __func__);
      goto err;
    }
  code = ping_r(method, ping);
  n2i->set->tests |= (1 << (method->id-1));
  if((item = sc_iditem_get(n2i->set, dst)) == NULL)
    {
      logprint("%s: could not get item for %s: %s", __func__,
	       scamper_addr_tostr(dst, buf, sizeof(buf)), strerror(errno));
      goto err;
    }
  item->tests |= (1 << (method->id-1));
  if(code == 1)
    item->results |= (1 << (method->id-1));

 done:
  rc = do_decoderead_addr(dst);
  scamper_ping_free(ping);
  return rc;

 err:
  scamper_ping_free(ping);
  return -1;
}

static int do_decoderead_trace(scamper_trace_t *trace)
{
  int rc = do_decoderead_addr(scamper_trace_dst_get(trace));
  scamper_trace_free(trace);
  return rc;
}

static int do_n2i_next(void)
{
  scamper_addr_t *addr;
  struct timeval tv;
  sc_ip2n2i_t *ip2n2i;
  char buf[128];

  assert(n2i_last != NULL);

  addr = slist_head_item(n2i_last->addrs);
  scamper_addr_tostr(addr, buf, sizeof(buf));

  if((ip2n2i = sc_ip2n2i_find(addr)) == NULL)
    {
      logprint("%s: could not find %s", __func__, buf);
      return -1;
    }
  if(ip2n2i->n2i != n2i_last)
    {
      logprint("%s: different n2i %u than expected %u", __func__,
	       ip2n2i->n2i->id, n2i_last->id);
      return -1;
    }

  logprint("%s: skipping %s", __func__, buf);

  sc_ip2n2i_free(ip2n2i);
  addr = slist_head_pop(n2i_last->addrs);
  scamper_addr_free(addr);
  if(slist_count(n2i_last->addrs) == 0)
    {
      sc_name2ips_free(n2i_last);
      n2i_last = NULL;
    }
  else
    {
      sc_name2ips_methods(n2i_last);
    }

  if(n2i_last != NULL)
    {
      timeval_add_s(&tv, &now, 1);
      if(sc_wait(&tv, n2i_last) != 0)
	{
	  logprint("%s: could not wait %s", __func__, buf);
	  return -1;
	}
    }
  return 0;
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
	 (obj_type == SCAMPER_FILE_OBJ_TRACE &&
	  do_decoderead_trace(obj_data) != 0))
	goto err;
    }
  else if(type == SCAMPER_CTRL_TYPE_ERR)
    {
      do_n2i_next();
    }
  else if(type == SCAMPER_CTRL_TYPE_EOF)
    {
      scamper_inst_free(scamper_inst);
      scamper_inst = NULL;
    }
  else if(type == SCAMPER_CTRL_TYPE_FATAL)
    {
      logprint("%s: fatal: %s", __func__, scamper_ctrl_strerror(scamper_ctrl));
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

static int fp_data(void)
{
  struct timeval tv, *tv_ptr;
  sc_wait_t *w;

  random_seed();

  if((n2i_tree = splaytree_alloc((splaytree_cmp_t)sc_name2ips_name_cmp)) == NULL ||
     (n2i_list = slist_alloc()) == NULL ||
     (waiting = heap_alloc(sc_wait_cmp)) == NULL ||
     do_infile() != 0 || do_scamperconnect() != 0 ||
     (outfile = scamper_file_open(outfile_name, 'w', outfile_type)) == NULL ||
     (decode_sf = scamper_file_opennull('r', "warts")) == NULL ||
     (decode_rb = scamper_file_readbuf_alloc()) == NULL)
    return -1;

  scamper_file_setreadfunc(decode_sf, decode_rb, scamper_file_readbuf_read);

  while(scamper_ctrl_isdone(scamper_ctrl) == 0)
    {
      /*
       * need to set a timeout on select if scamper's processing window is
       * not full and there is a trace in the waiting queue.
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
	  if(slist_count(n2i_list) > 0 ||
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

      if(splaytree_count(n2i_tree) == 0 && slist_count(n2i_list) == 0 &&
	 heap_count(waiting) == 0 && done == 0)
	{
	  scamper_inst_done(scamper_inst);
	  done = 1;
	}

      scamper_ctrl_wait(scamper_ctrl, tv_ptr);

      if(error != 0)
	return -1;
    }

  return 0;
}

static int sc_idset_print_cb(void *ptr, void *item)
{
  sc_idset_print(item);
  return 0;
}

static int fp_read(void)
{
  splaytree_t *tree = NULL;
  scamper_file_t *in = NULL;
  sc_policytest_t *method;
  scamper_ping_t *ping;
  sc_idset_t *set;
  sc_iditem_t *item;
  uint16_t type;
  void *data;
  int code;

  if(string_isdash(datafile) != 0)
    in = scamper_file_openfd(STDIN_FILENO, "-", 'r', "warts");
  else
    in = scamper_file_open(datafile, 'r', NULL);
  if(in == NULL)
    {
      fprintf(stderr, "could not open %s: %s\n", datafile, strerror(errno));
      goto err;
    }

  if((tree = splaytree_alloc((splaytree_cmp_t)sc_idset_cmp)) == NULL)
    goto err;

  while(scamper_file_read(in, ffilter, &type, &data) == 0)
    {
      if(data == NULL)
	break;

      ping = data;
      if((method = ping_to_method(ping)) == NULL)
	goto err;
      code = ping_r(method, ping);

      if((set = sc_idset_get(tree, scamper_ping_userid_get(ping))) == NULL)
	goto err;
      set->tests |= (1 << (method->id-1));

      if((item = sc_iditem_get(set, scamper_ping_dst_get(ping))) == NULL)
	goto err;
      item->tests |= (1 << (method->id-1));
      if(code == 1)
	item->results |= (1 << (method->id-1));

      scamper_ping_free(ping);
    }
  scamper_file_close(in);

  splaytree_inorder(tree, sc_idset_print_cb, NULL);
  splaytree_free(tree, (splaytree_free_t)sc_idset_free);

  return 0;

 err:
  return -1;
}

static int fp_init(void)
{
  uint16_t types[3];
  int typec = 0;

  if(flags & FLAG_TRACEROUTE)
    types[typec++] = SCAMPER_FILE_OBJ_TRACE;
  else
    types[typec++] = SCAMPER_FILE_OBJ_PING;
  if(options & OPT_OUTFILE)
    {
      types[typec++] = SCAMPER_FILE_OBJ_CYCLE_START;
      types[typec++] = SCAMPER_FILE_OBJ_CYCLE_STOP;
    }
  if((ffilter = scamper_file_filter_alloc(types, typec)) == NULL)
    return -1;

  return 0;
}

static void cleanup(void)
{
  if(n2i_tree != NULL) splaytree_free(n2i_tree, NULL);
  if(n2i_list != NULL) slist_free(n2i_list);
  if(waiting != NULL) heap_free(waiting, free);
  if(scamper_inst != NULL) scamper_inst_free(scamper_inst);
  if(scamper_ctrl != NULL) scamper_ctrl_free(scamper_ctrl);
  if(decode_rb != NULL) scamper_file_readbuf_free(decode_rb);
  if(decode_sf != NULL) scamper_file_close(decode_sf);
  if(outfile != NULL) scamper_file_close(outfile);
  if(ffilter != NULL) scamper_file_filter_free(ffilter);
  if(logfile != NULL) fclose(logfile);
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

#ifdef HAVE_DAEMON
  /* start a daemon if asked to */
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    return -1;
#endif

  if(fp_init() != 0)
    return -1;

  if(options & OPT_READ)
    return fp_read();

  return fp_data();
}
