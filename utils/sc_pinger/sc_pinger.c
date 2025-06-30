/*
 * sc_pinger : scamper driver to probe destinations with various ping
 *             methods
 *
 * $Id: sc_pinger.c,v 1.49 2025/06/29 22:32:14 mjl Exp $
 *
 * Copyright (C) 2020      The University of Waikato
 * Copyright (C) 2022-2025 Matthew Luckie
 * Copyright (C) 2023-2025 The Regents of the University of California
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
#include "scamper_ping.h"
#include "scamper_dealias.h"
#include "scamper_file.h"
#include "libscamperctrl.h"
#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "utils.h"

typedef struct sc_methstats sc_methstats_t;

static uint32_t               options       = 0;
static char                  *addrfile_name = NULL;
static int                    addrfile_fd   = -1;
static char                  *addrfile_buf  = NULL;
static size_t                 addrfile_len  = 8192;
static size_t                 addrfile_off  = 0;
static char                  *outfile_name  = NULL;
static char                  *outfile_type  = "warts";
static scamper_file_t        *outfile       = NULL;
static char                  *movedir_name  = NULL;
static char                  *logfile_name  = NULL;
static FILE                  *logfile_fd    = NULL;
static scamper_file_filter_t *ffilter       = NULL;
static int                    scamper_port  = 0;
static char                  *scamper_unix  = NULL;
static scamper_ctrl_t        *scamper_ctrl  = NULL;
static scamper_inst_t        *scamper_inst  = NULL;
static scamper_file_t        *decode_sf     = NULL;
static scamper_file_readbuf_t *decode_rb    = NULL;
static int                    probing       = 0;
static int                    more          = 0;
static int                    completed     = 0;
static long                   probe_count   = 5;
static long                   reply_count   = 3;
static int                    batch_count   = 0;
static uint32_t               limit         = 0;
static uint32_t               outfile_u     = 0;
static uint32_t               outfile_c     = 0;
static slist_t               *virgin        = NULL;
static slist_t               *waiting       = NULL;
static char                 **methods       = NULL;
static int                    methodc       = 0;
static int                    methodc_ok    = 0;
static int                    error         = 0;
static struct timeval         zombie;
static int                    ctrlcb_called = 0;
static sc_methstats_t       **method_stats  = NULL;
static size_t                 rxttl_window  = 0;
static size_t                 rxttl_thresh  = 0;

#define OPT_HELP        0x0001
#define OPT_ADDRFILE    0x0002
#define OPT_OUTFILE     0x0004
#define OPT_PORT        0x0008
#define OPT_UNIX        0x0010
#define OPT_LOG         0x0020
#define OPT_DAEMON      0x0040
#define OPT_COUNT       0x0080
#define OPT_REMOTE      0x0100
#define OPT_LIMIT       0x0200
#define OPT_MOVE        0x0400
#define OPT_BATCH       0x0800
#define OPT_METHOD      0x1000
#define OPT_ZOMBIE      0x2000
#define OPT_BAD         0x4000

#ifdef PACKAGE_VERSION
#define OPT_VERSION     0x8000
#endif

/*
 * sc_pingtest
 *
 * keep state about which method we are up to
 */
typedef struct sc_pinger
{
  scamper_addr_t   *dst;
  int               step;
} sc_pinger_t;

typedef struct sc_cmdstate
{
  uint8_t           type;
  union
  {
    sc_pinger_t    *pinger;
    slist_t        *batch;
    void           *ptr;
  } un;
} sc_cmdstate_t;

typedef struct sc_sample
{
  suseconds_t    usec;
  uint8_t        rxttl;
} sc_sample_t;

typedef struct sc_rxsec
{
  time_t         sec;      /* the second portion of a timestamp */
  slist_t       *samples;  /* list of sc_sample, ordered by usec */
} sc_rxsec_t;

struct sc_methstats
{
  struct timeval  left;    /* earlier timestamps have been discarded */
  splaytree_t    *tree;    /* tree of sc_rxsec_t, by sec */
  uint8_t         rxttl;   /* current rxttl */
  size_t          runlen;  /* current runlen of rxttl */
  size_t          samplec; /* number of samples in tree */
  int             sorted;  /* lmlb rxsec samples are sorted */
};

static void usage(uint32_t opt_mask)
{
  const char *v;

#ifdef OPT_VERSION
  v = "v";
#else
  v = "";
#endif

  fprintf(stderr,
	  "usage: sc_pinger [-D%s?] [-a infile] [-o outfile]\n"
	  "                 [-p port] [-R unix] [-U unix]\n"
	  "                 [-b batch-count] [-B bad-spec] [-c probe-count]\n"
	  "                 [-l limit] [-m method] [-M dir] [-t logfile]\n"
	  "                 [-Z zombie]\n", v);

  if(opt_mask == 0)
    {
      fprintf(stderr, "       sc_pinger -?\n\n");
      return;
    }

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "     -? give an overview of the usage of sc_pinger\n");

  if(opt_mask & OPT_ADDRFILE)
    fprintf(stderr, "     -a input addressfile\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "     -o output warts file\n");

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -p port to find scamper on\n");

  if(opt_mask & OPT_REMOTE)
    fprintf(stderr, "     -R find remote scamper process on unix socket\n");

  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "     -U find local scamper process on unix socket\n");

  if(opt_mask & OPT_DAEMON)
    fprintf(stderr, "     -D start as daemon\n");

  if(opt_mask & OPT_BATCH)
    fprintf(stderr, "     -b number of destinations to probe in batch\n");

  if(opt_mask & OPT_BAD)
    fprintf(stderr, "     -B how to detect and remove bad probe methods\n");

  if(opt_mask & OPT_COUNT)
    fprintf(stderr, "     -c [replyc]/probec\n");

  if(opt_mask & OPT_LIMIT)
    fprintf(stderr, "     -l limit on (dst, method) tuples per output file\n");

  if(opt_mask & OPT_METHOD)
    fprintf(stderr, "     -m probe method to try\n");

  if(opt_mask & OPT_MOVE)
    fprintf(stderr, "     -M directory to move completed files to\n");

  if(opt_mask & OPT_LOG)
    fprintf(stderr, "     -t logfile\n");

  if(opt_mask & OPT_ZOMBIE)
    fprintf(stderr, "     -Z time to wait before declaring scamper silent\n");

#ifdef OPT_VERSION
  if(opt_mask & OPT_VERSION)
    fprintf(stderr, "     -v display version and exit\n");
#endif

  return;
}

/*
 * check_printf
 *
 * ensure the filename has one format specifier, and it is for an
 * unsigned integer.  the digits can be zero padded, but its width
 * cannot otherwise be restricted.
 *
 * shared with sc_prefixprober, perhaps this should be in utils.c and
 * more generic.
 */
static int check_printf(const char *name)
{
  const char *ptr;

  for(ptr=name; *ptr != '\0'; ptr++)
    {
      if(isprint((unsigned char)*ptr) == 0)
	return 0;
      if(*ptr == '%')
	break;
    }

  /* no format specifier */
  if(*ptr == '\0')
    return 0;

  ptr++;

  /* check for valid zero padding specification, if %u is zero padded */
  if(*ptr == '0' && ptr[1] != '0' && isdigit((unsigned char)ptr[1]) != 0)
    {
      ptr++;
      while(isdigit((unsigned char )*ptr) != 0)
	ptr++;
    }

  /* ensure %u */
  if(*ptr != 'u')
    return 0;
  ptr++;

  /* ensure no other % */
  while(*ptr != '\0')
    {
      if(isprint((unsigned char)*ptr) == 0)
	return 0;
      if(*ptr == '%')
	return 0;
      ptr++;
    }

  return 1;
}

static int parse_count(const char *opt, long *enumerator, long *denominator)
{
  char *dup, *ptr;
  int rc = -1;

  if((dup = strdup(opt)) == NULL)
    goto done;

  ptr = dup;
  while(*ptr != '\0' && *ptr != '/')
    ptr++;
  if(*ptr == '/')
    {
      *ptr = '\0';
      ptr++;

      if(string_isdigit(ptr) == 0 || string_isdigit(dup) == 0 ||
	 string_tolong(dup, enumerator) != 0 ||
	 string_tolong(ptr, denominator) != 0 ||
	 *enumerator > *denominator || *enumerator < 1 || *denominator < 1)
	goto done;
    }
  else
    {
      if(string_isdigit(dup) == 0 || string_tolong(dup, enumerator) != 0)
	goto done;
      *denominator = *enumerator;
    }
  rc = 0;

 done:
  if(dup != NULL) free(dup);
  return rc;
}

static int check_options(int argc, char *argv[])
{
  char opts[64], *ptr, *dup = NULL;
  char *opt_count = NULL, *opt_port = NULL, *opt_limit = NULL;
  char *opt_batch = NULL, *opt_zombie = NULL;
  slist_t *method_list = NULL, *bad_list = NULL;
  long lo, enumerator, denominator;
  struct stat sb;
  size_t off = 0;
  int i, ch, rc = -1;

  string_concat(opts, sizeof(opts), &off, "a:b:B:c:Dl:m:M:o:p:R:t:U:Z:?");
#ifdef OPT_VERSION
  string_concatc(opts, sizeof(opts), &off, 'v');
#endif

  if((method_list = slist_alloc()) == NULL ||
     (bad_list = slist_alloc()) == NULL)
    goto done;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'a':
	  addrfile_name = optarg;
	  break;

	case 'b':
	  opt_batch = optarg;
	  break;

	case 'B':
	  if((dup = strdup(optarg)) == NULL ||
	     slist_tail_push(bad_list, dup) == NULL)
	    goto done;
	  dup = NULL;
	  break;

	case 'c':
	  opt_count = optarg;
	  break;

	case 'D':
	  options |= OPT_DAEMON;
	  break;

	case 'l':
	  options |= OPT_LIMIT;
	  opt_limit = optarg;
	  break;

	case 'm':
	  if((dup = strdup(optarg)) == NULL ||
	     slist_tail_push(method_list, dup) == NULL)
	    goto done;
	  dup = NULL;
	  break;

	case 'M':
	  options |= OPT_MOVE;
	  movedir_name = optarg;
	  break;

	case 'o':
	  outfile_name = optarg;
	  break;

	case 'p':
	  options |= OPT_PORT;
	  opt_port = optarg;
	  break;

	case 'R':
	  options |= OPT_REMOTE;
	  scamper_unix = optarg;
	  break;

	case 't':
	  logfile_name = optarg;
	  break;

	case 'U':
	  options |= OPT_UNIX;
	  scamper_unix = optarg;
	  break;

#ifdef OPT_VERSION
	case 'v':
	  options |= OPT_VERSION;
	  rc = 0;
	  goto done;
#endif

	case 'Z':
	  options |= OPT_ZOMBIE;
	  opt_zombie = optarg;
	  break;

	case '?':
	default:
	  usage(0xffffffff);
	  goto done;
	}
    }

  if(addrfile_name == NULL || outfile_name == NULL ||
     countbits32(options & (OPT_PORT|OPT_UNIX|OPT_REMOTE)) != 1)
    {
      usage(OPT_ADDRFILE | OPT_OUTFILE | OPT_UNIX | OPT_PORT | OPT_REMOTE);
      goto done;
    }

  if(string_endswith(outfile_name, ".gz") != 0)
    {
#ifdef HAVE_ZLIB
      outfile_type = "warts.gz";
#else
      usage(OPT_OUTFILE);
      fprintf(stderr, "cannot write to %s: did not link against zlib\n",
	      outfile_name);
      goto done;
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
      goto done;
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
      goto done;
#endif
    }

  if(opt_port != NULL)
    {
      if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
	{
	  usage(OPT_PORT);
	  goto done;
	}
      scamper_port = lo;
    }

  if(opt_count != NULL)
    {
      if(parse_count(opt_count, &enumerator, &denominator) != 0 ||
	 denominator > 30)
	{
	  usage(OPT_COUNT);
	  goto done;
	}
      reply_count = enumerator;
      probe_count = denominator;
    }

  if(opt_batch != NULL)
    {
      if(opt_count != NULL && probe_count != reply_count)
	{
	  usage(OPT_BATCH | OPT_COUNT);
	  fprintf(stderr, "cannot use both reply_count and probe batches\n");
	  goto done;
	}
      if(string_tolong(opt_batch, &lo) != 0 || lo < 2)
	{
	  usage(OPT_BATCH);
	  goto done;
	}
      batch_count = lo;
      probe_count = reply_count;
    }

  if((methodc = slist_count(method_list)) > 0)
    {
      if((methods = malloc_zero(sizeof(char *) * methodc)) == NULL)
	goto done;
      i = 0;
      while((ptr = slist_head_pop(method_list)) != NULL)
	methods[i++] = ptr;
    }
  else
    {
      methodc = 3;
      if((methods = malloc_zero(sizeof(char *) * 3)) == NULL ||
	 (methods[0] = strdup("icmp-echo")) == NULL ||
	 (methods[1] = strdup("udp-dport")) == NULL ||
	 (methods[2] = strdup("tcp-ack-sport -d 80")) == NULL)
	goto done;
    }
  methodc_ok = methodc;

  /*
   * if the user specifies a directory to move completed files into,
   * then make sure the directory exists and is a directory.
   */
  if(movedir_name != NULL)
    {
      if(stat(movedir_name, &sb) != 0)
	{
	  usage(OPT_MOVE);
	  fprintf(stderr, "cannot stat %s: %s\n", movedir_name,
		  strerror(errno));
	  goto done;
	}
      if(S_ISDIR(sb.st_mode) == 0)
	{
	  usage(OPT_MOVE);
	  fprintf(stderr, "%s is not a directory\n", movedir_name);
	  goto done;
	}
    }

  /*
   * if the user specifies a limit to the number of completed objects
   * per output file, then make sure the output filename includes %u
   * (and only one % parameter).
   */
  if(opt_limit != NULL)
    {
      if(string_isdigit(opt_limit) == 0 ||
	 string_tolong(opt_limit, &lo) != 0 || lo < 1)
	{
	  usage(OPT_LIMIT);
	  goto done;
	}
      limit = lo;

      if(check_printf(outfile_name) == 0)
	{
	  usage(OPT_LIMIT | OPT_OUTFILE);
	  goto done;
	}
    }

  if(opt_zombie != NULL &&
     (timeval_fromstr(&zombie, opt_zombie, 1000000) != 0 ||
      timeval_cmp_lt(&zombie, 10, 0) != 0))
    {
      usage(OPT_ZOMBIE);
      goto done;
    }

  if(slist_count(bad_list) > 0)
    {
      while((dup = slist_head_pop(bad_list)) != NULL)
	{
	  if(strncasecmp(dup, "rxttl-window=", 13) == 0)
	    {
	      if(string_isdigit(dup+13) == 0 || string_tolong(dup+13, &lo) != 0)
		{
		  usage(OPT_BAD);
		  goto done;
		}
	      rxttl_window = lo;
	    }
	  else if(strncasecmp(dup, "rxttl-thresh=", 13) == 0)
	    {
	      if(string_isdigit(dup+13) == 0 || string_tolong(dup+13, &lo) != 0)
		{
		  usage(OPT_BAD);
		  goto done;
		}
	      rxttl_thresh = lo;
	    }
	  else
	    {
	      usage(OPT_BAD);
	      goto done;
	    }

	  free(dup); dup = NULL;
	}

      if((rxttl_window != 0 || rxttl_thresh != 0) &&
	 (rxttl_window == 0 || rxttl_thresh == 0))
	{
	  usage(OPT_BAD);
	  goto done;
	}
    }

  rc = 0;

 done:
  if(bad_list != NULL) slist_free_cb(bad_list, free);
  if(method_list != NULL) slist_free_cb(method_list, free);
  if(dup != NULL) free(dup);
  return rc;
}

#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
static void print(char *format, ...) __attribute__((format(printf, 1, 2)));
#endif

static void print(char *format, ...)
{
  struct timeval tv;
  va_list ap;
  char msg[512];

  if(logfile_fd == NULL && (options & OPT_DAEMON) != 0)
    return;

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);

  gettimeofday_wrap(&tv);

  if((options & OPT_DAEMON) == 0)
    printf("%ld: %s\n", (long int)tv.tv_sec, msg);

  if(logfile_fd != NULL)
    {
      fprintf(logfile_fd, "%ld: %s\n", (long int)tv.tv_sec, msg);
      fflush(logfile_fd);
    }

  return;
}

static int movefile(const char *src)
{
  const char *filename = src, *ptr;
  char dst[1024];

  /*
   * figure out the name of the file, if the user specified a
   * directory as part of the output file component
   */
  for(ptr=filename; *ptr != '\0'; ptr++)
    if(*ptr == '/')
      filename = (ptr+1);

  snprintf(dst, sizeof(dst), "%s/%s", movedir_name, filename);

  if(rename(src, dst) != 0)
    {
      fprintf(stderr, "could not move the output file: %s\n",
	      strerror(errno));
      return -1;
    }

  return 0;
}

static int openfile(void)
{
  char buf[1024], *fn;

  if(limit != 0)
    {
      snprintf(buf, sizeof(buf), outfile_name, outfile_u);
      fn = buf;
    }
  else fn = outfile_name;

  if((outfile = scamper_file_open(fn, 'w', outfile_type)) == NULL)
    {
      print("%s: could not open output file", __func__);
      return -1;
    }

  return 0;
}

static int rotatefile(void)
{
  char *fn = NULL;
  int rc = -1;

  if(movedir_name != NULL)
    {
      if((fn = strdup(scamper_file_getfilename(outfile))) == NULL)
	goto done;
      scamper_file_close(outfile); outfile = NULL;
      if(movefile(fn) != 0)
	goto done;
    }
  else
    {
      scamper_file_close(outfile); outfile = NULL;
    }

  outfile_c = 0;
  outfile_u++;
  if(openfile() != 0)
    goto done;

  rc = 0;

 done:
  if(fn != NULL) free(fn);
  return rc;
}

static int sc_sample_cmp(const sc_sample_t *a, const sc_sample_t *b)
{
  if(a->usec < b->usec) return -1;
  if(a->usec > b->usec) return  1;
  return 0;
}

static int sc_rxsec_cmp(const sc_rxsec_t *a, const sc_rxsec_t *b)
{
  if(a->sec < b->sec) return -1;
  if(a->sec > b->sec) return  1;
  return 0;
}

static void sc_rxsec_free(sc_rxsec_t *rxs)
{
  if(rxs->samples != NULL)
    slist_free_cb(rxs->samples, free);
  free(rxs);
  return;
}

static sc_rxsec_t *sc_rxsec_alloc(time_t sec)
{
  sc_rxsec_t *rxs = NULL;
  if((rxs = malloc_zero(sizeof(sc_rxsec_t))) == NULL ||
     (rxs->samples = slist_alloc()) == NULL)
    goto err;
  rxs->sec = sec;
  return rxs;

 err:
  if(rxs != NULL) sc_rxsec_free(rxs);
  return NULL;
}

static sc_rxsec_t *sc_rxsec_get(splaytree_t *tree, time_t sec)
{
  sc_rxsec_t *rxs, fm;

  fm.sec = sec;
  if((rxs = splaytree_find(tree, &fm)) != NULL)
    return rxs;
  if((rxs = sc_rxsec_alloc(sec)) == NULL ||
     splaytree_insert(tree, rxs) == NULL)
    goto err;

  return rxs;

 err:
  if(rxs != NULL) sc_rxsec_free(rxs);
  return NULL;
}

static void sc_methstats_free(sc_methstats_t *ms)
{
  if(ms->tree != NULL)
    splaytree_free(ms->tree, (splaytree_free_t)sc_rxsec_free);
  free(ms);
  return;
}

static sc_methstats_t *sc_methstats_alloc(void)
{
  sc_methstats_t *ms;

  if((ms = malloc_zero(sizeof(sc_methstats_t))) == NULL ||
     (ms->tree = splaytree_alloc((splaytree_cmp_t)sc_rxsec_cmp)) == NULL)
    goto err;

  return ms;

 err:
  if(ms != NULL) sc_methstats_free(ms);
  return NULL;
}

static int sc_methstats_process(sc_methstats_t *ms,
				const struct timeval *tv, uint8_t rxttl)
{
  static int window_warned = 0;
  sc_sample_t *smpl = NULL;
  sc_rxsec_t *rxs;

  /* ignore samples before our window */
  if(timeval_cmp(tv, &ms->left) < 0)
    {
      if(window_warned == 0)
	{
	  print("warning: sample is before left of window, increase window");
	  window_warned = 1;
	}
      return 0;
    }

  /* put the sample on the appropriate list */
  if((rxs = sc_rxsec_get(ms->tree, tv->tv_sec)) == NULL ||
     (smpl = malloc(sizeof(sc_sample_t))) == NULL ||
     slist_tail_push(rxs->samples, smpl) == NULL)
    {
      print("%s: could not store sample", __func__);
      goto err;
    }
  smpl->usec = tv->tv_usec;
  smpl->rxttl = rxttl;
  ms->samplec++;

  /* if we put the sample on the left most list, flag for re-sorting */
  if(ms->left.tv_sec != 0 && ms->left.tv_sec == tv->tv_sec)
    ms->sorted = 0;

  return 0;

 err:
  if(smpl != NULL) free(smpl);
  return -1;
}

static int sc_methstats_rxttl_check(sc_methstats_t *ms)
{
  sc_rxsec_t *rxs;
  sc_sample_t *smpl;
  int bad = 0;

  if(rxttl_window >= ms->samplec)
    return 0;

  while(ms->samplec > rxttl_window && bad == 0)
    {
      rxs = splaytree_getlmlb(ms->tree); assert(rxs != NULL);

      if(ms->sorted == 0)
	{
	  if(slist_qsort(rxs->samples, (slist_cmp_t)sc_sample_cmp) != 0)
	    {
	      print("%s: could not sort", __func__);
	      return -1;
	    }
	  ms->sorted = 1;
	}

      do
	{
	  if((smpl = slist_head_pop(rxs->samples)) == NULL)
	    {
	      splaytree_remove_item(ms->tree, rxs);
	      sc_rxsec_free(rxs);
	      ms->sorted = 0;
	      break;
	    }
	  ms->samplec--;
	  ms->left.tv_sec = rxs->sec;
	  ms->left.tv_usec = smpl->usec;
	  if(smpl->rxttl != ms->rxttl)
	    {
	      ms->runlen = 1;
	      ms->rxttl  = smpl->rxttl;
	    }
	  else
	    {
	      ms->runlen++;
	      if(ms->runlen >= rxttl_thresh)
		bad = 1;
	    }
	  free(smpl);
	}
      while(ms->samplec > rxttl_window && bad == 0);
    }

  return bad;
}

static int sc_pinger_nextstep(sc_pinger_t *pinger)
{
  if(method_stats != NULL)
    {
      while(++pinger->step < methodc)
	if(method_stats[pinger->step] != NULL)
	  break;
    }
  else
    {
      pinger->step++;
    }
  if(pinger->step == methodc)
    return 0;
  return 1;
}

static void sc_pinger_free(sc_pinger_t *pinger)
{
  if(pinger->dst != NULL) scamper_addr_free(pinger->dst);
  free(pinger);
  return;
}

static sc_cmdstate_t *sc_cmdstate_alloc(uint8_t type, void *ptr)
{
  sc_cmdstate_t *cs;
  if(type > 1 ||
     (cs = malloc_zero(sizeof(sc_cmdstate_t))) == NULL)
    return NULL;
  cs->type = type;
  cs->un.ptr = ptr;
  return cs;
}

static int do_addrfile_line(char *buf)
{
  static int line = 0;
  sc_pinger_t *pinger = NULL;
  scamper_addr_t *sa = NULL;

  line++;

  if(buf[0] == '\0' || buf[0] == '#')
    return 0;

  if((sa = scamper_addr_fromstr_unspec(buf)) == NULL)
    {
      print("could not resolve %s on line %d", buf, line);
      goto err;
    }

  if((pinger = malloc_zero(sizeof(sc_pinger_t))) == NULL)
    {
      print("could not malloc pinger");
      goto err;
    }
  pinger->dst = sa; sa = NULL;
  if(slist_tail_push(virgin, pinger) == NULL)
    {
      print("could not push %s onto list", buf);
      goto err;
    }

  return 0;

 err:
  if(pinger != NULL) sc_pinger_free(pinger);
  if(sa != NULL) scamper_addr_free(sa);
  return -1;
}

static int do_addrfile(void)
{
  size_t start, end, off;
  ssize_t ss;

  if((ss = read(addrfile_fd, addrfile_buf + addrfile_off,
		addrfile_len - addrfile_off - 1)) < 0)
    goto err;

  start = 0; off = 0;
  end = addrfile_off + ss;

  while(off <= end)
    {
      if(off == end && ss != 0)
	break;
      if(addrfile_buf[off] == '\n' || (off == end && start < off))
	{
	  addrfile_buf[off] = '\0';
	  if(do_addrfile_line(addrfile_buf + start) != 0)
	    goto err;
	  start = ++off;
	}
      else
	{
	  ++off;
	}
    }

  if(ss == 0)
    {
      close(addrfile_fd); addrfile_fd = -1;
      return 0;
    }

  if(start == 0)
    {
      addrfile_len += 8192;
      addrfile_off = off;
      if(realloc_wrap((void **)&addrfile_buf, addrfile_len) != 0)
	{
	  print("%s: could not realloc %d bytes", __func__, (int)addrfile_len);
	  goto err;
	}
    }
  else
    {
      addrfile_off = end - start;
      memmove(addrfile_buf, addrfile_buf+start, addrfile_off);
    }

  return 0;

 err:
  close(addrfile_fd); addrfile_fd = -1;
  return -1;
}

static int do_method_ping_cmd(sc_pinger_t *pinger)
{
  char cmd[512], addr[128];
  sc_cmdstate_t *cs = NULL;
  size_t off = 0;

  assert(pinger != NULL);

  scamper_addr_tostr(pinger->dst, addr, sizeof(addr));
  if(probe_count != reply_count)
    string_concaf(cmd, sizeof(cmd), &off, "ping -c %ld -o %ld -P %s %s",
		  probe_count, reply_count, methods[pinger->step], addr);
  else
    string_concaf(cmd, sizeof(cmd), &off, "ping -c %ld -P %s %s",
		  probe_count, methods[pinger->step], addr);

  if((cs = sc_cmdstate_alloc(0, pinger)) == NULL)
    {
      print("%s: could not alloc cmdstate", __func__);
      return -1;
    }

  /* got a command, send it */
  if(scamper_inst_do(scamper_inst, cmd, cs) == NULL)
    {
      print("%s: could not send %s", __func__, cmd);
      return -1;
    }
  probing++;
  more--;

  print("p %d, c %d: %s", probing, completed, cmd);
  return 0;
}

static int do_method_getpinger(sc_pinger_t **out)
{
  sc_pinger_t *pinger;
  
  if((pinger = slist_head_pop(waiting)) != NULL)
    goto done;

  if((pinger = slist_head_pop(virgin)) == NULL)
    {
      if(addrfile_fd == -1)
	goto done;
      if(do_addrfile() != 0)
	return -1;
      if((pinger = slist_head_pop(virgin)) == NULL)
	goto done;
    }

  if(method_stats != NULL)
    {
      while(method_stats[pinger->step] == NULL && pinger->step < methodc)
	pinger->step++;
      if(pinger->step == methodc)
	return -1;
    }

 done:
  *out = pinger;
  return 0;
}

static int do_method_ping(void)
{
  sc_pinger_t *pinger;

  if(do_method_getpinger(&pinger) != 0)
    return -1;
  if(pinger == NULL)
    return 0;

  return do_method_ping_cmd(pinger);
}

static int do_method_radargun(void)
{
  slist_t *batch = NULL;
  slist_t *cmd_parts = NULL;
  char part[512], addr[128], *dup = NULL, *cmd = NULL;
  sc_pinger_t *pinger;
  sc_cmdstate_t *cs = NULL;
  size_t off, len = 0;
  int rc = 1;

  if((batch = slist_alloc()) == NULL || (cmd_parts = slist_alloc()) == NULL)
    {
      print("%s: could not alloc list", __func__);
      goto done;
    }

  /* put the first part of the probe command on the list */
  off = 0;
  string_concaf(part, sizeof(part), &off,
		"dealias -w 1s -r 1s -m radargun -q %ld", reply_count);
  if((dup = memdup(part, off+1)) == NULL ||
     slist_tail_push(cmd_parts, dup) == NULL)
    goto done;
  dup = NULL;
  len += off;

  while(slist_count(batch) < batch_count)
    {
      if(do_method_getpinger(&pinger) != 0)
	return -1;
      if(pinger == NULL)
	break;

      off = 0;
      scamper_addr_tostr(pinger->dst, addr, sizeof(addr));
      string_concaf(part, sizeof(part), &off, " -p '-P %s -i %s'",
		    methods[pinger->step], addr);
      len += off;

      if((dup = memdup(part, off+1)) == NULL ||
	 slist_tail_push(cmd_parts, dup) == NULL)
	goto done;
      dup = NULL;

      if(slist_tail_push(batch, pinger) == NULL)
	goto done;
      pinger = NULL;
    }

  if(slist_count(batch) == 0)
    {
      rc = 0;
      goto done;
    }

  /* can't do radargun with a single IP address */
  if(slist_count(batch) == 1)
    {
      pinger = slist_head_item(batch);
      rc = do_method_ping_cmd(pinger);
      goto done;
    }

  if((cmd = malloc(len + 1)) == NULL)
    goto done;
  off = 0;
  while((dup = slist_head_pop(cmd_parts)) != NULL)
    {
      string_concat(cmd, len + 1, &off, dup);
      free(dup); dup = NULL;
    }

  if((cs = sc_cmdstate_alloc(1, batch)) == NULL)
    goto done;
  batch = NULL;

  /* got a command, send it */
  if(scamper_inst_do(scamper_inst, cmd, cs) == NULL)
    {
      print("%s: could not send %s", __func__, cmd);
      goto done;
    }
  probing += slist_count(cs->un.batch);
  cs = NULL;
  more--;

  print("p %d, c %d: %s", probing, completed, cmd);
  rc = 0;

 done:
  if(cs != NULL) free(cs);
  if(cmd != NULL) free(cmd);
  if(dup != NULL) free(dup);
  if(cmd_parts != NULL) slist_free_cb(cmd_parts, free);
  if(batch != NULL) slist_free(batch);
  return rc;
}

static int do_method(void)
{
  if(methodc_ok == 0)
    {
      slist_empty_cb(waiting, (slist_free_t)sc_pinger_free);
      slist_empty_cb(virgin, (slist_free_t)sc_pinger_free);
      close(addrfile_fd); addrfile_fd = -1;
      return 0;
    }

  if(more < 1)
    return 0;
  if(batch_count >= 2)
    return do_method_radargun();
  return do_method_ping();
}

static int process_pinger(sc_pinger_t *pinger, scamper_ping_t *ping)
{
  const scamper_ping_probe_t *probe;
  const scamper_ping_reply_t *reply;
  const struct timeval *tx;
  scamper_addr_t *dst, *r_addr;
  sc_methstats_t *ms = NULL;
  uint16_t i, ping_sent;
  uint8_t rttl;
  char buf[128];
  int replyc = 0;

  probing--;

  if(ping != NULL)
    {
      ping_sent = scamper_ping_sent_get(ping);
      dst = scamper_ping_dst_get(ping);
      if(method_stats != NULL)
	ms = method_stats[pinger->step];
      for(i=0; i<ping_sent; i++)
	{
	  if((probe = scamper_ping_probe_get(ping, i)) == NULL ||
	     (reply = scamper_ping_probe_reply_get(probe, 0)) == NULL ||
	     (r_addr = scamper_ping_reply_addr_get(reply)) == NULL ||
	     (scamper_addr_cmp(dst, r_addr) != 0 &&
	      scamper_ping_reply_is_from_target(ping, reply) == 0))
	    continue;

	  if(rxttl_thresh > 0 && ms != NULL)
	    {
	      tx = scamper_ping_probe_tx_get(probe);
	      rttl = scamper_ping_reply_ttl_get(reply);
	      sc_methstats_process(ms, tx, rttl);
	    }

	  replyc++;
	}
      scamper_ping_free(ping);

      if(rxttl_thresh > 0 && replyc > 0 && ms != NULL &&
	 sc_methstats_rxttl_check(ms) != 0)
	{
	  methodc_ok--;
	  print("%s: detected %s bad, %d methods left",
		__func__, methods[pinger->step], methodc_ok);
	  sc_methstats_free(ms); method_stats[pinger->step] = NULL;
	}

      /* successful ping, we're done */
      if(replyc >= reply_count)
	goto done;
    }

  /* try with the next method, if there is another method to try */
  if(sc_pinger_nextstep(pinger) != 0)
    {
      if(slist_tail_push(waiting, pinger) == NULL)
	{
	  print("%s: could not try next method for %s", __func__,
		scamper_addr_tostr(pinger->dst, buf, sizeof(buf)));
	  return -1;
	}
      goto rotate;
    }

 done:
  completed++;
  print("%s: done %s", __func__,
	scamper_addr_tostr(pinger->dst, buf, sizeof(buf)));
  sc_pinger_free(pinger);

 rotate:
  if(limit != 0 && ++outfile_c == limit && rotatefile() != 0)
    return -1;
  return 0;
}

static int process_radargun(slist_t *batch, scamper_dealias_t *dealias)
{
  scamper_dealias_radargun_t *rg;
  scamper_dealias_probe_t *probe;
  scamper_dealias_reply_t *reply;
  scamper_dealias_probedef_t *def;
  const struct timeval *tx;
  sc_pinger_t *pinger, **pingers = NULL;
  int x, batchc, *replyc = NULL, replies = 0;
  uint32_t i, probec, id;
  sc_methstats_t *ms;
  uint8_t rttl;
  char buf[128];
  int rc = -1;

  /* figure out how many targets in this batch */
  if((batchc = slist_count(batch)) < 1)
    goto done;
  probing -= batchc;

  /* structures to help process radargun probes */
  if((pingers = malloc_zero(batchc * sizeof(sc_pinger_t *))) == NULL ||
     (replyc = malloc_zero(batchc * sizeof(int))) == NULL)
    goto done;
  for(x=0; x<batchc; x++)
    pingers[x] = slist_head_pop(batch);
  slist_free(batch); batch = NULL;

  if(dealias != NULL)
    {
      if((rg = scamper_dealias_radargun_get(dealias)) == NULL ||
	 scamper_dealias_radargun_defc_get(rg) != (uint32_t)batchc)
	goto done;
      probec = scamper_dealias_probec_get(dealias);

      for(i=0; i<probec; i++)
	{
	  probe = scamper_dealias_probe_get(dealias, i);
	  reply = scamper_dealias_probe_reply_get(probe, 0);
	  if(reply == NULL ||
	     scamper_dealias_reply_from_target(probe, reply) == 0)
	    continue;
	  def = scamper_dealias_probe_def_get(probe);
	  id = scamper_dealias_probedef_id_get(def);
	  if(id >= (uint32_t)batchc)
	    goto done;

	  if(method_stats != NULL && rxttl_thresh > 0)
	    {
	      pinger = pingers[id];
	      if((ms = method_stats[pinger->step]) != NULL)
		{
		  tx = scamper_dealias_probe_tx_get(probe);
		  rttl = scamper_dealias_reply_ttl_get(reply);
		  sc_methstats_process(ms, tx, rttl);
		}
	    }

	  replies++;
	  replyc[id]++;
	}

      /*
       * check method stats for all methods if we got any reply at
       * all.  easier code than checking just the methods that got a
       * reply this round.
       */
      if(method_stats != NULL && rxttl_thresh > 0 && replies > 0)
	{
	  for(x=0; x<methodc; x++)
	    {
	      if((ms = method_stats[x]) != NULL &&
		 sc_methstats_rxttl_check(ms) != 0)
		{
		  methodc_ok--;
		  print("%s: detected %s bad, %d methods left",
			__func__, methods[x], methodc_ok);
		  sc_methstats_free(ms);
		  method_stats[x] = NULL;
		}
	    }
	}

      scamper_dealias_free(dealias);
    }

  for(x=0; x<batchc; x++)
    {
      pinger = pingers[x];

      /* successful ping, we're done */
      if(replyc[x] >= reply_count)
	goto completed;

      /* try with the next method, if there is another method to try */
      if(sc_pinger_nextstep(pinger) != 0)
	{
	  if(slist_tail_push(waiting, pinger) == NULL)
	    {
	      print("%s: could not try next method for %s", __func__,
		    scamper_addr_tostr(pinger->dst, buf, sizeof(buf)));
	      goto done;
	    }
	  continue;
	}

    completed:
      completed++;
      print("%s: done %s", __func__,
	    scamper_addr_tostr(pinger->dst, buf, sizeof(buf)));
      sc_pinger_free(pinger);
    }

  if(limit != 0)
    {
      outfile_c += batchc;
      if(outfile_c >= limit && rotatefile() != 0)
	goto done;
    }

  rc = 0;

 done:
  if(pingers != NULL) free(pingers);
  if(replyc != NULL) free(replyc);
  if(batch != NULL) slist_free(batch);
  return rc;
}

static void ctrlcb(scamper_inst_t *inst, uint8_t type, scamper_task_t *task,
		   const void *data, size_t len)
{
  sc_cmdstate_t *cs = NULL;
  uint16_t obj_type;
  void *obj_data;

  ctrlcb_called = 1;

  if(type == SCAMPER_CTRL_TYPE_MORE)
    {
      more++;
      if(do_method() != 0)
	goto err;
    }
  else if(type == SCAMPER_CTRL_TYPE_DATA)
    {
      if(scamper_file_readbuf_add(decode_rb, data, len) != 0 ||
	 scamper_file_read(decode_sf, ffilter, &obj_type, &obj_data) != 0)
	{
	  print("%s: could not read", __func__);
	  goto err;
	}

      if(obj_data == NULL)
	return;

      if(scamper_file_write_obj(outfile, obj_type, obj_data) != 0)
	{
	  print("%s: could not write obj %d", __func__, obj_type);
	  goto err;
	}

      if(obj_type == SCAMPER_FILE_OBJ_CYCLE_START ||
	 obj_type == SCAMPER_FILE_OBJ_CYCLE_STOP)
	{
	  scamper_cycle_free(obj_data);
	  return;
	}

      cs = scamper_task_param_get(task);
      if(obj_type == SCAMPER_FILE_OBJ_PING)
	{
	  if(cs->type != 0)
	    goto err;
	  if(process_pinger(cs->un.pinger, (scamper_ping_t *)obj_data) != 0)
	    goto err;
	}
      else if(obj_type == SCAMPER_FILE_OBJ_DEALIAS)
	{
	  if(cs->type != 1)
	    goto err;
	  if(process_radargun(cs->un.batch, (scamper_dealias_t *)obj_data) != 0)
	    goto err;
	}
      else
	{
	  print("%s: unknown object %d", __func__, obj_type);
	  goto err;
	}
      free(cs); cs = NULL;
    }
  else if(type == SCAMPER_CTRL_TYPE_ERR)
    {
      cs = scamper_task_param_get(task);
      if(cs->type == 0)
	{
	  if(process_pinger(cs->un.pinger, NULL) != 0)
	    goto err;
	}
      else if(cs->type == 1)
	{
	  if(process_radargun(cs->un.batch, NULL) != 0)
	    goto err;
	}
      else goto err;
      free(cs); cs = NULL;
    }
  else if(type == SCAMPER_CTRL_TYPE_EOF)
    {
      scamper_inst_free(scamper_inst);
      scamper_inst = NULL;
    }
  else if(type == SCAMPER_CTRL_TYPE_FATAL)
    {
      print("fatal: %s", scamper_ctrl_strerror(scamper_ctrl));
      goto err;
    }

  return;

 err:
  if(cs != NULL) free(cs);
  error = 1;
  return;
}

#ifdef HAVE_SOCKADDR_UN
/*
 * inst_remote:
 *
 * create a remote instance, either via
 *  - mux: /path/to/mux/vp
 *  - socket: /path/to/unix-dir/vp
 */
static scamper_inst_t *inst_remote(void)
{
  scamper_inst_t *inst = NULL;
  struct stat sb;

  if(stat(scamper_unix, &sb) == 0)
    {
      if(S_ISSOCK(sb.st_mode) == 0)
	{
	  print("%s: %s is not a remote socket", __func__, scamper_unix);
	  return NULL;
	}
      if((inst = scamper_inst_remote(scamper_ctrl, scamper_unix)) == NULL)
	print("%s: could not alloc remote inst: %s", __func__,
	      scamper_ctrl_strerror(scamper_ctrl));
      return inst;
    }

  if((inst = scamper_inst_muxvp(scamper_ctrl, scamper_unix)) == NULL)
    print("%s: could not alloc mux vp inst: %s", __func__,
	  scamper_ctrl_strerror(scamper_ctrl));

  return inst;
}
#endif

/*
 * do_scamperconnect
 *
 * allocate socket and connect to scamper process listening on the port
 * specified.
 */
static int do_scamperconnect(void)
{
  if((scamper_ctrl = scamper_ctrl_alloc(ctrlcb)) == NULL)
    {
      print("%s: could not alloc scamper_ctrl", __func__);
      return -1;
    }

  if(scamper_port != 0)
    {
      scamper_inst = scamper_inst_inet(scamper_ctrl, NULL, NULL, scamper_port);
      if(scamper_inst == NULL)
	print("%s: could not alloc port inst: %s", __func__,
	      scamper_ctrl_strerror(scamper_ctrl));
    }
#ifdef HAVE_SOCKADDR_UN
  else if(scamper_unix != NULL)
    {
      if(options & OPT_UNIX)
	{
	  scamper_inst = scamper_inst_unix(scamper_ctrl, NULL, scamper_unix);
	  if(scamper_inst == NULL)
	    print("%s: could not alloc unix inst: %s", __func__,
		  scamper_ctrl_strerror(scamper_ctrl));
	}
      else if(options & OPT_REMOTE)
	{
	  scamper_inst = inst_remote();
	}
    }
#endif

  if(scamper_inst == NULL)
    return -1;

  return 0;
}

static int pinger_data(void)
{
  uint16_t types[] = {SCAMPER_FILE_OBJ_CYCLE_START,
		      SCAMPER_FILE_OBJ_CYCLE_STOP,
		      SCAMPER_FILE_OBJ_PING,
		      SCAMPER_FILE_OBJ_DEALIAS};
  int i, typec = sizeof(types) / sizeof(uint16_t);
  struct timeval *timeout = NULL, tv_in, tv_out, tv_diff;
  int done = 0, rc = -1;
  char *fn = NULL;
  size_t len;

#ifdef HAVE_DAEMON
  /* start a daemon if asked to */
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    {
      fprintf(stderr, "could not daemon\n");
      return -1;
    }
#endif

  assert(addrfile_name != NULL);

  /* won't need to read radargun objects */
  if(batch_count < 2)
    typec--;

  if(rxttl_thresh > 0)
    {
      len = sizeof(sc_methstats_t *) * methodc;
      if((method_stats = malloc_zero(len)) == NULL)
	{
	  print("%s: could not init", __func__);
	  return -1;
	}

      for(i=0; i<methodc; i++)
	{
	  if((method_stats[i] = sc_methstats_alloc()) == NULL)
	    {
	      print("%s: could not init", __func__);
	      return -1;
	    }
	}
    }

  if((logfile_name != NULL && (logfile_fd=fopen(logfile_name, "w")) == NULL) ||
     (addrfile_fd = open(addrfile_name, O_RDONLY)) < 0 ||
     (addrfile_buf = malloc(addrfile_len)) == NULL ||
     (ffilter = scamper_file_filter_alloc(types, typec)) == NULL ||
     (virgin = slist_alloc()) == NULL || (waiting = slist_alloc()) == NULL ||
     do_scamperconnect() != 0 || openfile() != 0 ||
     (decode_sf = scamper_file_opennull('r', "warts")) == NULL ||
     (decode_rb = scamper_file_readbuf_alloc()) == NULL)
    {
      print("%s: could not init", __func__);
      return -1;
    }

  /*
   * when we use a timeout, we copy the timeout value into a scratch
   * timeval, as select can overwrite the timeout we supply with how
   * much time is left
   */
  if(timeval_iszero(&zombie) == 0)
    timeout = &tv_diff;

  scamper_file_setreadfunc(decode_sf, decode_rb, scamper_file_readbuf_read);

  while(error == 0 && scamper_ctrl_isdone(scamper_ctrl) == 0)
    {
      if(more > 0 &&
	 (slist_count(waiting) > 0 || slist_count(virgin) > 0 ||
	  addrfile_fd != -1))
	{
	  if(do_method() != 0)
	    return -1;
	}

      if(probing == 0 && slist_count(virgin) == 0 &&
	 slist_count(waiting) == 0 && addrfile_fd == -1 && done == 0)
	{
	  print("%s: done", __func__);
	  scamper_inst_done(scamper_inst);
	  done = 1;
	}

      if(timeout != NULL)
	{
	  ctrlcb_called = 0;
	  timeval_cpy(&tv_diff, &zombie);
	  gettimeofday_wrap(&tv_in);
	}
      scamper_ctrl_wait(scamper_ctrl, timeout);
      if(timeout != NULL && ctrlcb_called == 0)
	{
	  gettimeofday_wrap(&tv_out);
	  if(timeval_cmp(&tv_in, &tv_out) > 0)
	    continue;
	  timeval_diff_tv(&tv_diff, &tv_in, &tv_out);
	  if(timeval_cmp(&tv_diff, &zombie) >= 0)
	    {
	      print("%s: timed out", __func__);
	      break;
	    }
	}
    }

  /* close the file and move it to a completed directory */
  if(movedir_name != NULL && outfile != NULL)
    {
      if((fn = strdup(scamper_file_getfilename(outfile))) == NULL)
	goto done;
      scamper_file_close(outfile); outfile = NULL;
      if(movefile(fn) != 0)
	goto done;
    }

  rc = 0;

 done:
  if(fn != NULL) free(fn);
  return rc;
}

static void cleanup(void)
{
  int i;

  if(methods != NULL)
    {
      for(i=0; i<methodc; i++)
	if(methods[i] != NULL)
	  free(methods[i]);
      free(methods);
      methods = NULL;
    }

  if(method_stats != NULL)
    {
      for(i=0; i<methodc; i++)
	if(method_stats[i] != NULL)
	  sc_methstats_free(method_stats[i]);
      free(method_stats);
      method_stats = NULL;
    }

  if(virgin != NULL)
    {
      slist_free_cb(virgin, (slist_free_t)sc_pinger_free);
      virgin = NULL;
    }

  if(waiting != NULL)
    {
      slist_free_cb(waiting, (slist_free_t)sc_pinger_free);
      waiting = NULL;
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

  if(logfile_fd != NULL)
    {
      fclose(logfile_fd);
      logfile_fd = NULL;
    }

  if(addrfile_buf != NULL)
    {
      free(addrfile_buf);
      addrfile_buf = NULL;
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
      printf("sc_pinger version %s\n", PACKAGE_VERSION);
      return 0;
    }
#endif

  return pinger_data();
}
