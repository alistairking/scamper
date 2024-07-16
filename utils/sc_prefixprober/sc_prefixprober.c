/*
 * sc_prefixprober : scamper driver to probe addresses in specified
 *                   prefixes
 *
 * $Id: sc_prefixprober.c,v 1.38 2024/04/26 06:52:24 mjl Exp $
 *
 * Copyright (C) 2023 The Regents of the University of California
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
#include "trace/scamper_trace.h"
#include "tracelb/scamper_tracelb.h"
#include "scamper_file.h"
#include "lib/libscamperctrl/libscamperctrl.h"
#include "mjl_list.h"
#include "mjl_prefixtree.h"
#include "utils.h"

#define OPT_HELP     0x0001
#define OPT_INFILE   0x0002
#define OPT_OUTFILE  0x0004
#define OPT_PORT     0x0008
#define OPT_UNIX     0x0010
#define OPT_LOG      0x0020
#define OPT_OPTIONS  0x0040
#define OPT_CMD      0x0080
#define OPT_REMOTE   0x0100
#define OPT_DAEMON   0x0200
#define OPT_DURATION 0x0400
#define OPT_LIST     0x0800
#define OPT_MOVE     0x1000
#define OPT_LIMIT    0x2000
#define OPT_DNPFILE  0x4000

#define FLAG_FIRST     0x01
#define FLAG_RANDOM    0x02
#define FLAG_NOSHUFFLE 0x04

static uint32_t                options       = 0;
static uint8_t                 flags         = 0;
static unsigned int            scamper_port  = 0;
static char                   *scamper_unix  = NULL;
static scamper_ctrl_t         *scamper_ctrl  = NULL;
static scamper_inst_t         *scamper_inst  = NULL;
static scamper_attp_t         *scamper_attp  = NULL;
static char                   *infile_name   = NULL;
static char                   *dnpfile_name  = NULL;
static char                   *outfile_name  = NULL;
static char                   *outfile_type  = "warts";
static scamper_file_t         *outfile       = NULL;
static char                   *logfile_name  = NULL;
static FILE                   *logfile_fd    = NULL;
static char                   *scamper_cmd   = "trace";
static char                   *movedir_name  = NULL;
static uint16_t                scamper_cmd_t = SCAMPER_FILE_OBJ_TRACE;
static int                     error         = 0;
static int                     more          = 0;
static int                     probing       = 0;
static uint32_t                duration      = 0;
static uint32_t                limit         = 0;
static uint32_t                outfile_u     = 0;
static uint32_t                outfile_c     = 0;
static scamper_file_filter_t  *ffilter       = NULL;
static scamper_file_t         *decode_sf     = NULL;
static scamper_file_readbuf_t *decode_rb     = NULL;
static struct timeval          now;
static struct timeval          next; /* when we can probe next prefix */
static struct timeval          gap;  /* inter-prefix gap */
static slist_t                *prefix_list   = NULL;
static slist_t                *waiting       = NULL;
static struct in6_addr         one;

typedef struct sc_prefix
{
  uint8_t      v;     /* 4 or 6 */
  uint8_t      dnp;   /* 1: do not probe */
  union
  {
    prefix4_t *v4;
    prefix6_t *v6;
  } pfx;
  void        *ptr;
  slist_t     *addrs; /* list of addresses to probe */
} sc_prefix_t;

/*
 * sc_prefix_nest_t
 *
 * data structure to organise nested prefixes so that the gaps in
 * the prefixes can be found.
 */
typedef struct sc_prefix_nest
{
  sc_prefix_t      *pfx;
  prefixtree_t     *pt;
  slist_t          *list;
} sc_prefix_nest_t;

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
        "usage: sc_prefixprober [-D?]\n"
        "                       [-a infile] [-o outfile] [-p port] [-R unix]\n"
	"                       [-U unix] [-c cmd] [-d duration] [-l limit]\n"
	"                       [-L list] [-m dir] [-O options] [-t logfile]\n"
        "                       [-x dnpfile]\n"
        "\n");

  if(opt_mask == 0)
    {
      fprintf(stderr, "        sc_prefixprober -?\n\n");
      return;
    }

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "     -? an overview of the usage of sc_prefixprober\n");

  if(opt_mask & OPT_INFILE)
    fprintf(stderr, "     -a input prefixes\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "     -o output warts file\n");

  if(opt_mask & OPT_OPTIONS)
    {
      fprintf(stderr, "     -O options\n");
      fprintf(stderr, "        first: probe first address in prefix\n");
      fprintf(stderr, "        random: probe random address in prefix\n");
      fprintf(stderr, "        noshuffle: do not shuffle probe order\n");
#ifdef HAVE_ZLIB
      fprintf(stderr, "        warts.gz: compress warts output using gzip compression\n");
#endif
#ifdef HAVE_LIBBZ2
      fprintf(stderr, "        warts.bz2: compress warts output using bzip2 compression\n");
#endif
#ifdef HAVE_LIBLZMA
      fprintf(stderr, "        warts.xz: compress warts output using xz compression\n");
#endif
    }

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -p port to find scamper on\n");

  if(opt_mask & OPT_REMOTE)
    fprintf(stderr, "     -R find remote scamper process on unix socket\n");

  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "     -U find local scamper process on unix socket\n");

  if(opt_mask & OPT_DAEMON)
    fprintf(stderr, "     -D start as daemon\n");

  if(opt_mask & OPT_CMD)
    fprintf(stderr, "     -c command to use with each address\n");

  if(opt_mask & OPT_DURATION)
    fprintf(stderr, "     -d total duration allowed, for task spacing\n");

  if(opt_mask & OPT_LIMIT)
    fprintf(stderr, "     -l limit on object count per output file\n");

  if(opt_mask & OPT_LIST)
    fprintf(stderr, "     -L list parameters (id=%%u, name=%%s, monitor=%%s, descr=%%s, cycle-id=%%u)\n");

  if(opt_mask & OPT_MOVE)
    fprintf(stderr, "     -m directory to move completed files to\n");

  if(opt_mask & OPT_LOG)
    fprintf(stderr, "     -t logfile\n");

  if(opt_mask & OPT_DNPFILE)
    fprintf(stderr, "     -x prefixes to do-not-probe\n");

  return;
}

/*
 * check_printf
 *
 * ensure the filename has one format specifier, and it is for an
 * unsigned integer.  the digits can be zero padded, but its width
 * cannot otherwise be restricted.
 *
 * shared with sc_pinger, perhaps this should be in utils.c and more
 * generic.
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
      while(isdigit((unsigned char)*ptr) != 0)
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

static int check_options(int argc, char *argv[])
{
  char *opts = "a:c:d:Dl:L:m:o:O:p:R:t:U:x:?";
  char *opt_port = NULL, *opt_cmd = NULL, *opt_duration = NULL;
  char *opt_limit = NULL, *opt, *dup = NULL, *opt_outtype = NULL, *param;
  struct stat sb;
  slist_t *list = NULL;
  int ch, rc = -1;
  long long ll;
  long lo;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'a':
	  options |= OPT_INFILE;
	  infile_name = optarg;
	  break;

	case 'c':
	  options |= OPT_CMD;
	  opt_cmd = optarg;
	  break;

	case 'd':
	  options |= OPT_DURATION;
	  opt_duration = optarg;
	  break;

	case 'D':
	  options |= OPT_DAEMON;
	  break;

	case 'l':
	  options |= OPT_LIMIT;
	  opt_limit = optarg;
	  break;

	case 'L':
	  options |= OPT_LIST;
	  /* process list parameters outside of getopt loop */
	  if((list == NULL && (list = slist_alloc()) == NULL) ||
	     slist_tail_push(list, optarg) == NULL)
	    goto done;
	  break;

	case 'm':
	  options |= OPT_MOVE;
	  movedir_name = optarg;
	  break;

	case 'o':
	  options |= OPT_OUTFILE;
	  outfile_name = optarg;
	  break;

	case 'O':
	  if(strcasecmp(optarg, "first") == 0)
	    flags |= FLAG_FIRST;
	  else if(strcasecmp(optarg, "random") == 0)
	    flags |= FLAG_RANDOM;
	  else if(strcasecmp(optarg, "noshuffle") == 0)
	    flags |= FLAG_NOSHUFFLE;
	  else if(strcasecmp(optarg, "gz") == 0 ||
		  strcasecmp(optarg, "warts.gz") == 0)
	    opt_outtype = "warts.gz";
	  else if(strcasecmp(optarg, "bz2") == 0 ||
		  strcasecmp(optarg, "warts.bz2") == 0)
	    opt_outtype = "warts.bz2";
	  else if(strcasecmp(optarg, "xz") == 0 ||
		  strcasecmp(optarg, "warts.xz") == 0)
	    opt_outtype = "warts.xz";
	  else {
	    usage(OPT_OPTIONS);
	    return -1;
	  }
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
	  options |= OPT_LOG;
	  logfile_name = optarg;
	  break;

	case 'U':
	  options |= OPT_UNIX;
	  scamper_unix = optarg;
	  break;

	case 'x':
	  options |= OPT_DNPFILE;
	  dnpfile_name = optarg;
	  break;

	case '?':
	  default:
	  usage(0xffffffff);
	  goto done;
	}
    }

  if(infile_name == NULL || outfile_name == NULL ||
     countbits32(options & (OPT_PORT|OPT_UNIX|OPT_REMOTE)) != 1)
    {
      usage(OPT_INFILE | OPT_OUTFILE | OPT_UNIX | OPT_PORT | OPT_REMOTE);
      goto done;
    }

  if((opt_outtype != NULL && strcmp(opt_outtype, "warts.gz") == 0) ||
     string_endswith(outfile_name, ".gz") != 0)
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
  else if((opt_outtype != NULL && strcmp(opt_outtype, "warts.bz2") == 0) ||
	  string_endswith(outfile_name, ".bz2") != 0)
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
  else if((opt_outtype != NULL && strcmp(opt_outtype, "warts.xz") == 0) ||
	  string_endswith(outfile_name, ".xz") != 0)
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

  if(flags == 0)
    {
      usage(OPT_OPTIONS);
      goto done;
    }

  if(opt_cmd != NULL)
    {
      if(strncasecmp(opt_cmd, "tracelb", 7) == 0 &&
	 (opt_cmd[7] == ' ' || opt_cmd[7] == '\0'))
	{
	  scamper_cmd_t = SCAMPER_FILE_OBJ_TRACELB;
	}
      else if(strncasecmp(opt_cmd, "trace", 5) == 0 &&
	      (opt_cmd[5] == ' ' || opt_cmd[5] == '\0'))
	{
	  scamper_cmd_t = SCAMPER_FILE_OBJ_TRACE;
	}
      else if(strncasecmp(opt_cmd, "ping", 4) == 0 &&
	      (opt_cmd[4] == ' ' || opt_cmd[4] == '\0'))
	{
	  scamper_cmd_t = SCAMPER_FILE_OBJ_PING;
	}
      else
	{
	  usage(OPT_CMD);
	  goto done;
	}
      scamper_cmd = opt_cmd;
    }

  if(opt_duration != NULL)
    {
      if(string_isdigit(opt_duration) == 0 ||
	 string_tolong(opt_duration, &lo) != 0 || lo < 1)
	{
	  usage(OPT_DURATION);
	  goto done;
	}
      duration = (uint32_t)lo;
    }

  if(list != NULL)
    {
      if((scamper_attp = scamper_attp_alloc()) == NULL)
	{
	  usage(OPT_LIST);
	  goto done;
	}
      while((opt = slist_head_pop(list)) != NULL)
	{
	  if((dup = strdup(opt)) == NULL ||
	     string_nullterm_char(dup, '=', &param) == NULL ||
	     param == NULL)
	    goto done;
	  if(strcasecmp(dup, "id") == 0)
	    {
	      if(string_isdigit(param) == 0 ||
		 string_tollong(param, &ll, NULL, 0) != 0 || ll > UINT32_MAX)
		{
		  usage(OPT_LIST);
		  goto done;
		}
	      scamper_attp_set_listid(scamper_attp, (uint32_t)ll);
	    }
	  else if(strcasecmp(dup, "name") == 0)
	    {
	      if(scamper_attp_set_listname(scamper_attp, param) != 0)
		{
		  usage(OPT_LIST);
		  goto done;
		}
	    }
	  else if(strcasecmp(dup, "descr") == 0)
	    {
	      if(scamper_attp_set_listdescr(scamper_attp, param) != 0)
		{
		  usage(OPT_LIST);
		  goto done;
		}
	    }
	  else if(strcasecmp(dup, "monitor") == 0)
	    {
	      if(scamper_attp_set_listmonitor(scamper_attp, param) != 0)
		{
		  usage(OPT_LIST);
		  goto done;
		}
	    }
	  else if(strcasecmp(dup, "cycle-id") == 0)
	    {
	      if(string_isdigit(param) == 0 ||
		 string_tollong(param, &ll, NULL, 0) != 0 || ll > UINT32_MAX)
		{
		  usage(OPT_LIST);
		  goto done;
		}
	      scamper_attp_set_cycleid(scamper_attp, (uint32_t)ll);
	    }
	  else
	    {
	      usage(OPT_LIST);
	      goto done;
	    }
	  free(dup); dup = NULL;
	}
    }

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
      if((sb.st_mode & S_IFDIR) == 0)
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

  rc = 0;

 done:
  if(dup != NULL) free(dup);
  if(list != NULL) slist_free(list);
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

static void sc_prefix_free(sc_prefix_t *p)
{
  if(p->v == 4 && p->pfx.v4 != NULL)
    prefix4_free(p->pfx.v4);
  else if(p->v == 6 && p->pfx.v6 != NULL)
    prefix6_free(p->pfx.v6);
  if(p->addrs != NULL)
    slist_free_cb(p->addrs, (slist_free_t)scamper_addr_free);
  free(p);
  return;
}

static sc_prefix_t *sc_prefix_alloc(uint8_t ipv, void *net, uint8_t len,
				    uint8_t dnp)
{
  sc_prefix_t *p;

  if((p = malloc_zero(sizeof(sc_prefix_t))) == NULL)
    goto err;
  if(ipv == 4)
    {
      if(len > 32 || (p->pfx.v4 = prefix4_alloc(net, len, p)) == NULL)
	goto err;
    }
  else if(ipv == 6)
    {
      if(len > 128 || (p->pfx.v6 = prefix6_alloc(net, len, p)) == NULL)
	goto err;
    }
  else goto err;
  p->v = ipv;
  p->dnp = dnp;
  return p;

 err:
  sc_prefix_free(p);
  return NULL;
}

/*
 * sc_prefix_ins_cmp
 *
 * comparison function to order the prefixes for insertion:
 * - v4 before v6,
 * - less-specific prefixes before more-specific prefixes.
 * - dnp prefixes before non-dnp prefixes,
 */
static int sc_prefix_ins_cmp(const sc_prefix_t *a, const sc_prefix_t *b)
{
  uint8_t al, bl;
  if(a->v < b->v) return -1;
  if(a->v > b->v) return  1;
  if(a->v == 4) { al = a->pfx.v4->len; bl = b->pfx.v4->len; }
  else          { al = a->pfx.v6->len; bl = b->pfx.v6->len; }
  if(al < bl) return -1;
  if(al > bl) return  1;
  if(a->dnp > b->dnp) return -1;
  if(a->dnp < b->dnp) return  1;
  return 0;
}

static int sc_prefix_cmp(const sc_prefix_t *a, const sc_prefix_t *b)
{
  if(a->v < b->v) return -1;
  if(a->v > b->v) return  1;
  if(a->v == 4) return prefix4_cmp(a->pfx.v4, b->pfx.v4);
  return prefix6_cmp(a->pfx.v6, b->pfx.v6);
}

static char *sc_prefix_tostr(const sc_prefix_t *p, char *buf, size_t len)
{
  char tmp[128];
  if(p->v == 4)
    snprintf(buf, len, "%s/%d",
	     inet_ntop(AF_INET, &p->pfx.v4->net, tmp, sizeof(tmp)),
	     p->pfx.v4->len);
  else if(p->v == 6)
    snprintf(buf, len, "%s/%d",
	     inet_ntop(AF_INET6, &p->pfx.v6->net, tmp, sizeof(tmp)),
	     p->pfx.v6->len);
  else
    return NULL;
  return buf;
}

static void sc_prefix_nest_free(sc_prefix_nest_t *nest)
{
  if(nest == NULL)
    return;
  if(nest->list != NULL)
    slist_free_cb(nest->list, (slist_free_t)sc_prefix_nest_free);
  if(nest->pt != NULL)
    {
      if(nest->pfx->v == 4)
	prefixtree_free_cb(nest->pt, (prefix_free_t)prefix4_free);
      else
	prefixtree_free_cb(nest->pt, (prefix_free_t)prefix6_free);
    }
  free(nest);
  return;
}

static sc_prefix_nest_t *sc_prefix_nest_alloc(sc_prefix_t *pfx)
{
  sc_prefix_nest_t *nest;
  if((nest = malloc_zero(sizeof(sc_prefix_nest_t))) == NULL)
    return NULL;
  nest->pfx = pfx;
  return nest;
}

static int sc_prefix_nest_cmp(const sc_prefix_nest_t *a,
			      const sc_prefix_nest_t *b)
{
  return sc_prefix_cmp(a->pfx, b->pfx);
}

static int sc_prefix_add(slist_t *list, char *str, uint8_t dnp,
			 const char *filename, int line)
{
  struct addrinfo hints, *res, *res0;
  sc_prefix_t *p;
  char *pf;
  void *va;
  long lo;

  if(str[0] == '#' || str[0] == '\0')
    return 0;

  string_nullterm_char(str, '/', &pf);
  if(pf == NULL)
    {
      print("%s: expected / on line %d of %s", __func__, line, filename);
      return -1;
    }
  if(string_isdigit(pf) == 0 || string_tolong(pf, &lo) != 0 || lo < 1)
    {
      print("%s: expected number > 0 after / on line %d of %s",
	    __func__, line, filename);
      return -1;
    }

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags    = AI_NUMERICHOST;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_family   = AF_UNSPEC;

  if(getaddrinfo(str, NULL, &hints, &res0) != 0 || res0 == NULL)
    {
      print("%s: invalid network address on line %d of %s",
	    __func__, line, filename);
      return -1;
    }

  for(res = res0; res != NULL; res = res->ai_next)
    {
      if(res->ai_family == PF_INET)
	{
	  va = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
	  if(prefix4_isvalid(va, lo) == 0)
	    {
	      print("%s: invalid IPv4 prefix on line %d of %s",
		    __func__, line, filename);
	      return -1;
	    }
	  if((p = sc_prefix_alloc(4, va, lo, dnp)) == NULL ||
	     slist_tail_push(list, p) == NULL)
	    {
	      if(p != NULL) sc_prefix_free(p);
	      print("%s: could not store IPv4 prefix on line %d of %s",
		    __func__, line, filename);
	      return -1;
	    }
	  break;
	}
      else if(res->ai_family == PF_INET6)
	{
	  va = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
	  if(prefix6_isvalid(va, lo) == 0)
	    {
	      print("%s: invalid IPv6 prefix on line %d of %s",
		    __func__, line, filename);
	      return -1;
	    }
	  if((p = sc_prefix_alloc(6, va, lo, dnp)) == NULL ||
	     slist_tail_push(list, p) == NULL)
	    {
	      if(p != NULL) sc_prefix_free(p);
	      print("%s: could not store IPv6 prefix on line %d of %s",
		    __func__, line, filename);
	      return -1;
	    }
	  break;
	}
    }
  freeaddrinfo(res0);

  return 0;
}

static int infile_line(char *str, void *param)
{
  static int line = 0;
  line++;
  return sc_prefix_add((slist_t *)param, str, 0, infile_name, line);
}

static int dnpfile_line(char *str, void *param)
{
  static int line = 0;
  line++;
  return sc_prefix_add((slist_t *)param, str, 1, dnpfile_name, line);
}

/*
 * rec_target_4_addrs
 *
 *
 */
static int rec_target_4_addrs(sc_prefix_t *p,
			      const struct in_addr *x, const struct in_addr *y)
{
  scamper_addr_t *sa = NULL;
  struct in_addr in;
  uint32_t u32, range;
  int rc = -1;

  assert(ntohl(y->s_addr) >= ntohl(x->s_addr));

  assert(p->addrs == NULL);
  if((p->addrs = slist_alloc()) == NULL)
    {
      print("%s: could not alloc addrs list", __func__);
      goto done;
    }

  /* if we have a /32, then we can only probe that address */
  if(x->s_addr == y->s_addr)
    {
      if((sa = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4, x)) == NULL ||
	 slist_tail_push(p->addrs, sa) == NULL)
	{
	  print("%s: could not add /32 to list", __func__);
	  goto done;
	}
      sa = NULL;
      rc = 0;
      goto done;
    }

  range = ntohl(y->s_addr) - ntohl(x->s_addr) + 1;

  if(flags & FLAG_FIRST)
    {
      /* the first address for a /31 (range == 2) is host = 0 */
      if(range > 2)
	in.s_addr = htonl(ntohl(x->s_addr) + 1);
      else
	in.s_addr = x->s_addr;
      if((sa = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4, &in)) == NULL ||
	 slist_tail_push(p->addrs, sa) == NULL)
	{
	  print("%s: could not add first addr in prefix to list", __func__);
	  goto done;
	}
      sa = NULL;
    }

  if(flags & FLAG_RANDOM)
    {
      if(random_u32(&u32) != 0)
	{
	  print("%s: could not generate random value", __func__);
	  goto done;
	}

      /*
       * the only random address for a /31 (range == 2) is host = 1 if
       * we have also already probed the first (host == 0) address
       */
      if(range == 2)
	{
	  if((flags & FLAG_FIRST) != 0)
	    u32 = 1;
	  else
	    u32 = u32 % range;
	}
      else
	{
	  /*
	   * do not randomly pick the first address if we are already
	   * going to be probing the first address
	   */
	  if((flags & FLAG_FIRST) != 0)
	    u32 = 2 + (u32 % (range - 3));
	  else
	    u32 = 1 + (u32 % (range - 2));
	}
      in.s_addr = htonl(ntohl(x->s_addr) + u32);
      if((sa = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV4, &in)) == NULL ||
	 slist_tail_push(p->addrs, sa) == NULL)
	{
	  print("%s: could not add random address to list", __func__);
	  goto done;
	}
      sa = NULL;
    }

  /* do not shuffle addresses within an IPv4 prefix if told not to shuffle */
  if((flags & FLAG_NOSHUFFLE) == 0)
    slist_shuffle(p->addrs);
  rc = 0;

 done:
  if(sa != NULL) scamper_addr_free(sa);
  return rc;
}

static int rec_target_4(sc_prefix_nest_t *nest)
{
  static const uint32_t add[] = {
    4294967295, 2147483647, 1073741823, 536870911, 268435455, 134217727,
    67108863, 33554431, 16777215, 8388607, 4194303, 2097151, 1048575, 524287,
    262143, 131071, 65535, 32767, 16383, 8191, 4095, 2047, 1023, 511, 255,
    127, 63, 31, 15, 7, 3, 1, 0
  };
  struct in_addr first, last;
  sc_prefix_nest_t *nest2;
  slist_node_t *sn;
  uint32_t x, y, f = ntohl(nest->pfx->pfx.v4->net.s_addr);

  /* if there are no nested prefixes, pick addresses in the whole prefix */
  if(nest->list == NULL)
    {
      last.s_addr = htonl(f + (add[nest->pfx->pfx.v4->len]));
      if(rec_target_4_addrs(nest->pfx, &nest->pfx->pfx.v4->net, &last) != 0)
	return -1;
      return 1;
    }

  /* find addresses in the prefix not covered by a more specific */
  x = f; slist_qsort(nest->list, (slist_cmp_t)sc_prefix_nest_cmp);
  for(sn = slist_head_node(nest->list); sn != NULL; sn = slist_node_next(sn))
    {
      nest2 = slist_node_item(sn);
      y = ntohl(nest2->pfx->pfx.v4->net.s_addr);
      if(y != x)
	{
	  first.s_addr = htonl(x);
	  last.s_addr = htonl(ntohl(nest2->pfx->pfx.v4->net.s_addr)-1);
	  if(rec_target_4_addrs(nest->pfx, &first, &last) != 0)
	    return -1;
	  return 1;
	}
      x += add[nest2->pfx->pfx.v4->len] + 1;
    }

  /* if there is uncovered space at the top of the prefix then use that */
  if(sn == NULL && x < f + add[nest->pfx->pfx.v4->len] + 1)
    {
      first.s_addr = htonl(x);
      last.s_addr = htonl(f + add[nest->pfx->pfx.v4->len]);
      if(rec_target_4_addrs(nest->pfx, &first, &last) != 0)
	return -1;
      return 1;
    }

  return 0;
}

static int rec_target_6_addrs(sc_prefix_t *p, const struct in6_addr *x,
			      const struct in6_addr *y)
{
  scamper_addr_t *sa = NULL;
  struct in6_addr in, range, r;
  uint32_t u32, v;
  int i, rc = -1;

  assert(addr6_human_cmp(y, x) >= 0);

  if((p->addrs = slist_alloc()) == NULL)
    {
      print("%s: could not alloc addrs list", __func__);
      goto done;
    }

  /* if we have a /128, then we can only probe that address */
  if(memcmp(x, y, sizeof(struct in6_addr)) == 0)
    {
      if((sa = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV6, x)) == NULL ||
	 slist_tail_push(p->addrs, sa) == NULL)
	{
	  print("%s: could not add /128 to list", __func__);
	  goto done;
	}
      sa = NULL;
      rc = 0;
      goto done;
    }

  if(flags & FLAG_FIRST)
    {
      memcpy(&in, x, sizeof(in));
      in.s6_addr[15] |= 1;
      if((sa = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV6, &in)) == NULL ||
	 slist_tail_push(p->addrs, sa) == NULL)
	{
	  print("%s: could not add first addr in prefix to list", __func__);
	  goto done;
	}
      sa = NULL;
    }

  if(flags & FLAG_RANDOM)
    {
      /* figure out the range of the random value*/
      addr6_sub(&range, y, x);

      /* generate a random value (r) that fits within the range */
      for(i=0; i<4; i++)
	{
	  v = ntohl(range.s6_addr32[i]);
	  if(v == 0)
	    {
	      r.s6_addr32[i] = 0;
	      continue;
	    }
	  if(random_u32(&u32) != 0)
	    {
	      print("%s: could not generate random value", __func__);
	      goto done;
	    }
	  r.s6_addr32[i] = htonl(u32 % v);
	  break;
	}
      i++;
      while(i<4)
	{
	  if(random_u32(&u32) != 0)
	    {
	      print("%s: could not generate random value", __func__);
	      goto done;
	    }
	  r.s6_addr32[i] = u32;
	  i++;
	}

      /* add the random value to the base value and construct an address */
      addr6_add(&in, x, &r);
      if((sa = scamper_addr_alloc(SCAMPER_ADDR_TYPE_IPV6, &in)) == NULL ||
	 slist_tail_push(p->addrs, sa) == NULL)
	{
	  print("%s: could not add random address to list", __func__);
	  goto done;
	}
      sa = NULL;
    }

  /* do not shuffle addresses within an IPv6 prefix if told not to shuffle */
  if((flags & FLAG_NOSHUFFLE) == 0)
    slist_shuffle(p->addrs);
  rc = 0;

 done:
  if(sa != NULL) scamper_addr_free(sa);
  return rc;
}

static int rec_target_6(sc_prefix_nest_t *nest)
{
  struct in6_addr last, f, x;
  sc_prefix_nest_t *nest2;
  slist_node_t *sn;

  /* if there are no nested prefixes, pick addresses in the whole prefix */
  if(nest->list == NULL)
    {
      memcpy(&last, &nest->pfx->pfx.v6->net, sizeof(struct in6_addr));
      if(addr6_add_netlen(&last, nest->pfx->pfx.v6->len) != 0)
	return -1;
      addr6_sub(&last, &last, &one);
      if(rec_target_6_addrs(nest->pfx, &nest->pfx->pfx.v6->net, &last) != 0)
	return -1;
      return 1;
    }

  /* find address in the prefix not covered by a more specific */
  memcpy(&x, &nest->pfx->pfx.v6->net, sizeof(struct in6_addr));
  slist_qsort(nest->list, (slist_cmp_t)sc_prefix_nest_cmp);
  for(sn = slist_head_node(nest->list); sn != NULL; sn = slist_node_next(sn))
    {
      nest2 = slist_node_item(sn);
      if(memcmp(&x, &nest2->pfx->pfx.v6->net, sizeof(struct in6_addr)) != 0)
	{
	  addr6_sub(&last, &nest2->pfx->pfx.v6->net, &one);
	  if(rec_target_6_addrs(nest->pfx, &x, &last) != 0)
	    return -1;
	  return 1;
	}
      if(addr6_add_netlen(&x, nest2->pfx->pfx.v6->len) != 0)
	return -1;
    }

  /* if there is uncovered space at the top of the prefix then use that */
  memcpy(&f, &nest->pfx->pfx.v6->net, sizeof(struct in6_addr));
  if(addr6_add_netlen(&f, nest->pfx->pfx.v6->len) != 0)
    return -1;
  if(sn == NULL && addr6_human_cmp(&x, &f) < 0)
    {
      addr6_sub(&last, &f, &one);
      if(rec_target_6_addrs(nest->pfx, &x, &last) != 0)
	return -1;
      return 1;
    }

  return 0;
}

static int do_targets_rec(slist_t *list)
{
  sc_prefix_nest_t *nest;
  slist_node_t *sn;

  for(sn = slist_head_node(list); sn != NULL; sn = slist_node_next(sn))
    {
      nest = slist_node_item(sn);
      if(nest->pfx->dnp != 0)
	continue;
      if((nest->pfx->v == 4 && rec_target_4(nest) < 0) ||
	 (nest->pfx->v == 6 && rec_target_6(nest) < 0) ||
	 (nest->list != NULL && do_targets_rec(nest->list) != 0))
	return -1;
    }

  return 0;
}

static int pp_targets(slist_t *list)
{
  prefixtree_t *pt4 = NULL, *pt6 = NULL;
  slist_node_t *sn;
  sc_prefix_t *p;
  prefix4_t *p4;
  prefix6_t *p6;
  slist_t *root = NULL;
  sc_prefix_nest_t *nest;
  int af, rc = -1;

  if((pt4 = prefixtree_alloc(AF_INET)) == NULL ||
     (pt6 = prefixtree_alloc(AF_INET6)) == NULL ||
     (root = slist_alloc()) == NULL)
    {
      print("%s: could not alloc data structures", __func__);
      goto done;
    }

  slist_qsort(list, (slist_cmp_t)sc_prefix_ins_cmp);
  for(sn = slist_head_node(list); sn != NULL; sn = slist_node_next(sn))
    {
      p = slist_node_item(sn);
      p4 = NULL; p6 = NULL;

      if(p->v == 4)
	{
	  /* if there is no enclosing prefix, this is a root prefix */
	  if((p4 = prefixtree_find_best4(pt4, p->pfx.v4)) == NULL)
	    {
	      if((p4 = prefix4_dup(p->pfx.v4)) == NULL ||
		 prefixtree_insert4(pt4, p4) == NULL ||
		 (p4->ptr = sc_prefix_nest_alloc(p)) == NULL ||
		 slist_tail_push(root, p4->ptr) == NULL)
		{
		  print("%s: could not add root IPv4 prefix", __func__);
		  goto done;
		}
	      continue;
	    }
	  else if(prefix4_cmp(p->pfx.v4, p4) == 0)
	    continue; /* duplicate of an existing prefix */

	  /* otherwise, need to keep looking down the tree */
	  nest = p4->ptr;
	  af = AF_INET;
	}
      else
	{
	  /* if there is no enclosing prefix, this is a root prefix */
	  if((p6 = prefixtree_find_best6(pt6, p->pfx.v6)) == NULL)
	    {
	      if((p6 = prefix6_dup(p->pfx.v6)) == NULL ||
		 prefixtree_insert6(pt6, p6) == NULL ||
		 (p6->ptr = sc_prefix_nest_alloc(p)) == NULL ||
		 slist_tail_push(root, p6->ptr) == NULL)
		{
		  print("%s: could not add root IPv6 prefix", __func__);
		  goto done;
		}
	      continue;
	    }
	  else if(prefix6_cmp(p->pfx.v6, p6) == 0)
	    continue; /* duplicate of an existing prefix */

	  /* otherwise, need to keep looking down the tree */
	  nest = p6->ptr;
	  af = AF_INET6;
	}

      /* go through all nested prefixes until we get to the last one */
      while(nest != NULL)
	{
	  /* create a prefixtree as needed */
	  if(nest->pt == NULL)
	    {
	      if((nest->pt = prefixtree_alloc(af)) == NULL ||
		 (nest->list = slist_alloc()) == NULL)
		{
		  print("%s: could not alloc prefixtree", __func__);
		  goto done;
		}
	    }

	  if(af == AF_INET)
	    {
	      if((p4 = prefixtree_find_best4(nest->pt, p->pfx.v4)) == NULL ||
		 prefix4_cmp(p->pfx.v4, p4) == 0)
		break;
	      nest = p4->ptr;
	    }
	  else
	    {
	      if((p6 = prefixtree_find_best6(nest->pt, p->pfx.v6)) == NULL ||
		 prefix6_cmp(p->pfx.v6, p6) == 0)
		break;
	      nest = p6->ptr;
	    }
	}

      if(af == AF_INET && p4 == NULL) /* p4 == NULL means not dup pref */
	{
	  if((p4 = prefix4_dup(p->pfx.v4)) == NULL ||
	     prefixtree_insert4(nest->pt, p4) == NULL ||
	     (p4->ptr = sc_prefix_nest_alloc(p)) == NULL ||
	     slist_tail_push(nest->list, p4->ptr) == NULL)
	    {
	      print("%s: could not add nested IPv4 prefix", __func__);
	      goto done;
	    }
	}
      else if(af == AF_INET6 && p6 == NULL) /* p6 == NULL means not dup pref */
	{
	  if((p6 = prefix6_dup(p->pfx.v6)) == NULL ||
	     prefixtree_insert6(nest->pt, p6) == NULL ||
	     (p6->ptr = sc_prefix_nest_alloc(p)) == NULL ||
	     slist_tail_push(nest->list, p6->ptr) == NULL)
	    {
	      print("%s: could not add nested IPv6 prefix", __func__);
	      goto done;
	    }
	}
    }

  if(do_targets_rec(root) != 0)
    goto done;
  rc = 0;

 done:
  while((nest = slist_head_pop(root)) != NULL)
    sc_prefix_nest_free(nest);
  slist_free(root);
  prefixtree_free_cb(pt4, (prefix_free_t)prefix4_free);
  prefixtree_free_cb(pt6, (prefix_free_t)prefix6_free);
  return rc;
}

static int do_method(void)
{
  char cmd[512], buf[192];
  size_t off = 0;
  scamper_addr_t *sa;
  sc_prefix_t *prefix;

  if(more < 1)
    return 0;

  /*
   * we can always probe a prefix that has already had another address
   * probed immediately.  if the user set a duration, then we can only
   * introduce new prefixes into the system at a defined interval.
   */
  if((prefix = slist_head_pop(waiting)) == NULL)
    {
      if(duration != 0)
	{
	  if(timeval_cmp(&next, &now) <= 0)
	    timeval_add_tv(&next, &gap);
	  else
	    return 0;
	}
      if((prefix = slist_head_pop(prefix_list)) == NULL)
	return 0;
    }

  sa = slist_head_pop(prefix->addrs);
  scamper_addr_tostr(sa, buf, sizeof(buf));
  scamper_addr_free(sa);

  string_concat(cmd, sizeof(cmd), &off, "%s %s", scamper_cmd, buf);
  if(scamper_inst_do(scamper_inst, cmd, prefix) == NULL)
    {
      print("%s: could not send %s", __func__, cmd);
      return -1;
    }
  more--;
  probing++;

  print("p %d, w %d, v %d: %s %s", probing,
	slist_count(waiting), slist_count(prefix_list),
	sc_prefix_tostr(prefix, buf, sizeof(buf)), cmd);

  return 0;
}

static int process(sc_prefix_t *pfx)
{
  char buf[192];
  int rc;

  if(slist_count(pfx->addrs) > 0)
    {
      if(slist_tail_push(waiting, pfx) != NULL)
	return 0;
      print("%s: could not put prefix on wait list", __func__);
      rc = -1;
    }
  else
    {
      print("p %d, w %d, v %d: %s done", probing,
	    slist_count(waiting), slist_count(prefix_list),
	    sc_prefix_tostr(pfx, buf, sizeof(buf)));
      rc = 0;
    }

  sc_prefix_free(pfx);
  return rc;
}

static void ctrlcb(scamper_inst_t *inst, uint8_t type, scamper_task_t *task,
		   const void *data, size_t len)
{
  scamper_ping_t *ping = NULL;
  scamper_trace_t *trace = NULL;
  scamper_tracelb_t *tracelb = NULL;
  sc_prefix_t *pfx;
  uint16_t obj_type;
  void *obj_data;
  char pfx_str[192], addr_str[128], cmd_str[512];

  if(type == SCAMPER_CTRL_TYPE_MORE)
    {
      more++;
      /* only need to know the time if -d was used */
      if(duration != 0)
	gettimeofday_wrap(&now);
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

      probing--;

      if(obj_type == SCAMPER_FILE_OBJ_PING)
	{
	  ping = (scamper_ping_t *)obj_data;
	  scamper_addr_tostr(scamper_ping_dst_get(ping),
			     addr_str, sizeof(addr_str));
	  scamper_ping_free(ping);
	}
      else if(obj_type == SCAMPER_FILE_OBJ_TRACE)
	{
	  trace = (scamper_trace_t *)obj_data;
	  scamper_addr_tostr(scamper_trace_dst_get(trace),
			     addr_str, sizeof(addr_str));
	  scamper_trace_free(trace);
	}
      else if(obj_type == SCAMPER_FILE_OBJ_TRACELB)
	{
	  tracelb = (scamper_tracelb_t *)obj_data;
	  scamper_addr_tostr(scamper_tracelb_dst_get(tracelb),
			     addr_str, sizeof(addr_str));
	  scamper_tracelb_free(tracelb);
	}
      else
	{
	  print("%s: unknown object type %d", __func__, obj_type);
	  goto err;
	}

      pfx = scamper_task_getparam(task);
      print("p %d, w %d, v %d: %s done %s", probing,
	    slist_count(waiting), slist_count(prefix_list),
	    sc_prefix_tostr(pfx, pfx_str, sizeof(pfx_str)), addr_str);
      if(process(pfx) != 0)
	goto err;

      if(limit != 0 && ++outfile_c == limit && rotatefile() != 0)
	goto err;
    }
  else if(type == SCAMPER_CTRL_TYPE_ERR)
    {
      probing--;
      pfx = scamper_task_getparam(task);
      print("p %d, w %d, v %d: %s err %s", probing,
	    slist_count(waiting), slist_count(prefix_list),
	    sc_prefix_tostr(pfx, pfx_str, sizeof(pfx_str)),
	    scamper_task_getcmd(task, cmd_str, sizeof(cmd_str)));
      if(process(pfx) != 0)
	goto err;
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
      print("%s: could not alloc scamper_ctrl", __func__);
      return -1;
    }

  if(scamper_port != 0)
    {
      type = "port";
      scamper_inst = scamper_inst_inet(scamper_ctrl,
				       scamper_attp, NULL, scamper_port);
    }
#ifdef HAVE_SOCKADDR_UN
  else if(scamper_unix != NULL)
    {
      if(options & OPT_UNIX)
	{
	  type = "unix";
	  scamper_inst = scamper_inst_unix(scamper_ctrl,
					   scamper_attp, scamper_unix);
	}
      else if(options & OPT_REMOTE)
	{
	  type = "remote";
	  scamper_inst = scamper_inst_remote(scamper_ctrl, scamper_unix);
	}
    }
#endif

  if(scamper_inst == NULL)
    {
      print("%s: could not alloc %s inst: %s", __func__, type,
	    scamper_ctrl_strerror(scamper_ctrl));
      return -1;
    }

  return 0;
}

static int pp_data(void)
{
  uint16_t types[] = {
    SCAMPER_FILE_OBJ_CYCLE_START,
    SCAMPER_FILE_OBJ_CYCLE_STOP,
    scamper_cmd_t};
  int typec = sizeof(types) / sizeof(uint16_t);
  struct timeval tv, *tv_ptr;
  sc_prefix_t *p;
  slist_t *list;
  char *fn = NULL;
  int done = 0, rc = -1;
  uint32_t u32;

#ifdef HAVE_DAEMON
  /* start a daemon if asked to */
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    {
      fprintf(stderr, "could not daemon\n");
      return -1;
    }
#endif

  random_seed();

  if((logfile_name != NULL && (logfile_fd=fopen(logfile_name, "w")) == NULL))
    {
      fprintf(stderr, "%s: could not open logfile: %s\n",
	      __func__, strerror(errno));
      goto done;
    }
  if((list = slist_alloc()) == NULL || (prefix_list = slist_alloc()) == NULL ||
     (ffilter = scamper_file_filter_alloc(types, typec)) == NULL ||
     (waiting = slist_alloc()) == NULL ||
     (decode_sf = scamper_file_opennull('r', "warts")) == NULL ||
     (decode_rb = scamper_file_readbuf_alloc()) == NULL)
    {
      print("%s: could not alloc data structures", __func__);
      goto done;
    }
  scamper_file_setreadfunc(decode_sf, decode_rb, scamper_file_readbuf_read);

  if(file_lines(infile_name, infile_line, list) != 0)
    {
      print("%s: could not read %s", __func__, infile_name);
      goto done;
    }
  if(dnpfile_name != NULL && file_lines(dnpfile_name, dnpfile_line, list) != 0)
    {
      print("%s: could not read %s", __func__, dnpfile_name);
      goto done;
    }

  /* figure out addresses to probe within each prefix */
  if(pp_targets(list) != 0)
    goto done;
  while((p = slist_head_pop(list)) != NULL)
    {
      if(p->addrs == NULL || slist_count(p->addrs) < 1)
	{
	  sc_prefix_free(p);
	  continue;
	}
      if(slist_tail_push(prefix_list, p) == NULL)
	{
	  print("%s: could not put put prefix on probe list", __func__);
	  sc_prefix_free(p);
	  goto done;
	}
    }
  if(slist_count(prefix_list) < 1)
    {
      print("%s: nothing to probe", __func__);
      goto done;
    }
  slist_free(list); list = NULL;

  /* do not shuffle probe order if told not to shuffle */
  if((flags & FLAG_NOSHUFFLE) == 0)
    slist_shuffle(prefix_list);

  /* connect to the scamper process */
  if(do_scamperconnect() != 0)
    goto done;

  if(openfile() != 0)
    goto done;

  if(duration != 0)
    {
      /* work out the inter-prefix gap */
      memset(&gap, 0, sizeof(gap));
      u32 = (duration * 1000) / (uint64_t)slist_count(prefix_list);
      if(u32 == 0)
	u32 = 1;
      timeval_add_ms(&gap, &gap, u32);

      /* start probing straight away */
      gettimeofday_wrap(&now);
      timeval_cpy(&next, &now);

      print("%s: inter-prefix gap %ld.%06d", __func__,
	    (long int)gap.tv_sec, (int)gap.tv_usec);
    }

  while(error == 0 && scamper_ctrl_isdone(scamper_ctrl) == 0)
    {
      tv_ptr = NULL;
      if(more > 0)
	{
	  /* only need to know the time if -d was used */
	  if(duration != 0)
	    gettimeofday_wrap(&now);

	  /* if there is something we can probe right now, then probe it */
	  if(slist_count(waiting) > 0 ||
	     (slist_count(prefix_list) > 0 &&
	      (duration == 0 || timeval_cmp(&next, &now) <= 0)))
	    {
	      if(do_method() != 0)
		{
		  error = 1;
		  break;
		}
	    }

	  /* if scamper still wants work, set an appropriate timeout */
	  if(more > 0 && duration != 0 &&
	     (slist_count(waiting) > 0 || slist_count(prefix_list) > 0))
	    {
	      tv_ptr = &tv;
	      if(slist_count(waiting) == 0 && timeval_cmp(&next, &now) > 0)
		timeval_diff_tv(&tv, &now, &next);
	      else
		memset(&tv, 0, sizeof(tv));
	    }
	}

      if(probing == 0 && slist_count(prefix_list) == 0 &&
	 slist_count(waiting) == 0 && done == 0)
	{
	  print("%s: done", __func__);
	  scamper_inst_done(scamper_inst);
	  done = 1;
	}

      if(scamper_ctrl_wait(scamper_ctrl, tv_ptr) != 0)
	{
	  print("%s: %s", __func__, scamper_ctrl_strerror(scamper_ctrl));
	  error = 1;
	  break;
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

  if(error == 0)
    rc = 0;

 done:
  if(fn != NULL) free(fn);
  return rc;
}

static void cleanup(void)
{
  if(prefix_list != NULL)
    {
      slist_free_cb(prefix_list, (slist_free_t)sc_prefix_free);
      prefix_list = NULL;
    }

  if(waiting != NULL)
    {
      slist_free_cb(waiting, (slist_free_t)sc_prefix_free);
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

  if(scamper_attp != NULL)
    {
      scamper_attp_free(scamper_attp);
      scamper_attp = NULL;
    }

  return;
}

int main(int argc, char *argv[])
{
#if defined(DMALLOC)
  free(malloc(1));
#endif

  /* we use this variable in many places */
  memset(&one, 0, sizeof(one));
  one.s6_addr[15] = 1;

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    return -1;

  return pp_data();
}
