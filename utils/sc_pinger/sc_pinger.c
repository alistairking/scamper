/*
 * sc_pinger : scamper driver to probe destinations with various ping
 *             methods
 *
 * $Id: sc_pinger.c,v 1.30 2024/04/26 06:52:24 mjl Exp $
 *
 * Copyright (C) 2020      The University of Waikato
 * Copyright (C) 2022-2023 Matthew Luckie
 * Copyright (C) 2023      The Regents of the University of California
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
#include "scamper_file.h"
#include "lib/libscamperctrl/libscamperctrl.h"
#include "mjl_list.h"
#include "utils.h"

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
static int                    probe_count   = 5;
static int                    reply_count   = 3;
static uint32_t               limit         = 0;
static uint32_t               outfile_u     = 0;
static uint32_t               outfile_c     = 0;
static slist_t               *virgin        = NULL;
static slist_t               *waiting       = NULL;
static char                 **methods       = NULL;
static int                    methodc       = 0;
static int                    error         = 0;

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

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
	  "usage: sc_pinger [-D?]\n"
	  "                 [-a infile] [-o outfile] [-p port] [-R unix]\n"
	  "                 [-U unix] [-c probec] [-l limit] [-m method]\n"
	  "                 [-M dir] [-t logfile]\n");

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

  if(opt_mask & OPT_COUNT)
    fprintf(stderr, "     -c [replyc]/probec\n");

  if(opt_mask & OPT_LIMIT)
    fprintf(stderr, "     -l limit on object count per output file\n");

  if(opt_mask & OPT_MOVE)
    fprintf(stderr, "     -m directory to move completed files to\n");

  if(opt_mask & OPT_LOG)
    fprintf(stderr, "     -t logfile\n");

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

static int parse_count(const char *opt)
{
  char *dup, *ptr;
  long lo_rc, lo_pc;
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
	 string_tolong(dup, &lo_rc) != 0 ||
	 string_tolong(ptr, &lo_pc) != 0 ||
	 lo_rc > lo_pc || lo_pc > 30 || lo_rc < 1 || lo_pc < 1)
	goto done;

      reply_count = lo_rc;
      probe_count = lo_pc;
    }
  else
    {
      if(string_isdigit(dup) == 0 ||
	 string_tolong(dup, &lo_pc) != 0)
	goto done;
      reply_count = lo_pc;
      probe_count = lo_pc;
    }
  rc = 0;

 done:
  if(dup != NULL) free(dup);
  return rc;
}

static int check_options(int argc, char *argv[])
{
  char *opt_count = NULL, *opt_port = NULL, *opt_limit = NULL;
  char *opts = "a:c:Dl:m:M:o:p:R:t:U:?", *ptr, *dup = NULL;
  struct stat sb;
  slist_t *list = NULL;
  long lo;
  int i, ch, rc = -1;

  if((list = slist_alloc()) == NULL)
    goto done;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case 'a':
	  addrfile_name = optarg;
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
	     slist_tail_push(list, dup) == NULL)
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

  if(opt_count != NULL && parse_count(opt_count) != 0)
    {
      usage(OPT_COUNT);
      goto done;
    }

  if((methodc = slist_count(list)) > 0)
    {
      if((methods = malloc_zero(sizeof(char *) * methodc)) == NULL)
	goto done;
      i = 0;
      while((ptr = slist_head_pop(list)) != NULL)
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
  if(list != NULL) slist_free_cb(list, free);
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

static void sc_pinger_free(sc_pinger_t *pinger)
{
  if(pinger->dst != NULL) scamper_addr_free(pinger->dst);
  free(pinger);
  return;
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
      memmove(addrfile_buf, addrfile_buf+start, end - start);
      addrfile_off = end - start;
    }

  return 0;

 err:
  close(addrfile_fd); addrfile_fd = -1;
  return -1;
}

static int do_method(void)
{
  char cmd[512], addr[128];
  sc_pinger_t *pinger;
  size_t off = 0;

  if(more < 1)
    return 0;

  if((pinger = slist_head_pop(waiting)) == NULL &&
     (pinger = slist_head_pop(virgin)) == NULL)
    {
      if(addrfile_fd == -1)
	return 0;
      if(do_addrfile() != 0)
	return -1;
      if((pinger = slist_head_pop(virgin)) == NULL)
	return 0;
    }

  scamper_addr_tostr(pinger->dst, addr, sizeof(addr));
  string_concat(cmd, sizeof(cmd), &off, "ping -c %d -o %d -P %s %s",
		probe_count, reply_count, methods[pinger->step], addr);

  /* got a command, send it */
  if(scamper_inst_do(scamper_inst, cmd, pinger) == NULL)
    {
      print("%s: could not send %s", __func__, cmd);
      return -1;
    }
  probing++;
  more--;

  print("p %d, c %d: %s", probing, completed, cmd);

  return 0;
}

static int process_pinger(sc_pinger_t *pinger, scamper_ping_t *ping)
{
  const scamper_ping_reply_t *reply;
  scamper_addr_t *dst, *r_addr;
  uint16_t i, ping_sent;
  char buf[128];
  int replyc = 0;

  probing--;

  if(ping != NULL)
    {
      ping_sent = scamper_ping_sent_get(ping);
      dst = scamper_ping_dst_get(ping);
      for(i=0; i<ping_sent; i++)
	{
	  if((reply = scamper_ping_reply_get(ping, i)) == NULL)
	    continue;
	  r_addr = scamper_ping_reply_addr_get(reply);
	  if(scamper_addr_cmp(dst, r_addr) != 0 &&
	     scamper_ping_reply_is_from_target(ping, reply) == 0)
	    continue;
	  replyc++;
	}
      scamper_ping_free(ping);

      /* successful ping, we're done */
      if(replyc >= reply_count)
	goto done;
    }

  /* try with the next method, if there is another method to try */
  if(++pinger->step < methodc)
    {
      if(slist_tail_push(waiting, pinger) == NULL)
	{
	  print("%s: could not try next method for %s", __func__,
		scamper_addr_tostr(pinger->dst, buf, sizeof(buf)));
	  return -1;
	}
      return 0;
    }

 done:
  completed++;
  print("%s: done %s", __func__,
	scamper_addr_tostr(pinger->dst, buf, sizeof(buf)));
  sc_pinger_free(pinger);
  return 0;
}

static void ctrlcb(scamper_inst_t *inst, uint8_t type, scamper_task_t *task,
		   const void *data, size_t len)
{
  sc_pinger_t *pinger;
  uint16_t obj_type;
  void *obj_data;

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

      if(obj_type != SCAMPER_FILE_OBJ_PING)
	{
	  print("%s: unknown object %d", __func__, obj_type);
	  goto err;
	}
      pinger = scamper_task_getparam(task);
      if(process_pinger(pinger, (scamper_ping_t *)obj_data) != 0)
	goto err;

      if(limit != 0 && ++outfile_c == limit && rotatefile() != 0)
	goto err;
    }
  else if(type == SCAMPER_CTRL_TYPE_ERR)
    {
      pinger = scamper_task_getparam(task);
      if(process_pinger(pinger, NULL) != 0)
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
      scamper_inst = scamper_inst_inet(scamper_ctrl, NULL, NULL, scamper_port);
    }
#ifdef HAVE_SOCKADDR_UN
  else if(scamper_unix != NULL)
    {
      if(options & OPT_UNIX)
	{
	  type = "unix";
	  scamper_inst = scamper_inst_unix(scamper_ctrl, NULL, scamper_unix);
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

static int pinger_data(void)
{
  uint16_t types[] = {SCAMPER_FILE_OBJ_CYCLE_START,
		      SCAMPER_FILE_OBJ_CYCLE_STOP,
		      SCAMPER_FILE_OBJ_PING};
  int typec = sizeof(types) / sizeof(uint16_t);
  int done = 0, rc = -1;
  char *fn = NULL;

#ifdef HAVE_DAEMON
  /* start a daemon if asked to */
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    {
      fprintf(stderr, "could not daemon\n");
      return -1;
    }
#endif

  assert(addrfile_name != NULL);

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

      scamper_ctrl_wait(scamper_ctrl, NULL);
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

  return pinger_data();
}
