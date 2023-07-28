/*
 * sc_pinger : scamper driver to probe destinations with various ping
 *             methods
 *
 * $Id: sc_pinger.c,v 1.15 2023/03/22 01:38:57 mjl Exp $
 *
 * Copyright (C) 2020 The University of Waikato
 * Copyright (C) 2022 Matthew Luckie
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
#include "scamper_file.h"
#include "lib/libscamperctrl/libscamperctrl.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"
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
static char                  *logfile_name  = NULL;
static FILE                  *logfile_fd    = NULL;
static scamper_file_filter_t *ffilter       = NULL;
static int                    scamper_port  = 0;
static char                  *scamper_unix  = NULL;
static scamper_ctrl_t        *scamper_ctrl  = NULL;
static scamper_inst_t        *scamper_inst  = NULL;
static scamper_file_t        *decode_sf     = NULL;
static scamper_file_readbuf_t *decode_rb    = NULL;
static int                    more          = 0;
static int                    completed     = 0;
static int                    probe_count   = 5;
static int                    reply_count   = 3;
static splaytree_t           *tree          = NULL;
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
#define OPT_TEXT        0x0020
#define OPT_DAEMON      0x0040
#define OPT_COUNT       0x0080
#define OPT_REMOTE      0x0100

/*
 * sc_pingtest
 *
 * keep state about which method we are up to
 */
typedef struct sc_pinger
{
  scamper_addr_t   *dst;
  int               step;
  splaytree_node_t *node;
} sc_pinger_t;

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
	  "usage: sc_pinger [-D?]\n"
	  "                 [-a infile] [-o outfile] [-p port] [-R unix]\n"
	  "                 [-U unix] [-c probec] [-m method] [-t logfile]\n");

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

  if(opt_mask & OPT_TEXT)
    fprintf(stderr, "     -t logfile\n");

  return;
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
  char *opt_count = NULL, *opt_port = NULL;
  char *opts = "a:c:Dm:o:p:R:t:U:?", *ptr, *dup = NULL;
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

	case 'm':
	  if((dup = strdup(optarg)) == NULL ||
	     slist_tail_push(list, dup) == NULL)
	    goto done;
	  dup = NULL;
	  break;

	case 'o':
	  outfile_name = optarg;
	  break;

	case 'p':
	  options |= OPT_PORT;
	  opt_port = optarg;
	  break;

	case 't':
	  logfile_name = optarg;
	  break;

	case 'R':
	  options |= OPT_REMOTE;
	  scamper_unix = optarg;
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
    printf("%ld: %s", (long int)tv.tv_sec, msg);

  if(logfile_fd != NULL)
    {
      fprintf(logfile_fd, "%ld: %s", (long int)tv.tv_sec, msg);
      fflush(logfile_fd);
    }

  return;
}

static int sc_pinger_cmp(const sc_pinger_t *a, const sc_pinger_t *b)
{
  return scamper_addr_cmp(a->dst, b->dst);
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

  if((sa = scamper_addr_resolve(AF_UNSPEC, buf)) == NULL)
    {
      print("could not resolve %s on line %d\n", buf, line);
      goto err;
    }

  if((pinger = malloc_zero(sizeof(sc_pinger_t))) == NULL)
    {
      print("could not malloc pinger\n");
      goto err;
    }
  pinger->dst = sa; sa = NULL;
  if(slist_tail_push(virgin, pinger) == NULL)
    {
      print("could not push %s onto list\n", buf);
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
	  print("%s: could not realloc %d bytes\n", __func__,
		(int)addrfile_len);
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

  if((pinger->node = splaytree_insert(tree, pinger)) == NULL)
    {
      print("%s: could not add %s to tree\n", __func__, addr);
      return -1;
    }

  /* got a command, send it */
  if(scamper_inst_do(scamper_inst, cmd) == NULL)
    {
      print("%s: could not send %s\n", __func__, cmd);
      return -1;
    }
  more--;

  print("p %d, c %d: %s\n", splaytree_count(tree), completed, cmd);

  return 0;
}

static int do_decoderead_ping(scamper_ping_t *ping)
{
  scamper_ping_reply_t *reply;
  sc_pinger_t     fm, *pinger;
  char            buf[128];
  int             rc = -1;
  int             i, replyc = 0;

  scamper_addr_tostr(ping->dst, buf, sizeof(buf));
  fm.dst = ping->dst;
  if((pinger = splaytree_find(tree, &fm)) == NULL)
    {
      print("%s: could not find dst %s\n", __func__, buf);
      goto done;
    }
  if(splaytree_remove_node(tree, pinger->node) != 0)
    {
      print("%s: could not remove node %s\n", __func__, buf);
      goto done;
    }
  pinger->node = NULL;
  pinger->step++;

  for(i=0; i<ping->ping_sent; i++)
    {
      if((reply = ping->ping_replies[i]) == NULL ||
	 (scamper_addr_cmp(ping->dst, reply->addr) != 0 &&
	  SCAMPER_PING_REPLY_FROM_TARGET(ping, reply) == 0))
	continue;
      replyc++;
    }

  /* try with the next method if necessary */
  if(replyc < reply_count && pinger->step < methodc)
    {
      if(slist_tail_push(waiting, pinger) == NULL)
	{
	  print("%s: could not try next method for %s\n", __func__, buf);
	  goto done;
	}
    }
  else
    {
      completed++;
      sc_pinger_free(pinger);
    }
  rc = 0;

 done:
  if(ping != NULL) scamper_ping_free(ping);
  return rc;
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

      assert(obj_type == SCAMPER_FILE_OBJ_PING);
      if(do_decoderead_ping((scamper_ping_t *)obj_data) != 0)
	goto err;
    }
  else if(type == SCAMPER_CTRL_TYPE_EOF)
    {
      scamper_inst_free(scamper_inst);
      scamper_inst = NULL;
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
      fprintf(stderr, "%s: could not alloc scamper_ctrl\n", __func__);
      return -1;
    }

  if(scamper_port != 0)
    {
      type = "port";
      scamper_inst = scamper_inst_inet(scamper_ctrl, NULL, scamper_port);
    }
#ifdef HAVE_SOCKADDR_UN
  else if(scamper_unix != NULL)
    {
      if(options & OPT_UNIX)
	{
	  type = "unix";
	  scamper_inst = scamper_inst_unix(scamper_ctrl, scamper_unix);
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
      print("%s: could not alloc %s inst: %s\n", __func__, type,
	    scamper_ctrl_strerror(scamper_ctrl));
      return -1;
    }

  return 0;
}

static int pinger_data(void)
{
  uint16_t types[] = {SCAMPER_FILE_OBJ_PING};
  int typec = sizeof(types) / sizeof(uint16_t);

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
     (tree = splaytree_alloc((splaytree_cmp_t)sc_pinger_cmp)) == NULL ||
     (virgin = slist_alloc()) == NULL || (waiting = slist_alloc()) == NULL ||
     do_scamperconnect() != 0 ||
     (outfile = scamper_file_open(outfile_name, 'w', outfile_type)) == NULL ||
     (decode_sf = scamper_file_opennull('r', "warts")) == NULL ||
     (decode_rb = scamper_file_readbuf_alloc()) == NULL)
    {
      print("%s: could not init\n", __func__);
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

      if(splaytree_count(tree) == 0 && slist_count(virgin) == 0 &&
	 slist_count(waiting) == 0 && addrfile_fd == -1)
	{
	  print("%s: done\n", __func__);
	  break;
	}

      scamper_ctrl_wait(scamper_ctrl, NULL);
    }

  return 0;
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

  if(tree != NULL)
    {
      splaytree_free(tree, (splaytree_free_t)sc_pinger_free);
      tree = NULL;
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
