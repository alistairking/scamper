/*
 * sc_pinger : scamper driver to probe destinations with various ping
 *             methods
 *
 * $Id: sc_pinger.c,v 1.5 2020/06/24 00:12:14 mjl Exp $
 *
 * Copyright (C) 2020 The University of Waikato
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
#include "scamper_writebuf.h"
#include "scamper_linepoll.h"
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
static int                    outfile_fd    = -1;
static char                  *logfile_name  = NULL;
static FILE                  *logfile_fd    = NULL;
static scamper_file_filter_t *ffilter       = NULL;
static scamper_file_t        *decode_in     = NULL;
static int                    decode_in_fd  = -1;
static int                    decode_out_fd = -1;
static scamper_writebuf_t    *decode_wb     = NULL;
static int                    scamper_fd    = -1;
static scamper_linepoll_t    *scamper_lp    = NULL;
static scamper_writebuf_t    *scamper_wb    = NULL;
static int                    scamper_port  = 0;
static char                  *scamper_unix  = NULL;
static int                    data_left     = 0;
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
	  "                 [-a infile] [-o outfile] [-p port] [-U unix]\n"
	  "                 [-c probec] [-m method] [-t logfile]\n");

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

  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "     -U unix domain to find scamper on\n");

  if(opt_mask & OPT_DAEMON)
    fprintf(stderr, "     -D start as daemon\n");

  if(opt_mask & OPT_COUNT)
    fprintf(stderr, "     -c [replyc]/probec\n");

  if(opt_mask & OPT_TEXT)
    fprintf(stderr, "     -t logfile\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  char *opt_count = NULL, *opt_port = NULL;
  char *opts = "a:c:Dm:o:p:t:U:?", *ptr, *dup = NULL;
  slist_t *list = NULL;
  long lo, lo_rc, lo_pc;
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
	  if((opt_count = strdup(optarg)) == NULL)
	    goto done;
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
	  opt_port = optarg;
	  break;

	case 't':
	  logfile_name = optarg;
	  break;

	case 'U':
	  scamper_unix = optarg;
	  break;

	case '?':
	default:
	  usage(0xffffffff);
	  goto done;
	}
    }

  if(addrfile_name == NULL || outfile_name == NULL ||
     (opt_port == NULL && scamper_unix == NULL) ||
     (opt_port != NULL && scamper_unix != NULL))
    {
      usage(OPT_ADDRFILE | OPT_OUTFILE | OPT_UNIX | OPT_PORT);
      goto done;
    }

  if(opt_port != NULL)
    {
      if(string_tolong(opt_port, &lo) != 0 || lo < 1 || lo > 65535)
	{
	  usage(OPT_PORT);
	  return -1;
	}
      scamper_port = lo;
    }

  if(opt_count != NULL)
    {
      ptr = opt_count;
      while(*ptr != '\0' && *ptr != '/')
	ptr++;
      if(*ptr == '/')
	{
	  *ptr = '\0';
	  ptr++;

	  if(string_isdigit(ptr) == 0 || string_isdigit(opt_count) == 0 ||
	     string_tolong(opt_count, &lo_rc) != 0 ||
	     string_tolong(ptr, &lo_pc) != 0 ||
	     lo_rc > lo_pc || lo_pc > 30 || lo_rc < 1 || lo_pc < 1)
	    {
	      usage(OPT_COUNT);
	      goto done;
	    }
	  reply_count = lo_rc;
	  probe_count = lo_pc;
	}
      else
	{
	  if(string_isdigit(opt_count) == 0 ||
	     string_tolong(opt_count, &lo_pc) != 0)
	    {
	      usage(OPT_COUNT);
	      goto done;
	    }
	  reply_count = lo_pc;
	  probe_count = lo_pc;
	}
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
  if(opt_count != NULL) free(opt_count);
  return rc;
}

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
	  print("%s: could not realloc %d bytes\n", __func__, addrfile_len);
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

static int do_decoderead(void)
{
  scamper_ping_t *ping = NULL;
  scamper_ping_reply_t *reply;
  sc_pinger_t     fm, *pinger;
  void           *data;
  uint16_t        type;
  char            buf[128];
  int             rc = -1;
  int             i, replyc = 0;

  /* try and read a traceroute from the warts decoder */
  if(scamper_file_read(decode_in, ffilter, &type, &data) != 0)
    {
      print("%s: scamper_file_read errno %d\n", __func__, errno);
      goto done;
    }

  if(data == NULL)
    {
      if(scamper_file_geteof(decode_in) != 0)
	{
	  scamper_file_close(decode_in);
	  decode_in = NULL;
	  decode_in_fd = -1;
	}
      rc = 0;
      goto done;
    }

  if(type == SCAMPER_FILE_OBJ_PING)
    ping = (scamper_ping_t *)data;
  else
    {
      print("%s: unknown type %d\n", __func__, type);
      goto done;
    }

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
  string_concat(cmd, sizeof(cmd), &off, "ping -c %d -o %d -P %s %s\n",
		probe_count, reply_count, methods[pinger->step], addr);

  if((pinger->node = splaytree_insert(tree, pinger)) == NULL)
    {
      print("%s: could not add %s to tree\n", __func__, addr);
      return -1;
    }

  /* got a command, send it */
  if(scamper_writebuf_send(scamper_wb, cmd, off) != 0)
    {
      print("%s: could not send %s\n", __func__, cmd);
      return -1;
    }
  more--;

  print("p %d, c %d: %s", splaytree_count(tree), completed, cmd);

  return 0;
}

/*
 * do_files
 *
 * open a socketpair that can be used to feed warts data into one end and
 * have the scamper_file routines decode it via the other end.
 *
 * also open a file to send the binary warts data file to.
 */
static int do_files(void)
{
  mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
  int fd_flags = O_WRONLY | O_CREAT | O_TRUNC;
  int pair[2];

  if((outfile_fd = open(outfile_name, fd_flags, mode)) == -1)
    {
      print("%s: could not open %s\n", __func__, outfile_name);
      return -1;
    }

  /*
   * setup a socketpair that is used to decode warts from a binary input.
   * pair[0] is used to write to the file, while pair[1] is used by
   * the scamper_file_t routines to parse the warts data.
   */
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
    {
      print("%s: could not socketpair\n", __func__);
      return -1;
    }

  decode_in_fd  = pair[0];
  decode_out_fd = pair[1];
  decode_in = scamper_file_openfd(decode_in_fd, NULL, 'r', "warts");
  if(decode_in == NULL)
    {
      print("%s: could not open decode_in\n");
      return -1;
    }

  if(fcntl_set(decode_in_fd, O_NONBLOCK) == -1 ||
     fcntl_set(decode_out_fd, O_NONBLOCK) == -1 ||
     (decode_wb = scamper_writebuf_alloc()) == NULL)
    {
      print("%s: could not open decode_wb\n");
      return -1;
    }

  return 0;
}

/*
 * do_scamperconnect
 *
 * allocate socket and connect to scamper process listening on the port
 * specified.
 */
static int do_scamperconnect(void)
{
#ifdef HAVE_SOCKADDR_UN
  struct sockaddr_un sn;
#endif

  struct sockaddr_in sin;
  struct in_addr in;

  if(scamper_port != 0)
    {
      inet_aton("127.0.0.1", &in);
      sockaddr_compose((struct sockaddr *)&sin, AF_INET, &in, scamper_port);
      if((scamper_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
	  print("%s: could not allocate new socket\n", __func__);
	  return -1;
	}
      if(connect(scamper_fd, (const struct sockaddr *)&sin, sizeof(sin)) != 0)
	{
	  print("%s: could not connect to scamper process on port %d\n",
		__func__, scamper_port);
	  return -1;
	}
      return 0;
    }
#ifdef HAVE_SOCKADDR_UN
  else if(scamper_unix != NULL)
    {
      if(sockaddr_compose_un((struct sockaddr *)&sn, scamper_unix) != 0)
	{
	  print("%s: could not build sockaddr_un\n", __func__);
	  return -1;
	}
      if((scamper_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
	  print("%s: could not allocate unix domain socket\n", __func__);
	  return -1;
	}
      if(connect(scamper_fd, (const struct sockaddr *)&sn, sizeof(sn)) != 0)
	{
	  print("%s: could not connect to scamper process\n", __func__);
	  return -1;
	}
      return 0;
    }
#endif

  print("%s: :(\n", __func__);
  return -1;
}

static int do_scamperread_line(void *param, uint8_t *buf, size_t linelen)
{
  char *head = (char *)buf;
  uint8_t uu[64];
  size_t uus;
  long l;

  /* skip empty lines */
  if(head[0] == '\0')
    return 0;
  
  /* if currently decoding data, then pass it to uudecode */
  if(data_left > 0)
    {
      uus = sizeof(uu);
      if(uudecode_line(head, linelen, uu, &uus) != 0)
	{
	  print("%s: could not uudecode_line\n", __func__);
	  error = 1;
	  return -1;
	}

      if(uus != 0)
	{
	  scamper_writebuf_send(decode_wb, uu, uus);
	  write_wrap(outfile_fd, uu, NULL, uus);
	}

      data_left -= (linelen + 1);
      return 0;
    }

  /* feedback letting us know that the command was accepted */
  if(linelen >= 2 && strncasecmp(head, "OK", 2) == 0)
    return 0;
  
  /* if the scamper process is asking for more tasks, give it more */
  if(linelen == 4 && strncasecmp(head, "MORE", linelen) == 0)
    {
      more++;
      if(do_method() != 0)
	return -1;
      return 0;
    }

  /* new piece of data */
  if(linelen > 5 && strncasecmp(head, "DATA ", 5) == 0)
    {
      if(string_isnumber(head+5) == 0 || string_tolong(head+5, &l) != 0)
	{
	  print("%s: could not parse %s\n", __func__, head);
	  error = 1;
	  return -1;
	}
      data_left = l;
      return 0;
    }

  /* feedback letting us know that the command was not accepted */
  if(linelen >= 3 && strncasecmp(head, "ERR", 3) == 0)
    {
      error = 1;
      return -1;
    }

  print("%s: unknown response '%s'\n", __func__, head);
  error = 1;
  return -1;
}

static int do_scamperread(void)
{
  ssize_t rc;
  uint8_t buf[512];

  if((rc = read(scamper_fd, buf, sizeof(buf))) > 0)
    {
      scamper_linepoll_handle(scamper_lp, buf, rc);
      return 0;
    }
  else if(rc == 0)
    {
      print("%s: disconnected\n", __func__);
      close(scamper_fd); scamper_fd = -1;
      return 0;
    }
  else if(errno == EINTR || errno == EAGAIN)
    {
      return 0;
    }

  fprintf(stderr, "could not read: errno %d\n", errno);
  return -1;
}

static int pinger_data(void)
{
  uint16_t types[] = {SCAMPER_FILE_OBJ_PING};
  int typec = sizeof(types) / sizeof(uint16_t);
  struct timeval tv, *tv_ptr;
  fd_set rfds, wfds, *wfdsp;
  int nfds;

#ifdef HAVE_DAEMON
  /* start a daemon if asked to */
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    {
      fprintf(stderr, "could not daemon\n");
      return -1;
    }
#endif

  if((logfile_name != NULL && (logfile_fd=fopen(logfile_name, "w")) == NULL) ||
     (addrfile_fd = open(addrfile_name, O_RDONLY)) < 0 ||
     (addrfile_buf = malloc(addrfile_len)) == NULL ||
     (ffilter = scamper_file_filter_alloc(types, typec)) == NULL ||
     (tree = splaytree_alloc((splaytree_cmp_t)sc_pinger_cmp)) == NULL ||
     (virgin = slist_alloc()) == NULL || (waiting = slist_alloc()) == NULL ||
     do_scamperconnect() != 0 || do_files() != 0 ||
     (scamper_lp = scamper_linepoll_alloc(do_scamperread_line, NULL)) == NULL ||
     (scamper_wb = scamper_writebuf_alloc()) == NULL)
    {
      print("%s: could not init\n", __func__);
      return -1;
    }
  scamper_writebuf_send(scamper_wb, "attach\n", 7);

  while(error == 0)
    {
      /*
       * need to set a timeout on select if scamper's processing window is
       * not full and there is a trace in the waiting queue.
       */
      tv_ptr = NULL;
      if(more > 0 &&
	 (slist_count(waiting) > 0 || slist_count(virgin) > 0 ||
	  addrfile_fd != -1))
	{
	  memset(&tv, 0, sizeof(tv));
	  tv_ptr = &tv;
	}

      nfds = 0; FD_ZERO(&rfds); FD_ZERO(&wfds); wfdsp = NULL;
      if(scamper_fd < 0 && decode_in_fd < 0)
	break;

      if(scamper_fd >= 0)
	{
	  FD_SET(scamper_fd, &rfds);
	  if(nfds < scamper_fd) nfds = scamper_fd;
	  if(scamper_writebuf_len(scamper_wb) > 0)
	    {
	      FD_SET(scamper_fd, &wfds);
	      wfdsp = &wfds;
	    }
	}

      if(decode_in_fd >= 0)
	{
	  FD_SET(decode_in_fd, &rfds);
	  if(nfds < decode_in_fd) nfds = decode_in_fd;
	}

      if(decode_out_fd >= 0 && scamper_writebuf_len(decode_wb) > 0)
	{
	  FD_SET(decode_out_fd, &wfds);
	  wfdsp = &wfds;
	  if(nfds < decode_out_fd) nfds = decode_out_fd;
	}

      if(splaytree_count(tree) == 0 && slist_count(virgin) == 0 &&
	 slist_count(waiting) == 0 && addrfile_fd == -1)
	{
	  print("%s: done\n", __func__);
	  break;
	}

      if(select(nfds+1, &rfds, wfdsp, NULL, tv_ptr) < 0)
	{
	  if(errno == EINTR) continue;
	  print("%s: select error\n", __func__);
	  break;
	}

      if(more > 0)
	{
	  if(do_method() != 0)
	    return -1;
	}

      if(scamper_fd >= 0)
	{
	  if(FD_ISSET(scamper_fd, &rfds) && do_scamperread() != 0)
	    return -1;
	  if(wfdsp != NULL && FD_ISSET(scamper_fd, wfdsp) &&
	     scamper_writebuf_write(scamper_fd, scamper_wb) != 0)
	    return -1;
	}

      if(decode_in_fd >= 0)
	{
	  if(FD_ISSET(decode_in_fd, &rfds) && do_decoderead() != 0)
	    return -1;
	}

      if(decode_out_fd >= 0)
	{
	  if(wfdsp != NULL && FD_ISSET(decode_out_fd, wfdsp) &&
	     scamper_writebuf_write(decode_out_fd, decode_wb) != 0)
	    return -1;

	  if(scamper_fd < 0 && scamper_writebuf_len(decode_wb) == 0)
	    {
	      close(decode_out_fd);
	      decode_out_fd = -1;
	    }
	}
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

    if(decode_in != NULL)
    {
      scamper_file_close(decode_in);
      decode_in = NULL;
    }

  if(ffilter != NULL)
    {
      scamper_file_filter_free(ffilter);
      ffilter = NULL;
    }

  if(decode_wb != NULL)
    {
      scamper_writebuf_free(decode_wb);
      decode_wb = NULL;
    }

  if(scamper_wb != NULL)
    {
      scamper_writebuf_free(scamper_wb);
      scamper_wb = NULL;
    }

  if(scamper_lp != NULL)
    {
      scamper_linepoll_free(scamper_lp, 0);
      scamper_lp = NULL;
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
