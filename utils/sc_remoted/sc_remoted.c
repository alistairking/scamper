/*
 * sc_remoted
 *
 * $Id: sc_remoted.c,v 1.108 2024/04/26 06:52:24 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2014-2023 Matthew Luckie
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
 *****************
 *
 * This code defines a protocol that exists between a central server
 * running sc_remoted, and a remote system running scamper.  As the
 * protocol allows multiple local processes to drive a single remote
 * scamper process, the protocol is based around "channels" to
 * separate multiple streams of scamper control connection over a
 * single TCP socket.
 *
 * The protocol is roughly designed as follows:
 *
 * Header:
 * ------
 * uint32_t  sequence
 * uint32_t  channel
 * uint16_t  msglen
 *
 * The control header is included in every message sent between the
 * scamper instance and the remote controller.
 * The sequence number uniquely identifies the message among a stream
 * of messages.
 * The channel number identifies the stream; channel #0 is reserved for
 * control messages.
 * The msglen value defines the size of the message following the header.
 *
 * Control Messages:
 * ----------------
 * uint8_t   type
 *
 * A control message begins with a mandatory type number.  The following
 * control message types are defined, with arrows defining who may send
 * which message type.
 *
 * 0 - Master        (remoted <-- scamper) -- CONTROL_MASTER_NEW
 * 1 - Master ID     (remoted --> scamper) -- CONTROL_MASTER_ID
 * 2 - New Channel   (remoted --> scamper) -- CONTROL_CHANNEL_NEW
 * 3 - Channel FIN   (remoted <-> scamper) -- CONTROL_CHANNEL_FIN
 * 4 - Keepalive     (remoted <-> scamper) -- CONTROL_KEEPALIVE
 * 5 - Ack           (remoted <-> scamper) -- CONTROL_ACK
 * 6 - Master Resume (remoted <-- scamper) -- CONTROL_MASTER_RES
 * 7 - Master Reject (remoted --> scamper) -- CONTROL_MASTER_REJ
 * 8 - Master OK     (remoted --> scamper) -- CONTROL_MASTER_OK
 *
 * Control Message - Master New (CONTROL_MASTER_NEW)
 * ----------------------------
 *
 * Whenever a scamper instance establishes a TCP connection with a remote
 * controller, it sends a message that identifies itself.  The message
 * is formatted as follows:
 *
 * uint8_t   magic_len
 * uint8_t  *magic
 * uint8_t   monitorname_len
 * char     *monitorname
 *
 * The magic value is generated randomly by the scamper instance when
 * the process starts, and is never modified.  The same magic value is
 * always supplied in a control socket connection and allows the remote
 * controller to identify that the scamper instance supports graceful
 * restart.
 * The monitorname is sent if the remote scamper instance uses the -M
 * option.
 * Both magic_len and monitorname_len include the terminating null byte.
 *
 * Control Message - Master ID (CONTROL_MASTER_ID)
 * ---------------------------
 *
 * After the "Master New" message has been received by the remote
 * controller, the remote controller sends an ID value to the scamper
 * instance that it can use as a list identifier in warts.  The message
 * is formatted as follows:
 *
 * uint8_t   id_len;
 * char     *id
 *
 * Control Message - New Channel (CONTROL_CHANNEL_NEW)
 * -----------------------------
 *
 * Whenever a remote controller has a new connection on a unix domain
 * socket, it sends a control message to scamper with a new channel
 * number to use for the connection.  The message is formatted as
 * follows:
 *
 * uint32_t  channel
 *
 * Control Message - Channel FIN (CONTROL_CHANNEL_FIN)
 * -----------------------------
 *
 * Whenever a client connection has no more to send, it sends a FIN
 * type to close the channel. the FIN message must be sent by both the
 * remote controller and the scamper instance for a channel to be
 * closed.  The message is formatted as follows:
 *
 * uint32_t  channel
 *
 * Control Message - Keepalive (CONTROL_KEEPALIVE)
 * ---------------------------
 *
 * Both scamper and remoted periodically send keepalive messages to
 * each other when their keepalive timers expire.  Keepalive messages
 * have no payload.
 *
 * Control Message - Acknowledgement (CONTROL_ACK)
 * ---------------------------------
 *
 * Both scamper and remoted acknowledge messages received by either
 * end of the connnection, provided the sender expected the message
 * to be acknowledged.
 *
 * uint32_t  sequence
 *
 * Control Message - Resume (CONTROL_MASTER_RES)
 * ------------------------
 *
 * Whenever a connection between scamper and remoted is interrupted,
 * scamper can resume by sending a resumption message with the same
 * magic value scamper supplied initially.  the resume message also
 * includes the next sequence number the scamper expects from remoted,
 * the left edge of the
 *
 * uint8_t   magic_len
 * uint8_t  *magic
 * uint32_t  rcv_nxt
 * uint32_t  snd_una
 * uint32_t  snd_nxt
 *
 * Control Message - Reject (CONTROL_MASTER_REJ)
 * ------------------------
 *
 * If a scamper connection is rejected because the magic value
 * supplied by scamper is invalid, remoted sends scamper a reject
 * message.
 *
 * Control Message - OK (CONTROL_MASTER_OK)
 * --------------------
 *
 * If a scamper resumption request is acceptable, then the remote
 * controller replies back with the next expected sequence number from
 * scamper.  this number will be in the range of snd_una and snd_nxt
 * sent by the scamper instance in the resume message.
 *
 * uint32_t  rcv_nxt
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_linepoll.h"
#include "scamper_writebuf.h"
#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "utils.h"

#ifdef HAVE_OPENSSL
#include "utils_tls.h"
#endif

#define SC_MESSAGE_HDRLEN 10

/*
 * sc_unit
 *
 * this generic structure says what kind of node is pointed to, and is
 * used to help garbage collect with kqueue / epoll.
 */
typedef struct sc_unit
{
  void               *data;
  dlist_t            *list; /* list == gclist if on that list */
  dlist_node_t       *node;
  uint8_t             type;
  uint8_t             gc;
} sc_unit_t;

#define UNIT_TYPE_MASTER  0
#define UNIT_TYPE_CHANNEL 1

/*
 * sc_fd
 *
 * this structure associates a file descriptor with a data pointer, as
 * well as information about what type the fd is and any current
 * state.
 */
typedef struct sc_fd
{
  int                 fd;
  sc_unit_t          *unit;
  uint8_t             type;
  uint8_t             flags;
} sc_fd_t;

#define FD_TYPE_SERVER       0
#define FD_TYPE_MASTER_INET  1
#define FD_TYPE_MASTER_UNIX  2
#define FD_TYPE_CHANNEL_UNIX 3

#define FD_FLAG_READ        1
#define FD_FLAG_WRITE       2

/*
 * sc_master_t
 *
 * this structure holds a mapping between a remote scamper process
 * that is willing to be driven and a local unix domain socket where
 * local processes can connect.  it also includes a list of all
 * clients connected using the socket.
 */
typedef struct sc_master
{
  sc_unit_t          *unit;
  char               *monitorname;
  char               *name;
  uint8_t            *magic;
  uint8_t             magic_len;
  int                 mode;

  sc_fd_t            *unix_fd;
  sc_fd_t             inet_fd;
  scamper_writebuf_t *inet_wb;

#ifdef HAVE_OPENSSL
  int                 inet_mode;
  SSL                *inet_ssl;
  BIO                *inet_rbio;
  BIO                *inet_wbio;
#endif

  struct timeval      tx_ka;
  struct timeval      rx_abort;
  struct timeval      zombie;

  slist_t            *messages;
  uint32_t            snd_nxt;
  uint32_t            rcv_nxt;

  dlist_t            *channels;
  uint32_t            next_channel;
  dlist_node_t       *node;
  splaytree_node_t   *tree_node;
  uint8_t             buf[65536 + SC_MESSAGE_HDRLEN];
  size_t              buf_offset;
} sc_master_t;

/*
 * sc_channel_t
 *
 * this structure holds a mapping between a local process that wants
 * to drive a remote scamper, and a channel corresponding to that
 * instance.
 */
typedef struct sc_channel
{
  uint32_t            id;
  sc_unit_t          *unit;
  sc_fd_t            *unix_fd;
  scamper_linepoll_t *unix_lp;
  scamper_writebuf_t *unix_wb;
  sc_master_t        *master;
  dlist_node_t       *node;
  uint8_t             flags;
} sc_channel_t;

/*
 * sc_message_t
 *
 * this structure contains messages that we send over the Internet
 * socket until we receive an acknowledgement from scamper that it got
 * the message.
 */
typedef struct sc_message
{
  uint32_t            sequence;
  uint32_t            channel;
  uint16_t            msglen;
  void               *data;
} sc_message_t;

#define OPT_HELP    0x0001
#define OPT_UNIX    0x0002
#define OPT_PORT    0x0004
#define OPT_DAEMON  0x0008
#define OPT_IPV4    0x0010
#define OPT_IPV6    0x0020
#define OPT_OPTION  0x0040
#define OPT_TLSCERT 0x0080
#define OPT_TLSPRIV 0x0100
#define OPT_ZOMBIE  0x0200
#define OPT_PIDFILE 0x0400
#define OPT_TLSCA   0x0800
#define OPT_ALL     0xffff

#define FLAG_DEBUG      0x0001 /* verbose debugging */
#define FLAG_SELECT     0x0002 /* use select instead of kqueue/epoll */
#define FLAG_ALLOW_G    0x0004 /* allow group members to connect */
#define FLAG_ALLOW_O    0x0008 /* allow everyone to connect */
#define FLAG_SKIP_VERIF 0x0010 /* skip TLS name verification */

#define CHANNEL_FLAG_EOF_TX 0x01
#define CHANNEL_FLAG_EOF_RX 0x02

#define MASTER_MODE_CONNECT 0
#define MASTER_MODE_GO      1
#define MASTER_MODE_FLUSH   2

#define CONTROL_MASTER_NEW   0 /* scamper --> remoted */
#define CONTROL_MASTER_ID    1 /* scamper <-- remoted */
#define CONTROL_CHANNEL_NEW  2 /* scamper <-- remoted */
#define CONTROL_CHANNEL_FIN  3 /* scamper <-> remoted */
#define CONTROL_KEEPALIVE    4 /* scamper <-> remoted */
#define CONTROL_ACK          5 /* scamper <-> remoted */
#define CONTROL_MASTER_RES   6 /* scamper --> remoted */
#define CONTROL_MASTER_REJ   7 /* scamper <-- remoted */
#define CONTROL_MASTER_OK    8 /* scamper <-- remoted */

static uint16_t     options        = 0;
static char        *unix_name      = NULL;
static char        *ss_addr        = NULL;
static int          ss_port        = 0;
static splaytree_t *mstree         = NULL;
static dlist_t     *mslist         = NULL;
static dlist_t     *gclist         = NULL;
static int          stop           = 0;
static int          reload         = 0;
static uint16_t     flags          = 0;
static int          serversockets[2];
static int          zombie         = 60 * 15;
static char        *pidfile        = NULL;
static struct timeval now;

#if defined(HAVE_EPOLL)
static int          epfd           = -1;
#elif defined(HAVE_KQUEUE)
static int          kqfd           = -1;
#endif

#ifdef HAVE_OPENSSL
static SSL_CTX     *tls_ctx = NULL;
static char        *tls_certfile   = NULL;
static char        *tls_privfile   = NULL;
static char        *tls_cafile     = NULL;
#define SSL_MODE_ACCEPT      0x00
#define SSL_MODE_ESTABLISHED 0x01
#endif

/*
 * sc_unit_gc_t:
 *
 * method to cleanup tasks when its time to garbage collect
 */
typedef void (*sc_unit_gc_t)(void *);
static void sc_channel_free(sc_channel_t *);
static void sc_master_free(sc_master_t *);
static const sc_unit_gc_t unit_gc[] = {
  (sc_unit_gc_t)sc_master_free,      /* UNIT_TYPE_MASTER */
  (sc_unit_gc_t)sc_channel_free,     /* UNIT_TYPE_CHANNEL */
};

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
typedef void (*sc_fd_cb_t)(void *);
static void sc_channel_unix_read_do(sc_channel_t *);
static void sc_channel_unix_write_do(sc_channel_t *);
static void sc_master_inet_read_do(sc_master_t *);
static void sc_master_inet_write_do(sc_master_t *);
static void sc_master_unix_accept_do(sc_master_t *);

static const sc_fd_cb_t read_cb[] = {
  NULL,                                 /* FD_TYPE_SERVER */
  (sc_fd_cb_t)sc_master_inet_read_do,   /* FD_TYPE_MASTER_INET */
  (sc_fd_cb_t)sc_master_unix_accept_do, /* FD_TYPE_MASTER_UNIX */
  (sc_fd_cb_t)sc_channel_unix_read_do,  /* FD_TYPE_CHANNEL_UNIX */
};
static const sc_fd_cb_t write_cb[] = {
  NULL,                                 /* FD_TYPE_SERVER */
  (sc_fd_cb_t)sc_master_inet_write_do,  /* FD_TYPE_MASTER_INET */
  NULL,                                 /* FD_TYPE_MASTER_UNIX */
  (sc_fd_cb_t)sc_channel_unix_write_do, /* FD_TYPE_CHANNEL_UNIX */
};
#endif

static void usage(uint32_t opt_mask)
{
  fprintf(stderr,
	  "usage: sc_remoted [-?46D] [-O option] -P [ip:]port -U unix\n"
#ifdef HAVE_OPENSSL
	  "                  [-c certfile] [-p privfile] [-C CAfile]\n"
#endif
	  "                  [-e pidfile] [-Z zombie-time]\n"
	  );

  if(opt_mask == 0)
    {
      fprintf(stderr, "\n     sc_remoted -?\n\n");
      return;
    }

  if(opt_mask & OPT_IPV4)
    fprintf(stderr, "     -4 only listen for connections over IPv4\n");

  if(opt_mask & OPT_IPV6)
    fprintf(stderr, "     -6 only listen for connections over IPv6\n");

  if(opt_mask & OPT_DAEMON)
    fprintf(stderr, "     -D operate as a daemon\n");

  if(opt_mask & OPT_PIDFILE)
    fprintf(stderr, "     -e write process ID to specified file\n");

  if(opt_mask & OPT_OPTION)
    {
      fprintf(stderr, "     -O options\n");
      fprintf(stderr, "        allowgroup: allow group access to sockets\n");
      fprintf(stderr, "        allowother: allow other access to sockets\n");
      fprintf(stderr, "        debug: print debugging messages\n");
      fprintf(stderr, "        select: use select\n");
      fprintf(stderr, "        skipnameverification: skip TLS name verif\n");
    }

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -P [ip:]port to accept remote scamper connections\n");

  if(opt_mask & OPT_UNIX)
    fprintf(stderr, "     -U directory for unix domain sockets\n");

#ifdef HAVE_OPENSSL
  if(opt_mask & OPT_TLSCERT)
    fprintf(stderr, "     -c server certificate in PEM format\n");
  if(opt_mask & OPT_TLSPRIV)
    fprintf(stderr, "     -p private key in PEM format\n");
  if(opt_mask & OPT_TLSCA)
    fprintf(stderr, "     -C require client authentication using this CA\n");
#endif

  if(opt_mask & OPT_ZOMBIE)
    fprintf(stderr, "     -Z time to retain state for disconnected scamper\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  struct sockaddr_storage sas;
  char *opts = "?46DO:c:C:e:p:P:U:Z:", *opt_addrport = NULL, *opt_zombie = NULL;
  char *opt_pidfile = NULL;
  long lo;
  int ch;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
	case '4':
	  options |= OPT_IPV4;
	  break;

	case '6':
	  options |= OPT_IPV6;
	  break;

	case 'D':
	  options |= OPT_DAEMON;
	  break;

	case 'e':
	  options |= OPT_PIDFILE;
	  opt_pidfile = optarg;
	  break;

	case 'O':
	  if(strcasecmp(optarg, "select") == 0)
	    flags |= FLAG_SELECT;
	  else if(strcasecmp(optarg, "allowgroup") == 0)
	    flags |= FLAG_ALLOW_G;
	  else if(strcasecmp(optarg, "allowother") == 0)
	    flags |= FLAG_ALLOW_O;
	  else if(strcasecmp(optarg, "debug") == 0)
	    flags |= FLAG_DEBUG;
	  else if(strcasecmp(optarg, "skipnameverification") == 0)
	    flags |= FLAG_SKIP_VERIF;
	  else
	    {
	      usage(OPT_ALL);
	      return -1;
	    }
	  break;

	case 'P':
	  opt_addrport = optarg;
	  break;

#ifdef HAVE_OPENSSL
	case 'c':
	  tls_certfile = optarg;
	  options |= OPT_TLSCERT;
	  break;

	case 'p':
	  tls_privfile = optarg;
	  options |= OPT_TLSPRIV;
	  break;

	case 'C':
	  tls_cafile = optarg;
	  options |= OPT_TLSCA;
	  break;
#endif

	case 'U':
	  unix_name = optarg;
	  break;

	case 'Z':
	  opt_zombie = optarg;
	  break;

	case '?':
	default:
	  usage(OPT_ALL);
	  return -1;
	}
    }

  if(unix_name == NULL || opt_addrport == NULL)
    {
      usage(OPT_PORT|OPT_UNIX);
      return -1;
    }

#ifdef HAVE_OPENSSL
  /*
   * the user must specify both a cert and private key if they specify
   * either
   */
  if((options & (OPT_TLSCERT|OPT_TLSPRIV)) != 0 &&
     (options & (OPT_TLSCERT|OPT_TLSPRIV)) != (OPT_TLSCERT|OPT_TLSPRIV))
    {
      usage(OPT_TLSCERT|OPT_TLSPRIV);
      return -1;
    }
  /*
   * if the user requires client cert verification, they must also
   * present server certificates as part of the authentication
   * process.
   */
  if((options & OPT_TLSCA) != 0 &&
     (options & (OPT_TLSCERT|OPT_TLSPRIV)) != (OPT_TLSCERT|OPT_TLSPRIV))
    {
      usage(OPT_TLSCERT|OPT_TLSPRIV|OPT_TLSCA);
      return -1;
    }
#endif

  if(string_addrport(opt_addrport, &ss_addr, &ss_port) != 0)
    {
      usage(OPT_PORT);
      return -1;
    }

  /*
   * if there was an address specified, and either -4 or -6 was passed in,
   * ensure the address at least matches the specified address family
   */
  if(ss_addr != NULL && (options & (OPT_IPV4|OPT_IPV6)) != 0 &&
     (sockaddr_compose_str((struct sockaddr *)&sas, ss_addr, ss_port) != 0 ||
      ((options & OPT_IPV4) != 0 && sas.ss_family == AF_INET6) ||
      ((options & OPT_IPV6) != 0 && sas.ss_family == AF_INET)))
    {
      usage(OPT_PORT | (options & (OPT_IPV4|OPT_IPV6)));
      return -1;
    }

  if(opt_pidfile != NULL && (pidfile = strdup(opt_pidfile)) == NULL)
    {
      usage(OPT_PIDFILE);
      return -1;
    }

  if(opt_zombie != NULL)
    {
      if(string_tolong(opt_zombie, &lo) != 0 || lo < 0 || lo > (60 * 60))
	{
	  usage(OPT_ZOMBIE);
	  return -1;
	}
      zombie = lo;
    }

  return 0;
}

#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
static void remote_debug(const char *func, const char *format, ...)
  __attribute__((format(printf, 2, 3)));
#endif

static void remote_debug(const char *func, const char *format, ...)
{
  char message[512], ts[16];
  struct tm *tm;
  va_list ap;
  time_t t;
  int ms;

  if(options & OPT_DAEMON)
    return;

  if((flags & FLAG_DEBUG) == 0)
    return;

  va_start(ap, format);
  vsnprintf(message, sizeof(message), format, ap);
  va_end(ap);

  t = now.tv_sec;
  if((tm = localtime(&t)) == NULL)
    return;
  ms = now.tv_usec / 1000;
  snprintf(ts, sizeof(ts), "[%02d:%02d:%02d:%03d]",
	   tm->tm_hour, tm->tm_min, tm->tm_sec, ms);

  fprintf(stderr, "%s %s: %s\n", ts, func, message);
  fflush(stderr);
  return;
}

static int sc_fd_peername(const sc_fd_t *fd, char *buf, size_t len)
{
  struct sockaddr_storage sas;
  socklen_t sl;

  sl = sizeof(sas);
  if(getpeername(fd->fd, (struct sockaddr *)&sas, &sl) != 0)
    {
      remote_debug(__func__, "could not getpeername: %s", strerror(errno));
      return -1;
    }
  if(sockaddr_tostr((struct sockaddr *)&sas, buf, len) == NULL)
    {
      remote_debug(__func__, "could not convert to string");
      return -1;
    }
  return 0;
}

static int sc_fd_read_add(sc_fd_t *fd)
{
#if defined(HAVE_EPOLL)
  struct epoll_event ev;
#elif defined(HAVE_KQUEUE)
  struct kevent kev;
#endif

  if((fd->flags & FD_FLAG_READ) != 0)
    return 0;
  fd->flags |= FD_FLAG_READ;
  if((flags & FLAG_SELECT) != 0)
    return 0;

#if defined(HAVE_EPOLL)
  ev.data.ptr = fd;
  if((fd->flags & FD_FLAG_WRITE) == 0)
    {
      ev.events = EPOLLIN;
      if(epoll_ctl(epfd, EPOLL_CTL_ADD, fd->fd, &ev) != 0)
	return -1;
    }
  else
    {
      ev.events = EPOLLIN | EPOLLOUT;
      if(epoll_ctl(epfd, EPOLL_CTL_MOD, fd->fd, &ev) != 0)
	return -1;
    }
#elif defined(HAVE_KQUEUE)
  EV_SET(&kev, fd->fd, EVFILT_READ, EV_ADD, 0, 0, fd);
  if(kevent(kqfd, &kev, 1, NULL, 0, NULL) != 0)
    return -1;
#endif
  return 0;
}

static int sc_fd_read_del(sc_fd_t *fd)
{
#if defined(HAVE_EPOLL)
  struct epoll_event ev;
#elif defined(HAVE_KQUEUE)
  struct kevent kev;
#endif

  if((fd->flags & FD_FLAG_READ) == 0)
    return 0;
  fd->flags &= ~(FD_FLAG_READ);
  if((flags & FLAG_SELECT) != 0)
    return 0;

#if defined(HAVE_EPOLL)
  ev.data.ptr = fd;
  if((fd->flags & FD_FLAG_WRITE) == 0)
    {
      ev.events = 0;
      if(epoll_ctl(epfd, EPOLL_CTL_DEL, fd->fd, &ev) != 0)
	return -1;
    }
  else
    {
      ev.events = EPOLLOUT;
      if(epoll_ctl(epfd, EPOLL_CTL_MOD, fd->fd, &ev) != 0)
	return -1;
    }
#elif defined(HAVE_KQUEUE)
  EV_SET(&kev, fd->fd, EVFILT_READ, EV_DELETE, 0, 0, fd);
  if(kevent(kqfd, &kev, 1, NULL, 0, NULL) != 0)
    return -1;
#endif
  return 0;
}

static int sc_fd_write_add(sc_fd_t *fd)
{
#if defined(HAVE_EPOLL)
  struct epoll_event ev;
#elif defined(HAVE_KQUEUE)
  struct kevent kev;
#endif

  if((fd->flags & FD_FLAG_WRITE) != 0)
    return 0;
  fd->flags |= FD_FLAG_WRITE;
  if((flags & FLAG_SELECT) != 0)
    return 0;

#if defined(HAVE_EPOLL)
  ev.data.ptr = fd;
  if((fd->flags & FD_FLAG_READ) == 0)
    {
      ev.events = EPOLLOUT;
      if(epoll_ctl(epfd, EPOLL_CTL_ADD, fd->fd, &ev) != 0)
	return -1;
    }
  else
    {
      ev.events = EPOLLIN | EPOLLOUT;
      if(epoll_ctl(epfd, EPOLL_CTL_MOD, fd->fd, &ev) != 0)
	return -1;
    }
#elif defined(HAVE_KQUEUE)
  EV_SET(&kev, fd->fd, EVFILT_WRITE, EV_ADD, 0, 0, fd);
  if(kevent(kqfd, &kev, 1, NULL, 0, NULL) != 0)
    return -1;
#endif
  return 0;
}

static int sc_fd_write_del(sc_fd_t *fd)
{
#if defined(HAVE_EPOLL)
  struct epoll_event ev;
#elif defined(HAVE_KQUEUE)
  struct kevent kev;
#endif

  if((fd->flags & FD_FLAG_WRITE) == 0)
    return 0;
  fd->flags &= ~(FD_FLAG_WRITE);
  if((flags & FLAG_SELECT) != 0)
    return 0;

#if defined(HAVE_EPOLL)
  ev.data.ptr = fd;
  if((fd->flags & FD_FLAG_READ) == 0)
    {
      ev.events = 0;
      if(epoll_ctl(epfd, EPOLL_CTL_DEL, fd->fd, &ev) != 0)
	return -1;
    }
  else
    {
      ev.events = EPOLLIN;
      if(epoll_ctl(epfd, EPOLL_CTL_MOD, fd->fd, &ev) != 0)
	return -1;
    }
#elif defined(HAVE_KQUEUE)
  EV_SET(&kev, fd->fd, EVFILT_WRITE, EV_DELETE, 0, 0, fd);
  if(kevent(kqfd, &kev, 1, NULL, 0, NULL) != 0)
    return -1;
#endif
  return 0;
}

#ifdef HAVE_OPENSSL
static int ssl_want_read(sc_master_t *ms)
{
  uint8_t buf[1024];
  int pending, rc, size, off = 0;

  if((pending = BIO_pending(ms->inet_wbio)) < 0)
    {
      remote_debug(__func__, "BIO_pending returned %d", pending);
      return -1;
    }

  while(off < pending)
    {
      if((size_t)(pending - off) > sizeof(buf))
	size = sizeof(buf);
      else
	size = pending - off;

      if((rc = BIO_read(ms->inet_wbio, buf, size)) <= 0)
	{
	  if(BIO_should_retry(ms->inet_wbio) == 0)
	    remote_debug(__func__, "BIO_read should not retry");
	  else
	    remote_debug(__func__, "BIO_read returned %d", rc);
	  return -1;
	}
      off += rc;

      scamper_writebuf_send(ms->inet_wb, buf, rc);
      sc_fd_write_add(&ms->inet_fd);
    }

  return pending;
}
#endif

static void sc_fd_free(sc_fd_t *sfd)
{
  if(sfd == NULL)
    return;
  if(sfd->fd != -1)
    close(sfd->fd);
  free(sfd);
  return;
}

static sc_fd_t *sc_fd_alloc(int fd, uint8_t type, sc_unit_t *unit)
{
  sc_fd_t *sfd;
  if((sfd = malloc_zero(sizeof(sc_fd_t))) == NULL)
    return NULL;
  sfd->fd = fd;
  sfd->type = type;
  sfd->unit = unit;
  return sfd;
}

static void sc_unit_onremove(sc_unit_t *scu)
{
  scu->node = NULL;
  scu->list = NULL;
  return;
}

static void sc_unit_gc(sc_unit_t *scu)
{
  if(scu->gc != 0)
    return;
  scu->gc = 1;
  dlist_node_tail_push(gclist, scu->node);
  scu->list = gclist;
  return;
}

static void sc_unit_free(sc_unit_t *scu)
{
  if(scu == NULL)
    return;
  if(scu->node != NULL)
    dlist_node_pop(scu->list, scu->node);
  free(scu);
  return;
}

static sc_unit_t *sc_unit_alloc(uint8_t type, void *data)
{
  sc_unit_t *scu;
  if((scu = malloc_zero(sizeof(sc_unit_t))) == NULL ||
     (scu->node = dlist_node_alloc(scu)) == NULL)
    {
      if(scu != NULL) sc_unit_free(scu);
      return NULL;
    }
  scu->type = type;
  scu->data = data;
  return scu;
}

static void sc_message_free(sc_message_t *msg)
{
  if(msg->data != NULL) free(msg->data);
  free(msg);
  return;
}

static int sc_master_cmp(const sc_master_t *a, const sc_master_t *b)
{
  if(a->magic_len < b->magic_len) return -1;
  if(a->magic_len > b->magic_len) return  1;
  return memcmp(a->magic, b->magic, a->magic_len);
}

static void sc_master_onremove(sc_master_t *ms)
{
  ms->node = NULL;
  return;
}

static sc_channel_t *sc_master_channel_find(sc_master_t *ms, uint32_t id)
{
  dlist_node_t *dn;
  sc_channel_t *cn;
  for(dn=dlist_head_node(ms->channels); dn != NULL; dn=dlist_node_next(dn))
    {
      cn = dlist_node_item(dn);
      if(cn->id == id)
	return cn;
    }
  return NULL;
}

static void sc_master_channels_onremove(sc_channel_t *cn)
{
  cn->node = NULL;
  return;
}

static int sc_master_inet_write(sc_master_t *ms, void *ptr, uint16_t len,
				uint32_t sequence, uint32_t channel)
{
  uint8_t hdr[SC_MESSAGE_HDRLEN];

  /* form the header */
  bytes_htonl(hdr+0, sequence);
  bytes_htonl(hdr+4, channel);
  bytes_htons(hdr+8, len);

#ifdef HAVE_OPENSSL
  if(ms->inet_ssl != NULL)
    {
      SSL_write(ms->inet_ssl, hdr, SC_MESSAGE_HDRLEN);
      SSL_write(ms->inet_ssl, ptr, len);
      if(ssl_want_read(ms) < 0)
	{
	  remote_debug(__func__, "ssl_want_read failed");
	  return -1;
	}
      return 0;
    }
#endif

  if(scamper_writebuf_send(ms->inet_wb, hdr, SC_MESSAGE_HDRLEN) != 0 ||
     scamper_writebuf_send(ms->inet_wb, ptr, len) != 0)
    {
      remote_debug(__func__, "could not write message");
      return -1;
    }

  sc_fd_write_add(&ms->inet_fd);
  return 0;
}

/*
 * sc_master_inet_send
 *
 * transparently handle sending when an SSL socket could be used.
 */
static int sc_master_inet_send(sc_master_t *ms, void *ptr, uint16_t len,
			       uint32_t channel, int ack)
{
  sc_message_t *msg = NULL;
  uint32_t sequence;

  if(len == 0)
    {
      remote_debug(__func__, "invalid length %d", len);
      return -1;
    }

  if(ack == 0 && ms->mode == MASTER_MODE_CONNECT)
    return 0;

  /* get a copy of the sequence number before it might change */
  sequence = ms->snd_nxt;

  /* if we require the segment to be acknowledged, keep a copy of it */
  if(ack != 0)
    {
      if((msg = malloc(sizeof(sc_message_t))) == NULL)
	{
	  remote_debug(__func__, "could not malloc message");
	  goto err;
	}
      msg->data = NULL;
      if((msg->data = memdup(ptr, len)) == NULL)
	{
	  remote_debug(__func__, "could not dup data");
	  goto err;
	}
      msg->sequence = sequence;
      msg->channel = channel;
      msg->msglen = len;
      if(slist_tail_push(ms->messages, msg) == NULL)
	{
	  remote_debug(__func__, "could not push message");
	  goto err;
	}
      msg = NULL;
      ms->snd_nxt++;
    }

  if(ms->mode == MASTER_MODE_CONNECT)
    {
      remote_debug(__func__, "not sending in connect mode");
      return 0;
    }

  if(sc_master_inet_write(ms, ptr, len, sequence, channel) != 0)
    goto err;
  timeval_add_s(&ms->tx_ka, &now, 30);

  return 0;

 err:
  if(msg != NULL) sc_message_free(msg);
  return -1;
}

static void sc_master_inet_free(sc_master_t *ms)
{
  remote_debug(__func__, "%s", ms->name);

  if(ms->inet_fd.fd != -1)
    {
      sc_fd_read_del(&ms->inet_fd);
      sc_fd_write_del(&ms->inet_fd);
      close(ms->inet_fd.fd);
      ms->inet_fd.fd = -1;
    }
  if(ms->inet_wb != NULL)
    {
      scamper_writebuf_free(ms->inet_wb);
      ms->inet_wb = NULL;
    }

#ifdef HAVE_OPENSSL
  if(ms->inet_ssl != NULL)
    {
      SSL_free(ms->inet_ssl);
    }
  else
    {
      if(ms->inet_wbio != NULL)
	BIO_free(ms->inet_wbio);
      if(ms->inet_rbio != NULL)
	BIO_free(ms->inet_rbio);
    }
  ms->inet_ssl = NULL;
  ms->inet_wbio = NULL;
  ms->inet_rbio = NULL;
#endif

  return;
}

#ifdef HAVE_OPENSSL
static int sc_master_is_valid_client_cert_0(sc_master_t *ms)
{
  X509 *cert;

  /* if we aren't verifying client certificates, then move on... */
  if(tls_cafile == NULL)
    return 1;

  if(SSL_get_verify_result(ms->inet_ssl) != X509_V_OK)
    {
      remote_debug(__func__, "invalid certificate");
      return 0;
    }

  if((cert = SSL_get_peer_certificate(ms->inet_ssl)) == NULL)
    {
      remote_debug(__func__, "no peer certificate");
      return 0;
    }

  X509_free(cert);
  return 1;
}

static int sc_master_is_valid_client_cert_1(sc_master_t *ms)
{
  /* do not do name verification */
  if(tls_cafile == NULL || (flags & FLAG_SKIP_VERIF) != 0)
    return 1;

  /* if no monitorname, then cannot do name verification */
  if(ms->monitorname == NULL)
    {
      remote_debug(__func__, "no monitor name supplied");
      return 0;
    }

  return tls_is_valid_cert(ms->inet_ssl, ms->monitorname);
}
#endif /* HAVE_OPENSSL */

/*
 * sc_master_unix_create
 *
 * create a unix domain socket for the scamper instance, that local
 * users can connect to in order to interact with the remote scamper
 * instance.  The name of the socket is derived from getpeername on the
 * Internet socket, and the monitorname if the remote scamper supplied
 * that variable.
 */
static int sc_master_unix_create(sc_master_t *ms)
{
  struct sockaddr_un sn;
  mode_t mode;
  char sab[128], filename[65535], tmp[512];
  int fd;

  /*
   * these are set so that we know whether or not to take
   * responsibility for cleaning them up upon a failure condition.
   */
  fd = -1;
  filename[0] = '\0';

  /* figure out the name for the unix domain socket */
  if(sc_fd_peername(&ms->inet_fd, sab, sizeof(sab)) != 0)
    goto err;
  if(ms->monitorname != NULL)
    {
      snprintf(tmp, sizeof(tmp), "%s-%s", ms->monitorname, sab);
      ms->name = strdup(tmp);
    }
  else
    {
      ms->name = strdup(sab);
    }
  if(ms->name == NULL)
    {
      remote_debug(__func__, "could not strdup ms->name: %s", strerror(errno));
      goto err;
    }

  /* create a unix domain socket for the remote scamper process */
  if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
      remote_debug(__func__, "could not create unix socket: %s",
		   strerror(errno));
      goto err;
    }
  snprintf(filename, sizeof(filename), "%s/%s", unix_name, ms->name);
  if(sockaddr_compose_un((struct sockaddr *)&sn, filename) != 0)
    {
      filename[0] = '\0'; /* could not actually bind so no unlink */
      remote_debug(__func__, "could not compose socket: %s", strerror(errno));
      goto err;
    }
  if(bind(fd, (struct sockaddr *)&sn, sizeof(sn)) != 0)
    {
      filename[0] = '\0'; /* could not actually bind so no unlink */
      remote_debug(__func__, "could not bind unix socket: %s",strerror(errno));
      goto err;
    }

  /* set the requested permissions on the control sockets */
  mode = S_IRWXU;
  if(flags & FLAG_ALLOW_G) mode |= S_IRWXG;
  if(flags & FLAG_ALLOW_O) mode |= S_IRWXO;
  if(chmod(filename, mode) != 0)
    {
      remote_debug(__func__, "could not chmod: %s", strerror(errno));
      goto err;
    }

  if(listen(fd, -1) != 0)
    {
      remote_debug(__func__, "could not listen: %s", strerror(errno));
      goto err;
    }

  /*
   * at this point, allocate the unix_fd structure and take
   * responsibility for the socket and filesystem point
   */
  if((ms->unix_fd = sc_fd_alloc(fd, FD_TYPE_MASTER_UNIX, ms->unit)) == NULL)
    {
      remote_debug(__func__, "could not alloc unix fd: %s", strerror(errno));
      goto err;
    }
  filename[0] = '\0'; fd = -1;

  if(sc_fd_read_add(ms->unix_fd) != 0)
    {
      remote_debug(__func__, "could not monitor unix fd: %s", strerror(errno));
      goto err;
    }

  return 0;

 err:
  if(fd != -1) close(fd);
  if(filename[0] != '\0') unlink(filename);
  return -1;
}

static void sc_master_unix_free(sc_master_t *ms)
{
  char filename[65535];

  if(ms->unix_fd != NULL)
    {
      sc_fd_free(ms->unix_fd);
      ms->unix_fd = NULL;
      snprintf(filename, sizeof(filename), "%s/%s", unix_name, ms->name);
      unlink(filename);
    }

  return;
}

/*
 * sc_master_zombie
 *
 * there was an error reading or writing to the scamper-facing file
 * descriptor.  turn the master into a zombie for now, to allow scamper
 * to call back and resume.
 */
static void sc_master_zombie(sc_master_t *ms)
{
  if(ms->mode == MASTER_MODE_FLUSH)
    {
      sc_unit_gc(ms->unit);
      return;
    }
  ms->mode = MASTER_MODE_CONNECT;
  sc_master_unix_free(ms);
  sc_master_inet_free(ms);
  timeval_add_s(&ms->zombie, &now, zombie);
  remote_debug(__func__, "%s zombie until %ld", ms->name,
	       (long)ms->zombie.tv_sec);
  return;
}

static void sc_master_inet_write_do(sc_master_t *ms)
{
  /* if we did a read which returned -1, then inet_wb will be null */
  if(ms->inet_fd.fd == -1)
    return;
  assert(ms->inet_wb != NULL);

  if(scamper_writebuf_write(ms->inet_fd.fd, ms->inet_wb) != 0)
    goto zombie;

  if(scamper_writebuf_len(ms->inet_wb) == 0)
    {
      if(ms->mode == MASTER_MODE_FLUSH)
	{
	  sc_unit_gc(ms->unit);
	  return;
	}
      if(sc_fd_write_del(&ms->inet_fd) != 0)
	goto zombie;
    }

  return;

 zombie:
  if(zombie == 0 || ms->name == NULL)
    {
      sc_unit_gc(ms->unit);
      return;
    }
  sc_master_zombie(ms);
  return;
}

/*
 * sc_master_tx_keepalive
 *
 * send a keepalive.  do not expect an acknowledgement.
 */
static int sc_master_tx_keepalive(sc_master_t *ms)
{
  uint8_t buf[1];
  buf[0] = CONTROL_KEEPALIVE;
  return sc_master_inet_send(ms, buf, 1, 0, 0);
}

static int sc_master_tx_ack(sc_master_t *ms, uint32_t sequence)
{
  uint8_t buf[1+4];
  buf[0] = CONTROL_ACK;
  bytes_htonl(buf+1, sequence);
  return sc_master_inet_send(ms, buf, 5, 0, 0);
}

static int sc_master_tx_rej(sc_master_t *ms)
{
  uint8_t buf[1];
  ms->mode = MASTER_MODE_FLUSH;
  buf[0] = CONTROL_MASTER_REJ;
  if(sc_master_inet_send(ms, buf, 1, 0, 0) != 0)
    return -1;
  return 0;
}

/*
 * sc_master_control_master
 *
 * a remote scamper connection has said hello.
 * create a unix file descriptor to listen locally for drivers that want to
 * use it.
 *
 */
static int sc_master_control_master(sc_master_t *ms, uint8_t *buf, size_t len)
{
  char     sab[128];
  uint8_t  resp[1+1+128];
  uint8_t *magic = NULL;
  char    *monitorname = NULL;
  uint8_t  magic_len, monitorname_len, u8;
  size_t   off = 0;

  /* ensure that there is a magic value present */
  if(len == 0 || (magic_len = buf[off++]) == 0)
    {
      remote_debug(__func__, "magic value not found");
      goto err;
    }
  magic = buf + off;

  /* ensure the magic length value makes sense */
  if(len - off < magic_len)
    {
      remote_debug(__func__, "len %d - off %d < magic_len %u",
		   (int)len, (int)off, magic_len);
      goto err;
    }
  off += magic_len;

  /* check if there is a monitorname supplied */
  if(off < len && (monitorname_len = buf[off++]) > 0)
    {
      if(off + monitorname_len > len)
	{
	  remote_debug(__func__,
		       "malformed monitorname length variable: %d + %u > %d",
		       (int)off, monitorname_len, (int)len);
	  goto err;
	}
      monitorname = (char *)(buf+off);
      for(u8=0; u8<monitorname_len-1; u8++)
	{
	  if(monitorname[u8] != '.' && monitorname[u8] != '-' &&
	     isalnum((unsigned char)monitorname[u8]) == 0)
	    goto err;
	}
      if(monitorname[monitorname_len-1] != '\0')
	goto err;
      if((ms->monitorname = memdup(monitorname, monitorname_len)) == NULL)
	goto err;
      off += monitorname_len;
      assert(off <= len);
    }

#ifdef HAVE_OPENSSL
  /* verify the monitorname if we are verifying TLS client certificates */
  if(sc_master_is_valid_client_cert_1(ms) == 0)
    goto err;
#endif

  /* copy the magic value out.  check that the magic value is unique */
  if((ms->magic = memdup(magic, magic_len)) == NULL)
    {
      remote_debug(__func__, "could not memdup magic: %s", strerror(errno));
      goto err;
    }
  ms->magic_len = magic_len;
  if((ms->tree_node = splaytree_insert(mstree, ms)) == NULL)
    {
      remote_debug(__func__, "could not insert magic node into tree");
      goto err;
    }

  /* create the unix domain socket for the scamper instance */
  if(sc_master_unix_create(ms) != 0)
    goto err;

  /* send the list name to the client. do not expect an ack */
  if(sc_fd_peername(&ms->inet_fd, sab, sizeof(sab)) != 0)
    goto err;
  remote_debug(__func__, "%s", sab);
  ms->mode = MASTER_MODE_GO;
  off = strlen(sab);
  resp[0] = CONTROL_MASTER_ID;
  resp[1] = off + 1;
  memcpy(resp+2, sab, off + 1);
  if(sc_master_inet_send(ms, resp, 1 + 1 + off + 1, 0, 0) != 0)
    {
      remote_debug(__func__, "could not write ID: %s\n", strerror(errno));
      goto err;
    }

  return 0;

 err:
  return -1;
}

/*
 * sc_master_control_channel_fin
 *
 *
 */
static int sc_master_control_channel_fin(sc_master_t *ms,
					 uint8_t *buf, size_t len)
{
  sc_channel_t *cn;
  uint32_t id;

  if(len != 4)
    {
      remote_debug(__func__, "malformed channel fin: %u\n",(uint32_t)len);
      return -1;
    }

  id = bytes_ntohl(buf);
  if((cn = sc_master_channel_find(ms, id)) == NULL)
    {
      remote_debug(__func__, "could not find channel %u\n", id);
      return -1;
    }
  cn->flags |= CHANNEL_FLAG_EOF_RX;

  if(cn->unix_wb == NULL || scamper_writebuf_gtzero(cn->unix_wb) == 0)
    sc_unit_gc(cn->unit);
  else
    sc_fd_read_del(cn->unix_fd);

  return 0;
}

static int sc_master_control_keepalive(sc_master_t *ms,uint8_t *buf,size_t len)
{
  if(len != 0)
    {
      remote_debug(__func__, "malformed keepalive: %u", (uint32_t)len);
      return -1;
    }
  return 0;
}

static int sc_master_control_ack(sc_master_t *ms, uint8_t *buf, size_t len)
{
  uint32_t sequence;
  sc_message_t *msg;

  if(len != 4)
    {
      remote_debug(__func__, "malformed acknowledgement: %u", (uint32_t)len);
      return -1;
    }

  sequence = bytes_ntohl(buf);
  if((msg = slist_head_item(ms->messages)) == NULL)
    {
      remote_debug(__func__, "nothing to ack: %u", sequence);
      return -1;
    }
  if(msg->sequence != sequence)
    {
      remote_debug(__func__, "unexpected sequence: %u", sequence);
      return -1;
    }

  slist_head_pop(ms->messages);
  sc_message_free(msg);
  return 0;
}

static int sc_master_control_resume(sc_master_t *ms, uint8_t *buf, size_t len)
{
  sc_master_t fm, *ms2;
  sc_message_t *msg;
  slist_node_t *sn;
  uint8_t *magic = NULL, magic_len;
  size_t   off = 0;
  uint32_t rcv_nxt, snd_una, snd_nxt;
  uint8_t  ok[5];

  /* ensure that there is a magic value present */
  if(len == 0 || (magic_len = buf[off++]) == 0)
    {
      remote_debug(__func__, "magic value not found");
      goto err;
    }
  magic = buf + off;

  /* ensure the magic length value makes sense */
  if(off + magic_len > len)
    {
      remote_debug(__func__, "len %d - off %d < magic_len %u",
		   (int)len, (int)off, magic_len);
      goto err;
    }
  off += magic_len;

  /* ensure there is enough left for the three expected sequence numbers */
  if(len - off < 12)
    {
      remote_debug(__func__, "len %d - off %d < 12 for sequence",
		   (int)len, (int)off);
      goto err;
    }
  rcv_nxt = bytes_ntohl(buf+off); off += 4;
  snd_una = bytes_ntohl(buf+off); off += 4;
  snd_nxt = bytes_ntohl(buf+off); off += 4;
  assert(off <= len);

  /* see if we can find the control socket based on the magic value */
  fm.magic = magic;
  fm.magic_len = magic_len;
  if((ms2 = splaytree_find(mstree, &fm)) == NULL)
    {
      remote_debug(__func__, "could not find master given magic");
      if(sc_master_tx_rej(ms) != 0)
	goto err;
      goto done;
    }

  /*
   * check that the next segment of data that scamper expects from
   * remoted is reasonable
   */
  if(ms2->snd_nxt != rcv_nxt)
    {
      for(sn=slist_head_node(ms2->messages); sn != NULL; sn=slist_node_next(sn))
	{
	  msg = slist_node_item(sn);
	  if(msg->sequence == rcv_nxt)
	    break;
	}
      if(sn == NULL)
	{
	  remote_debug(__func__, "rcv_nxt value %u expected %u",
		       rcv_nxt, ms2->snd_nxt);
	  if(sc_master_tx_rej(ms) != 0)
	    goto err;
	  goto done;
	}
    }

  /*
   * check that the next segment of data that remoted expects from
   * scamper is reasonable
   */
  if(SEQ_GT(snd_una, ms2->rcv_nxt) || SEQ_GT(ms2->rcv_nxt, snd_nxt))
    {
      remote_debug(__func__,
		   "scamper's send window %u:%u not expected %u",
		   snd_una, snd_nxt, ms2->rcv_nxt);
      if(sc_master_tx_rej(ms) != 0)
	goto err;
      goto done;
    }

  /*
   * go through frames that have not been acknowledged, and remove the frames
   * that the remote controller already has
   */
  while((msg = slist_head_item(ms2->messages)) != NULL)
    {
      if(SEQ_LT(msg->sequence, rcv_nxt) == 0)
	break;
      msg = slist_head_pop(ms2->messages);
      sc_message_free(msg);
    }

  /* adjust state */
  ms2->tx_ka = ms->tx_ka;
  ms2->rx_abort = ms->rx_abort;
  ms2->zombie = ms->zombie;
  ms2->buf_offset = 0;

  /* switch over the file descriptors */
  sc_master_inet_free(ms2);
  sc_master_unix_free(ms2);
  ms2->inet_fd = ms->inet_fd;
  ms2->inet_fd.unit = ms2->unit;
  ms->inet_fd.fd = -1;
  ms2->inet_wb = ms->inet_wb; ms->inet_wb = NULL;
#ifdef HAVE_OPENSSL
  ms2->inet_mode = ms->inet_mode;
  ms2->inet_ssl  = ms->inet_ssl;  ms->inet_ssl = NULL;
  ms2->inet_rbio = ms->inet_rbio; ms->inet_rbio = NULL;
  ms2->inet_wbio = ms->inet_wbio; ms->inet_wbio = NULL;
#endif

  if(ms2->inet_fd.flags & FD_FLAG_READ)
    {
      sc_fd_read_del(&ms2->inet_fd);
      sc_fd_read_add(&ms2->inet_fd);
    }
  if(ms2->inet_fd.flags & FD_FLAG_WRITE)
    {
      sc_fd_write_del(&ms2->inet_fd);
      sc_fd_write_add(&ms2->inet_fd);
    }

  /* create a new unix domain socket */
  if(sc_master_unix_create(ms2) != 0)
    goto err;

  /*
   * don't need the incoming sc_master_t, as we've switched the file
   * descriptors over.
   */
  sc_unit_gc(ms->unit);

  /* send an OK message to the scamper instance */
  ms2->mode = MASTER_MODE_GO;
  ok[0] = CONTROL_MASTER_OK;
  bytes_htonl(ok+1, ms2->rcv_nxt);
  if(sc_master_inet_write(ms2, ok, 5, 0, 0) != 0)
    goto err;
  remote_debug(__func__, "ok");

  for(sn=slist_head_node(ms2->messages); sn != NULL; sn=slist_node_next(sn))
    {
      msg = slist_node_item(sn);
      if(sc_master_inet_write(ms2, msg->data, msg->msglen, msg->sequence,
			      msg->channel) != 0)
	goto err;
    }

 done:
  return 0;

 err:
  return -1;
}

static int sc_master_control(sc_master_t *ms)
{
  uint32_t seq;
  uint16_t msglen;
  uint8_t type, *buf;

  seq = bytes_ntohl(ms->buf);
  msglen = bytes_ntohs(ms->buf+8);
  buf = ms->buf + SC_MESSAGE_HDRLEN;

  if(msglen < 1)
    {
      remote_debug(__func__, "malformed control msg: %u", msglen);
      return -1;
    }

  type = buf[0];
  buf++; msglen--;

  if(ms->mode == MASTER_MODE_CONNECT)
    {
      /* we expect sequence zero.  no acks for any of these messages. */
      if(seq != 0)
	{
	  remote_debug(__func__, "expected sequence zero in mode connect");
	  return -1;
	}
      switch(type)
	{
	case CONTROL_MASTER_NEW:
	  return sc_master_control_master(ms, buf, msglen);
	case CONTROL_MASTER_RES:
	  return sc_master_control_resume(ms, buf, msglen);
	}
    }
  else if(ms->mode == MASTER_MODE_GO)
    {
      /* check the sequence number is what we expect */
      if(seq != ms->rcv_nxt)
	{
	  remote_debug(__func__, "got seq %u expected %u", seq, ms->rcv_nxt);
	  return -1;
	}

      if(type == CONTROL_CHANNEL_FIN)
	{
	  if(sc_master_tx_ack(ms, seq) != 0)
	    return -1;
	  ms->rcv_nxt++;
	}

      switch(type)
	{
	case CONTROL_CHANNEL_FIN:
	  return sc_master_control_channel_fin(ms, buf, msglen);
	case CONTROL_KEEPALIVE:
	  return sc_master_control_keepalive(ms, buf, msglen);
	case CONTROL_ACK:
	  return sc_master_control_ack(ms, buf, msglen);
	}
    }

  remote_debug(__func__, "unhandled type %d", type);
  return -1;
}

/*
 * sc_master_inet_read_cb
 *
 * process data from the master inet-facing socket.  the data has been
 * through the SSL decoding routines, if necessary.
 *
 * todo: make this zero copy when the entire message is intact in the buf.
 */
static void sc_master_inet_read_cb(sc_master_t *ms, uint8_t *buf, size_t len)
{
  sc_channel_t *channel;
  uint32_t seq, id;
  uint16_t msglen, x, y;
  size_t off = 0;
  uint8_t *ptr;

  while(off < len)
    {
      /* to start with, ensure that we have a complete header */
      while(ms->buf_offset < SC_MESSAGE_HDRLEN && off < len)
	ms->buf[ms->buf_offset++] = buf[off++];
      if(off == len)
	return;

      /* figure out how large the message is supposed to be */
      seq = bytes_ntohl(ms->buf);
      id = bytes_ntohl(ms->buf+4);
      msglen = bytes_ntohs(ms->buf+8);

      /* ensure the sequence number is what we expect */
      if(seq != ms->rcv_nxt)
	{
	  remote_debug(__func__, "got seq %u expected %u", seq, ms->rcv_nxt);
	  goto err;
	}

      /* check the channel id is valid */
      channel = NULL;
      if(id != 0 && (channel = sc_master_channel_find(ms, id)) == NULL)
	{
	  remote_debug(__func__, "could not find channel %u", id);
	  goto err;
	}

      /* figure out how to build the message */
      x = msglen - (ms->buf_offset - SC_MESSAGE_HDRLEN);
      y = len - off;

      if(y < x)
	{
	  /* if we cannot complete the message, buffer what we have */
	  memcpy(ms->buf + ms->buf_offset, buf+off, y);
	  ms->buf_offset += y;
	  return;
	}

      /* we now have a complete message */
      memcpy(ms->buf + ms->buf_offset, buf+off, x);
      off += x;

      /* reset the buf_offset for the next message */
      ms->buf_offset = 0;

      /* get a pointer to the data */
      ptr = ms->buf + SC_MESSAGE_HDRLEN;

      /* if the message is a control message */
      if(id == 0)
	{
	  if(sc_master_control(ms) != 0)
	    goto err;
	  continue;
	}

      if(sc_master_tx_ack(ms, seq) != 0)
	goto err;
      ms->rcv_nxt++;

      /* the unix domain socket may have gone away but we need to flush */
      if(channel->unix_wb != NULL)
	{
	  if(scamper_writebuf_send(channel->unix_wb, ptr, msglen) != 0)
	    sc_unit_gc(channel->unit);
	  sc_fd_write_add(channel->unix_fd);
	}
    }

  return;

 err:
  sc_unit_gc(ms->unit);
  return;
}

/*
 * sc_master_inet_read_do
 *
 */
static void sc_master_inet_read_do(sc_master_t *ms)
{
  ssize_t rrc;
  uint8_t buf[4096];

#ifdef HAVE_OPENSSL
  int rc;
#endif

  if((rrc = read(ms->inet_fd.fd, buf, sizeof(buf))) < 0)
    {
      if(errno == EAGAIN || errno == EINTR)
	return;
      remote_debug(__func__, "read failed: %s", strerror(errno));
      goto zombie;
    }

  if(rrc == 0)
    {
      remote_debug(__func__, "%s disconnected", ms->name);
      goto zombie;
    }

  timeval_add_s(&ms->rx_abort, &now, 60);

#ifdef HAVE_OPENSSL
  if(ms->inet_ssl != NULL)
    {
      BIO_write(ms->inet_rbio, buf, rrc);
      ERR_clear_error();

      if(ms->inet_mode == SSL_MODE_ACCEPT)
	{
	  if((rc = SSL_accept(ms->inet_ssl)) > 0)
	    {
	      ms->inet_mode = SSL_MODE_ESTABLISHED;
	      if(ssl_want_read(ms) < 0)
		{
		  remote_debug(__func__, "ssl_want_read failed");
		  goto err;
		}
	      if(sc_master_is_valid_client_cert_0(ms) == 0)
		goto err;
	    }
	}

      /*
       * equivalent to checking if ms->inet_mode == SSL_MODE_ESTABLISHED,
       * but silenced warning about rc possibly being used without
       * first being initialised
       */
      if(ms->inet_mode != SSL_MODE_ACCEPT)
	{
	  assert(ms->inet_mode == SSL_MODE_ESTABLISHED);
	  while((rc = SSL_read(ms->inet_ssl, buf, sizeof(buf))) > 0)
	    {
	      sc_master_inet_read_cb(ms, buf, (size_t)rc);
	      /*
	       * the callback function might end up disconnecting the
	       * SSL connection
	       */
	      if(ms->inet_ssl == NULL)
		return;
	    }
	}

      if((rc = SSL_get_error(ms->inet_ssl, rc)) == SSL_ERROR_WANT_READ)
	{
	  if(ssl_want_read(ms) < 0)
	    {
	      remote_debug(__func__, "ssl_want_read failed");
	      goto err;
	    }
	}
      else if(rc != SSL_ERROR_WANT_WRITE)
	{
	  remote_debug(__func__, "mode %s rc %d",
		       ms->inet_mode == SSL_MODE_ACCEPT ? "accept" : "estab",
		       rc);
	  goto err;
	}

      return;
    }
#endif

  sc_master_inet_read_cb(ms, buf, (size_t)rrc);
  return;

  /* if we are keeping state for disconnected scamper instances */
 zombie:
  if(zombie == 0 || ms->name == NULL)
    sc_unit_gc(ms->unit);
  else
    sc_master_zombie(ms);
  return;

#ifdef HAVE_OPENSSL
 err:
  sc_unit_gc(ms->unit);
  return;
#endif
}

/*
 * sc_master_unix_accept_do
 *
 * a local process has connected to the unix domain socket that
 * corresponds to a remote scamper process.  accept the socket and
 * cause the remote scamper process to create a new channel.
 */
static void sc_master_unix_accept_do(sc_master_t *ms)
{
  struct sockaddr_storage ss;
  socklen_t socklen = sizeof(ss);
  sc_channel_t *cn = NULL;
  uint8_t msg[1+4];
  int s = -1;

  if((s = accept(ms->unix_fd->fd, (struct sockaddr *)&ss, &socklen)) == -1)
    {
      remote_debug(__func__, "accept failed: %s", strerror(errno));
      goto err;
    }

  if((cn = malloc_zero(sizeof(sc_channel_t))) == NULL)
    goto err;
  cn->id = ms->next_channel++;
  if(ms->next_channel == 0)
    ms->next_channel++;

  /* allocate a unit to describe this structure */
  if((cn->unit = sc_unit_alloc(UNIT_TYPE_CHANNEL, cn)) == NULL)
    {
      remote_debug(__func__, "could not alloc unit: %s", strerror(errno));
      goto err;
    }

  if((cn->unix_fd = sc_fd_alloc(s, FD_TYPE_CHANNEL_UNIX, cn->unit)) == NULL)
    {
      remote_debug(__func__, "could not alloc unix_fd: %s", strerror(errno));
      goto err;
    }
  s = -1;
  sc_fd_read_add(cn->unix_fd);

  if((cn->unix_wb = scamper_writebuf_alloc()) == NULL)
    goto err;
  if((cn->node = dlist_tail_push(ms->channels, cn)) == NULL)
    goto err;
  cn->master = ms;

  /* send a new channel message to scamper. expect an acknowledgement */
  msg[0] = CONTROL_CHANNEL_NEW;
  bytes_htonl(msg+1, cn->id);
  if(sc_master_inet_send(ms, msg, 1 + 4, 0, 1) != 0)
    goto err;

  return;

 err:
  if(s != -1) close(s);
  if(cn != NULL) sc_channel_free(cn);
  return;
}

/*
 * sc_master_free
 *
 * clean up the sc_master_t.
 */
static void sc_master_free(sc_master_t *ms)
{
  if(ms == NULL)
    return;

  sc_master_unix_free(ms);

  if(ms->channels != NULL)
    dlist_free_cb(ms->channels, (dlist_free_t)sc_channel_free);
  if(ms->messages != NULL)
    slist_free_cb(ms->messages, (slist_free_t)sc_message_free);

  if(ms->unit != NULL) sc_unit_free(ms->unit);

  sc_master_inet_free(ms);

  if(ms->tree_node != NULL) splaytree_remove_node(mstree, ms->tree_node);
  if(ms->name != NULL) free(ms->name);
  if(ms->monitorname != NULL) free(ms->monitorname);
  if(ms->magic != NULL) free(ms->magic);
  if(ms->node != NULL) dlist_node_pop(mslist, ms->node);
  free(ms);
  return;
}

static sc_master_t *sc_master_alloc(int fd)
{
  sc_master_t *ms = NULL;

#ifdef HAVE_OPENSSL
  int rc;
#endif

  if((ms = malloc_zero(sizeof(sc_master_t))) == NULL)
    return NULL;
  ms->inet_fd.fd = fd; fd = -1;
  ms->inet_fd.type = FD_TYPE_MASTER_INET;

  if((ms->channels = dlist_alloc()) == NULL)
    {
      remote_debug(__func__, "could not alloc channels: %s", strerror(errno));
      goto err;
    }
  dlist_onremove(ms->channels, (dlist_onremove_t)sc_master_channels_onremove);
  ms->next_channel = 1;

  /* allocate a unit to describe this */
  if((ms->unit = sc_unit_alloc(UNIT_TYPE_MASTER, ms)) == NULL)
    {
      remote_debug(__func__, "could not alloc unit: %s", strerror(errno));
      goto err;
    }
  ms->inet_fd.unit = ms->unit;

  if((ms->inet_wb = scamper_writebuf_alloc()) == NULL)
    {
      remote_debug(__func__, "could not alloc wb: %s", strerror(errno));
      goto err;
    }

  if((ms->messages = slist_alloc()) == NULL)
    {
      remote_debug(__func__, "could not alloc messages: %s", strerror(errno));
      goto err;
    }

#ifdef HAVE_OPENSSL
  if(tls_certfile != NULL)
    {
      if((ms->inet_wbio = BIO_new(BIO_s_mem())) == NULL ||
	 (ms->inet_rbio = BIO_new(BIO_s_mem())) == NULL ||
	 (ms->inet_ssl = SSL_new(tls_ctx)) == NULL)
	{
	  remote_debug(__func__, "could not alloc SSL");
	  goto err;
	}
      SSL_set_bio(ms->inet_ssl, ms->inet_rbio, ms->inet_wbio);
      SSL_set_accept_state(ms->inet_ssl);
      rc = SSL_accept(ms->inet_ssl);
      assert(rc == -1);
      if((rc = SSL_get_error(ms->inet_ssl, rc)) != SSL_ERROR_WANT_READ)
	{
	  remote_debug(__func__, "unexpected %d from SSL_accept", rc);
	  goto err;
	}
      if(ssl_want_read(ms) < 0)
	goto err;
    }
#endif

  return ms;

 err:
  if(ms != NULL) sc_master_free(ms);
  if(fd != -1) close(fd);
  return NULL;
}

/*
 * sc_channel_unix_write_do
 *
 * we can write to the unix fd without blocking, so do so.
 */
static void sc_channel_unix_write_do(sc_channel_t *cn)
{
  /* if we did a read which returned -1, then the unix_fd will be null */
  if(cn->unix_fd == NULL)
    return;

  if(scamper_writebuf_write(cn->unix_fd->fd, cn->unix_wb) != 0)
    {
      remote_debug(__func__, "write to %s channel %u failed",
		   cn->master->name, cn->id);
      goto err;
    }

  /*
   * if we still have data to write, then wait until we get signal to
   * write again
   */
  if(scamper_writebuf_gtzero(cn->unix_wb) != 0)
    return;

  /* nothing more to write, so remove fd */
  if(sc_fd_write_del(cn->unix_fd) != 0)
    {
      remote_debug(__func__, "could not delete unix write for %s channel %u",
		   cn->master->name, cn->id);
      goto err;
    }

  /* got an EOF, so we're done now */
  if((cn->flags & CHANNEL_FLAG_EOF_RX) != 0)
    {
      remote_debug(__func__, "received EOF for %s channel %u",
		   cn->master->name, cn->id);
      sc_unit_gc(cn->unit);
      return;
    }

  return;

 err:
  /* got an error trying to write, so we're done */
  sc_fd_free(cn->unix_fd); cn->unix_fd = NULL;
  scamper_writebuf_free(cn->unix_wb); cn->unix_wb = NULL;

  /* we've received an EOF, we're done */
  if((cn->flags & CHANNEL_FLAG_EOF_RX) != 0)
    {
      sc_unit_gc(cn->unit);
      return;
    }
  return;
}

/*
 * sc_channel_unix_read_do
 *
 * a local client process has written to a unix domain socket, which
 * we will process line by line.
 */
static void sc_channel_unix_read_do(sc_channel_t *cn)
{
  ssize_t rc;
  uint8_t buf[4096];

  if((rc = read(cn->unix_fd->fd, buf, sizeof(buf))) <= 0)
    {
      if(rc == -1 && (errno == EAGAIN || errno == EINTR))
	return;

      /* send an EOF if we haven't tx'd or rx'd an EOF. expect an ack */
      if((cn->flags & (CHANNEL_FLAG_EOF_RX|CHANNEL_FLAG_EOF_TX)) == 0)
	{
	  buf[0] = CONTROL_CHANNEL_FIN;
	  bytes_htonl(buf+1, cn->id);
	  sc_master_inet_send(cn->master, buf, 5, 0, 1);
	  cn->flags |= CHANNEL_FLAG_EOF_TX;
	}

      /* if we've received an EOF, we're done */
      if((cn->flags & CHANNEL_FLAG_EOF_RX) != 0)
	{
	  sc_unit_gc(cn->unit);
	  return;
	}

      /*
       * if we've received an error, close down the file descriptor
       * and write buf.  we keep the channel around so that when we
       * receive an EOF, we can match it and clean it up.
       */
      if(rc == -1)
	{
	  sc_fd_free(cn->unix_fd); cn->unix_fd = NULL;
	  scamper_writebuf_free(cn->unix_wb); cn->unix_wb = NULL;
	}
      else
	{
	  sc_fd_read_del(cn->unix_fd);
	}
      return;
    }

  /* send the message to scamper, expecting an acknowledgement */
  sc_master_inet_send(cn->master, buf, rc, cn->id, 1);

  return;
}

static void sc_channel_free(sc_channel_t *cn)
{
  if(cn == NULL)
    return;
  if(cn->master != NULL && cn->node != NULL)
    dlist_node_pop(cn->master->channels, cn->node);
  if(cn->unix_fd != NULL) sc_fd_free(cn->unix_fd);
  if(cn->unix_lp != NULL) scamper_linepoll_free(cn->unix_lp, 0);
  if(cn->unix_wb != NULL) scamper_writebuf_free(cn->unix_wb);
  if(cn->unit != NULL) sc_unit_free(cn->unit);
  free(cn);
  return;
}

/*
 * serversocket_accept
 *
 * a new connection has arrived.  accept the new connection while we wait
 * to understand the intention behind the socket.
 */
static int serversocket_accept(int ss)
{
  struct sockaddr_storage sas;
  sc_master_t *ms = NULL;
  socklen_t slen;
  int inet_fd = -1;
  char buf[256];

  slen = sizeof(ss);
  if((inet_fd = accept(ss, (struct sockaddr *)&sas, &slen)) == -1)
    {
      remote_debug(__func__, "could not accept: %s", strerror(errno));
      goto err;
    }
  if(fcntl_set(inet_fd, O_NONBLOCK) == -1)
    {
      remote_debug(__func__, "could not set O_NONBLOCK: %s", strerror(errno));
      goto err;
    }

  ms = sc_master_alloc(inet_fd);
  inet_fd = -1;
  if(ms == NULL)
    goto err;

  if(sc_fd_peername(&ms->inet_fd, buf, sizeof(buf)) == 0)
    remote_debug(__func__, "%s", buf);

  if(sc_fd_read_add(&ms->inet_fd) != 0)
    {
      remote_debug(__func__, "could not monitor inet fd: %s", strerror(errno));
      goto err;
    }

  timeval_add_s(&ms->rx_abort, &now, 30);
  timeval_cpy(&ms->tx_ka, &ms->rx_abort);

  if((ms->node = dlist_tail_push(mslist, ms)) == NULL)
    {
      remote_debug(__func__, "could not push to mslist: %s", strerror(errno));
      goto err;
    }

  return 0;

 err:
  if(inet_fd != -1) close(inet_fd);
  if(ms != NULL) sc_master_free(ms);
  return -1;
}

static int serversocket_init_sa(const struct sockaddr *sa)
{
  char buf[256];
  int opt, fd = -1;

  if((fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
      remote_debug(__func__, "could not open %s socket: %s",
		   sa->sa_family == AF_INET ? "ipv4" : "ipv6", strerror(errno));
      goto err;
    }

  opt = 1;
  if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt)) != 0)
    {
      remote_debug(__func__, "could not set SO_REUSEADDR on %s socket: %s",
		   sa->sa_family == AF_INET ? "ipv4" : "ipv6", strerror(errno));
      goto err;
    }

#ifdef IPV6_V6ONLY
  if(sa->sa_family == PF_INET6)
    {
      opt = 1;
      if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
		    (void *)&opt, sizeof(opt)) != 0)
	{
	  remote_debug(__func__, "could not set IPV6_V6ONLY: %s",
		       strerror(errno));
	  goto err;
	}
    }
#endif

  if(bind(fd, sa, sockaddr_len(sa)) != 0)
    {
      remote_debug(__func__, "could not bind %s socket to %s: %s",
		   sa->sa_family == AF_INET ? "ipv4" : "ipv6",
		   sockaddr_tostr(sa, buf, sizeof(buf)), strerror(errno));
      goto err;
    }

  if(listen(fd, -1) != 0)
    {
      remote_debug(__func__, "could not listen %s socket: %s",
		   sa->sa_family == AF_INET ? "ipv4" : "ipv6", strerror(errno));
      goto err;
    }

  return fd;

 err:
  if(fd != -1) close(fd);
  return -1;
}

/*
 * serversocket_init
 *
 * create two sockets so that we can use both IPv4 and IPv6 for incoming
 * connections from remote scamper processes.
 */
static int serversocket_init(void)
{
  struct sockaddr_storage sas;
  int i, pf, fd, x;

  if(ss_addr != NULL)
    {
      if(sockaddr_compose_str((struct sockaddr *)&sas, ss_addr, ss_port) != 0)
	{
	  remote_debug(__func__, "could not compose sockaddr");
	  return -1;
	}
      if((fd = serversocket_init_sa((struct sockaddr *)&sas)) == -1)
	return -1;
      serversockets[0] = fd;
      return 0;
    }

  x = 0;
  for(i=0; i<2; i++)
    {
      pf = i == 0 ? PF_INET : PF_INET6;
      if((pf == PF_INET  && (options & OPT_IPV6) != 0) ||
	 (pf == PF_INET6 && (options & OPT_IPV4) != 0))
	continue;

      sockaddr_compose((struct sockaddr *)&sas, pf, NULL, ss_port);
      if((fd = serversocket_init_sa((struct sockaddr *)&sas)) == -1)
	return -1;
      serversockets[x++] = fd;
    }

  return 0;
}

/*
 * unixdomain_direxists
 *
 * make sure the directory specified actually exists
 */
static int unixdomain_direxists(void)
{
  struct stat sb;
  if(stat(unix_name, &sb) != 0)
    {
      usage(OPT_UNIX);
      remote_debug(__func__,"could not stat %s: %s",unix_name,strerror(errno));
      return -1;
    }
  if((sb.st_mode & S_IFDIR) != 0)
    return 0;
  usage(OPT_UNIX);
  remote_debug(__func__, "%s is not a directory", unix_name);
  return -1;
}

static void cleanup(void)
{
  int i;

  for(i=0; i<2; i++)
    close(serversockets[i]);

  if(ss_addr != NULL)
    free(ss_addr);
  if(mslist != NULL)
    dlist_free_cb(mslist, (dlist_free_t)sc_master_free);
  if(mstree != NULL)
    splaytree_free(mstree, NULL);

#ifdef HAVE_OPENSSL
  if(tls_ctx != NULL) SSL_CTX_free(tls_ctx);
#endif

  if(gclist != NULL) dlist_free(gclist);

  if(pidfile != NULL)
    {
      unlink(pidfile);
      free(pidfile);
    }

#ifdef HAVE_EPOLL
  if(epfd != -1) close(epfd);
#endif

#ifdef HAVE_KQUEUE
  if(kqfd != -1) close(kqfd);
#endif

  return;
}

#ifdef HAVE_OPENSSL
static int remoted_tlsctx(void)
{
  STACK_OF(X509_NAME) *cert_names;

  if((tls_ctx = SSL_CTX_new(SSLv23_method())) == NULL)
    return -1;

  /* load the server key materials */
  if(SSL_CTX_use_certificate_chain_file(tls_ctx,tls_certfile)!=1)
    {
      remote_debug(__func__, "could not SSL_CTX_use_certificate_file");
      ERR_print_errors_fp(stderr);
      return -1;
    }
  if(SSL_CTX_use_PrivateKey_file(tls_ctx,tls_privfile,SSL_FILETYPE_PEM)!=1)
    {
      remote_debug(__func__, "could not SSL_CTX_use_PrivateKey_file");
      ERR_print_errors_fp(stderr);
      return -1;
    }

  if(tls_cafile != NULL)
    {
      /* load the materials to verify client certificates */
      if(SSL_CTX_load_verify_locations(tls_ctx, tls_cafile, NULL) != 1)
	{
	  remote_debug(__func__, "could not SSL_CTX_load_verify_locations");
	  ERR_print_errors_fp(stderr);
	  return -1;
	}
      if((cert_names = SSL_load_client_CA_file(tls_cafile)) == NULL)
	{
	  remote_debug(__func__, "could not SSL_load_client_CA_file");
	  ERR_print_errors_fp(stderr);
	  return -1;
	}
      SSL_CTX_set_client_CA_list(tls_ctx, cert_names);
      SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER, NULL);
    }
  else
    {
      SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_NONE, NULL);
    }
  SSL_CTX_set_options(tls_ctx,
		      SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
		      SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
  return 0;
}

static int remoted_tlsctx_reload(void)
{
  if(tls_ctx == NULL)
    return 0;
  SSL_CTX_free(tls_ctx); tls_ctx = NULL;
  return remoted_tlsctx();
}
#endif

static int remoted_pidfile(void)
{
  char buf[32];
  size_t len;
  int fd, fd_flags = O_WRONLY | O_TRUNC | O_CREAT;

#ifndef _WIN32 /* windows does not have getpid */
  pid_t pid = getpid();
#else
  DWORD pid = GetCurrentProcessId();
#endif

  if((fd = open(pidfile, fd_flags, MODE_644)) == -1)
    {
      remote_debug(__func__, "could not open %s: %s", pidfile, strerror(errno));
      return -1;
    }

  snprintf(buf, sizeof(buf), "%ld\n", (long)pid);
  len = strlen(buf);
  if(write_wrap(fd, buf, NULL, len) != 0)
    {
      remote_debug(__func__, "could not write pid: %s", strerror(errno));
      goto err;
    }
  close(fd);

  return 0;

 err:
  if(fd != -1) close(fd);
  return -1;
}

#ifdef HAVE_SIGACTION
static void remoted_sigaction(int sig)
{
  if(sig == SIGHUP)
    reload = 1;
  else if(sig == SIGINT)
    stop = 1;
  return;
}
#endif

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
#if defined(HAVE_EPOLL)
static int epoll_loop(void)
#else
static int kqueue_loop(void)
#endif
{
#if defined(HAVE_EPOLL)
  struct epoll_event events[1024];
  int events_c = sizeof(events) / sizeof(struct epoll_event);
  int timeout;
#else
  struct kevent events[1024];
  int events_c = sizeof(events) / sizeof(struct kevent);
  struct timespec ts, *timeout;
#endif
  struct timeval tv, to, *tvp;
  sc_master_t *ms;
  dlist_node_t *dn;
  sc_fd_t *scfd, scfd_ss[2];
  sc_unit_t *scu;
  int i, rc;

#if defined(HAVE_EPOLL)
  if((epfd = epoll_create(1000)) == -1)
    {
      remote_debug(__func__, "epoll_create failed: %s", strerror(errno));
      return -1;
    }
#else
  if((kqfd = kqueue()) == -1)
    {
      remote_debug(__func__, "kqueue failed: %s", strerror(errno));
      return -1;
    }
#endif

  /* add the server sockets to the poll set */
  memset(&scfd_ss, 0, sizeof(scfd_ss));
  for(i=0; i<2; i++)
    {
      if(serversockets[i] == -1)
	continue;
      scfd_ss[i].type = FD_TYPE_SERVER;
      scfd_ss[i].fd = serversockets[i];
      if(sc_fd_read_add(&scfd_ss[i]) != 0)
	return -1;
    }

  /* main event loop */
  while(stop == 0)
    {
      if(reload != 0)
	{
	  reload = 0;
#ifdef HAVE_OPENSSL
	  if(remoted_tlsctx_reload() != 0)
	    return -1;
#endif
	}

#if defined(HAVE_EPOLL)
      timeout = -1;
#else
      timeout = NULL;
#endif
      rc = 0;
      if((dn = dlist_head_node(mslist)) != NULL)
	{
	  gettimeofday_wrap(&now);

	  /* to start with, handle keepalives */
	  while(dn != NULL)
	    {
	      ms = dlist_node_item(dn);
	      dn = dlist_node_next(dn);

	      /* check if it is time to take care of a zombie */
	      if(ms->inet_fd.fd == -1)
		{
		  if(timeval_cmp(&now, &ms->zombie) < 0)
		    {
		      timeval_diff_tv(&tv, &now, &ms->zombie);
		      goto set_timeout;
		    }
		  remote_debug(__func__, "removing %s zombie", ms->name);
		  sc_master_free(ms);
		  continue;
		}

	      /* if the connection has gone silent, abort */
	      if(timeval_cmp(&now, &ms->rx_abort) >= 0)
		{
		  if(zombie > 0 && ms->name != NULL)
		    {
		      sc_master_zombie(ms);
		      timeval_diff_tv(&tv, &now, &ms->zombie);
		      goto set_timeout;
		    }
		  sc_master_free(ms);
		  continue;
		}

	      /*
	       * ensure we send something every 30 seconds.
	       * unix_fd being not null signifies the remote controller
	       * has received an opening "master" frame.
	       */
	      if(ms->unix_fd != NULL && timeval_cmp(&now, &ms->tx_ka) >= 0)
		{
		  timeval_add_s(&ms->tx_ka, &now, 30);
		  if(sc_master_tx_keepalive(ms) != 0)
		    {
		      sc_master_free(ms);
		      continue;
		    }
		}

	      /* now figure out timeout to set */
	      if(timeval_cmp(&ms->rx_abort, &ms->tx_ka) <= 0)
		tvp = &ms->rx_abort;
	      else
		tvp = &ms->tx_ka;
	      if(timeval_cmp(&now, tvp) <= 0)
		timeval_diff_tv(&tv, &now, tvp);
	      else
		memset(&tv, 0, sizeof(tv));

	    set_timeout:
	      if(rc == 0)
		{
		  timeval_cpy(&to, &tv);
		  rc++;
		}
	      else
		{
		  if(timeval_cmp(&tv, &to) < 0)
		    timeval_cpy(&to, &tv);
		}
	    }
	}

#if defined(HAVE_EPOLL)
      if(rc != 0)
	{
	  timeout = (to.tv_sec * 1000) + (to.tv_usec / 1000);
	  if(timeout == 0 && to.tv_usec != 0)
	    timeout++;
	}
      if((rc = epoll_wait(epfd, events, events_c, timeout)) == -1)
	{
	  if(errno == EINTR)
	    continue;
	  remote_debug(__func__, "epoll_wait failed: %s", strerror(errno));
	  return -1;
	}
#else
      if(rc != 0)
	{
	  ts.tv_sec = to.tv_sec;
	  ts.tv_nsec = to.tv_usec * 1000;
	  timeout = &ts;
	}
      if((rc = kevent(kqfd, NULL, 0, events, events_c, timeout)) == -1)
	{
	  if(errno == EINTR)
	    continue;
	  remote_debug(__func__, "kevent failed: %s", strerror(errno));
	  return -1;
	}
#endif

      gettimeofday_wrap(&now);

      for(i=0; i<rc; i++)
	{
#if defined(HAVE_EPOLL)
	  scfd = events[i].data.ptr;
#else
	  scfd = events[i].udata;
#endif

	  if((scu = scfd->unit) == NULL)
	    {
	      serversocket_accept(scfd->fd);
	      continue;
	    }

#if defined(HAVE_EPOLL)
	  if(events[i].events & (EPOLLIN|EPOLLHUP) && scu->gc == 0)
	    read_cb[scfd->type](scu->data);
	  if(events[i].events & EPOLLOUT && scu->gc == 0)
	    write_cb[scfd->type](scu->data);
#else
	  if(scu->gc != 0)
	    {
	      assert(scu->list == gclist);
	      continue;
	    }
	  if(events[i].filter == EVFILT_READ)
	    read_cb[scfd->type](scu->data);
	  else if(events[i].filter == EVFILT_WRITE)
	    write_cb[scfd->type](scu->data);
#endif
	}

      while((scu = dlist_head_pop(gclist)) != NULL)
	unit_gc[scu->type](scu->data);
    }

  return 0;
}
#endif

static int select_loop(void)
{
  struct timeval tv, to, *timeout, *tvp;
  fd_set rfds;
  fd_set wfds, *wfdsp;
  int i, count, nfds;
  dlist_node_t *dn, *dn2;
  sc_master_t *ms;
  sc_channel_t *cn;
  sc_unit_t *scu;

  while(stop == 0)
    {
      if(reload != 0)
	{
	  reload = 0;
#ifdef HAVE_OPENSSL
	  if(remoted_tlsctx_reload() != 0)
	    return -1;
#endif
	}

      FD_ZERO(&rfds); FD_ZERO(&wfds);
      wfdsp = NULL; nfds = -1; timeout = NULL;

      for(i=0; i<2; i++)
	{
	  if(serversockets[i] == -1)
	    continue;
	  FD_SET(serversockets[i], &rfds);
	  if(serversockets[i] > nfds)
	    nfds = serversockets[i];
	}

      if((dn = dlist_head_node(mslist)) != NULL)
	{
	  gettimeofday_wrap(&now);

	  /* to start with, handle keepalives */
	  while(dn != NULL)
	    {
	      ms = dlist_node_item(dn);
	      dn = dlist_node_next(dn);

	      /* check if it is time to take care of a zombie */
	      if(ms->inet_fd.fd == -1)
		{
		  if(timeval_cmp(&now, &ms->zombie) < 0)
		    {
		      timeval_diff_tv(&tv, &now, &ms->zombie);
		      goto set_timeout;
		    }
		  remote_debug(__func__, "removing %s zombie", ms->name);
		  sc_master_free(ms);
		  continue;
		}

	      /* if the connection has gone silent, abort */
	      if(timeval_cmp(&now, &ms->rx_abort) >= 0)
		{
		  if(zombie > 0 && ms->name != NULL)
		    {
		      sc_master_zombie(ms);
		      timeval_diff_tv(&tv, &now, &ms->zombie);
		      goto set_timeout;
		    }
		  sc_master_free(ms);
		  continue;
		}

	      /*
	       * ensure we send something every 30 seconds
	       * unix_fd being not null signifies the remote controller
	       * has received an opening "master" frame.
	       */
	      if(ms->unix_fd != NULL && timeval_cmp(&now, &ms->tx_ka) >= 0)
		{
		  timeval_add_s(&ms->tx_ka, &now, 30);
		  if(sc_master_tx_keepalive(ms) != 0)
		    {
		      sc_master_free(ms);
		      continue;
		    }
		}

	      /* now figure out timeout to set */
	      if(timeval_cmp(&ms->rx_abort, &ms->tx_ka) <= 0)
		tvp = &ms->rx_abort;
	      else
		tvp = &ms->tx_ka;
	      if(timeval_cmp(&now, tvp) <= 0)
		timeval_diff_tv(&tv, &now, tvp);
	      else
		memset(&tv, 0, sizeof(tv));

	      if(ms->inet_fd.fd != -1)
		{
		  /* put the master inet socket into the select set */
		  FD_SET(ms->inet_fd.fd, &rfds);
		  if(ms->inet_fd.fd > nfds)
		    nfds = ms->inet_fd.fd;
		  if(scamper_writebuf_len(ms->inet_wb) > 0)
		    {
		      FD_SET(ms->inet_fd.fd, &wfds);
		      wfdsp = &wfds;
		    }
		}

	      /* listen on the master unix domain socket for new connections */
	      if(ms->unix_fd != NULL)
		{
		  FD_SET(ms->unix_fd->fd, &rfds);
		  if(ms->unix_fd->fd > nfds) nfds = ms->unix_fd->fd;
		}

	      /* set the unix domain sockets for connected systems */
	      dn2 = dlist_head_node(ms->channels);
	      while(dn2 != NULL)
		{
		  cn = dlist_node_item(dn2);
		  dn2 = dlist_node_next(dn2);
		  if(cn->unix_fd == NULL)
		    continue;
		  if((cn->unix_fd->flags & (FD_FLAG_READ|FD_FLAG_WRITE)) == 0)
		    continue;
		  if(cn->unix_fd->fd > nfds)
		    nfds = cn->unix_fd->fd;
		  if(cn->unix_fd->flags & FD_FLAG_READ)
		    FD_SET(cn->unix_fd->fd, &rfds);
		  if(cn->unix_fd->flags & FD_FLAG_WRITE)
		    {
		      FD_SET(cn->unix_fd->fd, &wfds);
		      wfdsp = &wfds;
		    }
		}

	    set_timeout:
	      if(timeout == NULL)
		{
		  timeval_cpy(&to, &tv);
		  timeout = &to;
		}
	      else
		{
		  if(timeval_cmp(&tv, &to) < 0)
		    timeval_cpy(&to, &tv);
		}
	    }
	}

      if((count = select(nfds+1, &rfds, wfdsp, NULL, timeout)) < 0)
	{
	  if(errno == EINTR || errno == EAGAIN)
	    continue;
	  remote_debug(__func__, "select failed: %s", strerror(errno));
	  return -1;
	}

      gettimeofday_wrap(&now);

      if(count > 0)
	{
	  for(i=0; i<2; i++)
	    {
	      if(serversockets[i] != -1 &&
		 FD_ISSET(serversockets[i], &rfds) &&
		 serversocket_accept(serversockets[i]) != 0)
		return -1;
	    }

	  for(dn=dlist_head_node(mslist); dn != NULL; dn=dlist_node_next(dn))
	    {
	      ms = dlist_node_item(dn);
	      if(ms->inet_fd.fd != -1 && FD_ISSET(ms->inet_fd.fd, &rfds))
		sc_master_inet_read_do(ms);
	      if(ms->unit->gc == 0 && ms->unix_fd != NULL &&
		 FD_ISSET(ms->unix_fd->fd, &rfds))
		sc_master_unix_accept_do(ms);
	      if(ms->unit->gc == 0 && wfdsp != NULL &&
		 ms->inet_fd.fd != -1 && FD_ISSET(ms->inet_fd.fd, wfdsp))
		sc_master_inet_write_do(ms);

	      for(dn2 = dlist_head_node(ms->channels);
		  dn2 != NULL && ms->unit->gc == 0;
		  dn2 = dlist_node_next(dn2))
		{
		  cn = dlist_node_item(dn2);
		  if(cn->unix_fd != NULL && FD_ISSET(cn->unix_fd->fd, &rfds))
		    sc_channel_unix_read_do(cn);
		  if(wfdsp != NULL && cn->unix_fd != NULL &&
		     FD_ISSET(cn->unix_fd->fd, wfdsp))
		    sc_channel_unix_write_do(cn);
		}
	    }
	}

      while((scu = dlist_head_pop(gclist)) != NULL)
	unit_gc[scu->type](scu->data);
    }

  return 0;
}

int main(int argc, char *argv[])
{
  int i;

#ifdef HAVE_SIGACTION
  struct sigaction si_sa;
#endif

#ifdef DMALLOC
  free(malloc(1));
#endif

  gettimeofday_wrap(&now);

  for(i=0; i<2; i++)
    serversockets[i] = -1;

  atexit(cleanup);

  if(check_options(argc, argv) != 0)
    return -1;

  if(pidfile != NULL && remoted_pidfile() != 0)
    return -1;

#ifdef HAVE_OPENSSL
  if(tls_certfile != NULL)
    {
      SSL_library_init();
      SSL_load_error_strings();
      if(remoted_tlsctx() != 0)
	return -1;
    }
#endif

#ifdef HAVE_DAEMON
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    return -1;
#endif

#ifdef HAVE_SIGNAL
  if(signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    {
      remote_debug(__func__, "could not ignore SIGPIPE");
      return -1;
    }
#endif

#ifdef HAVE_SIGACTION
  sigemptyset(&si_sa.sa_mask);
  si_sa.sa_flags   = 0;
  si_sa.sa_handler = remoted_sigaction;
  if(sigaction(SIGHUP, &si_sa, 0) == -1)
    {
      remote_debug(__func__, "could not set sigaction for SIGHUP");
      return -1;
    }

  sigemptyset(&si_sa.sa_mask);
  si_sa.sa_flags   = 0;
  si_sa.sa_handler = remoted_sigaction;
  if(sigaction(SIGINT, &si_sa, 0) == -1)
    {
      remote_debug(__func__, "could not set sigaction for SIGINT");
      return -1;
    }
#endif

  if(unixdomain_direxists() != 0 || serversocket_init() != 0)
    return -1;

  if((mslist = dlist_alloc()) == NULL ||
     (mstree = splaytree_alloc((splaytree_cmp_t)sc_master_cmp)) == NULL ||
     (gclist = dlist_alloc()) == NULL)
    return -1;
  dlist_onremove(mslist, (dlist_onremove_t)sc_master_onremove);
  dlist_onremove(gclist, (dlist_onremove_t)sc_unit_onremove);

#if defined(HAVE_EPOLL)
  if((flags & FLAG_SELECT) == 0)
    return epoll_loop();
#elif defined(HAVE_KQUEUE)
  if((flags & FLAG_SELECT) == 0)
    return kqueue_loop();
#endif

  return select_loop();
}
