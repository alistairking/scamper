/*
 * sc_remoted
 *
 * $Id: sc_remoted.c,v 1.142 2025/04/21 03:24:13 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2014-2025 Matthew Luckie
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
 *****************
 *
 * This code also defines a user-facing protocol that allows user code
 * to work with a collection of remote scamper instances over a single
 * unix domain socket (the scamper multiplexor).  This protocol is roughly
 * designed as follows:
 *
 * Header:
 * ------
 * uint32_t channel
 * uint32_t msglen
 *
 * This control header is included in every message sent between the
 * remote controller and the user code.
 * Channel #0 is reserved for control messages.  All other channels
 * correspond to an individual scamper instance that the user code is
 * working with.
 * The msglen value defines the size of the message that follows the header.
 *
 * Control Messages:
 * ----------------
 *
 * uint16_t type
 *
 * A control message begins with a mandatory type number.  The following
 * control message types are defined.
 *
 * 0 - VP update       (remoted --> client) -- MUX_VP_UPDATE
 * 1 - VP depart       (remoted --> client) -- MUX_VP_DEPART
 * 2 - Go              (remoted --> client) -- MUX_GO
 * 3 - Channel open    (remoted <-- client) -- MUX_CHANNEL_OPEN
 * 4 - Channel close   (remoted <-> client) -- MUX_CHANNEL_CLOSE
 *
 * Control Message - Vantage Point update (MUX_VP_UPDATE)
 * ---------------------------------
 *
 * When user code first connects to the controller, or a scamper instance
 * connects to the controller, the controller advises the user code
 * about the existence of instances.  The format of the message is as follows:
 *
 * uint32_t instance_id
 * <series of attribute/value pairs>
 * each attribute/value pair is encoded as:
 *   uint16_t  attribute
 *   char     *value
 *
 *  attribute values:
 *   1: monitor name, as supplied to scamper with -M.
 *   2: arrival time, formatted as sec.usec.
 *   3: IPv4 address of the monitor, as viewed by sc_remoted.
 *   4: IPv4 address of the socket the monitor used to connect to sc_remoted.
 *   5: ASN of the IPv4 address, as viewed by sc_remoted, if available.
 *   6: country code of the monitor, if available
 *   7: coordinates of the monitor, if available
 *
 * The user code should read all MUX_VP_UPDATE messages,
 * until the remoted process sends a MUX_GO message, before passing
 * control to the user code.  When instances arrive after the first
 * batch, these are reported individually, and the 'last' value is set
 * on these individual reports.  Note that an instance can arrive with
 * the same monitor name as an existing VP, but will have a different
 * ID value.
 *
 * Control Message - Vantage Point depart (MUX_VP_DEPART)
 * ---------------------------------
 *
 * When a remote scamper instance disconnects from the controller, the
 * remote controller signals that to user code.  The departing instance
 * is identified using the same ID value that the user code saw in an
 * initial arrive message.
 * 
 * uint32_t instance_id
 *
 * Control Message - GO (MUX_GO)
 * --------------------
 *
 * Sent to user code once the server has sent it metadata for all
 * connected scamper instances.
 *
 * Control Message - Channel Close (MUX_CHANNEL_CLOSE)
 * ---------------------
 *
 * When either scamper or the channel owner is freeing state associated with
 * the channel, this is signalled with a close message.
 *
 * uint32_t channel_id
 *
 * Control Message - Channel Open (MUX_CHANNEL_OPEN)
 * -------------------------------
 *
 * When a local process wants to use an instance, it sends an open
 * message, identifying the instance by ID, and declaring the ID to
 * identify the channel.
 *
 * uint32_t instance_id
 * uint32_t channel_id
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

#define SC_MESSAGE_HDRLEN 10 /* sequence:4 + channel_id:4 + msglen:2 */

/*
 * sc_metadata
 *
 * this structure records per-node metadata stored in a file.
 */
typedef struct sc_metadata
{
  char               *name;
  char               *asn4;
  char               *latlong;
  char               *cc;
  char               *st;
  char               *place;
  char               *shortname;
  slist_t            *tags;
} sc_metadata_t;

/*
 * sc_unit
 *
 * this generic structure says what kind of node is pointed to, and is
 * used to help garbage collect with kqueue / epoll.
 */
typedef struct sc_unit
{
  void               *data;
  dlist_node_t       *unode;
  uint8_t             type;
  uint8_t             gc;
} sc_unit_t;

#define UNIT_TYPE_MASTER  0
#define UNIT_TYPE_ONECHAN 1
#define UNIT_TYPE_MUX     2

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
#define FD_TYPE_ONECHAN_UNIX 3
#define FD_TYPE_MUX_ACCEPT   4
#define FD_TYPE_MUX          5

#define FD_FLAG_READ        0x1
#define FD_FLAG_WRITE       0x2

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
  char               *monitorname; /* -M parameter to scamper */
  char               *name;        /* socket name (prefaced by monitorname) */
  uint8_t            *magic;       /* magic value first sent by scamper */
  uint8_t             magic_len;   /* size of magic first sent by scamper */
  int                 mode;        /* connect / go / flush */
  uint32_t            id;          /* unique ID value, assigned by remoted */

  sc_fd_t            *unix_fd;     /* socket that accepts clients */
  sc_fd_t             inet_fd;     /* the socket to the scamper instance */
  scamper_writebuf_t *inet_wb;     /* data outstanding towards scamper */

#ifdef HAVE_OPENSSL
  int                 inet_mode;
  SSL                *inet_ssl;
  BIO                *inet_rbio;
  BIO                *inet_wbio;
#endif

  struct timeval      arrival;
  struct timeval      tx_ka;
  struct timeval      rx_abort;
  struct timeval      zombie;

  slist_t            *messages;
  uint32_t            snd_nxt;
  uint32_t            rcv_nxt;

  dlist_t            *channels;
  uint32_t            next_channel;
  dlist_node_t       *mnode;
  splaytree_node_t   *tree_node;
  uint8_t             buf[65536 + SC_MESSAGE_HDRLEN];
  size_t              buf_offset;
} sc_master_t;

/*
 * sc_channel_t
 *
 * this structure holds a mapping between a local process that wants
 * to drive a remote scamper, and a channel corresponding to that
 * instance open towards scamper.
 */
typedef struct sc_channel
{
  uint32_t            id;      /* id, derived from master->next_channel */
  sc_master_t        *master;  /* corresponding master */
  dlist_node_t       *cnode;   /* node in master->channels */
  uint8_t             flags;   /* channel flags: eof tx/rx, type of channel */
  void               *data;    /* onechan or muxchan struct */
} sc_channel_t;

/*
 * sc_onechan_t
 *
 * this structure holds a mapping between a local process connected to
 * a unix domain socket that represents a single remote scamper instance.
 */
typedef struct sc_onechan
{
  sc_unit_t          *unit;
  sc_fd_t            *unix_fd;
  scamper_linepoll_t *unix_lp;
  scamper_writebuf_t *unix_wb;
  sc_channel_t       *channel;
} sc_onechan_t;

/*
 * sc_mux_t
 *
 * this structure holds a mapping between a local process that wants
 * to drive multiple remote scamper instances over a single unix domain
 * socket.
 */
typedef struct sc_mux
{
  sc_unit_t          *unit;
  sc_fd_t            *unix_fd;
  scamper_writebuf_t *unix_wb;
  dlist_t            *channels;     /* list of sc_muxchan_t */
  dlist_node_t       *mxnode;       /* node in mxlist */
  uint32_t            next_muxchan; /* next ID to assign */

  uint8_t            *buf;          /* data left over from previous recv */
  size_t              buf_len;      /* amount of data left over */
  uint32_t            recv_chan;    /* are we reading a long message */
  size_t              recv_left;    /* how much left of the frame to recv */
} sc_mux_t;

/*
 * sc_muxchan_t
 *
 * this structure holds a mapping between a local process using an mux
 * socket to drive multiple remote scamper instances, and the channel
 * opened towards scamper.
 */
typedef struct sc_muxchan
{
  sc_mux_t           *mux;
  sc_channel_t       *channel;
  uint32_t            channel_id;
  dlist_node_t       *mxcnode;
} sc_muxchan_t;

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
#define OPT_UNIXDIR 0x0002
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
#ifdef PACKAGE_VERSION
#define OPT_VERSION 0x1000
#endif
#define OPT_METADATA 0x2000
#define OPT_MUXSOCK 0x4000
#define OPT_ALL     0xffff

#define FLAG_DEBUG      0x0001 /* verbose debugging */
#define FLAG_SELECT     0x0002 /* use select instead of kqueue/epoll */
#define FLAG_ALLOW_G    0x0004 /* allow group members to connect */
#define FLAG_ALLOW_O    0x0008 /* allow everyone to connect */
#define FLAG_SKIP_VERIF 0x0010 /* skip TLS name verification */

#define CHANNEL_FLAG_EOF_TX  0x01
#define CHANNEL_FLAG_EOF_RX  0x02
#define CHANNEL_FLAG_ONECHAN 0x04
#define CHANNEL_FLAG_MUXCHAN 0x08

#define CHANNEL_IS_ONECHAN(cn) ((cn)->flags & CHANNEL_FLAG_ONECHAN)
#define CHANNEL_IS_MUXCHAN(cn) ((cn)->flags & CHANNEL_FLAG_MUXCHAN)

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

#define MUX_HDRLEN             8 /* channel_id:4 + msglen:4 */

#define MUX_VP_UPDATE          0 /* remoted --> client */
#define MUX_VP_DEPART          1 /* remoted --> client */
#define MUX_GO                 2 /* remoted --> client */
#define MUX_CHANNEL_OPEN       3 /* remoted <-- client */
#define MUX_CHANNEL_CLOSE      4 /* remoted <-> client */

#define VP_ATTR_NAME           1
#define VP_ATTR_ARRIVAL        2
#define VP_ATTR_IPV4           3
#define VP_ATTR_IPV4_ASN       4
#define VP_ATTR_CC             5
#define VP_ATTR_ST             6
#define VP_ATTR_PLACE          7
#define VP_ATTR_LATLONG        8
#define VP_ATTR_SHORTNAME      9
#define VP_ATTR_TAG           10

static uint16_t     options        = 0;
static char        *unix_dir       = NULL;
static char        *ss_addr        = NULL;
static uint16_t     ss_port        = 0;
static char        *metadata_file  = NULL;
static splaytree_t *metadata       = NULL;
static splaytree_t *mstree         = NULL;
static dlist_t     *mslist         = NULL;
static dlist_t     *gclist         = NULL;
static dlist_t     *mxlist         = NULL;
static int          stop           = 0;
static int          reload         = 0;
static uint16_t     flags          = 0;
static int          serversockets[2];
static char        *muxsocket_name = NULL;
static int          muxsocket      = -1;
static int          zombie         = 60 * 15;
static char        *pidfile        = NULL;
static uint32_t     master_id      = 1;
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
static void sc_onechan_free(sc_onechan_t *);
static void sc_master_free(sc_master_t *);
static void sc_mux_free(sc_mux_t *);
static const sc_unit_gc_t unit_gc[] = {
  (sc_unit_gc_t)sc_master_free,      /* UNIT_TYPE_MASTER */
  (sc_unit_gc_t)sc_onechan_free,     /* UNIT_TYPE_ONECHAN */
  (sc_unit_gc_t)sc_mux_free,         /* UNIT_TYPE_MUX */
};

#if defined(HAVE_EPOLL) || defined(HAVE_KQUEUE)
typedef void (*sc_fd_cb_t)(void *);
static void sc_onechan_unix_read_do(sc_onechan_t *);
static void sc_onechan_unix_write_do(sc_onechan_t *);
static void sc_master_inet_read_do(sc_master_t *);
static void sc_master_inet_write_do(sc_master_t *);
static void sc_master_unix_accept_do(sc_master_t *);
static void sc_mux_unix_read_do(sc_mux_t *ub);
static void sc_mux_unix_write_do(sc_mux_t *ub);

static const sc_fd_cb_t read_cb[] = {
  NULL,                                 /* FD_TYPE_SERVER */
  (sc_fd_cb_t)sc_master_inet_read_do,   /* FD_TYPE_MASTER_INET */
  (sc_fd_cb_t)sc_master_unix_accept_do, /* FD_TYPE_MASTER_UNIX */
  (sc_fd_cb_t)sc_onechan_unix_read_do,  /* FD_TYPE_ONECHAN_UNIX */
  NULL,                                 /* FD_TYPE_MUX_ACCEPT */
  (sc_fd_cb_t)sc_mux_unix_read_do,      /* FD_TYPE_MUX */
};
static const sc_fd_cb_t write_cb[] = {
  NULL,                                 /* FD_TYPE_SERVER */
  (sc_fd_cb_t)sc_master_inet_write_do,  /* FD_TYPE_MASTER_INET */
  NULL,                                 /* FD_TYPE_MASTER_UNIX */
  (sc_fd_cb_t)sc_onechan_unix_write_do, /* FD_TYPE_ONECHAN_UNIX */
  NULL,                                 /* FD_TYPE_MUX_ACCEPT */
  (sc_fd_cb_t)sc_mux_unix_write_do,     /* FD_TYPE_MUX */
};
#endif

static int sc_onechan_unix_send(sc_onechan_t *ocn, uint8_t *buf, uint16_t len);
static int sc_muxchan_unix_send(sc_muxchan_t *ucn, uint8_t *buf, uint32_t len);
static int sc_mux_unix_send(sc_mux_t *mux, uint8_t *buf, size_t len);

static void usage(uint32_t opt_mask)
{
  const char *v = "";

#ifdef OPT_VERSION
  v = "v";
#endif

  fprintf(stderr,
	  "usage: sc_remoted [-?46D%s] -P [ip:]port\n"
	  "                  [-M mux-socket] [-U unix-dir] [-O option]\n"
#ifdef HAVE_OPENSSL
	  "                  [-C CA-file] [-c cert-file] [-p priv-file]\n"
#endif
	  "                  [-e pid-file] [-m meta-file] [-Z zombie-time]\n",
	  v);

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

#ifdef OPT_VERSION
  if(opt_mask & OPT_VERSION)
    fprintf(stderr, "     -v display version and exit\n");
#endif

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

  if(opt_mask & OPT_MUXSOCK)
    fprintf(stderr, "     -M location to place multiplexed socket interface\n");

  if(opt_mask & OPT_METADATA)
    fprintf(stderr, "     -m location of metadata file\n");

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -P [ip:]port to accept remote scamper connections\n");

  if(opt_mask & OPT_UNIXDIR)
    fprintf(stderr, "     -U directory for individual unix domain sockets\n");

#ifdef HAVE_OPENSSL
  if(opt_mask & OPT_TLSCA)
    fprintf(stderr, "     -C require client authentication using this CA\n");
  if(opt_mask & OPT_TLSCERT)
    fprintf(stderr, "     -c server certificate in PEM format\n");
  if(opt_mask & OPT_TLSPRIV)
    fprintf(stderr, "     -p private key in PEM format\n");
#endif

  if(opt_mask & OPT_ZOMBIE)
    fprintf(stderr, "     -Z time to retain state for disconnected scamper\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  struct sockaddr_storage sas;
  char opts[32], *opt_addrport = NULL, *opt_zombie = NULL, *opt_pidfile = NULL;
  size_t off = 0;
  long lo;
  int ch;

  string_concat(opts, sizeof(opts), &off, "?46DO:c:C:e:m:M:p:P:U:Z:");
#ifdef OPT_VERSION
  string_concatc(opts, sizeof(opts), &off, 'v');
#endif

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

	case 'm':
	  options |= OPT_METADATA;
	  metadata_file = optarg;
	  break;

	case 'M':
	  options |= OPT_MUXSOCK;
	  muxsocket_name = optarg;
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
	  unix_dir = optarg;
	  break;

#ifdef OPT_VERSION
	case 'v':
	  options |= OPT_VERSION;
	  return 0;
#endif

	case 'Z':
	  opt_zombie = optarg;
	  break;

	case '?':
	default:
	  usage(OPT_ALL);
	  return -1;
	}
    }

  if(opt_addrport == NULL)
    {
      usage(OPT_PORT);
      return -1;
    }

  if(unix_dir == NULL && muxsocket_name == NULL)
    {
      usage(OPT_UNIXDIR | OPT_MUXSOCK);
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
     (sockaddr_compose_str((struct sockaddr *)&sas, AF_UNSPEC,
			   ss_addr, ss_port) != 0 ||
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
      if(string_tolong(opt_zombie, &lo) != 0 || lo < 0 || lo > (3 * 60 * 60))
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
  va_list ap;

  if(options & OPT_DAEMON)
    return;

  if((flags & FLAG_DEBUG) == 0)
    return;

  va_start(ap, format);
  vsnprintf(message, sizeof(message), format, ap);
  va_end(ap);

  fprintf(stderr, "[%s] %s: %s\n",
	  timeval_tostr_hhmmssms(&now, ts), func, message);
  fflush(stderr);
  return;
}

static int fd_peername(int fd, char *buf, size_t len, int with_port)
{
  struct sockaddr_storage sas;
  socklen_t socklen;

  socklen = sizeof(sas);
  if(getpeername(fd, (struct sockaddr *)&sas, &socklen) != 0)
    {
      remote_debug(__func__, "could not getpeername: %s", strerror(errno));
      return -1;
    }
  if(sockaddr_tostr((struct sockaddr *)&sas, buf, len, with_port) == NULL)
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
static int ssl_want_read_cb(void *param, uint8_t *buf, int len)
{
  sc_master_t *ms = param;
  scamper_writebuf_send(ms->inet_wb, buf, len);
  sc_fd_write_add(&ms->inet_fd);
  return 0;
}

static int ssl_want_read(sc_master_t *ms)
{
  char errbuf[64];
  int rc;

  if((rc = tls_want_read(ms->inet_wbio, ms, errbuf, sizeof(errbuf),
			 ssl_want_read_cb)) < 0)
    {
      remote_debug(__func__, "%s", errbuf);
      return -1;
    }

  return rc;
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

static void sc_unit_gc(sc_unit_t *scu)
{
  if(scu->gc != 0)
    return;
  scu->gc = 1;
  dlist_node_tail_push(gclist, scu->unode);
  return;
}

static void sc_unit_free(sc_unit_t *scu)
{
  if(scu == NULL)
    return;
  if(scu->gc != 0 && scu->unode != NULL)
    dlist_node_pop(gclist, scu->unode);
  free(scu);
  return;
}

static sc_unit_t *sc_unit_alloc(uint8_t type, void *data)
{
  sc_unit_t *scu;
  if((scu = malloc_zero(sizeof(sc_unit_t))) == NULL ||
     (scu->unode = dlist_node_alloc(scu)) == NULL)
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

static int sc_metadata_cmp(const sc_metadata_t *a, const sc_metadata_t *b)
{
  return strcmp(a->name, b->name);
}

static void sc_metadata_free(sc_metadata_t *md)
{
  if(md->name != NULL) free(md->name);
  if(md->asn4 != NULL) free(md->asn4);
  if(md->latlong != NULL) free(md->latlong);
  if(md->cc != NULL) free(md->cc);
  if(md->st != NULL) free(md->st);
  if(md->place != NULL) free(md->place);
  if(md->shortname != NULL) free(md->shortname);
  if(md->tags != NULL) slist_free_cb(md->tags, free);
  free(md);
  return;
}

static int sc_master_cmp(const sc_master_t *a, const sc_master_t *b)
{
  if(a->magic_len < b->magic_len) return -1;
  if(a->magic_len > b->magic_len) return  1;
  return memcmp(a->magic, b->magic, a->magic_len);
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
  tls_bio_free(ms->inet_ssl, ms->inet_rbio, ms->inet_wbio);
  ms->inet_ssl = NULL;
  ms->inet_wbio = NULL;
  ms->inet_rbio = NULL;
#endif

  return;
}

static int sc_master_inet_send_channel_new(sc_master_t *ms, sc_channel_t *cn)
{
  uint8_t msg[5];
  msg[0] = CONTROL_CHANNEL_NEW;
  bytes_htonl(msg+1, cn->id);
  return sc_master_inet_send(ms, msg, 1 + 4, 0, 1);
}

static int sc_master_inet_send_channel_eof(sc_master_t *ms, sc_channel_t *cn)
{
  uint8_t msg[5];
  msg[0] = CONTROL_CHANNEL_FIN;
  bytes_htonl(msg+1, cn->id);
  return sc_master_inet_send(ms, msg, 1 + 4, 0, 1);
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

static int unix_create(const char *filename)
{
  int fd = -1;
  mode_t mode;

  /* create a unix domain control socket */
  if((fd = unix_bind_listen(filename, -1)) == -1)
    {
      remote_debug(__func__, "could not create unix socket: %s",
		   strerror(errno));
      goto err;
    }

  /* set the requested permissions on the control socket */
  mode = S_IRWXU;
  if(flags & FLAG_ALLOW_G) mode |= S_IRWXG;
  if(flags & FLAG_ALLOW_O) mode |= S_IRWXO;
  if(chmod(filename, mode) != 0)
    {
      remote_debug(__func__, "could not chmod: %s", strerror(errno));
      goto err;
    }

  return fd;

 err:
  if(fd != -1)
    {
      unlink(filename);
      close(fd);
    }
  return -1;
}

static int attr_embed(uint8_t *buf, size_t len, size_t *off, uint16_t attr,
		      char *attr_str)
{
  size_t attr_len = strlen(attr_str) + 1;
  if(len - *off < attr_len + 2)
    return -1;
  bytes_htons(buf+(*off), attr); (*off) += 2;
  memcpy(buf+(*off), attr_str, attr_len); (*off) += attr_len;
  return 0;
}

static int tags_embed(uint8_t *buf, size_t len, size_t *off, slist_t *tags)
{
  slist_node_t *sn;
  char *tag;
  for(sn=slist_head_node(tags); sn != NULL; sn=slist_node_next(sn))
    {
      tag = slist_node_item(sn);
      if(attr_embed(buf, len, off, VP_ATTR_TAG, tag) != 0)
	return -1;
    }
  return 0;
}

static int sc_master_mux_encode(const sc_master_t *ms,uint8_t *buf,size_t *len)
{
  sc_metadata_t fm, *md = NULL;
  char tmp[128];
  size_t off;

  if(*len < 16)
    return -1;

  bytes_htonl(buf + 0, 0);                          /* channel zero */
  bytes_htonl(buf + 4, 0);                          /* msglen */
  bytes_htons(buf + MUX_HDRLEN, MUX_VP_UPDATE);     /* type */
  bytes_htonl(buf + MUX_HDRLEN + 2, ms->id);        /* id of scamper */
  off = MUX_HDRLEN + 6;

  if(ms->monitorname != NULL)
    {
      if(attr_embed(buf, *len, &off, VP_ATTR_NAME, ms->monitorname) != 0)
	return -1;
      fm.name = ms->monitorname;
      md = splaytree_find(metadata, &fm);
    }

  snprintf(tmp, sizeof(tmp), "%ld.%06d",
	   (long int)ms->arrival.tv_sec, (int)ms->arrival.tv_usec);
  if(attr_embed(buf, *len, &off, VP_ATTR_ARRIVAL, tmp) != 0)
    return -1;

  if(ms->inet_fd.fd != -1 &&
     fd_peername(ms->inet_fd.fd, tmp, sizeof(tmp), 0) == 0 &&
     attr_embed(buf, *len, &off, VP_ATTR_IPV4, tmp) != 0)
    return -1;

  /* append external metadata */
  if(md != NULL &&
     ((md->asn4 != NULL &&
       attr_embed(buf, *len, &off, VP_ATTR_IPV4_ASN, md->asn4) != 0) ||
      (md->latlong != NULL &&
       attr_embed(buf, *len, &off, VP_ATTR_LATLONG, md->latlong) != 0) ||
      (md->cc != NULL &&
       attr_embed(buf, *len, &off, VP_ATTR_CC, md->cc) != 0) ||
      (md->st != NULL &&
       attr_embed(buf, *len, &off, VP_ATTR_ST, md->st) != 0) ||
      (md->place != NULL &&
       attr_embed(buf, *len, &off, VP_ATTR_PLACE, md->place) != 0) ||
      (md->shortname != NULL &&
       attr_embed(buf, *len, &off, VP_ATTR_SHORTNAME, md->shortname) != 0) ||
      (md->tags != NULL &&
       tags_embed(buf, *len, &off, md->tags) != 0)))
    return -1;

  bytes_htonl(buf + 4, off - MUX_HDRLEN);                  /* msglen */

  *len = off;
  return 0;
}

static void sc_master_mux_notify(const sc_master_t *ms)
{
  dlist_node_t *dn;
  sc_mux_t *mux;
  uint8_t buf[1024];
  size_t len;

  len = sizeof(buf);
  if(sc_master_mux_encode(ms, buf, &len) != 0)
    return;

  for(dn=dlist_head_node(mxlist); dn != NULL; dn=dlist_node_next(dn))
    {
      mux = dlist_node_item(dn);
      if(sc_mux_unix_send(mux, buf, len) != 0)
	remote_debug(__func__, "could not write instance update message");
    }

  return;
}

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
  char sab[128], filename[65535], tmp[512];
  int fd;

  /*
   * these are set so that we know whether or not to take
   * responsibility for cleaning them up upon a failure condition.
   */
  fd = -1;
  filename[0] = '\0';

  /* figure out the name for the unix domain socket */
  if(fd_peername(ms->inet_fd.fd, sab, sizeof(sab), 1) != 0)
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

  snprintf(filename, sizeof(filename), "%s/%s", unix_dir, ms->name);
  if((fd = unix_create(filename)) == -1)
    goto err;

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
  if(fd != -1)
    {
      if(filename[0] != '\0') unlink(filename);
      close(fd);
    }
  return -1;
}

static void sc_master_unix_free(sc_master_t *ms)
{
  char filename[65535];

  if(ms->unix_fd != NULL)
    {
      sc_fd_free(ms->unix_fd);
      ms->unix_fd = NULL;
      snprintf(filename, sizeof(filename), "%s/%s", unix_dir, ms->name);
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
  if(unix_dir != NULL && sc_master_unix_create(ms) != 0)
    goto err;

  /* send the list name to the client. do not expect an ack */
  if(fd_peername(ms->inet_fd.fd, sab, sizeof(sab), 1) != 0)
    goto err;
  remote_debug(__func__, "%s", sab);
  ms->mode = MASTER_MODE_GO;
  ms->id = master_id; master_id++;
  gettimeofday_wrap(&ms->arrival);
  off = strlen(sab);
  resp[0] = CONTROL_MASTER_ID;
  resp[1] = off + 1;
  memcpy(resp+2, sab, off + 1);
  if(sc_master_inet_send(ms, resp, 1 + 1 + off + 1, 0, 0) != 0)
    {
      remote_debug(__func__, "could not write ID: %s", strerror(errno));
      goto err;
    }

  /* send the existence of the remote instance out */
  sc_master_mux_notify(ms);

  return 0;

 err:
  return -1;
}

static void onechan_fin(sc_onechan_t *ocn)
{
  if(ocn->unix_wb == NULL || scamper_writebuf_gtzero(ocn->unix_wb) == 0)
    sc_unit_gc(ocn->unit);
  else
    sc_fd_read_del(ocn->unix_fd);
  return;
}

static void muxchan_fin(sc_muxchan_t *mcn)
{
  uint8_t buf[MUX_HDRLEN + 2 + 4];

  if(mcn == NULL || mcn->mux == NULL)
    return;

  bytes_htonl(buf + 0,              0);
  bytes_htonl(buf + 4,              6); /* type:2 + channel:4 */
  bytes_htons(buf + MUX_HDRLEN,     MUX_CHANNEL_CLOSE);
  bytes_htonl(buf + MUX_HDRLEN + 2, mcn->channel_id);

  if(sc_mux_unix_send(mcn->mux, buf, MUX_HDRLEN + 2 + 4) != 0)
    remote_debug(__func__, "could not write mux channel close message");

  return;
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
      remote_debug(__func__, "malformed channel fin: %u", (uint32_t)len);
      return -1;
    }

  id = bytes_ntohl(buf);
  if((cn = sc_master_channel_find(ms, id)) == NULL)
    {
      remote_debug(__func__, "could not find channel %u", id);
      return 0;
    }
  cn->flags |= CHANNEL_FLAG_EOF_RX;

  if(CHANNEL_IS_ONECHAN(cn))
    {
      onechan_fin(cn->data);
    }
  else
    {
      assert(CHANNEL_IS_MUXCHAN(cn));
      muxchan_fin(cn->data);
    }

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
  if(unix_dir != NULL && sc_master_unix_create(ms2) != 0)
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

  /* XXX: send the existence of the remote instance out */
  /* sc_master_mux_notify(ms2); */

 done:
  return 0;

 err:
  return -1;
}

/*
 * sc_master_control
 *
 * process data received on the inet_fd and placed in the buf struct.
 */
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
  sc_channel_t *cn;
  sc_onechan_t *ocn;
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

      if((cn = sc_master_channel_find(ms, id)) != NULL)
	{
	  if(CHANNEL_IS_ONECHAN(cn))
	    {
	      ocn = cn->data;
	      if(sc_onechan_unix_send(cn->data, ptr, msglen) != 0)
		sc_unit_gc(ocn->unit);
	    }
	  else if(CHANNEL_IS_MUXCHAN(cn))
	    {
	      sc_muxchan_unix_send(cn->data, ptr, msglen);
	    }
	}
      else remote_debug(__func__, "could not find channel %u", id);
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
  sc_channel_t *cn = NULL;
  sc_onechan_t *ocn = NULL;
  int s = -1;

  if((s = accept(ms->unix_fd->fd, NULL, NULL)) == -1)
    {
      remote_debug(__func__, "accept failed: %s", strerror(errno));
      goto err;
    }

  if((cn = malloc_zero(sizeof(sc_channel_t))) == NULL ||
     (ocn = malloc_zero(sizeof(sc_onechan_t))) == NULL)
    goto err;
  cn->flags |= CHANNEL_FLAG_ONECHAN;
  cn->id = ms->next_channel++;
  if(ms->next_channel == 0)
    ms->next_channel++;

  /* allocate a unit to describe this structure */
  if((ocn->unit = sc_unit_alloc(UNIT_TYPE_ONECHAN, ocn)) == NULL)
    {
      remote_debug(__func__, "could not alloc unit: %s", strerror(errno));
      goto err;
    }

  if((ocn->unix_fd = sc_fd_alloc(s, FD_TYPE_ONECHAN_UNIX, ocn->unit)) == NULL)
    {
      remote_debug(__func__, "could not alloc unix_fd: %s", strerror(errno));
      goto err;
    }
  s = -1;
  sc_fd_read_add(ocn->unix_fd);

  if((ocn->unix_wb = scamper_writebuf_alloc()) == NULL)
    goto err;
  if((cn->cnode = dlist_tail_push(ms->channels, cn)) == NULL)
    goto err;
  cn->master = ms;

  /* send a new channel message to scamper. expect an acknowledgement */
  if(sc_master_inet_send_channel_new(ms, cn) != 0)
    goto err;

  cn->data = ocn;
  ocn->channel = cn;
  return;

 err:
  if(s != -1) close(s);
  if(cn != NULL) sc_channel_free(cn);
  if(ocn != NULL) sc_onechan_free(ocn);
  return;
}

/*
 * sc_master_free
 *
 * clean up the sc_master_t.
 */
static void sc_master_free(sc_master_t *ms)
{
  uint8_t dep[MUX_HDRLEN + 2 + 4];
  dlist_node_t *dn;
  sc_channel_t *cn;
  sc_mux_t *mux;

  if(ms == NULL)
    return;

  /* send depart message to any mux sockets */
  if(mxlist != NULL)
    {
      bytes_htonl(dep + 0, 0);                          /* channel zero */
      bytes_htonl(dep + 4, 6);                          /* msglen */
      bytes_htons(dep + MUX_HDRLEN, MUX_VP_DEPART);     /* type */
      bytes_htonl(dep + MUX_HDRLEN + 2, ms->id);        /* id of scamper */
      for(dn=dlist_head_node(mxlist); dn != NULL; dn = dlist_node_next(dn))
	{
	  mux = dlist_node_item(dn);
	  if(sc_mux_unix_send(mux, dep, MUX_HDRLEN + 2 + 4) != 0)
	    remote_debug(__func__, "could not write instance depart message");
	}
    }

  sc_master_unix_free(ms);

  if(ms->channels != NULL)
    {
      while((cn = dlist_head_pop(ms->channels)) != NULL)
	{
	  cn->cnode = NULL;
	  sc_channel_free(cn);
	}
      dlist_free(ms->channels);
    }
  if(ms->messages != NULL)
    slist_free_cb(ms->messages, (slist_free_t)sc_message_free);

  if(ms->unit != NULL) sc_unit_free(ms->unit);

  sc_master_inet_free(ms);

  if(ms->tree_node != NULL) splaytree_remove_node(mstree, ms->tree_node);
  if(ms->name != NULL) free(ms->name);
  if(ms->monitorname != NULL) free(ms->monitorname);
  if(ms->magic != NULL) free(ms->magic);
  if(ms->mnode != NULL) dlist_node_pop(mslist, ms->mnode);
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
      if(tls_bio_alloc(tls_ctx, &ms->inet_ssl,
		       &ms->inet_rbio, &ms->inet_wbio) != 0)
	{
	  remote_debug(__func__, "could not alloc SSL");
	  goto err;
	}
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

static int sc_muxchan_unix_send(sc_muxchan_t *mcn, uint8_t *buf, uint32_t len)
{
  uint8_t msg[MUX_HDRLEN];
  if(mcn == NULL || mcn->mux == NULL || mcn->mux->unix_wb == NULL)
    return 0;
  bytes_htonl(msg+0, mcn->channel_id);
  bytes_htonl(msg+4, len);
  if(scamper_writebuf_send(mcn->mux->unix_wb, msg, MUX_HDRLEN) != 0 ||
     scamper_writebuf_send(mcn->mux->unix_wb, buf, len) != 0)
    return -1;
  sc_fd_write_add(mcn->mux->unix_fd);
  return 0;
}

static int sc_onechan_unix_send(sc_onechan_t *ocn, uint8_t *buf, uint16_t len)
{
  if(ocn->unix_wb == NULL)
    return 0;
  if(scamper_writebuf_send(ocn->unix_wb, buf, len) != 0)
    return -1;
  sc_fd_write_add(ocn->unix_fd);
  return 0;
}

/*
 * sc_onechan_unix_write_do
 *
 * we can write to the unix fd without blocking, so do so.
 */
static void sc_onechan_unix_write_do(sc_onechan_t *ocn)
{
  sc_channel_t *cn = ocn->channel;

  /* if we did a read which returned -1, then the unix_fd will be null */
  if(ocn->unix_fd == NULL)
    return;

  if(scamper_writebuf_write(ocn->unix_fd->fd, ocn->unix_wb) != 0)
    {
      remote_debug(__func__, "write to %s channel %u failed",
		   cn->master->name, cn->id);
      goto err;
    }

  /*
   * if we still have data to write, then wait until we get signal to
   * write again
   */
  if(scamper_writebuf_gtzero(ocn->unix_wb) != 0)
    return;

  /* nothing more to write, so remove fd */
  if(sc_fd_write_del(ocn->unix_fd) != 0)
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
      sc_unit_gc(ocn->unit);
      return;
    }

  return;

 err:
  /* got an error trying to write, so we're done */
  sc_fd_free(ocn->unix_fd); ocn->unix_fd = NULL;
  scamper_writebuf_free(ocn->unix_wb); ocn->unix_wb = NULL;

  /* we've received an EOF, we're done */
  if((cn->flags & CHANNEL_FLAG_EOF_RX) != 0)
    sc_unit_gc(ocn->unit);

  return;
}

/*
 * sc_onechan_unix_read_do
 *
 * a local client process has written to a unix domain socket, which
 * we will process line by line.
 */
static void sc_onechan_unix_read_do(sc_onechan_t *ocn)
{
  sc_channel_t *cn = ocn->channel;
  ssize_t rc;
  uint8_t buf[4096];

  if((rc = read(ocn->unix_fd->fd, buf, sizeof(buf))) <= 0)
    {
      if(rc == -1 && (errno == EAGAIN || errno == EINTR))
	return;

      /* send an EOF if we haven't tx'd or rx'd an EOF. expect an ack */
      if((cn->flags & (CHANNEL_FLAG_EOF_RX|CHANNEL_FLAG_EOF_TX)) == 0)
	{
	  sc_master_inet_send_channel_eof(cn->master, cn);
	  cn->flags |= CHANNEL_FLAG_EOF_TX;
	}

      /* if we've received an EOF, we're done */
      if((cn->flags & CHANNEL_FLAG_EOF_RX) != 0)
	{
	  sc_unit_gc(ocn->unit);
	  return;
	}

      /*
       * if we've received an error, close down the file descriptor
       * and write buf.  we keep the channel around so that when we
       * receive an EOF, we can match it and clean it up.
       */
      if(rc == -1)
	{
	  sc_fd_free(ocn->unix_fd); ocn->unix_fd = NULL;
	  scamper_writebuf_free(ocn->unix_wb); ocn->unix_wb = NULL;
	}
      else
	{
	  sc_fd_read_del(ocn->unix_fd);
	}
      return;
    }

  /* send the message to scamper, expecting an acknowledgement */
  sc_master_inet_send(cn->master, buf, rc, cn->id, 1);

  return;
}

static void sc_onechan_free(sc_onechan_t *ocn)
{
  if(ocn == NULL)
    return;
  if(ocn->unix_fd != NULL) sc_fd_free(ocn->unix_fd);
  if(ocn->unix_lp != NULL) scamper_linepoll_free(ocn->unix_lp, 0);
  if(ocn->unix_wb != NULL) scamper_writebuf_free(ocn->unix_wb);
  if(ocn->unit != NULL) sc_unit_free(ocn->unit);
  if(ocn->channel != NULL)
    {
      ocn->channel->data = NULL;
      sc_channel_free(ocn->channel);
    }
  free(ocn);
  return;
}

static void sc_muxchan_free(sc_muxchan_t *mcn)
{
  if(mcn == NULL)
    return;
  if(mcn->channel != NULL)
    {
      mcn->channel->data = NULL;
      sc_channel_free(mcn->channel);
    }
  if(mcn->mux != NULL && mcn->mux->channels != NULL && mcn->mxcnode != NULL)
    {
      dlist_node_pop(mcn->mux->channels, mcn->mxcnode);
      mcn->mxcnode = NULL;
    }
  free(mcn);
  return;
}

static void sc_channel_free(sc_channel_t *cn)
{
  sc_onechan_t *ocn;
  sc_muxchan_t *mcn;

  if(cn == NULL)
    return;
  if(cn->master != NULL && cn->cnode != NULL)
    dlist_node_pop(cn->master->channels, cn->cnode);
  if(cn->data != NULL && CHANNEL_IS_ONECHAN(cn))
    {
      ocn = cn->data;
      ocn->channel = NULL;
      sc_onechan_free(ocn);
    }
  else if(cn->data != NULL && CHANNEL_IS_MUXCHAN(cn))
    {
      mcn = cn->data;
      mcn->channel = NULL;
      sc_muxchan_free(mcn);
    }

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
  sc_master_t *ms = NULL;
  int inet_fd = -1;
  char buf[256];

  if((inet_fd = accept(ss, NULL, NULL)) == -1)
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

  if(fd_peername(ms->inet_fd.fd, buf, sizeof(buf), 1) == 0)
    remote_debug(__func__, "%s", buf);

  if(sc_fd_read_add(&ms->inet_fd) != 0)
    {
      remote_debug(__func__, "could not monitor inet fd: %s", strerror(errno));
      goto err;
    }

  timeval_add_s(&ms->rx_abort, &now, 30);
  timeval_cpy(&ms->tx_ka, &ms->rx_abort);

  if((ms->mnode = dlist_tail_push(mslist, ms)) == NULL)
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
  int fd = -1;

  if((fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
      remote_debug(__func__, "could not open %s socket: %s",
		   sa->sa_family == AF_INET ? "ipv4" : "ipv6", strerror(errno));
      goto err;
    }

  if(setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1) != 0)
    {
      remote_debug(__func__, "could not set SO_REUSEADDR on %s socket: %s",
		   sa->sa_family == AF_INET ? "ipv4" : "ipv6", strerror(errno));
      goto err;
    }

#ifdef IPV6_V6ONLY
  if(sa->sa_family == PF_INET6)
    {
      if(setsockopt_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1) != 0)
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
		   sockaddr_tostr(sa, buf, sizeof(buf), 1), strerror(errno));
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
      if(sockaddr_compose_str((struct sockaddr *)&sas, AF_UNSPEC,
			      ss_addr, ss_port) != 0)
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

static void sc_mux_free(sc_mux_t *mux)
{
  sc_muxchan_t *mcn;

  if(mux == NULL)
    return;

  if(mux->mxnode != NULL) dlist_node_pop(mxlist, mux->mxnode);
  if(mux->unix_fd != NULL) sc_fd_free(mux->unix_fd);
  if(mux->unix_wb != NULL) scamper_writebuf_free(mux->unix_wb);
  if(mux->unit != NULL) sc_unit_free(mux->unit);
  if(mux->buf != NULL) free(mux->buf);

  if(mux->channels != NULL)
    {
      while((mcn = dlist_head_pop(mux->channels)) != NULL)
	{
	  mcn->mxcnode = NULL;
	  sc_muxchan_free(mcn);
	}
      dlist_free(mux->channels);
    }

  free(mux);
  return;
}

static sc_mux_t *sc_mux_alloc(void)
{
  sc_mux_t *mux = NULL;

  if((mux = malloc_zero(sizeof(sc_mux_t))) == NULL ||
     (mux->unix_wb = scamper_writebuf_alloc()) == NULL ||
     (mux->channels = dlist_alloc()) == NULL ||
     (mux->unit = sc_unit_alloc(UNIT_TYPE_MUX, mux)) == NULL)
    {
      remote_debug(__func__, "could not alloc mux: %s", strerror(errno));
      goto err;
    }

  mux->next_muxchan = 1;
  return mux;

 err:
  sc_mux_free(mux);
  return NULL;
}

sc_muxchan_t *sc_mux_chan_get(sc_mux_t *mux, uint32_t channel_id)
{
  sc_muxchan_t *mcn;
  dlist_node_t *dn;

  for(dn=dlist_head_node(mux->channels); dn != NULL; dn=dlist_node_next(dn))
    {
      mcn = dlist_node_item(dn);
      if(mcn->channel_id == channel_id)
	return mcn;
    }

  return NULL;
}

static int sc_mux_read_channel_open(sc_mux_t *mux,const uint8_t *buf,size_t len)
{
  sc_master_t *ms = NULL;
  sc_muxchan_t *mcn = NULL;
  sc_channel_t *cn = NULL;
  dlist_node_t *dn;
  uint32_t instance_id;
  uint32_t channel_id;

  if(len < 8)
    return -1;
  instance_id = bytes_ntohl(buf);
  channel_id = bytes_ntohl(buf+4);

  /* do not allow re-use of channel ids */
  if(sc_mux_chan_get(mux, channel_id) != NULL)
    goto err;

  /* find the master instance referred to */
  for(dn=dlist_head_node(mslist); dn != NULL; dn=dlist_node_next(dn))
    {
      ms = dlist_node_item(dn);
      if(ms->id == instance_id)
	break;
    }
  if(ms == NULL || ms->id != instance_id)
    goto err;

  if((cn = malloc_zero(sizeof(sc_channel_t))) == NULL ||
     (mcn = malloc_zero(sizeof(sc_muxchan_t))) == NULL)
    goto err;
  cn->flags |= CHANNEL_FLAG_MUXCHAN;
  cn->id = ms->next_channel++;
  if(ms->next_channel == 0)
    ms->next_channel++;
  if((cn->cnode = dlist_tail_push(ms->channels, cn)) == NULL)
    goto err;
  cn->master = ms;

  /* send a new channel message to scamper. expect an acknowledgement */
  if(sc_master_inet_send_channel_new(ms, cn) != 0)
    goto err;

  cn->data = mcn;
  mcn->channel = cn;
  mcn->mux = mux;
  mcn->channel_id = channel_id;

  if((mcn->mxcnode = dlist_tail_push(mux->channels, mcn)) == NULL)
    goto err;

  return 0;

 err:
  if(mcn != NULL)
    {
      mcn->channel = NULL;
      sc_muxchan_free(mcn);
    }
  if(cn != NULL)
    {
      cn->data = NULL;
      sc_channel_free(cn);
    }
  return -1;
}

static int sc_mux_read_channel_zero(sc_mux_t *mux,const uint8_t *buf,size_t len)
{
  uint16_t msg_type;

  if(len < 2)
    return -1;

  msg_type = bytes_ntohs(buf);
  if(msg_type == MUX_CHANNEL_OPEN)
    {
      if(sc_mux_read_channel_open(mux, buf+2, len-2) != 0)
	return -1;
    }

  return 0;
}

static void sc_mux_unix_read_do(sc_mux_t *mux)
{
  dlist_node_t *dn;
  sc_muxchan_t *mcn;
  sc_channel_t *cn;
  size_t off, len, left, x;
  uint32_t msg_chan, msg_len;
  ssize_t rrc;

  if(realloc_wrap((void **)&mux->buf, mux->buf_len + 8192) != 0)
    goto zombie;

  if((rrc = recv(mux->unix_fd->fd, mux->buf + mux->buf_len, 8192, 0)) <= 0)
    {
      if(rrc == -1 && (errno == EAGAIN || errno == EINTR))
	return;
      if(rrc == 0)
	remote_debug(__func__, "mux disconnected");
      else
	remote_debug(__func__, "mux read failed: %s", strerror(errno));
      goto zombie;
    }

  len = mux->buf_len + rrc;
  off = 0;
  mux->buf_len = 0;

  while(off < len)
    {
      /* how much is left in the buf? */
      left = len - off;

      if(mux->recv_chan != 0)
	{
	  x = mux->recv_left <= left ? mux->recv_left : left;
	  if((mcn = sc_mux_chan_get(mux, mux->recv_chan)) != NULL)
	    sc_master_inet_send(mcn->channel->master, mux->buf + off, x,
				mcn->channel->id, 1);
	  mux->recv_left -= x;
	  off += x;
	  if(mux->recv_left == 0)
	    mux->recv_chan = 0;
	  continue;
	}

      /* need to buffer the remainder */
      if(left < MUX_HDRLEN)
	break;

      msg_chan = bytes_ntohl(mux->buf + off);
      msg_len  = bytes_ntohl(mux->buf + off + 4);
      off += MUX_HDRLEN;

      /* have the code block at the top of the loop handle frame */
      if(msg_chan != 0)
	{
	  mux->recv_chan = msg_chan;
	  mux->recv_left = msg_len;
	  continue;
	}

      /* require all of a channel zero message before processing it */
      if(left < msg_len)
	break;

      if(sc_mux_read_channel_zero(mux, mux->buf + off, msg_len) != 0)
	goto zombie;

      off += msg_len;
    }

  mux->buf_len = len - off;
  if(mux->buf_len > 0)
    memmove(mux->buf, mux->buf + off, mux->buf_len);
  realloc_wrap((void **)&mux->buf, mux->buf_len);

  return;

 zombie:
  for(dn=dlist_head_node(mux->channels); dn != NULL; dn=dlist_node_next(dn))
    {
      mcn = dlist_node_item(dn);
      if((cn = mcn->channel) == NULL)
	continue;
      if((cn->flags & (CHANNEL_FLAG_EOF_RX|CHANNEL_FLAG_EOF_TX)) == 0)
	{
	  sc_master_inet_send_channel_eof(cn->master, cn);
	  cn->flags |= CHANNEL_FLAG_EOF_TX;
	}
    }
  sc_unit_gc(mux->unit);
  return;  
}

static int sc_mux_unix_send(sc_mux_t *mux, uint8_t *buf, size_t len)
{
  if(mux->unix_wb == NULL || mux->unix_fd == NULL)
    return -1;
  if(scamper_writebuf_send(mux->unix_wb, buf, len) != 0)
    return -1;
  sc_fd_write_add(mux->unix_fd);
  return 0;
}

static void sc_mux_unix_write_do(sc_mux_t *mux)
{
  if(mux->unix_fd == NULL)
    return;

  if(scamper_writebuf_write(mux->unix_fd->fd, mux->unix_wb) != 0)
    {
      remote_debug(__func__, "write to mux failed");
      goto err;
    }

  /*
   * if we still have data to write, then wait until we get signal to
   * write again
   */
  if(scamper_writebuf_gtzero(mux->unix_wb) != 0)
    return;

  /* nothing more to write, so remove fd */
  if(sc_fd_write_del(mux->unix_fd) != 0)
    {
      remote_debug(__func__, "could not delete unix write mux");
      goto err;
    }

  return;

 err:
  remote_debug(__func__, "err");
  return;
}

static int muxsocket_accept(int muxsock)
{
  sc_mux_t *mux = NULL;
  dlist_node_t *dn;
  sc_master_t *ms;
  uint8_t buf[1024];
  size_t len;
  int s;

  assert(muxsock == muxsocket);

  if((s = accept(muxsock, NULL, NULL)) == -1)
    {
      remote_debug(__func__, "accept failed: %s", strerror(errno));
      goto err;
    }

  if((mux = sc_mux_alloc()) == NULL ||
     (mux->unix_fd  = sc_fd_alloc(s, FD_TYPE_MUX, mux->unit)) == NULL)
    {
      remote_debug(__func__, "could not alloc mux: %s", strerror(errno));
      goto err;
    }
  s = -1;
  sc_fd_read_add(mux->unix_fd);

  for(dn=dlist_head_node(mslist); dn != NULL; dn=dlist_node_next(dn))
    {
      ms = dlist_node_item(dn);
      if(ms->mode != MASTER_MODE_GO)
	continue;
      len = sizeof(buf);
      if(sc_master_mux_encode(ms, buf, &len) == 0 &&
	 scamper_writebuf_send(mux->unix_wb, buf, len) != 0)
	remote_debug(__func__, "could not write VP update message");
    }

  /* send GO message */
  bytes_htonl(buf + 0,          0);       /* channel zero */
  bytes_htonl(buf + 4,          2);       /* msglen */
  bytes_htons(buf + MUX_HDRLEN, MUX_GO);  /* type */
  if(scamper_writebuf_send(mux->unix_wb, buf, MUX_HDRLEN + 2) != 0)
    {
      remote_debug(__func__, "could not write go message");
      goto err;
    }

  if((mux->mxnode = dlist_tail_push(mxlist, mux)) == NULL)
    {
      remote_debug(__func__, "could not add mux to list");
      goto err;
    }

  sc_fd_write_add(mux->unix_fd);

  return 0;

 err:
  if(s != -1) close(s);
  if(mux != NULL) sc_mux_free(mux);
  return -1;
}

static int muxsocket_init(void)
{
  if(muxsocket_name != NULL && (muxsocket = unix_create(muxsocket_name)) == -1)
    return -1;
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
  if(stat(unix_dir, &sb) != 0)
    {
      usage(OPT_UNIXDIR);
      remote_debug(__func__, "stat failed %s: %s", unix_dir, strerror(errno));
      return -1;
    }
  if(S_ISDIR(sb.st_mode) == 0)
    {
      usage(OPT_UNIXDIR);
      remote_debug(__func__, "%s is not a directory", unix_dir);
      return -1;
    }

  return 0;
}

static void cleanup(void)
{
  sc_master_t *ms;
  sc_mux_t *mux;
  int i;

  for(i=0; i<2; i++)
    {
      if(serversockets[i] != -1)
	{
	  close(serversockets[i]);
	  serversockets[i] = -1;
	}
    }

  if(muxsocket != -1)
    {
      unlink(muxsocket_name);
      close(muxsocket);
      muxsocket = -1;
    }

  if(metadata != NULL)
    {
      splaytree_free(metadata, (splaytree_free_t)sc_metadata_free);
      metadata = NULL;
    }

  if(ss_addr != NULL)
    {
      free(ss_addr);
      ss_addr = NULL;
    }

  if(mxlist != NULL)
    {
      while((mux = dlist_head_pop(mxlist)) != NULL)
	{
	  mux->mxnode = NULL;
	  sc_mux_free(mux);
	}
      dlist_free(mxlist); mxlist = NULL;
    }

  if(mslist != NULL)
    {
      while((ms = dlist_head_pop(mslist)) != NULL)
	{
	  ms->mnode = NULL;
	  sc_master_free(ms);
	}
      dlist_free(mslist); mslist = NULL;
    }
  if(mstree != NULL)
    {
      splaytree_free(mstree, NULL);
      mstree = NULL;
    }

#ifdef HAVE_OPENSSL
  if(tls_ctx != NULL)
    {
      SSL_CTX_free(tls_ctx);
      tls_ctx = NULL;
    }
#endif

  if(gclist != NULL)
    {
      dlist_free(gclist);
      gclist = NULL;
    }

  if(pidfile != NULL)
    {
      unlink(pidfile);
      free(pidfile);
      pidfile = NULL;
    }

#ifdef HAVE_EPOLL
  if(epfd != -1)
    {
      close(epfd);
      epfd = -1;
    }
#endif

#ifdef HAVE_KQUEUE
  if(kqfd != -1)
    {
      close(kqfd);
      kqfd = -1;
    }
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

/*
 * metadata_line:
 *
 * process lines of the format:
 *
 * hlz2-nz cc nz
 * hlz2-nz asn4 64504
 *
 */
static int metadata_line(char *line, void *param)
{
  splaytree_t *tree = param;
  sc_metadata_t fm, *md;
  char *name = NULL, *attr = NULL, *value = NULL, *tag = NULL;
  char **out = NULL, *ptr = line;

  if(*line == '#' || *line == '\0')
    return 0;

  /* name is the first string */
  name = ptr;

  /* null terminate name */
  while(*ptr != '\0' && isspace((unsigned char)*ptr) == 0)
    ptr++;
  if(*ptr == '\0')
    return -1;
  *ptr = '\0';

  /* find the start of the attribute type */
  ptr++;
  while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
    ptr++;
  if(*ptr == '\0')
    return -1;
  attr = ptr;

  /* null terminate attribute type */
  while(*ptr != '\0' && isspace((unsigned char)*ptr) == 0)
    ptr++;
  if(*ptr == '\0')
    return -1;
  *ptr = '\0';

  /* find the start of the attribute value */
  ptr++;
  while(*ptr != '\0' && isspace((unsigned char)*ptr) != 0)
    ptr++;
  if(*ptr == '\0')
    return -1;
  value = ptr;

  fm.name = name;
  if((md = splaytree_find(tree, &fm)) == NULL)
    {
      if((md = malloc_zero(sizeof(sc_metadata_t))) == NULL ||
	 (md->name = strdup(name)) == NULL ||
	 splaytree_insert(tree, md) == NULL)
	{
	  if(md != NULL)
	    sc_metadata_free(md);
	  return -1;
	}
    }

  /* handle arbitrary tags separately */
  if(strcasecmp(attr, "tag") == 0)
    {
      if((md->tags == NULL && (md->tags = slist_alloc()) == NULL) ||
	 (tag = strdup(value)) == NULL ||
	 slist_tail_push(md->tags, tag) == NULL)
	{
	  if(tag != NULL) free(tag);
	  return -1;
	}
      return 0;
    }

  if(strcasecmp(attr, "asn4") == 0) out = &md->asn4;
  else if(strcasecmp(attr, "cc") == 0) out = &md->cc;
  else if(strcasecmp(attr, "st") == 0) out = &md->st;
  else if(strcasecmp(attr, "place") == 0) out = &md->place;
  else if(strcasecmp(attr, "latlong") == 0) out = &md->latlong;
  else if(strcasecmp(attr, "shortname") == 0) out = &md->shortname;
  else remote_debug(__func__, "unknown attribute type %s", attr);

  if(out != NULL && (*out = strdup(value)) == NULL)
    return -1;
   
  return 0;
}

static int metadata_load(void)
{
  splaytree_t *tree = NULL;

  if((tree = splaytree_alloc((splaytree_cmp_t)sc_metadata_cmp)) == NULL ||
     (metadata_file != NULL &&
      file_lines(metadata_file, metadata_line, tree) != 0))
    goto err;

  /* switch over the metadata trees */
  if(metadata != NULL)
    splaytree_free(metadata, (splaytree_free_t)sc_metadata_free);
  metadata = tree; tree = NULL;

  return 0;

 err:
  if(tree != NULL)
    splaytree_free(tree, (splaytree_free_t)sc_metadata_free);
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
  sc_fd_t *scfd, scfds[3];
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

  /* add accept() sockets to the poll set */
  memset(scfds, 0, sizeof(scfds));
  scfd = &scfds[0];
  for(i=0; i<2; i++)
    {
      if(serversockets[i] == -1)
	continue;
      scfd->type = FD_TYPE_SERVER;
      scfd->fd = serversockets[i];
      if(sc_fd_read_add(scfd) != 0)
	return -1;
      scfd++;
    }
  if(muxsocket != -1)
    {
      scfd->type = FD_TYPE_MUX_ACCEPT;
      scfd->fd = muxsocket;
      if(sc_fd_read_add(scfd) != 0)
	return -1;
    }
  scfd = NULL;

  /* main event loop */
  while(stop == 0)
    {
      if(reload != 0)
	{
	  reload = 0;
	  metadata_load();
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
	       * XXX: unix_fd being not null signifies the remote
	       * controller has received an opening "master" frame.
	       */
	      if(ms->mode == MASTER_MODE_GO &&
		 timeval_cmp(&now, &ms->tx_ka) >= 0)
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

	  if(scfd->type == FD_TYPE_SERVER)
	    {
	      serversocket_accept(scfd->fd);
	      continue;
	    }
	  else if(scfd->type == FD_TYPE_MUX_ACCEPT)
	    {
	      muxsocket_accept(scfd->fd);
	      continue;
	    }

	  scu = scfd->unit; assert(scu != NULL);

#if defined(HAVE_EPOLL)
	  if(events[i].events & (EPOLLIN|EPOLLHUP) && scu->gc == 0)
	    read_cb[scfd->type](scu->data);
	  if(events[i].events & EPOLLOUT && scu->gc == 0)
	    write_cb[scfd->type](scu->data);
#else
	  if(scu->gc != 0)
	    continue;
	  if(events[i].filter == EVFILT_READ)
	    read_cb[scfd->type](scu->data);
	  else if(events[i].filter == EVFILT_WRITE)
	    write_cb[scfd->type](scu->data);
#endif
	}

      while((scu = dlist_head_pop(gclist)) != NULL)
	{
	  scu->unode = NULL;
	  unit_gc[scu->type](scu->data);
	}
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
  sc_onechan_t *ocn;
  sc_mux_t *mux;
  sc_unit_t *scu;

  while(stop == 0)
    {
      if(reload != 0)
	{
	  reload = 0;
	  metadata_load();
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

      if(muxsocket != -1)
	{
	  FD_SET(muxsocket, &rfds);
	  if(muxsocket > nfds)
	    nfds = muxsocket;
	}

      for(dn=dlist_head_node(mxlist); dn != NULL; dn=dlist_node_next(dn))
	{
	  mux = dlist_node_item(dn);
	  FD_SET(mux->unix_fd->fd, &rfds);
	  if(mux->unix_fd->fd > nfds)
	    nfds = mux->unix_fd->fd;
	  if(scamper_writebuf_len(mux->unix_wb) > 0)
	    {
	      FD_SET(mux->unix_fd->fd, &wfds);
	      wfdsp = &wfds;
	    }
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
	       * ensure we send something every 30 seconds.
	       * XXX: unix_fd being not null signifies the remote
	       * controller has received an opening "master" frame.
	       */
	      if(ms->mode == MASTER_MODE_GO &&
		 timeval_cmp(&now, &ms->tx_ka) >= 0)
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
		  if(CHANNEL_IS_ONECHAN(cn))
		    {
		      ocn = cn->data;
		      if(ocn->unix_fd == NULL ||
			 ((ocn->unix_fd->flags & FD_FLAG_READ) == 0 &&
			  (ocn->unix_fd->flags & FD_FLAG_WRITE) == 0))
			continue;
		      if(ocn->unix_fd->fd > nfds)
			nfds = ocn->unix_fd->fd;
		      if(ocn->unix_fd->flags & FD_FLAG_READ)
			FD_SET(ocn->unix_fd->fd, &rfds);
		      if(ocn->unix_fd->flags & FD_FLAG_WRITE)
			{
			  FD_SET(ocn->unix_fd->fd, &wfds);
			  wfdsp = &wfds;
			}
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

	  if(muxsocket != -1 && FD_ISSET(muxsocket, &rfds) &&
	     muxsocket_accept(muxsocket) != 0)
	    return -1;

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
		  if(CHANNEL_IS_ONECHAN(cn))
		    {
		      ocn = cn->data;
		      if(ocn->unix_fd != NULL &&
			 FD_ISSET(ocn->unix_fd->fd, &rfds))
			sc_onechan_unix_read_do(ocn);
		      if(wfdsp != NULL && ocn->unix_fd != NULL &&
			 FD_ISSET(ocn->unix_fd->fd, wfdsp))
			sc_onechan_unix_write_do(ocn);
		    }
		}
	    }

	  for(dn=dlist_head_node(mxlist); dn != NULL; dn=dlist_node_next(dn))
	    {
	      mux = dlist_node_item(dn);
	      if(mux->unix_fd->fd != -1 && FD_ISSET(mux->unix_fd->fd, &rfds))
		sc_mux_unix_read_do(mux);
	      if(wfdsp != NULL &&
		 mux->unix_fd->fd != -1 && FD_ISSET(mux->unix_fd->fd, wfdsp))
		sc_mux_unix_write_do(mux);
	    }
	}

      while((scu = dlist_head_pop(gclist)) != NULL)
	{
	  scu->unode = NULL;
	  unit_gc[scu->type](scu->data);
	}
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

#ifdef OPT_VERSION
  if(options & OPT_VERSION)
    {
      printf("sc_remoted version %s\n", PACKAGE_VERSION);
      return 0;
    }
#endif

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

  if((unix_dir != NULL && unixdomain_direxists() != 0) ||
     serversocket_init() != 0 ||
     muxsocket_init() != 0)
    return -1;

  if((mslist = dlist_alloc()) == NULL ||
     (mstree = splaytree_alloc((splaytree_cmp_t)sc_master_cmp)) == NULL ||
     (gclist = dlist_alloc()) == NULL ||
     (mxlist = dlist_alloc()) == NULL ||
     metadata_load() != 0)
    return -1;

#if defined(HAVE_EPOLL)
  if((flags & FLAG_SELECT) == 0)
    return epoll_loop();
#elif defined(HAVE_KQUEUE)
  if((flags & FLAG_SELECT) == 0)
    return kqueue_loop();
#endif

  return select_loop();
}
