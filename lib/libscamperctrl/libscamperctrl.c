/*
 * libscamperctrl
 *
 * $Id: libscamperctrl.c,v 1.91 2025/03/12 02:58:09 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2021-2025 Matthew Luckie. All rights reserved.
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

#include <sys/types.h>

#ifndef _WIN32 /* include headers that are not on windows */
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define HAVE_SOCKADDR_UN
#define socket_close(s) close((s))
#define socket_isvalid(s) ((s) != -1)
#define socket_isinvalid(s) ((s) == -1)
#define socket_invalid() (-1)
#define socket_setnfds(nfds, s) ((nfds) < (s) ? (s) : (nfds))
#endif

#ifdef _WIN32 /* include windows headers */
#include <winsock2.h>
#include <ws2tcpip.h>
#define socket_close(s) closesocket((s))
#define socket_isvalid(s) ((s) != INVALID_SOCKET)
#define socket_isinvalid(s) ((s) == INVALID_SOCKET)
#define socket_invalid() (INVALID_SOCKET)
#define socket_setnfds(nfds, s) (0)
#endif

#ifdef HAVE_KQUEUE
#include <sys/event.h>
#include <sys/time.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <ctype.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <errno.h>
#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#if defined(HAVE_STDINT_H)
#include <stdint.h>
#endif

#include "libscamperctrl.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"

typedef struct sc_tx
{
  uint8_t           *buf;      /* data to send */
  size_t             off;      /* where in the send we are up to */
  size_t             len;      /* length of data to send */
  dlist_node_t      *qdn;      /* pointer to the dlist_node_t when in queue */
  int                txtype;   /* type of frame */
  scamper_inst_t    *inst;     /* pointer to instance */
  scamper_task_t    *task;     /* pointer to task */
} sc_tx_t;

typedef struct sc_fd
{
#ifndef _WIN32 /* type: int vs SOCKET */
  int                fd;       /* file descriptor for socket */
#else
  SOCKET             fd;       /* file descriptor for socket */
#endif
  int                fdtype;   /* type of file descriptor */
  dlist_t           *queue;    /* queue of items to write */
  int                write;    /* has write want been signalled? */
  dlist_node_t      *fdsdn;    /* entry in ctrl->fds */
  void              *data;     /* pointer to scamper_inst_t / scamper_mux_t */
} sc_fd_t;

typedef struct sc_muxchan
{
  scamper_mux_t     *mux;
  scamper_inst_t    *inst;
  dlist_node_t      *cdn;
  uint32_t           chan;
} sc_muxchan_t;

struct scamper_ctrl
{
  dlist_t           *fds;      /* list of file descriptors */
  dlist_t           *insts;    /* insts under management */
  dlist_t           *muxs;     /* mux sockets under management */
  dlist_t           *waitlist; /* insts waiting to be processed after wait() */
  scamper_ctrl_cb_t  cb;       /* callback to call */
  uint8_t            wait;     /* are we currently in scamper_ctrl_wait */
  char               err[128]; /* error string */
  void              *param;    /* optional parameter */
#ifdef HAVE_KQUEUE
  int                kqfd;     /* kqueue fd */
#endif
};

struct scamper_inst
{
  scamper_ctrl_t    *ctrl;     /* backpointer to overall control structure */
  dlist_t           *list;     /* ctrl->insts or ctrl->waitlist or NULL */
  dlist_node_t      *idn;      /* dlist node in ctrl->insts or ctrl->waitlist */
  char              *name;     /* string representing name of instance */
  sc_fd_t           *fdn;      /* file descriptor, if not mux */
  sc_muxchan_t      *mc;       /* mux channel reference */
  scamper_vp_t      *vp;       /* VP, if tagged */
  void              *param;    /* user-supplied parameter */
  uint8_t            type;     /* types: inet, unix, remote, or mux-chan */
  uint8_t            flags;    /* flags: done */
  slist_t           *waitok;   /* commands we are waiting for an ok for */
  splaytree_t       *tree;     /* tasks searchable by their ID */
  char               err[128]; /* error string */

  /*
   * temporary buffer for storing incomplete lines in between to calls
   * to recv
   */
  uint8_t            line[128];
  size_t             line_off;

  /*
   * temporary buffer for storing data objects as we recv them from
   * the control socket.  data_left is the number of bytes still to
   * come over the control socket; the data buffer we allocate will be
   * smaller if the data is uuencoded.  data_o says where in data we
   * are to write bytes next, and data_len contains the upper limit of
   * how large the data buffer is.  we also keep a pointer that
   * identifies the task that this data is for.
   */
  scamper_task_t    *task;
  uint8_t           *data;
  size_t             data_o;
  size_t             data_len;
  size_t             data_left;
};

struct scamper_task
{
  char              *str;      /* measurement command for scamper */
  sc_tx_t           *tx;       /* backpointer to a frame in queue/waitok */
  void              *param;    /* user-supplied parameter */
  scamper_inst_t    *inst;     /* which instance issued this task */
  uint32_t           id;       /* the task ID returned by scamper */
  uint8_t            refcnt;   /* max value is 2 */
  uint8_t            flags;    /* flags */
};

struct scamper_attp
{
  uint8_t            flags;     /* which fields are set */
  uint32_t           l_id;      /* list id */
  uint32_t           c_id;      /* cycle id */
  uint32_t           priority;  /* mix priority */
  char              *l_name;    /* list name */
  char              *l_descr;   /* list description */
  char              *l_monitor; /* list monitor */
};

struct scamper_mux
{
  scamper_ctrl_t    *ctrl;      /* pointer to ctrl structure */
  sc_fd_t           *fdn;       /* file descriptor for client */
  dlist_t           *vps;       /* list of scamper_vp_t */
  dlist_t           *channels;  /* list of sc_muxchan_t */
  uint32_t           next_chan; /* next channel ID to use */

  uint8_t           *buf;       /* data left over from previous recv */
  size_t             buf_len;   /* amount of data left over */
  uint32_t           recv_chan; /* are we reading a long message */
  size_t             recv_left; /* how much left of the frame to recv */
};

struct scamper_vpset
{
  scamper_vp_t     **vps;
  size_t             vpc;
};

struct scamper_vp
{
  scamper_mux_t     *mux;
  uint32_t           id;
  char              *name;
  char              *arrival;
  char              *ipv4;
  char              *asn4;
  char              *cc;
  char              *st;
  char              *place;
  char              *latlong;
  char              *shortname;
  char             **tags;
  size_t             tagc;
  int                refcnt;
};

#define INST_HAS_FDN(inst) ( \
  ((inst)->type == SCAMPER_INST_TYPE_UNIX || \
   (inst)->type == SCAMPER_INST_TYPE_INET || \
   (inst)->type == SCAMPER_INST_TYPE_REMOTE))

#define TX_WANT_INST(tx) ( \
  ((tx)->txtype == TX_TYPE_ATTACH || \
   (tx)->txtype == TX_TYPE_HALT ||   \
   (tx)->txtype == TX_TYPE_TASK ||   \
   (tx)->txtype == TX_TYPE_DONE))

#define TX_TYPE_ATTACH           1
#define TX_TYPE_HALT             2
#define TX_TYPE_TASK             3
#define TX_TYPE_DONE             4
#define TX_TYPE_MUXVP_OPEN       5

#define SCAMPER_INST_FLAG_DONE   0x01 /* "done" sent for this inst */
#define SCAMPER_INST_FLAG_FREE   0x02 /* the inst is in the waitlist to free */

#define SCAMPER_TASK_FLAG_QUEUE  0x01
#define SCAMPER_TASK_FLAG_WAITOK 0x02
#define SCAMPER_TASK_FLAG_GOTID  0x04
#define SCAMPER_TASK_FLAG_DONE   0x08
#define SCAMPER_TASK_FLAG_HALT   0x10
#define SCAMPER_TASK_FLAG_HALTED 0x20

#define SCAMPER_ATTP_FLAG_LISTID   0x01
#define SCAMPER_ATTP_FLAG_CYCLEID  0x02
#define SCAMPER_ATTP_FLAG_PRIORITY 0x04

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

#define FD_TYPE_INST           0
#define FD_TYPE_MUX            1

#ifndef DMALLOC
static void *malloc_zero(size_t len)
#else
#define malloc_zero(len) malloc_zero_dm(len, __FILE__, __LINE__)
static void *malloc_zero_dm(size_t len, const char *file, const int line)
#endif
{
  void *ptr;

#ifndef DMALLOC
  ptr = malloc(len);
#else
  ptr = dmalloc_malloc(file, line, len, DMALLOC_FUNC_MALLOC, 0, 0);
#endif

  if(ptr != NULL)
    memset(ptr, 0, len);
  return ptr;
}

int realloc_wrap(void **ptr, size_t len)
{
  void *tmp;

  if(len != 0)
    {
      if(*ptr != NULL)
	tmp = realloc(*ptr, len);
      else
	tmp = malloc(len);
      if(tmp != NULL)
	{
	  *ptr = tmp;
	  return 0;
	}
    }
  else
    {
      if(*ptr != NULL)
	{
	  free(*ptr);
	  *ptr = NULL;
	}
      return 0;
    }

  return -1;
}

static uint16_t bytes_ntohs(const uint8_t *bytes)
{
  uint16_t u16;
  memcpy(&u16, bytes, 2);
  return ntohs(u16);
}

static uint32_t bytes_ntohl(const uint8_t *bytes)
{
  uint32_t u32;
  memcpy(&u32, bytes, 4);
  return ntohl(u32);
}

static void bytes_htons(uint8_t *bytes, uint16_t u16)
{
  uint16_t tmp = htons(u16);
  memcpy(bytes, &tmp, 2);
  return;
}

static void bytes_htonl(uint8_t *bytes, uint32_t u32)
{
  uint32_t tmp = htonl(u32);
  memcpy(bytes, &tmp, 4);
  return;
}

static int sa_fromstr(struct sockaddr *sa, const char *addr, uint16_t port)
{
  struct sockaddr_in *sin;
  struct sockaddr_in6 *sin6;

  sin = (struct sockaddr_in *)sa;
  memset(sin, 0, sizeof(struct sockaddr_in));
  if(inet_pton(AF_INET, addr, &sin->sin_addr) == 1)
    {
      sa->sa_family = AF_INET;
#if defined(HAVE_STRUCT_SOCKADDR_SA_LEN)
      sa->sa_len    = sizeof(struct sockaddr_in);
#endif
      sin->sin_port = htons(port);
      return 0;
    }

  sin6 = (struct sockaddr_in6 *)sa;
  memset(sin6, 0, sizeof(struct sockaddr_in6));
  if(inet_pton(AF_INET6, addr, &sin6->sin6_addr) == 1)
    {
      sa->sa_family   = AF_INET6;
#if defined(HAVE_STRUCT_SOCKADDR_SA_LEN)
      sa->sa_len      = sizeof(struct sockaddr_in6);
#endif
      sin6->sin6_port = htons(port);
      return 0;
    }

  return -1;
}

#ifdef HAVE_SOCKADDR_UN
static int unix_fd(const char *path, char *err, size_t errlen)
{
  struct sockaddr_un sun;
  int fd = -1;

  /* make sure the filename can fit in the space available */
  if(strlen(path) + 1 > sizeof(sun.sun_path))
    {
      snprintf(err, errlen, "path too long");
      goto err;
    }

  /* build the sockaddr_un */
  memset(&sun, 0, sizeof(struct sockaddr_un));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", path);
#if defined(HAVE_STRUCT_SOCKADDR_SA_LEN)
  sun.sun_len = sizeof(struct sockaddr_un);
#endif

  if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
      snprintf(err, errlen, "could not create unix socket: %s",
	       strerror(errno));
      goto err;
    }

  /* connect to the scamper instance */
  if(connect(fd, (const struct sockaddr *)&sun, sizeof(sun)) != 0)
    {
      snprintf(err, errlen, "could not connect: %s", strerror(errno));
      goto err;
    }

  return fd;

 err:
  if(fd != -1) close(fd);
  return -1;
}
#endif

static void tx_free(sc_tx_t *tx)
{
  if(tx->buf != NULL) free(tx->buf);
  free(tx);
  return;
}

static int fd_nonblock(int fd, char *err, size_t errlen)
{
#ifdef HAVE_FCNTL
  if(fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
    {
      snprintf(err, errlen, "could not set nonblocking: %s", strerror(errno));
      return -1;
    }
#endif
  return 0;
}

static int fd_set_read(scamper_ctrl_t *ctrl, sc_fd_t *fdn)
{
#ifdef HAVE_KQUEUE
  struct kevent kev;
  EV_SET(&kev, fdn->fd, EVFILT_READ, EV_ADD, 0, 0, fdn);
  if(kevent(ctrl->kqfd, &kev, 1, NULL, 0, NULL) != 0)
    return -1;
#endif
  return 0;
}

static int fd_set_write(scamper_ctrl_t *ctrl, sc_fd_t *fdn)
{
#ifdef HAVE_KQUEUE
  struct kevent kev;
#endif

  if(fdn->write == 0)
    {
#ifdef HAVE_KQUEUE
      EV_SET(&kev, fdn->fd, EVFILT_WRITE, EV_ADD, 0, 0, fdn);
      if(kevent(ctrl->kqfd, &kev, 1, NULL, 0, NULL) != 0)
	return -1;
#endif
      fdn->write = 1;
    }

  return 0;
}

static int fd_unset_write(scamper_ctrl_t *ctrl, sc_fd_t *fdn)
{
#ifdef HAVE_KQUEUE
  struct kevent kev;
#endif

  if(fdn->write != 0)
    {
#ifdef HAVE_KQUEUE
      EV_SET(&kev, fdn->fd, EVFILT_WRITE, EV_DELETE, 0, 0, fdn);
      if(kevent(ctrl->kqfd, &kev, 1, NULL, 0, NULL) != 0)
	return -1;
#endif
      fdn->write = 0;
    }

  return 0;
}

static int fd_write(scamper_ctrl_t *ctrl, sc_fd_t *fdn)
{
  scamper_task_t *task;
  sc_tx_t *tx;
  ssize_t rc;

  tx = dlist_head_item(fdn->queue);
  assert(tx != NULL);

  /* test if send was successful */
  if((rc = send(fdn->fd, tx->buf + tx->off, tx->len - tx->off, 0)) == -1)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not send: %s",
	       strerror(errno));
      return -1;
    }
  assert(rc >= 0);

  /* remove the command from the queue if we wrote all of it */
  if((size_t)rc == tx->len - tx->off)
    {
      /* remove the command from the queue to be sent to scamper */
      dlist_head_pop(fdn->queue);

      task = tx->task;
      if(tx->txtype == TX_TYPE_TASK)
	{
	  assert(task != NULL);
	  assert((task->flags & SCAMPER_TASK_FLAG_QUEUE) != 0);
	  assert((task->flags & SCAMPER_TASK_FLAG_WAITOK) == 0);
	  task->flags &= (~SCAMPER_TASK_FLAG_QUEUE);
	}

      /* do not need message anymore */
      free(tx->buf);
      tx->buf = NULL;

      /*
       * add the command to the list of commands waiting for an OK, if
       * the command is associated with an instance
       */
      if(tx->inst == NULL)
	{
	  tx_free(tx);
	  goto done;
	}

      if(slist_tail_push(tx->inst->waitok, tx) == NULL)
	{	  
	  tx_free(tx);
	  snprintf(ctrl->err, sizeof(ctrl->err), "could not put tx on waitok");
	  return -1;
	}

      if(tx->txtype == TX_TYPE_TASK)
	task->flags |= SCAMPER_TASK_FLAG_WAITOK;
    }
  else if(rc > 0)
    {
      tx->off += rc;
    }

 done:
  /* if nothing left to write, then unset write */
  if(dlist_count(fdn->queue) == 0 && fd_unset_write(ctrl, fdn) != 0)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not unset inst write");
      return -1;
    }

  return 0;
}

static sc_tx_t *fd_queue(sc_fd_t *fdn, int type, uint8_t *buf, size_t len)
{
  sc_tx_t *tx = NULL;

  if((tx = malloc_zero(sizeof(sc_tx_t))) == NULL ||
     (tx->qdn = dlist_tail_push(fdn->queue, tx)) == NULL)
    {
      if(tx != NULL)
	free(tx);
      return NULL;
    }

  tx->txtype = type;
  tx->buf = buf;
  tx->len = len;

  return tx;
}

static sc_fd_t *fd_alloc(int fd)
{
  sc_fd_t *fdn = NULL;

  if((fdn = malloc_zero(sizeof(sc_fd_t))) == NULL ||
     (fdn->queue = dlist_alloc()) == NULL)
    {
      if(fdn != NULL)
	free(fdn);
      return NULL;
    }
  fdn->fd = fd;

  return fdn;
}

static void fd_free(sc_fd_t *fdn)
{
  if(fdn->queue != NULL)
    dlist_free(fdn->queue);
  if(socket_isvalid(fdn->fd))
    socket_close(fdn->fd);
  free(fdn);
  return;
}

static int task_set_str(scamper_inst_t *inst, scamper_task_t *task,
			const char *str)
{
  size_t i, len = strlen(str);

  /* make sure the thing to isn't a reserved keyword */
  if(strncasecmp(str, "attach", 6) == 0 &&
     strncasecmp(str, "halt", 4) == 0 &&
     strncasecmp(str, "done", 4) == 0)
    {
      snprintf(inst->err, sizeof(inst->err), "invalid command");
      return -1;
    }

  /*
   * remove extraneous trailing \r\n characters from the end of the
   * command string, and then make sure all characters in the command
   * are printable
   */
  while(len > 0)
    {
      if(str[len-1] != '\r' && str[len-1] != '\n')
	break;
      len--;
    }

  /* error condition: no command */
  if(len == 0)
    {
      snprintf(inst->err, sizeof(inst->err), "no command");
      return -1;
    }

  for(i=0; i<len; i++)
    {
      /* error condition: unprintable character in command */
      if(isprint((unsigned char)str[i]) == 0)
	{
	  snprintf(inst->err, sizeof(inst->err), "unprintable char in command");
	  return -1;
	}
    }

  /* error condition: could not malloc task->str */
  if((task->str = malloc(len + 1)) == NULL)
    {
      snprintf(inst->err, sizeof(inst->err), "could not malloc task->str");
      return -1;
    }

  /* copy across string */
  memcpy(task->str, str, len);
  task->str[len] = '\0';
  return 0;
}

static int task_cmp(const scamper_task_t *a, const scamper_task_t *b)
{
  if(a->id < b->id) return -1;
  if(a->id > b->id) return  1;
  return 0;
}

/*
 * attp_str_isvalid:
 *
 * is the string passed in valid for an attach command parameter?
 *
 * this function needs to be kept up to date with what
 * scamper_control.c:params_get() considers valid
 */
static int attp_str_isvalid(const char *str)
{
  int i = 0;

  for(i=0; str[i] != '\0'; i++)
    {
      if(isprint((unsigned char)str[i]) == 0)
	return 0;
      if(str[i] == '"')
	return 0;
    }

  return 1;
}

static int attp_attach(const scamper_attp_t *attp, char *buf, size_t len)
{
  char cycleid[24], descr[128], listid[24], monitor[128], name[128];
  char priority[24];

  if(attp != NULL && attp->flags & SCAMPER_ATTP_FLAG_CYCLEID)
    snprintf(cycleid, sizeof(cycleid), " cycle_id %u", attp->c_id);
  else
    cycleid[0] = '\0';

  if(attp != NULL && attp->l_descr != NULL)
    snprintf(descr, sizeof(descr), " descr \"%s\"", attp->l_descr);
  else
    descr[0] = '\0';

  if(attp != NULL && attp->flags & SCAMPER_ATTP_FLAG_LISTID)
    snprintf(listid, sizeof(listid), " list_id %u", attp->l_id);
  else
    listid[0] = '\0';

  if(attp != NULL && attp->l_monitor != NULL)
    snprintf(monitor, sizeof(monitor), " monitor \"%s\"", attp->l_monitor);
  else
    monitor[0] = '\0';

  if(attp != NULL && attp->l_name != NULL)
    snprintf(name, sizeof(name), " name \"%s\"", attp->l_name);
  else
    name[0] = '\0';

  if(attp != NULL && attp->flags & SCAMPER_ATTP_FLAG_PRIORITY)
    snprintf(priority, sizeof(priority), " priority %u", attp->priority);
  else
    priority[0] = '\0';

  if(6 + strlen(cycleid) + strlen(descr) + strlen(listid) + strlen(monitor) +
     strlen(name) + strlen(priority) >= len)
    return -1;

  snprintf(buf, len, "attach%s%s%s%s%s%s",
	   cycleid, descr, listid, monitor, name, priority);
  return 0;
}

static sc_tx_t *inst_tx(scamper_inst_t *inst, int type, const char *str)
{
  sc_tx_t *tx = NULL;
  uint8_t *buf = NULL;
  size_t x, len = strlen(str);
  sc_fd_t *fdn;

  if(INST_HAS_FDN(inst))
    {
      fdn = inst->fdn;
      if((buf = malloc(len + 1)) == NULL ||
	 (tx = fd_queue(fdn, type, buf, len + 1)) == NULL)
	{
	  snprintf(inst->err, sizeof(inst->err), "could not malloc tx");
	  goto err;
	}
      buf = NULL;
      if(TX_WANT_INST(tx))
	tx->inst = inst;

      memcpy(tx->buf, str, len);
      tx->buf[len] = '\n';

      if(fd_set_write(inst->ctrl, fdn) != 0)
	goto err;
    }
  else if(inst->type == SCAMPER_INST_TYPE_MUXVP)
    {
      fdn = inst->mc->mux->fdn;
      x = MUX_HDRLEN + len + 1;
      if((buf = malloc(x)) == NULL ||
	 (tx = fd_queue(fdn, type, buf, x)) == NULL)
	{
	  snprintf(inst->err, sizeof(inst->err), "could not malloc tx");
	  goto err;
	}
      buf = NULL;
      if(TX_WANT_INST(tx))
	tx->inst = inst;

      bytes_htonl(tx->buf + 0, inst->mc->chan);
      bytes_htonl(tx->buf + 4, len + 1);
      memcpy(tx->buf + MUX_HDRLEN, str, len);
      tx->buf[MUX_HDRLEN + len] = '\n';

      if(fd_set_write(inst->ctrl, fdn) != 0)
	goto err;
    }
  else
    {
      snprintf(inst->err, sizeof(inst->err), "unknown instance type");
      goto err;
    }

  return tx;

 err:
  if(buf != NULL) free(buf);
  return NULL;
}

static int inst_rx(scamper_inst_t *inst, uint8_t *buf, size_t len)
{
  scamper_ctrl_t *ctrl = inst->ctrl;
  size_t i, j, s, x, enc, size, linelen;
  char *start, *ptr, a, b, c, d;
  uint8_t *tmp = NULL;
  scamper_task_t fm;
  sc_tx_t *tx;
  long lo;
  int rc = -1;

  if(inst->line_off > 0)
    {
      size = len + inst->line_off;
      if((tmp = malloc(size)) == NULL)
	{
	  snprintf(ctrl->err, sizeof(ctrl->err), "inst_rx: could not malloc");
	  goto done;
	}
      memcpy(tmp, inst->line, inst->line_off);
      memcpy(tmp + inst->line_off, buf, len);
      buf = tmp;
      len = size;
    }
  inst->line_off = 0;

  x = s = 0;
  while(x < len)
    {
      start = (char *)(buf + s);

      /* continue until we get to the end of the line */
      if(buf[x] != '\n')
	{
	  x++;
	  continue;
	}

      /* count how many characters in this line, then terminate the line */
      linelen = x - s;
      buf[x] = '\0';
      x++;

      /* empty lines are not allowed */
      if(linelen == 0)
	{
	  snprintf(ctrl->err, sizeof(ctrl->err), "unexpected empty line");
	  goto done;
	}

      if(inst->data_len == 0)
	{
	  if(strcasecmp(start, "MORE") == 0)
	    {
	      ctrl->cb(inst, SCAMPER_CTRL_TYPE_MORE, NULL, NULL, 0);
	    }
	  else if(strncasecmp(start, "OK id-", 6) == 0)
	    {
	      if((lo = strtol(start+6, NULL, 10)) < 1)
		{
		  snprintf(ctrl->err, sizeof(ctrl->err),
			   "invalid ID number in OK");
		  goto done;
		}
	      if((tx = slist_head_pop(inst->waitok)) == NULL)
		{
		  snprintf(ctrl->err, sizeof(ctrl->err), "no tx to pop");
		  goto done;
		}
	      assert(tx->txtype == TX_TYPE_TASK);
	      tx->task->id = lo;
	      tx->task->flags &= (~SCAMPER_TASK_FLAG_WAITOK);
	      tx->task->flags |= SCAMPER_TASK_FLAG_GOTID;
	      assert(splaytree_find(inst->tree, tx->task) == NULL);
	      if(splaytree_insert(inst->tree, tx->task) == NULL)
		{
		  snprintf(ctrl->err, sizeof(ctrl->err), "could not add task");
		  goto done;
		}
	      tx->task->tx = NULL; tx->task = NULL;
	      tx_free(tx);
	    }
	  else if(strncasecmp(start, "OK", 2) == 0)
	    {
	      tx = slist_head_pop(inst->waitok);
	      assert(tx->txtype != TX_TYPE_TASK);
	      tx_free(tx);
	    }
	  else if(strncasecmp(start, "ERR", 3) == 0)
	    {
	      tx = slist_head_pop(inst->waitok);
	      assert(tx->txtype == TX_TYPE_TASK);
	      ptr = NULL; size = 0;
	      if(start[3] == ' ' && start[4] != '\0')
		{
		  ptr = start + 4; i = 0;
		  while(isprint((unsigned char)ptr[i]))
		    i++;
		  if(ptr[i] == '\0')
		    size = i;
		  else
		    ptr = NULL;
		}
	      ctrl->cb(inst, SCAMPER_CTRL_TYPE_ERR, tx->task, ptr, size);
	      scamper_task_free(tx->task); tx->task = NULL;
	      ctrl->cb(inst, SCAMPER_CTRL_TYPE_MORE, NULL, NULL, 0);
	      tx_free(tx);
	    }
	  else if(strncasecmp(start, "DATA ", 5) == 0)
	    {
	      assert(inst->data == NULL);
	      assert(inst->data_left == 0);
	      assert(inst->data_len == 0);
	      assert(inst->data_o == 0);

	      /*
	       * find out how large the uuencoded data that follows
	       * is; the minimum acceptable length is 3 because we use
	       * lo-2 below to calculate the size of the buffer to
	       * store uudecoded data.
	       */
	      ptr = NULL;
	      if((lo = strtol(start+5, &ptr, 10)) < 3)
		{
		  snprintf(ctrl->err, sizeof(ctrl->err), "invalid data length");
		  goto done;
		}
	      inst->data_left = (size_t)lo;

	      /* allocate a buffer large enough to store a decoded blob */
	      size = (((lo-2) / 62) * 45) + ((((lo-2) % 62) / 4) * 3);
	      if((inst->data = malloc(size)) == NULL)
		{
		  snprintf(ctrl->err, sizeof(ctrl->err),
			   "could not malloc %d bytes", (int)size);
		  goto done;
		}
	      inst->data_len = size;

	      /* get the ID number if there is one */
	      if(strncasecmp(ptr, " id-", 4) == 0)
		{
		  if((lo = strtol(ptr+4, NULL, 10)) < 1)
		    {
		      snprintf(ctrl->err, sizeof(ctrl->err),
			       "invalid ID in DATA");
		      goto done;
		    }
		  fm.id = lo;
		  if((inst->task = splaytree_find(inst->tree, &fm)) == NULL)
		    {
		      snprintf(ctrl->err, sizeof(ctrl->err),
			       "could not find task with ID %ld", lo);
		      goto done;
		    }
		  splaytree_remove_item(inst->tree, &fm);
		}
	    }
	}
      else
	{
	  /*
	   * make sure the line isn't longer than the apparent amount
	   * of data left
	   */
	  if(linelen + 1 > inst->data_left)
	    {
	      snprintf(ctrl->err, sizeof(ctrl->err), "unexpected long line");
	      goto done;
	    }

	  /* make sure the line only contains valid uuencode characters */
	  for(j=0; j<linelen; j++)
	    {
	      if(start[j] < '!' || start[j] > '`')
		{
		  snprintf(ctrl->err, sizeof(ctrl->err),
			   "line did not start with valid character");
		  goto done;
		}
	    }

	  /* EOF */
	  if(start[0] == '`')
	    goto next;

	  /*
	   * make sure we have space left in the data buffer for that
	   * many bytes
	   */
	  enc = start[0] - 32;
	  if(enc > inst->data_len - inst->data_o)
	    {
	      snprintf(ctrl->err, sizeof(ctrl->err), "unexpected extra data");
	      goto done;
	    }

	  i = 0;
	  j = 1;
	  for(;;)
	    {
	      /* we need a minimum of 4 characters */
	      if(linelen - j < 4)
		{
		  snprintf(ctrl->err, sizeof(ctrl->err), "need 4 characters");
		  goto done;
		}
	      a = (start[j+0] - 32) & 0x3f;
	      b = (start[j+1] - 32) & 0x3f;
	      c = (start[j+2] - 32) & 0x3f;
	      d = (start[j+3] - 32) & 0x3f;

	      /* decode */
	      inst->data[inst->data_o+i] = (a << 2 & 0xfc) | (b >> 4 & 0x3);
	      if(enc - i > 1)
		inst->data[inst->data_o+i+1] = (b << 4 & 0xf0) | (c >> 2 & 0xf);
	      if(enc - i > 2)
		inst->data[inst->data_o+i+2] = (c << 6 & 0xc0) | d;

	      j += 4;
	      if(enc - i > 3)
		i += 3;
	      else break;
	    }

	  inst->data_o += enc;

	next:
	  inst->data_left -= (linelen + 1);
	  if(inst->data_left == 0)
	    {
	      if(inst->task != NULL)
		{
		  inst->task->inst = NULL;
		  inst->task->flags |= SCAMPER_TASK_FLAG_DONE;
		}
	      ctrl->cb(inst, SCAMPER_CTRL_TYPE_DATA, inst->task,
		       inst->data, inst->data_o);
	      free(inst->data); inst->data = NULL;
	      inst->data_o = 0;
	      inst->data_len = 0;
	      if(inst->task != NULL)
		{
		  scamper_task_free(inst->task);
		  inst->task = NULL;
		}
	    }
	}

      /* index into buf where next line starts */
      s = x;
    }

  assert(x == len);

  if(s != x)
    {
      if(s > x)
	{
	  snprintf(ctrl->err, sizeof(ctrl->err), "start beyond line");
	  goto done;
	}
      if(x - s > sizeof(inst->line))
	{
	  snprintf(ctrl->err, sizeof(ctrl->err), "long partial line");
	  goto done;
	}

      inst->line_off = x - s;
      memcpy(inst->line, buf + s, inst->line_off);
    }

  rc = 0;

 done:
  if(tmp != NULL) free(tmp);
  return rc;
}

static void inst_set_null(scamper_inst_t *inst)
{
  inst->ctrl = NULL;
  inst->list = NULL;
  inst->idn = NULL;
  inst->fdn = NULL;
  inst->mc = NULL;
  return;
}

static int inst_set_fd(scamper_inst_t *inst, int *fd)
{
  scamper_ctrl_t *ctrl = inst->ctrl;
  sc_fd_t *fdn = NULL;

  assert(ctrl != NULL);

  /* alloc the sc_fd_t to manage the fd */
  if((fdn = fd_alloc(*fd)) == NULL)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not alloc fd");
      return -1;
    }

  /* fdn now has the fd, will be responsible for closing it */
  *fd = socket_invalid();

  /*
   * put it in the ctrl->fds list.  sc_fd_t must be ejected from this
   * list before being freed.
   */
  if((fdn->fdsdn = dlist_tail_push(ctrl->fds, fdn)) == NULL)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not add to fd list");
      fd_free(fdn);
      return -1;
    }

  /* set pointers appropriately */
  inst->fdn = fdn;
  fdn->fdtype = FD_TYPE_INST;
  fdn->data = inst;
  fdn = NULL;

  if(ctrl->wait == 0 && fd_set_read(ctrl, inst->fdn) != 0)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not set read");
      return -1;
    }

  return 0;
}

static void inst_free(scamper_inst_t *inst)
{
  if(inst->fdn != NULL)
    {
      assert(INST_HAS_FDN(inst));
      assert(inst->ctrl != NULL);
      assert(inst->fdn->fdsdn != NULL);
      dlist_node_pop(inst->ctrl->fds, inst->fdn->fdsdn);
      fd_free(inst->fdn);
    }
  if(inst->mc != NULL)
    {
      assert(inst->type == SCAMPER_INST_TYPE_MUXVP);
      inst->mc->inst = NULL;
    }
  if(inst->idn != NULL)
    dlist_node_pop(inst->list, inst->idn);
  if(inst->name != NULL)
    free(inst->name);
  if(inst->waitok != NULL)
    slist_free_cb(inst->waitok, (slist_free_t)tx_free);
  if(inst->tree != NULL)
    splaytree_free(inst->tree, (splaytree_free_t)scamper_task_free);
  if(inst->data != NULL)
    free(inst->data);
  if(inst->vp != NULL)
    scamper_vp_free(inst->vp);
  free(inst);
  return;
}

#ifndef DMALLOC
static scamper_inst_t *inst_alloc(scamper_ctrl_t *ctrl, uint8_t type,
				  const char *name)
#else
#define inst_alloc(ctrl, type, name)				\
  inst_alloc_dm((ctrl), (type), (name), __FILE__, __LINE__)
static scamper_inst_t *inst_alloc_dm(scamper_ctrl_t *ctrl, uint8_t type,
				     const char *name,
				     const char *file, const int line)
#endif
{
  scamper_inst_t *inst;
  size_t len = sizeof(scamper_inst_t);
  dlist_t *list;

#ifndef DMALLOC
  inst = (scamper_inst_t *)malloc(len);
#else
  inst = (scamper_inst_t *)dmalloc_malloc(file, line, len,
					  DMALLOC_FUNC_MALLOC, 0, 0);
#endif
  if(inst == NULL)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not alloc instance");
      goto err;
    }

  memset(inst, 0, len);

  if((inst->name = strdup(name)) == NULL ||
     (inst->waitok = slist_alloc()) == NULL ||
     (inst->tree = splaytree_alloc((splaytree_cmp_t)task_cmp)) == NULL)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not initialise instance");
      goto err;
    }

  /* put the instance in the appropriate list */
  if(ctrl->wait == 0)
    list = ctrl->insts;
  else
    list = ctrl->waitlist;

#ifndef DMALLOC
  inst->idn = dlist_tail_push(list, inst);
#else
  inst->idn = dlist_tail_push_dm(list, inst, file, line);
#endif
  if(inst->idn == NULL)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not put inst on list");
      goto err;
    }

  inst->list = list;
  inst->ctrl = ctrl;
  inst->type = type;

  return inst;

 err:
  if(inst != NULL)
    inst_free(inst);
  return NULL;
}

static sc_muxchan_t *mc_get(scamper_mux_t *mux, uint32_t chan)
{
  sc_muxchan_t *mc;
  dlist_node_t *dn;

  for(dn=dlist_head_node(mux->channels); dn != NULL; dn=dlist_node_next(dn))
    {
      mc = dlist_node_item(dn);
      if(mc->chan == chan)
	return mc;
    }

  return NULL;
}

static sc_muxchan_t *mc_alloc(scamper_mux_t *mux, scamper_inst_t *inst)
{
  sc_muxchan_t *mc = NULL;

  if((mc = malloc_zero(sizeof(sc_muxchan_t))) == NULL ||
     (mc->cdn = dlist_tail_push(mux->channels, mc)) == NULL)
    goto err;
  mc->chan = mux->next_chan; mux->next_chan++;
  mc->inst = inst;
  mc->mux  = mux;
  inst->mc = mc;

  return mc;

 err:
  if(mc != NULL) free(mc);
  return NULL;
}

static int mux_vp_update(scamper_mux_t *mux, const uint8_t *buf, size_t len)
{
  scamper_vp_t *vp = NULL;
  size_t off = 4;
  uint16_t attr_type;
  const char *start;
  char **out = NULL, *tag = NULL;
  slist_t *tags = NULL;
  int tagc;

  if(len < 4)
    goto err;

  if((vp = malloc_zero(sizeof(scamper_vp_t))) == NULL)
    goto err;
  vp->refcnt = 1;
  vp->id = bytes_ntohl(buf);
  off = 4;

  while(off < len)
    {
      if(len - off < 2)
	goto err;
      attr_type = bytes_ntohs(buf+off);
      off += 2;
      start = (const char *)(buf + off);
      while(off < len && buf[off] != '\0')
	off++;
      if(off == len)
	goto err;
      off++;

      if(attr_type == VP_ATTR_TAG)
	{
	  if((tags == NULL && (tags = slist_alloc()) == NULL) ||
	     (tag = strdup(start)) == NULL ||
	     slist_tail_push(tags, tag) == NULL)
	    {
	      if(tag != NULL)
		free(tag);
	      goto err;
	    }
	}
      else
	{
	  out = NULL;
	  if(attr_type == VP_ATTR_NAME) out = &vp->name;
	  else if(attr_type == VP_ATTR_ARRIVAL) out = &vp->arrival;
	  else if(attr_type == VP_ATTR_IPV4) out = &vp->ipv4;
	  else if(attr_type == VP_ATTR_IPV4_ASN) out = &vp->asn4;
	  else if(attr_type == VP_ATTR_CC) out = &vp->cc;
	  else if(attr_type == VP_ATTR_ST) out = &vp->st;
	  else if(attr_type == VP_ATTR_PLACE) out = &vp->place;
	  else if(attr_type == VP_ATTR_LATLONG) out = &vp->latlong;
	  else if(attr_type == VP_ATTR_SHORTNAME) out = &vp->shortname;
	  if(out != NULL)
	    {
	      if(*out != NULL)
		free(*out);
	      if((*out = strdup(start)) == NULL)
		goto err;
	    }
	}
    }

  if(tags != NULL && (tagc = slist_count(tags)) > 0)
    {
      if((vp->tags = malloc_zero(tagc * sizeof(char *))) == NULL)
	goto err;
      while((tag = slist_head_pop(tags)) != NULL)
	vp->tags[vp->tagc++] = tag;
      slist_free(tags); tags = NULL;
    }

  if(dlist_tail_push(mux->vps, vp) == NULL)
    goto err;
  vp->mux = mux;

  return 0;

 err:
  if(vp != NULL)
    scamper_vp_free(vp);
  if(tags != NULL)
    slist_free_cb(tags, free);
  return -1;
}

static int mux_vp_depart(scamper_mux_t *mux, const uint8_t *buf, size_t len)
{
  scamper_vp_t *vp;
  dlist_node_t *dn;
  uint32_t id;

  if(len < 4)
    return -1;
  id = bytes_ntohl(buf);

  for(dn=dlist_head_node(mux->vps); dn != NULL; dn=dlist_node_next(dn))
    {
      vp = dlist_node_item(dn);
      if(vp->id == id)
	break;
    }
  if(dn == NULL)
    return 0;

  dlist_node_pop(mux->vps, dn);
  vp->mux = NULL;
  scamper_vp_free(vp);

  return 0;
}

static int mux_channel_eof(scamper_mux_t *mux, const uint8_t *buf, size_t len)
{
  scamper_ctrl_t *ctrl;
  scamper_inst_t *inst;
  sc_muxchan_t *mc;

  if(len < 4)
    return -1;

  if((mc = mc_get(mux, bytes_ntohl(buf))) == NULL)
    return 0;

  inst = mc->inst;
  ctrl = inst->ctrl;

  /* remove the sc_muxchan_t from the channel list */
  if(mc->cdn != NULL)
    dlist_node_pop(mux->channels, mc->cdn);
  if(mc->inst != NULL)
    mc->inst->mc = NULL;
  free(mc); mc = NULL;

  /* signal eof */
  ctrl->cb(inst, SCAMPER_CTRL_TYPE_EOF, NULL, NULL, 0);
  if(inst->list == ctrl->insts)
    {
      dlist_node_pop(inst->list, inst->idn);
      inst->idn = NULL; inst->list = NULL;
    }

  return 0;
}

static int mux_read_zero(scamper_mux_t *mux, const uint8_t *buf, size_t len)
{
  uint16_t msg_type;

  if(len < 2)
    return -1;

  msg_type = bytes_ntohs(buf);
  switch(msg_type)
    {
    case MUX_VP_UPDATE:
      if(mux_vp_update(mux, buf+2, len-2) != 0)
	return -1;
      break;
    case MUX_VP_DEPART:
      if(mux_vp_depart(mux, buf+2, len-2) != 0)
	return -1;
      break;
    case MUX_CHANNEL_CLOSE:
      if(mux_channel_eof(mux, buf+2, len-2) != 0)
	return -1;
      break;
    }

  return 0;
}

static void mux_free(scamper_mux_t *mux)
{
  sc_muxchan_t *mc;
  scamper_vp_t *vp;

  if(mux->channels != NULL)
    {
      while((mc = dlist_head_pop(mux->channels)) != NULL)
	{
	  if(mc->inst != NULL)
	    mc->inst->mc = NULL;
	  free(mc);
	}
      dlist_free(mux->channels);
    }

  if(mux->vps != NULL)
    {
      while((vp = dlist_head_pop(mux->vps)) != NULL)
	{
	  vp->mux = NULL;
	  scamper_vp_free(vp);
	}
      dlist_free(mux->vps);
    }

  if(mux->buf != NULL)
    free(mux->buf);
  if(mux->fdn != NULL)
    fd_free(mux->fdn);
  free(mux);

  return;
}

static int mux_read(scamper_mux_t *mux)
{
  scamper_ctrl_t *ctrl;
  scamper_inst_t *inst;
  sc_muxchan_t *mc;
  size_t off, len, left, x;
  ssize_t rc;
  uint32_t msg_chan, msg_len;

  if(realloc_wrap((void **)&mux->buf, mux->buf_len + 8192) != 0)
    {
      if((ctrl = mux->ctrl) != NULL)
	snprintf(ctrl->err, sizeof(ctrl->err), "mux_read: could not malloc");
      return -1;
    }
  assert(mux->buf != NULL);

  rc = recv(mux->fdn->fd, mux->buf + mux->buf_len, 8192, 0);

  if(rc < 0)
    {
      /* didn't recv anything but no fatal error */
      if(errno == EINTR || errno == EAGAIN)
	return 0;

      /* fatal error */
      if((ctrl = mux->ctrl) != NULL)
	snprintf(ctrl->err, sizeof(ctrl->err), "could not recv: %s",
		 strerror(errno));
      return -1;
    }

  if(rc == 0)
    {
      socket_close(mux->fdn->fd);
      mux->fdn->fd = socket_invalid();

      /* go through the list of channels and EOF each of them */
      while((mc = dlist_head_pop(mux->channels)) != NULL)
	{
	  if((inst = mc->inst) != NULL)
	    {
	      ctrl = inst->ctrl;
	      inst->mc = NULL;
	      if(ctrl != NULL)
		{
		  ctrl->cb(inst, SCAMPER_CTRL_TYPE_EOF, NULL, NULL, 0);
		  if(inst->list == ctrl->insts)
		    {
		      dlist_node_pop(inst->list, inst->idn);
		      inst->idn = NULL; inst->list = NULL;
		    }
		}
	    }
	  free(mc);
	}

      return 0;
    }

  len = mux->buf_len + rc;
  off = 0;
  mux->buf_len = 0;

  while(off < len)
    {
      /* how much is left in the buf? */
      left = len - off;

      /* pass non-channel zero messages to the appropriate instance */
      if(mux->recv_chan != 0)
	{
	  x = mux->recv_left <= left ? mux->recv_left : left;
	  if((mc = mc_get(mux, mux->recv_chan)) != NULL && mc->inst != NULL)
	    {
	      if(inst_rx(mc->inst, mux->buf + off, x) != 0)
		return -1;
	    }
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

      /* have the code block at the top of the loop handle frame */
      if(msg_chan != 0)
	{
	  off += MUX_HDRLEN;
	  mux->recv_chan = msg_chan;
	  mux->recv_left = msg_len;
	  continue;
	}

      /* require all of a channel zero message before processing it */
      if(left < MUX_HDRLEN + msg_len)
	break;
      off += MUX_HDRLEN;

      /* process the channel zero message */
      if(mux_read_zero(mux, mux->buf + off, msg_len) != 0)
	{
	  if((ctrl = mux->ctrl) != NULL)
	    snprintf(ctrl->err, sizeof(ctrl->err), "mux_read_zero failed");
	  return -1;
	}

      off += msg_len;
    }

  assert(off <= len);
  mux->buf_len = len - off;
  if(mux->buf_len > 0)
    memmove(mux->buf, mux->buf + off, mux->buf_len);
  realloc_wrap((void **)&mux->buf, mux->buf_len);

  return 0;
}

void scamper_task_free(scamper_task_t *task)
{
  assert(task->refcnt > 0);
  task->refcnt--;
  if(task->refcnt > 0)
    return;
  if(task->str != NULL)
    free(task->str);
  free(task);
  return;
}

scamper_task_t *scamper_task_use(scamper_task_t *task)
{
  if(task != NULL)
    task->refcnt++;
  return task;
}

void *scamper_task_param_get(scamper_task_t *task)
{
  return task->param;
}

void scamper_task_param_set(scamper_task_t *task, void *param)
{
  task->param = param;
  return;
}

char *scamper_task_cmd_get(scamper_task_t *task, char *buf, size_t len)
{
  size_t x, sl;
  sl = strlen(task->str);
  x  = sl < len ? sl : len - 1;
  memcpy(buf, task->str, x);
  buf[x] = '\0';
  return buf;
}

void *scamper_inst_param_get(const scamper_inst_t *inst)
{
  return inst->param;
}

void scamper_inst_param_set(scamper_inst_t *inst, void *param)
{
  inst->param = param;
  return;
}

const char *scamper_inst_name_get(const scamper_inst_t *inst)
{
  return inst->name;
}

uint8_t scamper_inst_type_get(const scamper_inst_t *inst)
{
  return inst->type;
}

scamper_task_t *scamper_inst_do(scamper_inst_t *inst, const char *str, void *p)
{
  scamper_task_t *task = NULL;
  sc_tx_t *tx = NULL;

  if(inst->ctrl == NULL)
    {
      snprintf(inst->err, sizeof(inst->err), "no corresponding control");
      return NULL;
    }

  /* can't send a command after sending done message */
  if((inst->flags & SCAMPER_INST_FLAG_DONE) != 0)
    {
      snprintf(inst->err, sizeof(inst->err), "instance marked done");
      return NULL;
    }

  /* allocate a task to return to the caller */
  if((task = malloc_zero(sizeof(scamper_task_t))) == NULL)
    {
      snprintf(inst->err, sizeof(inst->err), "could not malloc task");
      return NULL;
    }
  task->inst = inst;
  task->refcnt = 1;

  /*
   * make copy of command string for task record, and
   * put the command on the queue
   */
  if(task_set_str(inst, task, str) != 0 ||
     (tx = inst_tx(inst, TX_TYPE_TASK, task->str)) == NULL)
    {
      free(task);
      return NULL;
    }

  tx->task = task; task->tx = tx;
  task->flags |= SCAMPER_TASK_FLAG_QUEUE;
  task->param = p;

  return task;
}

int scamper_task_halt(scamper_task_t *task)
{
  scamper_inst_t *inst;
  char buf[20];

  if(task->inst == NULL)
    return -2;
  inst = task->inst;

  if(inst->ctrl == NULL)
    {
      snprintf(inst->err, sizeof(inst->err), "no corresponding control");
      return -1;
    }

  /*
   * if the user is halting a task which we have already given them
   * data for, then flag this error
   */
  if((task->flags & SCAMPER_TASK_FLAG_DONE) != 0)
    {
      snprintf(inst->err, sizeof(inst->err), "task already done");
      return -1;
    }

  /* if the task hasn't been passed to scamper yet, remove it */
  if(task->flags & SCAMPER_TASK_FLAG_QUEUE)
    {
      assert(task->tx != NULL); assert(task->tx->qdn != NULL);

      if(INST_HAS_FDN(inst))
	dlist_node_pop(inst->fdn->queue, task->tx->qdn);
      else
	dlist_node_pop(inst->mc->mux->fdn->queue, task->tx->qdn);
      task->tx->qdn = NULL;
      task->flags &= (~SCAMPER_TASK_FLAG_QUEUE);
      tx_free(task->tx); task->tx = NULL;
      scamper_task_free(task);
      return 0;
    }

  /*
   * if the task has been passed to scamper but we don't yet have an
   * ID, then mark the task as being marked for halting for when we do
   * get an ID from scamper.
   */
  if(task->flags & SCAMPER_TASK_FLAG_WAITOK)
    {
      task->flags |= SCAMPER_TASK_FLAG_HALT;
      return 0;
    }

  snprintf(buf, sizeof(buf), "halt %u", task->id);
  if(inst_tx(inst, TX_TYPE_HALT, buf) == NULL)
    return -1;
  task->flags |= SCAMPER_TASK_FLAG_HALTED;
  return 0;
}

int scamper_inst_is_muxvp(const scamper_inst_t *inst)
{
  if(inst->type != SCAMPER_INST_TYPE_MUXVP)
    return 0;
  return 1;
}

int scamper_inst_is_inet(const scamper_inst_t *inst)
{
  if(inst->type != SCAMPER_INST_TYPE_INET)
    return 0;
  return 1;
}

int scamper_inst_is_unix(const scamper_inst_t *inst)
{
  if(inst->type != SCAMPER_INST_TYPE_UNIX)
    return 0;
  return 1;
}

int scamper_inst_is_remote(const scamper_inst_t *inst)
{
  if(inst->type != SCAMPER_INST_TYPE_REMOTE)
    return 0;
  return 1;
}

scamper_vp_t *scamper_inst_vp_get(const scamper_inst_t *inst)
{
  return inst->vp;
}

int scamper_inst_done(scamper_inst_t *inst)
{
  /* set the done flag if not already set */
  if((inst->flags & SCAMPER_INST_FLAG_DONE) != 0)
    return 0;
  inst->flags |= SCAMPER_INST_FLAG_DONE;

  /* nothing else to do without a corresponding ctrl */
  if(inst->ctrl == NULL)
    return 0;

  if(inst_tx(inst, TX_TYPE_DONE, "done") == NULL)
    return -1;

  return 0;
}

const char *scamper_inst_strerror(const scamper_inst_t *inst)
{
  return inst->err;
}

/*
 * scamper_inst_free
 *
 * this function is called by a user to free the instance handle.
 */
void scamper_inst_free(scamper_inst_t *inst)
{
  assert(inst != NULL);

  /*
   * if we are in the body of a scamper_inst_wait call, then mark the
   * instance for garbage collection by placing it in the waitlist
   */
  if(inst->list != NULL && inst->ctrl != NULL && inst->ctrl->wait != 0)
    {
      inst->flags |= SCAMPER_INST_FLAG_FREE;
      if(inst->list != inst->ctrl->waitlist)
	{
	  if(inst->list != NULL)
	    dlist_node_eject(inst->list, inst->idn);
	  dlist_node_tail_push(inst->ctrl->waitlist, inst->idn);
	  inst->list = inst->ctrl->waitlist;
	}
    }
  else
    {
      inst_free(inst);
    }
  return;
}

scamper_inst_t *scamper_inst_muxvp(scamper_ctrl_t *ctrl, const char *str)
{
  scamper_mux_t *mux = NULL;
  scamper_inst_t *inst = NULL;
  scamper_vp_t *vp = NULL;
  char *ptr, *dup = NULL, *lastslash = NULL;
  struct stat sb, sb_cmp;
  dlist_node_t *dn;

  if((dup = strdup(str)) == NULL)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not strdup");
      goto done;
    }

  /*
   * evaluate if the path could be a mux socket, with a VP specified
   * after the last slash
   */
  for(ptr = dup; *ptr != '\0'; ptr++)
    if(*ptr == '/')
      lastslash = ptr;
  if(lastslash == NULL)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "expected mux/vp");
      goto done;
    }
  *lastslash = '\0'; ptr = lastslash + 1;
  if(stat(dup, &sb) != 0 || S_ISSOCK(sb.st_mode) == 0)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "%s not a unix socket", dup);
      goto done;
    }

  /* evaluate if we already have the mux socket open */
  for(dn=dlist_head_node(ctrl->muxs); dn != NULL; dn=dlist_node_next(dn))
    {
      mux = dlist_node_item(dn);
      if(mux->fdn != NULL && socket_isvalid(mux->fdn->fd) &&
	 fstat(mux->fdn->fd, &sb_cmp) == 0 &&
	 sb.st_dev == sb_cmp.st_dev && sb.st_ino == sb_cmp.st_ino)
	break;
    }

  /* do not have the mux socket open already, so open it */
  if(dn == NULL && (mux = scamper_mux_add(ctrl, dup)) == NULL)
    goto done;

  /* find the VP in the list */
  for(dn=dlist_head_node(mux->vps); dn != NULL; dn=dlist_node_next(dn))
    {
      vp = dlist_node_item(dn);
      if((vp->name != NULL && strcmp(vp->name, ptr) == 0) ||
	 (vp->shortname != NULL && strcmp(vp->shortname, ptr) == 0))
	break;
    }

  /* do not have a VP with specified name */
  if(dn == NULL)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "no VP named %s on %s",
	       ptr, dup);
      goto done;
    }

  assert(vp != NULL);
  inst = scamper_inst_vp(ctrl, vp);

 done:
  if(dup != NULL) free(dup);
  return inst;
}

scamper_inst_t *scamper_inst_vp(scamper_ctrl_t *ctrl, scamper_vp_t *vp)
{
  scamper_mux_t *mux = NULL;
  scamper_inst_t *inst = NULL;
  sc_muxchan_t *mc = NULL;
  uint8_t *open = NULL;
  char *name;

  if(vp->name != NULL)
    name = vp->name;
  else if(vp->ipv4 != NULL)
    name = vp->ipv4;
  else
    goto err;

  if((mux = vp->mux) == NULL)
    goto err;

  if((open = malloc(MUX_HDRLEN + 2 + 4 + 4)) == NULL ||
     (inst = inst_alloc(ctrl, SCAMPER_INST_TYPE_MUXVP, name)) == NULL ||
     (mc = mc_alloc(mux, inst)) == NULL)
    goto err;
  inst->vp = scamper_vp_use(vp);

  bytes_htonl(open + 0,              0);
  bytes_htonl(open + 4,              10);
  bytes_htons(open + MUX_HDRLEN,     MUX_CHANNEL_OPEN);
  bytes_htonl(open + MUX_HDRLEN + 2, vp->id);
  bytes_htonl(open + MUX_HDRLEN + 6, mc->chan);
  if(fd_queue(mux->fdn, TX_TYPE_MUXVP_OPEN, open, MUX_HDRLEN + 10) == NULL)
    goto err;
  open = NULL;
  if(fd_set_write(ctrl, mux->fdn) != 0)
    goto err;

  return inst;

 err:
  if(open != NULL) free(open);
  return NULL;
}

scamper_inst_t *scamper_inst_inet(scamper_ctrl_t *ctrl,
				  const scamper_attp_t *attp,
				  const char *addr, uint16_t port)
{
  struct sockaddr_storage sas;
  scamper_inst_t *inst = NULL;
  socklen_t sl;
  char buf[256], attp_buf[512];

#ifndef _WIN32 /* type: int vs SOCKET */
  int fd = -1;
#else
  SOCKET fd = INVALID_SOCKET;
#endif

  if(attp_attach(attp, attp_buf, sizeof(attp_buf)) != 0)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not form attach");
      goto err;
    }

  /* form the name of the instance based on address / port */
  if(addr == NULL)
    addr = "127.0.0.1";
  if(sa_fromstr((struct sockaddr *)&sas, addr, port) != 0)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not resolve");
      goto err;
    }
  if(sas.ss_family == AF_INET)
    {
      sl = sizeof(struct sockaddr_in);
      snprintf(buf, sizeof(buf), "%s:%d", addr, port);
    }
  else
    {
      sl = sizeof(struct sockaddr_in6);
      snprintf(buf, sizeof(buf), "[%s]:%d", addr, port);
    }

  /* connect to the scamper instance and set non-blocking */
  fd = socket(sas.ss_family, SOCK_STREAM, IPPROTO_TCP);
  if(socket_isinvalid(fd))
    {
      snprintf(ctrl->err, sizeof(ctrl->err),
	       "could not create inet socket: %s", strerror(errno));
      goto err;
    }
  if(connect(fd, (struct sockaddr *)&sas, sl) != 0)
    {
      snprintf(ctrl->err, sizeof(ctrl->err),
	       "could not connect: %s", strerror(errno));
      goto err;
    }

  if(fd_nonblock(fd, ctrl->err, sizeof(ctrl->err)) != 0 ||
     (inst = inst_alloc(ctrl, SCAMPER_INST_TYPE_INET, buf)) == NULL ||
     inst_set_fd(inst, &fd) != 0 ||
     inst_tx(inst, TX_TYPE_ATTACH, attp_buf) == NULL)
    goto err;

  return inst;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  if(inst != NULL)
    inst_free(inst);
  return NULL;
}

scamper_inst_t *scamper_inst_unix(scamper_ctrl_t *ctrl,
				  const scamper_attp_t *attp,
				  const char *path)
{
#ifdef HAVE_SOCKADDR_UN
  scamper_inst_t *inst = NULL;
  char attp_buf[512];
  int fd = -1;

  if(attp_attach(attp, attp_buf, sizeof(attp_buf)) != 0)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not form attach");
      goto err;
    }

  if((fd = unix_fd(path, ctrl->err, sizeof(ctrl->err))) == -1 ||
     fd_nonblock(fd, ctrl->err, sizeof(ctrl->err)) != 0 ||
     (inst = inst_alloc(ctrl, SCAMPER_INST_TYPE_UNIX, path)) == NULL ||
     inst_set_fd(inst, &fd) != 0 ||
     inst_tx(inst, TX_TYPE_ATTACH, attp_buf) == NULL)
    goto err;

  return inst;

 err:
  if(fd != -1) close(fd);
  if(inst != NULL) inst_free(inst);
#else
  snprintf(ctrl->err, sizeof(ctrl->err), "no sockaddr_un");
#endif
  return NULL;
}

scamper_inst_t *scamper_inst_remote(scamper_ctrl_t *ctrl, const char *path)
{
#ifdef HAVE_SOCKADDR_UN
  scamper_inst_t *inst = NULL;
  int fd = -1;

  if((fd = unix_fd(path, ctrl->err, sizeof(ctrl->err))) == -1 ||
     fd_nonblock(fd, ctrl->err, sizeof(ctrl->err)) != 0 ||
     (inst = inst_alloc(ctrl, SCAMPER_INST_TYPE_REMOTE, path)) == NULL ||
     inst_set_fd(inst, &fd) != 0)
    goto err;

  return inst;

 err:
  if(fd != -1) close(fd);
  if(inst != NULL) inst_free(inst);
#else
  snprintf(ctrl->err, sizeof(ctrl->err), "no sockaddr_un");
#endif
  return NULL;
}

/*
 * scamper_inst_read
 *
 * read from the control socket.
 */
static int scamper_inst_read(scamper_inst_t *inst)
{
  scamper_ctrl_t *ctrl;
  sc_fd_t *fdn;
  uint8_t buf[8192];
  ssize_t rc;

  assert(inst != NULL);
  assert(inst->ctrl != NULL);
  ctrl = inst->ctrl;
  fdn = inst->fdn;

  rc = recv(fdn->fd, buf, sizeof(buf), 0);

  /* if the scamper process exits, pass that through */
  if(rc == 0)
    {
      socket_close(fdn->fd);
      fdn->fd = socket_invalid();

      /*
       * signal EOF on callback.  the callback might call scamper_inst_free,
       * which we can detect because it will not be on ctrl->insts, rather
       * it will be on ctrl->waitlist.  if it is still on ctrl->insts, then
       * remove it from the monitored list.
       */
      ctrl->cb(inst, SCAMPER_CTRL_TYPE_EOF, NULL, NULL, 0);
      if(inst->list == ctrl->insts)
	{
	  dlist_node_pop(inst->list, inst->idn);
	  inst->idn = NULL; inst->list = NULL;
	}
      return 0;
    }

  if(rc < 0)
    {
      /* didn't recv anything but no fatal error */
      if(errno == EINTR || errno == EAGAIN)
	return 0;

      /* fatal error */
      snprintf(ctrl->err, sizeof(ctrl->err), "could not recv: %s",
	       strerror(errno));
      goto fatal;
    }

  if(inst_rx(inst, buf, rc) != 0)
    goto fatal;

  return 0;

 fatal:
  ctrl->cb(inst, SCAMPER_CTRL_TYPE_FATAL, NULL, NULL, 0);
  return 0;
}

scamper_ctrl_t *scamper_inst_ctrl_get(const scamper_inst_t *inst)
{
  return inst->ctrl;
}

static int ctrl_wait_done(scamper_ctrl_t *ctrl, int rc)
{
  scamper_inst_t *inst;

  /* no longer going to be in scamper_ctrl_wait() */
  ctrl->wait = 0;

  /*
   * the nodes in the waitlist were put in there by the user calling
   * - scamper_inst_free to free the instance,
   * - scamper_inst_unix, scamper_inst_remote, scamper_inst_inet to
   *   add a new instance.
   * while in scamper_ctrl_wait.  process them now.
   */
  while((inst = dlist_head_pop(ctrl->waitlist)) != NULL)
    {
      if(inst->flags & SCAMPER_INST_FLAG_FREE)
	{
	  inst->list = NULL; inst->idn = NULL;
	  inst_free(inst);
	}
      else
	{
	  assert(inst->ctrl == ctrl);
	  if(inst->list != NULL)
	    dlist_node_eject(inst->list, inst->idn);
	  dlist_node_tail_push(ctrl->insts, inst->idn);
	  inst->list = ctrl->insts;
	  if(INST_HAS_FDN(inst) &&
	     fd_set_read(ctrl, inst->fdn) != 0 && rc == 0)
	    {
	      snprintf(ctrl->err, sizeof(ctrl->err), "could not set read");
	      rc = -1;
	    }
	}
    }

  return rc;
}

scamper_mux_t *scamper_mux_add(scamper_ctrl_t *ctrl, const char *path)
{
  uint8_t buf[MUX_HDRLEN + 65536];
  scamper_mux_t *mux;
  ssize_t off, rc;
  uint32_t msg_len;
  uint16_t msg_type = 0;
  sc_fd_t *fdn = NULL;
  int fd = -1;

  if((mux = malloc_zero(sizeof(scamper_mux_t))) == NULL ||
     (mux->vps = dlist_alloc()) == NULL ||
     (mux->channels = dlist_alloc()) == NULL)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not alloc mux");
      goto err;
    }
  if((fd = unix_fd(path, ctrl->err, sizeof(ctrl->err))) == -1)
    goto err;
  mux->next_chan = 1;

  /* read until we get a go message */
  off = 0;
  for(;;)
    {
      /* no space left in buffer, error condition */
      if(sizeof(buf) <= (size_t)off)
	{
	  snprintf(ctrl->err, sizeof(ctrl->err),
		   "no space left in buf when initializing");
	  goto err;
	}

      /* read until we have at least a 6 byte header */
      if((rc = recv(fd, buf + off, sizeof(buf) - off, 0)) <= 0)
	{
	  if(rc == 0)
	    snprintf(ctrl->err, sizeof(ctrl->err), "mux disconnected");
	  else
	    snprintf(ctrl->err, sizeof(ctrl->err), "could not read mux: %s",
		     strerror(errno));
	  goto err;
	}
      off += rc;

      while(off >= 6)
	{
	  /*
	   * make sure we're dealing with channel zero, the message is
	   * at least long enough to contain a two byte type value.
	   * if we don't, this is an error condition.
	   */
	  if(bytes_ntohl(buf) != 0 || (msg_len = bytes_ntohl(buf+4)) < 2)
	    {
	      snprintf(ctrl->err, sizeof(ctrl->err), "invalid message on mux");
	      goto err;
	    }

	  /* need to do another read if we do not have all of the message */
	  if(msg_len > (uint32_t)off - MUX_HDRLEN)
	    break;

	  if((msg_type = bytes_ntohs(buf + MUX_HDRLEN)) == MUX_VP_UPDATE)
	    {
	      if(mux_vp_update(mux, buf + MUX_HDRLEN + 2, msg_len - 2) != 0)
		goto err;
	    }

	  /* shuffle any buffered data */
	  off -= (MUX_HDRLEN + msg_len);
	  memmove(buf, buf + MUX_HDRLEN + msg_len, off);

	  if(msg_type == MUX_GO)
	    goto done;
	}
    }

 done:
  assert(msg_type == MUX_GO);
  if(off != 0)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "unexpected data after GO");
      goto err;
    }

  if(fd_nonblock(fd, ctrl->err, sizeof(ctrl->err)) != 0)
    goto err;

  if((fdn = fd_alloc(fd)) == NULL)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not alloc fd");
      goto err;
    }
  fd = socket_invalid();

  if((fdn->fdsdn = dlist_tail_push(ctrl->fds, fdn)) == NULL)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not add to fd list");
      fd_free(fdn);
      goto err;
    }
  mux->fdn = fdn;
  fdn->fdtype = FD_TYPE_MUX;
  fdn->data = mux;
  fdn = NULL;

  if(dlist_tail_push(ctrl->muxs, mux) == NULL)
    goto err;
  mux->ctrl = ctrl;

  return mux;

 err:
  if(fd != -1) close(fd);
  if(fdn != NULL) fd_free(fdn);
  if(mux != NULL) mux_free(mux);
  return NULL;
}

void scamper_mux_free(scamper_mux_t *mux)
{
  mux_free(mux);
  return;
}

void scamper_vp_free(scamper_vp_t *vp)
{
  size_t i;
  if(--vp->refcnt > 0)
    return;
  if(vp->name != NULL) free(vp->name);
  if(vp->arrival != NULL) free(vp->arrival);
  if(vp->ipv4 != NULL) free(vp->ipv4);
  if(vp->asn4 != NULL) free(vp->asn4);
  if(vp->cc != NULL) free(vp->cc);
  if(vp->st != NULL) free(vp->st);
  if(vp->place != NULL) free(vp->place);
  if(vp->latlong != NULL) free(vp->latlong);
  if(vp->shortname != NULL) free(vp->shortname);
  if(vp->tags != NULL)
    {
      for(i=0; i<vp->tagc; i++)
	if(vp->tags[i] != NULL)
	  free(vp->tags[i]);
      free(vp->tags);
    }
  free(vp);
  return;
}

scamper_vp_t *scamper_vp_use(scamper_vp_t *vp)
{
  vp->refcnt++;
  return vp;
}

const char *scamper_vp_name_get(const scamper_vp_t *vp)
{
  if(vp != NULL)
    return vp->name;
  return NULL;
}

const char *scamper_vp_shortname_get(const scamper_vp_t *vp)
{
  if(vp != NULL)
    return vp->shortname;
  return NULL;
}

const char *scamper_vp_ipv4_get(const scamper_vp_t *vp)
{
  if(vp != NULL)
    return vp->ipv4;
  return NULL;
}

const char *scamper_vp_asn4_get(const scamper_vp_t *vp)
{
  if(vp != NULL)
    return vp->asn4;
  return NULL;
}

const char *scamper_vp_cc_get(const scamper_vp_t *vp)
{
  if(vp != NULL)
    return vp->cc;
  return NULL;
}

const char *scamper_vp_st_get(const scamper_vp_t *vp)
{
  if(vp != NULL)
    return vp->st;
  return NULL;
}

const char *scamper_vp_place_get(const scamper_vp_t *vp)
{
  if(vp != NULL)
    return vp->place;
  return NULL;
}

const char *scamper_vp_latlong_get(const scamper_vp_t *vp)
{
  if(vp != NULL)
    return vp->latlong;
  return NULL;
}

const char *scamper_vp_tag_get(const scamper_vp_t *vp, size_t i)
{
  if(vp == NULL || vp->tags == NULL || vp->tagc <= i)
    return NULL;
  return vp->tags[i];
}

size_t scamper_vp_tagc_get(const scamper_vp_t *vp)
{
  if(vp != NULL)
    return vp->tagc;
  return 0;
}

scamper_vp_t *scamper_vpset_vp_get(const scamper_vpset_t *vpset, size_t i)
{
  if(vpset == NULL || vpset->vps == NULL || vpset->vpc <= i)
    return NULL;
  return vpset->vps[i];
}

void scamper_vpset_free(scamper_vpset_t *vpset)
{
  size_t i;

  if(vpset->vps != NULL)
    {
      for(i=0; i<vpset->vpc; i++)
	scamper_vp_free(vpset->vps[i]);
      free(vpset->vps);
    }
  free(vpset);

  return;
}

size_t scamper_vpset_vp_count(const scamper_vpset_t *vpset)
{
  if(vpset == NULL)
    return 0;
  return vpset->vpc;
}

scamper_vpset_t *scamper_vpset_get(const scamper_mux_t *mux)
{
  scamper_vpset_t *vpset = NULL;
  dlist_node_t *dn;
  scamper_vp_t *vp;
  int vpc;

  vpc = dlist_count(mux->vps);
  if((vpset = malloc_zero(sizeof(scamper_vpset_t))) == NULL)
    goto err;

  if(vpc > 0)
    {
      if((vpset->vps = malloc_zero(sizeof(scamper_vp_t *) * vpc)) == NULL)
	goto err;
      for(dn=dlist_head_node(mux->vps); dn != NULL; dn=dlist_node_next(dn))
	{
	  vp = dlist_node_item(dn);
	  vpset->vps[vpset->vpc++] = scamper_vp_use(vp);
	}
    }

  return vpset;

 err:
  if(vpset != NULL) scamper_vpset_free(vpset);
  return NULL;
}

#ifdef HAVE_KQUEUE
int scamper_ctrl_wait(scamper_ctrl_t *ctrl, struct timeval *to)
{
  struct kevent events[128];
  int eventc = sizeof(events) / sizeof(struct kevent);
  struct timespec ts, *timeout;
  sc_fd_t *fdn;
  int i, c, rc = -1;

  if(to != NULL)
    {
      ts.tv_sec = to->tv_sec;
      ts.tv_nsec = to->tv_usec * 1000;
      timeout = &ts;
    }
  else
    {
      timeout = NULL;
    }

  if((c = kevent(ctrl->kqfd, NULL, 0, events, eventc, timeout)) == -1)
    {
      if(errno == EINTR)
	rc = 0;
      else
	snprintf(ctrl->err, sizeof(ctrl->err), "could not kevent");
      goto done;
    }

  ctrl->wait = 1;
  for(i=0; i<c; i++)
    {
      fdn = events[i].udata;
      if(events[i].filter == EVFILT_READ && socket_isvalid(fdn->fd))
	{
	  if(fdn->fdtype == FD_TYPE_INST)
	    {
	      if(scamper_inst_read(fdn->data) != 0)
		goto done;
	    }
	  else if(fdn->fdtype == FD_TYPE_MUX)
	    {
	      if(mux_read(fdn->data) != 0)
		goto done;
	    }
	}
      else if(events[i].filter == EVFILT_WRITE && socket_isvalid(fdn->fd))
	{
	  assert(fdn->fdtype == FD_TYPE_INST ||
		 fdn->fdtype == FD_TYPE_MUX);
	  if(fd_write(ctrl, fdn) != 0)
	    goto done;
	}
    }

  rc = 0;

 done:
  return ctrl_wait_done(ctrl, rc);
}
#else
int scamper_ctrl_wait(scamper_ctrl_t *ctrl, struct timeval *to)
{
  dlist_node_t *dn;
  fd_set rfds, wfds, *wfdsp, *rfdsp;
  int count = 0, rc = -1, nfds;
  sc_fd_t *fdn;

#ifndef _WIN32 /* type: int vs SOCKET */
  int fd;
#else
  SOCKET fd;
#endif

  nfds = -1; FD_ZERO(&rfds); FD_ZERO(&wfds); wfdsp = NULL; rfdsp = NULL;
  for(dn=dlist_head_node(ctrl->fds); dn != NULL; dn=dlist_node_next(dn))
    {
      fdn = dlist_node_item(dn);
      assert(socket_isvalid(fdn->fd));
      FD_SET(fdn->fd, &rfds); rfdsp = &rfds;
      nfds = socket_setnfds(nfds, fdn->fd);
      if(fdn->write != 0)
	{
	  FD_SET(fdn->fd, &wfds);
	  wfdsp = &wfds;
	}
    }

  if((count = select(nfds+1, rfdsp, wfdsp, NULL, to)) < 0)
    {
      if(errno == EINTR || errno == EAGAIN)
	rc = 0;
      else
	snprintf(ctrl->err, sizeof(ctrl->err), "could not select: %s",
		 strerror(errno));
      goto done;
    }

  if(rfdsp == NULL)
    return 0;

  ctrl->wait = 1;
  dn = dlist_head_node(ctrl->fds);
  while(dn != NULL && count > 0)
    {
      fdn = dlist_node_item(dn);
      dn = dlist_node_next(dn);

      /* take a copy incase FD becomes invalid, to work with count */
      fd = fdn->fd;

      if(FD_ISSET(fd, &rfds))
	{
	  count--;
	  if(fdn->fdtype == FD_TYPE_INST)
	    {
	      if(scamper_inst_read(fdn->data) != 0)
		goto done;
	    }
	  else if(fdn->fdtype == FD_TYPE_MUX)
	    {
	      if(mux_read(fdn->data) != 0)
		goto done;
	    }
	}
      if(wfdsp != NULL && FD_ISSET(fd, wfdsp))
	{
	  count--;
	  if(socket_isvalid(fdn->fd))
	    {
	      assert(fdn->fdtype == FD_TYPE_INST ||
		     fdn->fdtype == FD_TYPE_MUX);
	      if(fd_write(ctrl, fdn) != 0)
		goto done;
	    }
	}
    }

  rc = 0;

 done:
  return ctrl_wait_done(ctrl, rc);
}
#endif

/*
 * scamper_ctrl_free:
 *
 * a user has called scamper_ctrl_free.
 * detach all inst referenced in the lists from the ctrl, and then free
 * the ctrl data structure itself.
 * the user will free the inst themselves.
 */
void scamper_ctrl_free(scamper_ctrl_t *ctrl)
{
  scamper_mux_t *mux;

  assert(ctrl != NULL);

  if(ctrl->fds != NULL)
    dlist_free_cb(ctrl->fds, (dlist_free_t)fd_free);
  if(ctrl->muxs != NULL)
    {
      while((mux = dlist_head_pop(ctrl->muxs)) != NULL)
	{
	  /* mux->fdn was free'd when it was removed from ctrl->fds */
	  mux->fdn = NULL;
	  mux_free(mux);
	}
      dlist_free(ctrl->muxs);
    }
  if(ctrl->insts != NULL)
    dlist_free_cb(ctrl->insts, (dlist_free_t)inst_set_null);
  if(ctrl->waitlist != NULL)
    dlist_free_cb(ctrl->waitlist, (dlist_free_t)inst_set_null);

#ifdef HAVE_KQUEUE
  if(ctrl->kqfd != -1)
    close(ctrl->kqfd);
#endif

  free(ctrl);
  return;
}

#ifndef DMALLOC
scamper_ctrl_t *scamper_ctrl_alloc(scamper_ctrl_cb_t cb)
#else
scamper_ctrl_t *scamper_ctrl_alloc_dm(scamper_ctrl_cb_t cb,
				      const char *file, const int line)
#endif
{
  scamper_ctrl_t *ctrl;
  size_t len = sizeof(scamper_ctrl_t);

#ifndef DMALLOC
  ctrl = (scamper_ctrl_t *)malloc(len);
#else
  ctrl = (scamper_ctrl_t *)dmalloc_malloc(file, line, len,
					  DMALLOC_FUNC_MALLOC, 0, 0);
#endif

  if(ctrl == NULL)
    return NULL;
  memset(ctrl, 0, sizeof(scamper_ctrl_t));

#ifdef HAVE_KQUEUE
  if((ctrl->kqfd = kqueue()) == -1)
    goto err;
#endif

#ifndef DMALLOC
  ctrl->insts = dlist_alloc();
  ctrl->waitlist = dlist_alloc();
  ctrl->fds = dlist_alloc();
  ctrl->muxs = dlist_alloc();
#else
  ctrl->insts = dlist_alloc_dm(file, line);
  ctrl->waitlist = dlist_alloc_dm(file, line);
  ctrl->fds = dlist_alloc_dm(file, line);
  ctrl->muxs = dlist_alloc_dm(file, line);
#endif

  if(ctrl->insts == NULL || ctrl->waitlist == NULL || ctrl->fds == NULL ||
     ctrl->muxs == NULL)
    goto err;

  ctrl->cb = cb;

  return ctrl;

 err:
  if(ctrl != NULL) scamper_ctrl_free(ctrl);
  return NULL;
}

#ifdef DMALLOC
#undef scamper_ctrl_alloc
scamper_ctrl_t *scamper_ctrl_alloc(scamper_ctrl_cb_t cb)
{
  return scamper_ctrl_alloc_dm(cb, __FILE__, __LINE__);
}
#endif

const char *scamper_ctrl_type_tostr(uint8_t type)
{
  switch(type)
    {
    case SCAMPER_CTRL_TYPE_DATA:  return "data";
    case SCAMPER_CTRL_TYPE_MORE:  return "more";
    case SCAMPER_CTRL_TYPE_ERR:   return "err";
    case SCAMPER_CTRL_TYPE_EOF:   return "eof";
    case SCAMPER_CTRL_TYPE_FATAL: return "fatal";
    }
  return NULL;
}

int scamper_ctrl_isdone(scamper_ctrl_t *ctrl)
{
  if(dlist_count(ctrl->insts) > 0)
    return 0;
  return 1;
}

void *scamper_ctrl_param_get(const scamper_ctrl_t *ctrl)
{
  return ctrl->param;
}

void scamper_ctrl_param_set(scamper_ctrl_t *ctrl, void *param)
{
  ctrl->param = param;
  return;
}

const char *scamper_ctrl_strerror(const scamper_ctrl_t *ctrl)
{
  return ctrl->err;
}

#ifndef DMALLOC
scamper_attp_t *scamper_attp_alloc(void)
#else
scamper_attp_t *scamper_attp_alloc_dm(const char *file, const int line)
#endif
{
  scamper_attp_t *attp;
  size_t len = sizeof(scamper_attp_t);

#ifndef DMALLOC
  attp = (scamper_attp_t *)malloc(len);
#else
  attp = (scamper_attp_t *)dmalloc_malloc(file, line, len,
					  DMALLOC_FUNC_MALLOC, 0, 0);
#endif

  if(attp == NULL) return NULL;
  memset(attp, 0, len);
  return attp;
}

#ifdef DMALLOC
#undef scamper_attp_alloc
scamper_attp_t *scamper_attp_alloc(void)
{
  return scamper_attp_alloc_dm(__FILE__, __LINE__);
}
#endif

void scamper_attp_listid_set(scamper_attp_t *attp, uint32_t list_id)
{
  attp->flags |= SCAMPER_ATTP_FLAG_LISTID;
  attp->l_id = list_id;
  return;
}

int scamper_attp_listname_set(scamper_attp_t *attp, char *list_name)
{
  char *tmp;
  if(attp_str_isvalid(list_name) == 0 ||
     (tmp = strdup(list_name)) == NULL)
    return -1;
  if(attp->l_name != NULL)
    free(attp->l_name);
  attp->l_name = tmp;
  return 0;
}

int scamper_attp_listdescr_set(scamper_attp_t *attp, char *list_descr)
{
  char *tmp;
  if(attp_str_isvalid(list_descr) == 0 ||
     (tmp = strdup(list_descr)) == NULL)
    return -1;
  if(attp->l_descr != NULL)
    free(attp->l_descr);
  attp->l_descr = tmp;
  return 0;
}

int scamper_attp_listmonitor_set(scamper_attp_t *attp, char *list_monitor)
{
  char *tmp;
  if(attp_str_isvalid(list_monitor) == 0 ||
     (tmp = strdup(list_monitor)) == NULL)
    return -1;
  if(attp->l_monitor != NULL)
    free(attp->l_monitor);
  attp->l_monitor = tmp;
  return 0;
}

void scamper_attp_cycleid_set(scamper_attp_t *attp, uint32_t cycle_id)
{
  attp->flags |= SCAMPER_ATTP_FLAG_CYCLEID;
  attp->c_id = cycle_id;
  return;
}

void scamper_attp_priority_set(scamper_attp_t *attp, uint32_t priority)
{
  attp->flags |= SCAMPER_ATTP_FLAG_PRIORITY;
  attp->priority = priority;
  return;
}

void scamper_attp_free(scamper_attp_t *attp)
{
  if(attp == NULL)
    return;
  if(attp->l_name != NULL) free(attp->l_name);
  if(attp->l_descr != NULL) free(attp->l_descr);
  if(attp->l_monitor != NULL) free(attp->l_monitor);
  free(attp);
  return;
}
