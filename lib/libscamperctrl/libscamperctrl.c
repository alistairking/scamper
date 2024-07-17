/*
 * libscamperctrl
 *
 * $Id: libscamperctrl.c,v 1.59 2024/04/26 06:52:24 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2021-2023 Matthew Luckie. All rights reserved.
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

struct scamper_ctrl
{
  dlist_t           *insts;    /* insts under management */
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
  dlist_node_t      *dn;       /* dlist node in ctrl->insts or ctrl->waitlist */
  char              *name;     /* string representing name of instance */
  void              *param;    /* user-supplied parameter */
  uint8_t            type;     /* types: inet, unix, or remote */
  uint8_t            flags;    /* flags: done */
#ifndef _WIN32 /* type: int vs SOCKET */
  int                fd;       /* file descriptor for socket */
#else
  SOCKET             fd;       /* file descriptor for socket */
#endif
  uint32_t           seq;      /* next sequence number to assign */
  dlist_t           *queue;    /* list of commands queued */
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

typedef struct scamper_cmd
{
  uint8_t            type;    /* type of command */
  uint32_t           seq;     /* order the command was received in */
  char              *str;     /* string to send */
  size_t             off;     /* where in the command we are up to */
  size_t             len;     /* length of string, including \n */
  scamper_task_t    *task;    /* pointer to the task */
  dlist_node_t      *dn;      /* pointer to the dlist_node_t when in queue */
} scamper_cmd_t;

struct scamper_task
{
  scamper_cmd_t     *cmd;      /* backpointer to a command in queue/waitok */
  uint32_t           id;       /* the task ID returned by scamper */
  uint8_t            refcnt;   /* max value is 2 */
  uint8_t            flags;    /* flags */
  void              *param;    /* user-supplied parameter */
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

#define SCAMPER_INST_FLAG_DONE   0x01 /* "done" sent for this inst */
#ifdef HAVE_KQUEUE
#define SCAMPER_INST_FLAG_WRITE  0x02 /* EVFILT_WRITE set for kqueue */
#endif
#define SCAMPER_INST_FLAG_FREE   0x04 /* the inst is in the waitlist to free */

#define SCAMPER_CMD_TYPE_ATTACH  1
#define SCAMPER_CMD_TYPE_HALT    2
#define SCAMPER_CMD_TYPE_TASK    3
#define SCAMPER_CMD_TYPE_DONE    4

#define SCAMPER_TASK_FLAG_QUEUE  0x01
#define SCAMPER_TASK_FLAG_WAITOK 0x02
#define SCAMPER_TASK_FLAG_GOTID  0x04
#define SCAMPER_TASK_FLAG_DONE   0x08
#define SCAMPER_TASK_FLAG_HALT   0x10
#define SCAMPER_TASK_FLAG_HALTED 0x20

#define SCAMPER_ATTP_FLAG_LISTID   0x01
#define SCAMPER_ATTP_FLAG_CYCLEID  0x02
#define SCAMPER_ATTP_FLAG_PRIORITY 0x04

void scamper_task_free(scamper_task_t *task)
{
  assert(task->refcnt > 0);
  task->refcnt--;
  if(task->refcnt > 0)
    return;
  free(task);
  return;
}

void scamper_task_use(scamper_task_t *task)
{
  task->refcnt++;
  return;
}

static int scamper_task_cmp(const scamper_task_t *a, const scamper_task_t *b)
{
  if(a->id < b->id) return -1;
  if(a->id > b->id) return  1;
  return 0;
}

void *scamper_task_getparam(scamper_task_t *task)
{
  return task->param;
}

void scamper_task_setparam(scamper_task_t *task, void *param)
{
  task->param = param;
  return;
}

char *scamper_task_getcmd(scamper_task_t *task, char *buf, size_t len)
{
  size_t x;
  if(task->cmd->len < len)
    x = task->cmd->len - 1;
  else
    x = len - 1;
  memcpy(buf, task->cmd->str, x);
  buf[x] = '\0';
  return buf;
}

static void scamper_cmd_free(scamper_cmd_t *cmd)
{
  if(cmd->str != NULL)
    free(cmd->str);
  free(cmd);
  return;
}

/*
 * scamper_inst_cmd
 *
 * put the string in the queue to do.  silently remove any trailing \n
 * if they were included by the user even though we add our own.
 *
 * if an error occurs, this function places a string into the error buf.
 */
static scamper_cmd_t *scamper_inst_cmd(scamper_inst_t *inst,
				       uint8_t type, const char *str)
{
  scamper_cmd_t *cmd = NULL;
  size_t i, len = strlen(str);

#ifdef HAVE_KQUEUE
  struct kevent kev;
#endif

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
  if(len == 0)
    {
      snprintf(inst->err, sizeof(inst->err), "no command");
      goto err;
    }
  for(i=0; i<len; i++)
    {
      if(isprint((unsigned char)str[i]) == 0)
	{
	  snprintf(inst->err, sizeof(inst->err),
		   "unprintable character in command");
	  goto err;
	}
    }

  if((cmd = malloc(sizeof(scamper_cmd_t))) == NULL)
    {
      snprintf(inst->err, sizeof(inst->err), "could not malloc cmd");
      goto err;
    }
  memset(cmd, 0, sizeof(scamper_cmd_t));
  cmd->type = type;
  cmd->seq = inst->seq; inst->seq++;

  if((cmd->str = malloc(len+2)) == NULL)
    {
      snprintf(inst->err, sizeof(inst->err), "could not malloc cmd->str");
      goto err;
    }
  memcpy(cmd->str, str, len);
  cmd->str[len++] = '\n';
  cmd->str[len] = '\0';
  cmd->len = len;

  if((cmd->dn = dlist_tail_push(inst->queue, cmd)) == NULL)
    {
      snprintf(inst->err, sizeof(inst->err), "could not push cmd");
      goto err;
    }

#ifdef HAVE_KQUEUE
  if((inst->flags & SCAMPER_INST_FLAG_WRITE) == 0)
    {
      EV_SET(&kev, inst->fd, EVFILT_WRITE, EV_ADD, 0, 0, inst);
      if(kevent(inst->ctrl->kqfd, &kev, 1, NULL, 0, NULL) != 0)
	goto err;
      inst->flags |= SCAMPER_INST_FLAG_WRITE;
    }
#endif

  return cmd;

 err:
  if(cmd != NULL) scamper_cmd_free(cmd);
  return NULL;
}

void *scamper_inst_getparam(const scamper_inst_t *inst)
{
  return inst->param;
}

void scamper_inst_setparam(scamper_inst_t *inst, void *param)
{
  inst->param = param;
  return;
}

const char *scamper_inst_getname(const scamper_inst_t *inst)
{
  return inst->name;
}

uint8_t scamper_inst_gettype(const scamper_inst_t *inst)
{
  return inst->type;
}

scamper_task_t *scamper_inst_do(scamper_inst_t *inst, const char *str, void *p)
{
  scamper_task_t *task = NULL;
  scamper_cmd_t *cmd = NULL;

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

  /* make sure the thing to isn't a reserved keyword */
  if(strncasecmp(str, "attach", 6) == 0 &&
     strncasecmp(str, "halt", 4) == 0 &&
     strncasecmp(str, "done", 4) == 0)
    {
      snprintf(inst->err, sizeof(inst->err), "%s invalid command", str);
      return NULL;
    }

  /* allocate a task to return to the caller */
  if((task = malloc(sizeof(scamper_task_t))) == NULL)
    {
      snprintf(inst->err, sizeof(inst->err), "could not malloc task");
      return NULL;
    }
  memset(task, 0, sizeof(scamper_task_t));

  /* put the command on the queue */
  if((cmd = scamper_inst_cmd(inst, SCAMPER_CMD_TYPE_TASK, str)) == NULL)
    {
      free(task);
      return NULL;
    }
  cmd->task = task; task->cmd = cmd;
  task->refcnt = 1;
  task->flags |= SCAMPER_TASK_FLAG_QUEUE;
  task->param = p;
  return task;
}

int scamper_inst_halt(scamper_inst_t *inst, scamper_task_t *task)
{
  char buf[20];

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
      assert(task->cmd != NULL); assert(task->cmd->dn != NULL);
      dlist_node_pop(inst->queue, task->cmd->dn);
      task->flags &= (~SCAMPER_TASK_FLAG_QUEUE);
      task->cmd->dn = NULL;
      scamper_cmd_free(task->cmd); task->cmd = NULL;
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
  if(scamper_inst_cmd(inst, SCAMPER_CMD_TYPE_HALT, buf) == NULL)
    return -1;
  task->flags |= SCAMPER_TASK_FLAG_HALTED;
  return 0;
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

  if(scamper_inst_cmd(inst, SCAMPER_CMD_TYPE_DONE, "done") == NULL)
    return -1;
  return 0;
}

const char *scamper_inst_strerror(const scamper_inst_t *inst)
{
  return inst->err;
}

static void scamper_inst_freedo(scamper_inst_t *inst)
{
  if(inst->dn != NULL)
    dlist_node_pop(inst->list, inst->dn);
  if(socket_isvalid(inst->fd))
    socket_close(inst->fd);
  if(inst->name != NULL)
    free(inst->name);
  if(inst->waitok != NULL)
    slist_free_cb(inst->waitok, (slist_free_t)scamper_cmd_free);
  if(inst->queue != NULL)
    dlist_free_cb(inst->queue, (dlist_free_t)scamper_cmd_free);
  if(inst->tree != NULL)
    splaytree_free(inst->tree, (splaytree_free_t)scamper_task_free);
  if(inst->data != NULL)
    free(inst->data);
  free(inst);
  return;
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
	  dlist_node_tail_push(inst->ctrl->waitlist, inst->dn);
	  inst->list = inst->ctrl->waitlist;
	}
    }
  else
    {
      scamper_inst_freedo(inst);
    }
  return;
}

static int inst_set_read(scamper_ctrl_t *ctrl, scamper_inst_t *inst)
{
#ifdef HAVE_KQUEUE
  struct kevent kev;
  EV_SET(&kev, inst->fd, EVFILT_READ, EV_ADD, 0, 0, inst);
  if(kevent(ctrl->kqfd, &kev, 1, NULL, 0, NULL) != 0)
    return -1;
#endif
  return 0;
}

#ifndef DMALLOC
static scamper_inst_t *scamper_inst_alloc(scamper_ctrl_t *ctrl, uint8_t t,
#ifndef _WIN32 /* SOCKET vs int on windows */
					  int fd,
#else
					  SOCKET fd,
#endif
					  const char *name)
#else
#define scamper_inst_alloc(ctrl, t, fd, name)				\
  scamper_inst_alloc_dm((ctrl), (t), (fd), (name), __FILE__, __LINE__)
static scamper_inst_t *scamper_inst_alloc_dm(scamper_ctrl_t *ctrl, uint8_t t,
#ifndef _WIN32 /* SOCKET vs int on windows */
					     int fd,
#else
					     SOCKET fd,
#endif
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
  inst->fd = socket_invalid();

  if((inst->name = strdup(name)) == NULL ||
     (inst->waitok = slist_alloc()) == NULL ||
     (inst->queue = dlist_alloc()) == NULL ||
     (inst->tree = splaytree_alloc((splaytree_cmp_t)scamper_task_cmp)) == NULL)
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
  inst->dn = dlist_tail_push(list, inst);
#else
  inst->dn = dlist_tail_push_dm(list, inst, file, line);
#endif
  if(inst->dn == NULL)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not put inst on list");
      goto err;
    }

  inst->list = list;
  inst->ctrl = ctrl;
  inst->type = t;
  inst->fd   = fd;

  if(ctrl->wait == 0 && inst_set_read(ctrl, inst) != 0)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not set read");
      goto err;
    }

  return inst;

 err:
  if(inst != NULL)
    {
      /* the caller will call close on the fd they passed in */
      inst->fd = socket_invalid();
      scamper_inst_freedo(inst);
    }
  return NULL;
}

static int scamper_inst_attach(const scamper_attp_t *attp,char *buf,size_t len)
{
  char cycleid[24], descr[128], listid[24], monitor[128], name[128];
  char priority[24];

  if(attp == NULL)
    {
      snprintf(buf, len, "attach");
      return 0;
    }

  if(attp->flags & SCAMPER_ATTP_FLAG_CYCLEID)
    snprintf(cycleid, sizeof(cycleid), " cycle_id %u", attp->c_id);
  else
    cycleid[0] = '\0';

  if(attp->l_descr != NULL)
    snprintf(descr, sizeof(descr), " descr \"%s\"", attp->l_descr);
  else
    descr[0] = '\0';

  if(attp->flags & SCAMPER_ATTP_FLAG_LISTID)
    snprintf(listid, sizeof(listid), " list_id %u", attp->l_id);
  else
    listid[0] = '\0';

  if(attp->l_monitor != NULL)
    snprintf(monitor, sizeof(monitor), " monitor \"%s\"", attp->l_monitor);
  else
    monitor[0] = '\0';

  if(attp->l_name != NULL)
    snprintf(name, sizeof(name), " name \"%s\"", attp->l_name);
  else
    name[0] = '\0';

  if(attp->flags & SCAMPER_ATTP_FLAG_PRIORITY)
    snprintf(priority, sizeof(priority), " priority %u", attp->priority);
  else
    priority[0] = '\0';

  snprintf(buf, len, "attach%s%s%s%s%s%s",
	   cycleid, descr, listid, monitor, name, priority);

  return 0;
}

scamper_inst_t *scamper_inst_inet(scamper_ctrl_t *ctrl,
				  const scamper_attp_t *attp,
				  const char *addr, uint16_t port)
{
  struct addrinfo hints, *res, *res0;
  scamper_inst_t *inst = NULL;
  char buf[512];
  char servname[6];

#ifndef _WIN32 /* type: int vs SOCKET */
  int fd = -1;
#else
  SOCKET fd = INVALID_SOCKET;
#endif

  if(addr == NULL)
    addr = "127.0.0.1";

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags    = AI_NUMERICHOST;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_family   = AF_UNSPEC;

  snprintf(servname, sizeof(servname), "%u", port);
  if(getaddrinfo(addr, servname, &hints, &res0) != 0 || res0 == NULL)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not resolve");
      goto err;
    }

  for(res = res0; res != NULL; res = res->ai_next)
    if(res->ai_family == PF_INET || res->ai_family == PF_INET6)
      break;

  if(res == NULL)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not resolve");
      goto err;
    }

  /* connect to the scamper instance and set non-blocking */
  fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
  if(socket_isinvalid(fd))
    {
      snprintf(ctrl->err, sizeof(ctrl->err),
	       "could not create inet socket: %s", strerror(errno));
      goto err;
    }
  if(connect(fd, res->ai_addr, res->ai_addrlen) != 0)
    {
      snprintf(ctrl->err, sizeof(ctrl->err),
	       "could not connect: %s", strerror(errno));
      goto err;
    }

#ifdef HAVE_FCNTL
  if(fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
    {
      snprintf(ctrl->err, sizeof(ctrl->err),
	       "could not set nonblocking: %s", strerror(errno));
      goto err;
    }
#endif

  if(res->ai_family == PF_INET)
    snprintf(buf, sizeof(buf), "%s:%d", addr, port);
  else
    snprintf(buf, sizeof(buf), "[%s]:%d", addr, port);

  if((inst = scamper_inst_alloc(ctrl, SCAMPER_INST_TYPE_INET, fd, buf)) == NULL)
    goto err;
  fd = socket_invalid();
  if(scamper_inst_attach(attp, buf, sizeof(buf)) != 0)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not form attach");
      goto err;
    }
  if(scamper_inst_cmd(inst, SCAMPER_CMD_TYPE_ATTACH, buf) == NULL)
    goto err;

  freeaddrinfo(res0);
  return inst;

 err:
  if(res0 != NULL)
    freeaddrinfo(res0);
  if(socket_isvalid(fd))
    socket_close(fd);
  if(inst != NULL)
    scamper_inst_freedo(inst);
  return NULL;
}

#ifdef HAVE_SOCKADDR_UN
static int scamper_inst_unix_fd(scamper_ctrl_t *ctrl, const char *path)
{
  struct sockaddr_un sun;
  int fd = -1;

  /* make sure the filename can fit in the space available */
  if(strlen(path) + 1 > sizeof(sun.sun_path))
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "path too long");
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
      snprintf(ctrl->err, sizeof(ctrl->err),
	       "could not create unix socket: %s", strerror(errno));
      goto err;
    }

  /* connect to the scamper instance */
  if(connect(fd, (const struct sockaddr *)&sun, sizeof(sun)) != 0)
    {
      snprintf(ctrl->err, sizeof(ctrl->err),
	       "could not connect: %s", strerror(errno));
      goto err;
    }

  if(fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
    {
      snprintf(ctrl->err, sizeof(ctrl->err),
	       "could not set nonblocking: %s", strerror(errno));
      goto err;
    }

  return fd;

 err:
  if(fd != -1) close(fd);
  return -1;
}
#endif

scamper_inst_t *scamper_inst_unix(scamper_ctrl_t *ctrl,
				  const scamper_attp_t *attp,
				  const char *path)
{
#ifdef HAVE_SOCKADDR_UN
  scamper_inst_t *inst = NULL;
  char buf[512];
  int fd = -1;

  if((fd = scamper_inst_unix_fd(ctrl, path)) == -1 ||
     (inst = scamper_inst_alloc(ctrl,SCAMPER_INST_TYPE_UNIX,fd,path)) == NULL ||
     scamper_inst_attach(attp, buf, sizeof(buf)) != 0 ||
     scamper_inst_cmd(inst, SCAMPER_CMD_TYPE_ATTACH, buf) == NULL)
    goto err;

  return inst;

 err:
  if(fd != -1) close(fd);
  if(inst != NULL) scamper_inst_freedo(inst);
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

  if((fd = scamper_inst_unix_fd(ctrl, path)) == -1 ||
     (inst = scamper_inst_alloc(ctrl,SCAMPER_INST_TYPE_REMOTE,fd,path)) == NULL)
    goto err;

  return inst;

 err:
  if(fd != -1) close(fd);
  if(inst != NULL) scamper_inst_freedo(inst);
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
  scamper_task_t fm;
  scamper_cmd_t *cmd;
  uint8_t buf[8192];
  ssize_t x, rc, len;
  size_t size, enc, i, j, linelen;
  char *start, *ptr, a, b, c, d;
  long lo;

  assert(inst != NULL);
  assert(inst->ctrl != NULL);
  ctrl = inst->ctrl;

  rc = recv(inst->fd, buf + inst->line_off, sizeof(buf) - inst->line_off, 0);

  /* if the scamper process exits, pass that through */
  if(rc == 0)
    {
      socket_close(inst->fd);
      inst->fd = socket_invalid();

      /*
       * signal EOF on callback.  the callback might call scamper_inst_free,
       * which we can detect because it will not be on ctrl->insts, rather
       * it will be on ctrl->waitlist.  if it is still on ctrl->insts, then
       * remove it from the monitored list.
       */
      ctrl->cb(inst, SCAMPER_CTRL_TYPE_EOF, NULL, NULL, 0);
      if(inst->list == ctrl->insts)
	{
	  dlist_node_pop(inst->list, inst->dn);
	  inst->dn = NULL; inst->list = NULL;
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

  /* adjust for any partial recv left over from last time */
  memcpy(buf, inst->line, inst->line_off);
  len = rc + inst->line_off;
  inst->line_off = 0;

  start = (char *)buf;
  x = 0;
  while(x < len)
    {
      /* continue until we get to the end of the line */
      if(buf[x] != '\n')
	{
	  x++;
	  continue;
	}

      /* count how many characters in this line, then terminate the line */
      linelen = (char *)&buf[x] - start;
      buf[x] = '\0';
      x++;

      /* empty lines are not allowed */
      if(linelen == 0)
	{
	  snprintf(ctrl->err, sizeof(ctrl->err), "unexpected empty line");
	  goto fatal;
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
		  goto fatal;
		}
	      if((cmd = slist_head_pop(inst->waitok)) == NULL)
		{
		  snprintf(ctrl->err, sizeof(ctrl->err), "no cmd to pop");
		  goto fatal;
		}
	      assert(cmd->type == SCAMPER_CMD_TYPE_TASK);
	      cmd->task->id = lo;
	      cmd->task->flags &= (~SCAMPER_TASK_FLAG_WAITOK);
	      cmd->task->flags |= SCAMPER_TASK_FLAG_GOTID;
	      assert(splaytree_find(inst->tree, cmd->task) == NULL);
	      if(splaytree_insert(inst->tree, cmd->task) == NULL)
		{
		  snprintf(ctrl->err, sizeof(ctrl->err), "could not add task");
		  goto fatal;
		}
	      cmd->task->cmd = NULL; cmd->task = NULL;
	      scamper_cmd_free(cmd);
	    }
	  else if(strncasecmp(start, "OK", 2) == 0)
	    {
	      cmd = slist_head_pop(inst->waitok);
	      assert(cmd->type != SCAMPER_CMD_TYPE_TASK);
	      scamper_cmd_free(cmd);
	    }
	  else if(strncasecmp(start, "ERR", 3) == 0)
	    {
	      cmd = slist_head_pop(inst->waitok);
	      assert(cmd->type == SCAMPER_CMD_TYPE_TASK);
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
	      ctrl->cb(inst, SCAMPER_CTRL_TYPE_ERR, cmd->task, ptr, size);
	      scamper_task_free(cmd->task); cmd->task = NULL;
	      ctrl->cb(inst, SCAMPER_CTRL_TYPE_MORE, NULL, NULL, 0);
	      scamper_cmd_free(cmd);
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
		  goto fatal;
		}
	      inst->data_left = (size_t)lo;

	      /* allocate a buffer large enough to store a decoded blob */
	      size = (((lo-2) / 62) * 45) + ((((lo-2) % 62) / 4) * 3);
	      if((inst->data = malloc(size)) == NULL)
		{
		  snprintf(ctrl->err, sizeof(ctrl->err),
			   "could not malloc %d bytes", (int)size);
		  goto fatal;
		}
	      inst->data_len = size;

	      /* get the ID number if there is one */
	      if(strncasecmp(ptr, " id-", 4) == 0)
		{
		  if((lo = strtol(ptr+4, NULL, 10)) < 1)
		    {
		      snprintf(ctrl->err, sizeof(ctrl->err),
			       "invalid ID in DATA");
		      goto fatal;
		    }
		  fm.id = lo;
		  if((inst->task = splaytree_find(inst->tree, &fm)) == NULL)
		    {
		      snprintf(ctrl->err, sizeof(ctrl->err),
			       "could not find task with ID %ld", lo);
		      goto fatal;
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
	      goto fatal;
	    }

	  /* make sure the line only contains valid uuencode characters */
	  for(j=0; j<linelen; j++)
	    {
	      if(start[j] < '!' || start[j] > '`')
		{
		  snprintf(ctrl->err, sizeof(ctrl->err),
			   "line did not start with valid character");
		  goto fatal;
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
	      goto fatal;
	    }

	  i = 0;
	  j = 1;
	  for(;;)
	    {
	      /* we need a minimum of 4 characters */
	      if(linelen - j < 4)
		{
		  snprintf(ctrl->err, sizeof(ctrl->err), "need 4 characters");
		  goto fatal;
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
		inst->task->flags |= SCAMPER_TASK_FLAG_DONE;
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

      start = (char *)(buf+x);
    }

  /* if we didn't recv a complete line, buffer the remainder */
  if(start != (char *)(buf+x))
    {
      if(start > (char *)(buf+x))
	{
	  snprintf(ctrl->err, sizeof(ctrl->err), "start beyond line");
	  goto fatal;
	}
      if((size_t)((char *)(buf+x) - start) > sizeof(inst->line))
	{
	  snprintf(ctrl->err, sizeof(ctrl->err), "long partial line");
	  goto fatal;
	}
      inst->line_off = (char *)(buf+x) - start;
      memcpy(inst->line, start, inst->line_off);
    }

  return 0;

 fatal:
  ctrl->cb(inst, SCAMPER_CTRL_TYPE_FATAL, NULL, NULL, 0);
  return 0;
}

static int scamper_inst_write(scamper_inst_t *inst)
{
  scamper_ctrl_t *ctrl;
  scamper_task_t *task;
  scamper_cmd_t *cmd;
  ssize_t rc;

#ifdef HAVE_KQUEUE
  struct kevent kev;
#endif

  assert(inst != NULL);
  assert(inst->ctrl != NULL);
  ctrl = inst->ctrl;

  cmd = dlist_head_item(inst->queue);
  assert(cmd != NULL);

  /* test if send was successful */
  if((rc = send(inst->fd, cmd->str + cmd->off, cmd->len - cmd->off, 0)) == -1)
    {
      snprintf(ctrl->err, sizeof(ctrl->err), "could not send: %s",
	       strerror(errno));
      return -1;
    }
  assert(rc >= 0);

  /* remove the iov if we wrote all of it.  otherwise, shuffle bytes */
  if((size_t)rc == cmd->len - cmd->off)
    {
      /* remove the command from the queue to be sent to scamper */
      dlist_head_pop(inst->queue);

      task = cmd->task;
      if(cmd->type == SCAMPER_CMD_TYPE_TASK)
	{
	  assert(task != NULL);
	  assert((task->flags & SCAMPER_TASK_FLAG_QUEUE) != 0);
	  assert((task->flags & SCAMPER_TASK_FLAG_WAITOK) == 0);
	  task->flags &= (~SCAMPER_TASK_FLAG_QUEUE);
	}

      /* add the command to the list of commands waiting for an OK */
      if(slist_tail_push(inst->waitok, cmd) == NULL)
	{
	  snprintf(ctrl->err, sizeof(ctrl->err),
		   "could not push cmd onto waitok");
	  return -1;
	}
      if(cmd->type == SCAMPER_CMD_TYPE_TASK)
	task->flags |= SCAMPER_TASK_FLAG_WAITOK;
    }
  else if(rc > 0)
    {
      cmd->off += rc;
    }

#ifdef HAVE_KQUEUE
  if(dlist_count(inst->queue) == 0)
    {
      EV_SET(&kev, inst->fd, EVFILT_WRITE, EV_DELETE, 0, 0, inst);
      if(kevent(ctrl->kqfd, &kev, 1, NULL, 0, NULL) != 0)
	{
	  snprintf(ctrl->err, sizeof(ctrl->err),
		   "could not remove inst from kqueue");
	  return -1;
	}
      inst->flags &= ~(SCAMPER_INST_FLAG_WRITE);
    }
#endif

  return 0;
}

scamper_ctrl_t *scamper_inst_getctrl(const scamper_inst_t *inst)
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
	  inst->list = NULL; inst->dn = NULL;
	  scamper_inst_freedo(inst);
	}
      else
	{
	  assert(inst->ctrl == ctrl);
	  dlist_node_tail_push(ctrl->insts, inst->dn);
	  inst->list = ctrl->insts;
	  if(inst_set_read(ctrl, inst) != 0 && rc == 0)
	    {
	      snprintf(ctrl->err, sizeof(ctrl->err), "could not set read");
	      rc = -1;
	    }
	}
    }

  return rc;
}

#ifdef HAVE_KQUEUE
int scamper_ctrl_wait(scamper_ctrl_t *ctrl, struct timeval *to)
{
  struct kevent events[128];
  int eventc = sizeof(events) / sizeof(struct kevent);
  struct timespec ts, *timeout;
  scamper_inst_t *inst;
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
      inst = events[i].udata;
      if(events[i].filter == EVFILT_READ && socket_isvalid(inst->fd))
	{
	  if(scamper_inst_read(inst) != 0)
	    goto done;
	}
      else if(events[i].filter == EVFILT_WRITE && socket_isvalid(inst->fd))
	{
	  if(scamper_inst_write(inst) != 0)
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
  scamper_inst_t *inst;
  dlist_node_t *dn;
  fd_set rfds, wfds, *wfdsp, *rfdsp;
  int count = 0, rc = -1, nfds;

#ifndef _WIN32 /* type: int vs SOCKET */
  int fd;
#else
  SOCKET fd;
#endif

  nfds = -1; FD_ZERO(&rfds); FD_ZERO(&wfds); wfdsp = NULL; rfdsp = NULL;
  dn = dlist_head_node(ctrl->insts);
  while(dn != NULL)
    {
      inst = dlist_node_item(dn); assert(dn == inst->dn);
      dn = dlist_node_next(dn);
      assert(socket_isvalid(inst->fd));
      FD_SET(inst->fd, &rfds); rfdsp = &rfds;
      nfds = socket_setnfds(nfds, inst->fd);
      if(dlist_count(inst->queue) > 0)
	{
	  FD_SET(inst->fd, &wfds);
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
  dn=dlist_head_node(ctrl->insts);
  while(dn != NULL && count > 0)
    {
      inst = dlist_node_item(dn);
      dn = dlist_node_next(dn);

      /* take a copy incase FD becomes invalid, to work with count */
      fd = inst->fd;

      if(FD_ISSET(fd, &rfds))
	{
	  count--;
	  if(scamper_inst_read(inst) != 0)
	    goto done;
	}
      if(wfdsp != NULL && FD_ISSET(fd, wfdsp))
	{
	  count--;
	  if(socket_isvalid(inst->fd) && scamper_inst_write(inst) != 0)
	    goto done;
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
  scamper_inst_t *inst;
  dlist_t *list;
  int i;

  assert(ctrl != NULL);

  for(i=0; i<2; i++)
    {
      switch(i)
	{
	case 0: list = ctrl->insts; break;
	case 1: list = ctrl->waitlist; break;
	}
      if(list != NULL)
	{
	  while((inst = dlist_head_pop(list)) != NULL)
	    {
	      inst->ctrl = NULL;
	      inst->list = NULL;
	      inst->dn = NULL;
	    }
	  dlist_free(list);
	}
    }

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
#else
  ctrl->insts = dlist_alloc_dm(file, line);
  ctrl->waitlist = dlist_alloc_dm(file, line);
#endif

  if(ctrl->insts == NULL || ctrl->waitlist == NULL)
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

void *scamper_ctrl_getparam(const scamper_ctrl_t *ctrl)
{
  return ctrl->param;
}

void scamper_ctrl_setparam(scamper_ctrl_t *ctrl, void *param)
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

/*
 * scamper_attp_str_isvalid:
 *
 * is the string passed in valid for an attach command parameter?
 *
 * this function needs to be kept up to date with what
 * scamper_control.c:params_get() considers valid
 */
static int scamper_attp_str_isvalid(const char *str)
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

void scamper_attp_set_listid(scamper_attp_t *attp, uint32_t list_id)
{
  attp->flags |= SCAMPER_ATTP_FLAG_LISTID;
  attp->l_id = list_id;
  return;
}

int scamper_attp_set_listname(scamper_attp_t *attp, char *list_name)
{
  char *tmp;
  if(scamper_attp_str_isvalid(list_name) == 0 ||
     (tmp = strdup(list_name)) == NULL)
    return -1;
  if(attp->l_name != NULL)
    free(attp->l_name);
  attp->l_name = tmp;
  return 0;
}

int scamper_attp_set_listdescr(scamper_attp_t *attp, char *list_descr)
{
  char *tmp;
  if(scamper_attp_str_isvalid(list_descr) == 0 ||
     (tmp = strdup(list_descr)) == NULL)
    return -1;
  if(attp->l_descr != NULL)
    free(attp->l_descr);
  attp->l_descr = tmp;
  return 0;
}

int scamper_attp_set_listmonitor(scamper_attp_t *attp, char *list_monitor)
{
  char *tmp;
  if(scamper_attp_str_isvalid(list_monitor) == 0 ||
     (tmp = strdup(list_monitor)) == NULL)
    return -1;
  if(attp->l_monitor != NULL)
    free(attp->l_monitor);
  attp->l_monitor = tmp;
  return 0;
}

void scamper_attp_set_cycleid(scamper_attp_t *attp, uint32_t cycle_id)
{
  attp->flags |= SCAMPER_ATTP_FLAG_CYCLEID;
  attp->c_id = cycle_id;
  return;
}

void scamper_attp_set_priority(scamper_attp_t *attp, uint32_t priority)
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
