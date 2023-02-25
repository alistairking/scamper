/*
 * libscamperctrl
 *
 * $Id: libscamperctrl.c,v 1.17 2023/01/11 07:50:42 mjl Exp $
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
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#include "libscamperctrl.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"

struct scamper_ctrl
{
  dlist_t           *insts;    /* the instances under management */
  scamper_ctrl_cb_t  cb;       /* callback to call */
  uint8_t            wait;     /* are we currently in scamper_ctrl_wait */
  char               err[128]; /* error string */
};

struct scamper_inst
{
  scamper_ctrl_t    *ctrl;    /* backpointer to overall control structure */
  dlist_node_t      *dn;      /* dlist node in ctrl->insts */
  void              *param;   /* user-supplied parameter */
  uint8_t            type;    /* types: inet, unix, or remote */
  uint8_t            flags;   /* flags: done */
  uint8_t            gc;      /* scamper_inst_free called, garbage collect */
  int                fd;      /* file descriptor for socket */
  uint32_t           seq;     /* next sequence number to assign */
  dlist_t           *queue;   /* list of commands queued */
  slist_t           *waitok;  /* commands we are waiting for an ok for */
  splaytree_t       *tree;    /* tasks searchable by their ID */

  /*
   * temporary buffer for storing incomplete lines in between to calls
   * to read
   */
  uint8_t            line[128];
  size_t             line_off;

  /*
   * temporary buffer for storing data objects as we read them from
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
};

#define SCAMPER_INST_FLAG_DONE   0x01

#define SCAMPER_INST_TYPE_UNIX   1
#define SCAMPER_INST_TYPE_INET   2
#define SCAMPER_INST_TYPE_REMOTE 3

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
      snprintf(inst->ctrl->err, sizeof(inst->ctrl->err), "no command");
      goto err;
    }
  for(i=0; i<len; i++)
    {
      if(isprint(str[i]) == 0)
	{
	  snprintf(inst->ctrl->err, sizeof(inst->ctrl->err),
		   "unprintable character in command");
	  goto err;
	}
    }

  if((cmd = malloc(sizeof(scamper_cmd_t))) == NULL)
    {
      snprintf(inst->ctrl->err, sizeof(inst->ctrl->err),
	       "could not malloc cmd");
      goto err;
    }
  memset(cmd, 0, sizeof(scamper_cmd_t));
  cmd->type = type;
  cmd->seq = inst->seq; inst->seq++;

  if((cmd->str = malloc(len+2)) == NULL)
    {
      snprintf(inst->ctrl->err, sizeof(inst->ctrl->err),
	       "could not malloc cmd->str");
      goto err;
    }
  memcpy(cmd->str, str, len);
  cmd->str[len++] = '\n';
  cmd->str[len] = '\0';
  cmd->len = len;

  if((cmd->dn = dlist_tail_push(inst->queue, cmd)) == NULL)
    {
      snprintf(inst->ctrl->err, sizeof(inst->ctrl->err), "could not push cmd");
      goto err;
    }

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

scamper_task_t *scamper_inst_do(scamper_inst_t *inst, const char *str)
{
  scamper_task_t *task = NULL;
  scamper_cmd_t *cmd = NULL;

  /* can't send a command after sending done message */
  if((inst->flags & SCAMPER_INST_FLAG_DONE) != 0)
    {
      snprintf(inst->ctrl->err, sizeof(inst->ctrl->err),
	       "instance marked done");
      return NULL;
    }

  /* make sure the thing to isn't a reserved keyword */
  if(strncasecmp(str, "attach", 6) == 0 &&
     strncasecmp(str, "halt", 4) == 0 &&
     strncasecmp(str, "done", 4) == 0)
    {
      snprintf(inst->ctrl->err, sizeof(inst->ctrl->err),
	       "%s invalid command", str);
      return NULL;
    }

  /* allocate a task to return to the caller */
  if((task = malloc(sizeof(scamper_task_t))) == NULL)
    {
      snprintf(inst->ctrl->err, sizeof(inst->ctrl->err),
	       "could not malloc task");
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
  return task;
}

int scamper_inst_halt(scamper_inst_t *inst, scamper_task_t *task)
{
  char buf[20];

  /*
   * if the user is halting a task which we have already given them
   * data for, then flag this error
   */
  if((task->flags & SCAMPER_TASK_FLAG_DONE) != 0)
    {
      snprintf(inst->ctrl->err, sizeof(inst->ctrl->err), "task already done");
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
  if((inst->flags & SCAMPER_INST_FLAG_DONE) != 0)
    return 0;
  inst->flags |= SCAMPER_INST_FLAG_DONE;
  if(scamper_inst_cmd(inst, SCAMPER_CMD_TYPE_DONE, "done") == NULL)
    return -1;
  return 0;
}

static void scamper_inst_freedo(scamper_inst_t *inst)
{
  if(inst->fd != -1)
    close(inst->fd);
  if(inst->dn != NULL)
    dlist_node_pop(inst->ctrl->insts, inst->dn);
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

void scamper_inst_free(scamper_inst_t *inst)
{
  assert(inst != NULL);

  /*
   * if we are in the body of a scamper_inst_wait call, then mark the
   * instance for garbage collection
   */
  if(inst->ctrl->wait != 0)
    {
      inst->gc = 1;
      return;
    }

  scamper_inst_freedo(inst);
  return;
}

#ifndef DMALLOC
static scamper_inst_t *scamper_inst_alloc(scamper_ctrl_t *ctrl, uint8_t t,
					  int fd)
#else
#define scamper_inst_alloc(ctrl,t,fd) scamper_inst_alloc_dm((ctrl),(t),(fd), \
							    __FILE__, __LINE__)
static scamper_inst_t *scamper_inst_alloc_dm(scamper_ctrl_t *ctrl, uint8_t t,
					     int fd, const char *file,
					     const int line)
#endif
{
  scamper_inst_t *inst;
  size_t len = sizeof(scamper_inst_t);

#ifndef DMALLOC
  inst = (scamper_inst_t *)malloc(len);
#else
  inst = (scamper_inst_t *)dmalloc_malloc(file, line, len,
					  DMALLOC_FUNC_MALLOC, 0, 0);
#endif
  if(inst == NULL)
    goto err;

  memset(inst, 0, sizeof(scamper_inst_t));
  inst->fd = -1;

  if((inst->waitok = slist_alloc()) == NULL ||
     (inst->queue = dlist_alloc()) == NULL ||
     (inst->tree = splaytree_alloc((splaytree_cmp_t)scamper_task_cmp)) == NULL)
    goto err;

#ifndef DMALLOC
  inst->dn = dlist_tail_push(ctrl->insts, inst);
#else
  inst->dn = dlist_tail_push_dm(ctrl->insts, inst, file, line);
#endif
  if(inst->dn == NULL)
    goto err;

  inst->ctrl = ctrl;
  inst->type = t;
  inst->fd   = fd;

  return inst;

 err:
  snprintf(ctrl->err, sizeof(ctrl->err), "could not alloc instance");
  if(inst == NULL)
    return NULL;
  if(inst->dn != NULL)
    dlist_node_pop(ctrl->insts, inst->dn);
  if(inst->waitok != NULL)
    slist_free(inst->waitok);
  if(inst->queue != NULL)
    dlist_free(inst->queue);
  if(inst->tree != NULL)
    splaytree_free(inst->tree, NULL);
  free(inst);
  return NULL;
}

scamper_inst_t *scamper_inst_inet(scamper_ctrl_t *ctrl,
				  const char *addr, uint16_t port)
{
  struct addrinfo hints, *res, *res0;
  scamper_inst_t *inst = NULL;
  char servname[6];
  int fd = -1;

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
  if((fd = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP)) == -1)
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
  if(fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
    {
      snprintf(ctrl->err, sizeof(ctrl->err),
	       "could not set nonblocking: %s", strerror(errno));
      goto err;
    }

  if((inst = scamper_inst_alloc(ctrl, SCAMPER_INST_TYPE_INET, fd)) == NULL)
    goto err;
  fd = -1;
  if(scamper_inst_cmd(inst, SCAMPER_CMD_TYPE_ATTACH, "attach") == NULL)
    goto err;

  freeaddrinfo(res0);
  return inst;

 err:
  if(res0 != NULL)
    freeaddrinfo(res0);
  if(fd != -1)
    close(fd);
  if(inst != NULL)
    scamper_inst_free(inst);
  return NULL;
}

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

scamper_inst_t *scamper_inst_unix(scamper_ctrl_t *ctrl, const char *path)
{
  scamper_inst_t *inst = NULL;
  int fd = -1;

  if((fd = scamper_inst_unix_fd(ctrl, path)) == -1 ||
     (inst = scamper_inst_alloc(ctrl, SCAMPER_INST_TYPE_UNIX, fd)) == NULL ||
     scamper_inst_cmd(inst, SCAMPER_CMD_TYPE_ATTACH, "attach") == NULL)
    goto err;

  return inst;

 err:
  if(fd != -1) close(fd);
  if(inst != NULL) scamper_inst_free(inst);
  return NULL;
}

scamper_inst_t *scamper_inst_remote(scamper_ctrl_t *ctrl, const char *path)
{
  scamper_inst_t *inst = NULL;
  int fd = -1;

  if((fd = scamper_inst_unix_fd(ctrl, path)) == -1 ||
     (inst = scamper_inst_alloc(ctrl, SCAMPER_INST_TYPE_REMOTE, fd)) == NULL)
    goto err;

  return inst;

 err:
  if(fd != -1) close(fd);
  if(inst != NULL) scamper_inst_free(inst);
  return NULL;
}

/*
 * scamper_inst_read
 *
 * read from the control socket.
 */
static int scamper_inst_read(scamper_inst_t *inst)
{
  scamper_ctrl_t *ctrl = inst->ctrl;
  scamper_task_t fm;
  scamper_cmd_t *cmd;
  uint8_t buf[8192];
  ssize_t x, rc, len;
  size_t size, enc, i, j, linelen;
  char *start, *ptr, a, b, c, d;
  long lo;

  rc = read(inst->fd, buf + inst->line_off, sizeof(buf) - inst->line_off);

  /* if the scamper process exits, pass that through */
  if(rc == 0)
    {
      ctrl->cb(inst, SCAMPER_CTRL_TYPE_EOF, NULL, NULL, 0);
      return 0;
    }
  
  if(rc < 0)
    {
      /* didn't read anything but no fatal error */
      if(errno == EINTR || errno == EAGAIN)
	return 0;

      /* fatal error */
      snprintf(ctrl->err, sizeof(ctrl->err), "could not read: %s",
	       strerror(errno));
      goto err;
    }

  /* adjust for any partial read left over from last time */
  memcpy(buf, inst->line, inst->line_off);
  len = rc + inst->line_off;

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
	  goto err;
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
		  goto err;
		}
	      if((cmd = slist_head_pop(inst->waitok)) == NULL)
		{
		  snprintf(ctrl->err, sizeof(ctrl->err), "no cmd to pop");
		  goto err;
		}
	      assert(cmd->type == SCAMPER_CMD_TYPE_TASK);
	      cmd->task->id = lo;
	      cmd->task->flags &= (~SCAMPER_TASK_FLAG_WAITOK);
	      cmd->task->flags |= SCAMPER_TASK_FLAG_GOTID;
	      assert(splaytree_find(inst->tree, cmd->task) == NULL);
	      if(splaytree_insert(inst->tree, cmd->task) == NULL)
		{
		  snprintf(ctrl->err, sizeof(ctrl->err), "could not add task");
		  goto err;
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
	      ctrl->cb(inst, SCAMPER_CTRL_TYPE_ERR, cmd->task, NULL, 0);
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
		  goto err;
		}
	      inst->data_left = (size_t)lo;

	      /* allocate a buffer large enough to store a decoded blob */
	      size = (((lo-2) / 62) * 45) + ((((lo-2) % 62) / 4) * 3);
	      if((inst->data = malloc(size)) == NULL)
		{
		  snprintf(ctrl->err, sizeof(ctrl->err),
			   "could not malloc %d bytes", (int)size);
		  goto err;
		}
	      inst->data_len = size;

	      /* get the ID number if there is one */
	      if(strncasecmp(ptr, " id-", 4) == 0)
		{
		  if((lo = strtol(ptr+4, NULL, 10)) < 1)
		    {
		      snprintf(ctrl->err, sizeof(ctrl->err),
			       "invalid ID in DATA");
		      goto err;
		    }
		  fm.id = lo;
		  if((inst->task = splaytree_find(inst->tree, &fm)) == NULL)
		    {
		      snprintf(ctrl->err, sizeof(ctrl->err),
			       "could not find task with ID %ld", lo);
		      goto err;
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
	      goto err;
	    }

	  /* make sure the line only contains valid uuencode characters */
	  for(j=0; j<linelen; j++)
	    {
	      if(start[j] < '!' || start[j] > '`')
		{
		  snprintf(ctrl->err, sizeof(ctrl->err),
			   "line did not start with valid character");
		  goto err;
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
	      goto err;
	    }

	  i = 0;
	  j = 1;
	  for(;;)
	    {
	      /* we need a minimum of 4 characters */
	      if(linelen - j < 4)
		{
		  snprintf(ctrl->err, sizeof(ctrl->err), "need 4 characters");
		  goto err;
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

  /* if we didn't read a complete line, buffer the remainder */
  if(start != (char *)(buf+x))
    {
      if(start > (char *)(buf+x))
	{
	  snprintf(ctrl->err, sizeof(ctrl->err), "start beyond line");
	  goto err;
	}
      if((size_t)((char *)(buf+x) - start) > sizeof(inst->line))
	{
	  snprintf(ctrl->err, sizeof(ctrl->err), "long partial line");
	  goto err;
	}
      inst->line_off = (char *)(buf+x) - start;
      memcpy(inst->line, start, inst->line_off);
    }

  return 0;

 err:
  ctrl->cb(inst, SCAMPER_CTRL_TYPE_ERR, NULL, NULL, 0);
  return 0;  
}

static int scamper_inst_write(scamper_inst_t *inst)
{
  scamper_cmd_t *cmd;
  scamper_task_t *task;
  ssize_t rc;

  cmd = dlist_head_item(inst->queue);
  assert(cmd != NULL);

  /* test if write was successful */
  if((rc = write(inst->fd, cmd->str + cmd->off, cmd->len - cmd->off)) == -1)
    {
      snprintf(inst->ctrl->err, sizeof(inst->ctrl->err), "could not write: %s",
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
	  snprintf(inst->ctrl->err, sizeof(inst->ctrl->err),
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

  return 0;
}

int scamper_ctrl_wait(scamper_ctrl_t *ctrl, struct timeval *to)
{
  scamper_inst_t *inst;
  dlist_node_t *dn;
  fd_set rfds, wfds, *wfdsp;
  int rc = -1, nfds;

  nfds = 0; FD_ZERO(&rfds); FD_ZERO(&wfds); wfdsp = NULL;
  ctrl->wait = 1;

  for(dn=dlist_head_node(ctrl->insts); dn != NULL; dn=dlist_node_next(dn))
    {
      inst = dlist_node_item(dn);
      FD_SET(inst->fd, &rfds);
      if(nfds < inst->fd) nfds = inst->fd;
      if(dlist_count(inst->queue) > 0)
	{
	  FD_SET(inst->fd, &wfds);
	  wfdsp = &wfds;
	}
    }

  if(select(nfds+1, &rfds, wfdsp, NULL, to) < 0)
    {
      if(errno == EINTR)
	rc = 0;
      snprintf(ctrl->err, sizeof(ctrl->err), "could not select: %s",
	       strerror(errno));
      goto done;
    }

  dn=dlist_head_node(ctrl->insts);
  while(dn != NULL)
    {
      inst = dlist_node_item(dn);
      dn = dlist_node_next(dn);
      if(FD_ISSET(inst->fd, &rfds) && scamper_inst_read(inst) != 0)
	goto done;
      if(inst->gc == 0)
	{
	  if(wfdsp != NULL && FD_ISSET(inst->fd, wfdsp) &&
	     scamper_inst_write(inst) != 0)
	    goto done;
	}
      else scamper_inst_freedo(inst);
    }

  rc = 0;

 done:
  ctrl->wait = 0;
  return rc;
}

void scamper_ctrl_free(scamper_ctrl_t *ctrl)
{
  scamper_inst_t *inst;
  
  if(ctrl == NULL)
    return;

  if(ctrl->insts != NULL)
    {
      while((inst = dlist_head_pop(ctrl->insts)) != NULL)
	scamper_inst_free(inst);
      dlist_free(ctrl->insts);
    }

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

#ifndef DMALLOC
  ctrl->insts = dlist_alloc();
#else
  ctrl->insts = dlist_alloc_dm(file, line);
#endif

  if(ctrl->insts == NULL)
    {
      free(ctrl);
      return NULL;
    }

  ctrl->cb = cb;

  return ctrl;
}

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

const char *scamper_ctrl_strerror(const scamper_ctrl_t *ctrl)
{
  return ctrl->err;
}
