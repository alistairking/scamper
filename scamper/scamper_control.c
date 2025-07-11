/*
 * scamper_control.c
 *
 * $Id: scamper_control.c,v 1.292 2025/06/27 02:09:58 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2014 The Regents of the University of California
 * Copyright (C) 2014-2025 Matthew Luckie
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

#include "scamper.h"
#include "scamper_control.h"
#include "scamper_debug.h"
#include "scamper_fds.h"
#include "scamper_list.h"
#include "scamper_linepoll.h"
#include "scamper_writebuf.h"
#include "scamper_file.h"
#include "scamper_outfiles.h"
#include "scamper_task.h"
#include "scamper_queue.h"
#include "scamper_sources.h"
#include "scamper_source_file.h"
#include "scamper_source_control.h"
#include "scamper_priv.h"
#include "mjl_list.h"
#include "utils.h"

#ifdef HAVE_OPENSSL
#include "utils_tls.h"
#endif

/* hack to deal with lss clear */
#ifndef DISABLE_SCAMPER_TRACE
#include "trace/scamper_trace_do.h"
#endif

/* hack to deal with get / set nameserver */
#include "scamper_addr.h"
#include "scamper_addr_int.h"

#ifndef DISABLE_SCAMPER_HOST
#include "host/scamper_host_do.h"
#endif

#define REMOTE_HDRLEN 10

/*
 * client_obj_t
 *
 */
typedef struct client_obj
{
  uint8_t  *data;
  size_t    len;
  uint32_t  id;
  uint8_t   flags;
} client_obj_t;

/*
 * client_txt_t
 *
 * string and length, not including null character
 */
typedef struct client_txt
{
  char   *str;
  size_t  len;
} client_txt_t;

/*
 * client_message_t
 *
 * this structure contains messages that we send until we receive an
 * acknowledgement from remoted that it got the message.
 */
typedef struct client_message
{
  uint32_t            sequence;
  uint32_t            channel;
  size_t              msglen;
  void               *data;
} client_message_t;

/*
 * control_remote_t: struct to define a remote control instance.
 *
 * server_name: name/ip address of the remote control server
 * server_port: port to connect to on the remote control server
 * server_ssl:  speak tls or not.
 * fd:          file descriptor for an established session
 * wb:          writebuf for the established session
 * magic:       randomly generated magic for the instance
 * buf:         read buf to assemble incoming messages with
 * bufoff:      where in the read buf we are up to
 * alias:       alias assigned by the remote control server to this instance
 * num:         last ID assigned by this instance to identify callbacks
 * snd_nxt:     the next sequence number to use
 * rcv_nxt:     the next sequence number expected from the controller
 * messages:    list of client_message_t structures
 * list:        list of client_t instances
 * tx_ka:       when we sent the last keepalive to the remote instance
 * rx_abort:    when to give up on the remote instance if unresponsive
 * sq:          scamper_queue_t to manage events related to above timestamps
 * resume:      1 if we should resume using magic, 0 if we should restart
 * mode:        REMOTE_MODE_CONNECT or REMOTE_MODE_GO
 * node:        dlist_node_t for this control_remote_t in remote_list
 * ssl_mode:    SSL_MODE_HANDSHAKE or SSL_MODE_ESTABLISHED
 * ssl:         OpenSSL structure
 * ssl_rbio:    read BIO that OpenSSL structure will read from (we write)
 * ssl_wbio:    write BIO that OpenSSL structure will write to (we read)
 *
 */
typedef struct control_remote
{
  char               *server_name;
  uint16_t            server_port;
  int                 server_ssl;
  scamper_fd_t       *fd;
  scamper_writebuf_t *wb;
  uint8_t             magic[8];
  uint8_t             buf[65536 + REMOTE_HDRLEN];
  size_t              bufoff;
  char               *alias;
  uint32_t            num;
  uint32_t            snd_nxt;
  uint32_t            rcv_nxt;
  slist_t            *messages;
  dlist_t            *list;
  struct timeval      tx_ka;
  struct timeval      rx_abort;
  scamper_queue_t    *sq;
  int                 resume;
  int                 mode;
  dlist_node_t       *node;

#ifdef HAVE_OPENSSL
  int                 ssl_mode;
  SSL                *ssl;
  BIO                *ssl_rbio;
  BIO                *ssl_wbio;
#endif
} control_remote_t;

typedef struct control_unix
{
  char               *name;
  uint32_t            num;
  scamper_fd_t       *fd;
} control_unix_t;

typedef struct control_inet
{
  scamper_fd_t       *fd;
} control_inet_t;

/*
 * client_t
 *
 * this structure records state required to manage a client connected to
 * scamper via a control socket.
 */
typedef struct client
{
  /* the mode the client is in: interactive, attached, flush*/
  uint8_t             mode;

  /* the type the client is: socket or channel */
  uint8_t             type;

  /* node for this client in the list of connected clients */
  dlist_node_t       *node;

  /* linepoll to process incoming lines of text */
  scamper_linepoll_t *lp;

  /* text strings to pass over socket when able to */
  slist_t            *txt;

  union
  {
    struct client_sock
    {
      struct sockaddr    *sa;
      scamper_fd_t       *fdn;
      scamper_writebuf_t *wb;
    } sock;
    struct client_chan
    {
      uint32_t            id;
      control_remote_t   *rem;
      dlist_node_t       *node;
    } chan;
  } un;

  /*
   * the next set of variables are used when the client's connection is used
   * to supply tasks, and is also used to send the results back.
   *
   *  source:     the source allocated to the control socket.
   *  sof:        scamper file wrapper for accessing the warts code.
   *  sof_objs:   warts objects waiting to be written.
   *  sof_obj:    current object partially written over socket.
   *  sof_off:    offset into current object being written.
   *  sof_format: the format (warts/json) of results being sent to clients
   */
  scamper_source_t   *source;
  scamper_outfile_t  *sof;
  slist_t            *sof_objs;
  client_obj_t       *sof_obj;
  size_t              sof_off;
  uint8_t             sof_format;
} client_t;

#define CLIENT_MODE_INTERACTIVE 0
#define CLIENT_MODE_ATTACHED    1
#define CLIENT_MODE_FLUSH       2

#define CLIENT_TYPE_SOCKET      0
#define CLIENT_TYPE_CHANNEL     1

#define CLIENT_FORMAT_WARTS     0
#define CLIENT_FORMAT_JSON      1

#define CLIENT_OBJ_FLAG_ID      0x01
#define CLIENT_OBJ_FLAG_INPROG  0x02

#define REMOTE_MODE_CONNECT     0
#define REMOTE_MODE_GO          1

typedef struct command
{
  char *word;
  int (*handler)(client_t *client, char *param);
} command_t;

typedef struct param
{
  char  *word;
  char **var;
} param_t;

/*
 * client_list: a doubly linked list of connected clients
 * remote_list: a doubly linked list of remote control servers
 * ctrl_unix:   a local unix domain socket to control scamper
 * ctrl_inet:   an IP socket available to control scamper
 */
static dlist_t *client_list = NULL;
static dlist_t *remote_list = NULL;
static control_unix_t *ctrl_unix = NULL;
static control_inet_t *ctrl_inet = NULL;

#ifdef HAVE_OPENSSL
extern SSL_CTX *remote_tls_ctx;
#endif

#define CONTROL_MASTER_NEW   0 /* scamper --> remoted */
#define CONTROL_MASTER_ID    1 /* scamper <-- remoted */
#define CONTROL_CHANNEL_NEW  2 /* scamper <-- remoted */
#define CONTROL_CHANNEL_FIN  3 /* scamper <-> remoted */
#define CONTROL_KEEPALIVE    4 /* scamper <-> remoted */
#define CONTROL_ACK          5 /* scamper <-> remoted */
#define CONTROL_MASTER_RES   6 /* scamper --> remoted */
#define CONTROL_MASTER_REJ   7 /* scamper <-- remoted */
#define CONTROL_MASTER_OK    8 /* scamper <-- remoted */

/* forward declare remote_reconnect so that it may be used throughout */
static int remote_reconnect(void *param);
static int remote_tx_ka(void *param);
static int remote_rx_abort(void *param);
static control_remote_t *remote_find(const char *name, uint16_t port);
static void remote_free(control_remote_t *rm, int mode);

#define REMOTE_FREE_ALL    0
#define REMOTE_FREE_RECONN 1
#define REMOTE_FREE_RESUME 2

#ifdef HAVE_OPENSSL
#define SSL_MODE_HANDSHAKE   0x00
#define SSL_MODE_ESTABLISHED 0x01
#endif

static int command_handler(command_t *handler, int cnt, client_t *client,
			   char *word, char *param, int *retval)
{
  int i;

  for(i=0; i<cnt; i++)
    {
      if(strcasecmp(handler[i].word, word) == 0)
	{
	  *retval = handler[i].handler(client, param);
	  return 0;
	}
    }

  return -1;
}

/*
 * params_get
 *
 * go through the line and get parameters out, returning the start of
 * each parameter in the words array.
 *
 * the words array needs to be large enough for the expected command
 *
 * the input line is modified -- each parameter is null-terminated
 */
static int params_get(char *line, char **words, int *count)
{
  int i, w;

  i = 0; /* first character in the parameters */
  w = 0; /* first word to be read */

  /* if there is no line, there can't be any parameters */
  if(line == NULL)
    {
      *count = 0;
      return 0;
    }

  while(line[i] != '\0' && w < *count)
    {
      if(line[i] == '"')
	{
	  /* the start of the parameter is past the opening quote */
	  words[w++] = &line[++i];

	  /* until we get to the end of the param / string, keep hunting */
	  while(line[i] != '"' && line[i] != '\0') i++;

	  /* did not get the closing double-quote */
	  if(line[i] == '\0') return -1;
	}
      else
	{
	  /* the start of the word is here, skip past this opening char */
	  words[w++] = &line[i++];

	  /* until we get to the end of the word / string, keep hunting */
	  while(line[i] != ' ' && line[i] != '\0') i++;

	  if(line[i] == '\0') break;
	}

      /* null terminate the word, skip towards the next word */
      line[i++] = '\0';

      /* skip to the next word */
      while(line[i] == ' ' && line[i] != '\0') i++;
    }

  if(line[i] == '\0')
    {
      *count = w;
      return 0;
    }

  return -1;
}

static void client_message_free(client_message_t *msg)
{
  if(msg->data != NULL) free(msg->data);
  free(msg);
  return;
}

static void client_obj_free(client_obj_t *obj)
{
  if(obj == NULL)
    return;
  if(obj->data != NULL)
    free(obj->data);
  free(obj);
  return;
}

static void client_txt_free(client_txt_t *txt)
{
  if(txt == NULL)
    return;
  if(txt->str != NULL)
    free(txt->str);
  free(txt);
  return;
}

static char *client_sockaddr_tostr(client_t *client, char *buf, size_t len)
{
  assert(client->type == CLIENT_TYPE_SOCKET);

  /*
   * if the socket is a unix domain socket, make something up that
   * is sensible.
   */
#ifdef HAVE_SOCKADDR_UN
  if(client->un.sock.sa->sa_family == AF_UNIX)
    {
      if(ctrl_unix->name == NULL)
	return NULL;
      snprintf(buf, len, "%s:%d", ctrl_unix->name, ctrl_unix->num++);
      return buf;
    }
#endif

  /*
   * get the name of the connected socket, which is used to name the
   * source and the outfile
   */
  if(sockaddr_tostr(client->un.sock.sa, buf, len, 1) == NULL)
    {
      printerror_msg(__func__, "could not decipher client sockaddr");
      return NULL;
    }

  return buf;
}

/*
 * client_free
 *
 * free up client state for the socket handle.
 */
static void client_free(client_t *client)
{
#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

  if(client == NULL)
    return;

  /* free up the structures for doing socket work with */
  if(client->type == CLIENT_TYPE_SOCKET)
    {
      if(client->un.sock.fdn != NULL)
	{
	  fd = scamper_fd_fd_get(client->un.sock.fdn);
	  scamper_fd_free(client->un.sock.fdn);
	  client->un.sock.fdn = NULL;
	  shutdown(fd, SHUT_RDWR);
	  socket_close(fd);
	}

      if(client->un.sock.wb != NULL)
	{
	  scamper_writebuf_free(client->un.sock.wb);
	  client->un.sock.wb = NULL;
	}

      if(client->un.sock.sa != NULL)
	{
	  free(client->un.sock.sa);
	  client->un.sock.sa = NULL;
	}
    }
  else if(client->type == CLIENT_TYPE_CHANNEL)
    {
      if(client->un.chan.node != NULL)
	{
	  dlist_node_pop(client->un.chan.rem->list, client->un.chan.node);
	  client->un.chan.node = NULL;
	}
    }

  if(client->lp != NULL)
    {
      scamper_linepoll_free(client->lp, 0);
      client->lp = NULL;
    }

  /* remove the client from the list of clients */
  if(client->node != NULL)
    {
      dlist_node_pop(client_list, client->node);
      client->node = NULL;
    }

  /* make sure the source is empty before freeing */
  if(client->source != NULL)
    {
      scamper_source_abandon(client->source);
      scamper_source_free(client->source);
      client->source = NULL;
    }

  /* cleanup the output file */
  if(client->sof != NULL)
    {
      scamper_outfile_free(client->sof);
      client->sof = NULL;
    }

  if(client->sof_objs != NULL)
    {
      slist_free_cb(client->sof_objs, (slist_free_t)client_obj_free);
      client->sof_objs = NULL;
    }

  if(client->txt != NULL)
    {
      slist_free_cb(client->txt, (slist_free_t)client_txt_free);
      client->txt = NULL;
    }

  free(client);
  return;
}

#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
static int client_send(client_t *client, char *fs, ...)
  __attribute__((format(printf, 2, 3)));
#endif

static int client_send(client_t *client, char *fs, ...)
{
  char msg[512], *str = NULL;
  client_txt_t *t = NULL;
  size_t len, size = sizeof(msg) - 1;
  va_list ap;
  int ret;

  va_start(ap, fs);
  len = vsnprintf(msg, sizeof(msg), fs, ap);
  ret = (int)len;
  if(len < size)
    {
      va_end(ap);
      str = msg;
    }
  else
    {
      if((str = malloc_zero((size_t)(len+1))) == NULL)
	{
	  va_end(ap);
	  goto err;
	}
      vsnprintf(str, len+1, fs, ap);
      va_end(ap);
    }
  str[len++] = '\n';

  if(str == msg && (str = memdup(msg, len)) == NULL)
    goto err;
  if((t = malloc_zero(sizeof(client_txt_t))) == NULL)
    goto err;
  if(slist_tail_push(client->txt, t) == NULL)
    goto err;
  t->str = str;
  t->len = len;

  if(client->type == CLIENT_TYPE_SOCKET)
    scamper_fd_write_unpause(client->un.sock.fdn);
  else if(client->un.chan.rem->fd != NULL)
    scamper_fd_write_unpause(client->un.chan.rem->fd);

  return ret;

 err:
  if(str != NULL && str != msg)
    free(str);
  return -1;
}

/*
 * param_handler
 *
 */
static int param_handler(param_t *handler, int cnt, client_t *client,
			 char *param, char *next)
{
  int i;

  for(i=0; i<cnt; i++)
    {
      /* skip until we find the handler for this parameter */
      if(strcasecmp(handler[i].word, param) != 0)
	{
	  continue;
	}

      /* already seen this parameter specified */
      if(*handler[i].var != NULL)
	{
	  scamper_debug(__func__, "parameter '%s' already specified", param);
	  return -1;
	}

      /* the parameter passed does not have a value to go with it */
      if(next == NULL)
	{
	  scamper_debug(__func__, "parameter '%s' requires argument", param);
	  return -1;
	}

      /* got the parameter */
      *handler[i].var = next;
      return 0;
    }

  return -1;
}

static int set_long(client_t *client, char *buf, char *name,
		    int (*setfunc)(int), int min, int max)
{
  long l;
  char *err;

  if(buf == NULL)
    {
      client_send(client, "ERR set %s requires argument", name);
      scamper_debug(__func__, "set %s required argument", name);
      return -1;
    }

  /*
   * null terminate this word.  discard the return value, we don't care
   * about any further words.
   */
  string_nextword(buf);

  /* make sure the argument is an integer argument */
  if(string_isnumber(buf) == 0)
    {
      client_send(client, "ERR set %s argument is not an integer", name);
      scamper_debug(__func__, "set %s argument is not an integer", name);
      return -1;
    }

  /* convert the argument to a long.  catch any error */
  if(string_tolong(buf, &l) != 0)
    {
      err = strerror(errno);
      client_send(client, "ERR could not convert %s to long: %s", buf, err);
      scamper_debug(__func__, "could not convert %s to long: %s", buf, err);
      return -1;
    }

  if(setfunc(l) == -1)
    {
      client_send(client, "ERR %s: %ld out of range (%d, %d)", name,l,min,max);
      scamper_debug(__func__, "%s: %ld out of range (%d, %d)", name,l,min,max);
      return -1;
    }

  client_send(client, "OK %s %ld", name, l);
  return 0;
}

static int get_switch(client_t *client, char *name, char *buf, long *l)
{
  if(strcasecmp(buf, "on") == 0)
    {
      *l = 1;
    }
  else if(strcasecmp(buf, "off") == 0)
    {
      *l = 0;
    }
  else
    {
      client_send(client, "ERR %s <on|off>", name);
      return -1;
    }

  return 0;
}

static char *source_tostr(char *str, const size_t len,
			  const scamper_source_t *source)
{
  const char *ptr;
  char descr[256], outfile[256], type[512];
  int i;

  /* format type-specific data */
  switch((i = scamper_source_gettype(source)))
    {
    case SCAMPER_SOURCE_TYPE_FILE:
      snprintf(type, sizeof(type),
	       "type 'file' file '%s'",
	       scamper_source_file_getfilename(source));
      break;

    case SCAMPER_SOURCE_TYPE_CMDLINE:
      snprintf(type, sizeof(type), "type 'cmdline'");
      break;

    case SCAMPER_SOURCE_TYPE_CONTROL:
      snprintf(type, sizeof(type), "type 'control'");
      break;

    default:
      printerror_msg(__func__, "unknown source type %d", i);
      return NULL;
    }

  /* if there is a description for the source, then format it in */
  if((ptr = scamper_source_getdescr(source)) != NULL)
    snprintf(descr, sizeof(descr), " descr '%s'", ptr);
  else
    descr[0] = '\0';

  /* outfile */
  if((ptr = scamper_source_getoutfile(source)) != NULL)
    snprintf(outfile, sizeof(outfile), " outfile '%s'", ptr);
  else
    outfile[0] = '\0';

  snprintf(str, len,
	   "name '%s'%s list_id %u cycle_id %u priority %u%s %s",
	   scamper_source_getname(source),
	   descr,
	   scamper_source_getlistid(source),
	   scamper_source_getcycleid(source),
	   scamper_source_getpriority(source),
	   outfile,
	   type);

  return str;
}

/*
 * client_data_send
 *
 * take a data object and put it on the list of data objects to send.
 */
static int client_data_send(void *wf_param, const void *vdata, size_t len,
			    void *p)
{
  client_t *client = wf_param;
  client_obj_t *obj = NULL;
  const uint8_t *data = vdata;
  scamper_task_t *task = p;
  scamper_sourcetask_t *st;
  scamper_fd_t *fdn;

  assert(len >= 8);
  assert(client->sof_objs != NULL);

  if(client->sof_format == CLIENT_FORMAT_WARTS)
    {
      if(data[0] != 0x12 || data[1] != 0x05)
        {
	  printerror_msg(__func__,
		     "lost synchronisation: %02x%02x %02x%02x %02x%02x%02x%02x",
		     data[0], data[1], data[2], data[3], data[4], data[5],
		     data[6], data[7]);
	  goto err;
	}

      /* cycle end */
      if(data[2] == 0 && data[3] == 0x04)
	client->mode = CLIENT_MODE_FLUSH;
    }
  else if(client->sof_format == CLIENT_FORMAT_JSON)
    {
      if(data[0] != '{')
	{
	  printerror_msg(__func__, "lost synchronisation %c", data[0]);
	  goto err;
	}

      /* cycle end */
      if(strncmp("{\"type\":\"cycle-stop\",", (const char *)data, 21) == 0)
	client->mode = CLIENT_MODE_FLUSH;
    }

  if((obj = malloc_zero(sizeof(client_obj_t))) == NULL)
    {
      printerror(__func__, "could not alloc obj");
      goto err;
    }

  if((obj->data = memdup(vdata, len)) == NULL)
    {
      printerror(__func__, "could not memdup");
      goto err;
    }
  obj->len = len;

  if(task != NULL)
    {
      st = scamper_task_getsourcetask(task);
      obj->id = scamper_sourcetask_getid(st);
      obj->flags |= CLIENT_OBJ_FLAG_ID;

      if(scamper_task_is_inprog(task))
	obj->flags |= CLIENT_OBJ_FLAG_INPROG;
    }

  if(slist_tail_push(client->sof_objs, obj) == NULL)
    {
      printerror(__func__, "could not push obj onto list");
      goto err;
    }
  obj = NULL;

  if(client->type == CLIENT_TYPE_SOCKET)
    fdn = client->un.sock.fdn;
  else
    fdn = client->un.chan.rem->fd;
  if(fdn != NULL)
    scamper_fd_write_unpause(fdn);

  return 0;

 err:
  client_obj_free(obj);
  return -1;
}

static void client_signalmore(void *param)
{
  client_t *client = (client_t *)param;
  client_send(client, "MORE");
  return;
}

static char *client_tostr(void *param, char *buf, size_t len)
{
  client_t *client = param;
  size_t off = 0;

  assert(client->type == CLIENT_TYPE_SOCKET ||
	 client->type == CLIENT_TYPE_CHANNEL);

  buf[0] = '\0';
  if(client->type == CLIENT_TYPE_SOCKET)
    string_concaf(buf,len,&off,"fd %d", scamper_fd_fd_get(client->un.sock.fdn));
  else
    string_concat_u32(buf, len, &off, "chan ", client->un.chan.id);

  return buf;
}

/*
 * command_attach
 *
 * the client wants to receive data from measurements over their control
 * socket connection.
 *
 */
static int command_attach(client_t *client, char *buf)
{
  scamper_source_params_t ssp;
  scamper_file_t *sf;
  char sab[128];
  long long ll;
  char *cycleid_str = NULL, *descr = NULL, *format = NULL;
  char *listid_str = NULL, *monitor = NULL, *name = NULL, *priority_str = NULL;
  char *params[14], *next;
  int i, cnt = sizeof(params) / sizeof(char *);
  param_t handlers[] = {
    {"cycle_id", &cycleid_str},
    {"descr", &descr},
    {"format", &format},
    {"list_id", &listid_str},
    {"monitor", &monitor},
    {"name", &name},
    {"priority", &priority_str},
  };
  int handler_cnt = sizeof(handlers) / sizeof(param_t);

  if(params_get(buf, params, &cnt) != 0)
    {
      client_send(client, "ERR could not params_get");
      return 0;
    }
  for(i=0; i<cnt; i+=2)
    {
      if(i+1 != cnt) next = params[i+1];
      else next = NULL;
      if(param_handler(handlers, handler_cnt, client, params[i], next) == -1)
	{
	  client_send(client,"ERR command attach param '%s' failed",params[i]);
	  return 0;
	}
    }

  if(client_sockaddr_tostr(client, sab, sizeof(sab)) == NULL)
    goto err;

  /*
   * set the source parameters, processing the parameters in alphabetical
   * order to make sure we get them all
   */
  memset(&ssp, 0, sizeof(ssp));
  ssp.list_id    = 0;
  ssp.cycle_id   = 1;
  ssp.priority   = 1;

  if(cycleid_str != NULL)
    {
      if(string_tollong(cycleid_str, &ll, NULL, 0) != 0 ||
	 ll < 0 || ll > UINT32_MAX)
	{
	  client_send(client, "ERR invalid cycle_id");
	  return 0;
	}
      ssp.cycle_id = (uint32_t)ll;
    }

  ssp.descr = descr;

  if(format == NULL)
    format = "warts";

  if(strcasecmp(format, "warts") == 0)
    client->sof_format = CLIENT_FORMAT_WARTS;
  else if(strcasecmp(format, "json") == 0)
    client->sof_format = CLIENT_FORMAT_JSON;
  else
    {
      client_send(client, "ERR format must be warts or json");
      return 0;
    }

  if(listid_str != NULL)
    {
      if(string_tollong(listid_str, &ll, NULL, 0) != 0 ||
	 ll < 0 || ll > UINT32_MAX)
	{
	  client_send(client, "ERR invalid list_id");
	  return 0;
	}
      ssp.list_id = (uint32_t)ll;
    }

  ssp.monitor = monitor;

  /* if no name specified, then create one based on the socket */
  if(name == NULL)
    ssp.name = sab;
  else
    ssp.name = name;

  if(priority_str != NULL)
    {
      if(string_tollong(priority_str, &ll, NULL, 0) != 0 ||
	 ll < 1 || ll > 100000)
	{
	  client_send(client, "ERR invalid priority");
	  return 0;
	}
      ssp.priority = (uint32_t)ll;
    }

  if((client->sof_objs = slist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc objs list");
      goto err;
    }

  if((client->sof = scamper_outfile_opennull(sab, format)) == NULL)
    {
      printerror(__func__, "could not alloc outfile");
      goto err;
    }
  sf = scamper_outfile_getfile(client->sof);
  scamper_file_setwritefunc(sf, client, client_data_send);
  ssp.sof = client->sof;

  /* create the source */
  if((client->source = scamper_source_control_alloc(&ssp, client_signalmore,
						    client_tostr,
						    client)) == NULL)
    {
      printerror(__func__, "could not allocate source '%s'", sab);
      goto err;
    }

  /* put the source into rotation */
  if(scamper_sources_add(client->source) != 0)
    {
      printerror(__func__, "could not add source '%s' to rotation", sab);
      goto err;
    }

  client->mode = CLIENT_MODE_ATTACHED;
  client_send(client, "OK");
  return 0;

 err:
  client_send(client, "ERR internal error");
  client_free(client);
  return 0;
}

static int command_lss_clear(client_t *client, char *buf)
{
#ifndef DISABLE_SCAMPER_TRACE
  if(buf == NULL)
    {
      client_send(client, "ERR usage: lss-clear [lss-name]");
      return 0;
    }
  string_nextword(buf);
  if(scamper_do_trace_dtree_lss_clear(buf) != 0)
    return client_send(client, "ERR lss-clear %s failed", buf);
  return client_send(client, "OK lss-clear %s", buf);
#else
  return client_send(client, "ERR scamper not built with trace support");
#endif
}

static int command_exit(client_t *client, char *buf)
{
  client_free(client);
  return 0;
}

static int command_get_command(client_t *client, char *buf)
{
  const char *command = scamper_option_command_get();
  if(command == NULL)
    {
      return client_send(client, "OK null command");
    }
  return client_send(client, "OK command %s", command);
}

static int command_get_monitorname(client_t *client, char *buf)
{
  const char *monitorname = scamper_option_monitorname_get();
  if(monitorname == NULL)
    {
      return client_send(client, "OK null monitorname");
    }
  return client_send(client, "OK monitorname %s", monitorname);
}

static int command_get_nameserver(client_t *client, char *buf)
{
#ifndef DISABLE_SCAMPER_HOST
  const scamper_addr_t *nsip = scamper_do_host_getns();
  char nsbuf[128];
  if(nsip == NULL)
    return client_send(client, "OK null nameserver");
  return client_send(client, "OK nameserver %s",
		     scamper_addr_tostr(nsip, nsbuf, sizeof(nsbuf)));
#else
  return client_send(client, "ERR scamper not built with host support");
#endif
}

static int command_get_pid(client_t *client, char *buf)
{
#ifndef _WIN32 /* windows does not have getpid */
  pid_t pid = getpid();
#else
  DWORD pid = GetCurrentProcessId();
#endif
  return client_send(client, "OK pid %d", pid);
}

static int command_get_pps(client_t *client, char *buf)
{
  int pps = scamper_option_pps_get();
  return client_send(client, "OK pps %d", pps);
}

static int command_get_version(client_t *client, char *buf)
{
  return client_send(client, "OK version " SCAMPER_VERSION);
}

static int command_get_window(client_t *client, char *buf)
{
  return client_send(client, "OK window %d/%d",
		     scamper_queue_windowcount(), scamper_option_window_get());
}

static int command_get(client_t *client, char *buf)
{
  static command_t handlers[] = {
    {"command",     command_get_command},
    {"monitorname", command_get_monitorname},
    {"nameserver",  command_get_nameserver},
    {"pid",         command_get_pid},
    {"pps",         command_get_pps},
    {"version",     command_get_version},
    {"window",      command_get_window},
  };
  static int handler_cnt = sizeof(handlers) / sizeof(command_t);
  int ret;

  if(buf == NULL)
    {
      client_send(client, "ERR usage: get "
	  "[command | monitorname | nameserver | pid | pps | version | window]");
      return 0;
    }

  if(command_handler(handlers, handler_cnt, client, buf, NULL, &ret) == -1)
    {
      client_send(client, "ERR unhandled get command '%s'", buf);
      return 0;
    }

  return 0;
}

static int command_help(client_t *client, char *buf)
{
  client_send(client, "ERR XXX: todo");
  return 0;
}

/*
 * command_remote_add
 *
 * remote add server <name> ssl <on|off>
 */
static int command_remote_add(client_t *client, char *buf)
{
  char *params[4], *next, *server = NULL, *server_name = NULL, *ssl = NULL;
  int   i, cnt = sizeof(params) / sizeof(char *);
  param_t handlers[] = {
    {"server", &server},
    {"ssl", &ssl},
  };
  int handler_cnt = sizeof(handlers) / sizeof(param_t);
  uint16_t server_port;
  int server_ssl = 0;
  long lo;

  assert(client->type == CLIENT_TYPE_SOCKET);

  if(params_get(buf, params, &cnt) == -1)
    {
      client_send(client, "ERR remote add params_get failed");
      goto done;
    }

  for(i=0; i<cnt; i += 2)
    {
      if(i+1 != cnt) next = params[i+1];
      else next = NULL;
      if(param_handler(handlers, handler_cnt, client, params[i], next) == -1)
	{
	  client_send(client, "ERR remote add param '%s' failed", params[i]);
	  goto done;
	}
    }

  if(server == NULL)
    {
      client_send(client, "ERR usage remote add server <name>");
      goto done;
    }
  if(string_addrport(server, &server_name, &server_port) != 0)
    {
      client_send(client, "ERR invalid server, expect <name>:<port>");
      goto done;
    }
  if(remote_find(server_name, server_port) != NULL)
    {
      client_send(client, "ERR %s:%u already exists", server_name, server_port);
      goto done;
    }

  if(ssl != NULL)
    {
      if(get_switch(client, "ssl", ssl, &lo) != 0)
	goto done;
#ifdef HAVE_OPENSSL
      server_ssl = lo;
#else
      if(lo != 0)
	{
	  client_send(client, "ERR ssl not supported");
	  goto done;
	}
#endif
    }
  else
    {
#ifdef HAVE_OPENSSL
      server_ssl = 1;
#else
      server_ssl = 0;
#endif
    }

  if(scamper_control_add_remote(server_name, server_port, server_ssl) != 0)
    {
      client_send(client, "ERR could not add remote");
      goto done;
    }

  client_send(client, "OK");

 done:
  if(server_name != NULL) free(server_name);
  return 0;
}

/*
 * command_remote_delete
 *
 * remote delete <server>
 */
static int command_remote_delete(client_t *client, char *buf)
{
  control_remote_t *rm;
  char *params[1], *server, *server_name = NULL;
  int cnt = sizeof(params) / sizeof(char *);
  uint16_t server_port;

  if(remote_list == NULL)
    {
      client_send(client, "ERR no remote connections");
      goto done;
    }

  if(params_get(buf, params, &cnt) == -1)
    {
      client_send(client, "ERR remote delete params_get failed");
      goto done;
    }

  if(cnt != 1)
    {
      client_send(client, "ERR missing required parameter for remote delete");
      goto done;
    }
  server = params[0];
  if(string_addrport(server, &server_name, &server_port) != 0)
    {
      client_send(client, "ERR invalid server");
      goto done;
    }
  if((rm = remote_find(server_name, server_port)) == NULL)
    {
      client_send(client, "ERR %s:%u not found", server_name, server_port);
      goto done;
    }

  remote_free(rm, REMOTE_FREE_ALL);
  client_send(client, "OK");

 done:
  if(server_name != NULL) free(server_name);
  return 0;
}

/*
 * command_remote_list
 *
 * list the remote control instances scamper has established.
 */
static int command_remote_list(client_t *client, char *buf)
{
  control_remote_t *rm;
  dlist_node_t *dn;
  char tmp[256];
  size_t off;

  if(remote_list != NULL)
    {
      for(dn=dlist_head_node(remote_list); dn != NULL; dn=dlist_node_next(dn))
	{
	  rm = dlist_node_item(dn);
	  off = 0;

	  string_concat2(tmp, sizeof(tmp), &off, "INFO ", rm->server_name);
	  string_concat_u16(tmp, sizeof(tmp), &off, ":", rm->server_port);
	  if(rm->alias != NULL)
	    string_concat2(tmp, sizeof(tmp), &off, " alias ", rm->alias);
	  client_send(client, "%s", tmp);
	}
    }
  client_send(client, "OK");

  return 0;
}

static int command_remote(client_t *client, char *buf)
{
  static command_t handlers[] = {
    {"add", command_remote_add},
    {"delete", command_remote_delete},
    {"list", command_remote_list},
  };
  static int handler_cnt = sizeof(handlers) / sizeof(command_t);
  char *next;
  int ret;

  if(buf == NULL)
    {
      client_send(client, "ERR usage: remote [add]");
      return 0;
    }
  next = string_nextword(buf);

  if(command_handler(handlers, handler_cnt, client, buf, next, &ret) == -1)
    {
      client_send(client, "ERR unhandled outfile command '%s'", buf);
    }

  return 0;
}

static int command_set_command(client_t *client, char *buf)
{
  if(scamper_option_command_set(buf) == -1)
    {
      client_send(client, "ERR could not set command");
      return -1;
    }

  client_send(client, "OK");
  return 0;
}

static int command_set_monitorname(client_t *client, char *buf)
{
  if(scamper_option_monitorname_set(buf) == -1)
    {
      client_send(client, "ERR could not set monitorname");
      return -1;
    }

  client_send(client, "OK");
  return 0;
}

static int command_set_nameserver(client_t *client, char *buf)
{
#ifndef DISABLE_SCAMPER_HOST
  if(scamper_do_host_setns(buf) == -1)
    {
      client_send(client, "ERR could not set nameserver");
      return -1;
    }
  client_send(client, "OK");
  return 0;
#else
  client_send(client, "ERR scamper not built with host support");
  return -1;
#endif
}

static int command_set_pps(client_t *client, char *buf)
{
  return set_long(client, buf, "pps", scamper_option_pps_set,
		  SCAMPER_OPTION_PPS_MIN, SCAMPER_OPTION_PPS_MAX);
}

static int command_set_window(client_t *client, char *buf)
{
  return set_long(client, buf, "window", scamper_option_window_set,
		  SCAMPER_OPTION_WINDOW_MIN, SCAMPER_OPTION_WINDOW_MAX);
}

static int command_set(client_t *client, char *buf)
{
  static command_t handlers[] = {
    {"command",     command_set_command},
    {"monitorname", command_set_monitorname},
    {"nameserver",  command_set_nameserver},
    {"pps",         command_set_pps},
    {"window",      command_set_window},
  };
  static int handler_cnt = sizeof(handlers) / sizeof(command_t);
  char *next;
  int ret;

  if(buf == NULL)
    {
      client_send(client, "ERR usage: "
		  "set [command | monitorname | pps | window]");
      return 0;
    }
  next = string_nextword(buf);

  if(command_handler(handlers, handler_cnt, client, buf, next, &ret) == -1)
    {
      client_send(client, "ERR unhandled set command '%s'", buf);
    }
  return 0;
}

static int source_foreach(void *param, scamper_source_t *source)
{
  client_t *client = (client_t *)param;
  char str[1024];

  if(source_tostr(str, sizeof(str), source) != NULL)
    {
      client_send(client, "INFO %s", str);
    }

  return 0;
}

/*
 * command_source_list
 *
 * source list [<name>]
 *
 */
static int command_source_list(client_t *client, char *buf)
{
  scamper_source_t *source;
  char *params[1], str[1024];
  char *name;
  int   cnt = sizeof(params) / sizeof(char *);

  /* if there is no parameter, then dump all lists */
  if(buf == NULL)
    {
      scamper_sources_foreach(client, source_foreach);
      client_send(client, "OK");
      return 0;
    }

  /* if there is a parameter, then use that to find a source */
  if(params_get(buf, params, &cnt) == -1 || cnt != 1)
    {
      client_send(client, "ERR source check params_get failed");
      return -1;
    }
  name = params[0];
  if((source = scamper_sources_get(name)) == NULL)
    {
      client_send(client, "ERR no source '%s'", name);
      return 0;
    }
  client_send(client, "INFO %s", source_tostr(str, sizeof(str), source));
  client_send(client, "OK");

  return 0;
}

static int command_source(client_t *client, char *buf)
{
  static command_t handlers[] = {
    {"list",   command_source_list},
  };
  static int handler_cnt = sizeof(handlers) / sizeof(command_t);
  char *next;
  int ret;

  if(buf == NULL)
    {
      client_send(client,
		  "ERR usage: source [cycle | list]");
      return 0;
    }

  next = string_nextword(buf);
  if(command_handler(handlers, handler_cnt, client, buf, next, &ret) == -1)
    {
      client_send(client, "ERR unhandled command '%s'", buf);
      return 0;
    }

  return 0;
}

static int command_shutdown_cancel(client_t *client, char *buf)
{
  scamper_exitwhendone(0);
  client_send(client, "OK");
  return 0;
}

static int command_shutdown_done(client_t *client, char *buf)
{
  scamper_exitwhendone(1);
  client_send(client, "OK");
  return 0;
}

static int command_shutdown_flush(client_t *client, char *buf)
{
  /* empty the address list of all sources */
  scamper_sources_empty();

  /* tell scamper to exit when it has finished probing the existing window */
  scamper_exitwhendone(1);

  client_send(client, "OK");
  return 0;
}

static int command_shutdown_now(client_t *client, char *buf)
{
  /* empty the active trace window */
  scamper_queue_empty();

  /* empty the address list of all sources */
  scamper_sources_empty();

  /* tell scamper to exit when it has finished probing the existing window */
  scamper_exitwhendone(1);

  client_send(client, "OK");

  return 0;
}

static int command_shutdown(client_t *client, char *buf)
{
  static command_t handlers[] = {
    {"cancel", command_shutdown_cancel},
    {"done",   command_shutdown_done},
    {"flush",  command_shutdown_flush},
    {"now",    command_shutdown_now},
  };
  static int handler_cnt = sizeof(handlers) / sizeof(command_t);
  char *next;
  int ret;

  if(buf == NULL)
    {
      client_send(client, "ERR usage: [cancel | done | flush | now]");
      return 0;
    }

  next = string_nextword(buf);
  if(command_handler(handlers, handler_cnt, client, buf, next, &ret) == -1)
    {
      client_send(client, "ERR unhandled command '%s'", buf);
      return 0;
    }

  return 0;
}

static int client_isdone(client_t *client)
{
  size_t len;
  int c;

  if(client->type == CLIENT_TYPE_SOCKET &&
     (len = scamper_writebuf_len(client->un.sock.wb)) != 0)
    {
      scamper_debug(__func__, "client writebuf len %d", (int)len);
      return 0;
    }

  if(client->source != NULL && scamper_source_isfinished(client->source) == 0)
    {
      scamper_debug(__func__, "source not finished");
      return 0;
    }

  if(client->sof_obj != NULL)
    {
      scamper_debug(__func__, "object partially written");
      return 0;
    }

  if(client->sof_objs != NULL && (c = slist_count(client->sof_objs)) != 0)
    {
      scamper_debug(__func__, "objects outstanding %d", c);
      return 0;
    }

  return 1;
}

/*
 * client_attached_cb
 *
 * this callback is used when a control socket has been 'attached' such that
 * it sends commands over the control socket and in return it obtains
 * results.
 */
static int client_attached_cb(client_t *client, uint8_t *buf, size_t len)
{
  char errbuf[256];
  char *str;
  long long ll;
  uint32_t id;

  assert(client->source != NULL);

  /* the control socket will not be supplying any more tasks */
  if(len == 4 && strcasecmp((char *)buf, "done") == 0)
    {
      client_send(client, "OK");
      scamper_source_control_finish(client->source);
      return 0;
    }

  if(len >= 5 && strncasecmp((char *)buf, "halt ", 5) == 0)
    {
      str = string_nextword((char *)buf);
      if(string_isnumber(str) == 0)
	return client_send(client, "ERR usage: halt [id]");
      if(string_tollong(str, &ll, NULL, 0) != 0 || ll <= 0 || ll > 0xffffffffLL)
	return client_send(client, "ERR halt number invalid");
      id = (uint32_t)ll;
      if(scamper_source_halttask(client->source, id) != 0)
	return client_send(client, "ERR no task id-%u", id);
      return client_send(client, "OK halted %u", id);
    }

  /* try the command to see if it is valid and acceptable */
  if(scamper_source_command2(client->source, (char *)buf, &id,
			     errbuf, sizeof(errbuf)) != 0)
    {
      if(errbuf[0] != '\0')
	return client_send(client, "ERR command not accepted: %s", errbuf);
      return client_send(client, "ERR command not accepted");
    }

  return client_send(client, "OK id-%d", id);
}

static int client_interactive_cb(client_t *client, uint8_t *buf, size_t len)
{
  static command_t handlers[] = {
    {"attach",     command_attach},
    {"exit",       command_exit},
    {"get",        command_get},
    {"help",       command_help},
    {"lss-clear",  command_lss_clear},
    {"remote",     command_remote},
    {"set",        command_set},
    {"shutdown",   command_shutdown},
    {"source",     command_source},
  };
  static int handler_cnt = sizeof(handlers) / sizeof(command_t);
  char *next;
  int ret;

  /* XXX: should check for null? */
  next = string_nextword((char *)buf);

  if(command_handler(handlers,handler_cnt,client,(char *)buf,next,&ret) == -1)
    {
      client_send(client, "ERR unhandled command '%s'", buf);
      return 0;
    }

  return 0;
}

/*
 * client_read_line
 *
 * callback passed to the client's linepoll instance, which is used to read
 * incoming commands.  the current mode the client is in determines how the
 * command is actually handled.
 */
static int client_read_line(void *param, uint8_t *buf, size_t len)
{
  static int (*const func[])(client_t *, uint8_t *, size_t) = {
    client_interactive_cb,   /* CLIENT_MODE_INTERACTIVE == 0x00 */
    client_attached_cb,      /* CLIENT_MODE_ATTACHED    == 0x01 */
    NULL,                    /* CLIENT_MODE_FLUSH       == 0x02 */
  };
  client_t *client = (client_t *)param;

  /* make sure all the characters in the string are printable */
  if(string_isprint((char *)buf, len) == 0)
    {
      if(client->source != NULL)
	{
	  scamper_source_control_finish(client->source);
	  scamper_source_abandon(client->source);
	}
      client_send(client, "ERR invalid character in line");
      client->mode = CLIENT_MODE_FLUSH;
      return 0;
    }

  if(func[client->mode] != NULL)
    return func[client->mode](client, buf, len);
  return 0;
}

static client_t *client_alloc(uint8_t type)
{
  client_t *client = NULL;
  if(client_list == NULL && (client_list = dlist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc client_list");
      goto err;
    }
  if((client = malloc_zero(sizeof(client_t))) == NULL)
    {
      printerror(__func__, "could not alloc client");
      goto err;
    }
  client->type = type;
  if((client->node = dlist_tail_push(client_list, client)) == NULL ||
     (client->lp = scamper_linepoll_alloc(client_read_line, client)) == NULL ||
     (client->txt = slist_alloc()) == NULL)
    {
      printerror(__func__, "could not init client");
      goto err;
    }
  return client;

 err:
  if(client != NULL) client_free(client);
  return NULL;
}

static void client_read(const int fd, client_t *client)
{
  ssize_t rrc;
  uint8_t buf[4096];

  assert(client->type == CLIENT_TYPE_SOCKET);
  assert(scamper_fd_fd_get(client->un.sock.fdn) == fd);

  /* handle error conditions */
  if((rrc = recv(fd, buf, sizeof(buf), 0)) < 0)
    {
      if(errno == EAGAIN || errno == EINTR)
	return;
      printerror(__func__, "could not recv from %d", fd);
      client_free(client);
      return;
    }

  /* handle disconnection */
  if(rrc == 0)
    {
      scamper_fd_read_pause(client->un.sock.fdn);
      if(client->source != NULL)
	{
	  scamper_source_control_finish(client->source);
	  scamper_source_abandon(client->source);
	}
      if(client_isdone(client) != 0)
	client_free(client);
      else
	client->mode = CLIENT_MODE_FLUSH;
      return;
    }

  scamper_linepoll_handle(client->lp, buf, (size_t)rrc);
  return;
}

static int client_writebuf_send(client_t *client, void *buf, size_t len)
{
  assert(client->type == CLIENT_TYPE_SOCKET);
  return scamper_writebuf_send(client->un.sock.wb, buf, len);
}

static int client_write_do(client_t *client,
			   int (*sendfunc)(client_t *, void *, size_t))
{
  client_txt_t *t = NULL;
  client_obj_t *o = NULL;
  uint8_t data[8192];
  char str[128];
  size_t x, len;
  int rc;

  if(client->sof_off == 0)
    {
      while((t = slist_head_pop(client->txt)) != NULL)
	{
	  rc = sendfunc(client, t->str, t->len);
	  client_txt_free(t); t = NULL;
	  if(rc != 0)
	    return -1;
	}

      /* check if we should start sending through a completed task */
      if(client->sof_objs != NULL &&
	 (o = slist_head_pop(client->sof_objs)) != NULL)
	{
	  client->sof_obj = o;

	  if(client->sof_format == CLIENT_FORMAT_WARTS)
	    x = uuencode_len(o->len, NULL, NULL);
	  else
	    x = o->len;

	  if(o->flags & CLIENT_OBJ_FLAG_ID)
	    len = snprintf(str, sizeof(str), "DATA %d id-%u%s\n",
			   (int)x, o->id,
			   o->flags & CLIENT_OBJ_FLAG_INPROG ? " inprog" : "");
	  else
	    len = snprintf(str, sizeof(str), "DATA %d\n", (int)x);

	  if(sendfunc(client, str, len) < 0)
	    {
	      printerror(__func__, "could not send DATA header");
	      return -1;
	    }
	}
    }
  else
    {
      o = client->sof_obj;
    }

  if(o != NULL)
    {
      if(client->sof_format == CLIENT_FORMAT_WARTS)
	{
	  len = uuencode_bytes(o->data, o->len, &client->sof_off,
			       data, sizeof(data));
	}
      else
	{
	  if((len = o->len - client->sof_off) > sizeof(data))
	    len = sizeof(data);
	  memcpy(data, o->data + client->sof_off, len);
	  client->sof_off += len;
	}

      if(client->sof_off == o->len)
	{
	  client_obj_free(o);
	  client->sof_obj = NULL;
	  client->sof_off = 0;
	}

      if(sendfunc(client, data, len) != 0)
	{
	  printerror(__func__, "could not send %d bytes", (int)len);
	  return -1;
	}
    }

  return 0;
}

static void client_write(const int fd, client_t *client)
{
  assert(client->type == CLIENT_TYPE_SOCKET);
  assert(scamper_fd_fd_get(client->un.sock.fdn) == fd);

  /*
   * if there is nothing buffered in the writebuf, then put some more
   * in there.
   */
  if(scamper_writebuf_len(client->un.sock.wb) == 0 &&
     client_write_do(client, client_writebuf_send) != 0)
    goto err;

  if(scamper_writebuf_write(fd, client->un.sock.wb) != 0)
    {
      printerror(__func__, "fd %d", fd);
      goto err;
    }

  /*
   * do we have anything more to write for this client at this time?
   * if not, pause the polling for write events, and check if we're
   * going to have anything more at all.
   */
  if(scamper_writebuf_len(client->un.sock.wb) == 0 &&
     slist_count(client->txt) == 0 && client->sof_off == 0 &&
     (client->sof_objs == NULL || slist_count(client->sof_objs) == 0))
    {
      scamper_fd_write_pause(client->un.sock.fdn);
      if(client->mode == CLIENT_MODE_FLUSH && client_isdone(client) != 0)
	client_free(client);
    }

  return;

 err:
  client_free(client);
  return;
}

/*
 * remote_find
 *
 * check if we already have a connection to the supplied remote control
 * server.
 */
static control_remote_t *remote_find(const char *name, uint16_t port)
{
  dlist_node_t *dn;
  control_remote_t *rm;
  if(remote_list == NULL)
    return NULL;
  for(dn=dlist_head_node(remote_list); dn != NULL; dn=dlist_node_next(dn))
    {
      rm = dlist_node_item(dn);
      if(strcasecmp(rm->server_name, name) == 0 && rm->server_port == port)
	return rm;
    }
  return NULL;
}

/*
 * remote_free
 *
 * clean up remote control state based on the mode parameter.
 *
 * resume: clean up the TLS and Internet sockets, but not other state.
 * reconn: resume + channels.
 * all:    everything.
 */
static void remote_free(control_remote_t *rm, int mode)
{
  client_t *client;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

#ifdef HAVE_OPENSSL
  tls_bio_free(rm->ssl, rm->ssl_rbio, rm->ssl_wbio);
  rm->ssl = NULL;
  rm->ssl_wbio = NULL;
  rm->ssl_rbio = NULL;
  rm->ssl_mode = SSL_MODE_HANDSHAKE;
#endif

  if(rm->fd != NULL)
    {
      fd = scamper_fd_fd_get(rm->fd);
      scamper_fd_free(rm->fd); rm->fd = NULL;
      shutdown(fd, SHUT_RDWR);
      socket_close(fd);
    }

  if(rm->wb != NULL)
    {
      scamper_writebuf_free(rm->wb);
      rm->wb = NULL;
    }

  rm->bufoff = 0;
  rm->mode = REMOTE_MODE_CONNECT;

  if(mode == REMOTE_FREE_RESUME)
    return;

  if(rm->alias != NULL)
    {
      free(rm->alias);
      rm->alias = NULL;
    }

  while((client = dlist_head_pop(rm->list)) != NULL)
    {
      client->un.chan.node = NULL;
      client_free(client);
    }
  rm->snd_nxt = 0;
  rm->rcv_nxt = 0;

  if(rm->messages != NULL)
    slist_empty_cb(rm->messages, (slist_free_t)client_message_free);

  if(mode != REMOTE_FREE_ALL)
    return;

  if(rm->sq != NULL)
    {
      scamper_queue_free(rm->sq);
      rm->sq = NULL;
    }

  if(rm->server_name != NULL)
    {
      free(rm->server_name);
      rm->server_name = NULL;
    }

  if(rm->list != NULL)
    {
      dlist_free(rm->list);
      rm->list = NULL;
    }

  if(rm->messages != NULL)
    {
      slist_free(rm->messages);
      rm->messages = NULL;
    }

  if(rm->node != NULL)
    {
      dlist_node_pop(remote_list, rm->node);
      rm->node = NULL;
    }

  free(rm);
  return;
}

/*
 * remote_retry:
 *
 * the master control socket went away, schedule a reconnect.
 */
static int remote_retry(control_remote_t *rm, int now)
{
  struct timeval tv;
  uint8_t u8;

  /* free just the state for a given socket, not all of the structure */
  if(rm->resume != 0)
    remote_free(rm, REMOTE_FREE_RESUME);
  else
    remote_free(rm, REMOTE_FREE_RECONN);

  gettimeofday_wrap(&tv);
  if(now == 0)
    {
      random_u8(&u8); u8 &= 0x1f; tv.tv_sec += 30 + u8;
      scamper_debug(__func__, "waiting for %u seconds", 30 + u8);
    }

  scamper_queue_event_update_time(rm->sq, &tv);
  scamper_queue_event_update_cb(rm->sq, remote_reconnect, rm);
  return 0;
}

#ifdef HAVE_OPENSSL
static int remote_sock_ssl_want_read_cb(void *param, uint8_t *buf, int len)
{
  scamper_writebuf_send(param, buf, len);
  return 0;
}

/*
 * remote_sock_ssl_want_read
 *
 * the OpenSSL routines told us to do a read from the socket.
 */
static int remote_sock_ssl_want_read(control_remote_t *rm)
{
  char errbuf[64];
  int rc;

  if((rc = tls_want_read(rm->ssl_wbio, rm->wb, errbuf, sizeof(errbuf),
			 remote_sock_ssl_want_read_cb)) < 0)
    {
      scamper_debug(__func__, "%s", errbuf);
      return -1;
    }
  if(rc > 0)
    scamper_fd_write_unpause(rm->fd);

  return rc;
}

/*
 * remote_sock_ssl_init
 *
 * initialise the remote socket's SSL state.
 */
static int remote_sock_ssl_init(control_remote_t *rm)
{
  int rc;

  if(tls_bio_alloc(remote_tls_ctx, &rm->ssl, &rm->ssl_rbio, &rm->ssl_wbio) != 0)
    {
      scamper_debug(__func__, "could not create bios / ssl");
      return -1;
    }

  SSL_set_connect_state(rm->ssl);
  ERR_clear_error();
  rc = SSL_do_handshake(rm->ssl);
  assert(rc <= 0);
  if(SSL_get_error(rm->ssl, rc) == SSL_ERROR_WANT_READ &&
     remote_sock_ssl_want_read(rm) < 0)
    return -1;

  return 0;
}
#endif /* HAVE_OPENSSL */

/*
 * remote_sock_write
 *
 */
static int remote_sock_write(control_remote_t *rm, void *ptr, size_t len,
			     uint32_t sequence, uint32_t channel)
{
  uint8_t hdr[REMOTE_HDRLEN];

  assert(len <= 65535);

  bytes_htonl(hdr+0, sequence);
  bytes_htonl(hdr+4, channel);
  bytes_htons(hdr+8, (uint16_t)len);

#ifdef HAVE_OPENSSL
  if(rm->ssl != NULL)
    {
      SSL_write(rm->ssl, hdr, REMOTE_HDRLEN);
      SSL_write(rm->ssl, ptr, len);
      remote_sock_ssl_want_read(rm);
      return 0;
    }
#endif

  if(scamper_writebuf_send(rm->wb, hdr, REMOTE_HDRLEN) != 0 ||
     scamper_writebuf_send(rm->wb, ptr, len) != 0)
    {
      printerror(__func__, "could not write message");
      return -1;
    }
  scamper_fd_write_unpause(rm->fd);

  return 0;
}

/*
 * remote_sock_send
 *
 */
static int remote_sock_send(control_remote_t *rm, void *ptr, size_t len,
			    uint32_t channel, int ack)
{
  client_message_t *msg = NULL;
  uint32_t sequence;

  if(len == 0 || len > 65535)
    {
      scamper_debug(__func__, "invalid length %d", (int)len);
      goto err;
    }

  if(ack == 0 && rm->mode == REMOTE_MODE_CONNECT)
    {
      scamper_debug(__func__, "not sending unack frame in connect mode");
      return 0;
    }

  /* get a copy of the sequence number before it might change */
  sequence = rm->snd_nxt;

  /* if we require the segment to be acknowledged, keep a copy of it */
  if(ack != 0)
    {
      if((msg = malloc(sizeof(client_message_t))) == NULL)
	{
	  printerror(__func__, "could not malloc message");
	  goto err;
	}
      msg->data = NULL;
      if((msg->data = memdup(ptr, len)) == NULL)
	{
	  printerror(__func__, "could not dup data");
	  goto err;
	}
      msg->sequence = sequence;
      msg->channel = channel;
      msg->msglen = len;
      if(slist_tail_push(rm->messages, msg) == NULL)
	{
	  printerror(__func__, "could not push message");
	  goto err;
	}
      msg = NULL;
      rm->snd_nxt++;
    }

  if(rm->mode == REMOTE_MODE_CONNECT)
    {
      scamper_debug(__func__, "not sending in connect mode");
      return 0;
    }

  if(remote_sock_write(rm, ptr, len, sequence, channel) != 0)
    goto err;

  return 0;

 err:
  if(msg != NULL) client_message_free(msg);
  return -1;
}

/*
 * remote_rx_abort
 *
 * we have not received anything in some time from the remote controller.
 * assume the TCP socket got broken.  schedule a reconnect.
 */
static int remote_rx_abort(void *param)
{
  control_remote_t *rm = param;
  return remote_retry(rm, 1);
}

/*
 * remote_tx_ka
 *
 * we have not sent anything in some time to the remote controller.
 * send a keepalive to keep the socket going.
 */
static int remote_tx_ka(void *param)
{
  control_remote_t *rm = param;
  uint8_t buf[1];
  buf[0] = CONTROL_KEEPALIVE;
  if(remote_sock_send(rm, buf, sizeof(buf), 0, 0) != 0)
    return -1;
  scamper_fd_write_unpause(rm->fd);
  return 0;
}

/*
 * remote_tx_ack
 *
 * send an ack for the given sequence number
 */
static int remote_tx_ack(control_remote_t *rm, uint32_t sequence)
{
  uint8_t buf[1+4];
  buf[0] = CONTROL_ACK;
  bytes_htonl(buf+1, sequence);
  if(remote_sock_send(rm, buf, sizeof(buf), 0, 0) != 0)
    return -1;
  scamper_fd_write_unpause(rm->fd);
  return 0;
}

/*
 * remote_event_queue
 *
 * set the appropriate event handler
 */
static int remote_event_queue(control_remote_t *rm)
{
#ifdef HAVE_OPENSSL
  if(rm->ssl != NULL && rm->ssl_mode != SSL_MODE_ESTABLISHED)
    {
      scamper_queue_event_update_cb(rm->sq, remote_rx_abort, rm);
      scamper_queue_event_update_time(rm->sq, &rm->rx_abort);
      return 0;
    }
#endif

  if(timeval_cmp(&rm->tx_ka, &rm->rx_abort) <= 0)
    {
      scamper_queue_event_update_cb(rm->sq, remote_tx_ka, rm);
      scamper_queue_event_update_time(rm->sq, &rm->tx_ka);
    }
  else
    {
      scamper_queue_event_update_cb(rm->sq, remote_rx_abort, rm);
      scamper_queue_event_update_time(rm->sq, &rm->rx_abort);
    }
  return 0;
}

static client_t *remote_channel_find(control_remote_t *rem, uint32_t id)
{
  dlist_node_t *dn;
  client_t *client;

  for(dn=dlist_head_node(rem->list); dn != NULL; dn=dlist_node_next(dn))
    {
      client = dlist_node_item(dn);
      assert(client->type == CLIENT_TYPE_CHANNEL);
      if(client->un.chan.id == id)
	return client;
    }

  return NULL;
}

static int remote_read_control_master_id(control_remote_t *rm,
					 const uint8_t *buf, size_t len)
{
  uint8_t id_len;
  uint8_t off;

  if(rm->alias != NULL)
    {
      free(rm->alias);
      rm->alias = NULL;
    }

  if(len < 1)
    {
      printerror_msg(__func__, "len %d", (int)len);
      return -1;
    }

  if((id_len = buf[0]) == 0)
    {
      printerror_msg(__func__, "id_len zero");
      return -1;
    }
  buf++; len--;

  /* ensure the message could contain the specified number of bytes */
  if(len < id_len)
    {
      printerror_msg(__func__, "len %d < id_len %u", (int)len, id_len);
      return -1;
    }

  off = 0;
  while(off < id_len-1 && off < len)
    {
      if(isprint(buf[off++]) == 0)
	{
	  printerror_msg(__func__, "id contains non-printable character");
	  return -1;
	}
    }
  if(buf[id_len-1] != '\0')
    {
      printerror_msg(__func__, "id not null terminated");
      return -1;
    }

  if((rm->alias = memdup(buf, id_len)) == NULL)
    {
      printerror(__func__, "could not memdup alias");
      return -1;
    }
  scamper_debug(__func__, "remote alias: %s", rm->alias);
  rm->resume = 1;
  rm->mode = REMOTE_MODE_GO;
  return 0;
}

static int remote_read_control_channel_new(control_remote_t *rm,
					   const uint8_t *buf, size_t len)
{
  scamper_source_params_t ssp;
  scamper_file_t *sf;
  client_t *client = NULL;
  char listname[512];
  uint32_t channel;

  if(len != 4)
    {
      printerror_msg(__func__, "length %d != 4", (int)len);
      return -1;
    }
  channel = bytes_ntohl(buf);

  snprintf(listname,sizeof(listname), "%s_%u", rm->alias, rm->num++);

  if((client = client_alloc(CLIENT_TYPE_CHANNEL)) == NULL ||
     (client->sof_objs = slist_alloc()) == NULL ||
     (client->sof = scamper_outfile_opennull(listname, "warts")) == NULL)
    {
      printerror(__func__, "could not alloc client");
      goto err;
    }
  client->un.chan.id = channel;
  client->un.chan.rem = rm;
  client->mode = CLIENT_MODE_ATTACHED;

  sf = scamper_outfile_getfile(client->sof);
  scamper_file_setwritefunc(sf, client, client_data_send);

  memset(&ssp, 0, sizeof(ssp));
  ssp.list_id    = 0;
  ssp.cycle_id   = 1;
  ssp.priority   = 1;
  ssp.name       = (char *)listname;
  ssp.sof        = client->sof;
  if((client->source = scamper_source_control_alloc(&ssp, client_signalmore,
						    client_tostr,
						    client)) == NULL)
    {
      printerror(__func__, "could not allocate source '%s'", listname);
      goto err;
    }

  /* put the source into rotation */
  if(scamper_sources_add(client->source) != 0)
    {
      printerror(__func__, "could not add source '%s' to rotation", listname);
      goto err;
    }

  if((client->un.chan.node = dlist_tail_push(rm->list, client)) == NULL)
    {
      printerror(__func__, "could not add client to remote list");
      goto err;
    }
  client->un.chan.rem = rm;

  return 0;

 err:
  if(client != NULL) client_free(client);
  return -1;
}

/*
 * remote_read_control_channel_fin
 *
 *
 */
static int remote_read_control_channel_fin(control_remote_t *rm,
					   const uint8_t *buf, size_t len)
{
  client_t *client;
  uint32_t channel;

  if(len != 4)
    {
      printerror_msg(__func__, "malformed fin: %u", (unsigned int)len);
      return -1;
    }

  channel = bytes_ntohl(buf);
  scamper_debug(__func__, "channel %u", channel);
  if((client = remote_channel_find(rm, channel)) == NULL)
    {
      printerror_msg(__func__, "could not find channel %u", channel);
      return -1;
    }
  scamper_source_control_finish(client->source);
  scamper_source_abandon(client->source);

  return 0;
}

static int remote_read_control_keepalive(control_remote_t *rm,
					 const uint8_t *buf, size_t len)
{
  if(len != 0)
    {
      printerror_msg(__func__, "len %d != 0", (int)len);
      return -1;
    }
  return 0;
}

static int remote_read_control_ack(control_remote_t *rm,
				   const uint8_t *buf, size_t len)
{
  uint32_t sequence;
  client_message_t *msg;

  if(len != 4)
    {
      printerror_msg(__func__, "malformed acknowledgement: %u", (uint32_t)len);
      return -1;
    }

  sequence = bytes_ntohl(buf);
  if((msg = slist_head_item(rm->messages)) == NULL)
    {
      printerror_msg(__func__, "nothing to ack: %u", sequence);
      return -1;
    }
  if(msg->sequence != sequence)
    {
      printerror_msg(__func__, "expected %u got %u", sequence, msg->sequence);
      return -1;
    }

  slist_head_pop(rm->messages);
  client_message_free(msg);
  return 0;
}

static int remote_read_control_master_rej(control_remote_t *rm,
					  const uint8_t *buf, size_t len)
{
  uint32_t u32;

  scamper_debug(__func__, "rejected");

  /* can't resume */
  rm->resume = 0;

  /*
   * generate a new magic value in case remote controller is holding on
   * to the magic value used by the prior instance
   */
  random_u32(&u32); memcpy(rm->magic+0, &u32, 4);
  random_u32(&u32); memcpy(rm->magic+4, &u32, 4);
  return -1;
}

static int remote_read_control_master_ok(control_remote_t *rm,
					 const uint8_t *buf, size_t len)
{
  client_message_t *msg;
  slist_node_t *sn;
  uint32_t rcv_nxt;

  if(len != 4)
    {
      printerror_msg(__func__, "malformed ok: %u", (uint32_t)len);
      return -1;
    }

  rcv_nxt = bytes_ntohl(buf);
  while((msg = slist_head_item(rm->messages)) != NULL)
    {
      if(SEQ_LT(msg->sequence, rcv_nxt) == 0)
	break;
      msg = slist_head_pop(rm->messages);
      client_message_free(msg);
    }

  rm->mode = REMOTE_MODE_GO;
  for(sn=slist_head_node(rm->messages); sn != NULL; sn=slist_node_next(sn))
    {
      msg = slist_node_item(sn);
      if(remote_sock_write(rm, msg->data, msg->msglen, msg->sequence,
			   msg->channel) != 0)
	return -1;
    }

  scamper_fd_write_unpause(rm->fd);
  return 0;
}

static int remote_read_control(control_remote_t *rm)
{
  uint32_t seq;
  uint16_t msglen;
  uint8_t type, *buf;

  seq = bytes_ntohl(rm->buf);
  msglen = bytes_ntohs(rm->buf+8);
  buf = rm->buf + REMOTE_HDRLEN;

  if(msglen < 1)
    {
      printerror_msg(__func__, "msglen %u < 1", msglen);
      return -1;
    }

  type = buf[0];
  buf++; msglen--;

  if(rm->mode == REMOTE_MODE_CONNECT)
    {
      /* we expect sequence zero. no acks for any of these messages. */
      if(seq != 0)
	{
	  printerror_msg(__func__, "expected sequence zero in mode connect");
	  return -1;
	}
      switch(type)
	{
	case CONTROL_MASTER_ID:
	  return remote_read_control_master_id(rm, buf, msglen);
	case CONTROL_MASTER_OK:
	  return remote_read_control_master_ok(rm, buf, msglen);
	case CONTROL_MASTER_REJ:
	  return remote_read_control_master_rej(rm, buf, msglen);
	}
    }
  else if(rm->mode == REMOTE_MODE_GO)
    {
      /* check the sequence number is what we expect */
      if(seq != rm->rcv_nxt)
	{
	  printerror_msg(__func__, "got seq %u expected %u", seq, rm->rcv_nxt);
	  return -1;
	}

      /* send acks for channel new and fin messages */
      if(type == CONTROL_CHANNEL_NEW || type == CONTROL_CHANNEL_FIN)
	{
	  if(remote_tx_ack(rm, seq) != 0)
	    return -1;
	  rm->rcv_nxt++;
	}

      switch(type)
	{
	case CONTROL_CHANNEL_NEW:
	  return remote_read_control_channel_new(rm, buf, msglen);
	case CONTROL_CHANNEL_FIN:
	  return remote_read_control_channel_fin(rm, buf, msglen);
	case CONTROL_KEEPALIVE:
	  return remote_read_control_keepalive(rm, buf, msglen);
	case CONTROL_ACK:
	  return remote_read_control_ack(rm, buf, msglen);
	}
    }

  printerror_msg(__func__, "unhandled type %u in mode %u", type, rm->mode);
  return -1;
}

/*
 * remote_read_payload
 *
 * process a payload from reading the remote control socket.  the
 * payload has gone through OpenSSL before reaching here, if used.
 */
static int remote_read_payload(control_remote_t *rm,
			       const uint8_t *buf, size_t len)
{
  client_t *client;
  uint32_t channel_id, seq;
  size_t off = 0, msglen, x, y;

  while(off < len)
    {
      /* to start with, ensure that we have a complete header */
      while(rm->bufoff < REMOTE_HDRLEN && off < len)
	rm->buf[rm->bufoff++] = buf[off++];
      if(off == len)
	return 0;

      /* figure out how large the message is supposed to be */
      seq = bytes_ntohl(rm->buf);
      channel_id = bytes_ntohl(rm->buf+4);
      msglen = bytes_ntohs(rm->buf+8);

      /* figure out how to build the message */
      x = msglen - (rm->bufoff - REMOTE_HDRLEN);
      y = len - off;
      if(y < x)
	{
	  /* if we cannot complete the message, buffer what we have */
	  memcpy(rm->buf + rm->bufoff, buf+off, y);
	  rm->bufoff += y;
	  return 0;
	}

      /* we now have a complete message */
      memcpy(rm->buf + rm->bufoff, buf+off, x);
      off += x;

      /* reset the buf offset for the next message */
      rm->bufoff = 0;

      /* if the message is a control message */
      if(channel_id == 0)
	{
	  if(remote_read_control(rm) != 0)
	    return -1;
	  continue;
	}

      if(seq != rm->rcv_nxt)
	{
	  printerror_msg(__func__, "got seq %u expected %u", seq, rm->rcv_nxt);
	  return -1;
	}

      /* send an ack for this message */
      if(remote_tx_ack(rm, seq) != 0)
	return -1;
      rm->rcv_nxt++;
      if((client = remote_channel_find(rm, channel_id)) == NULL)
	{
	  printerror_msg(__func__, "could not find channel %u", channel_id);
	  return -1;
	}
      scamper_linepoll_handle(client->lp, rm->buf + REMOTE_HDRLEN, msglen);
    }

  return 0;
}

/*
 * remote_send_master
 *
 */
static int remote_send_master(control_remote_t *rm)
{
  const char *monitorname = scamper_option_monitorname_get();
  size_t off, len, tmp;
  uint8_t buf[512];

  if(monitorname != NULL)
    {
      if(strlen(monitorname) > 254)
	{
	  printerror_msg(__func__, "monitorname too long");
	  return -1;
	}
      off = 0;
      while(monitorname[off] != '\0')
	{
	  if(monitorname[off] != '.' && monitorname[off] != '-' &&
	     isalnum((unsigned char)monitorname[off]) == 0)
	    {
	      printerror_msg(__func__, "monitorname contains invalid char");
	      return -1;
	    }
	  off++;
	}
    }

  off = 0;
  len = 1 + 1 + 8 + 1 + (monitorname != NULL ? strlen(monitorname) + 1 : 0);
  buf[off++] = CONTROL_MASTER_NEW;
  buf[off++] = 8; /* length of magic */
  memcpy(buf+off, rm->magic, 8); off += 8;
  if(monitorname != NULL)
    {
      tmp = strlen(monitorname) + 1;
      buf[off++] = (uint8_t)tmp; /* we checked strlen(monitorname) <= 254 */
      memcpy(buf+off, monitorname, tmp);
    }
  else
    {
      buf[off++] = 0;
    }

  return remote_sock_write(rm, buf, len, 0, 0);
}

/*
 * remote_send_resume
 *
 *
 */
static int remote_send_resume(control_remote_t *rm)
{
  uint8_t buf[1+1+8+4+4+4];
  client_message_t *msg;
  size_t off;

  off = 0;
  buf[off++] = CONTROL_MASTER_RES;
  buf[off++] = 8;
  memcpy(buf+off, rm->magic, 8); off += 8;
  bytes_htonl(buf+off, rm->rcv_nxt); off += 4;
  if(slist_count(rm->messages) > 0)
    {
      msg = slist_head_item(rm->messages);
      bytes_htonl(buf+off, msg->sequence);
    }
  else bytes_htonl(buf+off, rm->snd_nxt);
  off += 4;
  bytes_htonl(buf+off, rm->snd_nxt); off += 4;

  return remote_sock_write(rm, buf, off, 0, 0);
}

/*
 * remote_read_sock
 *
 * handle a read event on remote control socket.  this function steps
 * through TLS negotiation and decryption.
 *
 * returns zero if the socket was disconnected, 1 if there was no error,
 * and -1 on error.
 */
static int remote_read_sock(control_remote_t *rm)
{
  ssize_t rrc;
  uint8_t buf[4096];

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

#ifdef HAVE_OPENSSL
  int ecode, ret;
#endif

  fd = scamper_fd_fd_get(rm->fd);
  if((rrc = recv(fd, buf, sizeof(buf), 0)) < 0)
    {
      if(errno == EAGAIN || errno == EINTR)
	return 1;
      printerror(__func__, "could not recv from %d", fd);
      return -1;
    }

  if(rrc == 0)
    {
      scamper_debug(__func__, "disconnected fd %d", fd);
      return 0;
    }

#ifdef HAVE_OPENSSL
  if(rm->ssl != NULL)
    {
      assert(rm->ssl_mode == SSL_MODE_HANDSHAKE ||
	     rm->ssl_mode == SSL_MODE_ESTABLISHED);

      BIO_write(rm->ssl_rbio, buf, rrc);
      if(rm->ssl_mode == SSL_MODE_HANDSHAKE)
	{
	  if(SSL_is_init_finished(rm->ssl) != 0)
	    {
	      if(tls_is_valid_cert(rm->ssl, rm->server_name) == 0)
		return -1;
	      rm->ssl_mode = SSL_MODE_ESTABLISHED;
	      return 1;
	    }

	  ERR_clear_error();
	  if((ret = SSL_do_handshake(rm->ssl)) > 0)
	    {
	      if(tls_is_valid_cert(rm->ssl, rm->server_name) == 0)
		return -1;
	      rm->ssl_mode = SSL_MODE_ESTABLISHED;
	      return 1;
	    }
	}
      else
	{
	  ERR_clear_error();
	  while((ret = SSL_read(rm->ssl, buf, sizeof(buf))) > 0)
	    {
	      if(remote_read_payload(rm, buf, (size_t)ret) != 0)
		return -1;
	    }
	}

      if((ecode = SSL_get_error(rm->ssl, ret)) == SSL_ERROR_WANT_READ)
	{
	  if(remote_sock_ssl_want_read(rm) < 0)
	    return -1;
	}
      else if(ecode != SSL_ERROR_WANT_WRITE)
	{
	  printerror_ssl(__func__, "mode %s",
			 rm->ssl_mode == SSL_MODE_HANDSHAKE ?
			 "handshake" : "estab");
	  return -1;
	}

      return 1;
    }
#endif

  if(remote_read_payload(rm, buf, (size_t)rrc) != 0)
    return -1;
  return 1;
}

/*
 * remote_read
 *
 * this function handles read events on the master control socket back
 * to the remote controller.  it does not handle regular client socket
 * traffic.
 *
 */
#ifndef _WIN32 /* SOCKET vs int on windows */
static void remote_read(int fd, void *param)
#else
static void remote_read(SOCKET fd, void *param)
#endif
{
  control_remote_t *rm = param;
  struct timeval tv;
  int rc;

#ifdef HAVE_OPENSSL
  int enter_mode = rm->ssl_mode;
#endif

  assert(scamper_fd_fd_get(rm->fd) == fd);

  if((rc = remote_read_sock(rm)) < 0)
    goto retry;

  if(rc == 0)
    {
      scamper_debug(__func__, "disconnected fd %d", fd);
      goto retry;
    }

  gettimeofday_wrap(&tv);
  timeval_add_s(&rm->rx_abort, &tv, 60);
  remote_event_queue(rm);

#ifdef HAVE_OPENSSL
  /* when TLS has completed, we need to enter into the attach mode */
  if(rm->ssl != NULL && enter_mode == SSL_MODE_HANDSHAKE &&
     rm->ssl_mode == SSL_MODE_ESTABLISHED)
    {
      if(rm->resume != 0)
	{
	  if(remote_send_resume(rm) != 0)
	    goto retry;
	}
      else if(remote_send_master(rm) != 0)
	goto retry;
    }
#endif

  return;

 retry:
  remote_retry(rm, 0);
  return;
}

static int client_channel_send(client_t *client, void *buf, size_t len)
{
  assert(client->type == CLIENT_TYPE_CHANNEL);
  if(remote_sock_send(client->un.chan.rem, buf, len, client->un.chan.id, 1) < 0)
    return -1;
  return 0;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
static void remote_write(int fd, void *param)
#else
static void remote_write(SOCKET fd, void *param)
#endif
{
  control_remote_t *rm = param;
  struct timeval tv;
  dlist_node_t *dn;
  client_t *client;
  uint8_t buf[1+4];

  /*
   * if there is nothing buffered in the writebuf, then put some more
   * in there.
   */
  if(scamper_writebuf_gtzero(rm->wb) == 0)
    {
      /* if there are no clients, then we won't have anything to send */
      if(rm->mode == REMOTE_MODE_CONNECT ||
	 dlist_head_node(rm->list) == NULL)
	{
	  scamper_fd_write_pause(rm->fd);
	  return;
	}

      /*
       * take a pass through the clients, getting something from each
       * connected channel, if available
       */
      dn = dlist_head_node(rm->list);
      while(dn != NULL)
	{
	  client = dlist_node_item(dn);
	  dn = dlist_node_next(dn);

	  if(client->mode == CLIENT_MODE_FLUSH && client_isdone(client) != 0)
	    {
	      /* construct a channel FIN message */
	      buf[0] = CONTROL_CHANNEL_FIN;
	      bytes_htonl(buf+1, client->un.chan.id);

	      /* don't need the client anymore */
	      client_free(client);

	      /* send the FIN */
	      if(remote_sock_send(rm, buf, sizeof(buf), 0, 1) != 0)
		goto err;

	      continue;
	    }

	  if(client_write_do(client, client_channel_send) != 0)
	    goto err;
	}

      /* if there is still nothing in the writebuf, then pause for now */
      if(scamper_writebuf_gtzero(rm->wb) == 0)
	{
	  scamper_fd_write_pause(rm->fd);
	  return;
	}
    }

  if(scamper_writebuf_write(fd, rm->wb) != 0)
    goto err;
  gettimeofday_wrap(&tv);
  timeval_add_s(&rm->tx_ka, &tv, 30);

  remote_event_queue(rm);
  return;

 err:
  remote_retry(rm, 0);
  return;
}

/*
 * remote_socket
 *
 */
#ifndef _WIN32 /* SOCKET vs int on windows */
static int remote_socket(control_remote_t *rm, int fd)
#else
static int remote_socket(control_remote_t *rm, SOCKET fd)
#endif
{
  if((rm->wb = scamper_writebuf_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc wb");
      goto err;
    }

  if(setsockopt_int(fd, IPPROTO_TCP, TCP_NODELAY, 1) != 0)
    {
      printerror(__func__, "could not set TCP_NODELAY");
      goto err;
    }

#ifdef O_NONBLOCK
  if(fcntl_set(fd, O_NONBLOCK) != 0)
    {
      printerror(__func__, "could not set O_NONBLOCK");
      goto err;
    }
#endif

  if((rm->fd = scamper_fd_private(fd, rm, remote_read, remote_write)) == NULL)
    {
      printerror(__func__, "could not add fd");
      goto err;
    }

  return 0;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  return -1;
}

/*
 * remote_host_cb
 *
 */
static void remote_host_cb(control_remote_t *rm, scamper_addr_t **a, int c)
{
  struct timeval tv;
  struct sockaddr *sa;
  struct sockaddr_in sin;
  int i;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd = -1;
#else
  SOCKET fd = INVALID_SOCKET;
#endif

  for(i=0; i<c; i++)
    {
      sa = (struct sockaddr *)&sin;
      sockaddr_compose(sa, AF_INET, a[i]->addr, rm->server_port);
      fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      if(socket_isinvalid(fd))
	continue;
      if(connect(fd, sa, sockaddr_len(sa)) != 0)
	{
	  socket_close(fd);
	  fd = socket_invalid();
	  continue;
	}
      break;
    }

  if(socket_isinvalid(fd))
    {
      printerror(__func__, "could not connect to %s:%d",
		 rm->server_name, rm->server_port);
      goto retry;
    }

  if(remote_socket(rm, fd) != 0)
    goto retry;

  if(rm->server_ssl == 0)
    {
      if(rm->resume != 0)
	remote_send_resume(rm);
      else
	remote_send_master(rm);
      scamper_fd_write_unpause(rm->fd);
    }
  else
    {
#ifdef HAVE_OPENSSL
      if(remote_sock_ssl_init(rm) != 0)
	goto retry;
#endif
    }

  gettimeofday_wrap(&tv);
  timeval_add_s(&rm->rx_abort, &tv, 60);
  timeval_add_s(&rm->tx_ka, &tv, 30);
  remote_event_queue(rm);

  return;

 retry:
  remote_retry(rm, 0);
  return;
}

/*
 * remote_connect
 *
 * this function is tasked with establishing a connection to a remote
 * control server.  it tries to negotiate SSL, if that is requested.
 * if the connect fails, the code schedules a retry for a later time.
 *
 */
static int remote_connect(control_remote_t *rm)
{
  struct sockaddr_storage sas;
  struct sockaddr *sa = (struct sockaddr *)&sas;
  struct timeval tv;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd = -1;
#else
  SOCKET fd = INVALID_SOCKET;
#endif

  /*
   * if we cannot convert the server name to an IP address, then assume
   * it is a hostname and invoke the name resolution code
   */
  if(sockaddr_compose_str(sa, AF_UNSPEC, rm->server_name, rm->server_port) != 0)
    {
#ifndef DISABLE_SCAMPER_HOST
      if(scamper_do_host_do_a(rm->server_name, rm,
			      (scamper_host_do_a_cb_t)remote_host_cb) == NULL)
	remote_retry(rm, 0);
      return 0;
#else
      printerror_msg(__func__, "scamper not built with host support");
      goto err;
#endif
    }

  fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
  if(socket_isinvalid(fd) == 0 && connect(fd, sa, sockaddr_len(sa)) != 0)
    {
      socket_close(fd);
      fd = socket_invalid();
    }

  if(socket_isinvalid(fd))
    {
      printerror(__func__, "could not connect to %s:%d",
		 rm->server_name, rm->server_port);
      remote_retry(rm, 0);
      return 0;
    }

  /* by definition, we can't do TLS to an IP address */
  rm->server_ssl = 0;

  if(remote_socket(rm, fd) != 0)
    {
      remote_retry(rm, 0);
      goto err;
    }

  if(rm->resume != 0)
    remote_send_resume(rm);
  else
    remote_send_master(rm);
  scamper_fd_write_unpause(rm->fd);

  gettimeofday_wrap(&tv);
  timeval_add_s(&rm->rx_abort, &tv, 60);
  timeval_add_s(&rm->tx_ka, &tv, 30);
  remote_event_queue(rm);

  return 0;

 err:
  return -1;
}

static int remote_reconnect(void *param)
{
  control_remote_t *rm = param;
  return remote_connect(rm);
}

#ifndef _WIN32 /* SOCKET vs int on windows */
static void control_accept(int fd, void *param)
#else
static void control_accept(SOCKET fd, void *param)
#endif
{
  struct sockaddr_storage ss;
  socklen_t socklen;
  client_t *c = NULL;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int s;
#else
  SOCKET s;
#endif

  /* accept the new client */
  socklen = sizeof(ss);
  s = accept(fd, (struct sockaddr *)&ss, &socklen);
  if(socket_isinvalid(s))
    {
      printerror(__func__, "could not accept");
      return;
    }

  scamper_debug(__func__, "fd %d", s);

  /* make the socket non-blocking, so a read or write will not hang scamper */
#ifdef HAVE_FCNTL
  if(fcntl_set(s, O_NONBLOCK) == -1)
    {
      printerror(__func__, "could not set NONBLOCK");
      goto err;
    }
#endif

  /* allocate the structure that holds the socket/client together */
  if((c = client_alloc(CLIENT_TYPE_SOCKET)) == NULL ||
     (c->un.sock.wb = scamper_writebuf_alloc()) == NULL ||
     (c->un.sock.sa = memdup(&ss, socklen)) == NULL ||
     (c->un.sock.fdn = scamper_fd_private(s, c,
				  (scamper_fd_cb_t)client_read,
				  (scamper_fd_cb_t)client_write)) == NULL)
    {
      printerror(__func__, "could not alloc client");
      goto err;
    }

  scamper_fd_write_pause(c->un.sock.fdn);
  c->mode = CLIENT_MODE_INTERACTIVE;
  return;

 err:
  if(socket_isvalid(s))
    socket_close(s);
  if(c != NULL) client_free(c);
  return;
}

int scamper_control_add_remote(const char *name, uint16_t port, int ssl)
{
  control_remote_t *rm = NULL;
  uint32_t u32;

  if((remote_list == NULL && (remote_list = dlist_alloc()) == NULL) ||
     (rm = malloc_zero(sizeof(control_remote_t))) == NULL ||
     (rm->list = dlist_alloc()) == NULL ||
     (rm->messages = slist_alloc()) == NULL ||
     (rm->sq = scamper_queue_alloc(NULL)) == NULL ||
     (rm->server_name = strdup(name)) == NULL ||
     (rm->node = dlist_tail_push(remote_list, rm)) == NULL)
    goto err;
  random_u32(&u32); memcpy(rm->magic+0, &u32, 4);
  random_u32(&u32); memcpy(rm->magic+4, &u32, 4);
  rm->server_port = port;
  rm->server_ssl = ssl;

  return remote_connect(rm);

 err:
  if(rm != NULL) remote_free(rm, REMOTE_FREE_ALL);
  return -1;
}

int scamper_control_add_unix(const char *file)
{
#ifdef HAVE_SOCKADDR_UN
  int fd;

  if((fd = scamper_priv_unix_bind(file)) == -1)
    {
      printerror(__func__, "could not open unix socket");
      goto err;
    }

  if((ctrl_unix = malloc_zero(sizeof(control_unix_t))) == NULL ||
     (ctrl_unix->fd = scamper_fd_private(fd,NULL,control_accept,NULL))==NULL ||
     (ctrl_unix->name = strdup(file)) == NULL)
    {
      printerror(__func__, "could not alloc ctrl_unix");
      goto err;
    }

  return 0;

 err:
  if(fd != -1 && (ctrl_unix == NULL || ctrl_unix->fd == NULL))
    close(fd);

#endif
  return -1;
}

int scamper_control_add_inet(const char *ip, uint16_t port)
{
  struct sockaddr_storage sas;
  struct sockaddr *sa = (struct sockaddr *)&sas;
  struct in_addr in;
  int af = AF_INET;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd = -1;
#else
  SOCKET fd = INVALID_SOCKET;
#endif

  if(ip != NULL)
    {
      if(sockaddr_compose_str(sa, AF_UNSPEC, ip, port) != 0)
	{
	  printerror(__func__, "could not compose sockaddr from %s:%d",
		     ip, port);
	  goto err;
	}
      af = sa->sa_family;
    }
  else
    {
      /* bind the socket to loopback on the specified port */
      in.s_addr = htonl(INADDR_LOOPBACK);
      sockaddr_compose(sa, AF_INET, &in, port);
    }

  /* open the TCP socket we are going to listen on */
  fd = socket(af, SOCK_STREAM, IPPROTO_TCP);
  if(socket_isinvalid(fd))
    {
      printerror(__func__, "could not create socket");
      goto err;
    }

  if(setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1) != 0)
    {
      printerror(__func__, "could not set SO_REUSEADDR");
      goto err;
    }

  if(setsockopt_int(fd, IPPROTO_TCP, TCP_NODELAY, 1) != 0)
    {
      printerror(__func__, "could not set TCP_NODELAY");
      goto err;
    }

  if(bind(fd, sa, sockaddr_len(sa)) != 0)
    {
      if(ip == NULL)
	printerror(__func__, "could not bind to port %d", port);
      else
	printerror(__func__, "could not bind to %s:%d", ip, port);
      goto err;
    }

  /* tell the system we want to listen for new clients on this socket */
  if(listen(fd, -1) != 0)
    {
      printerror(__func__, "could not listen");
      goto err;
    }

  if((ctrl_inet = malloc_zero(sizeof(control_inet_t))) == NULL ||
     (ctrl_inet->fd = scamper_fd_private(fd,NULL,control_accept,NULL)) == NULL)
    {
      printerror(__func__, "could not malloc control_inet_t");
      return -1;
    }

  return 0;

 err:
  if(socket_isvalid(fd) && (ctrl_inet == NULL || ctrl_inet->fd == NULL))
    socket_close(fd);
  return -1;
}

int scamper_control_init(void)
{
  return 0;
}

/*
 * scamper_control_cleanup
 *
 * go through and free all the clients that are connected.
 * write anything left in the writebuf to the clients (non-blocking) and
 * then close the socket.
 */
void scamper_control_cleanup(void)
{
  control_remote_t *rm;
  client_t *client;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

  if(client_list != NULL)
    {
      while((client = dlist_head_pop(client_list)) != NULL)
	{
	  client->node = NULL;
	  if(client->type == CLIENT_TYPE_SOCKET)
	    scamper_writebuf_write(scamper_fd_fd_get(client->un.sock.fdn),
				   client->un.sock.wb);
	  client_free(client);
	}
      dlist_free(client_list);
      client_list = NULL;
    }

  /* stop monitoring the control socket for new connections */
  if(ctrl_unix != NULL)
    {
      if(ctrl_unix->fd != NULL)
	{
	  fd = scamper_fd_fd_get(ctrl_unix->fd);
	  if(socket_isvalid(fd))
	    {
	      socket_close(fd);

#ifdef HAVE_SOCKADDR_UN
	      if(ctrl_unix->name != NULL)
		scamper_priv_unlink(ctrl_unix->name);
#endif
	    }
	  scamper_fd_free(ctrl_unix->fd);
	  ctrl_unix->fd = NULL;
	}

      if(ctrl_unix->name != NULL)
	{
	  free(ctrl_unix->name);
	  ctrl_unix->name = NULL;
	}
      free(ctrl_unix);
      ctrl_unix = NULL;
    }

  if(ctrl_inet != NULL)
    {
      if(ctrl_inet->fd != NULL)
	{
	  fd = scamper_fd_fd_get(ctrl_inet->fd);
	  if(socket_isvalid(fd))
	    socket_close(fd);
	  scamper_fd_free(ctrl_inet->fd);
	  ctrl_inet->fd = NULL;
	}
      free(ctrl_inet);
      ctrl_inet = NULL;
    }

  if(remote_list != NULL)
    {
      while((rm = dlist_head_pop(remote_list)) != NULL)
	{
	  rm->node = NULL;
	  remote_free(rm, REMOTE_FREE_ALL);
	}
      dlist_free(remote_list);
      remote_list = NULL;
    }

  return;
}
