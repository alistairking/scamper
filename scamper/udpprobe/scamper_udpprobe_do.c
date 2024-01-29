/*
 * scamper_udpprobe_do.c
 *
 * $Id: scamper_udpprobe_do.c,v 1.3 2023/11/23 00:55:46 mjl Exp $
 *
 * Copyright (C) 2023 The Regents of the University of California
 *
 * Authors: Matthew Luckie
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
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_task.h"
#include "scamper_getsrc.h"
#include "scamper_fds.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_debug.h"
#include "scamper_udpprobe.h"
#include "scamper_udpprobe_int.h"
#include "scamper_udpprobe_do.h"
#include "utils.h"
#include "mjl_list.h"

static scamper_task_funcs_t udpprobe_funcs;

typedef struct udpprobe_state
{
  scamper_fd_t *fdn;
  slist_t      *urs;
} udpprobe_state_t;

static scamper_udpprobe_t *udpprobe_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static udpprobe_state_t *udpprobe_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static void udpprobe_stop(scamper_task_t *task, uint8_t reason)
{
  scamper_udpprobe_t *up = udpprobe_getdata(task);
  udpprobe_state_t *state = udpprobe_getstate(task);
  scamper_udpprobe_reply_t *ur;
  int i, c;

  up->stop = reason;

  if(state != NULL && state->urs != NULL)
    {
      i = 0;
      c = slist_count(state->urs);
      up->replies = malloc_zero(sizeof(scamper_udpprobe_reply_t *) * c);
      if(up->replies != NULL)
	while((ur = slist_head_pop(state->urs)) != NULL)
	  up->replies[i++] = ur;
      up->replyc = i;
    }

  scamper_task_queue_done(task, 0);
  return;
}

static void udpprobe_state_free(udpprobe_state_t *state)
{
#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

  if(state->urs != NULL)
    slist_free_cb(state->urs, (slist_free_t)scamper_udpprobe_reply_free);
  if(state->fdn != NULL)
    {
      fd = scamper_fd_fd_get(state->fdn);
      if(socket_isvalid(fd))
	socket_close(fd);
      scamper_fd_free(state->fdn);
    }
  free(state);
  return;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
static void udpprobe_read(int fd, void *param)
#else
static void udpprobe_read(SOCKET fd, void *param)
#endif
{
  scamper_task_t *task = param;
  scamper_udpprobe_t *up = udpprobe_getdata(task);
  udpprobe_state_t *state = udpprobe_getstate(task);
  scamper_udpprobe_reply_t *ur;
  struct sockaddr_storage ss;
  socklen_t sl = sizeof(ss);
  uint8_t buf[8192];
  struct timeval tv;
  ssize_t rrc;
  void *addr;

  if((rrc=recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&ss, &sl)) <= 0)
    return;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(up->dst))
    addr = &((struct sockaddr_in *)&ss)->sin_addr;
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(up->dst))
    addr = &((struct sockaddr_in6 *)&ss)->sin6_addr;
  else
    return;

  if(scamper_addr_raw_cmp(up->dst, addr) != 0)
    return;

  gettimeofday_wrap(&tv);
  if((ur = scamper_udpprobe_reply_alloc()) == NULL ||
     (ur->data = memdup(buf, rrc)) == NULL)
    goto err;
  timeval_cpy(&ur->tv, &tv);
  ur->len = rrc;

  if(slist_tail_push(state->urs, ur) == NULL)
    goto err;

  if(SCAMPER_UDPPROBE_FLAG_IS_EXITFIRST(up))
    udpprobe_stop(task, SCAMPER_UDPPROBE_STOP_DONE);

  return;

 err:
  if(ur != NULL) scamper_udpprobe_reply_free(ur);
  return;
}

static udpprobe_state_t *udpprobe_state_alloc(scamper_task_t *task)
{
  scamper_udpprobe_t *up = udpprobe_getdata(task);
  udpprobe_state_t *state = NULL;
  struct sockaddr_storage ss;
  socklen_t sl;
  int af;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd = -1;
#else
  SOCKET fd = INVALID_SOCKET;
#endif

  if((state = malloc_zero(sizeof(udpprobe_state_t))) == NULL ||
     (state->urs = slist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc state");
      goto err;
    }

  af = scamper_addr_af(up->dst);
  fd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
  if(socket_isinvalid(fd))
    {
      printerror(__func__, "could not allocate socket");
      goto err;
    }

  /* bind to get a port assigned */
  if(af == AF_INET)
    {
      sockaddr_compose((struct sockaddr *)&ss, AF_INET, NULL, 0);
      sl = sizeof(struct sockaddr_in);
    }
  else if(af == AF_INET6)
    {
      sockaddr_compose((struct sockaddr *)&ss, AF_INET6, NULL, 0);
      sl = sizeof(struct sockaddr_in6);
    }
  else goto err;
  if(bind(fd, (struct sockaddr *)&ss, sl) != 0)
    {
      printerror(__func__, "could not bind socket");
      goto err;
    }

  /* get the source port for this probe */
  if(socket_sport(fd, &up->sport) != 0)
    {
      printerror(__func__, "could not get sport");
      goto err;
    }

  if((state->fdn = scamper_fd_private(fd, task, udpprobe_read, NULL)) == NULL)
    {
      scamper_debug(__func__, "could not register fd");
      goto err;
    }

  scamper_task_setstate(task, state);
  return state;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  if(state != NULL) udpprobe_state_free(state);
  return NULL;
}

static void do_udpprobe_probe(scamper_task_t *task)
{
  scamper_udpprobe_t *up = udpprobe_getdata(task);
  udpprobe_state_t *state = udpprobe_getstate(task);
  struct sockaddr_in6 sin6;
  struct sockaddr_in sin;
  struct sockaddr *sa;
  struct timeval finish;
  socklen_t sl;
  int fd;

  assert(state == NULL);

  if(SCAMPER_ADDR_TYPE_IS_IPV4(up->dst))
    {
      sa = (struct sockaddr *)&sin;
      sockaddr_compose(sa, AF_INET, up->dst->addr, up->dport);
      sl = sizeof(sin);
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(up->dst))
    {
      sa = (struct sockaddr *)&sin6;
      sockaddr_compose(sa, AF_INET6, up->dst->addr, up->dport);
      sl = sizeof(sin6);
    }
  else goto err;

  if((state = udpprobe_state_alloc(task)) == NULL)
    goto err;
  fd = scamper_fd_fd_get(state->fdn);

  gettimeofday_wrap(&up->start);
  if(sendto(fd, up->data, up->len, 0, sa, sl) != up->len)
    goto err;
  timeval_add_tv3(&finish, &up->start, &up->wait_timeout);
  scamper_task_queue_wait_tv(task, &finish);

  return;

 err:
  udpprobe_stop(task, SCAMPER_UDPPROBE_STOP_ERROR);
  return;
}

static void do_udpprobe_handle_timeout(scamper_task_t *task)
{
  udpprobe_stop(task, SCAMPER_UDPPROBE_STOP_DONE);
  return;
}

static void do_udpprobe_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_file_write_udpprobe(sf, udpprobe_getdata(task), task);
  return;
}

static void do_udpprobe_halt(scamper_task_t *task)
{
  scamper_udpprobe_t *up = udpprobe_getdata(task);
  up->stop = SCAMPER_UDPPROBE_STOP_HALTED;
  scamper_task_queue_done(task, 0);
  return;
}

static void do_udpprobe_free(scamper_task_t *task)
{
  scamper_udpprobe_t *up = udpprobe_getdata(task);
  udpprobe_state_t *state = udpprobe_getstate(task);

  if(state != NULL)
    udpprobe_state_free(state);
  if(up != NULL)
    scamper_udpprobe_free(up);

  return;
}

void scamper_do_udpprobe_free(void *data)
{
  scamper_udpprobe_free((scamper_udpprobe_t *)data);
  return;
}

scamper_task_t *scamper_do_udpprobe_alloctask(void *data,
					      scamper_list_t *list,
					      scamper_cycle_t *cycle)
{
  scamper_udpprobe_t *up = (scamper_udpprobe_t *)data;
  scamper_task_t *task = NULL;

  /* allocate a task structure and store the trace with it */
  if((task = scamper_task_alloc(up, &udpprobe_funcs)) == NULL)
    goto err;

  if(up->src == NULL && (up->src = scamper_getsrc(up->dst, 0)) == NULL)
    goto err;

  /* associate the list and cycle with the http structure */
  up->list = scamper_list_use(list);
  up->cycle = scamper_cycle_use(cycle);

  return task;

 err:
  if(task != NULL)
    {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
    }
  return NULL;
}

void scamper_do_udpprobe_cleanup(void)
{
  return;
}

int scamper_do_udpprobe_init(void)
{
  udpprobe_funcs.probe          = do_udpprobe_probe;
  udpprobe_funcs.handle_timeout = do_udpprobe_handle_timeout;
  udpprobe_funcs.write          = do_udpprobe_write;
  udpprobe_funcs.task_free      = do_udpprobe_free;
  udpprobe_funcs.halt           = do_udpprobe_halt;

  return 0;
}
