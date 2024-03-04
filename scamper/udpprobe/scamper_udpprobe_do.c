/*
 * scamper_udpprobe_do.c
 *
 * $Id: scamper_udpprobe_do.c,v 1.9 2024/02/27 03:34:02 mjl Exp $
 *
 * Copyright (C) 2023-2024 The Regents of the University of California
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
#include "scamper_udp_resp.h"
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
  if(state->urs != NULL)
    slist_free_cb(state->urs, (slist_free_t)scamper_udpprobe_reply_free);
  if(state->fdn != NULL)
    scamper_fd_free(state->fdn);
  free(state);
  return;
}

static void do_udpprobe_handle_udp(scamper_task_t *task, scamper_udp_resp_t *ur)
{
  scamper_udpprobe_t *up = udpprobe_getdata(task);
  udpprobe_state_t *state = udpprobe_getstate(task);
  scamper_udpprobe_reply_t *upr;

  if(state == NULL)
    return;

  /*
   * ignore the response if it was received on a different socket than
   * we probed with.  this is to avoid recording duplicate replies
   */
  if(ur->fd != scamper_fd_fd_get(state->fdn))
    return;

  if(ur->sport != up->dport)
    return;

  if((upr = scamper_udpprobe_reply_alloc()) == NULL ||
     (upr->data = memdup(ur->data, ur->datalen)) == NULL)
    goto err;
  if(timeval_iszero(&ur->rx) == 0)
    timeval_cpy(&upr->tv, &ur->rx);
  else
    gettimeofday_wrap(&upr->tv);
  upr->len = ur->datalen;

  if(slist_tail_push(state->urs, upr) == NULL)
    goto err;

  if(SCAMPER_UDPPROBE_FLAG_IS_EXITFIRST(up))
    udpprobe_stop(task, SCAMPER_UDPPROBE_STOP_DONE);

  return;

 err:
  if(upr != NULL) scamper_udpprobe_reply_free(upr);
  return;
}

static udpprobe_state_t *udpprobe_state_alloc(scamper_task_t *task)
{
  scamper_udpprobe_t *up = udpprobe_getdata(task);
  udpprobe_state_t *state = NULL;

  if((state = malloc_zero(sizeof(udpprobe_state_t))) == NULL ||
     (state->urs = slist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc state");
      goto err;
    }

  if(SCAMPER_ADDR_TYPE_IS_IPV4(up->dst))
    state->fdn = scamper_fd_udp4dg(up->src->addr, up->sport);
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(up->dst))
    state->fdn = scamper_fd_udp6(up->src->addr, up->sport);
  if(state->fdn == NULL)
    goto err;

  scamper_task_setstate(task, state);
  return state;

 err:
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
  int fd, ttl = 255;
  void *ttl_p = (void *)&ttl;
  size_t ttl_l = sizeof(ttl);

  assert(state == NULL);

  if((state = udpprobe_state_alloc(task)) == NULL)
    goto err;
  fd = scamper_fd_fd_get(state->fdn);

  if(SCAMPER_ADDR_TYPE_IS_IPV4(up->dst))
    {
      sa = (struct sockaddr *)&sin;
      sockaddr_compose(sa, AF_INET, up->dst->addr, up->dport);
      sl = sizeof(sin);
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(up->dst))
    {
      if(setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, ttl_p, ttl_l) == -1)
	{
	  printerror(__func__, "could not set hlim to %d", ttl);
	  goto err;
	}
      sa = (struct sockaddr *)&sin6;
      sockaddr_compose(sa, AF_INET6, up->dst->addr, up->dport);
      sl = sizeof(sin6);
    }
  else goto err;

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
					      scamper_cycle_t *cycle,
					      char *errbuf, size_t errlen)
{
  scamper_udpprobe_t *up = (scamper_udpprobe_t *)data;
  scamper_task_t *task = NULL;
  scamper_task_sig_t *sig = NULL;

  /* allocate a task structure and store the udpprobe with it */
  if((task = scamper_task_alloc(up, &udpprobe_funcs)) == NULL)
    {
      snprintf(errbuf, errlen, "%s: could not malloc state", __func__);
      goto err;
    }

  if(up->src == NULL &&
     (up->src = scamper_getsrc(up->dst, 0, errbuf, errlen)) == NULL)
    goto err;

  /* declare the signature of the task's probes */
  if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
    {
      snprintf(errbuf, errlen, "%s: could not alloc task signature", __func__);
      goto err;
    }
  sig->sig_tx_ip_dst = scamper_addr_use(up->dst);
  sig->sig_tx_ip_src = scamper_addr_use(up->src);
  SCAMPER_TASK_SIG_UDP(sig, up->sport, up->dport);
  if(scamper_task_sig_add(task, sig) != 0)
    {
      snprintf(errbuf, errlen, "%s: could not add signature to task", __func__);
      goto err;
    }
  sig = NULL;

  /* associate the list and cycle with the http structure */
  up->list = scamper_list_use(list);
  up->cycle = scamper_cycle_use(cycle);

  return task;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  if(task != NULL)
    {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
    }
  return NULL;
}

uint32_t scamper_do_udpprobe_userid(void *data)
{
  return ((scamper_udpprobe_t *)data)->userid;
}

void scamper_do_udpprobe_cleanup(void)
{
  return;
}

int scamper_do_udpprobe_init(void)
{
  udpprobe_funcs.probe          = do_udpprobe_probe;
  udpprobe_funcs.handle_udp     = do_udpprobe_handle_udp;
  udpprobe_funcs.handle_timeout = do_udpprobe_handle_timeout;
  udpprobe_funcs.write          = do_udpprobe_write;
  udpprobe_funcs.task_free      = do_udpprobe_free;
  udpprobe_funcs.halt           = do_udpprobe_halt;

  return 0;
}
