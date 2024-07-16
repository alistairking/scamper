/*
 * scamper_udpprobe_do.c
 *
 * $Id: scamper_udpprobe_do.c,v 1.11 2024/04/13 22:31:04 mjl Exp $
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
  scamper_fd_t **fds;
  slist_t       *probes;
  slist_t      **replies;
  int            probec;
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
  scamper_udpprobe_probe_t *probe;
  scamper_udpprobe_reply_t *reply;
  int i, j, pc, rc;

  up->stop = reason;

  if(state != NULL && state->probes != NULL &&
     (pc = slist_count(state->probes)) > 0)
    {
      up->probes = malloc_zero(sizeof(scamper_udpprobe_probe_t *) * pc);
      if(up->probes == NULL)
	goto done;

      i = 0;
      while((probe = slist_head_pop(state->probes)) != NULL)
	up->probes[i++] = probe;
      up->probe_sent = i;

      for(i=0; i<pc; i++)
	{
	  probe = up->probes[i];
	  rc = slist_count(state->replies[i]);
	  if(rc == 0)
	    continue;
	  probe->replies = malloc_zero(sizeof(scamper_udpprobe_reply_t *) * rc);
	  if(probe->replies != NULL)
	    {
	      j = 0;
	      while((reply = slist_head_pop(state->replies[i])) != NULL)
		probe->replies[j++] = reply;
	      probe->replyc = j;
	    }
	}
    }

 done:
  scamper_task_queue_done(task, 0);
  return;
}

static void udpprobe_state_free(scamper_udpprobe_t *up, udpprobe_state_t *state)
{
  uint8_t i;

  if(state->replies != NULL)
    {
      for(i=0; i<up->probe_count; i++)
	slist_free_cb(state->replies[i],
		      (slist_free_t)scamper_udpprobe_reply_free);
      free(state->replies);
    }

  if(state->probes != NULL)
    slist_free_cb(state->probes, (slist_free_t)scamper_udpprobe_probe_free);

  if(state->fds != NULL)
    {
      for(i=0; i<up->probe_count; i++)
	if(state->fds[i] != NULL)
	  scamper_fd_free(state->fds[i]);
      free(state->fds);
    }

  free(state);
  return;
}

static void do_udpprobe_handle_udp(scamper_task_t *task, scamper_udp_resp_t *ur)
{
  scamper_udpprobe_t *up = udpprobe_getdata(task);
  udpprobe_state_t *state = udpprobe_getstate(task);
  scamper_udpprobe_reply_t *reply;
  int i;

  if(state == NULL)
    return;

  /* find the socket we sent the probe with */
  for(i=0; i<state->probec; i++)
    if(ur->fd == scamper_fd_fd_get(state->fds[i]))
      break;
  if(i == state->probec)
    return;

  if((reply = scamper_udpprobe_reply_alloc()) == NULL ||
     (reply->data = memdup(ur->data, ur->datalen)) == NULL)
    goto err;
  if(timeval_iszero(&ur->rx) == 0)
    timeval_cpy(&reply->rx, &ur->rx);
  else
    gettimeofday_wrap(&reply->rx);
  reply->len = ur->datalen;

  if(slist_tail_push(state->replies[i], reply) == NULL)
    goto err;

  if(SCAMPER_UDPPROBE_FLAG_IS_EXITFIRST(up))
    udpprobe_stop(task, SCAMPER_UDPPROBE_STOP_DONE);

  return;

 err:
  if(reply != NULL) scamper_udpprobe_reply_free(reply);
  return;
}

static int udpprobe_state_alloc(scamper_task_t *task)
{
  scamper_udpprobe_t *up = udpprobe_getdata(task);
  udpprobe_state_t *state = udpprobe_getstate(task);
  uint8_t i;

  assert(state != NULL);
  if((state->probes = slist_alloc()) == NULL ||
     (state->replies = malloc_zero(sizeof(slist_t *)*up->probe_count)) == NULL)
    {
      printerror(__func__, "could not alloc state");
      return -1;
    }
  for(i=0; i<up->probe_count; i++)
    {
      if((state->replies[i] = slist_alloc()) == NULL)
	{
	  printerror(__func__, "could not alloc state");
	  return -1;
	}
    }

  return 0;
}

static void do_udpprobe_probe(scamper_task_t *task)
{
  scamper_udpprobe_t *up = udpprobe_getdata(task);
  udpprobe_state_t *state = udpprobe_getstate(task);
  scamper_udpprobe_probe_t *probe = NULL;
  struct sockaddr_in6 sin6;
  struct sockaddr_in sin;
  struct sockaddr *sa;
  struct timeval wait_tv;
  socklen_t sl;
  int fd, i;
  void *i_p = (void *)&i;
  size_t i_l = sizeof(i);

  if(state->probec == 0 && udpprobe_state_alloc(task) != 0)
    goto err;

  fd = scamper_fd_fd_get(state->fds[state->probec]);

  if(SCAMPER_ADDR_TYPE_IS_IPV4(up->dst))
    {
      sa = (struct sockaddr *)&sin;
      sockaddr_compose(sa, AF_INET, up->dst->addr, up->dport);
      sl = sizeof(sin);
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(up->dst))
    {
      i = 255;
      if(setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, i_p, i_l) != 0)
	{
	  printerror(__func__, "could not set hlim to %d", i);
	  goto err;
	}
#ifdef IPV6_TCLASS
      i = 0;
      if(setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, i_p, i_l) != 0)
	{
	  printerror(__func__, "could not set tclass to %d", i);
	  goto err;
	}
#endif /* IPV6_TCLASS */
      sa = (struct sockaddr *)&sin6;
      sockaddr_compose(sa, AF_INET6, up->dst->addr, up->dport);
      sl = sizeof(sin6);
    }
  else goto err;

  if((probe = scamper_udpprobe_probe_alloc()) == NULL ||
     slist_tail_push(state->probes, probe) == NULL)
    goto err;
  gettimeofday_wrap(&probe->tx);
  scamper_fd_sport(state->fds[state->probec], &probe->sport);
  if(state->probec == 0)
    timeval_cpy(&up->start, &probe->tx);
  state->probec++;

  if(sendto(fd, up->data, up->len, 0, sa, sl) != up->len)
    goto err;

  if(state->probec < up->probe_count)
    timeval_add_tv3(&wait_tv, &probe->tx, &up->wait_probe);
  else
    timeval_add_tv3(&wait_tv, &probe->tx, &up->wait_timeout);
  scamper_task_queue_wait_tv(task, &wait_tv);

  return;

 err:
  udpprobe_stop(task, SCAMPER_UDPPROBE_STOP_ERROR);
  return;
}

static void do_udpprobe_handle_timeout(scamper_task_t *task)
{
  scamper_udpprobe_t *up = udpprobe_getdata(task);
  udpprobe_state_t *state = udpprobe_getstate(task);

  if(state->probec == up->probe_count)
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
    udpprobe_state_free(up, state);
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
  udpprobe_state_t *state = NULL;
  uint16_t *sports = NULL;
  uint8_t i, probec = up->probe_count;

  /* allocate a task structure and store the udpprobe with it */
  if((task = scamper_task_alloc(up, &udpprobe_funcs)) == NULL ||
     (state = malloc_zero(sizeof(udpprobe_state_t))) == NULL ||
     (state->fds = malloc_zero(sizeof(scamper_fd_t *) * probec)) == NULL ||
     (sports = malloc_zero(sizeof(uint16_t) * probec)) == NULL)
    {
      snprintf(errbuf, errlen, "%s: could not malloc state", __func__);
      goto err;
    }

  if(up->src == NULL &&
     (up->src = scamper_getsrc(up->dst, 0, errbuf, errlen)) == NULL)
    goto err;

  /* declare the signature of the task's probes */
  for(i=0; i<up->probe_count; i++)
    {
      if(SCAMPER_ADDR_TYPE_IS_IPV4(up->dst))
	state->fds[i] = scamper_fd_udp4dg_dst(up->src->addr, up->sport,
					      sports, i,
					      up->dst->addr, up->dport);
      else if(SCAMPER_ADDR_TYPE_IS_IPV6(up->dst))
	state->fds[i] = scamper_fd_udp6_dst(up->src->addr, up->sport,
					    sports, i,
					    up->dst->addr, up->dport);
      if(state->fds[i] == NULL)
	{
	  snprintf(errbuf, errlen, "%s: could not open udp socket", __func__);
	  goto err;
	}
      if(scamper_fd_sport(state->fds[i], &sports[i]) != 0)
	{
	  snprintf(errbuf, errlen, "%s: could not get udp sport", __func__);
	  goto err;
	}

      if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
	{
	  snprintf(errbuf, errlen, "%s: could not alloc task signature", __func__);
	  goto err;
	}
      sig->sig_tx_ip_dst = scamper_addr_use(up->dst);
      sig->sig_tx_ip_src = scamper_addr_use(up->src);
      SCAMPER_TASK_SIG_UDP(sig, sports[i], up->dport);
      if(scamper_task_sig_add(task, sig) != 0)
	{
	  snprintf(errbuf, errlen, "%s: could not add signature to task", __func__);
	  goto err;
	}
      sig = NULL;
    }

  free(sports);

  scamper_task_setstate(task, state);

  /* associate the list and cycle with the http structure */
  up->list = scamper_list_use(list);
  up->cycle = scamper_cycle_use(cycle);

  return task;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  if(state != NULL) udpprobe_state_free(up, state);
  if(sports != NULL) free(sports);
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
