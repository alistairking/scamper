/*
 * scamper_owamp_warts.c
 *
 * Copyright (C) 2025 The Regents of the University of California
 *
 * Author: Matthew Luckie
 *
 * $Id: scamper_owamp_warts.c,v 1.3 2026/01/04 19:43:21 mjl Exp $
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
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_owamp.h"
#include "scamper_owamp_int.h"
#include "scamper_owamp_warts.h"

#include "mjl_list.h"
#include "utils.h"

/*
 * the bits of an owamp structure
 */
#define WARTS_OWAMP_LIST          1
#define WARTS_OWAMP_CYCLE         2
#define WARTS_OWAMP_USERID        3
#define WARTS_OWAMP_SRC           4
#define WARTS_OWAMP_DST           5
#define WARTS_OWAMP_DPORT         6
#define WARTS_OWAMP_FLAGS         7
#define WARTS_OWAMP_START         8
#define WARTS_OWAMP_STARTAT       9
#define WARTS_OWAMP_WAIT_TIMEOUT 10
#define WARTS_OWAMP_SCHEDC       11
#define WARTS_OWAMP_ATTEMPTS     12
#define WARTS_OWAMP_PKTSIZE      13
#define WARTS_OWAMP_DIR          14
#define WARTS_OWAMP_DSCP         15
#define WARTS_OWAMP_TTL          16
#define WARTS_OWAMP_HSRTT        17
#define WARTS_OWAMP_RESULT       18
#define WARTS_OWAMP_ERRMSG       19
#define WARTS_OWAMP_UDP_SPORT    20
#define WARTS_OWAMP_UDP_DPORT    21
#define WARTS_OWAMP_TXC          22

static const warts_var_t owamp_vars[] =
{
  {WARTS_OWAMP_LIST,            4},
  {WARTS_OWAMP_CYCLE,           4},
  {WARTS_OWAMP_USERID,          4},
  {WARTS_OWAMP_SRC,            -1},
  {WARTS_OWAMP_DST,            -1},
  {WARTS_OWAMP_DPORT,           2},
  {WARTS_OWAMP_FLAGS,           2},
  {WARTS_OWAMP_START,           8},
  {WARTS_OWAMP_STARTAT,         8},
  {WARTS_OWAMP_WAIT_TIMEOUT,    8},
  {WARTS_OWAMP_SCHEDC,          4},
  {WARTS_OWAMP_ATTEMPTS,        4},
  {WARTS_OWAMP_PKTSIZE,         2},
  {WARTS_OWAMP_DIR,             1},
  {WARTS_OWAMP_DSCP,            1},
  {WARTS_OWAMP_TTL,             1},
  {WARTS_OWAMP_HSRTT,           4},
  {WARTS_OWAMP_RESULT,          1},
  {WARTS_OWAMP_ERRMSG,         -1},
  {WARTS_OWAMP_UDP_SPORT,       2},
  {WARTS_OWAMP_UDP_DPORT,       2},
  {WARTS_OWAMP_TXC,             4},
};
#define owamp_vars_mfb WARTS_VAR_MFB(owamp_vars)

#define WARTS_OWAMP_SCHED_TV     1
#define WARTS_OWAMP_SCHED_TYPE   2

static const warts_var_t owamp_sched_vars[] =
{
  {WARTS_OWAMP_SCHED_TV,        8},
  {WARTS_OWAMP_SCHED_TYPE,      1},
};
#define owamp_sched_vars_mfb WARTS_VAR_MFB(owamp_sched_vars)

#define WARTS_OWAMP_RX_STAMP    1
#define WARTS_OWAMP_RX_ERREST   2
#define WARTS_OWAMP_RX_FLAGS    3
#define WARTS_OWAMP_RX_DSCP     4
#define WARTS_OWAMP_RX_TTL      5

static const warts_var_t owamp_rx_vars[] =
{
  {WARTS_OWAMP_RX_STAMP,        8},
  {WARTS_OWAMP_RX_ERREST,       2},
  {WARTS_OWAMP_RX_FLAGS,        1},
  {WARTS_OWAMP_RX_DSCP,         1},
  {WARTS_OWAMP_RX_TTL,          1},
};
#define owamp_rx_vars_mfb WARTS_VAR_MFB(owamp_rx_vars)
  
#define WARTS_OWAMP_TX_SCHED    1
#define WARTS_OWAMP_TX_STAMP    2
#define WARTS_OWAMP_TX_SEQ      3
#define WARTS_OWAMP_TX_ERREST   4
#define WARTS_OWAMP_TX_FLAGS    5
#define WARTS_OWAMP_TX_RXC      6

static const warts_var_t owamp_tx_vars[] =
{
  {WARTS_OWAMP_TX_SCHED,        8},
  {WARTS_OWAMP_TX_STAMP,        8},
  {WARTS_OWAMP_TX_SEQ,          4},
  {WARTS_OWAMP_TX_ERREST,       2},
  {WARTS_OWAMP_TX_FLAGS,        1},
  {WARTS_OWAMP_TX_RXC,          1},
};
#define owamp_tx_vars_mfb WARTS_VAR_MFB(owamp_tx_vars)

typedef struct warts_owamp_sched
{
  uint8_t   flags[WARTS_VAR_MFB(owamp_sched_vars)];
  uint16_t  flags_len;
  uint16_t  params_len;
  uint16_t  len;
} warts_owamp_sched_t;

typedef struct warts_owamp_rx
{
  uint8_t   flags[WARTS_VAR_MFB(owamp_rx_vars)];
  uint16_t  flags_len;
  uint16_t  params_len;
  uint16_t  len;
} warts_owamp_rx_t;

typedef struct warts_owamp_tx
{
  uint8_t           flags[WARTS_VAR_MFB(owamp_tx_vars)];
  uint16_t          flags_len;
  uint16_t          params_len;
  uint16_t          len;
  warts_owamp_rx_t *rxs;
} warts_owamp_tx_t;

static int warts_owamp_sched_params(const scamper_owamp_sched_t *sched,
				    warts_owamp_sched_t *state)
{
  const warts_var_t *var;
  int max_id = 0;
  size_t i;

  /* Unset all flags */
  memset(state->flags, 0, owamp_sched_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(owamp_sched_vars)/sizeof(warts_var_t); i++)
    {
      var = &owamp_sched_vars[i];
      if((var->id == WARTS_OWAMP_SCHED_TV && timeval_iszero(&sched->tv)) ||
	 (var->id == WARTS_OWAMP_SCHED_TYPE && sched->type == 0))
	continue;

      /* Set the flag for the rest of the variables */
      flag_set(state->flags, var->id, &max_id);

      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);
  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;

  return 0;
}

static int warts_owamp_sched_read(scamper_owamp_sched_t *sched,
				  const uint8_t *buf,
				  uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&sched->tv,     (wpr_t)extract_timeval,       NULL},
    {&sched->type,   (wpr_t)extract_byte,          NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static void warts_owamp_sched_write(const scamper_owamp_sched_t *sched,
				    uint8_t *buf, uint32_t *off, uint32_t len,
				    warts_owamp_sched_t *state)
{
  warts_param_writer_t handlers[] = {
    {&sched->tv,     (wpw_t)insert_timeval,       NULL},
    {&sched->type,   (wpw_t)insert_byte,          NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int warts_owamp_rx_params(const scamper_owamp_rx_t *rx,
				 warts_owamp_rx_t *state)
{
  const warts_var_t *var;
  int max_id = 0;
  size_t i;

  /* Unset all flags */
  memset(state->flags, 0, owamp_rx_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(owamp_rx_vars)/sizeof(warts_var_t); i++)
    {
      var = &owamp_rx_vars[i];
      if((var->id == WARTS_OWAMP_RX_STAMP  && timeval_iszero(&rx->stamp)) ||
	 (var->id == WARTS_OWAMP_RX_ERREST && rx->errest == 0) ||
	 (var->id == WARTS_OWAMP_RX_FLAGS  && rx->flags == 0) ||
	 (var->id == WARTS_OWAMP_RX_DSCP   && rx->dscp == 0) ||
	 (var->id == WARTS_OWAMP_RX_TTL    && rx->ttl == 0))
	continue;

      /* Set the flag for the rest of the variables */
      flag_set(state->flags, var->id, &max_id);

      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);
  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;

  return 0;
}

static int warts_owamp_rx_read(scamper_owamp_rx_t *rx, const uint8_t *buf,
			       uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&rx->stamp,     (wpr_t)extract_timeval,       NULL},
    {&rx->errest,    (wpr_t)extract_uint16,        NULL},
    {&rx->flags,     (wpr_t)extract_byte,          NULL},
    {&rx->dscp,      (wpr_t)extract_byte,          NULL},
    {&rx->ttl,       (wpr_t)extract_byte,          NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static void warts_owamp_rx_write(scamper_owamp_rx_t *rx,
				 uint8_t *buf, uint32_t *off, uint32_t len,
				 warts_owamp_rx_t *state)
{
  warts_param_writer_t handlers[] = {
    {&rx->stamp,     (wpw_t)insert_timeval,       NULL},
    {&rx->errest,    (wpw_t)insert_uint16,        NULL},
    {&rx->flags,     (wpw_t)insert_byte,          NULL},
    {&rx->dscp,      (wpw_t)insert_byte,          NULL},
    {&rx->ttl,       (wpw_t)insert_byte,          NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int warts_owamp_tx_params(const scamper_owamp_tx_t *tx,
				 warts_owamp_tx_t *state)
{
  const warts_var_t *var;
  int max_id = 0;
  uint8_t r;
  size_t i;

  /* Unset all flags */
  memset(state->flags, 0, owamp_tx_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(owamp_tx_vars)/sizeof(warts_var_t); i++)
    {
      var = &owamp_tx_vars[i];
      if((var->id == WARTS_OWAMP_TX_SCHED  && timeval_iszero(&tx->sched)) ||
	 (var->id == WARTS_OWAMP_TX_STAMP  && timeval_iszero(&tx->stamp)) ||
	 (var->id == WARTS_OWAMP_TX_SEQ    && tx->seq == 0) ||
	 (var->id == WARTS_OWAMP_TX_ERREST && tx->errest == 0) ||
	 (var->id == WARTS_OWAMP_TX_FLAGS  && tx->flags == 0) ||
	 (var->id == WARTS_OWAMP_TX_RXC    && tx->rxc == 0))
	continue;

      /* Set the flag for the rest of the variables */
      flag_set(state->flags, var->id, &max_id);

      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);
  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;

  if(tx->rxc > 0)
    {
      if((state->rxs = malloc_zero(sizeof(warts_owamp_rx_t) * tx->rxc)) == NULL)
	return -1;
      for(r=0; r<tx->rxc; r++)
	{
	  if(warts_owamp_rx_params(tx->rxs[r], &state->rxs[r]) != 0)
	    return -1;
	  state->len += state->rxs[r].len;
	}
    }

  return 0;
}

static int warts_owamp_tx_read(scamper_owamp_tx_t *tx, const uint8_t *buf,
			       uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&tx->sched,     (wpr_t)extract_timeval,       NULL},
    {&tx->stamp,     (wpr_t)extract_timeval,       NULL},
    {&tx->seq,       (wpr_t)extract_uint32,        NULL},
    {&tx->errest,    (wpr_t)extract_uint16,        NULL},
    {&tx->flags,     (wpr_t)extract_byte,          NULL},
    {&tx->rxc,       (wpr_t)extract_byte,          NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  scamper_owamp_rx_t *rx = NULL;
  slist_t *list = NULL;
  uint8_t i, rxc;
  int rc = -1;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto done;

  if(tx->rxc > 0)
    {
      if((list = slist_alloc()) == NULL)
	goto done;
      rxc = tx->rxc; tx->rxc = 0;
      for(i=0; i<rxc; i++)
	{
	  if((rx = scamper_owamp_rx_alloc()) == NULL ||
	     warts_owamp_rx_read(rx, buf, off, len) != 0 ||
	     slist_tail_push(list, rx) == NULL)
	    goto done;
	  rx = NULL;
	}
      if((tx->rxs = malloc_zero(rxc * sizeof(scamper_owamp_rx_t *))) == NULL)
	goto done;
      while((rx = slist_head_pop(list)) != NULL)
	tx->rxs[tx->rxc++] = rx;
    }
  rc = 0;

 done:
  if(list != NULL) slist_free_cb(list, (slist_free_t)scamper_owamp_rx_free);
  if(rx != NULL) scamper_owamp_rx_free(rx);
  return rc;
}

static void warts_owamp_tx_write(scamper_owamp_tx_t *tx,
				 uint8_t *buf, uint32_t *off, uint32_t len,
				 warts_owamp_tx_t *state)
{
  warts_param_writer_t handlers[] = {
    {&tx->sched,     (wpw_t)insert_timeval,       NULL},
    {&tx->stamp,     (wpw_t)insert_timeval,       NULL},
    {&tx->seq,       (wpw_t)insert_uint32,        NULL},
    {&tx->errest,    (wpw_t)insert_uint16,        NULL},
    {&tx->flags,     (wpw_t)insert_byte,          NULL},
    {&tx->rxc,       (wpw_t)insert_byte,          NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  uint8_t i;

  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  for(i=0; i<tx->rxc; i++)
    warts_owamp_rx_write(tx->rxs[i], buf, off, len, &state->rxs[i]);

  return;
}

static int warts_owamp_params(const scamper_owamp_t *owamp, uint8_t *flags,
			      uint16_t *flags_len, uint16_t *params_len)
{
  const warts_var_t *var;
  int max_id = 0;
  size_t i;

  /* Unset all flags */
  memset(flags, 0, owamp_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(owamp_vars)/sizeof(warts_var_t); i++)
    {
      var = &owamp_vars[i];
      if((var->id == WARTS_OWAMP_LIST    && owamp->list == NULL) ||
	 (var->id == WARTS_OWAMP_CYCLE   && owamp->cycle == NULL) ||
	 (var->id == WARTS_OWAMP_USERID  && owamp->userid == 0) ||
	 (var->id == WARTS_OWAMP_SRC     && owamp->src == NULL) ||
	 (var->id == WARTS_OWAMP_DST     && owamp->dst == NULL) ||
	 (var->id == WARTS_OWAMP_DPORT   && owamp->dport == 861) ||
	 (var->id == WARTS_OWAMP_FLAGS   && owamp->flags == 0) ||
	 (var->id == WARTS_OWAMP_START   && timeval_iszero(&owamp->start)) ||
	 (var->id == WARTS_OWAMP_STARTAT && timeval_iszero(&owamp->startat)) ||
	 (var->id == WARTS_OWAMP_WAIT_TIMEOUT &&
	  timeval_cmp_eq(&owamp->wait_timeout, 2, 0)) ||
	 (var->id == WARTS_OWAMP_SCHEDC  && owamp->schedc == 1) ||
	 (var->id == WARTS_OWAMP_ATTEMPTS && owamp->attempts == 10) ||
	 (var->id == WARTS_OWAMP_PKTSIZE && owamp->pktsize == (20 + 8 + 14)) ||
	 (var->id == WARTS_OWAMP_DIR     && owamp->dir == 0) ||
	 (var->id == WARTS_OWAMP_DSCP    && owamp->dscp == 0) ||
	 (var->id == WARTS_OWAMP_TTL     && owamp->ttl == 255) ||
	 (var->id == WARTS_OWAMP_HSRTT   && timeval_iszero(&owamp->hsrtt)) ||
	 (var->id == WARTS_OWAMP_RESULT  && owamp->result == 0) ||
	 (var->id == WARTS_OWAMP_ERRMSG  && owamp->errmsg == NULL) ||
	 (var->id == WARTS_OWAMP_UDP_SPORT && owamp->udp_sport == 0) ||
	 (var->id == WARTS_OWAMP_UDP_DPORT && owamp->udp_dport == 0) ||
	 (var->id == WARTS_OWAMP_TXC     && owamp->txc == 0))
	continue;

      /* Set the flag for the rest of the variables */
      flag_set(flags, var->id, &max_id);

      /* variables that don't have a fixed size */
      if(var->id == WARTS_OWAMP_SRC)
	{
	  if(warts_addr_size_static(owamp->src, params_len) != 0)
	    return -1;
	}
      else if(var->id == WARTS_OWAMP_DST)
	{
	  if(warts_addr_size_static(owamp->dst, params_len) != 0)
	    return -1;
	}
      else if(var->id == WARTS_OWAMP_ERRMSG)
	{
	  if(warts_str_size(owamp->errmsg, params_len) != 0)
	    return -1;
	}
      else
	{
	  assert(var->size >= 0);
	  *params_len += var->size;
	}
    }

  *flags_len = fold_flags(flags, max_id);
  return 0;
}

static int warts_owamp_params_read(scamper_owamp_t *owamp, warts_state_t *state,
				   uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&owamp->list,         (wpr_t)extract_list,         state},
    {&owamp->cycle,        (wpr_t)extract_cycle,        state},
    {&owamp->userid,       (wpr_t)extract_uint32,       NULL},
    {&owamp->src,          (wpr_t)extract_addr_static,  NULL},
    {&owamp->dst,          (wpr_t)extract_addr_static,  NULL},
    {&owamp->dport,        (wpr_t)extract_uint16,       NULL},
    {&owamp->flags,        (wpr_t)extract_uint16,       NULL},
    {&owamp->start,        (wpr_t)extract_timeval,      NULL},
    {&owamp->startat,      (wpr_t)extract_timeval,      NULL},
    {&owamp->wait_timeout, (wpr_t)extract_timeval,      NULL},
    {&owamp->schedc,       (wpr_t)extract_uint32,       NULL},
    {&owamp->attempts,     (wpr_t)extract_uint32,       NULL},
    {&owamp->pktsize,      (wpr_t)extract_uint16,       NULL},
    {&owamp->dir,          (wpr_t)extract_byte,         NULL},
    {&owamp->dscp,         (wpr_t)extract_byte,         NULL},
    {&owamp->ttl,          (wpr_t)extract_byte,         NULL},
    {&owamp->hsrtt,        (wpr_t)extract_rtt,          NULL},
    {&owamp->result,       (wpr_t)extract_byte,         NULL},
    {&owamp->errmsg,       (wpr_t)extract_string,       NULL},
    {&owamp->udp_sport,    (wpr_t)extract_uint16,       NULL},
    {&owamp->udp_dport,    (wpr_t)extract_uint16,       NULL},
    {&owamp->txc,          (wpr_t)extract_uint32,       NULL},
  };
  const int handler_cnt = sizeof(handlers) / sizeof(warts_param_reader_t);
  uint32_t o = *off;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  if(flag_isset(&buf[o], WARTS_OWAMP_DPORT) == 0)
    owamp->dport = 861;
  if(flag_isset(&buf[o], WARTS_OWAMP_WAIT_TIMEOUT) == 0)
    owamp->wait_timeout.tv_sec = 2;
  if(flag_isset(&buf[o], WARTS_OWAMP_SCHEDC) == 0)
    owamp->schedc = 1;
  if(flag_isset(&buf[o], WARTS_OWAMP_ATTEMPTS) == 0)
    owamp->attempts = 10;
  if(flag_isset(&buf[o], WARTS_OWAMP_PKTSIZE) == 0)
    owamp->pktsize = (20 + 8 + 14);
  if(flag_isset(&buf[o], WARTS_OWAMP_TTL) == 0)
    owamp->ttl = 255;

  return 0;
}

static int warts_owamp_params_write(const scamper_owamp_t *owamp,
				    const scamper_file_t *sf,
				    uint8_t *buf, uint32_t *off,
				    const uint32_t len, const uint8_t *flags,
				    const uint16_t flags_len,
				    const uint16_t params_len)
{
  uint32_t list_id, cycle_id;
  warts_param_writer_t handlers[] = {
    {&list_id,             (wpw_t)insert_uint32,       NULL},
    {&cycle_id,            (wpw_t)insert_uint32,       NULL},
    {&owamp->userid,       (wpw_t)insert_uint32,       NULL},
    {owamp->src,           (wpw_t)insert_addr_static,  NULL},
    {owamp->dst,           (wpw_t)insert_addr_static,  NULL},
    {&owamp->dport,        (wpw_t)insert_uint16,       NULL},
    {&owamp->flags,        (wpw_t)insert_uint16,       NULL},
    {&owamp->start,        (wpw_t)insert_timeval,      NULL},
    {&owamp->startat,      (wpw_t)insert_timeval,      NULL},
    {&owamp->wait_timeout, (wpw_t)insert_timeval,      NULL},
    {&owamp->schedc,       (wpw_t)insert_uint32,       NULL},
    {&owamp->attempts,     (wpw_t)insert_uint32,       NULL},
    {&owamp->pktsize,      (wpw_t)insert_uint16,       NULL},
    {&owamp->dir,          (wpw_t)insert_byte,         NULL},
    {&owamp->dscp,         (wpw_t)insert_byte,         NULL},
    {&owamp->ttl,          (wpw_t)insert_byte,         NULL},
    {&owamp->hsrtt,        (wpw_t)insert_rtt,          NULL},
    {&owamp->result,       (wpw_t)insert_byte,         NULL},
    {owamp->errmsg,        (wpw_t)insert_string,       NULL},
    {&owamp->udp_sport,    (wpw_t)insert_uint16,       NULL},
    {&owamp->udp_dport,    (wpw_t)insert_uint16,       NULL},
    {&owamp->txc,          (wpw_t)insert_uint32,       NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  owamp->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, owamp->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return 0;
}

int scamper_file_warts_owamp_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				  scamper_owamp_t **owamp_out)
{
  warts_state_t *state = scamper_file_getstate(sf);
  scamper_owamp_t *owamp = NULL;
  scamper_owamp_sched_t *sched = NULL;
  scamper_owamp_tx_t *tx = NULL;
  slist_t *sched_list = NULL, *tx_list = NULL;
  uint8_t *buf = NULL;
  uint32_t i, schedc, txc, off = 0;
  int rc = -1;

  if(warts_read(sf, &buf, hdr->len) != 0)
    goto done;

  if(buf == NULL)
    {
      *owamp_out = NULL;
      return 0;
    }

  if((owamp = scamper_owamp_alloc()) == NULL)
    goto done;

  if(warts_owamp_params_read(owamp, state, buf, &off, hdr->len) != 0)
    goto done;

  if(owamp->schedc > 0)
    {
      schedc = owamp->schedc; owamp->schedc = 0;
      if((sched_list = slist_alloc()) == NULL)
	goto done;
      for(i=0; i<schedc; i++)
	{
	  if((sched = scamper_owamp_sched_alloc()) == NULL ||
	     warts_owamp_sched_read(sched, buf, &off, hdr->len) != 0 ||
	     slist_tail_push(sched_list, sched) == NULL)
	    goto done;
	  sched = NULL;
	}
      if(scamper_owamp_scheds_alloc(owamp, schedc) != 0)
	goto done;
      while((sched = slist_head_pop(sched_list)) != NULL)
	owamp->sched[owamp->schedc++] = sched;
    }

  if(owamp->txc > 0)
    {
      txc = owamp->txc; owamp->txc = 0;
      if((tx_list = slist_alloc()) == NULL)
	goto done;
      for(i=0; i<txc; i++)
	{
	  if((tx = scamper_owamp_tx_alloc()) == NULL ||
	     warts_owamp_tx_read(tx, buf, &off, hdr->len) != 0 ||
	     slist_tail_push(tx_list, tx) == NULL)
	    goto done;
	  tx = NULL;
	}
      if(scamper_owamp_txs_alloc(owamp, txc) != 0)
	goto done;
      while((tx = slist_head_pop(tx_list)) != NULL)
	owamp->txs[owamp->txc++] = tx;
    }

  *owamp_out = owamp; owamp = NULL;
  rc = 0;

 done:
  if(sched != NULL)
    scamper_owamp_sched_free(sched);
  if(sched_list != NULL)
    slist_free_cb(sched_list, (slist_free_t)scamper_owamp_sched_free);
  if(tx != NULL)
    scamper_owamp_tx_free(tx);
  if(tx_list != NULL)
    slist_free_cb(tx_list, (slist_free_t)scamper_owamp_tx_free);
  if(buf != NULL) free(buf);
  if(owamp != NULL) scamper_owamp_free(owamp);
  return rc;
}

int scamper_file_warts_owamp_write(const scamper_file_t *sf,
				   const scamper_owamp_t *owamp, void *p)
{
  scamper_owamp_sched_t *sched;
  warts_owamp_sched_t *scheds = NULL;
  scamper_owamp_tx_t *tx;
  warts_owamp_tx_t *txs = NULL;
  uint8_t *buf = NULL, flags[owamp_vars_mfb];
  uint16_t flags_len, params_len;
  uint32_t i, len, off = 0;
  size_t size;
  int rc = -1;

  if(warts_owamp_params(owamp, flags, &flags_len, &params_len) != 0)
    goto done;
  len = 8 + flags_len + params_len + 2;

  if(owamp->schedc > 0)
    {
      size = owamp->schedc * sizeof(warts_owamp_sched_t);
      if((scheds = malloc_zero(size)) == NULL)
	goto done;
      for(i=0; i<owamp->schedc; i++)
	{
	  sched = owamp->sched[i];
	  if(warts_owamp_sched_params(sched, &scheds[i]) != 0)
	    goto done;
	  if(UINT32_MAX - len < scheds[i].len)
	    goto done;
	  len += scheds[i].len;
	}
    }

  if(owamp->txc > 0)
    {
      size = owamp->txc * sizeof(warts_owamp_tx_t);
      if((txs = malloc_zero(size)) == NULL)
	goto done;
      for(i=0; i<owamp->txc; i++)
	{
	  tx = owamp->txs[i];
	  if(warts_owamp_tx_params(tx, &txs[i]) != 0)
	    goto done;
	  if(UINT32_MAX - len < txs[i].len)
	    goto done;
	  len += txs[i].len;
	}
    }

  if((buf = malloc_zero(len)) == NULL)
    goto done;
  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_OWAMP);

  if(warts_owamp_params_write(owamp, sf, buf, &off, len, flags, flags_len,
			      params_len) != 0)
    {
      goto done;
    }

  if(owamp->schedc > 0)
    {
      for(i=0; i<owamp->schedc; i++)
	{
	  sched = owamp->sched[i];
	  warts_owamp_sched_write(sched, buf, &off, len, &scheds[i]);
	}
    }

  if(owamp->txc > 0)
    {
      for(i=0; i<owamp->txc; i++)
	{
	  tx = owamp->txs[i];
	  warts_owamp_tx_write(tx, buf, &off, len, &txs[i]);
	}
    }

  assert(off == len);

  if(warts_write(sf, buf, len, p) == -1)
    goto done;

  rc = 0;

 done:
  if(buf != NULL) free(buf);
  if(scheds != NULL) free(scheds);
  if(txs != NULL)
    {
      for(i=0; i<owamp->txc; i++)
	if(txs[i].rxs != NULL)
	  free(txs[i].rxs);
      free(txs);
    }
  return rc;
}
