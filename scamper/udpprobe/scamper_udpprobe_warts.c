/*
 * scamper_udpprobe_warts.c
 *
 * Copyright (C) 2023 The Regents of the University of California
 *
 * Author: Matthew Luckie
 *
 * $Id: scamper_udpprobe_warts.c,v 1.5 2024/04/04 06:55:33 mjl Exp $
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
#include "scamper_list.h"
#include "scamper_udpprobe.h"
#include "scamper_udpprobe_int.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_udpprobe_warts.h"
#include "utils.h"

/*
 * the bits of a udpprobe structure
 */
#define WARTS_UDPPROBE_LIST            1
#define WARTS_UDPPROBE_CYCLE           2
#define WARTS_UDPPROBE_USERID          3
#define WARTS_UDPPROBE_SRC             4
#define WARTS_UDPPROBE_DST             5
#define WARTS_UDPPROBE_P0_SPORT        6
#define WARTS_UDPPROBE_DPORT           7
#define WARTS_UDPPROBE_START           8
#define WARTS_UDPPROBE_WAIT_TIMEOUT    9
#define WARTS_UDPPROBE_FLAGS           10
#define WARTS_UDPPROBE_STOP            11
#define WARTS_UDPPROBE_LEN             12
#define WARTS_UDPPROBE_DATA            13
#define WARTS_UDPPROBE_P0_REPLYC       14
#define WARTS_UDPPROBE_PROBE_COUNT     15
#define WARTS_UDPPROBE_PROBE_SENT      16
#define WARTS_UDPPROBE_STOP_COUNT      17
#define WARTS_UDPPROBE_SPORT           18
#define WARTS_UDPPROBE_WAIT_PROBE      19

static const warts_var_t udpprobe_vars[] =
{
  {WARTS_UDPPROBE_LIST,         4},
  {WARTS_UDPPROBE_CYCLE,        4},
  {WARTS_UDPPROBE_USERID,       4},
  {WARTS_UDPPROBE_SRC,         -1},
  {WARTS_UDPPROBE_DST,         -1},
  {WARTS_UDPPROBE_P0_SPORT,     2},
  {WARTS_UDPPROBE_DPORT,        2},
  {WARTS_UDPPROBE_START,        8},
  {WARTS_UDPPROBE_WAIT_TIMEOUT, 4},
  {WARTS_UDPPROBE_FLAGS,        1},
  {WARTS_UDPPROBE_STOP,         1},
  {WARTS_UDPPROBE_LEN,          2},
  {WARTS_UDPPROBE_DATA,        -1},
  {WARTS_UDPPROBE_P0_REPLYC,    1},
  {WARTS_UDPPROBE_PROBE_COUNT,  1},
  {WARTS_UDPPROBE_PROBE_SENT,   1},
  {WARTS_UDPPROBE_STOP_COUNT,   1},
  {WARTS_UDPPROBE_SPORT,        2},
  {WARTS_UDPPROBE_WAIT_PROBE,   4},
};
#define udpprobe_vars_mfb WARTS_VAR_MFB(udpprobe_vars)

#define WARTS_UDPPROBE_REPLY_RX        1
#define WARTS_UDPPROBE_REPLY_LEN       2
#define WARTS_UDPPROBE_REPLY_DATA      3

static const warts_var_t udpprobe_reply_vars[] =
{
  {WARTS_UDPPROBE_REPLY_RX,     8},
  {WARTS_UDPPROBE_REPLY_LEN,    2},
  {WARTS_UDPPROBE_REPLY_DATA,  -1},
};
#define udpprobe_reply_vars_mfb WARTS_VAR_MFB(udpprobe_reply_vars)

typedef struct warts_udpprobe_reply
{
  uint8_t   flags[WARTS_VAR_MFB(udpprobe_reply_vars)];
  uint16_t  flags_len;
  uint16_t  params_len;
  uint16_t  len;
} warts_udpprobe_reply_t;

#define WARTS_UDPPROBE_PROBE_TX     1
#define WARTS_UDPPROBE_PROBE_SPORT  2
#define WARTS_UDPPROBE_PROBE_REPLYC 3
static const warts_var_t udpprobe_probe_vars[] =
{
  {WARTS_UDPPROBE_PROBE_TX,      8},
  {WARTS_UDPPROBE_PROBE_SPORT,   2},
  {WARTS_UDPPROBE_PROBE_REPLYC,  1},
};
#define udpprobe_probe_vars_mfb WARTS_VAR_MFB(udpprobe_probe_vars)

typedef struct warts_udpprobe_probe
{
  uint8_t   flags[WARTS_VAR_MFB(udpprobe_probe_vars)];
  uint16_t  flags_len;
  uint16_t  params_len;
  uint16_t  len;
} warts_udpprobe_probe_t;

static int warts_udpprobe_probe_params(const scamper_udpprobe_probe_t *up,
				       warts_udpprobe_probe_t *state)
{
  const warts_var_t *var;
  uint16_t u16;
  int max_id = 0;
  size_t i;

  memset(state->flags, 0, udpprobe_probe_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(udpprobe_probe_vars)/sizeof(warts_var_t); i++)
    {
      var = &udpprobe_probe_vars[i];
      if(var->id == WARTS_UDPPROBE_PROBE_REPLYC && up->replyc == 0)
	continue;
      flag_set(state->flags, var->id, &max_id);
      assert(var->size > 0);
      u16 = var->size;
      if(uint16_wouldwrap(state->params_len, u16))
	return -1;
      state->params_len += u16;
    }

  state->flags_len = fold_flags(state->flags, max_id);
  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;
  return 0;
}

static int warts_udpprobe_probe_read(scamper_udpprobe_probe_t *probe,
				     const uint8_t *buf,
				     uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&probe->tx,     (wpr_t)extract_timeval,       NULL},
    {&probe->sport,  (wpr_t)extract_uint16,        NULL},
    {&probe->replyc, (wpr_t)extract_byte,          NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static void warts_udpprobe_probe_write(const scamper_udpprobe_probe_t *probe,
				       uint8_t *buf,
				       uint32_t *off, uint32_t len,
				       warts_udpprobe_probe_t *state)
{
  warts_param_writer_t handlers[] = {
    {&probe->tx,     (wpw_t)insert_timeval,       NULL},
    {&probe->sport,  (wpw_t)insert_uint16,        NULL},
    {&probe->replyc, (wpw_t)insert_byte,          NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int warts_udpprobe_reply_params(const scamper_udpprobe_reply_t *ur,
				       warts_udpprobe_reply_t *state)
{
  const warts_var_t *var;
  uint16_t u16;
  int max_id = 0;
  size_t i;

  memset(state->flags, 0, udpprobe_reply_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(udpprobe_reply_vars)/sizeof(warts_var_t); i++)
    {
      var = &udpprobe_reply_vars[i];
      if((var->id == WARTS_UDPPROBE_REPLY_RX && timeval_iszero(&ur->rx)) ||
	 ((var->id == WARTS_UDPPROBE_REPLY_LEN ||
	   var->id == WARTS_UDPPROBE_REPLY_DATA) &&
	  (ur->data == NULL || ur->len == 0)))
	continue;
      flag_set(state->flags, var->id, &max_id);

      if(var->id == WARTS_UDPPROBE_REPLY_DATA)
	{
	  u16 = ur->len;
	}
      else
	{
	  assert(var->size > 0);
	  u16 = var->size;
	}

      if(uint16_wouldwrap(state->params_len, u16))
	return -1;
      state->params_len += u16;
    }

  state->flags_len = fold_flags(state->flags, max_id);
  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;
  return 0;
}

static int warts_udpprobe_reply_read(scamper_udpprobe_reply_t *ur,
				     const uint8_t *buf,
				     uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&ur->rx,   (wpr_t)extract_timeval,       NULL},
    {&ur->len,  (wpr_t)extract_uint16,        NULL},
    {&ur->data, (wpr_t)extract_bytes_alloc,   &ur->len},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static void warts_udpprobe_reply_write(const scamper_udpprobe_reply_t *ur,
				       uint8_t *buf,
				       uint32_t *off, uint32_t len,
				       warts_udpprobe_reply_t *state)
{
  uint16_t ur_len = ur->len;
  warts_param_writer_t handlers[] = {
    {&ur->rx,   (wpw_t)insert_timeval,       NULL},
    {&ur->len,  (wpw_t)insert_uint16,        NULL},
    {ur->data,  (wpw_t)insert_bytes_uint16, &ur_len},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int warts_udpprobe_params(const scamper_udpprobe_t *up, uint8_t *flags,
				 uint16_t *flags_len, uint16_t *params_len)
{
  const warts_var_t *var;
  int max_id = 0;
  size_t i;

  /* Unset all flags */
  memset(flags, 0, udpprobe_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(udpprobe_vars)/sizeof(warts_var_t); i++)
    {
      var = &udpprobe_vars[i];

      if((var->id == WARTS_UDPPROBE_LIST    && up->list == NULL) ||
	 (var->id == WARTS_UDPPROBE_CYCLE   && up->cycle == NULL) ||
	 (var->id == WARTS_UDPPROBE_USERID  && up->userid == 0) ||
	 (var->id == WARTS_UDPPROBE_SRC     && up->src == NULL) ||
	 (var->id == WARTS_UDPPROBE_DST     && up->dst == NULL) ||
	 (var->id == WARTS_UDPPROBE_P0_SPORT &&
	  (up->probes == NULL || up->probe_sent == 0 ||
	   up->probes[0] == NULL)) ||
	 (var->id == WARTS_UDPPROBE_DPORT   && up->dport == 0) ||
	 (var->id == WARTS_UDPPROBE_START   && timeval_iszero(&up->start)) ||
	 (var->id == WARTS_UDPPROBE_WAIT_TIMEOUT &&
	  timeval_iszero(&up->wait_timeout)) ||
	 (var->id == WARTS_UDPPROBE_WAIT_PROBE &&
	  timeval_iszero(&up->wait_probe)) ||
	 (var->id == WARTS_UDPPROBE_FLAGS   && up->flags == 0) ||
	 (var->id == WARTS_UDPPROBE_STOP    && up->stop == 0) ||
	 ((var->id == WARTS_UDPPROBE_LEN || var->id == WARTS_UDPPROBE_DATA) &&
	  (up->data == NULL || up->len == 0)) ||
	 (var->id == WARTS_UDPPROBE_P0_REPLYC &&
	  (up->probes == NULL || up->probe_sent == 0 || up->probes[0] == NULL ||
	   up->probes[0]->replyc == 0)) ||
	 (var->id == WARTS_UDPPROBE_PROBE_COUNT && up->probe_count == 1) ||
	 (var->id == WARTS_UDPPROBE_PROBE_SENT && up->probe_sent == 1) ||
	 (var->id == WARTS_UDPPROBE_STOP_COUNT && up->stop_count == 0) ||
	 (var->id == WARTS_UDPPROBE_SPORT && up->sport == 0))
	continue;

      /* Set the flag for the rest of the variables */
      flag_set(flags, var->id, &max_id);

      /* variables that don't have a fixed size */
      if(var->id == WARTS_UDPPROBE_SRC)
	{
	  if(warts_addr_size_static(up->src, params_len) != 0)
	    return -1;
	}
      else if(var->id == WARTS_UDPPROBE_DST)
	{
	  if(warts_addr_size_static(up->dst, params_len) != 0)
	    return -1;
	}
      else if(var->id == WARTS_UDPPROBE_DATA)
	{
	  *params_len += up->len;
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

static int warts_udpprobe_params_read(scamper_udpprobe_t *up,
				      uint8_t *p0_replyc, uint16_t *p0_sport,
				      warts_state_t *state, uint8_t *buf,
				      uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&up->list,         (wpr_t)extract_list,         state},
    {&up->cycle,        (wpr_t)extract_cycle,        state},
    {&up->userid,       (wpr_t)extract_uint32,       NULL},
    {&up->src,          (wpr_t)extract_addr_static,  NULL},
    {&up->dst,          (wpr_t)extract_addr_static,  NULL},
    {p0_sport,          (wpr_t)extract_uint16,       NULL},
    {&up->dport,        (wpr_t)extract_uint16,       NULL},
    {&up->start,        (wpr_t)extract_timeval,      NULL},
    {&up->wait_timeout, (wpr_t)extract_rtt,          NULL},
    {&up->flags,        (wpr_t)extract_byte,         NULL},
    {&up->stop,         (wpr_t)extract_byte,         NULL},
    {&up->len,          (wpr_t)extract_uint16,       NULL},
    {&up->data,         (wpr_t)extract_bytes_alloc,  &up->len},
    {p0_replyc,         (wpr_t)extract_byte,         NULL},
    {&up->probe_count,  (wpr_t)extract_byte,         NULL},
    {&up->probe_sent,   (wpr_t)extract_byte,         NULL},
    {&up->stop_count,   (wpr_t)extract_byte,         NULL},
    {&up->sport,        (wpr_t)extract_uint16,       NULL},
    {&up->wait_probe,   (wpr_t)extract_rtt,          NULL},
  };
  const int handler_cnt = sizeof(handlers) / sizeof(warts_param_reader_t);

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  if(up->probe_sent == 0)
    up->probe_sent = 1;
  if(up->probe_count == 0)
    up->probe_count = 1;

  return 0;
}

static int warts_udpprobe_params_write(const scamper_udpprobe_t *up,
				       const scamper_file_t *sf,
				       uint8_t *buf, uint32_t *off,
				       const uint32_t len,
				       const uint8_t *flags,
				       const uint16_t flags_len,
				       const uint16_t params_len)
{
  uint16_t up_len = up->len;
  uint32_t list_id, cycle_id;
  uint8_t p0_replyc = 0, p0_sport = 0;
  warts_param_writer_t handlers[] = {
    {&list_id,            (wpw_t)insert_uint32,       NULL},
    {&cycle_id,           (wpw_t)insert_uint32,       NULL},
    {&up->userid,         (wpw_t)insert_uint32,       NULL},
    {up->src,             (wpw_t)insert_addr_static,  NULL},
    {up->dst,             (wpw_t)insert_addr_static,  NULL},
    {&p0_sport,           (wpw_t)insert_uint16,       NULL},
    {&up->dport,          (wpw_t)insert_uint16,       NULL},
    {&up->start,          (wpw_t)insert_timeval,      NULL},
    {&up->wait_timeout,   (wpw_t)insert_rtt,          NULL},
    {&up->flags,          (wpw_t)insert_byte,         NULL},
    {&up->stop,           (wpw_t)insert_byte,         NULL},
    {&up->len,            (wpw_t)insert_uint16,       NULL},
    {up->data,            (wpw_t)insert_bytes_uint16, &up_len},
    {&p0_replyc,          (wpw_t)insert_byte,         NULL},
    {&up->probe_count,    (wpw_t)insert_byte,         NULL},
    {&up->probe_sent,     (wpw_t)insert_byte,         NULL},
    {&up->stop_count,     (wpw_t)insert_byte,         NULL},
    {&up->sport,          (wpw_t)insert_uint16,       NULL},
    {&up->wait_probe,     (wpw_t)insert_rtt,          NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  up->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, up->cycle, &cycle_id) == -1) return -1;

  if(up->probes != NULL && up->probe_sent > 0 && up->probes[0] != NULL)
    {
      p0_replyc = up->probes[0]->replyc;
      p0_sport  = up->probes[0]->sport;
    }

  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return 0;
}

int scamper_file_warts_udpprobe_read(scamper_file_t *sf,
				     const warts_hdr_t *hdr,
				     scamper_udpprobe_t **up_out)
{
  warts_state_t *state = scamper_file_getstate(sf);
  scamper_udpprobe_t *up = NULL;
  scamper_udpprobe_probe_t *probe;
  uint8_t *buf = NULL;
  uint32_t off = 0, pN_urc = 0, px;
  uint8_t i, j, p0_replyc = 0;
  uint16_t p0_sport = 0;
  int rc = -1;
  size_t x;

  if(warts_read(sf, &buf, hdr->len) != 0)
    goto done;

  if(buf == NULL)
    {
      *up_out = NULL;
      return 0;
    }

  if((up = scamper_udpprobe_alloc()) == NULL)
    goto done;

  if(warts_udpprobe_params_read(up, &p0_replyc, &p0_sport, state, buf, &off, hdr->len) != 0)
    goto done;

  if(up->probe_sent == 0)
    up->probe_sent = 1;
  if(up->probe_count == 0)
    up->probe_count = 1;

  x = sizeof(scamper_udpprobe_probe_t *) * up->probe_sent;
  if((up->probes = malloc_zero(x)) == NULL ||
     (up->probes[0] = scamper_udpprobe_probe_alloc()) == NULL)
    goto done;
  probe = up->probes[0];
  probe->sport = p0_sport;
  probe->replyc = p0_replyc;
  timeval_cpy(&probe->tx, &up->start);

  if(p0_replyc > 0)
    {
      x = sizeof(scamper_udpprobe_reply_t *) * p0_replyc;
      if((probe->replies = malloc_zero(x)) == NULL)
	goto done;
      for(i=0; i<p0_replyc; i++)
	{
	  if((probe->replies[i] = scamper_udpprobe_reply_alloc()) == NULL ||
	     warts_udpprobe_reply_read(probe->replies[i], buf,
				       &off, hdr->len) != 0)
	    goto done;
	}
    }

  if(up->probe_sent > 1)
    {
      for(i=1; i<up->probe_sent; i++)
	{
	  if((up->probes[i] = scamper_udpprobe_probe_alloc()) == NULL ||
	     warts_udpprobe_probe_read(up->probes[i], buf,
				       &off, hdr->len) != 0)
	    goto done;
	  probe = up->probes[i];
	  pN_urc += probe->replyc;
	  if(probe->replyc > 0)
	    {
	      x = sizeof(scamper_udpprobe_reply_t *) * probe->replyc;
	      if((probe->replies = malloc_zero(x)) == NULL)
		goto done;
	    }
	}

      if(pN_urc > 0)
	{
	  i = 1; j = 0;
	  for(px=0; px<pN_urc; px++)
	    {
	      while(i < up->probe_sent)
		{
		  if(j < up->probes[i]->replyc)
		    break;
		  i++; j=0;
		}
	      if(i == up->probe_sent)
		goto done;

	      probe = up->probes[i];
	      if((probe->replies[j] = scamper_udpprobe_reply_alloc()) == NULL ||
		 warts_udpprobe_reply_read(probe->replies[j], buf,
					   &off, hdr->len) != 0)
		goto done;
	      j++;
	    }
	}
    }

  *up_out = up; up = NULL;
  rc = 0;

 done:
  if(buf != NULL) free(buf);
  if(up != NULL) scamper_udpprobe_free(up);
  return rc;
}

int scamper_file_warts_udpprobe_write(const scamper_file_t *sf,
				      const scamper_udpprobe_t *up, void *p)
{
  scamper_udpprobe_probe_t *p0 = NULL, *probe;
  warts_udpprobe_reply_t *p0_urs = NULL;
  warts_udpprobe_probe_t *pN_ups = NULL;
  warts_udpprobe_reply_t *pN_urs = NULL;
  uint8_t *buf = NULL;
  uint8_t  flags[udpprobe_vars_mfb];
  uint16_t flags_len, params_len;
  uint32_t j, x, pN_urc = 0, len, off = 0;
  uint8_t i;
  int rc = -1;

  if(warts_udpprobe_params(up, flags, &flags_len, &params_len) != 0)
    goto done;
  len = 8 + flags_len + params_len + 2;

  /*
   * for backwards compatibility, handle details of the first probe
   * separately to the remaining probes.
   */
  if(up->probes != NULL && up->probe_sent > 0 && up->probes[0] != NULL &&
     up->probes[0]->replyc > 0)
    {
      p0 = up->probes[0];
      p0_urs = malloc_zero(sizeof(warts_udpprobe_reply_t) * p0->replyc);
      if(p0_urs == NULL)
	goto done;
      for(i=0; i<p0->replyc; i++)
	{
	  if(warts_udpprobe_reply_params(p0->replies[i], &p0_urs[i]) != 0)
	    goto done;
	  len += p0_urs[i].len;
	}
    }

  /* for all N additional probes/replies, deal with them here */
  if(up->probe_sent > 1)
    {
      pN_ups = malloc_zero(sizeof(warts_udpprobe_probe_t) * (up->probe_sent-1));
      if(pN_ups == NULL)
	goto done;
      for(i=1; i<up->probe_sent; i++)
	{
	  if(warts_udpprobe_probe_params(up->probes[i], &pN_ups[i-1]) != 0)
	    goto done;
	  len += pN_ups[i-1].len;
	  pN_urc += up->probes[i]->replyc;
	}
      if(pN_urc > 0)
	{
	  pN_urs = malloc_zero(sizeof(warts_udpprobe_reply_t) * pN_urc);
	  if(pN_urs == NULL)
	    goto done;
	  x = 0;
	  for(i=1; i<up->probe_sent; i++)
	    {
	      probe = up->probes[i];
	      for(j=0; j<probe->replyc; j++)
		{
		  if(warts_udpprobe_reply_params(probe->replies[j],
						 &pN_urs[x]) != 0)
		    goto done;
		  len += pN_urs[x].len;
		  x++;
		}
	    }
	}
    }

  /* Allocate memory to store all of the data (including packets) */
  if((buf = malloc_zero(len)) == NULL)
    goto done;
  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_UDPPROBE);

  if(warts_udpprobe_params_write(up, sf, buf, &off, len, flags, flags_len,
				 params_len) != 0)
    {
      goto done;
    }

  if(p0 != NULL)
    {
      for(i=0; i<p0->replyc; i++)
	warts_udpprobe_reply_write(p0->replies[i], buf, &off, len, &p0_urs[i]);
    }

  if(up->probe_sent > 1)
    {
      for(i=1; i<up->probe_sent; i++)
	warts_udpprobe_probe_write(up->probes[i], buf, &off, len, &pN_ups[i-1]);
      if(pN_urc > 0)
	{
	  x = 0;
	  for(i=1; i<up->probe_sent; i++)
	    {
	      probe = up->probes[i];
	      for(j=0; j<probe->replyc; j++)
		{
		  warts_udpprobe_reply_write(probe->replies[j],
					     buf, &off, len, &pN_urs[x]);
		  x++;
		}
	    }
	}
    }

  assert(off == len);

  if(warts_write(sf, buf, len, p) == -1)
    goto done;

  rc = 0;

 done:
  if(p0_urs != NULL) free(p0_urs);
  if(pN_urs != NULL) free(pN_urs);
  if(pN_ups != NULL) free(pN_ups);
  if(buf != NULL) free(buf);
  return rc;
}
