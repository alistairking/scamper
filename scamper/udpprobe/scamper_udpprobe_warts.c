/*
 * scamper_udpprobe_warts.c
 *
 * Copyright (C) 2023 The Regents of the University of California
 *
 * Author: Matthew Luckie
 *
 * $Id: scamper_udpprobe_warts.c,v 1.3 2023/11/22 21:53:57 mjl Exp $
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
#define WARTS_UDPPROBE_SPORT           6
#define WARTS_UDPPROBE_DPORT           7
#define WARTS_UDPPROBE_START           8
#define WARTS_UDPPROBE_TIMEOUT         9
#define WARTS_UDPPROBE_FLAGS           10
#define WARTS_UDPPROBE_STOP            11
#define WARTS_UDPPROBE_LEN             12
#define WARTS_UDPPROBE_DATA            13
#define WARTS_UDPPROBE_REPLYC          14

static const warts_var_t udpprobe_vars[] =
{
  {WARTS_UDPPROBE_LIST,         4},
  {WARTS_UDPPROBE_CYCLE,        4},
  {WARTS_UDPPROBE_USERID,       4},
  {WARTS_UDPPROBE_SRC,         -1},
  {WARTS_UDPPROBE_DST,         -1},
  {WARTS_UDPPROBE_SPORT,        2},
  {WARTS_UDPPROBE_DPORT,        2},
  {WARTS_UDPPROBE_START,        8},
  {WARTS_UDPPROBE_TIMEOUT,      4},
  {WARTS_UDPPROBE_FLAGS,        1},
  {WARTS_UDPPROBE_STOP,         1},
  {WARTS_UDPPROBE_LEN,          2},
  {WARTS_UDPPROBE_DATA,        -1},
  {WARTS_UDPPROBE_REPLYC,       1},
};
#define udpprobe_vars_mfb WARTS_VAR_MFB(udpprobe_vars)

#define WARTS_UDPPROBE_REPLY_TV        1
#define WARTS_UDPPROBE_REPLY_LEN       2
#define WARTS_UDPPROBE_REPLY_DATA      3

static const warts_var_t udpprobe_reply_vars[] =
{
  {WARTS_UDPPROBE_REPLY_TV,     8},
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
      if((var->id == WARTS_UDPPROBE_REPLY_TV && timeval_iszero(&ur->tv)) ||
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
    {&ur->tv,   (wpr_t)extract_timeval,       NULL},
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
    {&ur->tv,   (wpw_t)insert_timeval,       NULL},
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
	 (var->id == WARTS_UDPPROBE_SPORT   && up->sport == 0) ||
	 (var->id == WARTS_UDPPROBE_DPORT   && up->dport == 0) ||
	 (var->id == WARTS_UDPPROBE_START   && timeval_iszero(&up->start)) ||
	 (var->id == WARTS_UDPPROBE_TIMEOUT && timeval_iszero(&up->wait_timeout)) ||
	 (var->id == WARTS_UDPPROBE_FLAGS   && up->flags == 0) ||
	 (var->id == WARTS_UDPPROBE_STOP    && up->stop == 0) ||
	 ((var->id == WARTS_UDPPROBE_LEN || var->id == WARTS_UDPPROBE_DATA) &&
	  (up->data == NULL || up->len == 0)) ||
	 (var->id == WARTS_UDPPROBE_REPLYC  && up->replyc == 0))
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
				      warts_state_t *state, uint8_t *buf,
				      uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&up->list,         (wpr_t)extract_list,         state},
    {&up->cycle,        (wpr_t)extract_cycle,        state},
    {&up->userid,       (wpr_t)extract_uint32,       NULL},
    {&up->src,          (wpr_t)extract_addr_static,  NULL},
    {&up->dst,          (wpr_t)extract_addr_static,  NULL},
    {&up->sport,        (wpr_t)extract_uint16,       NULL},
    {&up->dport,        (wpr_t)extract_uint16,       NULL},
    {&up->start,        (wpr_t)extract_timeval,      NULL},
    {&up->wait_timeout, (wpr_t)extract_rtt,          NULL},
    {&up->flags,        (wpr_t)extract_byte,         NULL},
    {&up->stop,         (wpr_t)extract_byte,         NULL},
    {&up->len,          (wpr_t)extract_uint16,       NULL},
    {&up->data,         (wpr_t)extract_bytes_alloc,  &up->len},
    {&up->replyc,       (wpr_t)extract_byte,         NULL},
  };
  const int handler_cnt = sizeof(handlers) / sizeof(warts_param_reader_t);
  size_t x;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  if(up->replyc > 0)
    {
      x = sizeof(scamper_udpprobe_reply_t *) * up->replyc;
      if((up->replies = malloc_zero(x)) == NULL)
	return -1;
    }

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
  warts_param_writer_t handlers[] = {
    {&list_id,            (wpw_t)insert_uint32,       NULL},
    {&cycle_id,           (wpw_t)insert_uint32,       NULL},
    {&up->userid,         (wpw_t)insert_uint32,       NULL},
    {up->src,             (wpw_t)insert_addr_static,  NULL},
    {up->dst,             (wpw_t)insert_addr_static,  NULL},
    {&up->sport,          (wpw_t)insert_uint16,       NULL},
    {&up->dport,          (wpw_t)insert_uint16,       NULL},
    {&up->start,          (wpw_t)insert_timeval,      NULL},
    {&up->wait_timeout,   (wpw_t)insert_rtt,          NULL},
    {&up->flags,          (wpw_t)insert_byte,         NULL},    
    {&up->stop,           (wpw_t)insert_byte,         NULL},
    {&up->len,            (wpw_t)insert_uint16,       NULL},
    {up->data,            (wpw_t)insert_bytes_uint16, &up_len},
    {&up->replyc,         (wpw_t)insert_byte,         NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  up->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, up->cycle, &cycle_id) == -1) return -1;

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
  uint8_t *buf = NULL;
  uint32_t i, off = 0;
  int rc = -1;

  if(warts_read(sf, &buf, hdr->len) != 0)
    goto done;

  if(buf == NULL)
    {
      *up_out = NULL;
      return 0;
    }

  if((up = scamper_udpprobe_alloc()) == NULL)
    goto done;

  if(warts_udpprobe_params_read(up, state, buf, &off, hdr->len) != 0)
    goto done;

  if(up->replyc > 0)
    {
      for(i=0; i<up->replyc; i++)
	{
	  if((up->replies[i] = scamper_udpprobe_reply_alloc()) == NULL ||
	     warts_udpprobe_reply_read(up->replies[i], buf,&off,hdr->len) != 0)
	    goto done;
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
  warts_udpprobe_reply_t *urs = NULL;
  uint8_t *buf = NULL;
  uint8_t  flags[udpprobe_vars_mfb];
  uint16_t flags_len, params_len;
  uint32_t len, off = 0;
  uint8_t i;
  int rc = -1;

  if(warts_udpprobe_params(up, flags, &flags_len, &params_len) != 0)
    goto done;
  len = 8 + flags_len + params_len + 2;

  if(up->replyc > 0)
    {
      urs = malloc_zero(sizeof(warts_udpprobe_reply_t) * up->replyc);
      if(urs == NULL)
	goto done;
      for(i=0; i<up->replyc; i++)
	{
	  if(warts_udpprobe_reply_params(up->replies[i], &urs[i]) != 0)
	    goto done;
	  len += urs[i].len;
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

  if(up->replyc > 0)
    {
      for(i=0; i<up->replyc; i++)
	warts_udpprobe_reply_write(up->replies[i], buf, &off, len, &urs[i]);
    }

  assert(off == len);

  if(warts_write(sf, buf, len, p) == -1)
    goto done;

  rc = 0;

 done:
  if(urs != NULL) free(urs);
  if(buf != NULL) free(buf);
  return rc;
}
