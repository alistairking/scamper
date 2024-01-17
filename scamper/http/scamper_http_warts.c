/*
 * scamper_http_warts.c
 *
 * Copyright (C) 2023-2024 The Regents of the University of California
 *
 * Author: Matthew Luckie
 *
 * $Id: scamper_http_warts.c,v 1.4 2024/01/03 03:51:42 mjl Exp $
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
#include "scamper_http.h"
#include "scamper_http_int.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_http_warts.h"
#include "utils.h"

/*
 * the bits of a http structure
 */
#define WARTS_HTTP_LIST            1
#define WARTS_HTTP_CYCLE           2
#define WARTS_HTTP_USERID          3
#define WARTS_HTTP_SRC             4
#define WARTS_HTTP_DST             5
#define WARTS_HTTP_SPORT           6
#define WARTS_HTTP_DPORT           7
#define WARTS_HTTP_START           8
#define WARTS_HTTP_STOP            9
#define WARTS_HTTP_TYPE            10
#define WARTS_HTTP_HOST            11
#define WARTS_HTTP_FILE            12
#define WARTS_HTTP_HEADERS         13
#define WARTS_HTTP_BUFC            14
#define WARTS_HTTP_HSRTT           15
#define WARTS_HTTP_FLAGS           16
#define WARTS_HTTP_MAXTIME         17

static const warts_var_t http_vars[] =
{
 {WARTS_HTTP_LIST,            4},
 {WARTS_HTTP_CYCLE,           4},
 {WARTS_HTTP_USERID,          4},
 {WARTS_HTTP_SRC,            -1},
 {WARTS_HTTP_DST,            -1},
 {WARTS_HTTP_SPORT,           2},
 {WARTS_HTTP_DPORT,           2},
 {WARTS_HTTP_START,           8},
 {WARTS_HTTP_STOP,            1},
 {WARTS_HTTP_TYPE,            1},
 {WARTS_HTTP_HOST,           -1},
 {WARTS_HTTP_FILE,           -1},
 {WARTS_HTTP_HEADERS,        -1},
 {WARTS_HTTP_BUFC,            4},
 {WARTS_HTTP_HSRTT,           4},
 {WARTS_HTTP_FLAGS,           4},
 {WARTS_HTTP_MAXTIME,         8},
};
#define http_vars_mfb WARTS_VAR_MFB(http_vars)

/*
 * the bits of a http_buf structure
 */
#define WARTS_HTTP_BUF_TYPE        1
#define WARTS_HTTP_BUF_TV          2
#define WARTS_HTTP_BUF_LEN         3
#define WARTS_HTTP_BUF_DATA        4

static const warts_var_t http_buf_vars[] =
{
 {WARTS_HTTP_BUF_TYPE,       1},
 {WARTS_HTTP_BUF_TV,         8},
 {WARTS_HTTP_BUF_LEN,        2},
 {WARTS_HTTP_BUF_DATA,      -1},
};
#define http_buf_vars_mfb WARTS_VAR_MFB(http_buf_vars)

typedef struct warts_http_buf
{
  uint8_t   flags[WARTS_VAR_MFB(http_buf_vars)];
  uint16_t  flags_len;
  uint16_t  params_len;
  uint16_t  len;
} warts_http_buf_t;

static int warts_http_headers_len(const scamper_http_t *http,
				  uint16_t *params_len)
{
  uint16_t len = 1;
  uint8_t x;
  assert(http->headerc > 0);
  for(x=0; x<http->headerc; x++)
    len += strlen(http->headers[x]) + 1;
  if(uint16_wouldwrap(*params_len, len))
    return -1;
  *params_len += len;
  return 0;
}

static void insert_http_headers(uint8_t *buf, uint32_t *off, const uint32_t len,
				const scamper_http_t *http, void *param)
{
  uint8_t x;
  assert(http->headerc > 0);
  insert_byte(buf, off, len, &http->headerc, NULL);
  for(x=0; x<http->headerc; x++)
    insert_string(buf, off, len, http->headers[x], NULL);
  return;
}

static int extract_http_headers(uint8_t *buf, uint32_t *off, const uint32_t len,
				scamper_http_t *http, void *param)
{
  uint8_t x;
  if(extract_byte(buf, off, len, &http->headerc, NULL) != 0)
    return -1;
  if((http->headers = malloc_zero(http->headerc * sizeof(char *))) == NULL)
    return -1;
  for(x=0; x<http->headerc; x++)
    if(extract_string(buf, off, len, &http->headers[x], NULL) != 0)
      return -1;
  return 0;
}

static void insert_http_buf_type(uint8_t *buf, uint32_t *off,
				 const uint32_t len,
				 const scamper_http_buf_t *htb, void *param)
{
  uint8_t u8;
  u8 = (htb->dir << 7) | htb->type;
  insert_byte(buf, off, len, &u8, NULL);
  return;
}

static int extract_http_buf_type(uint8_t *buf, uint32_t *off,
				 const uint32_t len,
				 scamper_http_buf_t *htb, void *param)
{
  uint8_t u8;
  if(extract_byte(buf, off, len, &u8, NULL) != 0)
    return -1;
  htb->dir  = (u8 >> 7);
  htb->type = (u8 & 0x7f);
  return 0;
}

static int warts_http_buf_params(const scamper_http_buf_t *htb,
				 warts_http_buf_t *state)
{
  const warts_var_t *var;
  uint16_t u16;
  int max_id = 0;
  size_t i;

  memset(state->flags, 0, http_buf_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(http_buf_vars)/sizeof(warts_var_t); i++)
    {
      var = &http_buf_vars[i];
      if((var->id == WARTS_HTTP_BUF_TYPE && htb->type == 0 && htb->dir == 0) ||
	 (var->id == WARTS_HTTP_BUF_TV && timeval_iszero(&htb->tv)) ||
	 ((var->id == WARTS_HTTP_BUF_LEN || var->id == WARTS_HTTP_BUF_DATA) &&
	  (htb->data == NULL || htb->len == 0)))
	continue;

      flag_set(state->flags, var->id, &max_id);
      if(var->id == WARTS_HTTP_BUF_DATA)
	{
	  u16 = htb->len;
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

static int warts_http_buf_read(scamper_http_buf_t *htb, const uint8_t *buf,
			       uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {htb,        (wpr_t)extract_http_buf_type, NULL},
    {&htb->tv,   (wpr_t)extract_timeval,       NULL},
    {&htb->len,  (wpr_t)extract_uint16,        NULL},
    {&htb->data, (wpr_t)extract_bytes_alloc,   &htb->len},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  return warts_params_read(buf, off, len, handlers, handler_cnt);
}

static void warts_http_buf_write(const scamper_http_buf_t *htb,
				 uint8_t *buf, uint32_t *off, uint32_t len,
				 warts_http_buf_t *state)
{
  uint16_t htb_len = htb->len;
  warts_param_writer_t handlers[] = {
    {htb,        (wpw_t)insert_http_buf_type, NULL},
    {&htb->tv,   (wpw_t)insert_timeval,       NULL},
    {&htb->len,  (wpw_t)insert_uint16,        NULL},
    {htb->data,  (wpw_t)insert_bytes_uint16,  &htb_len},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int warts_http_params(const scamper_http_t *http, uint8_t *flags,
			     uint16_t *flags_len, uint16_t *params_len)
{
  const warts_var_t *var;
  int max_id = 0;
  size_t i;

  /* Unset all flags */
  memset(flags, 0, http_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(http_vars)/sizeof(warts_var_t); i++)
    {
      var = &http_vars[i];

      if((var->id == WARTS_HTTP_LIST    && http->list == NULL) ||
	 (var->id == WARTS_HTTP_CYCLE   && http->cycle == NULL) ||
	 (var->id == WARTS_HTTP_USERID  && http->userid == 0) ||
	 (var->id == WARTS_HTTP_SRC     && http->src == NULL) ||
	 (var->id == WARTS_HTTP_DST     && http->dst == NULL) ||
	 (var->id == WARTS_HTTP_SPORT   && http->sport == 0) ||
	 (var->id == WARTS_HTTP_DPORT   &&
	  ((http->type == SCAMPER_HTTP_TYPE_HTTP  && http->dport == 80) ||
	   (http->type == SCAMPER_HTTP_TYPE_HTTPS && http->dport == 443))) ||
	 (var->id == WARTS_HTTP_START   && timeval_iszero(&http->start)) ||
	 (var->id == WARTS_HTTP_STOP    && http->stop == 0) ||
	 (var->id == WARTS_HTTP_TYPE    && http->type == 0) ||
	 (var->id == WARTS_HTTP_HEADERS && http->headerc == 0) ||
	 (var->id == WARTS_HTTP_BUFC    && http->bufc == 0) ||
	 (var->id == WARTS_HTTP_HSRTT   && timeval_iszero(&http->hsrtt)) ||
	 (var->id == WARTS_HTTP_FLAGS   && http->flags == 0) ||
	 (var->id == WARTS_HTTP_MAXTIME && timeval_iszero(&http->maxtime)))
	continue;

      /* Set the flag for the rest of the variables */
      flag_set(flags, var->id, &max_id);

      /* variables that don't have a fixed size */
      if(var->id == WARTS_HTTP_SRC)
	{
	  if(warts_addr_size_static(http->src, params_len) != 0)
	    return -1;
	}
      else if(var->id == WARTS_HTTP_DST)
	{
	  if(warts_addr_size_static(http->dst, params_len) != 0)
	    return -1;
	}
      else if(var->id == WARTS_HTTP_HOST)
	{
	  if(warts_str_size(http->host, params_len) != 0)
	    return -1;
	}
      else if(var->id == WARTS_HTTP_FILE)
	{
	  if(warts_str_size(http->file, params_len) != 0)
	    return -1;
	}
      else if(var->id == WARTS_HTTP_HEADERS)
	{
	  if(warts_http_headers_len(http, params_len) != 0)
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

static int warts_http_params_read(scamper_http_t *http, warts_state_t *state,
				  uint8_t *buf, uint32_t *off, uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&http->list,         (wpr_t)extract_list,         state},
    {&http->cycle,        (wpr_t)extract_cycle,        state},
    {&http->userid,       (wpr_t)extract_uint32,       NULL},
    {&http->src,          (wpr_t)extract_addr_static,  NULL},
    {&http->dst,          (wpr_t)extract_addr_static,  NULL},
    {&http->sport,        (wpr_t)extract_uint16,       NULL},
    {&http->dport,        (wpr_t)extract_uint16,       NULL},
    {&http->start,        (wpr_t)extract_timeval,      NULL},
    {&http->stop,         (wpr_t)extract_byte,         NULL},
    {&http->type,         (wpr_t)extract_byte,         NULL},
    {&http->host,         (wpr_t)extract_string,       NULL},
    {&http->file,         (wpr_t)extract_string,       NULL},
    {&http,               (wpr_t)extract_http_headers, NULL},
    {&http->bufc,         (wpr_t)extract_uint32,       NULL},
    {&http->hsrtt,        (wpr_t)extract_rtt,          NULL},
    {&http->flags,        (wpr_t)extract_uint32,       NULL},
    {&http->maxtime,      (wpr_t)extract_timeval,      NULL},
  };
  const int handler_cnt = sizeof(handlers) / sizeof(warts_param_reader_t);
  uint32_t o = *off;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    return -1;

  if(http->bufc > 0 &&
     (http->bufs=malloc_zero(sizeof(scamper_http_buf_t *)*http->bufc)) == NULL)
    return -1;

  if(flag_isset(&buf[o], WARTS_HTTP_DPORT) == 0)
    {
      if(http->type == SCAMPER_HTTP_TYPE_HTTPS)
	http->dport = 443;
      else if(http->type == SCAMPER_HTTP_TYPE_HTTP)
	http->dport = 80;
      else
	return -1;
    }

  return 0;
}

static int warts_http_params_write(const scamper_http_t *http,
				   const scamper_file_t *sf,
				   uint8_t *buf, uint32_t *off,
				   const uint32_t len, const uint8_t *flags,
				   const uint16_t flags_len,
				   const uint16_t params_len)
{
  uint32_t list_id, cycle_id;
  warts_param_writer_t handlers[] = {
    {&list_id,            (wpw_t)insert_uint32,       NULL},
    {&cycle_id,           (wpw_t)insert_uint32,       NULL},
    {&http->userid,       (wpw_t)insert_uint32,       NULL},
    {http->src,           (wpw_t)insert_addr_static,  NULL},
    {http->dst,           (wpw_t)insert_addr_static,  NULL},
    {&http->sport,        (wpw_t)insert_uint16,       NULL},
    {&http->dport,        (wpw_t)insert_uint16,       NULL},
    {&http->start,        (wpw_t)insert_timeval,      NULL},
    {&http->stop,         (wpw_t)insert_byte,         NULL},
    {&http->type,         (wpw_t)insert_byte,         NULL},
    {http->host,          (wpw_t)insert_string,       NULL},
    {http->file,          (wpw_t)insert_string,       NULL},
    {http,                (wpw_t)insert_http_headers, NULL},
    {&http->bufc,         (wpw_t)insert_uint32,       NULL},
    {&http->hsrtt,        (wpw_t)insert_rtt,          NULL},
    {&http->flags,        (wpw_t)insert_uint32,       NULL},
    {&http->maxtime,      (wpw_t)insert_timeval,      NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  http->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, http->cycle, &cycle_id) == -1) return -1;

  warts_params_write(buf, off, len, flags, flags_len, params_len, handlers,
		     handler_cnt);
  return 0;
}

int scamper_file_warts_http_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				 scamper_http_t **http_out)
{
  warts_state_t *state = scamper_file_getstate(sf);
  scamper_http_t *http = NULL;
  uint8_t *buf = NULL;
  uint32_t i, off = 0;
  int rc = -1;

  if(warts_read(sf, &buf, hdr->len) != 0)
    goto done;

  if(buf == NULL)
    {
      *http_out = NULL;
      return 0;
    }

  if((http = scamper_http_alloc()) == NULL)
    goto done;

  if(warts_http_params_read(http, state, buf, &off, hdr->len) != 0)
    goto done;

  if(http->bufc > 0)
    {
      for(i=0; i<http->bufc; i++)
	{
	  if((http->bufs[i] = scamper_http_buf_alloc()) == NULL ||
	     warts_http_buf_read(http->bufs[i], buf, &off, hdr->len) != 0)
	    goto done;
	}
    }

  *http_out = http; http = NULL;
  rc = 0;

 done:
  if(buf != NULL) free(buf);
  if(http != NULL) scamper_http_free(http);
  return rc;
}

int scamper_file_warts_http_write(const scamper_file_t *sf,
				  const scamper_http_t *http, void *p)
{
  warts_http_buf_t *htbs = NULL;
  uint8_t *buf = NULL;
  uint8_t  flags[http_vars_mfb];
  uint16_t flags_len, params_len;
  uint32_t i, len, off = 0;
  int rc = -1;

  if(warts_http_params(http, flags, &flags_len, &params_len) != 0)
    goto done;
  len = 8 + flags_len + params_len + 2;

  if(http->bufc > 0)
    {
      if((htbs = malloc_zero(sizeof(warts_http_buf_t) * http->bufc)) == NULL)
	goto done;
      for(i=0; i<http->bufc; i++)
	{
	  if(warts_http_buf_params(http->bufs[i], &htbs[i]) != 0)
	    goto done;
	  len += htbs[i].len;
	}
    }

  /* Allocate memory to store all of the data (including packets) */
  if((buf = malloc_zero(len)) == NULL)
    goto done;
  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_HTTP);

  if(warts_http_params_write(http, sf, buf, &off, len, flags, flags_len,
			     params_len) != 0)
    {
      goto done;
    }

  if(http->bufc > 0)
    {
      for(i=0; i<http->bufc; i++)
	warts_http_buf_write(http->bufs[i], buf, &off, len, &htbs[i]);
    }

  assert(off == len);

  /* Write the whole buffer to a warts file */
  if(warts_write(sf, buf, len, p) == -1)
    goto done;

  rc = 0;

 done:
  if(htbs != NULL) free(htbs);
  if(buf != NULL) free(buf);
  return rc;
}
