/*
 * scamper_host_warts.c
 *
 * Copyright (C) 2019-2023 Matthew Luckie
 *
 * Author: Matthew Luckie
 *
 * $Id: scamper_host_warts.c,v 1.19 2024/04/27 21:04:41 mjl Exp $
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
#include "scamper_host.h"
#include "scamper_host_int.h"
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_host_warts.h"
#include "utils.h"

/*
 * the bits of a host structure
 */
#define WARTS_HOST_LIST            1
#define WARTS_HOST_CYCLE           2
#define WARTS_HOST_USERID          3
#define WARTS_HOST_SRC             4
#define WARTS_HOST_DST             5
#define WARTS_HOST_START           6
#define WARTS_HOST_FLAGS           7
#define WARTS_HOST_WAIT            8
#define WARTS_HOST_STOP            9
#define WARTS_HOST_RETRIES         10
#define WARTS_HOST_QTYPE           11
#define WARTS_HOST_QCLASS          12
#define WARTS_HOST_QNAME           13
#define WARTS_HOST_QCOUNT          14

static const warts_var_t host_vars[] =
{
  {WARTS_HOST_LIST,            4},
  {WARTS_HOST_CYCLE,           4},
  {WARTS_HOST_USERID,          4},
  {WARTS_HOST_SRC,            -1},
  {WARTS_HOST_DST,            -1},
  {WARTS_HOST_START,           8},
  {WARTS_HOST_FLAGS,           2},
  {WARTS_HOST_WAIT,            2},
  {WARTS_HOST_STOP,            1},
  {WARTS_HOST_RETRIES,         1},
  {WARTS_HOST_QTYPE,           2},
  {WARTS_HOST_QCLASS,          2},
  {WARTS_HOST_QNAME,          -1},
  {WARTS_HOST_QCOUNT,          1},
};
#define host_vars_mfb WARTS_VAR_MFB(host_vars)

/*
 * the bits of a host query structure
 */
#define WARTS_HOST_QUERY_TX        1
#define WARTS_HOST_QUERY_RX        2
#define WARTS_HOST_QUERY_ID        3
#define WARTS_HOST_QUERY_ANCOUNT   4
#define WARTS_HOST_QUERY_NSCOUNT   5
#define WARTS_HOST_QUERY_ARCOUNT   6
#define WARTS_HOST_QUERY_RCODE     7
#define WARTS_HOST_QUERY_FLAGS     8

static const warts_var_t host_query_vars[] =
{
 {WARTS_HOST_QUERY_TX,        8},
 {WARTS_HOST_QUERY_RX,        8},
 {WARTS_HOST_QUERY_ID,        2},
 {WARTS_HOST_QUERY_ANCOUNT,   2},
 {WARTS_HOST_QUERY_NSCOUNT,   2},
 {WARTS_HOST_QUERY_ARCOUNT,   2},
 {WARTS_HOST_QUERY_RCODE,     1},
 {WARTS_HOST_QUERY_FLAGS,     1},
};
#define host_query_vars_mfb WARTS_VAR_MFB(host_query_vars)

/*
 * the bits of a host rr structure
 */
#define WARTS_HOST_RR_CLASS         1
#define WARTS_HOST_RR_TYPE          2
#define WARTS_HOST_RR_NAME          3
#define WARTS_HOST_RR_TTL           4
#define WARTS_HOST_RR_DATA          5

static const warts_var_t host_rr_vars[] =
{
 {WARTS_HOST_RR_CLASS,        2},
 {WARTS_HOST_RR_TYPE,         2},
 {WARTS_HOST_RR_NAME,        -1},
 {WARTS_HOST_RR_TTL,          4},
 {WARTS_HOST_RR_DATA,        -1},
};
#define host_rr_vars_mfb WARTS_VAR_MFB(host_rr_vars)

/*
 * the bits of a rr_mx structure
 */
#define WARTS_HOST_RR_MX_PREFERENCE 1
#define WARTS_HOST_RR_MX_EXCHANGE   2

static const warts_var_t host_rr_mx_vars[] =
{
 {WARTS_HOST_RR_MX_PREFERENCE,  2},
 {WARTS_HOST_RR_MX_EXCHANGE,   -1},
};
#define host_rr_mx_vars_mfb WARTS_VAR_MFB(host_rr_mx_vars)

/*
 * the bits of a rr_soa structure
 */
#define WARTS_HOST_RR_SOA_MNAME     1
#define WARTS_HOST_RR_SOA_RNAME     2
#define WARTS_HOST_RR_SOA_SERIAL    3
#define WARTS_HOST_RR_SOA_REFRESH   4
#define WARTS_HOST_RR_SOA_RETRY     5
#define WARTS_HOST_RR_SOA_EXPIRE    6
#define WARTS_HOST_RR_SOA_MINIMUM   7

static const warts_var_t host_rr_soa_vars[] =
{
 {WARTS_HOST_RR_SOA_MNAME,   -1},
 {WARTS_HOST_RR_SOA_RNAME,   -1},
 {WARTS_HOST_RR_SOA_SERIAL,   4},
 {WARTS_HOST_RR_SOA_REFRESH,  4},
 {WARTS_HOST_RR_SOA_RETRY,    4},
 {WARTS_HOST_RR_SOA_EXPIRE,   4},
 {WARTS_HOST_RR_SOA_MINIMUM,  4},
};
#define host_rr_soa_vars_mfb WARTS_VAR_MFB(host_rr_soa_vars)

/*
 * the bits of a rr_txt structure
 */
#define WARTS_HOST_RR_TXT_STRC      1
#define WARTS_HOST_RR_TXT_STRS      2

static const warts_var_t host_rr_txt_vars[] =
{
  {WARTS_HOST_RR_TXT_STRC,    2},
  {WARTS_HOST_RR_TXT_STRS,   -1},
};
#define host_rr_txt_vars_mfb WARTS_VAR_MFB(host_rr_txt_vars)

typedef struct warts_host_query
{
  uint8_t   flags[WARTS_VAR_MFB(host_query_vars)];
  uint16_t  flags_len;
  uint16_t  params_len;
  uint32_t  len;
} warts_host_query_t;

typedef struct warts_host_rr_mx
{
  uint8_t   flags[WARTS_VAR_MFB(host_rr_mx_vars)];
  uint16_t  flags_len;
  uint16_t  params_len;
  uint16_t  len;
} warts_host_rr_mx_t;

typedef struct warts_host_rr_soa
{
  uint8_t   flags[WARTS_VAR_MFB(host_rr_soa_vars)];
  uint16_t  flags_len;
  uint16_t  params_len;
  uint16_t  len;
} warts_host_rr_soa_t;

typedef struct warts_host_rr_txt
{
  uint8_t   flags[WARTS_VAR_MFB(host_rr_txt_vars)];
  uint16_t  flags_len;
  uint16_t  params_len;
  uint16_t  len;
} warts_host_rr_txt_t;

typedef struct warts_host_rr
{
  uint8_t   flags[WARTS_VAR_MFB(host_rr_vars)];
  uint16_t  flags_len;
  uint16_t  params_len;
  uint32_t  len;

  scamper_host_rr_t *rr;
  uint16_t  data_type;
  union
  {
    warts_host_rr_soa_t *soa;
    warts_host_rr_mx_t  *mx;
    warts_host_rr_txt_t *txt;
    void                *v;
  } data_un;
} warts_host_rr_t;

typedef struct warts_host_rr_read
{
  int       type;
  void     *data;
} warts_host_rr_read_t;

static void warts_host_query_params(const scamper_host_query_t *query,
				    warts_host_query_t *state)
{
  const warts_var_t *var;
  int max_id = 0;
  size_t i;

  memset(state->flags, 0, host_query_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(host_query_vars)/sizeof(warts_var_t); i++)
    {
      var = &host_query_vars[i];
      if((var->id == WARTS_HOST_QUERY_TX &&
	  query->tx.tv_sec == 0 && query->tx.tv_usec == 0) ||
	 (var->id == WARTS_HOST_QUERY_RX &&
	  query->rx.tv_sec == 0 && query->rx.tv_usec == 0) ||
	 (var->id == WARTS_HOST_QUERY_ID      && query->id == 0) ||
	 (var->id == WARTS_HOST_QUERY_ANCOUNT && query->ancount == 0) ||
	 (var->id == WARTS_HOST_QUERY_NSCOUNT && query->nscount == 0) ||
	 (var->id == WARTS_HOST_QUERY_ARCOUNT && query->arcount == 0) ||
	 (var->id == WARTS_HOST_QUERY_RCODE   && query->rcode == 0) ||
	 (var->id == WARTS_HOST_QUERY_FLAGS   && query->flags == 0))
	continue;
      flag_set(state->flags, var->id, &max_id);
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len = fold_flags(state->flags, max_id);
  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;
  return;
}

static int warts_host_query_read(scamper_host_query_t *query,
				 const uint8_t *buf, uint32_t *off,
				 uint32_t len)
{
  warts_param_reader_t handlers[] = {
    {&query->tx,      (wpr_t)extract_timeval, NULL},
    {&query->rx,      (wpr_t)extract_timeval, NULL},
    {&query->id,      (wpr_t)extract_uint16,  NULL},
    {&query->ancount, (wpr_t)extract_uint16,  NULL},
    {&query->nscount, (wpr_t)extract_uint16,  NULL},
    {&query->arcount, (wpr_t)extract_uint16,  NULL},
    {&query->rcode,   (wpr_t)extract_byte,    NULL},
    {&query->flags,   (wpr_t)extract_byte,    NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto err;
  return 0;

 err:
  return -1;
}

static void warts_host_query_write(const scamper_host_query_t *query,
				   uint8_t *buf, uint32_t *off, uint32_t len,
				   warts_host_query_t *state)
{
  warts_param_writer_t handlers[] = {
    {&query->tx,      (wpw_t)insert_timeval, NULL},
    {&query->rx,      (wpw_t)insert_timeval, NULL},
    {&query->id,      (wpw_t)insert_uint16,  NULL},
    {&query->ancount, (wpw_t)insert_uint16,  NULL},
    {&query->nscount, (wpw_t)insert_uint16,  NULL},
    {&query->arcount, (wpw_t)insert_uint16,  NULL},
    {&query->rcode,   (wpw_t)insert_byte,    NULL},
    {&query->flags,   (wpw_t)insert_byte,    NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int warts_host_rr_mx_params(const scamper_host_rr_mx_t *mx,
				   warts_host_rr_mx_t *state)
{
  const warts_var_t *var;
  int max_id = 0;
  size_t i;

  memset(state->flags, 0, host_rr_mx_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(host_rr_mx_vars)/sizeof(warts_var_t); i++)
    {
      var = &host_rr_mx_vars[i];
      if((var->id == WARTS_HOST_RR_MX_PREFERENCE && mx->preference == 0) ||
	 (var->id == WARTS_HOST_RR_MX_EXCHANGE && mx->exchange == NULL))
	continue;
      flag_set(state->flags, var->id, &max_id);

      if(var->id == WARTS_HOST_RR_MX_EXCHANGE)
	{
	  if(warts_str_size(mx->exchange, &state->params_len) != 0)
	    return -1;
	  continue;
	}
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len += fold_flags(state->flags, max_id);
  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;
  return 0;
}

static int warts_host_rr_mx_read(void **data, const uint8_t *buf,
				 uint32_t *off, uint32_t len)
{
  scamper_host_rr_mx_t *mx = NULL;
  uint16_t preference = 0;
  char *exchange = NULL;
  warts_param_reader_t handlers[] = {
    {&preference, (wpr_t)extract_uint16, NULL},
    {&exchange,   (wpr_t)extract_string, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto err;
  if(exchange == NULL)
    goto err;
  if((mx = scamper_host_rr_mx_alloc(preference, exchange)) == NULL)
    goto err;
  free(exchange);
  *data = mx;
  return 0;

 err:
  if(exchange != NULL) free(exchange);
  return -1;
}

static void warts_host_rr_mx_write(scamper_host_rr_mx_t *mx, uint8_t *buf,
				   uint32_t *off, uint32_t len,
				   warts_host_rr_mx_t *state)
{
  warts_param_writer_t handlers[] = {
    {&mx->preference, (wpw_t)insert_uint16, NULL},
    {mx->exchange,    (wpw_t)insert_string, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int warts_host_rr_soa_params(const scamper_host_rr_soa_t *soa,
				    warts_host_rr_soa_t *state)
{
  const warts_var_t *var;
  int max_id = 0;
  size_t i;

  memset(state->flags, 0, host_rr_soa_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(host_rr_soa_vars)/sizeof(warts_var_t); i++)
    {
      var = &host_rr_soa_vars[i];
      if((var->id == WARTS_HOST_RR_SOA_MNAME   && soa->mname == NULL) ||
	 (var->id == WARTS_HOST_RR_SOA_RNAME   && soa->mname == NULL) ||
	 (var->id == WARTS_HOST_RR_SOA_SERIAL  && soa->serial == 0) ||
	 (var->id == WARTS_HOST_RR_SOA_REFRESH && soa->refresh == 0) ||
	 (var->id == WARTS_HOST_RR_SOA_RETRY   && soa->retry == 0) ||
	 (var->id == WARTS_HOST_RR_SOA_EXPIRE  && soa->expire == 0) ||
	 (var->id == WARTS_HOST_RR_SOA_MINIMUM && soa->minimum == 0))
	continue;

      flag_set(state->flags, var->id, &max_id);
      if(var->id == WARTS_HOST_RR_SOA_MNAME)
	{
	  if(warts_str_size(soa->mname, &state->params_len) != 0)
	    return -1;
	  continue;
	}
      else if(var->id == WARTS_HOST_RR_SOA_RNAME)
	{
	  if(warts_str_size(soa->rname, &state->params_len) != 0)
	    return -1;
	  continue;
	}
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len += fold_flags(state->flags, max_id);
  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;
  return 0;
}

static int warts_host_rr_soa_read(void **data,
				  const uint8_t *buf, uint32_t *off,
				  uint32_t len)
{
  scamper_host_rr_soa_t *soa = NULL;
  char *mname = NULL, *rname = NULL;
  uint32_t serial = 0, refresh = 0, retry = 0, expire = 0, minimum = 0;
  warts_param_reader_t handlers[] = {
    {&mname,   (wpr_t)extract_string, NULL},
    {&rname,   (wpr_t)extract_string, NULL},
    {&serial,  (wpr_t)extract_uint32, NULL},
    {&refresh, (wpr_t)extract_uint32, NULL},
    {&retry,   (wpr_t)extract_uint32, NULL},
    {&expire,  (wpr_t)extract_uint32, NULL},
    {&minimum, (wpr_t)extract_uint32, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  int rc = -1;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto done;
  if(mname == NULL || rname == NULL)
    goto done;
  if((soa = scamper_host_rr_soa_alloc(mname, rname)) == NULL)
    goto done;
  soa->serial = serial;
  soa->refresh = refresh;
  soa->retry = retry;
  soa->expire = expire;
  soa->minimum = minimum;
  *data = soa;
  rc = 0;

 done:
  if(mname != NULL) free(mname);
  if(rname != NULL) free(rname);
  return rc;
}

static void warts_host_rr_soa_write(scamper_host_rr_soa_t *soa,
				    uint8_t *buf, uint32_t *off, uint32_t len,
				    warts_host_rr_soa_t *state)
{
  warts_param_writer_t handlers[] = {
    {soa->mname,    (wpw_t)insert_string, NULL},
    {soa->rname,    (wpw_t)insert_string, NULL},
    {&soa->serial,  (wpw_t)insert_uint32, NULL},
    {&soa->refresh, (wpw_t)insert_uint32, NULL},
    {&soa->retry,   (wpw_t)insert_uint32, NULL},
    {&soa->expire,  (wpw_t)insert_uint32, NULL},
    {&soa->minimum, (wpw_t)insert_uint32, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int txt_strs_size(const scamper_host_rr_txt_t *txt, uint16_t *len)
{
  size_t s = 0, x;
  uint16_t i;
  for(i=0; i<txt->strc; i++)
    {
      if((x = strlen(txt->strs[i])) >= 256)
	return -1;
      s += 1 + x;
    }
  if(s > UINT16_MAX || uint16_wouldwrap(*len, (uint16_t)s))
    return -1;
  *len += (uint16_t)s;
  return 0;
}

static void txt_strs_insert(uint8_t *buf, uint32_t *off, const uint32_t len,
			    const scamper_host_rr_txt_t *txt, void *param)
{
  size_t size;
  uint16_t i;
  for(i=0; i<txt->strc; i++)
    {
      size = strlen(txt->strs[i]); assert(size < 256);
      buf[(*off)++] = (uint8_t)size;
      if(size > 0)
	{
	  memcpy(&buf[*off], txt->strs[i], size);
	  *off += size;
	}
    }
  return;
}

static int txt_strs_extract(const uint8_t *buf, uint32_t *off,
			    const uint32_t len,
			    scamper_host_rr_txt_t *txt, void *param)
{
  size_t size;
  uint16_t i;

  if(*off >= len)
    return -1;

  if((txt->strs = malloc_zero(txt->strc * sizeof(char *))) == NULL)
    return -1;
  for(i=0; i<txt->strc; i++)
    {
      size = buf[(*off)++];
      if(len - *off < size)
	return -1;
      if((txt->strs[i] = malloc(size+1)) == NULL)
	return -1;
      memcpy(txt->strs[i], &buf[*off], size);
      txt->strs[i][size] = '\0';
      *off += size;
    }

  return 0;
}

static int warts_host_rr_txt_params(const scamper_host_rr_txt_t *txt,
				    warts_host_rr_txt_t *state)
{
  const warts_var_t *var;
  int max_id = 0;
  size_t i;

  memset(state->flags, 0, host_rr_txt_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(host_rr_txt_vars)/sizeof(warts_var_t); i++)
    {
      var = &host_rr_txt_vars[i];
      if((var->id == WARTS_HOST_RR_TXT_STRC && txt->strc == 0) ||
	 (var->id == WARTS_HOST_RR_TXT_STRS && txt->strc == 0))
	continue;

      flag_set(state->flags, var->id, &max_id);
      if(var->id == WARTS_HOST_RR_TXT_STRS)
	{
	  if(txt_strs_size(txt, &state->params_len) != 0)
	    return -1;
	  continue;
	}
      assert(var->size >= 0);
      state->params_len += var->size;
    }

  state->flags_len += fold_flags(state->flags, max_id);
  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;
  return 0;
}

static int warts_host_rr_txt_read(void **data,
				  const uint8_t *buf, uint32_t *off,
				  uint32_t len)
{
  scamper_host_rr_txt_t *txt = NULL;
  warts_param_reader_t handlers[] = {
    {NULL, (wpr_t)extract_uint16,   NULL}, /* strc */
    {NULL, (wpr_t)txt_strs_extract, NULL}, /* strs */
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);

  if((txt = scamper_host_rr_txt_alloc(0)) == NULL)
    goto err;
  handlers[0].data = &txt->strc;
  handlers[1].data = txt;

  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto err;

  *data = txt;
  return 0;

 err:
  if(txt != NULL) scamper_host_rr_txt_free(txt);
  return -1;
}

static void warts_host_rr_txt_write(scamper_host_rr_txt_t *txt,
				    uint8_t *buf, uint32_t *off, uint32_t len,
				    warts_host_rr_txt_t *state)
{
  warts_param_writer_t handlers[] = {
    {&txt->strc,     (wpw_t)insert_uint16,   NULL},
    {txt,            (wpw_t)txt_strs_insert, NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
  warts_params_write(buf, off, len, state->flags, state->flags_len,
		     state->params_len, handlers, handler_cnt);
  return;
}

static int extract_rrdata(const uint8_t *buf, uint32_t *off, uint32_t len,
			  warts_host_rr_read_t *rrdata,
			  warts_addrtable_t *table)
{
  uint16_t type;

  if(extract_uint16(buf, off, len, &type, NULL) != 0)
    return -1;

  rrdata->type = type;
  if(type == SCAMPER_HOST_RR_DATA_TYPE_ADDR)
    {
      if(extract_addr(buf, off, len,
		      (scamper_addr_t **)&rrdata->data, table) != 0)
	return -1;
      return 0;
    }
  else if(type == SCAMPER_HOST_RR_DATA_TYPE_STR)
    {
      if(extract_string(buf, off, len, (char **)&rrdata->data, NULL) != 0)
	return -1;
      return 0;
    }
  else if(type == SCAMPER_HOST_RR_DATA_TYPE_SOA)
    {
      if(warts_host_rr_soa_read(&rrdata->data, buf, off, len) != 0)
	return -1;
      return 0;
    }
  else if(type == SCAMPER_HOST_RR_DATA_TYPE_MX)
    {
      if(warts_host_rr_mx_read(&rrdata->data, buf, off, len) != 0)
	return -1;
      return 0;
    }
  else if(type == SCAMPER_HOST_RR_DATA_TYPE_TXT)
    {
      if(warts_host_rr_txt_read(&rrdata->data, buf, off, len) != 0)
	return -1;
      return 0;
    }
  return -1;
}

static void insert_rrdata(uint8_t *buf, uint32_t *off, const uint32_t len,
			  const warts_host_rr_t *rr,
			  warts_addrtable_t *table)
{
  insert_uint16(buf, off, len, &rr->data_type, NULL);

  if(rr->data_type == SCAMPER_HOST_RR_DATA_TYPE_ADDR)
    insert_addr(buf, off, len, rr->rr->un.addr, table);
  else if(rr->data_type == SCAMPER_HOST_RR_DATA_TYPE_STR)
    insert_string(buf, off, len, rr->rr->un.str, NULL);
  else if(rr->data_type == SCAMPER_HOST_RR_DATA_TYPE_SOA)
    warts_host_rr_soa_write(rr->rr->un.soa, buf, off, len, rr->data_un.soa);
  else if(rr->data_type == SCAMPER_HOST_RR_DATA_TYPE_MX)
    warts_host_rr_mx_write(rr->rr->un.mx, buf, off, len, rr->data_un.mx);
  else if(rr->data_type == SCAMPER_HOST_RR_DATA_TYPE_TXT)
    warts_host_rr_txt_write(rr->rr->un.txt, buf, off, len, rr->data_un.txt);

  return;
}

static int warts_host_rr_data_len(const scamper_host_rr_t *rr,
				  warts_host_rr_t *state,
				  warts_addrtable_t *table,
				  uint16_t *params_len)
{
  uint16_t len = 2;
  int x;

  x = scamper_host_rr_data_type(rr->class, rr->type);
  assert(x == SCAMPER_HOST_RR_DATA_TYPE_ADDR ||
	 x == SCAMPER_HOST_RR_DATA_TYPE_STR ||
	 x == SCAMPER_HOST_RR_DATA_TYPE_SOA ||
	 x == SCAMPER_HOST_RR_DATA_TYPE_MX  ||
	 x == SCAMPER_HOST_RR_DATA_TYPE_TXT);

  state->data_type = (uint16_t)x;
  state->rr = (scamper_host_rr_t *)rr;
  if(state->data_type == SCAMPER_HOST_RR_DATA_TYPE_ADDR)
    {
      if(warts_addr_size(table, rr->un.addr, &len) != 0)
	return -1;
    }
  else if(state->data_type == SCAMPER_HOST_RR_DATA_TYPE_STR)
    {
      if(warts_str_size(rr->un.str, &len) != 0)
	return -1;
    }
  else if(state->data_type == SCAMPER_HOST_RR_DATA_TYPE_SOA)
    {
      if((state->data_un.soa=malloc_zero(sizeof(warts_host_rr_soa_t))) == NULL)
	return -1;
      warts_host_rr_soa_params(rr->un.soa, state->data_un.soa);
      if(uint16_wouldwrap(len, state->data_un.soa->len))
	return -1;
      len += state->data_un.soa->len;
    }
  else if(state->data_type == SCAMPER_HOST_RR_DATA_TYPE_MX)
    {
      if((state->data_un.mx=malloc_zero(sizeof(warts_host_rr_mx_t))) == NULL)
	return -1;
      warts_host_rr_mx_params(rr->un.mx, state->data_un.mx);
      if(uint16_wouldwrap(len, state->data_un.mx->len))
	return -1;
      len += state->data_un.mx->len;
    }
  else if(state->data_type == SCAMPER_HOST_RR_DATA_TYPE_TXT)
    {
      if((state->data_un.txt=malloc_zero(sizeof(warts_host_rr_txt_t))) == NULL)
	return -1;
      warts_host_rr_txt_params(rr->un.txt, state->data_un.txt);
      if(uint16_wouldwrap(len, state->data_un.txt->len))
	return -1;
      len += state->data_un.txt->len;
    }
  else return -1;

  if(uint16_wouldwrap(*params_len, len))
    return -1;
  *params_len += len;
  return 0;
}

static int warts_host_rr_params(const scamper_host_rr_t *rr,
				warts_host_rr_t *state,
				warts_addrtable_t *table)
{
  const warts_var_t *var;
  int max_id = 0;
  size_t i;

  memset(state->flags, 0, host_rr_vars_mfb);
  state->params_len = 0;

  for(i=0; i<sizeof(host_rr_vars)/sizeof(warts_var_t); i++)
    {
      var = &host_rr_vars[i];
      if((var->id == WARTS_HOST_RR_CLASS && rr->class == 0) ||
	 (var->id == WARTS_HOST_RR_TYPE  && rr->type == 0) ||
	 (var->id == WARTS_HOST_RR_NAME  && rr->name == NULL) ||
	 (var->id == WARTS_HOST_RR_TTL   && rr->ttl == 0) ||
	 (var->id == WARTS_HOST_RR_DATA  && rr->un.v == NULL))
	continue;

      flag_set(state->flags, var->id, &max_id);
      if(var->id == WARTS_HOST_RR_NAME)
	{
	  if(warts_str_size(rr->name, &state->params_len) != 0)
	    return -1;
	}
      else if(var->id == WARTS_HOST_RR_DATA)
	{
	  if(warts_host_rr_data_len(rr, state, table, &state->params_len) != 0)
	    return -1;
	}
      else
	{
	  state->params_len += var->size;
	}
    }

  state->flags_len += fold_flags(state->flags, max_id);
  state->len = state->flags_len + state->params_len;
  if(state->params_len != 0)
    state->len += 2;
  return 0;
}

static int warts_host_rr_read(scamper_host_rr_t **rr, int i,
			      const uint8_t *buf, uint32_t *off,
			      uint32_t len, warts_addrtable_t *table)
{
  uint16_t class, type;
  uint32_t ttl;
  char *name = NULL;
  warts_host_rr_read_t rrdata;
  warts_param_reader_t handlers[] = {
    {&class, (wpr_t)extract_uint16, NULL},
    {&type,  (wpr_t)extract_uint16, NULL},
    {&name,  (wpr_t)extract_string, NULL},
    {&ttl,   (wpr_t)extract_uint32, NULL},
    {&rrdata,(wpr_t)extract_rrdata, table},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_reader_t);
  int rc = -1;

  rrdata.type = -1; rrdata.data = NULL;
  if(warts_params_read(buf, off, len, handlers, handler_cnt) != 0)
    goto done;

  /* sanity check the stored RR */
  if(name == NULL)
    goto done;
  if(rrdata.data != NULL &&
     (rrdata.type == -1 ||
      rrdata.type != scamper_host_rr_data_type(class, type)))
    goto done;

  if((rr[i] = scamper_host_rr_alloc(name, class, type, ttl)) == NULL)
    goto done;
  rr[i]->un.v = rrdata.data; rrdata.data = NULL;
  rc = 0;

 done:
  if(name != NULL) free(name);
  if(rrdata.data != NULL)
    {
      if(rrdata.type == SCAMPER_HOST_RR_DATA_TYPE_ADDR)
	scamper_addr_free(rrdata.data);
      else if(rrdata.type == SCAMPER_HOST_RR_DATA_TYPE_STR)
	free(rrdata.data);
      else if(rrdata.type == SCAMPER_HOST_RR_DATA_TYPE_SOA)
	scamper_host_rr_soa_free(rrdata.data);
      else if(rrdata.type == SCAMPER_HOST_RR_DATA_TYPE_MX)
	scamper_host_rr_mx_free(rrdata.data);
      else if(rrdata.type == SCAMPER_HOST_RR_DATA_TYPE_TXT)
	scamper_host_rr_txt_free(rrdata.data);
    }
  return rc;
}

static void warts_host_rr_write(scamper_host_rr_t *rr, uint8_t *buf,
				uint32_t *off, uint32_t len,
				warts_host_rr_t *state,
				warts_addrtable_t *table)
{
   warts_param_writer_t handlers[] = {
     {&rr->class, (wpw_t)insert_uint16, NULL},
     {&rr->type,  (wpw_t)insert_uint16, NULL},
     {rr->name,   (wpw_t)insert_string, NULL},
     {&rr->ttl,   (wpw_t)insert_uint32, NULL},
     {state,      (wpw_t)insert_rrdata, table},
   };
   const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);
   warts_params_write(buf, off, len, state->flags, state->flags_len,
		      state->params_len, handlers, handler_cnt);
   return;
}

static int warts_host_params(const scamper_host_t *host,
			     warts_addrtable_t *table, uint8_t *flags,
			     uint16_t *flags_len, uint16_t *params_len)
{
  const warts_var_t *var;
  int max_id = 0;
  size_t i;

  /* Unset all flags */
  memset(flags, 0, host_vars_mfb);
  *params_len = 0;

  for(i=0; i<sizeof(host_vars)/sizeof(warts_var_t); i++)
    {
      var = &host_vars[i];

      if((var->id == WARTS_HOST_LIST    && host->list == NULL) ||
	 (var->id == WARTS_HOST_CYCLE   && host->cycle == NULL) ||
	 (var->id == WARTS_HOST_USERID  && host->userid == 0) ||
	 (var->id == WARTS_HOST_SRC     && host->src == NULL) ||
	 (var->id == WARTS_HOST_DST     && host->dst == NULL) ||
	 (var->id == WARTS_HOST_FLAGS   && host->flags == 0) ||
	 (var->id == WARTS_HOST_WAIT && timeval_iszero(&host->wait_timeout)) ||
	 (var->id == WARTS_HOST_STOP    && host->stop == 0) ||
	 (var->id == WARTS_HOST_RETRIES && host->retries == 0) ||
	 (var->id == WARTS_HOST_QTYPE   && host->qtype == 0) ||
	 (var->id == WARTS_HOST_QCLASS  && host->qclass == 0) ||
	 (var->id == WARTS_HOST_QNAME   && host->qname == NULL) ||
	 (var->id == WARTS_HOST_QCOUNT  && host->qcount == 0))
	continue;

      /* Set the flag for the rest of the variables */
      flag_set(flags, var->id, &max_id);

      /* Variables that don't have a fixed size */
      if(var->id == WARTS_HOST_SRC)
	{
	  if(warts_addr_size(table, host->src, params_len) != 0)
	    return -1;
	}
      else if(var->id == WARTS_HOST_DST)
	{
	  if(warts_addr_size(table, host->dst, params_len) != 0)
	    return -1;
	}
      else if(var->id == WARTS_HOST_QNAME)
	{
	  if(warts_str_size(host->qname, params_len) != 0)
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

static int warts_host_params_read(scamper_host_t *host,
				  warts_addrtable_t *table,
				  warts_state_t *state,
				  uint8_t *buf, uint32_t *off, uint32_t len)
{
  uint16_t wait = 0;
  warts_param_reader_t handlers[] = {
    {&host->list,         (wpr_t)extract_list,    state},
    {&host->cycle,        (wpr_t)extract_cycle,   state},
    {&host->userid,       (wpr_t)extract_uint32,  NULL},
    {&host->src,          (wpr_t)extract_addr,    table},
    {&host->dst,          (wpr_t)extract_addr,    table},
    {&host->start,        (wpr_t)extract_timeval, NULL},
    {&host->flags,        (wpr_t)extract_uint16,  NULL},
    {&wait,               (wpr_t)extract_uint16,  NULL},
    {&host->stop,         (wpr_t)extract_byte,    NULL},
    {&host->retries,      (wpr_t)extract_byte,    NULL},
    {&host->qtype,        (wpr_t)extract_uint16,  NULL},
    {&host->qclass,       (wpr_t)extract_uint16,  NULL},
    {&host->qname,        (wpr_t)extract_string,  NULL},
    {&host->qcount,       (wpr_t)extract_byte,    NULL},
  };
  const int handler_cnt = sizeof(handlers) / sizeof(warts_param_reader_t);
  int rc;

  if((rc = warts_params_read(buf, off, len, handlers, handler_cnt)) != 0)
    return rc;
  if(host->dst == NULL)
    return -1;

  host->wait_timeout.tv_sec = wait / 1000;
  host->wait_timeout.tv_usec = ((wait % 1000) * 1000);

  return 0;
}

static int warts_host_params_write(const scamper_host_t *host,
				   const scamper_file_t *sf,
				   warts_addrtable_t *table,
				   uint8_t *buf, uint32_t *off,
				   const uint32_t len, const uint8_t *flags,
				   const uint16_t flags_len,
				   const uint16_t params_len)
{
  uint32_t list_id, cycle_id;
  uint16_t wait;
  warts_param_writer_t handlers[] = {
    {&list_id,            (wpw_t)insert_uint32,   NULL},
    {&cycle_id,           (wpw_t)insert_uint32,   NULL},
    {&host->userid,       (wpw_t)insert_uint32,   NULL},
    {host->src,           (wpw_t)insert_addr,     table},
    {host->dst,           (wpw_t)insert_addr,     table},
    {&host->start,        (wpw_t)insert_timeval,  NULL},
    {&host->flags,        (wpw_t)insert_uint16,   NULL},
    {&wait,               (wpw_t)insert_uint16,   NULL},
    {&host->stop,         (wpw_t)insert_byte,     NULL},
    {&host->retries,      (wpw_t)insert_byte,     NULL},
    {&host->qtype,        (wpw_t)insert_uint16,   NULL},
    {&host->qclass,       (wpw_t)insert_uint16,   NULL},
    {host->qname,         (wpw_t)insert_string,   NULL},
    {&host->qcount,       (wpw_t)insert_byte,     NULL},
  };
  const int handler_cnt = sizeof(handlers)/sizeof(warts_param_writer_t);

  if(warts_list_getid(sf,  host->list,  &list_id)  == -1) return -1;
  if(warts_cycle_getid(sf, host->cycle, &cycle_id) == -1) return -1;

  wait =
    (host->wait_timeout.tv_sec * 1000) + (host->wait_timeout.tv_usec / 1000);

  warts_params_write(buf, off, len, flags, flags_len, params_len,
		     handlers, handler_cnt);

  return 0;
}

int scamper_file_warts_host_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				 scamper_host_t **host_out)
{
  scamper_host_t *host = NULL;
  scamper_host_query_t *query;
  warts_addrtable_t *table = NULL;
  warts_state_t *state = scamper_file_getstate(sf);
  uint8_t *buf = NULL;
  uint32_t off = 0, i, j;

  if(warts_read(sf, &buf, hdr->len) != 0)
    goto err;

  if(buf == NULL)
    {
      *host_out = NULL;
      return 0;
    }

  if((host = scamper_host_alloc()) == NULL)
    goto err;

  if((table = warts_addrtable_alloc_byid()) == NULL)
    goto err;

  if(warts_host_params_read(host, table, state, buf, &off, hdr->len) != 0)
    goto err;

  if(host->qcount > 0)
    {
      if(scamper_host_queries_alloc(host, host->qcount) != 0)
	goto err;
      for(i=0; i<host->qcount; i++)
	{
	  if((host->queries[i] = query = scamper_host_query_alloc()) == NULL)
	    goto err;
	  if(warts_host_query_read(query, buf, &off, hdr->len) != 0)
	    goto err;
	  if(scamper_host_query_rr_alloc(query) != 0)
	    goto err;
	  for(j=0; j<query->ancount; j++)
	    if(warts_host_rr_read(query->an, j, buf,&off,hdr->len, table) != 0)
	      goto err;
	  for(j=0; j<query->nscount; j++)
	    if(warts_host_rr_read(query->ns, j, buf,&off,hdr->len, table) != 0)
	      goto err;
	  for(j=0; j<query->arcount; j++)
	    if(warts_host_rr_read(query->ar, j, buf,&off,hdr->len, table) != 0)
	      goto err;
	}
    }

  warts_addrtable_free(table);
  *host_out = host;
  free(buf);
  return 0;

 err:
  if(table != NULL) warts_addrtable_free(table);
  if(buf != NULL) free(buf);
  if(host != NULL) scamper_host_free(host);
  return -1;
}

int scamper_file_warts_host_write(const scamper_file_t *sf,
				  const scamper_host_t *host, void *p)
{
  scamper_host_query_t *query;
  warts_addrtable_t *table = NULL;
  warts_host_query_t *query_state = NULL;
  warts_host_rr_t *rr_state = NULL;
  uint8_t *buf = NULL;
  uint8_t  flags[host_vars_mfb];
  uint16_t flags_len, params_len;
  uint32_t len, i, j, r = 0, rrc = 0, off = 0;
  size_t size;

  if((table = warts_addrtable_alloc_byaddr()) == NULL)
    goto err;

  if(warts_host_params(host, table, flags, &flags_len, &params_len) != 0)
    goto err;
  len = 8 + flags_len + params_len + 2;

  if(host->qcount > 0)
    {
      /* figure out how many resource records there are */
      for(i=0; i<host->qcount; i++)
	{
	  query = host->queries[i];
	  rrc += (query->ancount + query->nscount + query->arcount);
	}

      size = host->qcount * sizeof(warts_host_query_t);
      if((query_state = (warts_host_query_t *)malloc_zero(size)) == NULL)
	goto err;

      if(rrc > 0)
	{
	  size = rrc * sizeof(warts_host_rr_t);
	  if((rr_state = (warts_host_rr_t *)malloc_zero(size)) == NULL)
	    goto err;
	}

      for(i=0; i<host->qcount; i++)
	{
	  query = host->queries[i];
	  warts_host_query_params(query, &query_state[i]);
	  len += query_state[i].len;
	  for(j=0; j<query->ancount; j++)
	    {
	      if(warts_host_rr_params(query->an[j], &rr_state[r], table) != 0)
		goto err;
	      len += rr_state[r].len;
	      r++;
	    }
	  for(j=0; j<query->nscount; j++)
	    {
	      if(warts_host_rr_params(query->ns[j], &rr_state[r], table) != 0)
		goto err;
	      len += rr_state[r].len;
	      r++;
	    }
	  for(j=0; j<query->arcount; j++)
	    {
	      if(warts_host_rr_params(query->ar[j], &rr_state[r], table) != 0)
		goto err;
	      len += rr_state[r].len;
	      r++;
	    }
	}
      assert(r == rrc);
    }

  /* Allocate memory to store all of the data (including packets) */
  if((buf = malloc_zero(len)) == NULL)
    goto err;
  insert_wartshdr(buf, &off, len, SCAMPER_FILE_OBJ_HOST);

  if(warts_host_params_write(host, sf, table, buf, &off, len,
			     flags, flags_len, params_len) != 0)
    {
      goto err;
    }

  if(host->qcount > 0)
    {
      r = 0;
      for(i=0; i<host->qcount; i++)
	{
	  query = host->queries[i];
	  warts_host_query_write(query, buf, &off, len, &query_state[i]);
	  for(j=0; j<query->ancount; j++)
	    warts_host_rr_write(query->an[j], buf, &off, len,
				&rr_state[r++], table);
	  for(j=0; j<query->nscount; j++)
	    warts_host_rr_write(query->ns[j], buf, &off, len,
				&rr_state[r++], table);
	  for(j=0; j<query->arcount; j++)
	    warts_host_rr_write(query->ar[j], buf, &off, len,
				&rr_state[r++], table);
	}
      free(query_state); query_state = NULL;
      for(i=0; i<r; i++)
	if(rr_state[i].data_un.v != NULL)
	  free(rr_state[i].data_un.v);
      free(rr_state); rr_state = NULL;
    }

  assert(off == len);

  /* Write the whole buffer to a warts file */
  if(warts_write(sf, buf, len, p) == -1)
    goto err;

  warts_addrtable_free(table);
  free(buf);
  return 0;

err:
  if(query_state != NULL) free(query_state);
  if(rr_state != NULL) free(rr_state);
  if(table != NULL) warts_addrtable_free(table);
  if(buf != NULL) free(buf);
  return -1;
}
