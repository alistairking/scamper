/*
 * common_http : common functions for unit testing http
 *
 * $Id: common_http.c,v 1.6 2026/03/30 01:14:14 mjl Exp $
 *
 *        Marcus Luckie, Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024 Marcus Luckie
 * Copyright (C) 2024-2025 Matthew Luckie
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

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_file.h"
#include "scamper_http.h"
#include "scamper_http_int.h"
#include "common_ok.h"
#include "common_http.h"
#include "utils.h"

typedef scamper_http_t * (*scamper_http_makefunc_t)(void);

static int http_buf_ok(const scamper_http_buf_t *in,
		       const scamper_http_buf_t *out)
{
  if(in == NULL || out == NULL ||
     in->dir != out->dir ||
     in->type != out->type ||
     in->len != out->len ||
     timeval_cmp(&in->tv, &out->tv) != 0 ||
     buf_ok(in->data, out->data, in->len) != 0)
    return -1;
  return 0;
}

int http_ok(const scamper_http_t *in, const scamper_http_t *out)
{
  uint32_t u32;
  uint8_t u8;

  assert(in != NULL);
  if(out == NULL ||
     in->userid != out->userid ||
     addr_ok(in->src, out->src) != 0 ||
     addr_ok(in->dst, out->dst) != 0 ||
     in->sport != out->sport ||
     in->dport != out->dport ||
     in->flags != out->flags ||
     timeval_cmp(&in->start, &out->start) != 0 ||
     timeval_cmp(&in->hsrtt, &out->hsrtt) != 0 ||
     timeval_cmp(&in->maxtime, &out->maxtime) != 0 ||
     str_ok(in->host, out->host) != 0 ||
     str_ok(in->file, out->file) != 0 ||
     in->ech_config_list_len != out->ech_config_list_len ||
     buf_ok(in->ech_config_list, out->ech_config_list,
	    in->ech_config_list_len) != 0 ||
     str_ok(in->errmsg, out->errmsg) != 0 ||
     in->stop != out->stop ||
     in->type != out->type ||
     in->ech_status != out->ech_status ||
     str_ok(in->ech_outer_sni, out->ech_outer_sni) != 0 ||
     in->ech_retry_config_len != out->ech_retry_config_len ||
     buf_ok(in->ech_retry_config, out->ech_retry_config,
	    in->ech_retry_config_len) != 0 ||
     in->headerc != out->headerc ||
     in->bufc != out->bufc)
    return -1;

  if(in->headerc > 0)
    {
      if(in->headers == NULL || out->headers == NULL)
	return -1;
      for(u8=0; u8<in->headerc; u8++)
	if(str_ok(in->headers[u8], out->headers[u8]) != 0)
	  return -1;
    }

  if(in->bufc > 0)
    {
      if(in->bufs == NULL || out->bufs == NULL)
	return -1;
      for(u32=0; u32<in->bufc; u32++)
	if(http_buf_ok(in->bufs[u32], out->bufs[u32]) != 0)
	  return -1;
    }

  return 0;
}

static scamper_http_t *http_1(void)
{
  scamper_http_t *http = NULL;

  if((http = scamper_http_alloc()) == NULL ||
     (http->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (http->dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL)
    goto err;

  http->userid               = 69;
  http->sport                = 120;
  http->dport                = 443;
  http->start.tv_sec         = 1724828853;
  http->start.tv_usec        = 123456;
  http->flags                = 0;
  http->stop = SCAMPER_HTTP_STOP_DONE;
  http->type = SCAMPER_HTTP_TYPE_HTTPS;
  http->host = strdup("www.example.org");
  http->file = strdup("/index.html");
  return http;

 err:
  if(http != NULL) scamper_http_free(http);
  return NULL;
}

static scamper_http_t *http_2(void)
{
  scamper_http_t *http = NULL;

  if((http = scamper_http_alloc()) == NULL ||
     (http->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (http->dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL ||
     (http->errmsg = strdup("hello world")) == NULL)
    goto err;

  http->userid               = 70;
  http->sport                = 120;
  http->dport                = 443;
  http->start.tv_sec         = 1724828853;
  http->start.tv_usec        = 123456;
  http->flags                = 0;
  http->stop = SCAMPER_HTTP_STOP_ERROR;
  http->type = SCAMPER_HTTP_TYPE_HTTPS;
  http->host = strdup("www.example.org");
  http->file = strdup("/index.html");
  return http;

 err:
  if(http != NULL) scamper_http_free(http);
  return NULL;
}

static scamper_http_t *http_3(void)
{
  scamper_http_t *http = NULL;
  size_t len;

  if((http = scamper_http_alloc()) == NULL ||
     (http->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (http->dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL)
    goto err;

  http->userid               = 70;
  http->sport                = 120;
  http->dport                = 443;
  http->start.tv_sec         = 1724828853;
  http->start.tv_usec        = 123456;
  http->flags                = SCAMPER_HTTP_FLAG_GREASE;
  http->stop                 = SCAMPER_HTTP_STOP_DONE;
  http->type                 = SCAMPER_HTTP_TYPE_HTTPS;
  http->host                 = strdup("www.example.org");
  http->file                 = strdup("/index.html");
  http->ech_status           = SCAMPER_HTTP_ECH_STATUS_GREASE_ECH;

  if(base64_decode((const uint8_t *)"Zm9vYmFy",
		   &http->ech_retry_config, &len) != 0)
    goto err;
  http->ech_retry_config_len = len;

  return http;

 err:
  if(http != NULL) scamper_http_free(http);
  return NULL;
}

static scamper_http_t *http_4(void)
{
  scamper_http_t *http = NULL;
  size_t len;

  if((http = scamper_http_alloc()) == NULL ||
     (http->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (http->dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL)
    goto err;

  http->userid               = 70;
  http->sport                = 120;
  http->dport                = 443;
  http->start.tv_sec         = 1724828853;
  http->start.tv_usec        = 123456;
  http->flags                = 0;
  http->stop                 = SCAMPER_HTTP_STOP_DONE;
  http->type                 = SCAMPER_HTTP_TYPE_HTTPS;
  http->host                 = strdup("www.example.org");
  http->file                 = strdup("/index.html");
  http->ech_status           = SCAMPER_HTTP_ECH_STATUS_SUCCESS;
  http->ech_outer_sni        = strdup("www.example.org");

  if(base64_decode((const uint8_t *)"Zm9vYmFy",
		   &http->ech_config_list, &len) != 0)
    goto err;
  http->ech_config_list_len = len;

  return http;

 err:
  if(http != NULL) scamper_http_free(http);
  return NULL;
}

static scamper_http_t *http_5(void)
{
  scamper_http_t *http = NULL;
  size_t len;

  if((http = scamper_http_alloc()) == NULL ||
     (http->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (http->dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL)
    goto err;

  http->userid               = 70;
  http->sport                = 120;
  http->dport                = 443;
  http->start.tv_sec         = 1724828853;
  http->start.tv_usec        = 123456;
  http->flags                = 0;
  http->stop                 = SCAMPER_HTTP_STOP_DONE;
  http->type                 = SCAMPER_HTTP_TYPE_HTTPS;
  http->host                 = strdup("www.example.org");
  http->file                 = strdup("/index.html");
  http->ech_status           = SCAMPER_HTTP_ECH_STATUS_FAILED_ECH;
  http->ech_outer_sni        = strdup("www.example.org");

  if(base64_decode((const uint8_t *)"Zm9vYmE=",
		   &http->ech_retry_config, &len) != 0)
    goto err;
  http->ech_retry_config_len = len;
  if(base64_decode((const uint8_t *)"Zm9vYmFy",
		   &http->ech_config_list, &len) != 0)
    goto err;
  http->ech_config_list_len = len;

  return http;

 err:
  if(http != NULL) scamper_http_free(http);
  return NULL;
}

static scamper_http_makefunc_t makers[] = {
  http_1,
  http_2,
  http_3,
  http_4,
  http_5,
};

scamper_http_t *http_makers(size_t i)
{
  if(i >= sizeof(makers) / sizeof(scamper_http_makefunc_t))
    return NULL;
  return makers[i]();
}

size_t http_makerc(void)
{
  return sizeof(makers) / sizeof(scamper_http_makefunc_t);
}
