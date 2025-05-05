/*
 * common_http : common functions for unit testing http
 *
 * $Id: common_http.c,v 1.2 2025/04/23 09:55:03 mjl Exp $
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

int http_ok(const scamper_http_t *in, const scamper_http_t *out)
{
  assert(in != NULL);
  if(out == NULL ||
     addr_ok(in->src, out->src) != 0 ||
     addr_ok(in->dst, out->dst) != 0 ||
     in->userid != out->userid ||
     timeval_cmp(&in->start, &out->start) != 0 ||
     in->sport != out->sport ||
     in->dport != out->dport ||
     in->flags != out->flags)
    return -1;

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

static scamper_http_makefunc_t makers[] = {
  http_1,
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
