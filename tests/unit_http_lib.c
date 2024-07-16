/*
 * unit_http_lib: unit tests for http library
 *
 * $Id: unit_http_lib.c,v 1.3 2024/03/04 19:36:41 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2023 The Regents of the University of California
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
#include "scamper_http.h"
#include "scamper_http_int.h"
#include "utils.h"

static scamper_http_buf_t *htb_make(uint8_t dir, uint8_t type,
				    const char *data, uint16_t len)
{
  scamper_http_buf_t *htb;

  if((htb = scamper_http_buf_alloc()) == NULL ||
     (htb->data = memdup(data, len)) == NULL)
    goto err;
  htb->dir = dir;
  htb->type = type;
  htb->len = len;
  return htb;

 err:
  if(htb != NULL) scamper_http_buf_free(htb);
  return NULL;
}

static scamper_http_t *test_chunked_build(const char *input, size_t len,
					  size_t *offs, size_t offc)
{
  scamper_http_t *http = NULL;
  const char *hdr = "HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n";
  size_t off, i;

  if((http = scamper_http_alloc()) == NULL ||
     (http->bufs=malloc_zero((sizeof(scamper_http_buf_t *) * (offc+2))))==NULL)
    goto err;
  http->bufc = offc + 2;

  if((http->bufs[0] = htb_make(SCAMPER_HTTP_BUF_DIR_RX,
			       SCAMPER_HTTP_BUF_TYPE_HDR,
			       hdr, strlen(hdr))) == NULL)
    goto err;

  off = 0;
  for(i=0; i<offc; i++)
    {
      if((http->bufs[1+i] = htb_make(SCAMPER_HTTP_BUF_DIR_RX,
				     SCAMPER_HTTP_BUF_TYPE_DATA,
				     input + off, offs[i] - off)) == NULL)
	goto err;
      off = offs[i];
    }
  if((http->bufs[offc+1] = htb_make(SCAMPER_HTTP_BUF_DIR_RX,
				    SCAMPER_HTTP_BUF_TYPE_DATA,
				    input + off, len - off)) == NULL)
    goto err;

  return http;

 err:
  if(http != NULL) scamper_http_free(http);
  return NULL;
}

static int test_chunked(void)
{
  const char *chunked = "10\r\n0123456789abcdef\r\n5\r\nedcba\r\n0\r\n";
  const char *out = "0123456789abcdefedcba";
  scamper_http_t *http = NULL;
  size_t offs[2];
  uint8_t buf[21];
  size_t i, j, len, chunked_len = strlen(chunked);

  for(i=1; i<chunked_len-2; i++)
    {
      offs[0] = i;
      for(j=i+1; j<chunked_len-1; j++)
	{
	  offs[1] = j;

	  if((http = test_chunked_build(chunked,chunked_len,offs,2)) == NULL ||
	     scamper_http_rx_data_len_get(http, &len) != 0 ||
	     len != sizeof(buf) ||
	     scamper_http_rx_data_get(http, buf, sizeof(buf)) != 0 ||
	     memcmp(buf, out, sizeof(buf)) != 0)
	    goto err;

	  scamper_http_free(http); http = NULL;
	}
    }

  return 0;

 err:
  if(http != NULL) scamper_http_free(http);
  return -1;
}

int main(int argc, char *argv[])
{
  static int (* const tests[])(void) = {
    test_chunked,
  };
  size_t i, testc = sizeof(tests) / sizeof(void *);

  for(i=0; i<testc; i++)
    if(tests[i]() != 0)
      break;

  if(i != testc)
    return -1;

  printf("OK\n");
  return 0;
}
