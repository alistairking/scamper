/*
 * unit_http_lib: unit tests for http library
 *
 * $Id: unit_http_lib.c,v 1.4 2025/02/27 07:37:00 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2023-2025 The Regents of the University of California
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

static int test_rxhdr(void)
{
  scamper_http_t *http = NULL;
  scamper_http_hdr_fields_t *rxhdrs = NULL;
  scamper_http_hdr_field_t *field;
  const char *name, *value, *hdr =
    "HTTP/1.1 200 OK\r\n"
    "Transfer-Encoding: Chunked\r\n"
    "Server:X \r\n"
    "Malformed\r\n"
    "Bad:\r\n"
    "Bad2:  \r\n"
    "Foo:   bar  \n"
    "\r\n";

  if((http = scamper_http_alloc()) == NULL ||
     (http->bufs = malloc_zero((sizeof(scamper_http_buf_t *) * 1))) == NULL ||
     (http->bufs[0] = htb_make(SCAMPER_HTTP_BUF_DIR_RX,
			       SCAMPER_HTTP_BUF_TYPE_HDR,
			       hdr, strlen(hdr))) == NULL)
    return -1;
  http->bufc = 1;

  if((rxhdrs = scamper_http_rx_hdr_fields_get(http)) == NULL ||
     scamper_http_hdr_fields_count_get(rxhdrs) != 3 ||
     (field = scamper_http_hdr_fields_get(rxhdrs, 0)) == NULL ||
     (name = scamper_http_hdr_field_name_get(field)) == NULL ||
     (value = scamper_http_hdr_field_value_get(field)) == NULL ||
     strcmp(name, "Transfer-Encoding") != 0 || strcmp(value, "Chunked") != 0 ||
     (field = scamper_http_hdr_fields_get(rxhdrs, 1)) == NULL ||
     (name = scamper_http_hdr_field_name_get(field)) == NULL ||
     (value = scamper_http_hdr_field_value_get(field)) == NULL ||
     strcmp(name, "Server") != 0 || strcmp(value, "X") != 0 ||
     (field = scamper_http_hdr_fields_get(rxhdrs, 2)) == NULL ||
     (name = scamper_http_hdr_field_name_get(field)) == NULL ||
     (value = scamper_http_hdr_field_value_get(field)) == NULL ||
     strcmp(name, "Foo") != 0 || strcmp(value, "bar") != 0)
    return -1;

  scamper_http_hdr_fields_free(rxhdrs);
  scamper_http_free(http);

  return 0;
}

int main(int argc, char *argv[])
{
  static int (* const tests[])(void) = {
    test_chunked,
    test_rxhdr,
  };
  size_t i, testc = sizeof(tests) / sizeof(void *);

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
#endif

  for(i=0; i<testc; i++)
    {
#ifdef DMALLOC
      dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem,
			NULL, NULL, NULL, NULL);
#endif

      if(tests[i]() != 0)
	{
	  printf("test %d failed\n", (int)i);
	  break;
	}

#ifdef DMALLOC
      dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem,
			NULL, NULL, NULL, NULL);
      if(start_mem != stop_mem)
	{
	  printf("memory leak: %d\n", (int)i);
	  break;
	}
#endif
    }

  if(i != testc)
    return -1;

  printf("OK\n");
  return 0;
}
