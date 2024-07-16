/*
 * unit_http_lib: fuzz http library
 *
 * $Id: fuzz_http_lib.c,v 1.2 2024/03/04 19:36:41 mjl Exp $
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
				    const uint8_t *data, uint16_t len)
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

#ifdef FUZZ_CHUNKED
static void check(const uint8_t *buf_in, size_t len_in)
{
  scamper_http_t *http = NULL;
  const char *hdr = "HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n";
  uint8_t *buf = NULL;
  size_t len;

  if((http = scamper_http_alloc()) == NULL ||
     (http->bufs = malloc_zero((sizeof(scamper_http_buf_t *) * 2))) == NULL)
    goto done;
  http->bufc = 2;

  if((http->bufs[0] = htb_make(SCAMPER_HTTP_BUF_DIR_RX,
			       SCAMPER_HTTP_BUF_TYPE_HDR,
			       (const uint8_t *)hdr, strlen(hdr))) == NULL ||
     (http->bufs[1] = htb_make(SCAMPER_HTTP_BUF_DIR_RX,
			       SCAMPER_HTTP_BUF_TYPE_DATA,
			       buf_in, len_in)) == NULL)
    goto done;

  /*
   * even if scamper_http_rx_data_len_get determines that the data is
   * malformed, try parse it
   */
  if(scamper_http_rx_data_len_get(http, &len) != 0)
    len = len_in + 4096;

  if((buf = malloc(len)) == NULL)
    goto done;

  scamper_http_rx_data_get(http, buf, len);

 done:
  if(buf != NULL) free(buf);
  if(http != NULL) scamper_http_free(http);
  return;
}
#endif

#ifdef FUZZ_HDRS
static void check(const uint8_t *buf_in, size_t len_in)
{
  scamper_http_t *http = NULL;
  scamper_http_hdr_fields_t *hdfs = NULL;
  const char *data = "hello world\r\n";
  char *value = NULL;

  if((http = scamper_http_alloc()) == NULL ||
     (http->bufs = malloc_zero((sizeof(scamper_http_buf_t *) * 2))) == NULL)
    goto done;
  http->bufc = 2;

  if((http->bufs[0] = htb_make(SCAMPER_HTTP_BUF_DIR_RX,
			       SCAMPER_HTTP_BUF_TYPE_HDR,
			       buf_in, len_in)) == NULL ||
     (http->bufs[1] = htb_make(SCAMPER_HTTP_BUF_DIR_RX,
			       SCAMPER_HTTP_BUF_TYPE_DATA,
			       (const uint8_t *)data, strlen(data))) == NULL)
    goto done;

  hdfs = scamper_http_rx_hdr_fields_get(http);

  scamper_http_rx_hdr_name_get(http, "Transfer-Encoding", &value);

 done:
  if(value != NULL) free(value);
  if(http != NULL) scamper_http_free(http);
  if(hdfs != NULL) scamper_http_hdr_fields_free(hdfs);
  return;
}
#endif

static int input(const char *filename, uint8_t **out, size_t *len)
{
  uint8_t *buf = NULL;
  struct stat sb;
  size_t readc;
  int fd = -1;

  if((fd = open(filename, O_RDONLY)) == -1 ||
     fstat(fd, &sb) != 0)
    goto err;
  *len = sb.st_size;
  if((buf = malloc(*len)) == NULL ||
     read_wrap(fd, buf, &readc, *len) != 0 || readc != *len)
    goto err;

  close(fd);
  *out = buf;
  return 0;

 err:
  if(buf != NULL) free(buf);
  if(fd != -1) close(fd);
  return -1;
}

int main(int argc, char *argv[])
{
  uint8_t *buf = NULL;
  size_t len;

  if(argc != 2)
    {
      printf("missing input\n");
      return -1;
    }

  if(input(argv[1], &buf, &len) != 0)
    return -1;

  check(buf, len);

  if(buf != NULL)
    free(buf);

  return 0;
}
