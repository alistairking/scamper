/*
 * unit_rxifd_h3_request : unit tests h3_request in sc_rxifd
 *
 * $Id: unit_rxifd_h3_request.c,v 1.2 2026/05/24 22:41:51 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2026 The Regents of the University of California
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

#include "utils.h"
#include "mjl_list.h"
#include "mjl_huffman.h"
#include "sc_rxifd.h"

#include "common.h"

typedef struct sc_test
{
  char    *request;
  char    *path;
  int      http_code;
} sc_test_t;

char       *quic_url         = NULL;
size_t      quic_urllen      = 0;
huffman_t  *quic_huff        = NULL;
size_t      quic_hdr_maxsize = 8192;
static int  reply_status     = 0;

void quic_h3_request(sc_quicstream_t *qs);

void quic_h3_reply(sc_quicstream_t *qs, int status)
{
  reply_status = status;
  return;
}

static int check(const char *request, char *path, int http_code)
{
  sc_quicstream_t qs;
  uint8_t *dec_buf = NULL;
  size_t len;
  int rc = -1;

  quic_url = path;
  quic_urllen = strlen(path);
  reply_status = 0;

  memset(&qs, 0, sizeof(qs));

  if(hex2buf(request, &dec_buf, &len) != 0)
    goto done;
  qs.buf = dec_buf; dec_buf = NULL;
  qs.len = len;
  quic_h3_request(&qs);
  if(reply_status != http_code)
    {
      printf("reply status %d\n", reply_status);
      goto done;
    }
  rc = 0;

 done:
  if(qs.buf != NULL)
    free(qs.buf);
  if(dec_buf != NULL)
    free(dec_buf);
  return rc;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    /* huffman encoded request from curl for /rxif */
    {"012a0000d1d75092ac64ea398abc9eaa92a42e7b26b8db4d34cf"
     "518462cf26975f508825b650c3cb85a5c3dd",
     "/rxif",
     200,
    },
    /* huffman encoded request from curl for /rxif, check against /rxifd */
    {"012a0000d1d75092ac64ea398abc9eaa92a42e7b26b8db4d34cf"
     "518462cf26975f508825b650c3cb85a5c3dd",
     "/rxifd",
     404,
    },
    /* request from curl for / with special :path: / of c1 */
    {"01250000d1d75092ac64ea398abc9eaa92a42e7b26b8db4d34cf"
     "c15f508825b650c3cb85a5c3dd",
     "/",
     200,
    },
    /*
     * literal field line with name reference, not huffman encoded
     * RFC7541 C.2.2.
     */
    {"01100000510c2f73616d706c652f70617468",
     "/sample/path",
     200,
    },
    /* literal field line with literal name, not huffman encoded */
    {"01150000253a706174680c2f73616d706c652f70617468",
     "/sample/path",
     200,
    },
    /*
     * Literal Field Line with Name Reference,
     * RFC9204 B.1.
     */
    {"010f0000510b2f696e6465782e68746d6c",
     "/index.html",
     200,
    },
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  huffman_entry_t rfc7541_dict[256] = RFC7541_DICT;
  char filename[128];

  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/h3-frame-%03x.dat", argv[2], (int)i);
	  if(dump_hex(tests[i].request, filename) != 0)
	    break;
	}
    }
  else if(argc == 1)
    {
      if((quic_huff = huffman_alloc(rfc7541_dict)) == NULL)
	return -1;
      for(i=0; i<testc; i++)
	if(check(tests[i].request, tests[i].path, tests[i].http_code) != 0)
	  break;
      huffman_free(quic_huff);
    }
  else
    {
      printf("invalid usage\n");
      return -1;
    }

  if(i != testc)
    {
      printf("test %d failed\n", (int)i);
      return -1;
    }

  printf("OK\n");
  return 0;
}
