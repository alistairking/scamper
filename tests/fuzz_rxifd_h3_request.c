/*
 * fuzz_rxifd_h3_request : fuzzer for quic_h3_request in sc_rxifd
 *
 * $Id: fuzz_rxifd_h3_request.c,v 1.2 2026/05/24 22:41:51 mjl Exp $
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

char       *quic_url         = "/index.html";
size_t      quic_urllen      = 11;
huffman_t  *quic_huff        = NULL;
size_t      quic_hdr_maxsize = 8192;

void quic_h3_request(sc_quicstream_t *qs);

void quic_h3_reply(sc_quicstream_t *qs, int status)
{
  return;
}

int main(int argc, char *argv[])
{
  huffman_entry_t rfc7541_dict[256] = RFC7541_DICT;
  struct stat sb;
  uint8_t *buf = NULL;
  size_t readc, len;
  int rc = -1, fd = -1;
  sc_quicstream_t qs;

  memset(&qs, 0, sizeof(qs));

  if(argc < 2 ||
     (quic_huff = huffman_alloc(rfc7541_dict)) == NULL ||
     (fd = open(argv[1], O_RDONLY)) == -1 ||
     fstat(fd, &sb) != 0)
    goto done;
  len = sb.st_size;
  if((buf = malloc(len)) == NULL ||
     read_wrap(fd, buf, &readc, len) != 0 || readc != len)
    goto done;

  qs.buf = buf; buf = NULL;
  qs.len = len;
  quic_h3_request(&qs);

  rc = 0;

 done:
  if(quic_huff != NULL) huffman_free(quic_huff);
  if(fd != -1) close(fd);
  if(buf != NULL) free(buf);
  if(qs.buf != NULL) free(qs.buf);
  return rc;
}
