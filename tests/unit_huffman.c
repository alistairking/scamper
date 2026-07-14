/*
 * unit_base64 : unit tests for base64 functions
 *
 * $Id: unit_huffman.c,v 1.3 2026/05/14 08:31:42 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2026 Matthew Luckie
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

#include "mjl_huffman.h"
#include "common.h"

typedef struct sc_test
{
  char    *huffman;
  char    *decoded;
} sc_test_t;

static int decode_check(const huffman_t *hf,
			const char *huff_str, const char *cmp_str)
{
  size_t cmp_len, huff_len, off = 0;
  uint8_t *dec_buf = NULL, *huff_buf = NULL;
  int rc = -1;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

  cmp_len = strlen(cmp_str);
  if(hex2buf(huff_str, &huff_buf, &huff_len) != 0 ||
     (dec_buf = malloc(cmp_len)) == NULL ||
     huffman_decode(hf, huff_buf, huff_len, dec_buf, &off, cmp_len) != 0 ||
     off != cmp_len ||
     strncmp((const char *)dec_buf, cmp_str, cmp_len) != 0)
    goto done;

  if(huff_buf != NULL)
    {
      free(huff_buf);
      huff_buf = NULL;
    }
  if(dec_buf != NULL)
    {
      free(dec_buf);
      dec_buf = NULL;
    }

  rc = 0;

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(start_mem != stop_mem)
    {
      printf("decode memory leak\n");
      goto done;
    }
#endif

 done:
  if(dec_buf != NULL) free(dec_buf);
  if(huff_buf != NULL) free(huff_buf);
  return rc;
}

int main(int argc, char *argv[])
{
  /* first 12 from RFC7541 appendix C */
  sc_test_t tests[] = {
    {"f1e3c2e5f23a6ba0ab90f4ff", "www.example.com"},
    {"a8eb10649cbf", "no-cache"},
    {"25a849e95ba97d7f", "custom-key"},
    {"25a849e95bb8e8b4bf", "custom-value"},
    {"6402", "302"},
    {"aec3771a4b", "private"},
    {"d07abe941054d444a8200595040b8166e082a62d1bff",
     "Mon, 21 Oct 2013 20:13:21 GMT"},
    {"9d29ad171863c78f0b97c8e9ae82ae43d3", "https://www.example.com"},
    {"640eff", "307"},
    {"d07abe941054d444a8200595040b8166e084a62d1bff",
     "Mon, 21 Oct 2013 20:13:22 GMT"},
    {"9bd9ab", "gzip"},
    {"94e7821dd7f2e6c7b335dfdfcd5b3960"
     "d5af27087f3672c1ab270fb5291f9587"
     "316065c003ed4ee5b1063d5007",
     "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  huffman_t *hf;
  huffman_entry_t rfc7541_dict[256] = RFC7541_DICT;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

  if((hf = huffman_alloc(rfc7541_dict)) == NULL)
    return -1;

  for(i=0; i<testc; i++)
    if(decode_check(hf, tests[i].huffman, tests[i].decoded) != 0)
      break;
  if(i != testc)
    {
      printf("decode test %d failed\n", (int)i);
      return -1;
    }

  huffman_free(hf);

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(start_mem != stop_mem)
    {
      printf("memory leak\n");
      return -1;
    }
#endif
  
  printf("OK\n");
  return 0;
}
