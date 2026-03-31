/*
 * unit_base64 : unit tests for base64 functions
 *
 * $Id: unit_base64.c,v 1.6 2026/03/28 20:54:55 mjl Exp $
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

#include "common.h"
#include "utils.h"

typedef struct sc_test
{
  char    *bytes;
  char    *base64;
} sc_test_t;

static int encode_check(const char *in_str, const char *b64_str)
{
  size_t in_len, out_len, b64_len;
  uint8_t *in_buf = NULL;
  char *out_buf = NULL;
  int rc = -1;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

  b64_len = strlen(b64_str);
  if(hex2buf(in_str, &in_buf, &in_len) != 0 ||
     base64_encode(in_buf, in_len, &out_buf, &out_len) != 0 ||
     b64_len != out_len ||
     strcmp(b64_str, out_buf) != 0)
    goto done;

  if(in_buf != NULL)
    {
      free(in_buf);
      in_buf = NULL;
    }
  if(out_buf != NULL)
    {
      free(out_buf);
      out_buf = NULL;
    }

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(start_mem != stop_mem)
    {
      printf("encode memory leak\n");
      goto done;
    }
#endif

  rc = 0;

 done:
  if(in_buf != NULL) free(in_buf);
  if(out_buf != NULL) free(out_buf);
  return rc;
}

static int decode_check(const char *b64_str, const char *cmp_str)
{
  size_t cmp_len, dec_len;
  uint8_t *cmp_buf = NULL, *dec_buf = NULL;
  int rc = -1;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

  if(hex2buf(cmp_str, &cmp_buf, &cmp_len) != 0 ||
     base64_decode((const uint8_t *)b64_str, &dec_buf, &dec_len) != 0 ||
     dec_len != cmp_len ||
     memcmp(dec_buf, cmp_buf, cmp_len) != 0)
    goto done;

  if(cmp_buf != NULL)
    {
      free(cmp_buf);
      cmp_buf = NULL;
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
  if(cmp_buf != NULL) free(cmp_buf);
  return rc;
}

static int decode_bad_check(const char *b64_str)
{
  size_t dec_len = 0;
  uint8_t *dec_buf = NULL;
  int rc = -1;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

  if(base64_decode((const uint8_t *)b64_str, &dec_buf, &dec_len) == 0 ||
     dec_buf != NULL || dec_len != 0)
    goto done;

  if(dec_buf != NULL)
    {
      free(dec_buf);
      dec_buf = NULL;
    }

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(start_mem != stop_mem)
    {
      printf("decode_bad memory leak\n");
      goto done;
    }
#endif

  rc = 0;

 done:
  if(dec_buf != NULL) free(dec_buf);
  return rc;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {"66", "Zg=="},               /* f */
    {"666F", "Zm8="},             /* fo */
    {"666F6F", "Zm9v"},           /* foo */
    {"666F6F62", "Zm9vYg=="},     /* foob */
    {"666F6F6261", "Zm9vYmE="},   /* fooba */
    {"666F6F626172", "Zm9vYmFy"}, /* foobar */
    {"660FBF", "Zg+/"},
    {"FB", "+w=="},
    {"FF", "/w=="},
    {"FFE0", "/+A="},
    {"FBF7", "+/c="},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  const char *bad_tests[] = {
    "Z===",
    "Z;==",
    "Z=9v",
  };
  size_t bad_testc = sizeof(bad_tests) / sizeof(const char *);

  for(i=0; i<testc; i++)
    if(encode_check(tests[i].bytes, tests[i].base64) != 0)
      break;
  if(i != testc)
    {
      printf("encode test %d failed\n", (int)i);
      return -1;
    }

  for(i=0; i<testc; i++)
    if(decode_check(tests[i].base64, tests[i].bytes) != 0)
      break;
  if(i != testc)
    {
      printf("decode test %d failed\n", (int)i);
      return -1;
    }

  for(i=0; i<bad_testc; i++)
    if(decode_bad_check(bad_tests[i]) != 0)
      break;
  if(i != bad_testc)
    {
      printf("bad decode test %d failed\n", (int)i);
      return -1;
    }

  printf("OK\n");
  return 0;
}
