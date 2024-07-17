/*
 * unit_timeval: unit tests for string_* functions in utils.c
 *
 * $Id: unit_string.c,v 1.2 2024/04/28 20:09:52 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024 Matthew Luckie
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

typedef struct sc_byte2hex_test
{
  uint8_t  bytes[4];
  size_t   bytes_len;
  size_t   buf_len;
  size_t   off_in;
  size_t   off_out;
  char    *str;
} sc_byte2hex_test_t;

typedef struct sc_jsonesc_test
{
  const char *in;
  const char *out;
  size_t      len_in;
  size_t      len_out;
} sc_jsonesc_test_t;

static int byte2hex_tests(void)
{
  sc_byte2hex_test_t tests[] = {
    {{0xff, 0xab, 0xcd, 0x01}, 4, 9, 0, 8, "ffabcd01"},
    {{0xff, 0xab, 0xcd, 0x01}, 0, 9, 0, 0, ""},
    {{0xff, 0xab, 0xcd, 0x01}, 4, 0, 0, 0, "###########"},
    {{0xff, 0xab, 0xcd, 0x01}, 4, 7, 0, 6, "ffabcd"},
    {{0xff, 0xab, 0xcd, 0x01}, 4, 6, 0, 4, "ffab"},
    {{0xff, 0xab, 0xcd, 0x01}, 4, 12, 2, 10, "##ffabcd01"},
    {{0xff, 0xab, 0xcd, 0x01}, 4, 12, 13, 13, NULL},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_byte2hex_test_t);
  size_t off;
  char buf[12];
  char *rc;

  for(i=0; i<testc; i++)
    {
      /* set the output buf to ##### */
      memset(buf, 35, sizeof(buf));
      buf[sizeof(buf)-1] = '\0';

      /* run the test */
      off = tests[i].off_in;
      rc = string_byte2hex(buf, tests[i].buf_len, &off,
			   tests[i].bytes, tests[i].bytes_len);
      if(off != tests[i].off_out ||
	 (rc == NULL && tests[i].str != NULL) ||
	 (rc != NULL && (tests[i].str == NULL || strcmp(rc, tests[i].str) != 0)))
	{
	  printf("byte2hex fail %d %d %d %p\n",
		 (int)i, (int)off, (int)tests[i].off_out, rc);
	  return -1;
	}
    }

  return 0;
}

static int jsonesc_tests(void)
{
  sc_jsonesc_test_t tests[] = {
    {"foo", "foo", 4, 4},
    {"test\"", "test\\\"", 7, 7},
    {"foo", "fo", 3, 4},
    {"test\"", "test", 5, 7},
    {"foo", NULL, 0, 4},
    {"bar\\", "bar\\\\", 6, 6},
  };
  size_t i, l, testc = sizeof(tests) / sizeof(sc_jsonesc_test_t);
  char buf[12], *rc;

  for(i=0; i<testc; i++)
    {
      l = json_esc_len(tests[i].in);
      if(l != tests[i].len_out)
	{
	  printf("jsonesc fail %d %d != %d\n", (int)i,
		 (int)l, (int)tests[i].len_out);
	  return -1;
	}

      rc = json_esc(tests[i].in, buf, tests[i].len_in);
      if((rc == NULL && tests[i].out != NULL) ||
	 (rc != NULL && (tests[i].out == NULL || strcmp(rc, tests[i].out) != 0)))
	{
	  printf("jsonesc fail %d %p \"%s\"\n", (int)i, rc,
		 rc == NULL ? "<null>" : rc);
	  return -1;
	}
    }

  return 0;
}

int main(int argc, char *argv[])
{
  if(byte2hex_tests() != 0 ||
     jsonesc_tests() != 0)
    return -1;

  printf("OK\n");
  return 0;
}
