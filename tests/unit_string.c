/*
 * unit_string: unit tests for string_* functions in utils.c
 *
 * $Id: unit_string.c,v 1.11 2025/02/15 09:20:37 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
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

typedef struct sc_concat_test
{
  char   *strs[4];
  size_t  strc;
  size_t  len;
  char   *out;
} sc_concat_test_t;

typedef struct sc_concatu_test
{
  char     *pre;
  uint32_t  val;
  size_t    len;
  char     *out;
} sc_concatu_test_t;

typedef struct sc_concatc_test
{
  const char *str;
  char        c;
  size_t      len_in;
  size_t      off_in;
  size_t      off_out;
} sc_concatc_test_t;

static int byte2hex_tests(void)
{
  sc_byte2hex_test_t tests[] = {
    {{0xff, 0xab, 0xcd, 0x01}, 4, 9, 0, 8, "ffabcd01"},
    {{0xff, 0xab, 0xcd, 0x01}, 0, 9, 0, 0, ""},
    {{0xff, 0xab, 0xcd, 0x01}, 4, 0, 0, 0, "###########"},
    {{0xff, 0xab, 0xcd, 0x01}, 4, 7, 0, 6, "ffabcd"},
    {{0xff, 0xab, 0xcd, 0x01}, 4, 6, 0, 4, "ffab"},
    {{0xff, 0xab, 0xcd, 0x01}, 4, 12, 2, 10, "##ffabcd01"},
    {{0xff, 0xab, 0xcd, 0x01}, 4, 12, 13, 13, "###########"},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_byte2hex_test_t);
  size_t off;
  char buf[12];

  for(i=0; i<testc; i++)
    {
      /* set the output buf to ##### */
      memset(buf, 35, sizeof(buf));
      buf[sizeof(buf)-1] = '\0';

      /* run the test */
      off = tests[i].off_in;
      string_byte2hex(buf, tests[i].buf_len, &off,
		      tests[i].bytes, tests[i].bytes_len);
      if(off != tests[i].off_out || strcmp(buf, tests[i].str) != 0)
	{
	  printf("byte2hex fail %d %d %d\n",
		 (int)i, (int)off, (int)tests[i].off_out);
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

static int concat_tests(void)
{
  sc_concat_test_t tests[] = {
    {{"abc", "def",  NULL,  NULL}, 2, 7,  "abcdef"},
    {{"abc", "def",  NULL,  NULL}, 2, 6,  "abcde"},
    {{"abc", "def",  NULL,  NULL}, 2, 5,  "abcd"},
    {{"abc", "def",  NULL,  NULL}, 2, 4,  "abc"},
    {{"abc", "def",  NULL,  NULL}, 2, 3,  "ab"},
    {{"abc", "def",  NULL,  NULL}, 2, 2,  "a"},
    {{"abc", "def",  NULL,  NULL}, 2, 1,  ""},
    {{"a",    NULL,  NULL,  NULL}, 1, 2,  "a"},
    {{"abc", "def", "ghi",  NULL}, 3, 10, "abcdefghi"},
    {{"abc", "def", "ghi", "jkl"}, 4, 13, "abcdefghijkl"},
    {{"abc", "def", "ghi", "jkl"}, 4, 10, "abcdefghi"},
    {{"abc", "def", "ghi", "jkl"}, 4, 0,  NULL},
    {{"abc", "def", "ghi", "jkl"}, 4, 1,  ""},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_concat_test_t);
  size_t off, x;
  char   buf[16];

  for(i=0; i<testc; i++)
    {
      /* set the output buf to ##### */
      memset(buf, 35, sizeof(buf));
      buf[sizeof(buf)-1] = '\0';

      off = 0;
      for(x=0; x<tests[i].strc; x++)
	string_concat(buf, tests[i].len, &off, tests[i].strs[x]);
      if(tests[i].out != NULL && strcmp(buf, tests[i].out) != 0)
	{
	  printf("concat fail %d %s != %s\n", (int)i, buf, tests[i].out);
	  return -1;
	}
      if(strncasecmp("###############", buf+tests[i].len,
		     sizeof(buf)-tests[i].len-1) != 0 ||
	 buf[sizeof(buf)-1] != '\0')
	{
	  printf("concat fail %d overrun\n", (int)i);
	  return -1;
	}
    }

  return 0;
}

static int concat_u8_tests(void)
{
  sc_concatu_test_t tests[] = {
    {"foo:", 32,  8, "foo:32"},
    {"foo:", 32,  6, "foo:3"},
    {"foo:", 255, 8, "foo:255"},
    {"foo:", 0,   6, "foo:0"},
    {NULL,   32,  3, "32"},
    {NULL,   32,  2, "3"},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_concatu_test_t);
  size_t off;
  char   buf[16], cmp[16];

  for(i=0; i<testc; i++)
    {
      /* set the output buf to ##### */
      memset(buf, 35, sizeof(buf));
      buf[sizeof(buf)-1] = '\0';

      off = 0;
      string_concat_u8(buf, tests[i].len, &off, tests[i].pre, tests[i].val);
      if(strcmp(buf, tests[i].out) != 0)
	{
	  printf("concat_u8 fail %d %s != %s\n", (int)i, buf, tests[i].out);
	  return -1;
	}
    }

  for(i=0; i<256; i++)
    {
      off = 0;
      string_concat_u8(buf, sizeof(buf), &off, NULL, i);
      snprintf(cmp, sizeof(cmp), "%u", (uint8_t)i);
      if(strcmp(buf, cmp) != 0)
	{
	  printf("concat_u8 fail %d %s != %s\n", (int)i, buf, cmp);
	  return -1;
	}
    }

  return 0;
}

static int concat_u16_tests(void)
{
  sc_concatu_test_t  tests[] = {
    {"foo:", 32,     8, "foo:32"},
    {"foo:", 32,     6, "foo:3"},
    {"foo:", 255,    8, "foo:255"},
    {"foo:", 0,      6, "foo:0"},
    {"foo:", 1000,   9, "foo:1000"},
    {"foo:", 65535, 10, "foo:65535"},
    {NULL,   32,     3, "32"},
    {NULL,   32,     2, "3"},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_concatu_test_t);
  size_t off;
  char   buf[16], cmp[16];

  for(i=0; i<testc; i++)
    {
      /* set the output buf to ##### */
      memset(buf, 35, sizeof(buf));
      buf[sizeof(buf)-1] = '\0';

      off = 0;
      string_concat_u16(buf, tests[i].len, &off, tests[i].pre, tests[i].val);
      if(strcmp(buf, tests[i].out) != 0)
	{
	  printf("concat_u16 fail %d %s != %s\n", (int)i, buf, tests[i].out);
	  return -1;
	}
    }

  for(i=0; i<65536; i++)
    {
      off = 0;
      string_concat_u16(buf, sizeof(buf), &off, NULL, i);
      snprintf(cmp, sizeof(cmp), "%u", (uint16_t)i);
      if(strcmp(buf, cmp) != 0)
	{
	  printf("concat_u16 fail %d %s != %s\n", (int)i, buf, cmp);
	  return -1;
	}
    }

  return 0;
}

static int concat_u32_tests(void)
{
  sc_concatu_test_t tests[] = {
    {"foo:", 32,          8, "foo:32"},
    {"bar:", 32,          6, "bar:3"},
    {"foo:", 255,         8, "foo:255"},
    {"bar:", 0,           6, "bar:0"},
    {"foo:", 1000,        9, "foo:1000"},
    {"bar:", 65535,      10, "bar:65535"},
    {"foo:", 429496729,  14, "foo:429496729"},
    {"bar:", 4294967295, 15, "bar:4294967295"},
    {NULL,   32,          3, "32"},
    {NULL,   32,          2, "3"},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_concatu_test_t);
  size_t off;
  char   buf[16];

  for(i=0; i<testc; i++)
    {
      /* set the output buf to ##### */
      memset(buf, 35, sizeof(buf));
      buf[sizeof(buf)-1] = '\0';

      off = 0;
      string_concat_u32(buf, tests[i].len, &off, tests[i].pre, tests[i].val);
      if(strcmp(buf, tests[i].out) != 0)
	{
	  printf("concat_u32 fail %d %s != %s\n", (int)i, buf, tests[i].out);
	  return -1;
	}
    }

  return 0;
}

static int concat_c_tests(void)
{
  sc_concatc_test_t tests[] = {
    {"##c",         'c', 12, 2, 3},
    {"d",           'd', 12, 0, 1},
    {"###########", 'f', 12, 11, 11},
    {"##########e", 'e', 12, 10, 11},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_concatc_test_t);
  size_t off, len;
  char buf[12];

  for(i=0; i<testc; i++)
    {
      /* set the output buf to ##### */
      memset(buf, 35, sizeof(buf));
      buf[sizeof(buf)-1] = '\0';

      /* run the test */
      len = tests[i].len_in;
      off = tests[i].off_in;
      string_concatc(buf, len, &off, tests[i].c);
      if(off != tests[i].off_out || strcmp(buf, tests[i].str) != 0)
	{
	  printf("concat_c fail %d %s != %s\n", (int)i, buf, tests[i].str);
	  return -1;
	}
    }
  return 0;
}

int main(int argc, char *argv[])
{
  if(byte2hex_tests() != 0 || jsonesc_tests() != 0 ||
     concat_tests() != 0 || concat_u8_tests() != 0 ||
     concat_u16_tests() != 0 || concat_u32_tests() != 0 ||
     concat_c_tests() != 0)
    return -1;

  printf("OK\n");
  return 0;
}
