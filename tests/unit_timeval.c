/*
 * unit_timeval: unit tests for timeval_* functions in utils.c
 *
 * $Id: unit_timeval.c,v 1.11 2025/07/11 23:19:00 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2023-2025 Matthew Luckie
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

typedef struct sc_math_test
{
  time_t      start_sec;
  suseconds_t start_usec;
  time_t      val_sec;
  suseconds_t val_usec;
  time_t      finish_sec;
  suseconds_t finish_usec;
} sc_math_test_t;

typedef struct sc_fromstr_test
{
  const char *param;
  uint32_t    unit;
  int         rc;
  time_t      finish_sec;
  suseconds_t finish_usec;
} sc_fromstr_test_t;

typedef struct sc_tostr_us_test
{
  const char  *out;
  time_t       tv_sec;
  suseconds_t  tv_usec;
} sc_tostr_us_test_t;

typedef struct sc_cmp_test
{
  time_t      a_sec;
  suseconds_t a_usec;
  time_t      b_sec;
  suseconds_t b_usec;
  int         rc;
} sc_cmp_test_t;

typedef struct sc_div_test
{
  time_t      in_sec;
  suseconds_t in_usec;
  time_t      out_sec;
  suseconds_t out_usec;
  uint32_t    d;
} sc_div_test_t;

typedef struct sc_inrange_test
{
  time_t      a_sec;
  suseconds_t a_usec;
  time_t      b_sec;
  suseconds_t b_usec;
  time_t      r_sec;
  suseconds_t r_usec;
  int         rc;
} sc_inrange_test_t;

static int fromstr_tests(void)
{
  sc_fromstr_test_t tests[] = {
    {"10s",               1000000,  0,         10,      0},
    {"10",                1000000,  0,         10,      0},
    {"10.",               1000000, -1,          0,      0},
    {"1.1s",              1000000,  0,          1, 100000},
    {"1.1",               1000000,  0,          1, 100000},
    {"1.01s",             1000000,  0,          1,  10000},
    {"1.01",              1000000,  0,          1,  10000},
    {"2.003000s",         1000000,  0,          2,   3000},
    {"2.003000",          1000000,  0,          2,   3000},
    {"2.0030001s",        1000000, -1,          0,      0},
    {"2.0030001",         1000000, -1,          0,      0},
    {"3.000450s",         1000000,  0,          3,    450},
    {"3.000450",          1000000,  0,          3,    450},
    {"4.342542s",         1000000,  0,          4, 342542},
    {"4.342542",          1000000,  0,          4, 342542},
    {"6.9ms",                1000,  0,          0,   6900},
    {"6.9",                  1000,  0,          0,   6900},
    {"69",                    100,  0,          0,   6900}, /* centiseconds */
    {"69.00",                 100,  0,          0,   6900},
    {"690",                    10,  0,          0,   6900}, /* deciseconds */
    {"50us",                    1,  0,          0,     50},
    {"50",                      1,  0,          0,     50},
    {"50.0us",                  1,  0,          0,     50},
    {"0.1us",                   1, -1,          0,      0},
    {"0.1",                     1, -1,          0,      0},
    {"0.05ms",               1000,  0,          0,     50},
    {"0.05",                 1000,  0,          0,     50},
    {"0.004ms",              1000,  0,          0,      4},
    {"0.004",                1000,  0,          0,      4},
    {"0.045ms",              1000,  0,          0,     45},
    {"0.045",                1000,  0,          0,     45},
    {"0.0004ms",             1000, -1,          0,      0},
    {"0.0004",               1000, -1,          0,      0},
    {"0.0400ms",             1000, -1,          0,      0},
    {"0.0400",               1000, -1,          0,      0},
    {"0.4ms",                1000,  0,          0,    400},
    {"0.4",                  1000,  0,          0,    400},
    {"1708459200.654321", 1000000,  0, 1708459200, 654321},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_fromstr_test_t);
  struct timeval calc, finish;
  int rc;

  for(i=0; i<testc; i++)
    {
      finish.tv_sec = tests[i].finish_sec;
      finish.tv_usec = tests[i].finish_usec;
      memset(&calc, 0, sizeof(calc));
      rc = timeval_fromstr(&calc, tests[i].param, tests[i].unit);
      if(rc != tests[i].rc ||
	 (rc == 0 && timeval_cmp(&calc, &finish) != 0))
	{
	  printf("fromstr fail %s %d: %d %ld.%06d\n", tests[i].param,
		 tests[i].rc, rc, (long int)calc.tv_sec, (int)calc.tv_usec);
	  return -1;
	}
    }

  return 0;
}

static int add_tests(void)
{
  sc_math_test_t tests[] = {
    {1708459200,  100000, 0, 900000, 1708459201, 0},
    {1708459200,   10000, 0, 900000, 1708459200, 910000},
    {1708459200,  500000, 0, 812241, 1708459201, 312241},
    {1708459200, 1000000, 0, 999999, 1708459201, 999999},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_math_test_t);
  struct timeval in, add, out;
  for(i=0; i<testc; i++)
    {
      in.tv_sec   = tests[i].start_sec;
      in.tv_usec  = tests[i].start_usec;
      add.tv_sec  = tests[i].val_sec;
      add.tv_usec = tests[i].val_usec;
      timeval_add_tv(&in, &add);
      if(in.tv_sec != tests[i].finish_sec ||
	 in.tv_usec != tests[i].finish_usec)
	{
	  printf("add_tv fail %lu\n", i);
	  return -1;
	}

      in.tv_sec   = tests[i].start_sec;
      in.tv_usec  = tests[i].start_usec;
      add.tv_sec  = tests[i].val_sec;
      add.tv_usec = tests[i].val_usec;
      timeval_add_tv3(&out, &in, &add);
      if(out.tv_sec != tests[i].finish_sec ||
	 out.tv_usec != tests[i].finish_usec)
	{
	  printf("add_tv3 fail %lu\n", i);
	  return -1;
	}
    }

  return 0;
}

static int sub_tests(void)
{
  sc_math_test_t tests[] = {
    /* simple subtractions */
    {1708459200,  100000, 0,  50000, 1708459200,  50000},
    {1708459200,  100000, 0, 100000, 1708459200,      0},
    {1708459200, 1000000, 0, 100000, 1708459200, 900000},
    /* handle usec wrap */
    {1708459200,  100000, 0,  900000, 1708459199, 200000},
    {1708459200,  100000, 0,  999999, 1708459199, 100001},
    /* subtracting with usec value of 1000000 */
    {1708459200,  100000, 0, 1000000, 1708459199, 100000},
    {1708459200,  100000, 1, 1000000, 1708459198, 100000},
    {1708459200, 1000000, 1, 1000000, 1708459199, 0},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_math_test_t);
  struct timeval start, val, finish;

  for(i=0; i<testc; i++)
    {
      start.tv_sec = tests[i].start_sec;
      start.tv_usec = tests[i].start_usec;
      val.tv_sec = tests[i].val_sec;
      val.tv_usec = tests[i].val_usec;
      finish.tv_sec = tests[i].finish_sec;
      finish.tv_usec = tests[i].finish_usec;
      timeval_sub_tv(&start, &val);
      if(timeval_cmp(&start, &finish) != 0)
	{
	  printf("sub_tv fail %lu\n", i);
	  return -1;
	}

      start.tv_sec = tests[i].start_sec;
      start.tv_usec = tests[i].start_usec;
      val.tv_sec = tests[i].val_sec;
      val.tv_usec = tests[i].val_usec;
      timeval_sub_tv3(&finish, &start, &val);
      if(finish.tv_sec != tests[i].finish_sec ||
	 finish.tv_usec != tests[i].finish_usec)
	{
	  printf("sub_tv3 fail %lu\n", i);
	  return -1;
	}
    }

  return 0;
}

static int diff_tests(void)
{
  sc_math_test_t tests[] = {
    {1708459200,  100000, 1708459201,       0, 0, 900000},
    {1708459200,   10000, 1708459200,  910000, 0, 900000},
    {1708459200,  500000, 1708459201,  312241, 0, 812241},
    {1708459200, 1000000, 1708459201,  999999, 0, 999999},
    {1708459200, 1000000, 1708459201, 1000000, 1,      0},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_math_test_t);
  struct timeval a, b, out;
  for(i=0; i<testc; i++)
    {
      a.tv_sec  = tests[i].start_sec;
      a.tv_usec = tests[i].start_usec;
      b.tv_sec  = tests[i].val_sec;
      b.tv_usec = tests[i].val_usec;
      timeval_diff_tv(&out, &a, &b);
      if(out.tv_sec != tests[i].finish_sec ||
	 out.tv_usec != tests[i].finish_usec)
	{
	  printf("diff fail %lu\n", i);
	  return -1;
	}
    }

  return 0;
}

static int cmp_tests(void)
{
  sc_cmp_test_t tests[] = {
    {1708459200,  100000, 1708459201,  100000, -1},
    {1708459200, 1000000, 1708459201,       0, -1},
    {1708459201,       0, 1708459200, 1000000,  1},
    {1708459201,       0, 1708459201,       0,  0},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_cmp_test_t);
  struct timeval a, b;

  for(i=0; i<testc; i++)
    {
      a.tv_sec  = tests[i].a_sec;
      a.tv_usec = tests[i].a_usec;
      b.tv_sec  = tests[i].b_sec;
      b.tv_usec = tests[i].b_usec;
      if(timeval_cmp(&a, &b) != tests[i].rc)
	{
	  printf("cmp fail %lu\n", i);
	  return -1;
	}
    }

  return 0;
}

static int tostr_us_tests(void)
{
  sc_tostr_us_test_t tests[] = {
    {"123.456",  0, 123456},
    {"1123.456", 1, 123456},
    {"999.000", 0, 999000},
    {"888.001", 0, 888001},
    {"777.010", 0, 777010},
    {"654.100", 0, 654100},
    {"0.000", 0, 0},
    {"123456.789", 123, 456789},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_tostr_us_test_t);
  struct timeval in;
  char buf[16];

  for(i=0; i<testc; i++)
    {
      in.tv_sec  = tests[i].tv_sec;
      in.tv_usec = tests[i].tv_usec;
      timeval_tostr_us(&in, buf, sizeof(buf));
      if(strcmp(buf, tests[i].out) != 0)
	{
	  printf("tostr_us fail %lu %s != %s\n", i, buf, tests[i].out);
	  return -1;
	}
    }

  return 0;
}

static int div_tests(void)
{
  sc_div_test_t tests[] = {
    {10,    0,    2, 500000,        4},
    {10000, 0, 2500,      0,        4},
    {10,    0,    0, 100000,      100},
    {10,    0,    0,      1, 10000000},
    {10,    0,    0,      0, 10000001},
    {43200, 0,    0, 183525,   235390},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_div_test_t);
  struct timeval in, out;

  for(i=0; i<testc; i++)
    {
      in.tv_sec = tests[i].in_sec;
      in.tv_usec = tests[i].in_usec;
      timeval_div(&out, &in, tests[i].d);
      if(out.tv_sec != tests[i].out_sec || out.tv_usec != tests[i].out_usec)
	{
	  printf("div fail %lu %ld.%06d\n", i,
		 (long int)out.tv_sec, (int)out.tv_usec);
	  return -1;
	}
    }

  return 0;
}

static int mul_tests(void)
{
  sc_div_test_t tests[] = {
    {2,    500000, 10,        0,        4},
    {2500,      0, 10000,     0,        4},
    {0,    100000, 10,        0,      100},
    {0,         1, 10,        0, 10000000},
    {5000,      0, 500000000, 0,   100000},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_div_test_t);
  struct timeval in, out;

  for(i=0; i<testc; i++)
    {
      in.tv_sec = tests[i].in_sec;
      in.tv_usec = tests[i].in_usec;
      timeval_mul(&out, &in, tests[i].d);
      if(out.tv_sec != tests[i].out_sec || out.tv_usec != tests[i].out_usec)
	{
	  printf("mul fail %lu %ld.%06d\n",
		 i, (long int)out.tv_sec, (int)out.tv_usec);
	  return -1;
	}
    }

  return 0;
}

static int inrange_tests(void)
{
  sc_inrange_test_t tests[] = {
    {1, 500000, 1, 500000, 0, 250000, 1},
    {1, 500000, 1, 475000, 0,  25000, 1},
    {1, 500000, 1, 474000, 0,  25000, 0},
    {1, 500000, 1, 474999, 0,  25000, 0},
    {1, 500000, 1, 499999, 0,      1, 1},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_inrange_test_t);
  struct timeval a, b, r;

  for(i=0; i<testc; i++)
    {
      r.tv_sec  = tests[i].r_sec;
      r.tv_usec = tests[i].r_usec;
      a.tv_sec  = tests[i].a_sec;
      a.tv_usec = tests[i].a_usec;
      b.tv_sec  = tests[i].b_sec;
      b.tv_usec = tests[i].b_usec;

      if(timeval_inrange_tv(&a, &b, &r) != tests[i].rc)
	{
	  printf("inrange fail %lu #1\n", i);
	  return -1;
	}

      if(timeval_inrange_tv(&b, &a, &r) != tests[i].rc)
	{
	  printf("inrange fail %lu #2\n", i);
	  return -1;
	}
    }

  return 0;
}

int main(int argc, char *argv[])
{
  if(fromstr_tests() != 0 || tostr_us_tests() != 0 ||
     add_tests() != 0 || sub_tests() != 0 || diff_tests() != 0 ||
     cmp_tests() != 0 || div_tests() != 0 || mul_tests() != 0 ||
     inrange_tests() != 0)
    return -1;

  printf("OK\n");
  return 0;
}
