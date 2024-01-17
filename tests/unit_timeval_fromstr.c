/*
 * unit_timeval_fromstr: unit tests for timeval_fromstr() in utils.c
 *
 * $Id: unit_timeval_fromstr.c,v 1.2 2023/12/23 19:19:57 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2023 Matthew Luckie
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

typedef struct sc_test
{
  const char *param;
  uint32_t    unit;
  int       (*func)(int rc, const struct timeval *tv);
} sc_test_t;

static int tv_10s(int rc, const struct timeval *tv)
{
  if(rc != 0 || tv->tv_sec != 10 || tv->tv_usec != 0)
    return -1;
  return 0;
}

static int tv_1_1s(int rc, const struct timeval *tv)
{
  if(rc != 0 || tv->tv_sec != 1 || tv->tv_usec != 100000)
    return -1;
  return 0;
}

static int tv_1_01s(int rc, const struct timeval *tv)
{
  if(rc != 0 || tv->tv_sec != 1 || tv->tv_usec != 10000)
    return -1;
  return 0;
}

static int tv_2_003s(int rc, const struct timeval *tv)
{
  if(rc != 0 || tv->tv_sec != 2 || tv->tv_usec != 3000)
    return -1;
  return 0;
}

static int tv_3_00045s(int rc, const struct timeval *tv)
{
  if(rc != 0 || tv->tv_sec != 3 || tv->tv_usec != 450)
    return -1;
  return 0;
}

static int tv_4_342542s(int rc, const struct timeval *tv)
{
  if(rc != 0 || tv->tv_sec != 4 || tv->tv_usec != 342542)
    return -1;
  return 0;
}

static int tv_50us(int rc, const struct timeval *tv)
{
  if(rc != 0 || tv->tv_sec != 0 || tv->tv_usec != 50)
    return -1;
  return 0;
}

static int tv_4us(int rc, const struct timeval *tv)
{
  if(rc != 0 || tv->tv_sec != 0 || tv->tv_usec != 4)
    return -1;
  return 0;
}

static int tv_45us(int rc, const struct timeval *tv)
{
  if(rc != 0 || tv->tv_sec != 0 || tv->tv_usec != 45)
    return -1;
  return 0;
}

static int tv_6_9ms(int rc, const struct timeval *tv)
{
  if(rc != 0 || tv->tv_sec != 0 || tv->tv_usec != 6900)
    return -1;
  return 0;
}

static int tv_0_4ms(int rc, const struct timeval *tv)
{
  if(rc != 0 || tv->tv_sec != 0 || tv->tv_usec != 400)
    return -1;
  return 0;
}

static int invalid(int rc, const struct timeval *tv)
{
  if(rc == 0)
    return -1;
  return 0;
}

static int check(const char *param, uint32_t unit,
		 int (*func)(int rc, const struct timeval *tv))
{
  struct timeval tv;
  memset(&tv, 0, sizeof(tv));
  if(func(timeval_fromstr(&tv, param, unit), &tv) != 0)
    {
      printf("fail %s: %ld.%06d\n",
	     param, (long int)tv.tv_sec, (int)tv.tv_usec);
      return -1;
    }
  return 0;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {"10s",        1000000, tv_10s},
    {"10",         1000000, tv_10s},
    {"10.",        1000000, invalid},
    {"1.1s",       1000000, tv_1_1s},
    {"1.1",        1000000, tv_1_1s},
    {"1.01s",      1000000, tv_1_01s},
    {"1.01",       1000000, tv_1_01s},
    {"2.003000s",  1000000, tv_2_003s},
    {"2.003000",   1000000, tv_2_003s},
    {"2.0030001s", 1000000, invalid},
    {"2.0030001",  1000000, invalid},
    {"3.000450s",  1000000, tv_3_00045s},
    {"3.000450",   1000000, tv_3_00045s},
    {"4.342542s",  1000000, tv_4_342542s},
    {"4.342542",   1000000, tv_4_342542s},
    {"6.9ms",         1000, tv_6_9ms},
    {"6.9",           1000, tv_6_9ms},
    {"69",             100, tv_6_9ms}, /* centiseconds */
    {"69.00",          100, tv_6_9ms},
    {"690",             10, tv_6_9ms}, /* deciseconds */
    {"50us",             1, tv_50us},
    {"50",               1, tv_50us},
    {"50.0us",           1, tv_50us},
    {"0.1us",            1, invalid},
    {"0.1",              1, invalid},
    {"0.05ms",        1000, tv_50us},
    {"0.05",          1000, tv_50us},
    {"0.004ms",       1000, tv_4us},
    {"0.004",         1000, tv_4us},
    {"0.045ms",       1000, tv_45us},
    {"0.045",         1000, tv_45us},
    {"0.0004ms",      1000, invalid},
    {"0.0004",        1000, invalid},
    {"0.0400ms",      1000, invalid},
    {"0.0400",        1000, invalid},
    {"0.4ms",         1000, tv_0_4ms},
    {"0.4",           1000, tv_0_4ms},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);

  for(i=0; i<testc; i++)
    if(check(tests[i].param, tests[i].unit, tests[i].func) != 0)
      break;

  if(i != testc)
    return -1;

  printf("OK\n");
  return 0;
}
