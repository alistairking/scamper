/*
 * unit_addr : unit tests for scamper_addr
 *
 * $Id: unit_addr.c,v 1.8 2025/07/12 07:10:06 mjl Exp $
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

#include "scamper_addr.h"
#include "scamper_addr_int.h"

typedef struct sc_reserved
{
  int type;
  const char *addr;
  int (*func)(scamper_addr_t *addr);
} sc_reserved_t;

typedef struct sc_cmp
{
  const char *a;
  const char *b;
  int         rc;
} sc_cmp_t;

scamper_addrcache_t *addrcache = NULL;

static int is_reserved(scamper_addr_t *addr)
{
  return (scamper_addr_isreserved(addr) != 0) ? 0 : -1;
}

static int is_not_reserved(scamper_addr_t *addr)
{
  return (scamper_addr_isreserved(addr) == 0) ? 0 : -1;
}

static int reserved_tests(void)
{
  sc_reserved_t tests[] = {
    {SCAMPER_ADDR_TYPE_IPV6, "::", is_reserved},
    {SCAMPER_ADDR_TYPE_IPV6, "1000::", is_reserved},
    {SCAMPER_ADDR_TYPE_IPV6, "2000::", is_not_reserved},
    {SCAMPER_ADDR_TYPE_IPV6, "2001::66", is_reserved},     /* teredo */
    {SCAMPER_ADDR_TYPE_IPV6, "2001:2::", is_reserved},     /* benchmarking */
    {SCAMPER_ADDR_TYPE_IPV6, "2001:3::", is_reserved},     /* AMT */
    {SCAMPER_ADDR_TYPE_IPV6, "2001:4:112::", is_reserved}, /* AS112-v6 */
    {SCAMPER_ADDR_TYPE_IPV6, "2001:10::", is_reserved},    /* ORCHID */
    {SCAMPER_ADDR_TYPE_IPV6, "2001:20::", is_reserved},    /* ORCHIDv2 */
    {SCAMPER_ADDR_TYPE_IPV6, "2001:40::", is_not_reserved},
    {SCAMPER_ADDR_TYPE_IPV6, "2001:db8::", is_reserved},   /* documentation */
    {SCAMPER_ADDR_TYPE_IPV6, "2401::", is_not_reserved},
    {SCAMPER_ADDR_TYPE_IPV6, "2402::", is_not_reserved},
    {SCAMPER_ADDR_TYPE_IPV6, "3000::", is_not_reserved},   /* check 2000::/3 */
    {SCAMPER_ADDR_TYPE_IPV6, "4000::", is_reserved},
  };
  scamper_addr_t *sa;
  size_t i, testc = sizeof(tests) / sizeof(sc_reserved_t);
  int rc;

  for(i=0; i<testc; i++)
    {
      if((sa = scamper_addr_fromstr(tests[i].type, tests[i].addr)) == NULL)
	{
	  printf("reserved resolve fail %ld: %s\n", i, tests[i].addr);
	  break;
	}
      rc = tests[i].func(sa);
      scamper_addr_free(sa);
      if(rc != 0)
	{
	  printf("reserved fail %ld: %s\n", i, tests[i].addr);
	  break;
	}
    }

  if(i != testc)
    return -1;

  return 0;
}

static int cmp_tests(int human)
{
  sc_cmp_t tests[] = {
    {"192.0.2.1",                "192.0.2.4",                -1},
    {"192.0.2.3",                "192.0.2.2",                 1},
    {"192.0.2.8",                "192.0.2.8",                 0},
    {"2001:db8::",               "2001::",                    1},
    {"2001::",                   "2001:db8::",               -1},
    {"2001:db8::",               "2001:db8::",                0},
    {"192.0.2.1",                "2001:db8::",               -1},
    {"2001:db8::",               "192.0.2.1",                 1},
    {"2001:db8:face:feed::",     "2001:db8:feed:face::",     -1},
    {"2001:db8:feed:face::",     "2001:db8:face:feed::",      1},
    {"2001:db8:feed:feed::",     "2001:db8:feed:feed::",      0},
    {"2001:db8:0:0:face:feed::", "2001:db8:0:0:feed:face::", -1},
    {"2001:db8:0:0:feed:face::", "2001:db8:0:0:face:feed::",  1},
    {"2001:db8:0:0:feed:feed::", "2001:db8:0:0:feed:feed::",  0},
    {"2001:db8::face:feed",      "2001:db8::feed:face",      -1},
    {"2001:db8::feed:face",      "2001:db8::face:feed",       1},
    {"2001:db8::feed:feed",      "2001:db8::feed:feed",       0},
  };
  scamper_addr_t *sa, *sb;
  size_t i, testc = sizeof(tests) / sizeof(sc_cmp_t);
  int rc;

  for(i=0; i<testc; i++)
    {
      if((sa = scamper_addr_fromstr_unspec(tests[i].a)) == NULL ||
	 (sb = scamper_addr_fromstr_unspec(tests[i].b)) == NULL)
	{
	  printf("cmp resolve fail %ld\n", i);
	  break;
	}

      if(human == 0)
	rc = scamper_addr_cmp(sa, sb);
      else
	rc = scamper_addr_human_cmp(sa, sb);

      scamper_addr_free(sa);
      scamper_addr_free(sb);

      if((human == 0 && ((tests[i].rc == 0 && rc != 0) ||
			 (tests[i].rc != 0 && rc == 0))) ||
	 (human == 1 && tests[i].rc != rc))
	{
	  printf("cmp human %d test %ld fail\n", human, i);
	  break;
	}
    }

  if(i != testc)
    return -1;

  return 0;
}

static int prefix_tests(void)
{
  sc_cmp_t tests[] = {
    {"192.0.2.1",                "192.0.2.254",               24},
    {"192.0.2.0",                "192.0.2.254",               24},
    {"192.0.2.0",                "192.0.2.255",               24},
    {"192.0.2.1",                "192.0.2.2",                 30},
    {"192.0.2.1",                "192.0.2.0",                 31},
    {"192.0.2.1",                "192.0.2.1",                 32},
    {"2001:db8:8000::",          "2001:db8::",                32},
    {"2001:db8:4000::",          "2001:db8::",                33},
    {"2001:db8:2000::",          "2001:db8::",                34},
    {"2001:db8:1000::",          "2001:db8::",                35},
    {"2001:db8::1",              "2001:db8::2",               126},
    {"2001:db8::0",              "2001:db8::1",               127},
    {"0.0.0.0",                  "255.255.255.255",           0},
  };
  scamper_addr_t *sa, *sb;
  size_t i, testc = sizeof(tests) / sizeof(sc_cmp_t);
  int rc;

  for(i=0; i<testc; i++)
    {
      rc = -2;
      if((sa = scamper_addr_fromstr_unspec(tests[i].a)) == NULL ||
	 (sb = scamper_addr_fromstr_unspec(tests[i].b)) == NULL ||
	 (rc = scamper_addr_prefix(sa, sb)) != tests[i].rc)
	{
	  printf("prefix fail %ld %d\n", i, rc);
	  break;
	}

      scamper_addr_free(sa);
      scamper_addr_free(sb);
    }

  if(i != testc)
    return -1;

  return 0;
}

static int prefix_host_tests(void)
{
  sc_cmp_t tests[] = {
    {"192.0.2.1",                "192.0.2.254",               24},
    {"192.0.3.0",                "192.0.3.254",               23},
    {"192.0.2.254",              "192.0.3.254",               23},
    {"192.0.3.0",                "192.0.3.254",               23},
    {"192.0.3.0",                "192.0.3.255",               21},
    {"192.0.2.1",                "192.0.2.2",                 30},
  };
  scamper_addr_t *sa, *sb;
  size_t i, testc = sizeof(tests) / sizeof(sc_cmp_t);
  int rc;

  for(i=0; i<testc; i++)
    {
      rc = -2;
      if((sa = scamper_addr_fromstr_unspec(tests[i].a)) == NULL ||
	 (sb = scamper_addr_fromstr_unspec(tests[i].b)) == NULL ||
	 (rc = scamper_addr_prefixhosts(sa, sb)) != tests[i].rc)
	{
	  printf("prefix hosts fail %ld %d\n", i, rc);
	  break;
	}

      scamper_addr_free(sa);
      scamper_addr_free(sb);
    }

  if(i != testc)
    return -1;

  return 0;
}

static int fbd_tests(void)
{
  sc_cmp_t tests[] = {
    {"192.0.2.1",                "192.0.2.254",               25},
    {"192.0.2.0",                "192.0.2.254",               25},
    {"192.0.2.0",                "192.0.2.255",               25},
    {"192.0.2.1",                "192.0.2.2",                 31},
    {"192.0.2.1",                "192.0.2.0",                 32},
    {"192.0.2.1",                "192.0.2.1",                 32},
    {"2001:db8:8000::",          "2001:db8::",                33},
    {"2001:db8:4000::",          "2001:db8::",                34},
    {"2001:db8:2000::",          "2001:db8::",                35},
    {"2001:db8:1000::",          "2001:db8::",                36},
    {"2001:db8::1",              "2001:db8::2",               127},
    {"2001:db8::0",              "2001:db8::1",               128},
    {"0.0.0.0",                  "255.255.255.255",           1},
    {"192.0.2.1",                "192.0.2.1",                 32},
  };
  scamper_addr_t *sa, *sb;
  size_t i, testc = sizeof(tests) / sizeof(sc_cmp_t);
  int rc;

  for(i=0; i<testc; i++)
    {
      rc = -2;
      if((sa = scamper_addr_fromstr_unspec(tests[i].a)) == NULL ||
	 (sb = scamper_addr_fromstr_unspec(tests[i].b)) == NULL ||
	 (rc = scamper_addr_fbd(sa, sb)) != tests[i].rc)
	{
	  printf("fbd fail %ld %d\n", i, rc);
	  break;
	}

      scamper_addr_free(sa);
      scamper_addr_free(sb);
    }

  if(i != testc)
    return -1;

  return 0;
}  

int main(int argc, char *argv[])
{
  if((addrcache = scamper_addrcache_alloc()) == NULL)
    return -1;

  if(reserved_tests() != 0 || cmp_tests(0) != 0 || cmp_tests(1) != 0 ||
     prefix_tests() != 0 || prefix_host_tests() != 0 || fbd_tests() != 0)
    return -1;

  scamper_addrcache_free(addrcache);

  printf("OK\n");
  return 0;
}
