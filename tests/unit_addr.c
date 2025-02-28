/*
 * unit_cmd_dealias : unit tests for dealias commands
 *
 * $Id: unit_addr.c,v 1.4 2025/02/20 19:07:21 mjl Exp $
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

typedef struct sc_test
{
  int type;
  const char *addr;
  int (*func)(scamper_addr_t *addr);
} sc_test_t;

scamper_addrcache_t *addrcache = NULL;

static int is_reserved(scamper_addr_t *addr)
{
  return (scamper_addr_isreserved(addr) != 0) ? 0 : -1;
}

static int is_not_reserved(scamper_addr_t *addr)
{
  return (scamper_addr_isreserved(addr) == 0) ? 0 : -1;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
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
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  int rc;

  if((addrcache = scamper_addrcache_alloc()) == NULL)
    return -1;

  for(i=0; i<testc; i++)
    {
      if((sa = scamper_addr_fromstr(tests[i].type, tests[i].addr)) == NULL)
	{
	  printf("resolve fail %ld: %s\n", i, tests[i].addr);
	  break;
	}
      rc = tests[i].func(sa);
      scamper_addr_free(sa);
      if(rc != 0)
	{
	  printf("unit fail %ld: %s\n", i, tests[i].addr);
	  break;
	}
    }

  scamper_addrcache_free(addrcache);

  if(i != testc)
    return -1;

  printf("OK\n");
  return 0;
}
