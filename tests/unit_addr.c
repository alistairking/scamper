/*
 * unit_cmd_dealias : unit tests for dealias commands
 *
 * $Id: unit_addr.c,v 1.3 2023/09/24 22:35:01 mjl Exp $
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
    {SCAMPER_ADDR_TYPE_IPV6, "3000::", is_not_reserved}, /* ensure 2000::/3 check is ok */
    {SCAMPER_ADDR_TYPE_IPV6, "4000::", is_reserved},
    {SCAMPER_ADDR_TYPE_IPV6, "2001::66", is_reserved},   /* teredo */
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
