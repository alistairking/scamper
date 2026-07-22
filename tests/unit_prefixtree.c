/*
 * unit_prefixtree : unit tests for prefixtree structure
 *
 * $Id: unit_prefixtree.c,v 1.3 2026/07/11 03:57:59 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2025-2026 Matthew Luckie
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

#include "mjl_prefixtree.h"
#include "utils.h"

int ip6_bit(const struct in6_addr *ip, int bit);
int prefix6_bit(const prefix6_t *pref, int bit);

typedef struct sc_prefix
{
  char       *str;
  int         i;
  prefix4_t  *pf4;
} sc_prefix_t;

typedef struct sc_test
{
  char       *str;
  int         i;
} sc_test_t;

static int test_ipv4_1(void)
{
  sc_prefix_t prefixes[] = {
    {"0.0.0.0/0",       1, NULL},
    {"192.0.2.0/24",    2, NULL},
    {"192.0.31.0/24",   3, NULL},
    {"192.0.32.0/24",   4, NULL},
    {"192.0.32.128/25", 5, NULL},
  };
  sc_test_t tests[] = {
    {"1.2.3.4",      1},
    {"192.0.1.255",  1},
    {"192.0.2.0",    2},
    {"192.0.2.2",    2},
    {"192.0.2.255",  2},
    {"192.0.3.0",    1},
    {"192.0.31.3",   3},
    {"192.0.32.4",   4},
    {"192.0.32.127", 4},
    {"192.0.32.128", 5},
    {"192.0.32.255", 5},
    {"192.0.33.0",   1},
    {"192.0.33.2",   1},
  };
  size_t i, prefixc = sizeof(prefixes) / sizeof(sc_prefix_t);
  size_t testc = sizeof(tests) / sizeof(sc_test_t);
  prefixtree_t *tree = NULL;
  struct sockaddr_in sin;
  prefix4_t *pf4;
  int rc = -1;

  if((tree = prefixtree_alloc4()) == NULL)
    goto done;

  for(i=0; i<prefixc; i++)
    {
      if(prefix_to_sockaddr(prefixes[i].str, (struct sockaddr *)&sin) != 0)
	goto done;
      pf4 = prefix4_alloc(&sin.sin_addr, sin.sin_port, (void *)&prefixes[i].i);
      if(pf4 == NULL)
	goto done;
      prefixes[i].pf4 = pf4;
      if(prefixtree_insert4(tree, pf4) == NULL)
	goto done;
    }

  for(i=0; i<testc; i++)
    {
      if(sockaddr_compose_str((struct sockaddr *)&sin, AF_INET,
			      tests[i].str, 0) != 0 ||
	 (pf4 = prefixtree_find_ip4(tree, &sin.sin_addr)) == NULL ||
	 *((int *)pf4->ptr) != tests[i].i)
	goto done;
    }

  prefixtree_free(tree);

  rc = 0;

 done:
  for(i=0; i<prefixc; i++)
    if(prefixes[i].pf4 != NULL)
      prefix4_free(prefixes[i].pf4);
  return rc;
}

static int test_ipv6_bit(void)
{
  struct in6_addr in6;
  prefix6_t pf6;
  int i, j, t, rc = 0;

  for(i=0; i<128; i++)
    {
      memset(&in6, 0, sizeof(in6));
      in6.s6_addr[i/8] = (uint8_t)(1 << (7 - (i % 8)));
      memcpy(&pf6.net, &in6, sizeof(in6));

      for(j=0; j<128; j++)
	{
	  t = (in6.s6_addr[j/8] >> (7 - (j % 8))) & 1;
	  if(ip6_bit(&in6, j) != t)
	    {
	      printf("ip6_bit %d %d failed\n", i, j);
	      rc = -1;
	    }
	  if(prefix6_bit(&pf6, j) != t)
	    {
	      printf("prefix6_bit %d %d failed\n", i, j);
	      rc = -1;
	    }
	}
    }

  return rc;
}

int main(int argc, char *argv[])
{
  if(test_ipv4_1() != 0 ||
     test_ipv6_bit() != 0)
    return -1;
  printf("OK\n");
  return 0;
}
