/*
 * unit_cmd_sniff : unit tests for sniff commands
 *
 * $Id: unit_cmd_sniff.c,v 1.3 2024/02/13 04:59:48 mjl Exp $
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

#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_sniff.h"
#include "scamper_sniff_cmd.h"

#include "utils.h"
#include "common.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(const scamper_sniff_t *sniff);
} sc_test_t;

scamper_addrcache_t *addrcache = NULL;

static int defaults(const scamper_sniff_t *in)
{
  if(in == NULL ||
     check_addr(scamper_sniff_src_get(in), "192.0.2.1") != 0 ||
     scamper_sniff_icmpid_get(in) != 12345)
    return -1;
  return 0;
}

static int time_55s(const scamper_sniff_t *in)
{
  const struct timeval *tv;
  if(defaults(in) != 0 ||
     (tv = scamper_sniff_limit_time_get(in)) == NULL ||
     tv->tv_sec != 55 || tv->tv_usec != 0)
    return -1;
  return 0;
}

static int count_69(const scamper_sniff_t *in)
{
  if(defaults(in) != 0 ||
     scamper_sniff_limit_pktc_get(in) != 69)
    return -1;
  return 0;
}

static int check(const char *cmd, int (*func)(const scamper_sniff_t *in))
{
  scamper_sniff_t *sniff;
  char *dup, errbuf[256];
  int rc;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

  if((addrcache = scamper_addrcache_alloc()) == NULL)
    return -1;

  if((dup = strdup(cmd)) == NULL)
    return -1;
  sniff = scamper_do_sniff_alloc(dup, errbuf, sizeof(errbuf));
  free(dup);
  if((rc = func(sniff)) != 0)
    printf("fail: %s\n", cmd);
  if(sniff != NULL)
    scamper_sniff_free(sniff);

  scamper_addrcache_free(addrcache);

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(start_mem != stop_mem && rc == 0)
    {
      printf("memory leak: %s\n", cmd);
      rc = -1;
    }
#endif

  return rc;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {"-S 192.0.2.1 icmp[icmpid] == 12345", defaults},
    {"-S 192.0.2.1 -G 55s icmp[icmpid] == 12345", time_55s},
    {"-S 192.0.2.1 -c 69 icmp[icmpid] == 12345", count_69},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];

  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/sniff-%03x.txt", argv[2], (int)i);
	  if(dump_cmd(tests[i].cmd, filename) != 0)
	    break;
	}
    }
  else if(argc == 1)
    {
      for(i=0; i<testc; i++)
	if(check(tests[i].cmd, tests[i].func) != 0)
	  break;
    }
  else
    {
      printf("invalid usage\n");
      return -1;
    }

  if(i != testc)
    return -1;

  printf("OK\n");
  return 0;
}
