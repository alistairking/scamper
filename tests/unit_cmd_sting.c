/*
 * unit_cmd_sting : unit tests for sting commands
 *
 * $Id: unit_cmd_sting.c,v 1.4 2024/02/13 04:59:48 mjl Exp $
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
#include "scamper_list.h"
#include "scamper_sting.h"
#include "scamper_sting_cmd.h"

#include "utils.h"
#include "common.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(const scamper_sting_t *in);
} sc_test_t;

scamper_addrcache_t *addrcache = NULL;

static int isnull(const scamper_sting_t *in)
{
  return (in == NULL) ? 0 : -1;
}

static int i30(const scamper_sting_t *in)
{
  const struct timeval *tv;
  if(in == NULL ||
     (tv = scamper_sting_inter_get(in)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 30000)
    return -1;
  return 0;
}

static int m69(const scamper_sting_t *in)
{
  const struct timeval *tv;
  if(in == NULL ||
     (tv = scamper_sting_mean_get(in)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 69000)
    return -1;
  return 0;
}

static int defaults(const scamper_sting_t *in)
{
  const struct timeval *tv;
  if(in == NULL ||
     check_addr(scamper_sting_dst_get(in), "192.0.2.1") != 0 ||
     scamper_sting_seqskip_get(in) != 3 ||
     scamper_sting_dport_get(in) != 80 ||
     scamper_sting_count_get(in) != 48 ||
     (tv = scamper_sting_mean_get(in)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 100000 ||
     (tv = scamper_sting_inter_get(in)) == NULL ||
     tv->tv_sec != 2 || tv->tv_usec != 0)
    return -1;
  return 0;
}

static int check(const char *cmd, int (*func)(const scamper_sting_t *in))
{
  scamper_sting_t *sting;
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
  sting = scamper_do_sting_alloc(dup, errbuf, sizeof(errbuf));
  free(dup);
  if((rc = func(sting)) != 0)
    printf("fail: %s\n", cmd);
  if(sting != NULL)
    scamper_sting_free(sting);

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
    {"-i 30ms 192.0.2.1", i30},
    {"-i 0ms 192.0.2.1", isnull},
    {"-i 11s 192.0.2.1", isnull},
    {"-m 69ms 192.0.2.1", m69},
    {"-m 0ms 192.0.2.1", isnull},
    {"-m 1.1s 192.0.2.1", isnull},
    {"192.0.2.1", defaults},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];

  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/sting-%03x.txt", argv[2], (int)i);
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
