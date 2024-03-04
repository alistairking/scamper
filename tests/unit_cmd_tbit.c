/*
 * unit_cmd_tbit : unit tests for tbit commands
 *
 * $Id: unit_cmd_tbit.c,v 1.2 2024/02/13 04:59:48 mjl Exp $
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
#include "scamper_tbit.h"
#include "scamper_tbit_cmd.h"

#include "utils.h"
#include "common.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(const scamper_tbit_t *tbit);
} sc_test_t;

scamper_addrcache_t *addrcache = NULL;

static int notnull(const scamper_tbit_t *in)
{
  if(in == NULL)
    return -1;
  return 0;
}

static int check(const char *cmd, int (*func)(const scamper_tbit_t *in))
{
  scamper_tbit_t *tbit;
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
  tbit = scamper_do_tbit_alloc(dup, errbuf, sizeof(errbuf));
  free(dup);
  if((rc = func(tbit)) != 0)
    printf("fail: %s\n", cmd);
  if(tbit != NULL)
    scamper_tbit_free(tbit);

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
    {"-t pmtud -U 55 -u http://www.example.com/ -s 45678 -m 1460 -M 1280 192.0.2.1", notnull},
    {"-t blind-rst -p bgp -T 69 -b 1909 -s 56789 192.0.2.1", notnull},
    {"-t blind-syn -p bgp -T 69 -b 1909 -s 56789 192.0.2.1", notnull},
    {"-t blind-data -p bgp -T 69 -b 1909 -s 56789 192.0.2.1", notnull},
    {"-t icw -u http://www.example.com/ -s 45678 192.0.2.1", notnull},
    {"-t null -w 2 -O tcpts -O sack -u http://www.example.com/ -s 45678 192.0.2.1", notnull},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];

  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/tbit-%03x.txt", argv[2], (int)i);
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
