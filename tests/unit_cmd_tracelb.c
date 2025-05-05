/*
 * unit_cmd_tracelb : unit tests for tracelb commands
 *
 * $Id: unit_cmd_tracelb.c,v 1.3 2025/05/02 04:39:00 mjl Exp $
 *
 *        Marcus Luckie, Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024 Matthew Luckie
 * Copyright (C) 2024 Marcus Luckie
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
#include "scamper_tracelb.h"
#include "scamper_tracelb_cmd.h"

#include "utils.h"
#include "common.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(scamper_tracelb_t *trace);
} sc_test_t;

static int verbose = 0;

scamper_addrcache_t *addrcache = NULL;

static int isnull(scamper_tracelb_t *in)
{
  return (in == NULL) ? 0 : -1;
}

static int notnull(scamper_tracelb_t *in)
{
  return (in != NULL) ? 0 : -1;
}

static int confidence_95(scamper_tracelb_t *in)
{
  if (in == NULL ||
      scamper_tracelb_confidence_get(in) != 95)
    return -1;
  return 0;
}

static int dport_22(scamper_tracelb_t *in)
{
  if (in == NULL ||
      scamper_tracelb_dport_get(in) != 22)
    return -1;
  return 0;
}

static int firsthop_1(scamper_tracelb_t *in)
{
  if (in == NULL ||
      scamper_tracelb_firsthop_get(in) != 1)
    return -1;
  return 0;
}

static int firsthop_254(scamper_tracelb_t *in)
{
  if (in == NULL ||
      scamper_tracelb_firsthop_get(in) != 254)
    return -1;
  return 0;
}

static int gaplimit_5(scamper_tracelb_t *in)
{
  if (in == NULL ||
      scamper_tracelb_gaplimit_get(in) != 5)
    return -1;
  return 0;
}

static int attempts_5(scamper_tracelb_t *in)
{
  if (in == NULL ||
      scamper_tracelb_attempts_get(in) != 5)
    return -1;
  return 0;
}

static int maxprobec_3050(scamper_tracelb_t *in)
{
  if (in == NULL ||
      scamper_tracelb_probec_max_get(in) != 3050)
    return -1;
  return 0;
}

static int check(const char *cmd, int (*func)(scamper_tracelb_t *in))
{
  scamper_tracelb_t *trace;
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
  trace = scamper_do_tracelb_alloc(dup, errbuf, sizeof(errbuf));
  free(dup);
  if((rc = func(trace)) != 0)
    printf("fail: %s\n", cmd);
  if(trace != NULL)
    scamper_tracelb_free(trace);

  scamper_addrcache_free(addrcache);

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(start_mem != stop_mem && rc == 0)
    {
      printf("memory leak: %s\n", cmd);
      rc = -1;
    }
#endif

  if(func == isnull && verbose)
    printf("%s: %s\n", cmd, errbuf);

  return rc;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {"192.0.2.1", notnull},
    {"-c 95 192.0.2.1", confidence_95},
    {"-c 99 192.0.2.1", notnull},
    {"-d 22 192.0.2.1", dport_22},
    {"-f 1 192.0.2.1", firsthop_1},
    {"-f 254 192.0.2.1", firsthop_254},
    {"-g 5 192.0.2.1", gaplimit_5},
    {"-O ptr 192.0.2.1", notnull},
    {"-P UDP-dport 192.0.2.1", notnull},
    {"-q 5 192.0.2.1", attempts_5},
    {"-Q 3050 192.0.2.1", maxprobec_3050},
    {"-r 192.0.2.2 192.0.2.1", notnull},
    {"-s 3306 192.0.2.1", notnull},
    {"-t 5 192.0.2.1", notnull},
    {"-U 2 192.0.2.1", notnull},
    {"-w 2 192.0.2.1", notnull},
    {"-W 100 192.0.2.1", notnull},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];

  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
        {
          snprintf(filename, sizeof(filename),
                   "%s/tracelb-%03x.txt", argv[2], (int)i);
          if(dump_string(tests[i].cmd, filename) != 0)
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
