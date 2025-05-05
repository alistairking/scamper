/*
 * unit_config : unit test for config system
 *
 * $Id: unit_config.c,v 1.1 2025/05/03 04:45:03 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2025 Matthew Luckie
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

#include "common.h"
#include "scamper_config.h"
#include "utils.h"

extern scamper_config_t *config;

typedef struct sc_test
{
  const char *config;
  int (*check)(void);
} sc_test_t;

static int trace_disable(void)
{
  if(config->trace_enable != 0 ||
     config->tracelb_enable == 0)
    return -1;
  return 0;
}

static int tracelb_disable(void)
{
  if(config->trace_enable == 0 ||
     config->tracelb_enable != 0)
    return -1;
  return 0;
}

static int trace_ping_disable(void)
{
  if(config->trace_enable != 0 ||
     config->ping_enable != 0)
    return -1;
  return 0;
}

static int check_config(const char *file, int (*check)(void))
{
  if(scamper_config_init(NULL) != 0 ||
     scamper_config_read(file) != 0 ||
     check() != 0)
    return -1;

  scamper_config_cleanup();
  return 0;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {"# disable traceroute\n"
     "trace.enable=0",
     trace_disable},
    {"# disable traceroute\n"
     "trace.enable=0\n",
     trace_disable},
    {"# disable traceroute\n"
     "trace.enable= 0\n",
     trace_disable},
    {"# disable traceroute\n"
     "trace.enable = 0\n"
     "\n",
     trace_disable},
    {"# disable MDA traceroute\n"
     "tracelb.enable = 0",
     tracelb_disable},
    {"# disable ping and trace\n"
     "\n"
     "trace.enable=0\n"
     "ping.enable=0\n",
     trace_ping_disable},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];
  int check = 0;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
#endif

  if(argc != 3 ||
     (strcasecmp(argv[1], "dump") != 0 &&
      strcasecmp(argv[1], "check") != 0))
    {
      fprintf(stderr, "usage: unit_config dump|check dir\n");
      return -1;
    }

  if(strcasecmp(argv[1], "check") == 0)
    check = 1;

  for(i=0; i<testc; i++)
    {
      snprintf(filename, sizeof(filename),
	       "%s/config-%03x.txt", argv[2], (int)i);

#ifdef DMALLOC
      if(check != 0)
	dmalloc_get_stats(NULL, NULL, NULL, NULL,
			  &start_mem, NULL, NULL, NULL, NULL);
#endif

      if(dump_string(tests[i].config, filename) != 0)
	break;

      if(check != 0 && check_config(filename, tests[i].check) != 0)
	{
	  printf("fail check %d\n", (int)i);
	  return -1;
	}

#ifdef DMALLOC
      if(check != 0)
	{
	  dmalloc_get_stats(NULL, NULL, NULL, NULL,
			    &stop_mem, NULL, NULL, NULL, NULL);
	  if(start_mem != stop_mem)
	    {
	      printf("memory leak: %d\n", (int)i);
	      return -1;
	    }
	}
#endif
    }

  if(check != 0)
    printf("OK\n");
  return 0;
}
