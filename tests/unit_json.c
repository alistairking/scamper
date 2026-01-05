/*
 * unit_json : unit tests for rendering json
 *
 * $Id: unit_json.c,v 1.2 2026/01/04 19:54:18 mjl Exp $
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

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_file.h"

#include "scamper_dealias.h"
#include "common_dealias.h"

#include "scamper_host.h"
#include "common_host.h"

#include "scamper_neighbourdisc.h"
#include "common_neighbourdisc.h"

#include "scamper_owamp.h"
#include "common_owamp.h"

#include "scamper_ping.h"
#include "common_ping.h"

#include "scamper_trace.h"
#include "common_trace.h"

#include "scamper_udpprobe.h"
#include "common_udpprobe.h"

#include "mjl_list.h"
#include "utils.h"

typedef void * (*makers_func_t)(size_t i);
typedef char * (*json_func_t)(void *data, size_t *len);
typedef void   (*free_func_t)(void *data);

typedef struct sc_test
{
  const char    *type_str;
  uint16_t       type_id;
  size_t       (*makerc)(void);
  makers_func_t  makers;
  json_func_t    json;
  free_func_t    dofree;
} sc_test_t;

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {
      "dealias",
      SCAMPER_FILE_OBJ_DEALIAS,
      dealias_makerc,
      (makers_func_t)dealias_makers,
      (json_func_t)scamper_dealias_tojson,
      (free_func_t)scamper_dealias_free,
    },
    {
      "host",
      SCAMPER_FILE_OBJ_HOST,
      host_makerc,
      (makers_func_t)host_makers,
      (json_func_t)scamper_host_tojson,
      (free_func_t)scamper_host_free,
    },
    {
      "neighbourdisc",
      SCAMPER_FILE_OBJ_NEIGHBOURDISC,
      neighbourdisc_makerc,
      (makers_func_t)neighbourdisc_makers,
      (json_func_t)scamper_neighbourdisc_tojson,
      (free_func_t)scamper_neighbourdisc_free,
    },
    {
      "owamp",
      SCAMPER_FILE_OBJ_OWAMP,
      owamp_makerc,
      (makers_func_t)owamp_makers,
      (json_func_t)scamper_owamp_tojson,
      (free_func_t)scamper_owamp_free,
    },
    {
      "ping",
      SCAMPER_FILE_OBJ_PING,
      ping_makerc,
      (makers_func_t)ping_makers,
      (json_func_t)scamper_ping_tojson,
      (free_func_t)scamper_ping_free,
    },
    {
      "trace",
      SCAMPER_FILE_OBJ_TRACE,
      trace_makerc,
      (makers_func_t)trace_makers,
      (json_func_t)scamper_trace_tojson,
      (free_func_t)scamper_trace_free,
    },
    {
      "udpprobe",
      SCAMPER_FILE_OBJ_UDPPROBE,
      udpprobe_makerc,
      (makers_func_t)udpprobe_makers,
      (json_func_t)scamper_udpprobe_tojson,
      (free_func_t)scamper_udpprobe_free,
    },
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  size_t j, makerc;
  size_t len;
  void *data;
  char *str;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  time_t tt = 1746761704;
  char tmp[128];
#endif

#ifdef DMALLOC
  strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", localtime(&tt));
#endif

  for(i=0; i<testc; i++)
    {
      makerc = tests[i].makerc();

      for(j=0; j<makerc; j++)
	{
#ifdef DMALLOC
	  dmalloc_get_stats(NULL, NULL, NULL, NULL,
			    &start_mem, NULL, NULL, NULL, NULL);
#endif

	  if((data = tests[i].makers(j)) == NULL)
	    {
	      printf("could not create %s %d\n", tests[i].type_str, (int)j);
	      return -1;
	    }

	  if((str = tests[i].json(data, &len)) == NULL)
	    {
	      printf("could not json %s %d\n", tests[i].type_str, (int)j);
	      return -1;
	    }

	  tests[i].dofree(data);
	  free(str);

#ifdef DMALLOC
	  dmalloc_get_stats(NULL, NULL, NULL, NULL,
			    &stop_mem, NULL, NULL, NULL, NULL);
	  if(start_mem != stop_mem)
	    {
	      printf("memory leak: %s %d\n", tests[i].type_str, (int)j);
	      return -1;
	    }
#endif
	}
    }

  printf("OK\n");
  return 0;
}
