/*
 * unit_warts : unit tests for warts storage
 *
 * $Id: unit_warts.c,v 1.4 2025/04/23 09:56:28 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024      Marcus Luckie
 * Copyright (C) 2024-2025 Matthew Luckie
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

#include "scamper_http.h"
#include "common_http.h"

#include "scamper_ping.h"
#include "common_ping.h"

#include "scamper_trace.h"
#include "common_trace.h"

#include "scamper_udpprobe.h"
#include "common_udpprobe.h"

#include "mjl_list.h"
#include "utils.h"

typedef void * (*makers_func_t)(size_t i);
typedef int    (*write_func_t)(scamper_file_t *sf, const void *data, void *);
typedef int    (*check_func_t)(const void *a, const void *b);
typedef void   (*free_func_t)(void *data);

typedef struct sc_test
{
  const char    *type_str;
  uint16_t       type_id;
  size_t       (*makerc)(void);
  makers_func_t  makers;
  write_func_t   write;
  check_func_t   check;
  free_func_t    dofree;
} sc_test_t;

static int write_file(const char *filename, write_func_t wf, const void *data)
{
  scamper_file_t *file = NULL;
  int rc = -1;

  if((file = scamper_file_open(filename, 'w', "warts")) == NULL ||
     wf(file, data, NULL) != 0)
    {
      printf("could not write\n");
      goto done;
    }
  rc = 0;

 done:
  if(file != NULL) scamper_file_close(file);
  return rc;
}

static int check_file(const char *filename, check_func_t cf, free_func_t ff,
		      uint16_t in_type, const void *in_data)
{
  scamper_file_t *file = NULL;
  uint16_t obj_type;
  void *obj_data = NULL;
  int rc = -1;

  if((file = scamper_file_open(filename, 'r', "warts")) == NULL ||
     scamper_file_read(file, NULL, &obj_type, &obj_data) != 0 ||
     obj_type != in_type || cf(in_data, obj_data) != 0)
    goto done;

  rc = 0;

 done:
  if(obj_data != NULL && obj_type == in_type)
    ff(obj_data);
  if(file != NULL) scamper_file_close(file);
  return rc;  
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {
      "dealias",
      SCAMPER_FILE_OBJ_DEALIAS,
      dealias_makerc,
      (makers_func_t)dealias_makers,
      (write_func_t)scamper_file_write_dealias,
      (check_func_t)dealias_ok,
      (free_func_t)scamper_dealias_free,
    },
    {
      "host",
      SCAMPER_FILE_OBJ_HOST,
      host_makerc,
      (makers_func_t)host_makers,
      (write_func_t)scamper_file_write_host,
      (check_func_t)host_ok,
      (free_func_t)scamper_host_free,
    },
    {
      "http",
      SCAMPER_FILE_OBJ_HTTP,
      http_makerc,
      (makers_func_t)http_makers,
      (write_func_t)scamper_file_write_http,
      (check_func_t)http_ok,
      (free_func_t)scamper_http_free,
    },
    {
      "ping",
      SCAMPER_FILE_OBJ_PING,
      ping_makerc,
      (makers_func_t)ping_makers,
      (write_func_t)scamper_file_write_ping,
      (check_func_t)ping_ok,
      (free_func_t)scamper_ping_free,
    },
    {
      "trace",
      SCAMPER_FILE_OBJ_TRACE,
      trace_makerc,
      (makers_func_t)trace_makers,
      (write_func_t)scamper_file_write_trace,
      (check_func_t)trace_ok,
      (free_func_t)scamper_trace_free,
    },
    {
      "udpprobe",
      SCAMPER_FILE_OBJ_UDPPROBE,
      udpprobe_makerc,
      (makers_func_t)udpprobe_makers,
      (write_func_t)scamper_file_write_udpprobe,
      (check_func_t)udpprobe_ok,
      (free_func_t)scamper_udpprobe_free,
    },
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  size_t j, makerc;
  char filename[128];
  void *data;
  int check = 0;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
#endif

  if(argc != 3 ||
     (strcasecmp(argv[1], "dump") != 0 &&
      strcasecmp(argv[1], "check") != 0))
    {
      fprintf(stderr, "usage: unit_warts dump|check dir\n");
      return -1;
    }

  if(strcasecmp(argv[1], "check") == 0)
    check = 1;

  for(i=0; i<testc; i++)
    {
      makerc = tests[i].makerc();

      for(j=0; j<makerc; j++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/%s-%03d.warts", argv[2], tests[i].type_str, (int)j);

#ifdef DMALLOC
	  if(check != 0)
	    dmalloc_get_stats(NULL, NULL, NULL, NULL,
			      &start_mem, NULL, NULL, NULL, NULL);
#endif

	  if((data = tests[i].makers(j)) == NULL)
	    {
	      printf("could not create %s %d\n", tests[i].type_str, (int)j);
	      return -1;
	    }

	  if(write_file(filename, tests[i].write, data) != 0)
	    {
	      printf("could not write %s %d\n", tests[i].type_str, (int)j);
	      return -1;
	    }

	  if(check != 0 && check_file(filename, tests[i].check, tests[i].dofree,
				      tests[i].type_id, data) != 0)
	    {
	      printf("fail check %s %d\n", tests[i].type_str, (int)j);
	      return -1;
	    }

	  tests[i].dofree(data);

#ifdef DMALLOC
	  if(check != 0)
	    {
	      dmalloc_get_stats(NULL, NULL, NULL, NULL,
				&stop_mem, NULL, NULL, NULL, NULL);
	      if(start_mem != stop_mem)
		{
		  printf("memory leak: %s %d\n", tests[i].type_str, (int)j);
		  return -1;
		}
	    }
#endif
	}
    }

  if(check != 0)
    printf("OK\n");

  return 0;
}
