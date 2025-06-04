/*
 * unit_text : unit tests for rendering text
 *
 * $Id: unit_text.c,v 1.1 2025/05/17 08:56:19 mjl Exp $
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

#include "scamper_ping.h"
#include "common_ping.h"

#include "scamper_trace.h"
#include "common_trace.h"

#include "mjl_list.h"
#include "utils.h"

typedef void * (*makers_func_t)(size_t i);
typedef char * (*text_func_t)(void *data, size_t *len);
typedef void   (*free_func_t)(void *data);

typedef struct sc_test
{
  const char    *type_str;
  uint16_t       type_id;
  size_t       (*makerc)(void);
  makers_func_t  makers;
  text_func_t    text;
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
      (text_func_t)scamper_dealias_totext,
      (free_func_t)scamper_dealias_free,
    },
    {
      "ping",
      SCAMPER_FILE_OBJ_PING,
      ping_makerc,
      (makers_func_t)ping_makers,
      (text_func_t)scamper_ping_totext,
      (free_func_t)scamper_ping_free,
    },
    {
      "trace",
      SCAMPER_FILE_OBJ_TRACE,
      trace_makerc,
      (makers_func_t)trace_makers,
      (text_func_t)scamper_trace_totext,
      (free_func_t)scamper_trace_free,
    },
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  size_t j, makerc;
  size_t len;
  void *data;
  char *str;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
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

	  if((str = tests[i].text(data, &len)) == NULL)
	    {
	      printf("could not text %s %d\n", tests[i].type_str, (int)j);
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
