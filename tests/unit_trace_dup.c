/*
 * unit_trace_dup : unit tests for trace dup functions
 *
 * $Id: unit_trace_dup.c,v 1.1 2025/02/13 04:56:22 mjl Exp $
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
#include "scamper_trace.h"
#include "common_trace.h"
#include "mjl_list.h"
#include "utils.h"

typedef scamper_trace_t * (*test_func_t)(void);

int main(int argc, char *argv[])
{
  static test_func_t tests[] = {
    trace_1,
  };
  size_t i, testc = sizeof(tests) / sizeof(test_func_t);
  scamper_trace_t *in, *out;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
#endif

  for(i=0; i<testc; i++)
    {
#ifdef DMALLOC
      dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

      if((in = tests[i]()) == NULL)
	{
	  printf("could not create trace %d\n", (int)i);
	  return -1;
	}

      if((out = scamper_trace_dup(in)) == NULL)
	{
	  printf("could not dup trace %d\n", (int)i);
	  return -1;
	}

      if(trace_ok(in, out) != 0)
	{
	  printf("did not correctly dup %d\n", (int)i);
	  return -1;
	}

      scamper_trace_free(in);
      scamper_trace_free(out);

#ifdef DMALLOC
      dmalloc_get_stats(NULL,NULL,NULL,NULL,&stop_mem,NULL,NULL,NULL,NULL);
      if(start_mem != stop_mem)
	{
	  printf("memory leak: %d\n", (int)i);
	  return -1;
	}
#endif
    }

  printf("OK\n");
  return 0;
}
