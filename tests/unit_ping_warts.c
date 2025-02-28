/*
 * unit_ping_warts : unit tests for warts ping storage
 *
 * $Id: unit_ping_warts.c,v 1.4 2025/02/13 01:23:45 mjl Exp $
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

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_file.h"
#include "scamper_ping.h"
#include "common_ping.h"
#include "mjl_list.h"
#include "utils.h"

typedef scamper_ping_t * (*test_func_t)(void);

static int write_file(const char *filename, const scamper_ping_t *ping)
{
  scamper_file_t *file = NULL;
  int rc = -1;

  if((file = scamper_file_open(filename, 'w', "warts")) == NULL ||
     scamper_file_write_ping(file, ping, NULL) != 0)
    {
      printf("could not write\n");
      goto done;
    }
  rc = 0;

 done:
  if(file != NULL) scamper_file_close(file);
  return rc;
}

static int check_file(const char *filename, const scamper_ping_t *in)
{
  scamper_file_t *file = NULL;
  uint16_t obj_type;
  void *obj_data = NULL;
  int rc = -1;

  if((file = scamper_file_open(filename, 'r', "warts")) == NULL ||
     scamper_file_read(file, NULL, &obj_type, &obj_data) != 0 ||
     obj_type != SCAMPER_FILE_OBJ_PING ||
     ping_ok(in, obj_data) != 0)
    goto done;

  rc = 0;

 done:
  if(obj_data != NULL && obj_type == SCAMPER_FILE_OBJ_PING)
    scamper_ping_free(obj_data);
  if(file != NULL) scamper_file_close(file);
  return rc;  
}

int main(int argc, char *argv[])
{
  static test_func_t tests[] = {
    ping_1,
    ping_2,
  };
  size_t i, testc = sizeof(tests) / sizeof(test_func_t);
  scamper_ping_t *ping;
  char filename[128];
  int check = 0;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
#endif

  if(argc != 3 ||
     (strcasecmp(argv[1], "dump") != 0 &&
      strcasecmp(argv[1], "check") != 0))
    {
      fprintf(stderr, "usage: unit_ping_warts dump|check dir\n");
      return -1;
    }

  if(strcasecmp(argv[1], "check") == 0)
    check = 1;

  for(i=0; i<testc; i++)
    {
      snprintf(filename, sizeof(filename),
	       "%s/ping-%03x.warts", argv[2], (int)i);

#ifdef DMALLOC
      if(check != 0)
	dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

      if((ping = tests[i]()) == NULL)
	{
	  printf("could not create ping %d\n", (int)i);
	  return -1;
	}

      if(write_file(filename, ping) != 0)
	{
	  printf("could not write ping %d\n", (int)i);
	  return -1;
	}

      if(check != 0 && check_file(filename, ping) != 0)
	{
	  printf("fail check %d\n", (int)i);
	  return -1;
	}

      scamper_ping_free(ping);

#ifdef DMALLOC
      if(check != 0)
	{
	  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
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
