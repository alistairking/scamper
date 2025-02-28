/*
 * unit_udpprobe_warts : unit tests for warts udpprobe storage
 *
 * $Id: unit_udpprobe_warts.c,v 1.2 2025/02/13 18:48:55 mjl Exp $
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

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_file.h"
#include "scamper_udpprobe.h"
#include "scamper_udpprobe_int.h"
#include "scamper_ifname.h"
#include "scamper_ifname_int.h"
#include "common_ok.h"
#include "mjl_list.h"
#include "utils.h"

typedef scamper_udpprobe_t * (*test_func_t)(void);

static int udpprobe_ok(const scamper_udpprobe_t *in, const scamper_udpprobe_t *out)
{
  assert(in != NULL);
  if(out == NULL ||
     addr_ok(in->src, out->src) != 0 ||
     addr_ok(in->dst, out->dst) != 0 ||
     in->userid != out->userid ||
     timeval_cmp(&in->start, &out->start) != 0 ||
     timeval_cmp(&in->wait_probe, &out->wait_probe) != 0 ||
     timeval_cmp(&in->wait_timeout, &out->wait_timeout) != 0 ||
     in->probe_count != out->probe_count ||
     in->sport != out->sport ||
     in->dport != out->dport ||
     in->flags != out->flags)
    return -1;

  return 0;
}

static scamper_udpprobe_t *udpprobe_1(void)
{
  scamper_udpprobe_t *up = NULL;
  uint8_t data [] = { 5, 56, 32, 59};

  if((up = scamper_udpprobe_alloc()) == NULL ||
     (up->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (up->dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL)
    goto err;

  up->userid               = 69;
  up->sport                = 120;
  up->dport                = 154;
  up->probe_count          = 163;
  up->stop_count           = 50;
  up->start.tv_sec         = 1724828853;
  up->start.tv_usec        = 123456;
  up->wait_timeout.tv_sec  = 1;
  up->wait_timeout.tv_usec = 0;
  up->wait_probe.tv_sec    = 5;
  up->wait_probe.tv_usec   = 0;
  up->flags                = 0;
  up->data                 = memdup(data, 4);
  up->len                  = 4;
  up->stop = SCAMPER_UDPPROBE_STOP_DONE;

  return up;

 err:
  if(up != NULL) scamper_udpprobe_free(up);
  return NULL;
}

static int write_file(const char *filename, const scamper_udpprobe_t *up)
{
  scamper_file_t *file = NULL;
  int rc = -1;

  if((file = scamper_file_open(filename, 'w', "warts")) == NULL ||
     scamper_file_write_udpprobe(file, up, NULL) != 0)
    {
      printf("could not write\n");
      goto done;
    }
  rc = 0;

 done:
  if(file != NULL) scamper_file_close(file);
  return rc;
}

static int check_file(const char *filename, const scamper_udpprobe_t *in)
{
  scamper_file_t *file = NULL;
  uint16_t obj_type;
  void *obj_data = NULL;
  int rc = -1;

  if((file = scamper_file_open(filename, 'r', "warts")) == NULL ||
     scamper_file_read(file, NULL, &obj_type, &obj_data) != 0 ||
     obj_type != SCAMPER_FILE_OBJ_UDPPROBE ||
     udpprobe_ok(in, obj_data) != 0)
    goto done;

  rc = 0;

 done:
  if(obj_data != NULL && obj_type == SCAMPER_FILE_OBJ_UDPPROBE)
    scamper_udpprobe_free(obj_data);
  if(file != NULL) scamper_file_close(file);
  return rc;  
}

int main(int argc, char *argv[])
{
  static test_func_t tests[] = {
    udpprobe_1,
  };
  size_t i, testc = sizeof(tests) / sizeof(test_func_t);
  scamper_udpprobe_t *up;
  char filename[128];
  int check = 0;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
#endif

  if(argc != 3 ||
     (strcasecmp(argv[1], "dump") != 0 &&
      strcasecmp(argv[1], "check") != 0))
    {
      fprintf(stderr, "usage: unit_udpprobe_warts dump|check dir\n");
      return -1;
    }

  if(strcasecmp(argv[1], "check") == 0)
    check = 1;

  for(i=0; i<testc; i++)
    {
      snprintf(filename, sizeof(filename),
	       "%s/udpprobe-%03x.warts", argv[2], (int)i);

#ifdef DMALLOC
      if(check != 0)
	dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

      if((up = tests[i]()) == NULL)
	{
	  printf("could not create udpprobe %d\n", (int)i);
	  return -1;
	}

      if(write_file(filename, up) != 0)
	{
	  printf("could not write udpprobe %d\n", (int)i);
	  return -1;
	}

      if(check != 0 && check_file(filename, up) != 0)
	{
	  printf("fail check %d\n", (int)i);
	  return -1;
	}

      scamper_udpprobe_free(up);

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

  printf("OK\n");
  return 0;
}
