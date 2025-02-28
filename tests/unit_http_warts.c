/*
 * unit_http_warts : unit tests for warts http storage
 *
 * $Id: unit_http_warts.c,v 1.2 2025/02/13 18:48:55 mjl Exp $
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
#include "scamper_http.h"
#include "scamper_http_int.h"
#include "scamper_ifname.h"
#include "scamper_ifname_int.h"
#include "common_ok.h"
#include "mjl_list.h"
#include "utils.h"

typedef scamper_http_t * (*test_func_t)(void);

static int http_ok(const scamper_http_t *in, const scamper_http_t *out)
{
  assert(in != NULL);
  if(out == NULL ||
     addr_ok(in->src, out->src) != 0 ||
     addr_ok(in->dst, out->dst) != 0 ||
     in->userid != out->userid ||
     timeval_cmp(&in->start, &out->start) != 0 ||
     in->sport != out->sport ||
     in->dport != out->dport ||
     in->flags != out->flags)
    return -1;

  return 0;
}

static scamper_http_t *http_1(void)
{
  scamper_http_t *http = NULL;

  if((http = scamper_http_alloc()) == NULL ||
     (http->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (http->dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL)
    goto err;

  http->userid               = 69;
  http->sport                = 120;
  http->dport                = 443;
  http->start.tv_sec         = 1724828853;
  http->start.tv_usec        = 123456;
  http->flags                = 0;
  http->stop = SCAMPER_HTTP_STOP_DONE;
  http->type = SCAMPER_HTTP_TYPE_HTTPS;
  http->host = strdup("www.example.org");
  http->file = strdup("/index.html");
  return http;

 err:
  if(http != NULL) scamper_http_free(http);
  return NULL;
}

static int write_file(const char *filename, const scamper_http_t *http)
{
  scamper_file_t *file = NULL;
  int rc = -1;

  if((file = scamper_file_open(filename, 'w', "warts")) == NULL ||
     scamper_file_write_http(file, http, NULL) != 0)
    {
      printf("could not write\n");
      goto done;
    }
  rc = 0;

 done:
  if(file != NULL) scamper_file_close(file);
  return rc;
}

static int check_file(const char *filename, const scamper_http_t *in)
{
  scamper_file_t *file = NULL;
  uint16_t obj_type;
  void *obj_data = NULL;
  int rc = -1;

  if((file = scamper_file_open(filename, 'r', "warts")) == NULL ||
     scamper_file_read(file, NULL, &obj_type, &obj_data) != 0 ||
     obj_type != SCAMPER_FILE_OBJ_HTTP ||
     http_ok(in, obj_data) != 0)
    goto done;

  rc = 0;

 done:
  if(obj_data != NULL && obj_type == SCAMPER_FILE_OBJ_HTTP)
    scamper_http_free(obj_data);
  if(file != NULL) scamper_file_close(file);
  return rc;  
}

int main(int argc, char *argv[])
{
  static test_func_t tests[] = {
    http_1,
  };
  size_t i, testc = sizeof(tests) / sizeof(test_func_t);
  scamper_http_t *http;
  char filename[128];
  int check = 0;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
#endif

  if(argc != 3 ||
     (strcasecmp(argv[1], "dump") != 0 &&
      strcasecmp(argv[1], "check") != 0))
    {
      fprintf(stderr, "usage: unit_http_warts dump|check dir\n");
      return -1;
    }

  if(strcasecmp(argv[1], "check") == 0)
    check = 1;

  for(i=0; i<testc; i++)
    {
      snprintf(filename, sizeof(filename),
	       "%s/http-%03x.warts", argv[2], (int)i);

#ifdef DMALLOC
      if(check != 0)
	dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

      if((http = tests[i]()) == NULL)
	{
	  printf("could not create http %d\n", (int)i);
	  return -1;
	}

      if(write_file(filename, http) != 0)
	{
	  printf("could not write http %d\n", (int)i);
	  return -1;
	}

      if(check != 0 && check_file(filename, http) != 0)
	{
	  printf("fail check %d\n", (int)i);
	  return -1;
	}

      scamper_http_free(http);

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
