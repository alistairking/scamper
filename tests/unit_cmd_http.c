/*
 * unit_cmd_http : unit tests for http commands
 *
 * $Id: unit_cmd_http.c,v 1.6 2024/02/13 04:59:48 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2023 Matthew Luckie
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
#include "scamper_http.h"
#include "scamper_http_cmd.h"
#include "common.h"
#include "utils.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(const scamper_http_t *http);
} sc_test_t;

scamper_addrcache_t *addrcache = NULL;

static int isnull(const scamper_http_t *in)
{
  return (in == NULL) ? 0 : -1;
}

static int http_check(const scamper_http_t *http, const char *ip,
		      uint8_t type, const char *host_cmp, uint16_t dport,
		      const char *file_cmp)
{
  const char *file, *host;
  if(scamper_http_type_get(http) != type ||
     check_addr(scamper_http_dst_get(http), ip) != 0 ||
     (host = scamper_http_host_get(http)) == NULL ||
     strcmp(host, host_cmp) != 0 ||
     (file = scamper_http_file_get(http)) == NULL ||
     strcmp(file, file_cmp) != 0 ||
     scamper_http_dport_get(http) != dport)
    return -1;
  return 0;
}

static int http_example(const scamper_http_t *http)
{
  return http_check(http, "192.0.2.1", SCAMPER_HTTP_TYPE_HTTP,
		    "www.example.com", 80, "/");
}

static int http_example_userid(const scamper_http_t *http)
{
  if(http_check(http, "192.0.2.1", SCAMPER_HTTP_TYPE_HTTP,
		"www.example.com", 80, "/") != 0 ||
     scamper_http_userid_get(http) != 69)
    return -1;
  return 0;
}

static int https_example(const scamper_http_t *http)
{
  return http_check(http, "2001:db8::1", SCAMPER_HTTP_TYPE_HTTPS,
		    "www.example.com", 443, "/");
}

static int https_example_7443(const scamper_http_t *http)
{
  return http_check(http, "2001:db8::1", SCAMPER_HTTP_TYPE_HTTPS,
		    "www.example.com", 7443, "/");
}

static int https_example_foo(const scamper_http_t *http)
{
  return http_check(http, "2001:db8::1", SCAMPER_HTTP_TYPE_HTTPS,
		    "www.example.com", 443, "/foo.txt");
}

static int http_example_header(const scamper_http_t *http)
{
  const char *header;
  if(http_check(http, "192.0.2.1", SCAMPER_HTTP_TYPE_HTTP,
		"www.example.com", 80, "/") != 0 ||
     scamper_http_headerc_get(http) != 1 ||
     (header = scamper_http_header_get(http, 0)) == NULL ||
     strcmp(header, "User-Agent: mjl") != 0)
    return -1;
  return 0;
}

static int http_example_header_foob(const scamper_http_t *http)
{
  const char *header;
  if(http_check(http, "192.0.2.1", SCAMPER_HTTP_TYPE_HTTP,
		"www.example.com", 80, "/") != 0 ||
     scamper_http_headerc_get(http) != 1 ||
     (header = scamper_http_header_get(http, 0)) == NULL ||
     strcmp(header, "foo:b") != 0)
    return -1;
  return 0;
}

static int http_example_header_foo_b_b(const scamper_http_t *http)
{
  const char *header;
  if(http_check(http, "192.0.2.1", SCAMPER_HTTP_TYPE_HTTP,
		"www.example.com", 80, "/") != 0 ||
     scamper_http_headerc_get(http) != 1 ||
     (header = scamper_http_header_get(http, 0)) == NULL ||
     strcmp(header, "foo: b b") != 0)
    return -1;
  return 0;
}

static int https_insecure(const scamper_http_t *http)
{
  if(http_check(http, "192.0.2.1", SCAMPER_HTTP_TYPE_HTTPS,
		"www.example.com", 443, "/") != 0 ||
     scamper_http_flag_is_insecure(http) == 0)
    return -1;
  return 0;
}

static int https_maxtime(const scamper_http_t *http)
{
  const struct timeval *tv;
  if(http_check(http, "192.0.2.1", SCAMPER_HTTP_TYPE_HTTPS,
		"www.example.com", 443, "/") != 0 ||
     (tv = scamper_http_maxtime_get(http)) == NULL ||
     tv->tv_sec != 45 || tv->tv_usec != 654321)
    return -1;
  return 0;
}

static int check(const char *cmd, int (*func)(const scamper_http_t *in))
{
  scamper_http_t *http;
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
  http = scamper_do_http_alloc(dup, errbuf, sizeof(errbuf));
  free(dup);
  if((rc = func(http)) != 0)
    printf("fail: %s\n", cmd);
  if(http != NULL)
    scamper_http_free(http);

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
    {"-u http://www.example.com/ 192.0.2.1", http_example},
    {"-u http://www.example.com/ -U 69 192.0.2.1", http_example_userid},
    {"-u https://www.example.com 2001:db8::1", https_example},
    {"-u https://www.example.com:7443 2001:db8::1", https_example_7443},
    {"-u https://www.example.com/foo.txt 2001:db8::1", https_example_foo},
    {"-u 'https://www.example.com/foo.txt' 2001:db8::1", https_example_foo},
    {"-u \"https://www.example.com/foo.txt\" 2001:db8::1", https_example_foo},
    {"-u https://www.example.com:77443 2001:db8::1", isnull},
    {"-u htt://www.example.com 2001:db8::1", isnull},
    {"-u http://www.example;.com 2001:db8::1", isnull},
    {"-u https://www.example.com: 2001:db8::1", isnull},
    {"-u https://www.example.com\\ 2001:db8::1", isnull},
    /* check header parsing */
    {"-H 'User-Agent: mjl' -u http://www.example.com/ 192.0.2.1",
     http_example_header},
    {"-H 'host: www.example.com' -u http://www.example.com/ 192.0.2.1", isnull},
    {"-H foo -u http://www.example.com/ 192.0.2.1", isnull},
    {"-H foo: -u http://www.example.com/ 192.0.2.1", isnull},
    {"-H 'foo : bar' -u http://www.example.com/ 192.0.2.1", isnull},
    {"-H 'foo: b b' -u http://www.example.com/ 192.0.2.1",
     http_example_header_foo_b_b},
    {"-H foo:b -u http://www.example.com/ 192.0.2.1",
     http_example_header_foob},
    {"-O insecure -u https://www.example.com/ 192.0.2.1", https_insecure},
    {"-m 45.654321 -u https://www.example.com/ 192.0.2.1", https_maxtime},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];

  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/http-%03x.txt", argv[2], (int)i);
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
