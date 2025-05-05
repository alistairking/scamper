/*
 * unit_cmd_tbit : unit tests for tbit commands
 *
 * $Id: unit_cmd_tbit.c,v 1.4 2025/05/02 04:39:00 mjl Exp $
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

#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_tbit.h"
#include "scamper_tbit_cmd.h"

#include "utils.h"
#include "common.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(const scamper_tbit_t *tbit);
} sc_test_t;

scamper_addrcache_t *addrcache = NULL;

static int notnull(const scamper_tbit_t *in)
{
  if(in == NULL)
    return -1;
  return 0;
}

static int check_http(const scamper_tbit_t *in, uint8_t type,
		      const char *host, const char *file)
{
  scamper_tbit_app_http_t *http;
  if(scamper_tbit_app_proto_get(in) != SCAMPER_TBIT_APP_HTTP ||
     (http = scamper_tbit_app_http_get(in)) == NULL ||
     scamper_tbit_app_http_type_get(http) != type ||
     strcmp(scamper_tbit_app_http_host_get(http), "www.example.com") != 0 ||
     strcmp(scamper_tbit_app_http_file_get(http), "/") != 0)
    return -1;
  return 0;
}

static int null_fo(const scamper_tbit_t *in)
{
  const uint8_t *cookie, ccmp[4] = {0xab, 0xcd, 0xef, 0x01};
  const scamper_tbit_null_t *tnull;
  if(in == NULL ||
     scamper_tbit_type_get(in) != SCAMPER_TBIT_TYPE_NULL ||
     scamper_tbit_sport_get(in) != 45678 ||
     check_addr(scamper_tbit_dst_get(in), "192.0.2.1") != 0 ||
     check_http(in, SCAMPER_TBIT_APP_HTTP_TYPE_HTTP, "www.example.com", "/") != 0 ||
     (tnull = scamper_tbit_null_get(in)) == NULL ||
     scamper_tbit_client_fo_cookielen_get(in) != 4 ||
     (cookie = scamper_tbit_client_fo_cookie_get(in)) == NULL ||
     memcmp(cookie, ccmp, 4) != 0 ||
     scamper_tbit_null_options_get(tnull) != SCAMPER_TBIT_NULL_OPTION_FO)
    return -1;
  return 0;
}

static int check(const char *cmd, int (*func)(const scamper_tbit_t *in))
{
  scamper_tbit_t *tbit;
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
  tbit = scamper_do_tbit_alloc(dup, errbuf, sizeof(errbuf));
  free(dup);
  if((rc = func(tbit)) != 0)
    printf("fail: %s\n", cmd);
  if(tbit != NULL)
    scamper_tbit_free(tbit);

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
    {"-t blind-data -p bgp -T 69 -b 1909 -s 56789 192.0.2.1", notnull},
    {"-t blind-rst -p bgp -T 69 -b 1909 -s 56789 192.0.2.1", notnull},
    {"-t blind-rst -u https://www.example.com/ -s 56789 192.0.2.1", notnull},
    {"-t blind-syn -p bgp -T 69 -b 1909 -s 56789 192.0.2.1", notnull},
    {"-t ecn -u http://www.example.com/ -s 45678 192.0.2.1", notnull},
    {"-t icw -u http://www.example.com/ -s 45678 192.0.2.1", notnull},
    {"-t null -w 2 -O tcpts -O sack -u http://www.example.com/ -s 45678 192.0.2.1", notnull},
    {"-t null -T 254 -w 2 -O tcpts -O sack -u http://www.example.com/ -s 45678 192.0.2.1", notnull},
    {"-t null -O ipts-syn -u http://www.example.com/ 192.0.2.1", notnull},
    {"-t null -O iprr-syn -u http://www.example.com/ 192.0.2.1", notnull},
    {"-t null -O ipqs-syn -u http://www.example.com/ 192.0.2.1", notnull},
    {"-t null -O fo -f abcdef01 -u http://www.example.com/ -s 45678 192.0.2.1", null_fo},
    {"-t null -O fo-exp -f abcdef01 -u http://www.example.com/ -s 45678 192.0.2.1", notnull},
    {"-t pmtud -U 55 -u http://www.example.com/ -s 45678 -m 1460 -M 1280 192.0.2.1", notnull},
    {"-t pmtud -U 55 -O blackhole -u http://www.example.com/ -s 45678 -m 1460 -M 1280 192.0.2.1", notnull},
    {"-t pmtud -P 192.0.2.1 -u http://www.example.com/ -s 45678 -m 1460 -M 1280 192.0.2.1", notnull},
    {"-t sack-rcvr -u http://www.example.com/ -s 45678 192.0.2.1", notnull},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];

  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/tbit-%03x.txt", argv[2], (int)i);
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
