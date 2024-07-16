/*
 * unit_cmd_host : unit tests for host commands
 *
 * $Id: unit_cmd_host.c,v 1.5 2024/04/28 20:10:19 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2023-2024 Matthew Luckie
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
#include "scamper_host.h"
#include "scamper_host_cmd.h"
#include "common.h"
#include "utils.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(const scamper_host_t *host);
} sc_test_t;

static int verbose = 0;

scamper_addrcache_t *addrcache = NULL;

static int isnull(const scamper_host_t *in)
{
  return (in == NULL) ? 0 : -1;
}

static int example_com_a(const scamper_host_t *in)
{
  const char *qname;
  const struct timeval *tv;

  if(in == NULL ||
     check_addr(scamper_host_dst_get(in), "192.0.2.1") != 0 ||
     (qname = scamper_host_qname_get(in)) == NULL ||
     strcmp(qname, "example.com") != 0 ||
     scamper_host_qtype_get(in) != SCAMPER_HOST_TYPE_A ||
     scamper_host_qclass_get(in) != SCAMPER_HOST_CLASS_IN ||
     (tv = scamper_host_wait_timeout_get(in)) == NULL ||
     tv->tv_sec != 5 || tv->tv_usec != 0 ||
     scamper_host_retries_get(in) != 0)
    return -1;

  return 0;
}

static int mail_example_com_mx_w_1_5(const scamper_host_t *in)
{
  const char *qname;
  const struct timeval *tv;

  if(in == NULL ||
     check_addr(scamper_host_dst_get(in), "192.0.2.1") != 0 ||
     (qname = scamper_host_qname_get(in)) == NULL ||
     strcmp(qname, "mail.example.com") != 0 ||
     scamper_host_qclass_get(in) != SCAMPER_HOST_CLASS_IN ||
     scamper_host_qtype_get(in) != SCAMPER_HOST_TYPE_MX ||
     (tv = scamper_host_wait_timeout_get(in)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 500000)
    return -1;

  return 0;
}

static int ns_example_com_ns_R_1(const scamper_host_t *in)
{
  const char *qname;

  if(in == NULL ||
     check_addr(scamper_host_dst_get(in), "192.0.2.2") != 0 ||
     (qname = scamper_host_qname_get(in)) == NULL ||
     strcmp(qname, "ns.example.com") != 0 ||
     scamper_host_qclass_get(in) != SCAMPER_HOST_CLASS_IN ||
     scamper_host_qtype_get(in) != SCAMPER_HOST_TYPE_NS ||
     scamper_host_retries_get(in) != 1)
    return -1;

  return 0;
}

static int example_com_txt_T(const scamper_host_t *in)
{
  const char *qname;

  if(in == NULL ||
     check_addr(scamper_host_dst_get(in), "192.0.2.2") != 0 ||
     (qname = scamper_host_qname_get(in)) == NULL ||
     strcmp(qname, "example.com") != 0 ||
     scamper_host_qclass_get(in) != SCAMPER_HOST_CLASS_IN ||
     scamper_host_qtype_get(in) != SCAMPER_HOST_TYPE_TXT ||
     (scamper_host_flags_get(in) & SCAMPER_HOST_FLAG_TCP) == 0)
    return -1;

  return 0;
}

static int example_com_aaaa_r(const scamper_host_t *in)
{
  const char *qname;

  if(in == NULL ||
     check_addr(scamper_host_dst_get(in), "192.0.2.2") != 0 ||
     (qname = scamper_host_qname_get(in)) == NULL ||
     strcmp(qname, "example.com") != 0 ||
     scamper_host_qclass_get(in) != SCAMPER_HOST_CLASS_IN ||
     scamper_host_qtype_get(in) != SCAMPER_HOST_TYPE_AAAA ||
     (scamper_host_flags_get(in) & SCAMPER_HOST_FLAG_NORECURSE) == 0)
    return -1;

  return 0;
}

static int example_com_soa(const scamper_host_t *in)
{
  const char *qname;

  if(in == NULL ||
     check_addr(scamper_host_dst_get(in), "192.0.2.2") != 0 ||
     (qname = scamper_host_qname_get(in)) == NULL ||
     strcmp(qname, "example.com") != 0 ||
     scamper_host_qclass_get(in) != SCAMPER_HOST_CLASS_IN ||
     scamper_host_qtype_get(in) != SCAMPER_HOST_TYPE_SOA)
    return -1;

  return 0;
}

static int x192_0_2_55_ptr(const scamper_host_t *in)
{
  const char *qname;

  if(in == NULL ||
     check_addr(scamper_host_dst_get(in), "192.0.2.2") != 0 ||
     (qname = scamper_host_qname_get(in)) == NULL ||
     strcmp(qname, "192.0.2.55") != 0 ||
     scamper_host_qclass_get(in) != SCAMPER_HOST_CLASS_IN ||
     scamper_host_qtype_get(in) != SCAMPER_HOST_TYPE_PTR)
    return -1;

  return 0;
}

static int check(const char *cmd, int (*func)(const scamper_host_t *in))
{
  scamper_host_t *host;
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
  host = scamper_do_host_alloc(dup, errbuf, sizeof(errbuf));
  free(dup);
  if((rc = func(host)) != 0)
    printf("fail: %s\n", cmd);
  if(host != NULL)
    scamper_host_free(host);

  scamper_addrcache_free(addrcache);

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(start_mem != stop_mem && rc == 0)
    {
      printf("memory leak: %s\n", cmd);
      rc = -1;
    }
#endif

  if(func == isnull && verbose)
    printf("%s: %s\n", cmd, errbuf);

  return rc;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {"-s 192.0.2.1 example.com", example_com_a},
    {"-s 192.0.2.1 -t a example.com", example_com_a},
    {"-s 192.0.2.1 -t mx -W 1.5 mail.example.com", mail_example_com_mx_w_1_5},
    {"-s 192.0.2.1 -t mx -W 1.500 mail.example.com", mail_example_com_mx_w_1_5},
    {"-s 192.0.2.1 -t mx -W 1.5001 mail.example.com", isnull},
    {"-s 192.0.2.1 -t mx -W 1.5s mail.example.com", mail_example_com_mx_w_1_5},
    {"-s 192.0.2.1 -t mx -W 1.500s mail.example.com", mail_example_com_mx_w_1_5},
    {"-s 192.0.2.1 -t mx -W 1.5001s mail.example.com", isnull},
    {"-s 192.0.2.1 -t mx -W 1500ms mail.example.com", mail_example_com_mx_w_1_5},
    {"-s 192.0.2.2 -t ns -R 1 ns.example.com", ns_example_com_ns_R_1},
    {"-s 192.0.2.2 -t txt -T example.com", example_com_txt_T},
    {"-s 192.0.2.2 -t soa example.com", example_com_soa},
    {"-s 192.0.2.2 -t aaaa -r example.com", example_com_aaaa_r},
    {"-s 192.0.2.2 192.0.2.55", x192_0_2_55_ptr},
    {"-s 192.0.2.2 -t ptr 192.0.2.55", x192_0_2_55_ptr},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];

  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/host-%03x.txt", argv[2], (int)i);
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
