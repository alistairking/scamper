/*
 * unit_cmd_trace : unit tests for trace commands
 *
 * $Id: unit_cmd_trace.c,v 1.13 2024/03/04 19:36:41 mjl Exp $
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
#include "scamper_trace.h"
#include "scamper_trace_cmd.h"

#include "utils.h"
#include "common.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(scamper_trace_t *trace);
} sc_test_t;

static int verbose = 0;

scamper_addrcache_t *addrcache = NULL;

static int isnull(scamper_trace_t *in)
{
  return (in == NULL) ? 0 : -1;
}

static int notnull(scamper_trace_t *in)
{
  return (in != NULL) ? 0 : -1;
}

static int check_wait_timeout_def(const scamper_trace_t *trace)
{
  const struct timeval *tv = scamper_trace_wait_timeout_get(trace);
  if(tv->tv_sec != 5 || tv->tv_usec != 0)
    return -1;
  return 0;
}

static int check_wait_probe_def(const scamper_trace_t *trace)
{
  const struct timeval *tv = scamper_trace_wait_probe_get(trace);
  if(tv->tv_sec != 0 || tv->tv_usec != 0)
    return -1;
  return 0;
}

static int confidence_95(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     scamper_trace_confidence_get(trace) != 95)
    return -1;
  return 0;
}

static int confidence_99(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     scamper_trace_confidence_get(trace) != 99)
    return -1;
  return 0;
}

static int dport_443(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     scamper_trace_dport_get(trace) != 443)
    return -1;
  return 0;
}

static int firsthop_5(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     scamper_trace_firsthop_get(trace) != 5)
    return -1;
  return 0;
}

static int gaplimit_4(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     scamper_trace_gaplimit_get(trace) != 4)
    return -1;
  return 0;
}

static int gapaction_2(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     scamper_trace_gapaction_get(trace) != 2)
    return -1;
  return 0;
}

static int loops_4(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     scamper_trace_loops_get(trace) != 4)
    return -1;
  return 0;
}

static int maxttl_69(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     scamper_trace_hoplimit_get(trace) != 69)
    return -1;
  return 0;
}

static int do_pmtud(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     (scamper_trace_flags_get(trace) & SCAMPER_TRACE_FLAG_PMTUD) == 0)
    return -1;
  return 0;
}

static int squeries_4_gaplimit_6(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     scamper_trace_squeries_get(trace) != 4 ||
     scamper_trace_gaplimit_get(trace) != 6)
    return -1;
  return 0;
}

static int offset_4(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     scamper_trace_offset_get(trace) != 4)
    return -1;
  return 0;
}

static int payload_hex(scamper_trace_t *trace)
{
  const uint8_t *payload;
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     scamper_trace_payload_len_get(trace) != 8 ||
     (payload = scamper_trace_payload_get(trace)) == NULL ||
     payload[0] != 0x01 || payload[1] != 0x23 || payload[2] != 0x45 ||
     payload[3] != 0x67 || payload[4] != 0x89 || payload[5] != 0xab ||
     payload[6] != 0xcd || payload[7] != 0xef)
    return -1;
  return 0;
}

static int attempts_5_all(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     (scamper_trace_flags_get(trace) & SCAMPER_TRACE_FLAG_ALLATTEMPTS) == 0 ||
     scamper_trace_attempts_get(trace) != 5)
    return -1;
  return 0;
}

static int attempts_1(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     scamper_trace_attempts_get(trace) != 1)
    return -1;
  return 0;
}

static int rtraddr(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     check_addr(scamper_trace_rtr_get(trace), "192.0.2.69") != 0)
    return -1;
  return 0;
}

static int sport_40000(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     scamper_trace_sport_get(trace) != 40000)
    return -1;
  return 0;
}

static int srcaddr(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     check_addr(scamper_trace_src_get(trace), "192.0.2.44") != 0)
    return -1;
  return 0;
}

static int tos_45(scamper_trace_t *trace)
{
  if(trace == NULL ||
     check_wait_probe_def(trace) != 0 || check_wait_timeout_def(trace) != 0 ||
     scamper_trace_tos_get(trace) != 45)
    return -1;
  return 0;
}

static int wait_1_waitprobe_69(scamper_trace_t *trace)
{
  const struct timeval *wait_timeout;
  const struct timeval *wait_probe;
  if(trace == NULL)
    return -1;
  wait_timeout = scamper_trace_wait_timeout_get(trace);
  wait_probe = scamper_trace_wait_probe_get(trace);
  if(wait_timeout->tv_sec != 1 || wait_timeout->tv_usec != 0 ||
     wait_probe->tv_sec != 0 || wait_probe->tv_usec != 690000)
    return -1;
  return 0;
}

static int waitprobe_0(scamper_trace_t *trace)
{
  const struct timeval *wait_probe;
  if(trace == NULL ||
     (wait_probe = scamper_trace_wait_probe_get(trace)) == NULL ||
     wait_probe->tv_sec != 0 || wait_probe->tv_usec != 0)
    return -1;
  return 0;
}

static int atf(scamper_trace_t *trace)
{
  const struct timeval *tv;
  if(trace == NULL ||
     scamper_trace_userid_get(trace) != 686 ||
     scamper_trace_type_get(trace) != SCAMPER_TRACE_TYPE_TCP ||
     (tv = scamper_trace_wait_probe_get(trace)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 0 ||
     scamper_trace_hoplimit_get(trace) != 30 ||
     (scamper_trace_flags_get(trace) & SCAMPER_TRACE_FLAG_ALLATTEMPTS) == 0 ||
     scamper_trace_attempts_get(trace) != 3 ||
     scamper_trace_dport_get(trace) != 6969 ||
     scamper_trace_gaplimit_get(trace) != 30 ||
     (tv = scamper_trace_wait_timeout_get(trace)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 0 ||
     scamper_trace_tos_get(trace) != 0 ||
     check_addr(scamper_trace_dst_get(trace), "192.0.2.1") != 0)
    return -1;
  return 0;
}

static int check(const char *cmd, int (*func)(scamper_trace_t *in))
{
  scamper_trace_t *trace;
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
  trace = scamper_do_trace_alloc(dup, errbuf, sizeof(errbuf));
  free(dup);
  if((rc = func(trace)) != 0)
    printf("fail: %s\n", cmd);
  if(trace != NULL)
    scamper_trace_free(trace);

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
    {"-c 95 192.0.2.1", confidence_95},
    {"-c 99 192.0.2.1", confidence_99},
    {"-c 69 192.0.2.1", isnull}, /* invalid confidence value */
    {"-d 443 192.0.2.1", dport_443},
    {"-f 5 192.0.2.1", firsthop_5},
    {"-f 0 192.0.2.1", isnull}, /* firsthop cannot be <= 0 */
    {"-f 256 192.0.2.1", isnull}, /* firsthop cannot be >= 256 */
    {"-g 4 192.0.2.1", gaplimit_4},
    {"-g 0 192.0.2.1", isnull}, /* gaplimit cannot be <= 0 */
    {"-g 256 192.0.2.1", isnull}, /* gaplimit cannot be >= 256 */
    {"-G 2 192.0.2.1", gapaction_2},
    {"-l 4 192.0.2.1", loops_4},
    {"-m 69 192.0.2.1", maxttl_69},
    {"-M 192.0.2.1", do_pmtud},
    {"-N 4 -g 6 192.0.2.1", squeries_4_gaplimit_6},
    {"-N 6 -g 4 192.0.2.1", isnull}, /* squeries > gaplimit */
    {"-o 4 192.0.2.1", isnull}, /* offset not allowed with IPv4 */
    {"-o 4 2001:db8::1", offset_4},
    {"-p 0123456789abcdef 192.0.2.1", payload_hex},
    {"-p 0123 -p 456789abcdef 192.0.2.1", isnull},
    {"-q 5 -Q 192.0.2.1", attempts_5_all},
    {"-q 1 192.0.2.1", attempts_1},
    {"-r 192.0.2.69 192.0.2.1", rtraddr},
    {"-s 40000 192.0.2.1", sport_40000},
    {"-S 192.0.2.44 192.0.2.1", srcaddr},
    {"-t 45 192.0.2.1", tos_45},
    {"-U 686 -P tcp -W 0 -m 30 -Q -q 3 -d 6969 -g 30 -w 1 -t 0 -s 0 192.0.2.1", atf},
    {"-w 1 -W 69 192.0.2.1", wait_1_waitprobe_69},
    {"-W 0 192.0.2.1", waitprobe_0},
    {"-z 192.0.2.5 -z 192.0.2.8 192.0.2.1", notnull},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];

  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/trace-%03x.txt", argv[2], (int)i);
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
