/*
 * unit_cmd_trace : unit tests for trace commands
 *
 * $Id: unit_cmd_trace.c,v 1.2 2023/06/04 23:53:35 mjl Exp $
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
#include "scamper_list.h"
#include "scamper_trace.h"
#include "scamper_trace_cmd.h"

#include "utils.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(scamper_trace_t *trace);
} sc_test_t;

scamper_addrcache_t *addrcache = NULL;

uint16_t scamper_sport_default(void)
{
  return 31337;
}

void scamper_debug(const char *func, const char *format, ...)
{
  return;
}

void printerror(const char *func, const char *format, ...)
{
  return;
}

static int isnull(scamper_trace_t *in)
{
  return (in == NULL) ? 0 : -1;
}

static int notnull(scamper_trace_t *in)
{
  return (in != NULL) ? 0 : -1;
}

static int confidence_95(scamper_trace_t *trace)
{
  if(trace == NULL ||
     scamper_trace_confidence_get(trace) != 95)
    return -1;
  return 0;
}

static int confidence_99(scamper_trace_t *trace)
{
  if(trace == NULL ||
     scamper_trace_confidence_get(trace) != 99)
    return -1;
  return 0;
}

static int dport_443(scamper_trace_t *trace)
{
  if(trace == NULL ||
     scamper_trace_dport_get(trace) != 443)
    return -1;
  return 0;
}

static int firsthop_5(scamper_trace_t *trace)
{
  if(trace == NULL ||
     scamper_trace_firsthop_get(trace) != 5)
    return -1;
  return 0;
}

static int gaplimit_4(scamper_trace_t *trace)
{
  if(trace == NULL ||
     scamper_trace_gaplimit_get(trace) != 4)
    return -1;
  return 0;
}

static int gapaction_2(scamper_trace_t *trace)
{
  if(trace == NULL ||
     scamper_trace_gapaction_get(trace) != 2)
    return -1;
  return 0;
}

static int loops_4(scamper_trace_t *trace)
{
  if(trace == NULL ||
     scamper_trace_loops_get(trace) != 4)
    return -1;
  return 0;
}

static int maxttl_69(scamper_trace_t *trace)
{
  if(trace == NULL ||
     scamper_trace_hoplimit_get(trace) != 69)
    return -1;
  return 0;
}

static int do_pmtud(scamper_trace_t *trace)
{
  if(trace == NULL ||
     (scamper_trace_flags_get(trace) & SCAMPER_TRACE_FLAG_PMTUD) == 0)
    return -1;
  return 0;
}
	  
static int squeries_4_gaplimit_6(scamper_trace_t *trace)
{
  if(trace == NULL ||
     scamper_trace_squeries_get(trace) != 4 ||
     scamper_trace_gaplimit_get(trace) != 6) 
    return -1;
  return 0;
}

static int offset_4(scamper_trace_t *trace)
{
  if(trace == NULL ||
     scamper_trace_offset_get(trace) != 4)
    return -1;
  return 0;
}

static int payload_hex(scamper_trace_t *trace)
{
  const uint8_t *payload;
  if(trace == NULL ||
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
     (scamper_trace_flags_get(trace) & SCAMPER_TRACE_FLAG_ALLATTEMPTS) == 0 ||
     scamper_trace_attempts_get(trace) != 5)
    return -1;
  return 0;
}

static int attempts_1(scamper_trace_t *trace)
{
  if(trace == NULL ||
     scamper_trace_attempts_get(trace) != 1)
    return -1;
  return 0;
}

static int rtraddr(scamper_trace_t *trace)
{
  scamper_addr_t *rtr = NULL;
  int rc = 0;

  if(trace == NULL ||
     (rtr = scamper_addr_alloc_ipv4("192.0.2.69")) == NULL ||
     scamper_addr_cmp(scamper_trace_rtr_get(trace), rtr) == 0)
    rc = -1;
  if(rtr != NULL) scamper_addr_free(rtr);

  return rc;
}

static int sport_40000(scamper_trace_t *trace)
{
  if(trace == NULL ||
     scamper_trace_sport_get(trace) != 40000)
    return -1;
  return 0;
}

static int srcaddr(scamper_trace_t *trace)
{
  scamper_addr_t *src = NULL;
  int rc = 0;

  if(trace == NULL ||
     (src = scamper_addr_alloc_ipv4("192.0.2.44")) == NULL ||
     scamper_addr_cmp(scamper_trace_src_get(trace), src) == 0)
    rc = -1;
  if(src != NULL) scamper_addr_free(src);

  return rc;
}

static int tos_45(scamper_trace_t *trace)
{
  if(trace == NULL ||
     scamper_trace_tos_get(trace) != 45)
    return -1;
  return 0;
}

static int wait_1_waitprobe_69(scamper_trace_t *trace)
{
  if(trace == NULL ||
     scamper_trace_wait_get(trace) != 1 ||
     scamper_trace_wait_probe_get(trace) != 69)
    return -1;
  return 0;
}

static int check(const char *cmd, int (*func)(scamper_trace_t *in))
{
  scamper_trace_t *trace;
  char *dup;
  int rc;

  if((dup = strdup(cmd)) == NULL)
    return -1;
  trace = scamper_do_trace_alloc(dup);
  free(dup);
  if((rc = func(trace)) != 0)
    printf("fail: %s\n", cmd);
  if(trace != NULL)
    scamper_trace_free(trace);

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
    {"-w 1 -W 69 192.0.2.1", wait_1_waitprobe_69},
    {"-z 192.0.2.5 -z 192.0.2.8 192.0.2.1", notnull},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);

  if((addrcache = scamper_addrcache_alloc()) == NULL)
    return -1;

  for(i=0; i<testc; i++)
    if(check(tests[i].cmd, tests[i].func) != 0)
      break;

  scamper_addrcache_free(addrcache);

  if(i != testc)
    return -1;

  printf("OK\n");
  return 0;
}
