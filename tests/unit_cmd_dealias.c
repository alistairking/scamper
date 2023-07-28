/*
 * unit_cmd_dealias : unit tests for dealias commands
 *
 * $Id: unit_cmd_dealias.c,v 1.1 2023/06/04 23:26:36 mjl Exp $
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
#include "scamper_dealias.h"
#include "scamper_dealias_cmd.h"

#include "utils.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(scamper_dealias_t *dealias);
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

#if 0
static int notnull(scamper_dealias_t *in)
{
  return (in != NULL) ? 0 : -1;
}
#endif

static int isnull(scamper_dealias_t *in)
{
  return (in == NULL) ? 0 : -1;
}

static int ally_ttl_udp(scamper_dealias_t *in)
{
  const scamper_dealias_ally_t *ally;
  const scamper_dealias_probedef_t *def;
  const scamper_dealias_probedef_udp_t *udp;

  if(in == NULL ||
     (ally = scamper_dealias_ally_get(in)) == NULL ||
     (def = scamper_dealias_ally_def0_get(ally)) == NULL ||
     scamper_dealias_probedef_ttl_get(def) != 4 ||
     (udp = scamper_dealias_probedef_udp_get(def)) == NULL ||
     scamper_dealias_probedef_udp_sport_get(udp) != 57665 ||
     scamper_dealias_probedef_udp_dport_get(udp) != 33436 ||
     (def = scamper_dealias_ally_def1_get(ally)) == NULL ||
     scamper_dealias_probedef_ttl_get(def) != 5 ||
     (udp = scamper_dealias_probedef_udp_get(def)) == NULL ||
     scamper_dealias_probedef_udp_sport_get(udp) != 57664 ||
     scamper_dealias_probedef_udp_dport_get(udp) != 33435)
    return -1;

  return 0;
}

static int ally_icmp(scamper_dealias_t *in)
{
  const scamper_dealias_ally_t *ally;
  const scamper_dealias_probedef_t *def;
  const scamper_dealias_probedef_icmp_t *icmp;

  if(in == NULL ||
     (ally = scamper_dealias_ally_get(in)) == NULL ||
     (def = scamper_dealias_ally_def0_get(ally)) == NULL ||
     (icmp = scamper_dealias_probedef_icmp_get(def)) == NULL ||
     scamper_dealias_probedef_icmp_csum_get(icmp) != 59832 ||
     (def = scamper_dealias_ally_def1_get(ally)) == NULL ||
     (icmp = scamper_dealias_probedef_icmp_get(def)) == NULL ||
     scamper_dealias_probedef_icmp_csum_get(icmp) != 59835)
    return -1;

  return 0;
}

static int check(const char *cmd, int (*func)(scamper_dealias_t *in))
{
  scamper_dealias_t *dealias;
  char *dup;
  int rc;

  if((dup = strdup(cmd)) == NULL)
    return -1;
  dealias = scamper_do_dealias_alloc(dup);
  free(dup);
  if((rc = func(dealias)) != 0)
    printf("fail: %s\n", cmd);
  if(dealias != NULL)
    scamper_dealias_free(dealias);

  return rc;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    /* valid TTL-limited probes using UDP packets */
    {"-m ally -O inseq -p '-P udp -d 33436 -F 57665 -t 4 -i 192.0.2.1' -p '-P udp -d 33435 -F 57664 -t 5 -i 192.0.2.2'", ally_ttl_udp},
    /* ICMP probes don't have source or destination ports */
    {"-m ally -p '-P icmp-echo -d 33436 -i 192.0.2.1' -p '-P icmp-echo -d 33435 -i 192.0.2.2'", isnull},
    {"-m ally -p '-P icmp-echo -F 57665 -i 192.0.2.1' -p '-P icmp-echo -F 57665 -i 192.0.2.2'", isnull},
    /* valid ICMP probes */
    {"-m ally -W 1000 -p '-P icmp-echo -c 59832 -i 192.0.2.1' -p '-P icmp-echo -c 59835 -i 192.0.2.2'", ally_icmp},
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
