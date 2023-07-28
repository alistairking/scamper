/*
 * unit_cmd_ping : unit tests for ping commands
 *
 * $Id: unit_cmd_ping.c,v 1.1 2023/06/05 00:21:20 mjl Exp $
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
#include "scamper_ping.h"
#include "scamper_ping_cmd.h"

#include "utils.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(scamper_ping_t *ping);
} sc_test_t;

uint16_t scamper_sport_default(void)
{
  return 31337;
}

uint16_t scamper_pid_u16(void)
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

static int isnull(scamper_ping_t *in)
{
  return (in == NULL) ? 0 : -1;
}

static int recordroute(scamper_ping_t *ping)
{
  if(ping == NULL ||
     (scamper_ping_flags_get(ping) & SCAMPER_PING_FLAG_V4RR) == 0)
    return -1;
  return 0;
}

static int tcpack_2323(scamper_ping_t *ping)
{
  if(ping == NULL ||
     scamper_ping_probe_tcpack_get(ping) != 2323)
    return -1;
  return 0;
}

static int tcpsyn_2323(scamper_ping_t *ping)
{
  if(ping == NULL ||
     scamper_ping_probe_tcpseq_get(ping) != 2323)
    return -1;
  return 0;
}

static int payload_hex(scamper_ping_t *ping)
{
  const uint8_t *payload;
  if(ping == NULL ||
     scamper_ping_probe_datalen_get(ping) != 8 ||
     (payload = scamper_ping_probe_data_get(ping)) == NULL ||
     payload[0] != 0x01 || payload[1] != 0x23 || payload[2] != 0x45 ||
     payload[3] != 0x67 || payload[4] != 0x89 || payload[5] != 0xab ||
     payload[6] != 0xcd || payload[7] != 0xef)
    return -1;
  return 0;
}

static int tbt_1280_1300(scamper_ping_t *ping)
{
  if(ping == NULL ||
     (scamper_ping_flags_get(ping) & SCAMPER_PING_FLAG_DL) == 0 ||
     (scamper_ping_flags_get(ping) & SCAMPER_PING_FLAG_TBT) == 0 ||
     scamper_ping_probe_size_get(ping) != 1300 ||
     scamper_ping_reply_pmtu_get(ping) != 1280)
    return -1;
  return 0;
}

static int check(const char *cmd, int (*func)(scamper_ping_t *in))
{
  scamper_ping_t *ping;
  char *dup;
  int rc;

  if((dup = strdup(cmd)) == NULL)
    return -1;
  ping = scamper_do_ping_alloc(dup);
  free(dup);
  if((rc = func(ping)) != 0)
    printf("fail: %s\n", cmd);
  if(ping != NULL)
    scamper_ping_free(ping);

  return rc;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {"-R 192.0.2.1", recordroute},
    {"-A 2323 -P tcp-ack 192.0.2.1", tcpack_2323},
    {"-A 2323 -P tcp-syn 192.0.2.1", tcpsyn_2323},
    {"-B 0123456789abcdef 192.0.2.1", payload_hex},
    {"-B 0123 -B 456789abcdef 192.0.2.1", isnull},
    {"-O dl -O tbt -M 1280 -s 1300 2001:db8::1", tbt_1280_1300},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);

  for(i=0; i<testc; i++)
    if(check(tests[i].cmd, tests[i].func) != 0)
      break;

  if(i != testc)
    return -1;

  printf("OK\n");
  return 0;
}
