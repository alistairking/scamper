/*
 * unit_cmd_ping : unit tests for ping commands
 *
 * $Id: unit_cmd_ping.c,v 1.14 2024/02/19 07:33:40 mjl Exp $
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
#include "common.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(const scamper_ping_t *ping);
} sc_test_t;

static int verbose = 0;

static int isnull(const scamper_ping_t *ping)
{
  return (ping == NULL) ? 0 : -1;
}

static int recordroute(const scamper_ping_t *ping)
{
  if(ping == NULL ||
     (scamper_ping_flags_get(ping) & SCAMPER_PING_FLAG_V4RR) == 0 ||
     scamper_ping_probe_size_get(ping) != 20 + 40 + 8 + 56 ||
     check_addr(scamper_ping_dst_get(ping), "192.0.2.1") != 0)
    return -1;
  return 0;
}

static int tcpack_2323(const scamper_ping_t *ping)
{
  if(ping == NULL ||
     scamper_ping_probe_tcpack_get(ping) != 2323 ||
     scamper_ping_probe_size_get(ping) != 20 + 20)
    return -1;
  return 0;
}

static int tcpsyn_2323(const scamper_ping_t *ping)
{
  if(ping == NULL ||
     scamper_ping_probe_tcpseq_get(ping) != 2323 ||
     scamper_ping_probe_size_get(ping) != 20 + 20)
    return -1;
  return 0;
}

static int payload_hex(const scamper_ping_t *ping)
{
  const uint8_t *payload;
  if(ping == NULL ||
     scamper_ping_probe_datalen_get(ping) != 8 ||
     (payload = scamper_ping_probe_data_get(ping)) == NULL ||
     scamper_ping_probe_method_get(ping) != SCAMPER_PING_METHOD_ICMP_ECHO ||
     scamper_ping_method_is_icmp(ping) == 0 ||
     scamper_ping_method_is_icmp_time(ping) != 0 ||
     scamper_ping_probe_size_get(ping) != 20 + 8 + 8 ||
     payload[0] != 0x01 || payload[1] != 0x23 || payload[2] != 0x45 ||
     payload[3] != 0x67 || payload[4] != 0x89 || payload[5] != 0xab ||
     payload[6] != 0xcd || payload[7] != 0xef)
    return -1;
  return 0;
}

static int atf(const scamper_ping_t *ping)
{
  const struct timeval *tv;
  if(ping == NULL ||
     scamper_ping_probe_dport_get(ping) != 0 ||
     scamper_ping_probe_method_get(ping) != SCAMPER_PING_METHOD_ICMP_ECHO ||
     (tv = scamper_ping_wait_probe_get(ping)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 0 ||
     scamper_ping_probe_tos_get(ping) != 0 ||
     scamper_ping_probe_count_get(ping) != 5 ||
     (scamper_ping_flags_get(ping) & SCAMPER_PING_FLAG_DL) == 0 ||
     check_addr(scamper_ping_dst_get(ping), "2001:db8::1") != 0)
    return -1;
  return 0;
}

static int tbt_1280_1300(const scamper_ping_t *ping)
{
  if(ping == NULL ||
     (scamper_ping_flags_get(ping) & SCAMPER_PING_FLAG_DL) == 0 ||
     (scamper_ping_flags_get(ping) & SCAMPER_PING_FLAG_TBT) == 0 ||
     scamper_ping_probe_size_get(ping) != 1300 ||
     scamper_ping_reply_pmtu_get(ping) != 1280)
    return -1;
  return 0;
}

static int icmpecho_plain(const scamper_ping_t *ping)
{
  if(ping == NULL ||
     scamper_ping_probe_method_get(ping) != SCAMPER_PING_METHOD_ICMP_ECHO ||
     scamper_ping_method_is_icmp(ping) == 0 ||
     scamper_ping_method_is_icmp_time(ping) != 0 ||
     scamper_ping_probe_size_get(ping) != 20 + 8 + 56)
    return -1;
  return 0;
}

static int icmptime_plain(const scamper_ping_t *ping)
{
  if(ping == NULL ||
     scamper_ping_probe_method_get(ping) != SCAMPER_PING_METHOD_ICMP_TIME ||
     scamper_ping_method_is_icmp(ping) == 0 ||
     scamper_ping_method_is_icmp_time(ping) == 0 ||
     scamper_ping_probe_size_get(ping) != 20 + 20 + 44)
    return -1;
  return 0;
}

static int tcpsyn_plain(const scamper_ping_t *ping)
{
  if(ping == NULL ||
     scamper_ping_probe_method_get(ping) != SCAMPER_PING_METHOD_TCP_SYN ||
     scamper_ping_method_is_tcp(ping) == 0 ||
     scamper_ping_probe_size_get(ping) != 20 + 20)
    return -1;
  return 0;
}

static int udp_plain(const scamper_ping_t *ping)
{
  if(ping == NULL ||
     scamper_ping_probe_method_get(ping) != SCAMPER_PING_METHOD_UDP ||
     scamper_ping_method_is_udp(ping) == 0 ||
     scamper_ping_probe_size_get(ping) != 20 + 8 + 12)
    return -1;
  return 0;
}

static int icmpecho_zero_payload(const scamper_ping_t *ping)
{
  if(ping == NULL ||
     scamper_ping_probe_method_get(ping) != SCAMPER_PING_METHOD_ICMP_ECHO ||
     scamper_ping_probe_size_get(ping) != 20 + 8)
    return -1;
  return 0;
}

static int icmpecho_zero_payload_v6(const scamper_ping_t *ping)
{
  if(ping == NULL ||
     scamper_ping_probe_method_get(ping) != SCAMPER_PING_METHOD_ICMP_ECHO ||
     scamper_ping_probe_size_get(ping) != 40 + 8)
    return -1;
  return 0;
}

static int icmpecho_csum_default(const scamper_ping_t *ping)
{
  if(ping == NULL ||
     scamper_ping_probe_method_get(ping) != SCAMPER_PING_METHOD_ICMP_ECHO ||
     scamper_ping_probe_size_get(ping) != 20 + 8 + 56 ||
     scamper_ping_probe_icmpsum_get(ping) != 0x2323)
    return -1;
  return 0;
}

static int icmpecho_csum_payload4(const scamper_ping_t *ping)
{
  if(ping == NULL ||
     scamper_ping_probe_method_get(ping) != SCAMPER_PING_METHOD_ICMP_ECHO ||
     scamper_ping_probe_size_get(ping) != 20 + 8 + 4 ||
     scamper_ping_probe_icmpsum_get(ping) != 2323)
    return -1;
  return 0;
}

static int udp_zero_bytes_c1(const scamper_ping_t *ping)
{
  const uint8_t *payload;
  int i;
  if(ping == NULL ||
     scamper_ping_probe_count_get(ping) != 1 ||
     scamper_ping_probe_method_get(ping) != SCAMPER_PING_METHOD_UDP ||
     scamper_ping_probe_size_get(ping) != 20 + 8 + 20 ||
     scamper_ping_probe_datalen_get(ping) != 20 ||
     (payload = scamper_ping_probe_data_get(ping)) == NULL)
    return -1;
  for(i=0; i<20; i++)
    if(payload[i] != 0)
      return -1;
  return 0;
}

static int wait_timeout_1_0(const scamper_ping_t *ping)
{
  const struct timeval *tv;
  if(ping == NULL ||
     (tv = scamper_ping_wait_timeout_get(ping)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 0)
    return -1;
  return 0;
}

static int wait_timeout_1_5(const scamper_ping_t *ping)
{
  const struct timeval *tv;
  if(ping == NULL ||
     (tv = scamper_ping_wait_timeout_get(ping)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 500000)
    return -1;
  return 0;
}

static int wait_probe_3_0(const scamper_ping_t *ping)
{
  const struct timeval *tv;
  if(ping == NULL ||
     (tv = scamper_ping_wait_probe_get(ping)) == NULL ||
     tv->tv_sec != 3 || tv->tv_usec != 0 ||
     (tv = scamper_ping_wait_timeout_get(ping)) == NULL ||
     tv->tv_sec != 3 || tv->tv_usec != 0)
    return -1;
  return 0;
}

static int wait_probe_3_69(const scamper_ping_t *ping)
{
  const struct timeval *tv;
  if(ping == NULL ||
     (tv = scamper_ping_wait_probe_get(ping)) == NULL ||
     tv->tv_sec != 3 || tv->tv_usec != 690000)
    return -1;
  return 0;
}

static int wait_probe_0_5(const scamper_ping_t *ping)
{
  const struct timeval *tv;
  if(ping == NULL ||
     (tv = scamper_ping_wait_probe_get(ping)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 500000 ||
     (tv = scamper_ping_wait_timeout_get(ping)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 0)
    return -1;
  return 0;
}

static int wait_probe_0_25_timeout_0_5(const scamper_ping_t *ping)
{
  const struct timeval *tv;
  if(ping == NULL ||
     (tv = scamper_ping_wait_probe_get(ping)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 250000 ||
     (tv = scamper_ping_wait_timeout_get(ping)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 500000)
    return -1;
  return 0;
}

static int check(const char *cmd, int (*func)(const scamper_ping_t *in))
{
  scamper_ping_t *ping;
  char *dup, errbuf[256];
  int rc;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

  if((dup = strdup(cmd)) == NULL)
    return -1;
  ping = scamper_do_ping_alloc(dup, errbuf, sizeof(errbuf));
  free(dup);
  if((rc = func(ping)) != 0)
    printf("fail: %s\n", cmd);
  if(ping != NULL)
    scamper_ping_free(ping);

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
    {"-R 192.0.2.1", recordroute},
    {"-A -1 -P tcp-ack 192.0.2.1", isnull},
    {"-A 2323 -P tcp-ack 192.0.2.1", tcpack_2323},
    {"-A 2323 -P tcp-syn 192.0.2.1", tcpsyn_2323},
    {"-B 0123456789abcdef -s 36 192.0.2.1", payload_hex},
    {"-B 0123 -B 456789abcdef 192.0.2.1", isnull},
    {"-d 0 -P icmp-echo -i 1 -z 0 -c 5 -F 0 -O dl 2001:db8::1", atf},
    {"-i 3 192.0.2.1", wait_probe_3_0},
    {"-i 3s 192.0.2.1", wait_probe_3_0},
    {"-i 3.69 192.0.2.1", wait_probe_3_69},
    {"-i 3.69s 192.0.2.1", wait_probe_3_69},
    {"-i 0.5 192.0.2.1", wait_probe_0_5},
    {"-i 0.5s 192.0.2.1", wait_probe_0_5},
    {"-i 0.25 -W 0.5 192.0.2.1", wait_probe_0_25_timeout_0_5},
    {"-i 0.25s -W 0.5 192.0.2.1", wait_probe_0_25_timeout_0_5},
    {"-i 0.25 -W 0.5s 192.0.2.1", wait_probe_0_25_timeout_0_5},
    {"-i 0.25s -W 0.5s 192.0.2.1", wait_probe_0_25_timeout_0_5},
    {"-i 21 192.0.2.1", isnull},
    {"-i 21s 192.0.2.1", isnull},
    {"-O dl -O tbt -M 1280 -s 1300 2001:db8::1", tbt_1280_1300},
    {"-P icmp-echo 192.0.2.1", icmpecho_plain},
    {"-P icmp-time 192.0.2.1", icmptime_plain},
    {"-P tcp-syn 192.0.2.1", tcpsyn_plain},
    {"-P udp 192.0.2.1", udp_plain},
    {"-P icmp-echo -C 0x2323 192.0.2.1", icmpecho_csum_default},
    {"-P udp -C 2323 192.0.2.1", isnull},
    {"-P icmp-echo -b 0 -s 28 192.0.2.1", icmpecho_zero_payload},
    {"-P icmp-echo -b 0 -s 29 192.0.2.1", isnull},
    {"-P icmp-echo -b 0 -C 2323 192.0.2.1", isnull},
    {"-P icmp-echo -b 0 -s 48 2001:db8::1", icmpecho_zero_payload_v6},
    {"-P icmp-echo -b 4 -C 2323 192.0.2.1", icmpecho_csum_payload4},
    {"-P udp -B 0000000000000000000000000000000000000000 -c 1 192.0.2.1", udp_zero_bytes_c1},
    {"-W 1. 192.0.2.1", isnull},
    {"-W 1 192.0.2.1", wait_timeout_1_0},
    {"-W 1s 192.0.2.1", wait_timeout_1_0},
    {"-W 1.5 192.0.2.1", wait_timeout_1_5},
    {"-W 1.5s 192.0.2.1", wait_timeout_1_5},
    {"-W 1.5000000 192.0.2.1", isnull},
    {"-W 1.5000000s 192.0.2.1", isnull},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];

  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/ping-%03x.txt", argv[2], (int)i);
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
