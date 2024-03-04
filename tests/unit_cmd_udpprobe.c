/*
 * unit_cmd_udpprobe : unit tests for udpprobe commands
 *
 * $Id: unit_cmd_udpprobe.c,v 1.7 2024/02/13 04:59:48 mjl Exp $
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
#include "scamper_udpprobe.h"
#include "scamper_udpprobe_cmd.h"

#include "utils.h"
#include "common.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(const scamper_udpprobe_t *up);
} sc_test_t;

static int isnull(const scamper_udpprobe_t *in)
{
  return (in == NULL) ? 0 : -1;
}

static int check_defaults(const scamper_udpprobe_t *in, const char *dst)
{
  const uint8_t *pl;
  if(in == NULL ||
     check_addr(scamper_udpprobe_dst_get(in), dst) != 0 ||
     scamper_udpprobe_dport_get(in) != 70 ||
     scamper_udpprobe_len_get(in) != 1 ||
     (pl = scamper_udpprobe_data_get(in)) == NULL ||
     pl[0] != 0x69)
    return -1;
  return 0;
}

static int snmpv3(const scamper_udpprobe_t *in)
{
  const uint8_t pl_cmp[] = {
    0x30, 0x3a, 0x02, 0x01, 0x03, 0x30, 0x0f, 0x02, 0x02, 0x4a, 0x69, 0x02,
    0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10,
    0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x00,
    0x04, 0x00, 0x04, 0x00, 0x30, 0x12, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0c,
    0x02, 0x02, 0x37, 0xf0, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
  };
  const uint8_t *pl;
  if(in == NULL ||
     check_addr(scamper_udpprobe_dst_get(in), "192.0.2.1") != 0 ||
     scamper_udpprobe_dport_get(in) != 161 ||
     scamper_udpprobe_len_get(in) != sizeof(pl_cmp) ||
     (pl = scamper_udpprobe_data_get(in)) == NULL ||
     memcmp(pl, pl_cmp, sizeof(pl_cmp)) != 0)
    return -1;
  return 0;
}

static int timeout_3(const scamper_udpprobe_t *in)
{
  const struct timeval *tv;
  if(check_defaults(in, "192.0.2.1") != 0 ||
     (tv = scamper_udpprobe_wait_timeout_get(in)) == NULL ||
     tv->tv_sec != 3 || tv->tv_usec != 0)
    return -1;
  return 0;
}

static int exitfirst(const scamper_udpprobe_t *in)
{
  if(check_defaults(in, "192.0.2.1") != 0 ||
     scamper_udpprobe_flag_is_exitfirst(in) == 0)
    return -1;
  return 0;
}

static int check(const char *cmd, int (*func)(const scamper_udpprobe_t *in))
{
  scamper_udpprobe_t *up;
  char *dup, errbuf[256];
  int rc;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

  if((dup = strdup(cmd)) == NULL)
    return -1;
  up = scamper_do_udpprobe_alloc(dup, errbuf, sizeof(errbuf));
  free(dup);
  if((rc = func(up)) != 0)
    printf("fail: %s\n", cmd);
  if(up != NULL)
    scamper_udpprobe_free(up);

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
    {"-d 161 -p 303a020103300f02024a69020300ffe30401040201030410300e0400020100020100040004000400301204000400a00c020237f00201000201003000 192.0.2.1", snmpv3},
    {"-w 3 -d 70 -p 69 192.0.2.1", timeout_3},
    {"-w 3s -d 70 -p 69 192.0.2.1", timeout_3},
    {"-w 6 -d 70 -p 69 192.0.2.1", isnull},
    {"-w 6s -d 70 -p 69 192.0.2.1", isnull},
    {"-O exitfirst -d 70 -p 69 192.0.2.1", exitfirst},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];

  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/udpprobe-%03x.txt", argv[2], (int)i);
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
