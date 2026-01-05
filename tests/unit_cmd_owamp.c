/*
 * unit_cmd_owamp : unit tests for owamp commands
 *
 * $Id: unit_cmd_owamp.c,v 1.2 2026/01/04 02:15:41 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2026 The Regents of the University of California
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
#include "scamper_owamp.h"
#include "scamper_owamp_cmd.h"

#include "utils.h"
#include "common.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(const scamper_owamp_t *owamp);
} sc_test_t;

scamper_addrcache_t *addrcache = NULL;

static int check(const char *cmd, int (*func)(const scamper_owamp_t *in))
{
  scamper_owamp_t *owamp;
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
  owamp = scamper_do_owamp_alloc(dup, errbuf, sizeof(errbuf));
  free(dup);
  if((rc = func(owamp)) != 0)
    printf("fail: %s\n", cmd);
  if(owamp != NULL)
    scamper_owamp_free(owamp);

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

static int isnull(const scamper_owamp_t *in)
{
  return (in == NULL) ? 0 : -1;
}

static int notnull(const scamper_owamp_t *in)
{
  return (in != NULL) ? 0 : -1;
}

static int defaults(const scamper_owamp_t *in)
{
  const struct timeval *tv;
  scamper_owamp_sched_t *sched;
  if(in == NULL ||
     check_addr(scamper_owamp_dst_get(in), "192.0.2.1") != 0 ||
     scamper_owamp_attempts_get(in) != 10 ||
     scamper_owamp_dir_get(in) != SCAMPER_OWAMP_DIR_TX ||
     scamper_owamp_dport_get(in) != 861 ||
     scamper_owamp_userid_get(in) != 0 ||
     scamper_owamp_ttl_get(in) != 255 ||
     scamper_owamp_pktsize_get(in) != 20 + 8 + 14 ||
     scamper_owamp_flags_get(in) != 0 ||
     (tv = scamper_owamp_wait_timeout_get(in)) == NULL ||
     timeval_cmp_eq(tv, 2, 0) == 0 ||
     scamper_owamp_schedc_get(in) != 1 ||
     (sched = scamper_owamp_sched_get(in, 0)) == NULL ||
     scamper_owamp_sched_type_get(sched) != SCAMPER_OWAMP_SCHED_TYPE_FIXED ||
     (tv = scamper_owamp_sched_tv_get(sched)) == NULL ||
     timeval_cmp_eq(tv, 0, 100000) == 0)
    return -1;
  return 0;
}

static int defaults_v6(const scamper_owamp_t *in)
{
  if(in == NULL ||
     check_addr(scamper_owamp_dst_get(in), "2001:db8::55") != 0 ||
     scamper_owamp_pktsize_get(in) != 40 + 8 + 14)
    return -1;
  return 0;
}

static int count_1500(const scamper_owamp_t *in)
{
  if(in == NULL ||
     scamper_owamp_attempts_get(in) != 1500)
    return -1;
  return 0;
}

static int dir_tx(const scamper_owamp_t *in)
{
  if(in == NULL ||
     scamper_owamp_dir_get(in) != SCAMPER_OWAMP_DIR_TX)
    return -1;
  return 0;
}

static int dir_rx(const scamper_owamp_t *in)
{
  if(in == NULL ||
     scamper_owamp_dir_get(in) != SCAMPER_OWAMP_DIR_RX)
    return -1;
  return 0;
}

static int sched_05_01_02(const scamper_owamp_t *in)
{
  const struct timeval *tv;
  scamper_owamp_sched_t *sched;
  if(in == NULL ||
     scamper_owamp_schedc_get(in) != 3 ||
     (sched = scamper_owamp_sched_get(in, 0)) == NULL ||
     scamper_owamp_sched_type_get(sched) != SCAMPER_OWAMP_SCHED_TYPE_FIXED ||
     (tv = scamper_owamp_sched_tv_get(sched)) == NULL ||
     timeval_cmp_eq(tv, 0, 500000) == 0 ||
     (sched = scamper_owamp_sched_get(in, 1)) == NULL ||
     scamper_owamp_sched_type_get(sched) != SCAMPER_OWAMP_SCHED_TYPE_FIXED ||
     (tv = scamper_owamp_sched_tv_get(sched)) == NULL ||
     timeval_cmp_eq(tv, 0, 100000) == 0 ||
     (sched = scamper_owamp_sched_get(in, 2)) == NULL ||
     scamper_owamp_sched_type_get(sched) != SCAMPER_OWAMP_SCHED_TYPE_FIXED ||
     (tv = scamper_owamp_sched_tv_get(sched)) == NULL ||
     timeval_cmp_eq(tv, 0, 200000) == 0)
    return -1;
  return 0;
}

static int pktsize_1200(const scamper_owamp_t *in)
{
  if(in == NULL ||
     scamper_owamp_pktsize_get(in) != 1200)
    return -1;
  return 0;
}

static int userid_55(const scamper_owamp_t *in)
{
  if(in == NULL ||
     scamper_owamp_userid_get(in) != 55)
    return -1;
  return 0;
}

static int wait_1s(const scamper_owamp_t *in)
{
  const struct timeval *tv;
  if(in == NULL ||
     (tv = scamper_owamp_wait_timeout_get(in)) == NULL ||
     timeval_cmp_eq(tv, 1, 0) == 0)
    return -1;
  return 0;
}

int main(int argc, char *argv[])
{
  char startat_passed_ok[32], startat_passed_bad[32];
  char startat_future_ok[32], startat_future_bad[32];
  sc_test_t tests[] = {
    {"192.0.2.1", defaults},
    {"2001:db8::55", defaults_v6},
    {"-c 1500 192.0.2.1", count_1500},
    {"-d tx 192.0.2.1", dir_tx},
    {"-d rx 192.0.2.1", dir_rx},
    {"-i 0.5,0.1,0.2 192.0.2.1", sched_05_01_02},
    {"-s 1200 192.0.2.1", pktsize_1200},
    {"-U 55 192.0.2.1", userid_55},
    {"-w 1.0s 192.0.2.1", wait_1s},
    {startat_passed_ok, notnull},
    {startat_passed_bad, isnull},
    {startat_future_ok, notnull},
    {startat_future_bad, isnull},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];
  struct timeval now, tv, x;

  gettimeofday_wrap(&now);

  /* startat passed less than a second ago */
  x.tv_sec = 0; x.tv_usec = 423251;
  timeval_sub_tv3(&tv, &now, &x);
  snprintf(startat_passed_ok, sizeof(startat_passed_ok),
	   "-@ %u.%06u 192.0.2.1", (uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec);

  /* startat passed more than a second ago */
  x.tv_sec = 1; x.tv_usec = 423251;
  timeval_sub_tv3(&tv, &now, &x);
  snprintf(startat_passed_bad, sizeof(startat_passed_bad),
	   "-@ %u.%06u 192.0.2.1", (uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec);

  /* startat less than ten seconds away */
  x.tv_sec = 7; x.tv_usec = 423251;
  timeval_add_tv3(&tv, &now, &x);
  snprintf(startat_future_ok, sizeof(startat_future_ok),
	   "-@ %u.%06u 192.0.2.1", (uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec);

  /* startat more than ten seconds away */
  x.tv_sec = 15; x.tv_usec = 423251;
  timeval_add_tv3(&tv, &now, &x);
  snprintf(startat_future_bad, sizeof(startat_future_bad),
	   "-@ %u.%06u 192.0.2.1", (uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec);

  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/owamp-%03x.txt", argv[2], (int)i);
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
