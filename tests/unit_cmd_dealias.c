/*
 * unit_cmd_dealias : unit tests for dealias commands
 *
 * $Id: unit_cmd_dealias.c,v 1.29 2024/03/04 19:36:41 mjl Exp $
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
#include "scamper_dealias.h"
#include "scamper_dealias_cmd.h"

#include "utils.h"
#include "common.h"

typedef struct sc_test
{
  const char *cmd;
  int (*func)(const scamper_dealias_t *dealias);
} sc_test_t;

static int verbose = 0;

scamper_addrcache_t *addrcache = NULL;

static int isnull(const scamper_dealias_t *in)
{
  return (in == NULL) ? 0 : -1;
}

static int ally_ttl_udp(const scamper_dealias_t *in)
{
  const scamper_dealias_ally_t *ally;
  const scamper_dealias_probedef_t *def;
  const scamper_dealias_probedef_udp_t *udp;
  const struct timeval *tv;

  if(in == NULL ||
     (ally = scamper_dealias_ally_get(in)) == NULL ||
     (tv = scamper_dealias_ally_wait_probe_get(ally)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 150000 ||
     (tv = scamper_dealias_ally_wait_timeout_get(ally)) == NULL ||
     tv->tv_sec != 5 || tv->tv_usec != 0 ||
     (def = scamper_dealias_ally_def0_get(ally)) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.1") != 0 ||
     scamper_dealias_probedef_size_get(def) != 20 + 8 + 2 ||
     scamper_dealias_probedef_id_get(def) != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 4 ||
     (udp = scamper_dealias_probedef_udp_get(def)) == NULL ||
     scamper_dealias_probedef_udp_sport_get(udp) != 57665 ||
     scamper_dealias_probedef_udp_dport_get(udp) != 33436 ||
     (def = scamper_dealias_ally_def1_get(ally)) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.2") != 0 ||
     scamper_dealias_probedef_size_get(def) != 20 + 8 + 2 ||
     scamper_dealias_probedef_id_get(def) != 1 ||
     scamper_dealias_probedef_ttl_get(def) != 5 ||
     (udp = scamper_dealias_probedef_udp_get(def)) == NULL ||
     scamper_dealias_probedef_udp_sport_get(udp) != 57664 ||
     scamper_dealias_probedef_udp_dport_get(udp) != 33435)
    return -1;

  return 0;
}

static int ally_2def(const scamper_dealias_t *in)
{
  const scamper_dealias_ally_t *ally;
  const scamper_dealias_probedef_t *def;
  const scamper_dealias_probedef_icmp_t *icmp;
  const struct timeval *tv;

  if(in == NULL ||
     (ally = scamper_dealias_ally_get(in)) == NULL ||
     (tv = scamper_dealias_ally_wait_probe_get(ally)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 0 ||
     (tv = scamper_dealias_ally_wait_timeout_get(ally)) == NULL ||
     tv->tv_sec != 5 || tv->tv_usec != 0 ||
     (def = scamper_dealias_ally_def0_get(ally)) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.1") != 0 ||
     scamper_dealias_probedef_size_get(def) != 20 + 8 + 2 ||
     scamper_dealias_probedef_id_get(def) != 0 ||
     (icmp = scamper_dealias_probedef_icmp_get(def)) == NULL ||
     scamper_dealias_probedef_icmp_csum_get(icmp) != 59832 ||
     scamper_dealias_probedef_ttl_get(def) != 255 ||
     (def = scamper_dealias_ally_def1_get(ally)) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.2") != 0 ||
     scamper_dealias_probedef_id_get(def) != 1 ||
     scamper_dealias_probedef_size_get(def) != 20 + 8 + 2 ||
     (icmp = scamper_dealias_probedef_icmp_get(def)) == NULL ||
     scamper_dealias_probedef_icmp_csum_get(icmp) != 59835 ||
     scamper_dealias_probedef_ttl_get(def) != 255)
    return -1;

  return 0;
}

static int ally_1def_2dst(const scamper_dealias_t *in)
{
  const scamper_dealias_ally_t *ally;
  const scamper_dealias_probedef_t *def;
  const scamper_dealias_probedef_tcp_t *tcp;
  const struct timeval *tv;

  if(in == NULL ||
     (ally = scamper_dealias_ally_get(in)) == NULL ||
     (tv = scamper_dealias_ally_wait_probe_get(ally)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 500000 ||
     (tv = scamper_dealias_ally_wait_timeout_get(ally)) == NULL ||
     tv->tv_sec != 5 || tv->tv_usec != 0 ||
     (def = scamper_dealias_ally_def0_get(ally)) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.1") != 0 ||
     scamper_dealias_probedef_size_get(def) != 20 + 20 ||
     scamper_dealias_probedef_id_get(def) != 0 ||
     (tcp = scamper_dealias_probedef_tcp_get(def)) == NULL ||
     scamper_dealias_probedef_tcp_dport_get(tcp) != 80 ||
     scamper_dealias_probedef_ttl_get(def) != 255 ||
     (def = scamper_dealias_ally_def1_get(ally)) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.2") != 0 ||
     scamper_dealias_probedef_size_get(def) != 20 + 20 ||
     scamper_dealias_probedef_id_get(def) != 1 ||
     (tcp = scamper_dealias_probedef_tcp_get(def)) == NULL ||
     scamper_dealias_probedef_tcp_dport_get(tcp) != 80 ||
     scamper_dealias_probedef_ttl_get(def) != 255)
    return -1;

  return 0;
}

static int mercator(const scamper_dealias_t *in)
{
  const scamper_dealias_mercator_t *mc;
  const scamper_dealias_probedef_t *def;
  const scamper_dealias_probedef_udp_t *udp;
  const struct timeval *tv;

  if(in == NULL ||
     (mc = scamper_dealias_mercator_get(in)) == NULL ||
     (tv = scamper_dealias_mercator_wait_timeout_get(mc)) == NULL ||
     tv->tv_sec != 5 || tv->tv_usec != 0 ||
     (def = scamper_dealias_mercator_def_get(mc)) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.1") != 0 ||
     scamper_dealias_probedef_size_get(def) != 20 + 8 + 2 ||
     scamper_dealias_probedef_id_get(def) != 0 ||
     (udp = scamper_dealias_probedef_udp_get(def)) == NULL ||
     scamper_dealias_probedef_udp_dport_get(udp) != 33435 ||
     scamper_dealias_probedef_ttl_get(def) != 255)
    return -1;

  return 0;
}

static int mercator_54321(const scamper_dealias_t *in)
{
  const scamper_dealias_mercator_t *mc;
  const scamper_dealias_probedef_t *def;
  const scamper_dealias_probedef_udp_t *udp;
  const struct timeval *tv;

  if(in == NULL ||
     (mc = scamper_dealias_mercator_get(in)) == NULL ||
     (tv = scamper_dealias_mercator_wait_timeout_get(mc)) == NULL ||
     tv->tv_sec != 5 || tv->tv_usec != 0 ||
     (def = scamper_dealias_mercator_def_get(mc)) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.1") != 0 ||
     scamper_dealias_probedef_size_get(def) != 20 + 8 + 2 ||
     scamper_dealias_probedef_id_get(def) != 0 ||
     (udp = scamper_dealias_probedef_udp_get(def)) == NULL ||
     scamper_dealias_probedef_udp_dport_get(udp) != 54321 ||
     scamper_dealias_probedef_ttl_get(def) != 255)
    return -1;

  return 0;
}

static int bump_udp(const scamper_dealias_t *in)
{
  const scamper_dealias_bump_t *bump;
  const scamper_dealias_probedef_t *def;
  const struct timeval *tv;

  if(in == NULL ||
     (bump = scamper_dealias_bump_get(in)) == NULL ||
     (tv = scamper_dealias_bump_wait_probe_get(bump)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 0 ||
     (def = scamper_dealias_bump_def0_get(bump)) == NULL ||
     scamper_dealias_probedef_size_get(def) != 20 + 8 + 2 ||
     scamper_dealias_probedef_id_get(def) != 0 ||
     scamper_dealias_probedef_udp_get(def) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.1") != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 255 ||
     (def = scamper_dealias_bump_def1_get(bump)) == NULL ||
     scamper_dealias_probedef_size_get(def) != 20 + 8 + 2 ||
     scamper_dealias_probedef_id_get(def) != 1 ||
     scamper_dealias_probedef_udp_get(def) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.2") != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 255)
    return -1;

  return 0;
}

static int radargun_3def(const scamper_dealias_t *in)
{
  const scamper_dealias_radargun_t *rg;
  const scamper_dealias_probedef_t *def;
  const struct timeval *tv;

  if(in == NULL ||
     (rg = scamper_dealias_radargun_get(in)) == NULL ||
     (tv = scamper_dealias_radargun_wait_probe_get(rg)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 150000 ||
     (tv = scamper_dealias_radargun_wait_timeout_get(rg)) == NULL ||
     tv->tv_sec != 5 || tv->tv_usec != 0 ||
     (tv = scamper_dealias_radargun_wait_round_get(rg)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 450000 ||
     (def = scamper_dealias_radargun_def_get(rg, 0)) == NULL ||
     scamper_dealias_probedef_size_get(def) != 20 + 8 + 2 ||
     scamper_dealias_probedef_id_get(def) != 0 ||
     scamper_dealias_probedef_icmp_get(def) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.1") != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 255 ||
     (def = scamper_dealias_radargun_def_get(rg, 1)) == NULL ||
     scamper_dealias_probedef_size_get(def) != 20 + 20 ||
     scamper_dealias_probedef_id_get(def) != 1 ||
     scamper_dealias_probedef_tcp_get(def) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.2") != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 255 ||
     (def = scamper_dealias_radargun_def_get(rg, 2)) == NULL ||
     scamper_dealias_probedef_size_get(def) != 20 + 8 + 2 ||
     scamper_dealias_probedef_id_get(def) != 2 ||
     scamper_dealias_probedef_udp_get(def) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.3") != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 255)
    return -1;

  return 0;
}

static int radargun_1def_3dst(const scamper_dealias_t *in)
{
  const scamper_dealias_radargun_t *rg;
  const scamper_dealias_probedef_t *def;
  const struct timeval *tv;

  if(in == NULL ||
     (rg = scamper_dealias_radargun_get(in)) == NULL ||
     (tv = scamper_dealias_radargun_wait_probe_get(rg)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 150000 ||
     (tv = scamper_dealias_radargun_wait_timeout_get(rg)) == NULL ||
     tv->tv_sec != 5 || tv->tv_usec != 0 ||
     (tv = scamper_dealias_radargun_wait_round_get(rg)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 450000 ||
     (def = scamper_dealias_radargun_def_get(rg, 0)) == NULL ||
     scamper_dealias_probedef_size_get(def) != 20 + 20 ||
     scamper_dealias_probedef_id_get(def) != 0 ||
     scamper_dealias_probedef_tcp_get(def) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.1") != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 255 ||
     (def = scamper_dealias_radargun_def_get(rg, 1)) == NULL ||
     scamper_dealias_probedef_size_get(def) != 20 + 20 ||
     scamper_dealias_probedef_id_get(def) != 1 ||
     scamper_dealias_probedef_tcp_get(def) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.2") != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 255 ||
     (def = scamper_dealias_radargun_def_get(rg, 2)) == NULL ||
     scamper_dealias_probedef_size_get(def) != 20 + 20 ||
     scamper_dealias_probedef_id_get(def) != 2 ||
     scamper_dealias_probedef_tcp_get(def) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.3") != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 255)
    return -1;

  return 0;
}

static int radargun_1def_3dst_v6(const scamper_dealias_t *in)
{
  const scamper_dealias_radargun_t *rg;
  const scamper_dealias_probedef_t *def;
  const struct timeval *tv;

  if(in == NULL ||
     (rg = scamper_dealias_radargun_get(in)) == NULL ||
     (tv = scamper_dealias_radargun_wait_probe_get(rg)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 20000 ||
     (tv = scamper_dealias_radargun_wait_timeout_get(rg)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 0 ||
     (tv = scamper_dealias_radargun_wait_round_get(rg)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 60000 ||
     scamper_dealias_radargun_rounds_get(rg) != 2 ||
     (def = scamper_dealias_radargun_def_get(rg, 0)) == NULL ||
     scamper_dealias_probedef_size_get(def) != 40 + 8 + 2 ||
     scamper_dealias_probedef_id_get(def) != 0 ||
     scamper_dealias_probedef_icmp_get(def) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "2001:DB8::1") != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 255 ||
     (def = scamper_dealias_radargun_def_get(rg, 1)) == NULL ||
     scamper_dealias_probedef_size_get(def) != 40 + 8 + 2 ||
     scamper_dealias_probedef_id_get(def) != 1 ||
     scamper_dealias_probedef_icmp_get(def) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "2001:DB8::2") != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 255 ||
     (def = scamper_dealias_radargun_def_get(rg, 2)) == NULL ||
     scamper_dealias_probedef_size_get(def) != 40 + 8 + 2 ||
     scamper_dealias_probedef_id_get(def) != 2 ||
     scamper_dealias_probedef_icmp_get(def) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "2001:DB8::3") != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 255)
    return -1;

  return 0;
}

static int radargun_2def_3dst(const scamper_dealias_t *in)
{
  const scamper_dealias_radargun_t *rg;
  const scamper_dealias_probedef_t *def;
  const struct timeval *tv;
  char *addrs[] = {"192.0.2.1", "192.0.2.2", "192.0.2.3"};
  uint32_t x;
  int i, j;

  if(in == NULL ||
     (rg = scamper_dealias_radargun_get(in)) == NULL ||
     (tv = scamper_dealias_radargun_wait_probe_get(rg)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 150000 ||
     (tv = scamper_dealias_radargun_wait_timeout_get(rg)) == NULL ||
     tv->tv_sec != 5 || tv->tv_usec != 0 ||
     (tv = scamper_dealias_radargun_wait_round_get(rg)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 900000)
    return -1;

  x = 0;
  for(i=0; i<2; i++)
    {
      for(j=0; j<3; j++)
	{
	  if((def = scamper_dealias_radargun_def_get(rg, x)) == NULL ||
	     check_addr(scamper_dealias_probedef_dst_get(def), addrs[j]) != 0 ||
	     scamper_dealias_probedef_id_get(def) != x ||
	     scamper_dealias_probedef_ttl_get(def) != 255)
	    return -1;
	  if((i == 0 && scamper_dealias_probedef_is_tcp(def) == 0) ||
	     (i == 1 && scamper_dealias_probedef_is_udp(def) == 0))
	    return -1;
	  x++;
	}
    }

  return 0;
}

static int prefixscan_udp(const scamper_dealias_t *in)
{
  const scamper_dealias_prefixscan_t *pfs;
  const scamper_dealias_probedef_t *def;
  const struct timeval *tv;

  if(in == NULL ||
     (pfs = scamper_dealias_prefixscan_get(in)) == NULL ||
     (tv = scamper_dealias_prefixscan_wait_probe_get(pfs)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 0 ||
     (tv = scamper_dealias_prefixscan_wait_timeout_get(pfs)) == NULL ||
     tv->tv_sec != 5 || tv->tv_usec != 0 ||
     (def = scamper_dealias_prefixscan_def_get(pfs, 0)) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.69") != 0 ||
     scamper_dealias_probedef_size_get(def) != 20 + 8 + 2 ||
     scamper_dealias_probedef_id_get(def) != 0 ||
     scamper_dealias_probedef_udp_get(def) == NULL ||
     scamper_dealias_probedef_ttl_get(def) != 255)
    return -1;

  return 0;
}

static int speedtrap(const scamper_dealias_t *in)
{
  const scamper_dealias_ally_t *ally;
  const scamper_dealias_probedef_t *def;
  const struct timeval *tv;

  if(in == NULL ||
     scamper_dealias_userid_get(in) != 45 ||
     (ally = scamper_dealias_ally_get(in)) == NULL ||
     scamper_dealias_ally_fudge_get(ally) != 65535 ||
     (tv = scamper_dealias_ally_wait_probe_get(ally)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 0 ||
     (tv = scamper_dealias_ally_wait_timeout_get(ally)) == NULL ||
     tv->tv_sec != 2 || tv->tv_usec != 0 ||
     (def = scamper_dealias_ally_def0_get(ally)) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "2001:DB8::1") != 0 ||
     scamper_dealias_probedef_id_get(def) != 0 ||
     scamper_dealias_probedef_icmp_get(def) == NULL ||
     scamper_dealias_probedef_size_get(def) != 1300 ||
     scamper_dealias_probedef_mtu_get(def) != 1280 ||
     scamper_dealias_probedef_ttl_get(def) != 255 ||
     (def = scamper_dealias_ally_def1_get(ally)) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "2001:DB8::2") != 0 ||
     scamper_dealias_probedef_id_get(def) != 1 ||
     scamper_dealias_probedef_size_get(def) != 1300 ||
     scamper_dealias_probedef_mtu_get(def) != 1280 ||
     scamper_dealias_probedef_icmp_get(def) == NULL ||
     scamper_dealias_probedef_ttl_get(def) != 255)
    return -1;

  return 0;
}

static int radargun_lfp(const scamper_dealias_t *in)
{
  const scamper_dealias_radargun_t *rg;
  const scamper_dealias_probedef_t *def;
  const struct timeval *tv;

  if(in == NULL ||
     (rg = scamper_dealias_radargun_get(in)) == NULL ||
     scamper_dealias_radargun_rounds_get(rg) != 3 ||
     (tv = scamper_dealias_radargun_wait_round_get(rg)) == NULL ||
     tv->tv_sec != 3 || tv->tv_usec != 0 ||
     (tv = scamper_dealias_radargun_wait_probe_get(rg)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 0 ||
     (tv = scamper_dealias_radargun_wait_timeout_get(rg)) == NULL ||
     tv->tv_sec != 5 || tv->tv_usec != 0 ||
     (def = scamper_dealias_radargun_def_get(rg, 0)) == NULL ||
     scamper_dealias_probedef_size_get(def) != 84 ||
     scamper_dealias_probedef_id_get(def) != 0 ||
     scamper_dealias_probedef_icmp_get(def) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.1") != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 255 ||
     (def = scamper_dealias_radargun_def_get(rg, 1)) == NULL ||
     scamper_dealias_probedef_size_get(def) != 20 + 20 ||
     scamper_dealias_probedef_id_get(def) != 1 ||
     scamper_dealias_probedef_tcp_get(def) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.1") != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 255 ||
     (def = scamper_dealias_radargun_def_get(rg, 2)) == NULL ||
     scamper_dealias_probedef_size_get(def) != 48 ||
     scamper_dealias_probedef_id_get(def) != 2 ||
     scamper_dealias_probedef_udp_get(def) == NULL ||
     check_addr(scamper_dealias_probedef_dst_get(def), "192.0.2.1") != 0 ||
     scamper_dealias_probedef_ttl_get(def) != 255)
    return -1;

  return 0;
}

static int midarest_3def_3dst(const scamper_dealias_t *in)
{
  const scamper_dealias_midarest_t *me;
  const scamper_dealias_probedef_t *def;
  const struct timeval *tv;
  char *addrs[] = {"192.0.2.1", "192.0.2.2", "192.0.2.3"};
  uint32_t x;
  int i, j;

  if(in == NULL ||
     (me = scamper_dealias_midarest_get(in)) == NULL ||
     scamper_dealias_midarest_rounds_get(me) != 30 ||
     scamper_dealias_midarest_defc_get(me) != (3 * 3) ||
     (tv = scamper_dealias_midarest_wait_round_get(me)) == NULL ||
     tv->tv_sec != 10 || tv->tv_usec != 0 ||
     (tv = scamper_dealias_midarest_wait_probe_get(me)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 111111 ||
     (tv = scamper_dealias_midarest_wait_timeout_get(me)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 0)
    return -1;

  x = 0;
  for(i=0; i<3; i++)
    {
      for(j=0; j<3; j++)
	{
	  if((def = scamper_dealias_midarest_def_get(me, x)) == NULL ||
	     check_addr(scamper_dealias_probedef_dst_get(def), addrs[j]) != 0 ||
	     scamper_dealias_probedef_id_get(def) != x ||
	     scamper_dealias_probedef_ttl_get(def) != 64)
	    return -1;
	  if((i == 0 && scamper_dealias_probedef_is_tcp(def) == 0) ||
	     (i == 1 && scamper_dealias_probedef_is_icmp(def) == 0) ||
	     (i == 2 && scamper_dealias_probedef_is_udp(def) == 0))
	    return -1;
	  x++;
	}
    }

  return 0;
}

static int midarest_3def_3dst_W03_r3(const scamper_dealias_t *in)
{
  const scamper_dealias_midarest_t *me;
  const struct timeval *tv;

  if(in == NULL ||
     (me = scamper_dealias_midarest_get(in)) == NULL ||
     scamper_dealias_midarest_rounds_get(me) != 30 ||
     scamper_dealias_midarest_defc_get(me) != (3 * 3) ||
     (tv = scamper_dealias_midarest_wait_round_get(me)) == NULL ||
     tv->tv_sec != 3 || tv->tv_usec != 0 ||
     (tv = scamper_dealias_midarest_wait_probe_get(me)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 300000 ||
     (tv = scamper_dealias_midarest_wait_timeout_get(me)) == NULL ||
     tv->tv_sec != 1 || tv->tv_usec != 0)
    return -1;

  return 0;
}

static int midarest_3def_3dst_W02_w2_r3(const scamper_dealias_t *in)
{
  const scamper_dealias_midarest_t *me;
  const struct timeval *tv;

  if(in == NULL ||
     (me = scamper_dealias_midarest_get(in)) == NULL ||
     scamper_dealias_midarest_rounds_get(me) != 30 ||
     scamper_dealias_midarest_defc_get(me) != (3 * 3) ||
     (tv = scamper_dealias_midarest_wait_round_get(me)) == NULL ||
     tv->tv_sec != 3 || tv->tv_usec != 0 ||
     (tv = scamper_dealias_midarest_wait_probe_get(me)) == NULL ||
     tv->tv_sec != 0 || tv->tv_usec != 200000 ||
     (tv = scamper_dealias_midarest_wait_timeout_get(me)) == NULL ||
     tv->tv_sec != 2 || tv->tv_usec != 0)
    return -1;

  return 0;
}

static int midardisc_4def_3sch(const scamper_dealias_t *in)
{
  const scamper_dealias_probedef_t *def;
  const scamper_dealias_midardisc_t *md;
  const scamper_dealias_midardisc_round_t *r;
  const struct timeval *tv;
  char *addrs[] = {"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"};
  uint32_t i;

  if(in == NULL ||
     (md = scamper_dealias_midardisc_get(in)) == NULL ||
     scamper_dealias_midardisc_defc_get(md) != 4 ||
     scamper_dealias_midardisc_schedc_get(md) != 3 ||
     (tv = scamper_dealias_midardisc_startat_get(md)) == NULL ||
     tv->tv_sec != 1703214000 || tv->tv_usec != 654321)
    return -1;

  for(i=0; i<4; i++)
    {
      if((def = scamper_dealias_midardisc_def_get(md, i)) == NULL ||
	 check_addr(scamper_dealias_probedef_dst_get(def), addrs[i]) != 0 ||
	 scamper_dealias_probedef_id_get(def) != i ||
	 scamper_dealias_probedef_ttl_get(def) != 64)
	return -1;
      if((i == 0 && scamper_dealias_probedef_is_tcp(def) == 0) ||
	 (i == 1 && scamper_dealias_probedef_is_icmp(def) == 0) ||
	 (i == 2 && scamper_dealias_probedef_is_udp(def) == 0) ||
	 (i == 3 && scamper_dealias_probedef_is_tcp(def) == 0))
	return -1;
    }

  for(i=0; i<3; i++)
    {
      if((r = scamper_dealias_midardisc_sched_get(md, i)) == NULL ||
	 (tv = scamper_dealias_midardisc_round_start_get(r)) == NULL)
	return -1;
      switch(i)
	{
	case 0:
	  if(scamper_dealias_midardisc_round_begin_get(r) != 0 ||
	     scamper_dealias_midardisc_round_end_get(r) != 2 ||
	     tv->tv_sec != 0 || tv->tv_usec != 0)
	    return -1;
	  break;
	case 1:
	  if(scamper_dealias_midardisc_round_begin_get(r) != 1 ||
	     scamper_dealias_midardisc_round_end_get(r) != 3 ||
	     tv->tv_sec != 0 || tv->tv_usec != 123000)
	    return -1;
	  break;
	case 2:
	  if(scamper_dealias_midardisc_round_begin_get(r) != 2 ||
	     scamper_dealias_midardisc_round_end_get(r) != 3 ||
	     tv->tv_sec != 0 || tv->tv_usec != 234000)
	    return -1;
	  break;
	}
    }

  return 0;
}

static int check(const char *cmd, int (*func)(const scamper_dealias_t *in))
{
  scamper_dealias_t *dealias;
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
  dealias = scamper_do_dealias_alloc(dup, errbuf, sizeof(errbuf));
  free(dup);
  if((rc = func(dealias)) != 0)
    printf("fail: %s\n", cmd);
  if(dealias != NULL)
    scamper_dealias_free(dealias);

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
    /* valid TTL-limited probes using UDP packets */
    {"-m ally -O inseq"
     " -p '-P udp -d 33436 -F 57665 -t 4 -i 192.0.2.1'"
     " -p '-P udp -d 33435 -F 57664 -t 5 -i 192.0.2.2'", ally_ttl_udp},
    /* ICMP probes don't have source or destination ports */
    {"-m ally"
     " -p '-P icmp-echo -d 33436 -i 192.0.2.1'"
     " -p '-P icmp-echo -d 33435 -i 192.0.2.2'", isnull},
    {"-m ally"
     " -p '-P icmp-echo -F 57665 -i 192.0.2.1'"
     " -p '-P icmp-echo -F 57665 -i 192.0.2.2'", isnull},
    /* valid ally probes */
    {"-m ally -W 1000"
     " -p '-P icmp-echo -c 59832 -i 192.0.2.1'"
     " -p '-P icmp-echo -c 59835 -i 192.0.2.2'", ally_2def},
    {"-m ally -W 1s"
     " -p '-P icmp-echo -c 59832 -i 192.0.2.1'"
     " -p '-P icmp-echo -c 59835 -i 192.0.2.2'", ally_2def},
    {"-m ally -W 1000ms"
     " -p '-P icmp-echo -c 59832 -i 192.0.2.1'"
     " -p '-P icmp-echo -c 59835 -i 192.0.2.2'", ally_2def},
    {"-m ally -W 500"
     " -p '-P tcp-ack -d 80' 192.0.2.1 192.0.2.2", ally_1def_2dst},
    {"-m ally -W 0.5s"
     " -p '-P tcp-ack -d 80' 192.0.2.1 192.0.2.2", ally_1def_2dst},
    /* invalid ally with inconsistent probedefs */
    {"-m ally -W 1000"
     " -p '-P icmp-echo -i 192.0.2.1' 192.0.2.2", isnull},
    {"-m ally -W 1000"
     " -p '-P icmp-echo -i 192.0.2.1' 192.0.2.1 192.0.2.2", isnull},
    /* valid mercator without a probedef */
    {"-m mercator 192.0.2.1", mercator},
    {"-m mercator -p '-P udp -d 54321' 192.0.2.1", mercator_54321},
    /* bump needs two probedefs */
    {"-m bump 192.0.2.1 192.0.2.2", isnull},
    {"-m bump -p '-P udp' 192.0.2.1 192.0.2.2", isnull},
    /* valid bump with two probedefs */
    {"-m bump -p '-P udp -i 192.0.2.1' -p '-P udp -i 192.0.2.2'", bump_udp},
    /* invalid prefixscan with no probedef */
    {"-m prefixscan 192.0.2.69 192.0.2.2/30", isnull},
    /* invalid prefixscan with an IP address included in probedef */
    {"-m prefixscan -p '-P udp -i 192.0.2.69' 192.0.2.69 192.0.2.2/30", isnull},
    /* valid prefixscan with a probedef */
    {"-m prefixscan -p '-P udp' 192.0.2.69 192.0.2.2/30", prefixscan_udp},
    /* invalid radargun with -P icmp */
    {"-m radargun"
     " -p '-P icmp -i 192.0.2.1'"
     " -p '-P tcp-ack -i 192.0.2.2'"
     " -p '-P udp -i 192.0.2.3'", isnull},
    /* valid radargun with three probedefs */
    {"-m radargun"
     " -p '-P icmp-echo -i 192.0.2.1'"
     " -p '-P tcp-ack -i 192.0.2.2'"
     " -p '-P udp -i 192.0.2.3'", radargun_3def},
    /* valid radargun with one probedef and three destinations */
    {"-m radargun -p '-P tcp-ack' 192.0.2.1 192.0.2.2 192.0.2.3",
     radargun_1def_3dst},
    {"-m radargun -p '-P tcp-ack' -p '-P udp' 192.0.2.1 192.0.2.2 192.0.2.3",
     radargun_2def_3dst},
    {"-m radargun -q 2 -W 20ms -w 1s"
     " -p '-P icmp-echo' 2001:DB8::1 2001:DB8::2 2001:DB8::3",
     radargun_1def_3dst_v6},
    /* speedtrap */
    {"-m ally -U 45 -f 65535 -w 2 -W 1000"
     " -p '-P icmp-echo -s 1300 -M 1280' 2001:DB8::1 2001:DB8::2", speedtrap},
    {"-m ally -U 45 -f 65535 -w 2s -W 1s"
     " -p '-P icmp-echo -s 1300 -M 1280' 2001:DB8::1 2001:DB8::2", speedtrap},
    /* valid radargun imitating lightweight finterprint */
    {"-m radargun -q 3 -W 1000 -r 3000"
     " -p '-P icmp-echo -s 84 -i 192.0.2.1'"
     " -p '-P tcp-ack -s 40 -i 192.0.2.1'"
     " -p '-P udp -s 48 -i 192.0.2.1'", radargun_lfp},
    {"-m radargun -q 3 -W 1s -r 3s"
     " -p '-P icmp-echo -s 84 -i 192.0.2.1'"
     " -p '-P tcp-ack -s 40 -i 192.0.2.1'"
     " -p '-P udp -s 48 -i 192.0.2.1'", radargun_lfp},
    /* invalid alias resolution commands because the size is not accepted */
    {"-m radargun -q 3 -p '-P icmp-echo -s 29' 192.0.2.1 192.0.2.2 192.0.2.3",
     isnull},
    {"-m ally -p '-P tcp-ack -d 80 -s 35' 192.0.2.1 192.0.2.2", isnull},
    {"-m prefixscan -p '-P udp -s 29' 192.0.2.69 192.0.2.2/30", isnull},
    {"-m bump -p '-P udp -i 192.0.2.1' -p '-P udp -s 29 -i 192.0.2.2'", isnull},
    /* valid midar estimation */
    {"-m midarest -r 10000 -p '-P tcp-ack' -p '-P icmp-echo' -p '-P udp'"
     " 192.0.2.1 192.0.2.2 192.0.2.3", midarest_3def_3dst},
    {"-m midarest -r 10s -p '-P tcp-ack' -p '-P icmp-echo' -p '-P udp'"
     " 192.0.2.1 192.0.2.2 192.0.2.3", midarest_3def_3dst},
    {"-m midarest -p '-P tcp-ack' -p '-P icmp-echo' -p '-P udp'"
     " 192.0.2.1 192.0.2.2 192.0.2.3", midarest_3def_3dst},
    /* check the midarest wait parameter math */
    {"-m midarest -W 1s -r 2s -p '-P tcp-ack' -p '-P icmp-echo' -p '-P udp'"
     " 192.0.2.1 192.0.2.2 192.0.2.3", isnull},
    {"-m midarest -W 0.3s -r 3s -p '-P tcp-ack' -p '-P icmp-echo' -p '-P udp'"
     " 192.0.2.1 192.0.2.2 192.0.2.3", midarest_3def_3dst_W03_r3},
    {"-m midarest -W 0.2s -w 2s -r 3s"
     " -p '-P tcp-ack' -p '-P icmp-echo' -p '-P udp'"
     " 192.0.2.1 192.0.2.2 192.0.2.3", midarest_3def_3dst_W02_w2_r3},
    /* check midardisc */
    {"-m midardisc -@ 1703214000.654321"
     " -p '-P tcp-ack -i 192.0.2.1'"
     " -p '-P icmp-echo -i 192.0.2.2'"
     " -p '-P udp -i 192.0.2.3'"
     " -p '-P tcp-ack -i 192.0.2.4'"
     " -S 0:0:2 -S 0.123:1:3 -S 0.234:2:3",
     midardisc_4def_3sch},
    {"-m midardisc "
     " -p '-P tcp-ack -i 192.0.2.1'"
     " -p '-P icmp-echo -i 192.0.2.2'"
     " -p '-P udp -i 192.0.2.3'"
     " -p '-P tcp-ack -i 192.0.2.4'"
     " -S 0:0:2 -S 0.0:1:3 -S 0.234:2:3", /* two rounds with same start time */
     isnull},
    {"-m midardisc "
     " -p '-P tcp-ack -i 192.0.2.1'"
     " -p '-P icmp-echo -i 192.0.2.2'"
     " -p '-P udp -i 192.0.2.3'"
     " -p '-P tcp-ack -i 192.0.2.4'"
     " -S 0:0:2 -S 0.123:0:1 -S 0.234:2:3", /* two rounds with invalid slide */
     isnull},
    {"-m midardisc "
     " -p '-P tcp-ack -i 192.0.2.1'"
     " -p '-P icmp-echo -i 192.0.2.2'"
     " -p '-P udp -i 192.0.2.3'"
     " -p '-P tcp-ack -i 192.0.2.4'"
     " -S 0:0:2 -S 0.123:1:3 -S 0.234:0:3", /* two rounds with invalid slide */
     isnull},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];

  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/dealias-%03x.txt", argv[2], (int)i);
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
