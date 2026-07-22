/*
 * unit_probe_build : unit tests for probe building functions
 *
 * $Id: unit_probe_build.c,v 1.7 2026/06/22 19:00:01 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2025-2026 Matthew Luckie
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

#include "scamper_debug.h"
#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_dlhdr.h"
#include "scamper_probe.h"
#include "scamper_udp4.h"
#include "scamper_icmp4.h"
#include "scamper_tcp4.h"
#include "scamper_udp6.h"
#include "scamper_icmp6.h"
#include "scamper_tcp6.h"

#include "common.h"

typedef struct sc_test
{
  int       (*define)(scamper_probe_t *, const char **);
  int       (*build)(scamper_probe_t *, uint8_t *, size_t *);
} sc_test_t;

static int udp4_1(scamper_probe_t *pr, const char **expected)
{
  /* build a simple UDP packet with 4 byte payload */
  static uint8_t data[] = {0xaa, 0xbb, 0xcc, 0xdd};
  if((pr->pr_ip_src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (pr->pr_ip_dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL)
    return -1;
  pr->pr_ip_tos   = 0;
  pr->pr_ip_ttl   = 255;
  pr->pr_ip_proto = IPPROTO_UDP;
  pr->pr_ip_id    = 0x1234;
  pr->pr_ip_off   = 0;
  pr->pr_udp_sport = 49713;
  pr->pr_udp_dport = 33435;
  pr->pr_data      = data;
  pr->pr_len       = sizeof(data);

  *expected =
    "45000020" "12340000" "ff112595" "c0000201" "c0000202"
    "c231829b" "000cbf6b"
    "aabbccdd";

  return 0;
}

static int udp4_2(scamper_probe_t *pr, const char **expected)
{
  /* the same as udp4_1 but one fewer byte in payload */
  if(udp4_1(pr, expected) != 0)
    return -1;
  pr->pr_len -= 1;

  *expected =
    "4500001f" "12340000" "ff112596" "c0000201" "c0000202"
    "c231829b" "000bc04a"
    "aabbcc";

  return 0;
}

static int icmp4_1(scamper_probe_t *pr, const char **expected)
{
  /* build a simple ICMP echo packet with 4 byte payload */
  static uint8_t data[] = {0xdd, 0xcc, 0xbb, 0xaa};
  if((pr->pr_ip_src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (pr->pr_ip_dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL)
    return -1;
  pr->pr_ip_tos    = 0;
  pr->pr_ip_ttl    = 255;
  pr->pr_ip_proto  = IPPROTO_ICMP;
  pr->pr_ip_id     = 0x4321;
  pr->pr_ip_off    = 0;
  pr->pr_icmp_type = ICMP_ECHO;
  pr->pr_icmp_code = 0;
  pr->pr_icmp_id   = 0x5678;
  pr->pr_icmp_seq  = 0x9876;
  pr->pr_data      = data;
  pr->pr_len       = sizeof(data);

  *expected =
    "45000020" "43210000" "ff01f4b7" "c0000201" "c0000202"
    "08006f99" "56789876"
    "ddccbbaa";

  return 0;
}

static int icmp4_2(scamper_probe_t *pr, const char **expected)
{
  /* the same as icmp4_1 but one fewer byte in payload */
  if(icmp4_1(pr, expected) != 0)
    return -1;
  pr->pr_len -= 1;

  *expected =
    "4500001f" "43210000" "ff01f4b8" "c0000201" "c0000202"
    "08007043" "56789876"
    "ddccbb";

  return 0;
}

static int icmp4_3(scamper_probe_t *pr, const char **expected)
{
  /* build a simple ICMP echo packet with 4 byte payload */
  static uint8_t data[] = {0xdd, 0xcc, 0xbb, 0xaa};
  static scamper_probe_ipopt_t ipopt;

  if((pr->pr_ip_src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (pr->pr_ip_dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL)
    return -1;
  pr->pr_ip_tos    = 0;
  pr->pr_ip_ttl    = 255;
  pr->pr_ip_proto  = IPPROTO_ICMP;
  pr->pr_ip_id     = 0x4321;
  pr->pr_ip_off    = 0;
  pr->pr_ipopts    = &ipopt; ipopt.type = SCAMPER_PROBE_IPOPTS_V4RR;
  pr->pr_ipoptc    = 1;
  pr->pr_icmp_type = ICMP_ECHO;
  pr->pr_icmp_code = 0;
  pr->pr_icmp_id   = 0x5678;
  pr->pr_icmp_seq  = 0x9876;
  pr->pr_data      = data;
  pr->pr_len       = sizeof(data);

  *expected =
    "4f000048" "43210000" "ff01df68" "c0000201" "c0000202"
    "072704"
    "00000000" "00000000" "00000000" "00000000" "00000000"
    "00000000" "00000000" "00000000" "00000000" "00"
    "08006f99" "56789876" "ddccbbaa";

  return 0;
}

static int tcp4_1(scamper_probe_t *pr, const char **expected)
{
  /* build a simple TCP SYN packet */
  if((pr->pr_ip_src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (pr->pr_ip_dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL)
    return -1;
  pr->pr_ip_tos     = 0;
  pr->pr_ip_ttl     = 255;
  pr->pr_ip_proto   = IPPROTO_TCP;
  pr->pr_ip_id      = 0x4321;
  pr->pr_ip_off     = 0;
  pr->pr_tcp_sport  = 55435;
  pr->pr_tcp_dport  = 443;
  pr->pr_tcp_seq    = 0x12345678;
  pr->pr_tcp_flags  = TH_SYN;
  pr->pr_tcp_wscale = 2;
  pr->pr_tcp_mss    = 1460;

  *expected =
    "45000030" "43210000" "ff06f4a2" "c0000201" "c0000202"
    "d88b01bb" "12345678" "00000000" "70020000" "bc270000"
    "020405b4" "03030201";

  return 0;
}

static int tcp4_2(scamper_probe_t *pr, const char **expected)
{
  /* build a simple TCP SYN packet with cookie */
  static uint8_t cookie[] = {0xdd, 0xcc, 0xbb, 0xaa};
  if((pr->pr_ip_src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (pr->pr_ip_dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL)
    return -1;
  pr->pr_ip_tos     = 0;
  pr->pr_ip_ttl     = 255;
  pr->pr_ip_proto   = IPPROTO_TCP;
  pr->pr_ip_id      = 0x4321;
  pr->pr_ip_off     = 0;
  pr->pr_tcp_sport  = 55435;
  pr->pr_tcp_dport  = 443;
  pr->pr_tcp_seq    = 0x12345678;
  pr->pr_tcp_flags  = TH_SYN;
  pr->pr_tcp_opts         |= SCAMPER_PROBE_TCPOPT_FO;
  pr->pr_tcp_fo_cookie     = cookie;
  pr->pr_tcp_fo_cookielen  = 4;

  *expected =
    "45000030" "43210000" "ff06f4a2" "c0000201" "c0000202"
    "d88b01bb" "12345678" "00000000" "70020000" "0c650000"
    "2206ddcc" "bbaa0101";

  return 0;
}

static int tcp4_3(scamper_probe_t *pr, const char **expected)
{
  /* build a simple TCP ACK packet with data */
  static uint8_t data[] = {0xdd, 0xcc, 0xbb, 0xaa, 0xdd, 0xcc, 0xbb, 0xaa};
  if((pr->pr_ip_src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (pr->pr_ip_dst = scamper_addr_fromstr_ipv4("192.0.2.2")) == NULL)
    return -1;
  pr->pr_ip_tos     = 0;
  pr->pr_ip_ttl     = 255;
  pr->pr_ip_proto   = IPPROTO_TCP;
  pr->pr_ip_id      = 0x4321;
  pr->pr_ip_off     = IP_DF;
  pr->pr_tcp_sport  = 55435;
  pr->pr_tcp_dport  = 443;
  pr->pr_tcp_seq    = 0x12345678;
  pr->pr_tcp_ack    = 0x87654321;
  pr->pr_tcp_flags  = TH_ACK;
  pr->pr_data       = data;
  pr->pr_len        = sizeof(data);

  *expected =
    "45000030" "43214000" "ff06b4a2" "c0000201" "c0000202"
    "d88b01bb" "12345678" "87654321" "50100000" "eb5f0000"
    "ddccbbaa" "ddccbbaa";

  return 0;
}

static int tcp4_4(scamper_probe_t *pr, const char **expected)
{
  /* the same as tcp4_1 but one fewer byte in payload */
  if(tcp4_3(pr, expected) != 0)
    return -1;
  pr->pr_len -= 1;

  *expected =
    "4500002f" "43214000" "ff06b4a3" "c0000201" "c0000202"
    "d88b01bb" "12345678" "87654321" "50100000" "ec0a0000"
    "ddccbbaa" "ddccbb";

  return 0;
}

static int udp6_1(scamper_probe_t *pr, const char **expected)
{
  /* build a simple UDP packet with 24 byte payload */
  static uint8_t data[] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd,
    0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc, 0xdd
  };
  if((pr->pr_ip_src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (pr->pr_ip_dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL)
    return -1;
  pr->pr_ip_tos   = 0;
  pr->pr_ip_ttl   = 128;
  pr->pr_ip_proto = IPPROTO_UDP;
  pr->pr_udp_sport = 49713;
  pr->pr_udp_dport = 33435;
  pr->pr_data      = data;
  pr->pr_len       = sizeof(data);

  *expected =
    "60000000" "00201180"
    "20010db8000000000000000000000001"
    "20010db8000000000000000000000002"
    "c231829b" "002091d3"
    "aabbccdd" "aabbccdd" "aabbccdd" "aabbccdd" "aabbccdd" "aabbccdd";

  return 0;
}

static int udp6_2(scamper_probe_t *pr, const char **expected)
{
  /* the same as udp6_1 but one fewer byte in payload */
  if(udp6_1(pr, expected) != 0)
    return -1;
  pr->pr_len -= 1;

  *expected =
    "60000000" "001f1180"
    "20010db8000000000000000000000001"
    "20010db8000000000000000000000002"
    "c231829b" "001f92b2"
    "aabbccdd" "aabbccdd" "aabbccdd" "aabbccdd" "aabbccdd" "aabbcc";

  return 0;
}

static int icmp6_1(scamper_probe_t *pr, const char **expected)
{
  /* build a simple ICMP echo packet with 4 byte payload */
  static uint8_t data[] = {0xdd, 0xcc, 0xbb, 0xaa};
  if((pr->pr_ip_src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (pr->pr_ip_dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL)
    return -1;
  pr->pr_ip_tos    = 0;
  pr->pr_ip_ttl    = 128;
  pr->pr_ip_proto  = IPPROTO_ICMPV6;
  pr->pr_icmp_type = ICMP6_ECHO_REQUEST;
  pr->pr_icmp_code = 0;
  pr->pr_icmp_id   = 0x5678;
  pr->pr_icmp_seq  = 0x9876;
  pr->pr_data      = data;
  pr->pr_len       = sizeof(data);

  *expected =
    "60000000" "000c3a80"
    "20010db8000000000000000000000001"
    "20010db8000000000000000000000002"
    "80009bdd" "56789876"
    "ddccbbaa";

  return 0;
}

static int icmp6_2(scamper_probe_t *pr, const char **expected)
{
  /* the same as icmp6_1 but one fewer byte in payload */
  if(icmp6_1(pr, expected) != 0)
    return -1;
  pr->pr_len -= 1;

  *expected =
    "60000000" "000b3a80"
    "20010db8000000000000000000000001"
    "20010db8000000000000000000000002"
    "80009c88" "56789876"
    "ddccbb";

  return 0;
}

static int tcp6_1(scamper_probe_t *pr, const char **expected)
{
  /* build a simple TCP SYN packet */
  if((pr->pr_ip_src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (pr->pr_ip_dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL)
    return -1;
  pr->pr_ip_tos     = 0;
  pr->pr_ip_ttl     = 255;
  pr->pr_ip_proto   = IPPROTO_TCP;
  pr->pr_tcp_sport  = 55435;
  pr->pr_tcp_dport  = 443;
  pr->pr_tcp_seq    = 0x12345678;
  pr->pr_tcp_flags  = TH_SYN;
  pr->pr_tcp_wscale = 2;
  pr->pr_tcp_mss    = 1460;

  *expected =
    "60000000" "001c06ff"
    "20010db8000000000000000000000001"
    "20010db8000000000000000000000002"
    "d88b01bb" "12345678" "00000000" "70020000" "e4b60000"
    "020405b4" "03030201";

  return 0;
}

static int tcp6_2(scamper_probe_t *pr, const char **expected)
{
  /* build a simple TCP SYN packet with cookie */
  static uint8_t cookie[] = {0xdd, 0xcc, 0xbb, 0xaa};
  if((pr->pr_ip_src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (pr->pr_ip_dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL)
    return -1;
  pr->pr_ip_tos     = 0;
  pr->pr_ip_ttl     = 255;
  pr->pr_ip_proto   = IPPROTO_TCP;
  pr->pr_tcp_sport  = 55435;
  pr->pr_tcp_dport  = 443;
  pr->pr_tcp_seq    = 0x12345678;
  pr->pr_tcp_flags  = TH_SYN;
  pr->pr_tcp_opts         |= SCAMPER_PROBE_TCPOPT_FO;
  pr->pr_tcp_fo_cookie     = cookie;
  pr->pr_tcp_fo_cookielen  = 4;

  *expected =
    "60000000" "001c06ff"
    "20010db8000000000000000000000001"
    "20010db8000000000000000000000002"
    "d88b01bb" "12345678" "00000000" "70020000" "34f40000"
    "2206ddcc" "bbaa0101";

  return 0;
}

static int tcp6_3(scamper_probe_t *pr, const char **expected)
{
  /* build a simple TCP ACK packet with data */
  static uint8_t data[] = {0xdd, 0xcc, 0xbb, 0xaa, 0xdd, 0xcc, 0xbb, 0xaa};
  if((pr->pr_ip_src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (pr->pr_ip_dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL)
    return -1;
  pr->pr_ip_tos     = 0;
  pr->pr_ip_ttl     = 255;
  pr->pr_ip_proto   = IPPROTO_TCP;
  pr->pr_tcp_sport  = 55435;
  pr->pr_tcp_dport  = 443;
  pr->pr_tcp_seq    = 0x12345678;
  pr->pr_tcp_ack    = 0x87654321;
  pr->pr_tcp_flags  = TH_ACK;
  pr->pr_data       = data;
  pr->pr_len        = sizeof(data);

  *expected =
    "60000000" "001c06ff"
    "20010db8000000000000000000000001"
    "20010db8000000000000000000000002"
    "d88b01bb" "12345678" "87654321" "50100000" "13ef0000"
    "ddccbbaa" "ddccbbaa";

  return 0;
}

static int tcp6_4(scamper_probe_t *pr, const char **expected)
{
  /* the same as tcp6_1 but one fewer byte in payload */
  if(tcp6_3(pr, expected) != 0)
    return -1;
  pr->pr_len -= 1;

  *expected =
    "60000000" "001b06ff"
    "20010db8000000000000000000000001"
    "20010db8000000000000000000000002"
    "d88b01bb" "12345678" "87654321" "50100000" "149a0000"
    "ddccbbaa" "ddccbb";

  return 0;
}

int compare(const uint8_t *pktbuf, size_t pktlen, const char *expected)
{
  uint8_t *buf = NULL;
  int rc = -1;
  size_t i;

  if(strlen(expected) / 2 != pktlen)
    {
      printf("expected %d got %d\n", (int)strlen(expected) / 2, (int)pktlen);
      goto done;
    }

  if(hex2buf(expected, &buf, &i) != 0)
    {
      printf("could not build buf\n");
      goto done;
    }

  if(i != pktlen || memcmp(buf, pktbuf, pktlen) != 0)
    {
      printf("resulting packet unexpected\n");
      goto done;
    }

  rc = 0;

 done:
  if(rc != 0)
    {
      for(i=0; i<pktlen; i++)
	printf("%02x", pktbuf[i]);
      printf("\n");
    }
  if(buf != NULL) free(buf);
  return rc;
}

void probe_clean(scamper_probe_t *pr)
{
  if(pr->pr_ip_src != NULL) scamper_addr_free(pr->pr_ip_src);
  if(pr->pr_ip_dst != NULL) scamper_addr_free(pr->pr_ip_dst);
  memset(pr, 0, sizeof(scamper_probe_t));
  return;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {udp4_1,  scamper_udp4_build},
    {udp4_2,  scamper_udp4_build},
    {icmp4_1, scamper_icmp4_build},
    {icmp4_2, scamper_icmp4_build},
    {icmp4_3, scamper_icmp4_build},
    {tcp4_1,  scamper_tcp4_build},
    {tcp4_2,  scamper_tcp4_build},
    {tcp4_3,  scamper_tcp4_build},
    {tcp4_4,  scamper_tcp4_build},
    {udp6_1,  scamper_udp6_build},
    {udp6_2,  scamper_udp6_build},
    {icmp6_1, scamper_icmp6_build},
    {icmp6_2, scamper_icmp6_build},
    {tcp6_1,  scamper_tcp6_build},
    {tcp6_2,  scamper_tcp6_build},
    {tcp6_3,  scamper_tcp6_build},
    {tcp6_4,  scamper_tcp6_build},
  };
  size_t i, pktlen, testc = sizeof(tests) / sizeof(sc_test_t);
  const char *expected;
  scamper_probe_t pr;
  uint8_t pktbuf[1500];
  int rc = 0;

  for(i=0; i<testc; i++)
    {
      memset(&pr, 0, sizeof(pr));
      pktlen = sizeof(pktbuf);
      expected = NULL;
      if(tests[i].define(&pr, &expected) != 0 ||
	 tests[i].build(&pr, pktbuf, &pktlen) != 0 ||
	 compare(pktbuf, pktlen, expected) != 0)
	{
	  printf("test %d failed\n", (int)i);
	  rc = -1;
	}
      probe_clean(&pr);
    }

  if(rc == 0)
    printf("OK\n");
  return rc;
}
