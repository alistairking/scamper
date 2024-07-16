/*
 * unit_dl_parse_ip : unit tests for dl_parse_ip function
 *
 * $Id: unit_dl_parse_ip.c,v 1.7 2024/04/20 00:15:02 mjl Exp $
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
#include "scamper_dl.h"
#include "common.h"
#include "utils.h"

/*
 * function prototype of a normally static function that is not in
 * scamper_dl.h
 */
int dl_parse_ip(scamper_dl_rec_t *dl, uint8_t *pktbuf, size_t pktlen);

typedef struct sc_test
{
  char *pkt;
  int (*func)(uint8_t *pkt, size_t len);
} sc_test_t;

static int tcp_cookie_base(const scamper_dl_rec_t *dl, const uint8_t *pkt,
			   uint16_t ip_datalen, uint16_t ip_size,
			   uint8_t tcp_hl,
			   const uint8_t *cookie, uint8_t cookie_len)
{
  const uint8_t ip_src[4] = {192, 0, 2, 1};
  const uint8_t ip_dst[4] = {192, 0, 2, 2};
  int i;

  if(SCAMPER_DL_IS_IPV4(dl) == 0 ||
     SCAMPER_DL_IS_IP_DF(dl) == 0 ||
     dl->dl_ip_hl != 20 || dl->dl_ip_datalen != ip_datalen ||
     dl->dl_ip_size != ip_size ||
     dl->dl_ip_id != 0 || dl->dl_ip_off != 0 || dl->dl_ip_ttl != 246 ||
     SCAMPER_DL_IS_TCP_SYNACK(dl) == 0 ||
     dl->dl_ip_data != pkt + 20 ||
     dl->dl_tcp_sport != 80 || dl->dl_tcp_dport != 41715 ||
     dl->dl_tcp_datalen != 0 || dl->dl_tcp_data != NULL ||
     dl->dl_tcp_seq != 0xCD2552F8U || dl->dl_tcp_ack != 0x77AEC23EU ||
     dl->dl_tcp_win != 0xF507U || dl->dl_tcp_hl != tcp_hl ||
     (dl->dl_tcp_opts & SCAMPER_DL_TCP_OPT_FO) == 0 ||
     dl->dl_tcp_fo_cookielen != cookie_len)
    return -1;

  for(i=0; i<cookie_len; i++)
    if(dl->dl_tcp_fo_cookie[i] != cookie[i])
      return -1;
  for(i=0; i<4; i++)
    if(dl->dl_ip_src[i] != ip_src[i] || dl->dl_ip_dst[i] != ip_dst[i])
      return -1;

  return 0;
}

static int tcp_cookie_24(uint8_t *pkt, size_t len)
{
  const uint8_t cookie[] =
    {0x11, 0x60, 0x8B, 0x62, 0x08, 0x51, 0x31, 0x60,
     0xD5, 0x01, 0xB3, 0xCE, 0x21, 0x60, 0x84, 0x70,
     0x3B, 0xC1, 0x21, 0x60, 0x84, 0x70, 0x3B, 0xC1};
  scamper_dl_rec_t dl;

  assert(sizeof(cookie) == 24);

  memset(&dl, 0, sizeof(dl));
  if(dl_parse_ip(&dl, pkt, len) == 0 ||
     tcp_cookie_base(&dl, pkt, 48, 68, 12 * 4, cookie, 24) != 0)
    return -1;

  return 0;
}

static int tcp_cookie_38(uint8_t *pkt, size_t len)
{
  const uint8_t cookie[] =
    {0x11, 0x60, 0x8B, 0x62, 0x08, 0x51, 0x31, 0x60,
     0xD5, 0x01, 0xB3, 0xCE, 0x21, 0x60, 0x84, 0x70,
     0x3B, 0xC1, 0x21, 0x60, 0x84, 0x70, 0x3B, 0xC1,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x69,
    };
  scamper_dl_rec_t dl;

  assert(sizeof(cookie) == 38);

  memset(&dl, 0, sizeof(dl));
  if(dl_parse_ip(&dl, pkt, len) == 0 ||
     tcp_cookie_base(&dl, pkt, 60, 80, 15 * 4, cookie, 38) != 0)
    return -1;

  return 0;
}

static int tcp_cookie_bad(uint8_t *pkt, size_t len)
{
  scamper_dl_rec_t dl;

  /* a malformed TCP fast open cookie should not show up in here */
  memset(&dl, 0, sizeof(dl));
  if(dl_parse_ip(&dl, pkt, len) == 0 ||
     SCAMPER_DL_IS_TCP_SYNACK(&dl) == 0 ||
     (dl.dl_tcp_opts & SCAMPER_DL_TCP_OPT_FO) != 0 ||
     dl.dl_tcp_fo_cookielen != 0)
    return -1;

  return 0;
}

static int icmp_echo_req(uint8_t *pkt, size_t len)
{
  scamper_dl_rec_t dl;

  memset(&dl, 0, sizeof(dl));
  if(dl_parse_ip(&dl, pkt, len) == 0 ||
     SCAMPER_DL_IS_IPV4(&dl) == 0 ||
     SCAMPER_DL_IS_ICMP_ECHO_REQUEST(&dl) == 0 ||
     dl.dl_icmp_id != 1 || dl.dl_icmp_seq != 1 ||
     dl.dl_ip_size != 84 || dl.dl_ip_data != pkt + 20)
    return -1;

  return 0;
}

static int icmp6_nadv(uint8_t *pkt, size_t len)
{
  scamper_dl_rec_t dl;
  uint8_t target[] = {
    0x24, 0x07, 0x70, 0x00, 0x90, 0x00, 0xee, 0x02,
    0xde, 0xa6, 0x32, 0xff, 0xfe, 0x05, 0x77, 0x87};
  uint8_t mac[] = {0xdc, 0xa6, 0x32, 0x05, 0x77, 0x87};

  memset(&dl, 0, sizeof(dl));
  if(dl_parse_ip(&dl, pkt, len) == 0 ||
     SCAMPER_DL_IS_ICMP6_ND_NADV(&dl) == 0 ||
     dl.dl_ip_hl != 40 || dl.dl_ip_data != pkt + 40 ||
     dl.dl_ip_size != 40 + 32 || dl.dl_ip_datalen != len - 40 ||
     dl.dl_ip_ttl != 255 ||
     memcmp(dl.dl_icmp6_nd_target, target, sizeof(target)) != 0 ||
     dl.dl_icmp6_nd_opts_len != 8 ||
     dl.dl_icmp6_nd_opts[0] != 2 || dl.dl_icmp6_nd_opts[1] != 1 ||
     memcmp(dl.dl_icmp6_nd_opts+2, mac, sizeof(mac)) != 0)
    return -1;

  return 0;
}

static int icmp6_echo_req(uint8_t *pkt, size_t len)
{
  scamper_dl_rec_t dl;

  memset(&dl, 0, sizeof(dl));
  if(dl_parse_ip(&dl, pkt, len) == 0 ||
     SCAMPER_DL_IS_IPV6(&dl) == 0 ||
     dl.dl_ip_hl != 40 || dl.dl_ip_data != pkt + 40 ||
     dl.dl_ip_size != 104 || dl.dl_ip_datalen != len - 40 ||
     dl.dl_ip_ttl != 64 ||
     SCAMPER_DL_IS_ICMP_ECHO_REPLY(&dl) == 0 ||
     dl.dl_icmp_id != 3 || dl.dl_icmp_seq != 1)
    return -1;

  return 0;
}

static int check(const char *pkt, int (*func)(uint8_t *pkt, size_t len))
{
  size_t len;
  uint8_t *buf = NULL;
  int rc = -1;

  if(hex2buf(pkt, &buf, &len) != 0)
    goto done;

  rc = func(buf, len);

 done:
  if(buf != NULL) free(buf);
  return rc;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {"4500004400004000f606c5ebc0000201c0000202"
     "0050a2f3cd2552f877aec23ec012f5074a150000"
     "221a11608b6208513160d501b3ce216084703bc1216084703bc10000",
     tcp_cookie_24},
    {"4500005000004000f606c5ebc0000201c0000202"
     "0050a2f3cd2552f877aec23ef012f5074a150000"
     "222811608b6208513160d501b3ce216084703bc1"
     "216084703bc10000000000000000000000000069",
     tcp_cookie_38},
    {"4500005000004000f606c5ebc0000201c0000202"
     "0050a2f3cd2552f877aec23ef012f5074a150000"
     "222a11608b6208513160d501b3ce216084703bc1"
     "216084703bc10000000000000000000000000069",
     tcp_cookie_bad},
    {"45000054cb63400040019b71c0a8031c08080808"
     "08008d2b00010001"
     "fa132a65000000007e8609000000000010111213"
     "1415161718191a1b1c1d1e1f2021222324252627"
     "28292a2b2c2d2e2f3031323334353637",
     icmp_echo_req},
    {"6000000000203aff"
     "240770009000ee02dea632fffe057787"         /* IPv6 src */
     "240770009000ee025656e3476f276a2b"         /* IPv6 dst */
     "880037f760000000"                         /* ICMP6 hdr */
     "240770009000ee02dea632fffe057787"         /* target */
     "0201dca632057787",                        /* options */
     icmp6_nadv},
    {"6000000000403a40"
     "240770009000ee02dea632fffe057787"
     "240770009000ee025656e3476f276a2b"
     "8100a4c700030001"
     "51d52a6500000000da71060000000000"
     "101112131415161718191a1b1c1d1e1f"
     "202122232425262728292a2b2c2d2e2f"
     "3031323334353637",
     icmp6_echo_req},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];

  /* dump packets if requested */
  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/pkt-%03x.dat", argv[2], (int)i);
	  if(dump_hex(tests[i].pkt, filename) != 0)
	    break;
	}
    }
  else if(argc == 1)
    {
      for(i=0; i<testc; i++)
	if(check(tests[i].pkt, tests[i].func) != 0)
	  break;
    }
  else
    {
      printf("invalid usage\n");
      return -1;
    }

  if(i != testc)
    {
      printf("test %d failed\n", (int)i);
      return -1;
    }

  printf("OK\n");
  return 0;
}
