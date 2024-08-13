/*
 * unit_dl_filter_compile : unit tests for BPF compiler
 *
 * $Id: unit_dl_filter_compile.c,v 1.5 2024/08/13 06:42:20 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024 Matthew Luckie
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

#include "scamper_dl.h"
#include "utils.h"
#include "common.h"

#ifdef HAVE_BPF
typedef struct bpf_insn    filt_insn_t;
typedef struct bpf_program filt_prog_t;
#endif

#ifdef __linux__
typedef struct sock_filter filt_insn_t;
typedef struct sock_fprog  filt_prog_t;
#endif

typedef struct sc_header
{
  uint8_t     rx_type;
  const char *v4;
  const char *v6;
} sc_header_t;

typedef struct sc_packet
{
  const char *str;
  uint8_t     ipv;   /* IPv4 or IPv6, or arp (0) */
  uint16_t    proto; /* ICMP, UDP, TCP */
  uint16_t    port;  /* port that would be matched */
} sc_packet_t;

typedef struct sc_test
{
  size_t   portc;
  uint16_t ports[10];
} sc_test_t;

int dl_filter_compile(uint8_t rx_type, filt_prog_t *prog,
		      const uint16_t *ports, size_t portc);

static int bpf_check(const filt_prog_t *prog, uint8_t *pkt, uint32_t len,
		     uint32_t *out)
{
  uint32_t acc = 0, idx = 0;
  size_t i;
  filt_insn_t *insn;

#if defined(HAVE_BPF)
  size_t prog_len = prog->bf_len;
#else
  size_t prog_len = prog->len;
#endif

  for(i=0; i<prog_len; i++)
    {
#if defined(HAVE_BPF)
      insn = &prog->bf_insns[i];
#else
      insn = &prog->filter[i];
#endif
      if(insn->code == BPF_LD+BPF_ABS+BPF_W)
	{
	  if(insn->k > len || len - insn->k < 4)
	    return -1;
	  acc = bytes_ntohl(pkt + insn->k);
	}
      else if(insn->code == BPF_LD+BPF_ABS+BPF_H)
	{
	  if(insn->k > len || len - insn->k < 2)
	    return -1;
	  acc = bytes_ntohs(pkt + insn->k);
	}
      else if(insn->code == BPF_LD+BPF_ABS+BPF_B)
	{
	  if(insn->k >= len)
	    return -1;
	  acc = pkt[insn->k];
	}
      else if(insn->code == BPF_LDX+BPF_MSH+BPF_B)
	{
	  if(insn->k >= len)
	    return -1;
	  idx = (pkt[insn->k] & 0xf) << 2;
	}
      else if(insn->code == BPF_LD+BPF_IND+BPF_H)
	{
	  if(idx >= len || len - idx < insn->k || len - idx - insn->k < 2)
	    return -1;
	  acc = bytes_ntohs(pkt + idx + insn->k);
	}
      else if(insn->code == BPF_JMP+BPF_JEQ+BPF_K)
	{
	  if(acc == insn->k)
	    i += insn->jt;
	  else
	    i += insn->jf;
	}
      else if(insn->code == BPF_JMP+BPF_JSET+BPF_K)
	{
	  if((acc & insn->k) != 0)
	    i += insn->jt;
	  else
	    i += insn->jf;
	}
      else if(insn->code == BPF_ALU+BPF_RSH+BPF_K)
	{
	  acc = (acc >> insn->k);
	}
      else if(insn->code == BPF_RET+BPF_K)
	{
	  *out = insn->k;
	  return 0;
	}
      else break;
    }

  return -1;
}

#ifdef HAVE_BPF
static void prog_free(struct bpf_program *prog)
{
  if(prog->bf_insns != NULL)
    free(prog->bf_insns);
  return;
}
#else
static void prog_free(struct sock_fprog *prog)
{
  if(prog->filter != NULL)
    free(prog->filter);
  return;
}
#endif

static int make_packet(const char *hdr_str, const char *pld_str,
		       uint8_t **pkt, size_t *len)
{
  uint8_t *hdr_pkt = NULL, *pld_pkt = NULL;
  size_t hdr_len = 0, pld_len = 0;
  int rc = -1;

  if(hex2buf(hdr_str, &hdr_pkt, &hdr_len) != 0 ||
     hex2buf(pld_str, &pld_pkt, &pld_len) != 0 ||
     pld_len == 0)
    goto done;

  if((*len = hdr_len + pld_len) == 0)
    {
      *pkt = NULL;
      return 0;
    }

  if((*pkt = malloc(*len)) == NULL)
    goto done;

  if(hdr_len > 0)
    memcpy(*pkt, hdr_pkt, hdr_len);
  memcpy((*pkt) + hdr_len, pld_pkt, pld_len);
  rc = 0;

 done:
  if(hdr_pkt != NULL) free(hdr_pkt);
  if(pld_pkt != NULL) free(pld_pkt);
  return rc;
}

static int match_port(uint16_t port, const uint16_t *ports, uint16_t portc)
{
  uint16_t i;
  for(i=0; i<portc; i++)
    if(port == ports[i])
      return 1;
  return 0;
}

static int check(sc_test_t *test, int id, sc_header_t *hdr,
		 sc_packet_t *pkts, size_t pktc)
{
  const uint16_t *udp4_ports; uint16_t udp4_portc;
  const uint16_t *tcp4_ports; uint16_t tcp4_portc;
  const uint16_t *udp6_ports; uint16_t udp6_portc;
  const uint16_t *tcp6_ports; uint16_t tcp6_portc;
  filt_prog_t prog;
  uint8_t *pkt = NULL;
  uint32_t retk;
  size_t i, len;
  int rc = -1;
  int x, matched;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

  memset(&prog, 0, sizeof(prog));
  if(dl_filter_compile(hdr->rx_type, &prog, test->ports, test->portc) != 0)
    {
      fprintf(stderr, "filter %d did not compile\n", id);
      goto done;
    }

  udp4_portc = test->ports[0]; udp4_ports = test->ports + 4;
  tcp4_portc = test->ports[1]; tcp4_ports = udp4_ports + udp4_portc;
  udp6_portc = test->ports[2]; udp6_ports = tcp4_ports + tcp4_portc;
  tcp6_portc = test->ports[3]; tcp6_ports = udp6_ports + udp6_portc;

  for(i=0; i<pktc; i++)
    {
      if(make_packet(pkts[i].ipv == 4 ? hdr->v4 : hdr->v6,
		     pkts[i].str, &pkt, &len) != 0)
	{
	  fprintf(stderr, "could not make packet %d\n", (int)i);
	  goto done;
	}
      retk = 1;
      x = bpf_check(&prog, pkt, len, &retk);
      free(pkt); pkt = NULL;
      if(x != 0 || retk == 1)
	{
	  fprintf(stderr, "filter %d packet %d failed: %d %d\n",
		  id, (int)i, x, retk);
	  goto done;
	}

      /* all ICMP packets should match */
      if((pkts[i].ipv == 4 && pkts[i].proto == IPPROTO_ICMP) ||
	 (pkts[i].ipv == 6 && pkts[i].proto == IPPROTO_ICMPV6))
	{
	  if(retk == 0)
	    {
	      fprintf(stderr, "filter %d packet %d didn't pick up ICMP\n",
		      id, (int)i);
	      goto done;
	    }
	  continue;
	}

      if(pkts[i].ipv == 4 && pkts[i].proto == IPPROTO_UDP)
	matched = match_port(pkts[i].port, udp4_ports, udp4_portc);
      else if(pkts[i].ipv == 4 && pkts[i].proto == IPPROTO_TCP)
	matched = match_port(pkts[i].port, tcp4_ports, tcp4_portc);
      else if(pkts[i].ipv == 6 && pkts[i].proto == IPPROTO_UDP)
	matched = match_port(pkts[i].port, udp6_ports, udp6_portc);
      else if(pkts[i].ipv == 6 && pkts[i].proto == IPPROTO_TCP)
	matched = match_port(pkts[i].port, tcp6_ports, tcp6_portc);
      else
	{
	  fprintf(stderr, "filter %d packet %d unmatched %d %d\n",
		  id, (int)i, pkts[i].ipv, pkts[i].proto);
	  goto done;
	}

      /* matched and retk should agree */
      if((matched == 0 && retk != 0) || (matched != 0 && retk == 0))
	{
	  fprintf(stderr, "filter %d packet %d matched %d retk %d\n",
		  id, (int)i, matched, retk);
	  goto done;
	}
    }

  rc = 0;

 done:
  if(pkt != NULL) free(pkt);
  prog_free(&prog);

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(start_mem != stop_mem && rc == 0)
    {
      printf("memory leak: test %d\n", (int)i);
      rc = -1;
    }
#endif

  return rc;
}

int main(int argc, char *argv[])
{
  char pf4[9], pf6[9];
  sc_header_t hdrs[] = {
    {SCAMPER_DL_RX_RAW,  "", ""},
    {SCAMPER_DL_RX_NULL, pf4, pf6},
    {SCAMPER_DL_RX_ETHERNET,
     "b827eb642c4fdca6321c360d0800", "b827eb642c4fdca6321c360d86dd"},
  };
  sc_packet_t packets[] = {
    /* 0: ICMPv4 */
    {"4500001c00004000400100007f0000017f0000010000cfae304e0003",
     4, IPPROTO_ICMP, 0},
    /* 1: ICMPv6 */
    {"6000000000083a40"
     "00000000000000000000000000000001"
     "00000000000000000000000000000001"
     "81004e2f30890003",
     6, IPPROTO_ICMPV6, 0},
    /* 2, 3: IPv4 UDP out and back to 33435 */
    {"4500001c486f4000401100007f0000017f000001"
     "b097829b0008cea8",
     4, IPPROTO_UDP, 33435},
    {"4500001c486f4000401100007f0000017f000001"
     "829bb0970008cea8",
     4, IPPROTO_UDP, 33435},
    /* 4, 5: IPv4 TCP 443, SYN (out) and RST (back) */
    {"45000028b63d4000400600007f0000017f000001"
     "b0c101bbf2d320b7000000005002ffffebd80000",
     4, IPPROTO_TCP, 443},
    {"4500002800004000400600007f0000017f000001"
     "01bbb0c100000000f2d320b850140000fe1c0000",
     4, IPPROTO_TCP, 443},
    /* 6, 7: IPv4 TCP 8443, SYN (out) and RST (back) */
    {"45000028af724000400600007f0000017f000001"
     "b0f520fb7c38c8e0000000005002ffff9ad60000",
     4, IPPROTO_TCP, 8443},
    {"4500002800004000400600007f0000017f000001"
     "20fbb0f5000000007c38c8e150140000fe1c0000",
     4, IPPROTO_TCP, 8443},
    /* 8, 9: IPv6 UDP out and back to 33435 */
    {"6004000000081140"
     "00000000000000000000000000000001"
     "00000000000000000000000000000001"
     "ab21829b0008001b",
     6, IPPROTO_UDP, 33435},
    {"6004000000081140"
     "00000000000000000000000000000001"
     "00000000000000000000000000000001"
     "829bab210008001b",
     6, IPPROTO_UDP, 33435},
    /* 10, 11: IPv6 TCP, SYN (out) and RST (back) */
    {"6000000000140640"
     "00000000000000000000000000000001"
     "00000000000000000000000000000001"
     "95c501bb615e5d9d000000005002ffff59650000",
     6, IPPROTO_TCP, 443},
    {"6006ccab00140640"
     "00000000000000000000000000000001"
     "00000000000000000000000000000001"
     "01bb95c500000000615e5d9e50140000001c0000",
     6, IPPROTO_TCP, 443},
    /* 12, 13: IPv6 TCP 8443, SYN (out) and RST (back) */
    {"6000000000140640"
     "00000000000000000000000000000001"
     "00000000000000000000000000000001"
     "97fb20fb175cdba3000000005002ffff03eb0000",
     6, IPPROTO_TCP, 8443},
    {"6004ab3c00140640"
     "00000000000000000000000000000001"
     "00000000000000000000000000000001"
     "20fb97fb00000000175cdba450140000001c0000",
     6, IPPROTO_TCP, 8443},
  };
  /* udp4, tcp4, udp6, tcp6 */
  sc_test_t tests[] = {
    /* 0: ICMPv4, ICMPv6 */
    {4, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
    /* 1: udp4 33435 */
    {5, {1, 0, 0, 0, 33435, 0, 0, 0, 0, 0}},
    /* 2: udp4 33434 */
    {5, {1, 0, 0, 0, 33434, 0, 0, 0, 0, 0}},
    /* 3: udp4 33535, 33434 */
    {6, {2, 0, 0, 0, 33435, 33434, 0, 0, 0, 0}},
    /* 4: udp4 33534, 33435 */
    {6, {2, 0, 0, 0, 33434, 33435, 0, 0, 0, 0}},
    /* 5: udp4 33435, tcp4 8443 */
    {6, {1, 1, 0, 0, 33435, 8443, 0, 0, 0, 0}},
    /* 6: udp4 33434, tcp4 8443 */
    {6, {1, 1, 0, 0, 33434, 8443, 0, 0, 0, 0}},
    /* 7: udp4 33435, tcp4 8443, tcp4 443 */
    {7, {1, 2, 0, 0, 33435, 8443, 443, 0, 0, 0}},
    /* 8: udp4 33435, tcp4 443, tcp4 8443 */
    {7, {1, 2, 0, 0, 33434, 443, 8443, 0, 0, 0}},
    /* 9: udp4 33435, tcp4 444, tcp4 8444 */
    {7, {1, 2, 0, 0, 33434, 444, 8444, 0, 0, 0}},
    /* 10: udp6 33435 */
    {5, {0, 0, 1, 0, 33435, 0, 0, 0, 0, 0}},
    /* 11: udp6 33434 */
    {5, {0, 0, 1, 0, 33434, 0, 0, 0, 0, 0}},
    /* 12: udp6 33535, 33434 */
    {6, {0, 0, 2, 0, 33435, 33434, 0, 0, 0, 0}},
    /* 13: udp6 33534, 33435 */
    {6, {0, 0, 2, 0, 33434, 33435, 0, 0, 0, 0}},
    /* 14: udp6 33435, tcp6 8443 */
    {6, {0, 0, 1, 1, 33435, 8443, 0, 0, 0, 0}},
    /* 15: udp6 33434, tcp6 8443 */
    {6, {0, 0, 1, 1, 33434, 8443, 0, 0, 0, 0}},
    /* 16: udp6 33435, tcp6 8443, tcp6 443 */
    {7, {0, 0, 1, 2, 33435, 8443, 443, 0, 0, 0}},
    /* 17: udp6 33435, tcp6 443, tcp6 8443 */
    {7, {0, 0, 1, 2, 33434, 443, 8443, 0, 0, 0}},
    /* 18: udp6 33435, tcp6 444, tcp6 8444 */
    {7, {0, 0, 1, 2, 33434, 444, 8444, 0, 0, 0}},
    /* 19: udp4 33435, tcp4 443, udp6 33435, tcp6 8443 */
    {8, {1, 1, 1, 1, 33435, 443, 33435, 8443, 0, 0}},
    /* 20: udp4 33435, tcp4 443, tcp4 8443, udp6 33435, tcp6 8443, tcp6 443 */
    {10, {1, 2, 1, 2, 33435, 443, 8443, 33435, 8443, 443}},
  };
  size_t packetc = sizeof(packets) / sizeof(sc_packet_t);
  size_t testc = sizeof(tests) / sizeof(sc_test_t);
  size_t hdrc = sizeof(hdrs) / sizeof(sc_header_t);
  size_t i, j;

  snprintf(pf4, sizeof(pf4), "%08x", htonl(PF_INET));
  snprintf(pf6, sizeof(pf6), "%08x", htonl(PF_INET6));

  for(i=0; i<testc; i++)
    {
      for(j=0; j<hdrc; j++)
	{
	  if(check(&tests[i], (int)i, &hdrs[j], packets, packetc) != 0)
	    {
	      printf("test %d failed\n", (int)i);
	      return -1;
	    }
	}
    }

  printf("OK\n");
  return 0;
}
