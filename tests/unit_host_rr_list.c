/*
 * unit_host_rr_list : unit tests for host_rr_list function
 *
 * $Id: unit_host_rr_list.c,v 1.8 2025/02/26 04:10:35 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2023-2025 Matthew Luckie
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

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_host.h"
#include "scamper_host_int.h"

#include "utils.h"
#include "mjl_list.h"

#include "common.h"

/* function prototype of a normally static function */
slist_t *host_rr_list(const uint8_t *buf, size_t off, size_t len);

typedef struct sc_test
{
  char   *pkt;
  size_t  off;
  int    (*func)(const slist_t *rr_list);
} sc_test_t;

static int com_soa(const slist_t *rr_list)
{
  const uint16_t types[2] = {
    SCAMPER_HOST_RR_DATA_TYPE_SOA,
    SCAMPER_HOST_RR_DATA_TYPE_OPT};
  scamper_host_rr_t *rr;
  scamper_host_rr_soa_t *soa;
  slist_node_t *sn;
  const char *str;
  int i = 0;

  if(rr_list == NULL)
    return -1;
  for(sn=slist_head_node(rr_list); sn != NULL; sn=slist_node_next(sn))
    {
      if(i >= 2)
	return -1;

      rr = slist_node_item(sn);
      if(scamper_host_rr_data_type(rr->class, rr->type) != types[i])
	return -1;

      if(i == 0)
	{
	  if(rr->class != SCAMPER_HOST_CLASS_IN ||
	     rr->type != SCAMPER_HOST_TYPE_SOA ||
	     rr->ttl != 509 ||
	     strcmp(rr->name, "com") != 0 ||
	     (soa = scamper_host_rr_soa_get(rr)) == NULL ||
	     (str = scamper_host_rr_soa_mname_get(soa)) == NULL ||
	     strcmp(str, "a.gtld-servers.net") != 0 ||
	     (str = scamper_host_rr_soa_rname_get(soa)) == NULL ||
	     strcmp(str, "nstld.verisign-grs.com") != 0 ||
	     scamper_host_rr_soa_serial_get(soa) != 1699073504 ||
	     scamper_host_rr_soa_refresh_get(soa) != 1800 ||
	     scamper_host_rr_soa_retry_get(soa) != 900 ||
	     scamper_host_rr_soa_expire_get(soa) != 604800 ||
	     scamper_host_rr_soa_minimum_get(soa) != 86400)
	    return -1;
	}
      else if(i == 1)
	{
	  if(rr->type != SCAMPER_HOST_TYPE_OPT ||
	     rr->class != 4096 ||
	     rr->ttl != 0 ||
	     strcmp(rr->name, "") != 0)
	    return -1;
	}
      else return -1;
      i++;
    }
  return 0;
}

static int example_org_txt(const slist_t *rr_list)
{
  const uint16_t types[3] = {
    SCAMPER_HOST_RR_DATA_TYPE_TXT,
    SCAMPER_HOST_RR_DATA_TYPE_TXT,
    SCAMPER_HOST_RR_DATA_TYPE_OPT};
  scamper_host_rr_t *rr;
  scamper_host_rr_txt_t *txt;
  slist_node_t *sn;
  const char *str;
  int i = 0;

  if(rr_list == NULL)
    return -1;
  for(sn=slist_head_node(rr_list); sn != NULL; sn=slist_node_next(sn))
    {
      if(i >= 3)
	return -1;

      rr = slist_node_item(sn);
      if(scamper_host_rr_data_type(rr->class, rr->type) != types[i])
	return -1;

      if(i == 0)
	{
	  if(rr->class != SCAMPER_HOST_CLASS_IN ||
	     rr->type != SCAMPER_HOST_TYPE_TXT ||
	     rr->ttl != 86368 ||
	     strcmp(rr->name, "example.org") != 0 ||
	     (txt = scamper_host_rr_txt_get(rr)) == NULL ||
	     scamper_host_rr_txt_strc_get(txt) != 1 ||
	     (str = scamper_host_rr_txt_str_get(txt, 0)) == NULL ||
	     strcmp(str, "v=spf1 -all") != 0)
	    return -1;
	}
      else if(i == 1)
	{
	  if(rr->class != SCAMPER_HOST_CLASS_IN ||
	     rr->type != SCAMPER_HOST_TYPE_TXT ||
	     rr->ttl != 86368 ||
	     strcmp(rr->name, "example.org") != 0 ||
	     (txt = scamper_host_rr_txt_get(rr)) == NULL ||
	     scamper_host_rr_txt_strc_get(txt) != 1 ||
	     (str = scamper_host_rr_txt_str_get(txt, 0)) == NULL ||
	     strcmp(str, "6r4wtj10lt2hw0zhyhk7cgzzffhjp7fl") != 0)
	    return -1;
	}
      else if(i == 2)
	{
	  if(rr->type != SCAMPER_HOST_TYPE_OPT ||
	     rr->class != 1232 ||
	     rr->ttl != 0 ||
	     strcmp(rr->name, "") != 0)
	    return -1;
	}
      else return -1;
      i++;
    }
  return 0;
}

static int doesnotexist_nsid(const slist_t *rr_list)
{
  const uint8_t nsid[14] = {
    0x61, 0x38, 0x2e, 0x75, 0x73, 0x2d, 0x73, 0x6a, 0x63,
    0x2e, 0x72, 0x6f, 0x6f, 0x74};
  const uint16_t types[2] = {
    SCAMPER_HOST_RR_DATA_TYPE_SOA,
    SCAMPER_HOST_RR_DATA_TYPE_OPT};
  scamper_host_rr_t *rr;
  scamper_host_rr_opt_t *opt;
  scamper_host_rr_opt_elem_t *elem;
  slist_node_t *sn;
  int i = 0;

  if(rr_list == NULL)
    return -1;

  for(sn=slist_head_node(rr_list); sn != NULL; sn=slist_node_next(sn))
    {
      if(i >= 2)
	return -1;

      rr = slist_node_item(sn);
      if(scamper_host_rr_data_type(rr->class, rr->type) != types[i])
	return -1;

      if(i == 0)
	{
	  if(rr->class != SCAMPER_HOST_CLASS_IN ||
	     rr->type != SCAMPER_HOST_TYPE_SOA ||
	     rr->ttl != 86400 ||
	     strcmp(rr->name, "") != 0)
	    return -1;
	}
      else if(i == 1)
	{
	  if(rr->class != 4096 ||
	     rr->type != SCAMPER_HOST_TYPE_OPT ||
	     rr->ttl != 0 ||
	     strcmp(rr->name, "") != 0 ||
	     (opt = scamper_host_rr_opt_get(rr)) == NULL ||
	     scamper_host_rr_opt_elemc_get(opt) != 1 ||
	     (elem = scamper_host_rr_opt_elem_get(opt, 0)) == NULL ||
	     elem->code != SCAMPER_HOST_RR_OPT_ELEM_CODE_NSID ||
	     elem->len != 14 ||
	     memcmp(elem->data, nsid, 14) != 0)
	    return -1;
	}
      else return -1;
      i++;
    }

  return 0;
}

static int dns_resolver_arpa_svcb(const slist_t *rr_list)
{
  const uint16_t types[5] = {
    SCAMPER_HOST_RR_DATA_TYPE_SVCB,
    SCAMPER_HOST_RR_DATA_TYPE_SVCB,
    SCAMPER_HOST_RR_DATA_TYPE_ADDR,
    SCAMPER_HOST_RR_DATA_TYPE_ADDR,
    SCAMPER_HOST_RR_DATA_TYPE_ADDR,
  };
  const uint16_t keys[9] = {1, 3, 4, 6,  1, 3, 4,  6,  7};
  const uint16_t lens[9] = {4, 2, 8, 16, 3, 2, 8, 16, 16};
  const char *addrs[3] = {"9.9.9.9", "149.112.112.112", "2620:fe::fe"};
  const uint8_t vals[9][16] = {
    {3, 'd', 'o', 't'},
    {0x03, 0x55},  /* 853 */
    {9, 9, 9, 9, 149, 112, 112, 112},
    {0x26, 0x20, 0, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe},
    {2, 'h', '2'},
    {0x01, 0xBB},  /* 443 */
    {9, 9, 9, 9, 149, 112, 112, 112},
    {0x26, 0x20, 0, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe},
    {'/','d','n','s','-','q','u','e','r','y','{','?','d','n','s', '}'}
  };
  const uint8_t *val;
  scamper_host_rr_t *rr;
  scamper_host_rr_svcb_t *svcb;
  scamper_host_rr_svcb_param_t *param;
  slist_node_t *sn;
  const char *name;
  uint16_t j, x = 0;
  int i = 0;

  if(rr_list == NULL)
    return -1;

  for(sn=slist_head_node(rr_list); sn != NULL; sn=slist_node_next(sn))
    {
      if(i >= 5)
	return -1;

      rr = slist_node_item(sn);
      if(scamper_host_rr_data_type(rr->class, rr->type) != types[i] ||
	 rr->class != SCAMPER_HOST_CLASS_IN || rr->ttl != 60)
	return -1;

      if(i == 0 || i == 1)
	{
	  if(rr->type != SCAMPER_HOST_TYPE_SVCB ||
	     (name = scamper_host_rr_name_get(rr)) == NULL ||
	     strcmp(name, "_dns.resolver.arpa") != 0 ||
	     (svcb = scamper_host_rr_svcb_get(rr)) == NULL ||
	     scamper_host_rr_svcb_priority_get(svcb) != (uint16_t)(i + 1) ||
	     (name = scamper_host_rr_svcb_target_get(svcb)) == NULL ||
	     strcmp(name, "dns.quad9.net") != 0 ||
	     scamper_host_rr_svcb_paramc_get(svcb) != (i + 4))
	    return -1;

	  for(j=0; j < i + 4; j++)
	    {
	      if((param = scamper_host_rr_svcb_param_get(svcb, j)) == NULL ||
		 scamper_host_rr_svcb_param_key_get(param) != keys[x] ||
		 scamper_host_rr_svcb_param_len_get(param) != lens[x] ||
		 (val = scamper_host_rr_svcb_param_val_get(param)) == NULL ||
		 memcmp(vals[x], val, lens[x]) != 0)
		return -1;
	      x++;
	    }
	}
      else if(i == 2 || i == 3 || i == 4)
	{
	  if((i == 2 && rr->type != SCAMPER_HOST_TYPE_A) ||
	     (i == 3 && rr->type != SCAMPER_HOST_TYPE_A) ||
	     (i == 4 && rr->type != SCAMPER_HOST_TYPE_AAAA) ||
	     (name = scamper_host_rr_name_get(rr)) == NULL ||
	     strcmp(name, "dns.quad9.net") != 0 ||
	     check_addr(scamper_host_rr_addr_get(rr), addrs[i-2]) != 0)
	    return -1;
	}

      i++;
    }

  return 0;
}

static int make_buf(const char *pkt, uint8_t **buf_out, size_t *len_out)
{
  size_t len = strlen(pkt);
  size_t i, off = 0;
  uint8_t *buf = NULL;
  int rc = -1;

  if((len % 2) != 0 || len == 0 || (buf = malloc(len / 2)) == NULL)
    goto done;

  for(i=0; i<len; i+=2)
    {
      if(ishex(pkt[i]) == 0 || ishex(pkt[i+1]) == 0)
	goto done;
      buf[off++] = hex2byte(pkt[i], pkt[i+1]);
    }

  *buf_out = buf; buf = NULL;
  *len_out = off;
  rc = 0;

 done:
  if(buf != NULL) free(buf);
  return rc;
}

static int check(const char *pkt, size_t off, int (*func)(const slist_t *list))
{
  uint8_t *buf = NULL;
  slist_t *rr_list = NULL;
  size_t len;
  int rc;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

  if(make_buf(pkt, &buf, &len) != 0)
    return -1;
  rr_list = host_rr_list(buf, off, len);
  rc = func(rr_list);
  if(buf != NULL) free(buf);
  if(rr_list != NULL)
    slist_free_cb(rr_list, (slist_free_t)scamper_host_rr_free);

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(start_mem != stop_mem && rc == 0)
    {
      printf("memory leak: %s\n", pkt);
      rc = -1;
    }
#endif

  return rc;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {"c72381800001000100000001" /* 12 byte header */
     "03636f6d00" /* com (5 bytes)*/
     "00060001" /* SOA IN (4 bytes) */
     "c00c00060001000001fd003d01610c6774"
     "6c642d73657276657273036e657400056e73746c640c76657269"
     "7369676e2d677273c00c6545cde0000007080000038400093a80"
     "00015180"
     "0000291000000000000000", /* . OPT 4096 ttl=0, rdlength=0 */
     12 + 5 + 4,
     com_soa},
    {"f0d781a00001000200000001" /* 12 byte header */
     "076578616d706c65036f726700" /* example.org (13 bytes) */
     "00100001" /* TXT IN (4 bytes) */
     "c00c0010000100015160"
     "000c0b763d73706631202d616c6c" /* v=spf1 -all */
     "c00c0010000100015160"
     "00212036723477746a31306c74326877" /* 6r4wtj10lt2hw0zhyhk7cgzzffhjp7fl */
     "307a6879686b3763677a7a6666686a7037666c"
     "00002904d0000000000000", /* . OPT 1232 ttl=0, rdlength=0 */
     12 + 13 + 4,
     example_org_txt},
    {"dc2f85030001000000010001" /* 12 byte header */
     "0e646f65732d6e6f742d657869737400" /* does-not-exist (16 bytes) */
     "00010001" /* A IN (4 bytes) */
     "000006000100015180004001610c726f6f742d73657276657273036e657400056e73"
     "746c640c766572697369676e2d67727303636f6d0078a52a5900000708000003"
     "8400093a8000015180"
     "00002910000000000000120003000e61382e75732d736a632e726f6f74",
     12 + 16 + 4,
     doesnotexist_nsid},
    {"79e581000001000200000003" /* 12 byte header */
     "045f646e73087265736f6c766572046172706100" /* _dns.resolver.arpa (20b) */
     "00400001" /* SVCB IN (4 bytes) */
     "c00c004000010000003c003f00010364"
     "6e73057175616439036e657400000100"
     "0403646f740003000203550004000809"
     "0909099570707000060010262000fe00"
     "00000000000000000000fec00c004000"
     "010000003c0052000203646e73057175"
     "616439036e6574000001000302683200"
     "03000201bb0004000809090909957070"
     "7000060010262000fe00000000000000"
     "00000000fe000700102f646e732d7175"
     "6572797b3f646e737d03646e73057175"
     "616439036e657400000100010000003c"
     "000409090909c0cd000100010000003c"
     "000495707070c0cd001c00010000003c"
     "0010262000fe00000000000000000000"
     "00fe",
     12 + 20 + 4,
     dns_resolver_arpa_svcb},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];

  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/rrset-%03x.dat", argv[2], (int)i);
	  if(dump_hex(tests[i].pkt, filename) != 0)
	    break;
	}
    }
  else if(argc == 1)
    {
      for(i=0; i<testc; i++)
	if(check(tests[i].pkt, tests[i].off, tests[i].func) != 0)
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
