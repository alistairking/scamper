/*
 * unit_icmpext : unit tests for parsing icmpext
 *
 * $Id: unit_icmpext.c,v 1.8 2026/07/13 01:10:55 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2026 Matthew Luckie
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

#include "scamper_icmpext.h"
#include "scamper_icmpext_int.h"

#include "common.h"
#include "utils.h"

typedef struct sc_test
{
  char *ext;
  int (*func)(const scamper_icmpexts_t *);
} sc_test_t;

static int mpls_one(const scamper_icmpexts_t *exts)
{
  uint8_t data[] = {0x03, 0xea, 0x41, 0x01};
  if(exts == NULL || exts->extc != 1 ||
     exts->exts[0]->ie_cn != 1 ||
     exts->exts[0]->ie_ct != 1 ||
     exts->exts[0]->ie_dl != 4 ||
     memcmp(exts->exts[0]->ie_data, data, 4) != 0)
    return -1;

  if(scamper_icmpext_is_mpls(exts->exts[0]) == 0 ||
     scamper_icmpext_mpls_count_get(exts->exts[0]) != 1 ||
     scamper_icmpext_mpls_label_get(exts->exts[0], 0) != 16036 ||
     scamper_icmpext_mpls_ttl_get(exts->exts[0], 0) != 1 ||
     scamper_icmpext_mpls_exp_get(exts->exts[0], 0) != 0 ||
     scamper_icmpext_mpls_s_get(exts->exts[0], 0) != 1)
    return -1;
	 
  return 0;
}

static int mpls_two(const scamper_icmpexts_t *exts)
{
  uint8_t data[] = {0x03, 0x2e, 0xd0, 0x01, 0x00, 0x01, 0x11, 0x01};
  if(exts == NULL || exts->extc != 1 ||
     exts->exts[0]->ie_cn != 1 ||
     exts->exts[0]->ie_ct != 1 ||
     exts->exts[0]->ie_dl != 8 ||
     memcmp(exts->exts[0]->ie_data, data, 8) != 0)
    return -1;

  if(scamper_icmpext_is_mpls(exts->exts[0]) == 0 ||
     scamper_icmpext_mpls_count_get(exts->exts[0]) != 2 ||
     scamper_icmpext_mpls_label_get(exts->exts[0], 0) != 13037 ||
     scamper_icmpext_mpls_ttl_get(exts->exts[0], 0) != 1 ||
     scamper_icmpext_mpls_exp_get(exts->exts[0], 0) != 0 ||
     scamper_icmpext_mpls_s_get(exts->exts[0], 0) != 0 ||
     scamper_icmpext_mpls_label_get(exts->exts[0], 1) != 17 ||
     scamper_icmpext_mpls_ttl_get(exts->exts[0], 1) != 1 ||
     scamper_icmpext_mpls_exp_get(exts->exts[0], 1) != 0 ||
     scamper_icmpext_mpls_s_get(exts->exts[0], 1) != 1)
    return -1;
  
  return 0;
}

static int rfc5837_one(const scamper_icmpexts_t *exts)
{
  uint8_t data[] = {
    0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
    0xC0, 0x00, 0x02, 0x01, 0x03, 0x65, 0x6D, 0x30,
    0x00, 0x00, 0x23, 0x28
  };
  if(exts == NULL || exts->extc != 1 ||
     exts->exts[0]->ie_cn != 2  ||
     exts->exts[0]->ie_ct != 15 ||
     exts->exts[0]->ie_dl != 20 ||
     memcmp(exts->exts[0]->ie_data, data, 20) != 0 ||
     scamper_icmpext_is_mpls(exts->exts[0]) != 0)
    return -1;
  return 0;
}

static int mpls_one_rfc5837_one(const scamper_icmpexts_t *exts)
{
  uint8_t ext0[] = {
    0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00,
    0xC0, 0x00, 0x02, 0x01, 0x03, 0x65, 0x6D, 0x30,
    0x00, 0x00, 0x23, 0x28
  };
  uint8_t ext1[] = {0x03, 0xea, 0x41, 0x01};
  if(exts == NULL || exts->extc != 2 ||
     exts->exts[0]->ie_cn != 2  ||
     exts->exts[0]->ie_ct != 15 ||
     exts->exts[0]->ie_dl != 20 ||
     memcmp(exts->exts[0]->ie_data, ext0, 20) != 0 ||
     scamper_icmpext_is_mpls(exts->exts[0]) != 0 ||
     exts->exts[1]->ie_cn != 1 ||
     exts->exts[1]->ie_ct != 1 ||
     exts->exts[1]->ie_dl != 4 ||
     memcmp(exts->exts[1]->ie_data, ext1, 4) != 0 ||
     scamper_icmpext_is_mpls(exts->exts[1]) == 0)
    return -1;
  return 0;
}

static int cksum_ffff(const scamper_icmpexts_t *exts)
{
  uint8_t data[] = {0x00, 0x02, 0xDF, 0xF4};
  if(exts == NULL || exts->extc != 1 ||
     exts->exts[0]->ie_cn != 0 ||
     exts->exts[0]->ie_ct != 1 ||
     exts->exts[0]->ie_dl != 4 ||
     memcmp(exts->exts[0]->ie_data, data, 4) != 0)
    return -1;
  return 0;
}

static int one_empty(const scamper_icmpexts_t *exts)
{
  if(exts == NULL || exts->extc != 1 ||
     exts->exts[0]->ie_cn != 1 ||
     exts->exts[0]->ie_ct != 1 ||
     exts->exts[0]->ie_dl != 0 ||
     exts->exts[0]->ie_data != NULL ||
     scamper_icmpext_is_mpls(exts->exts[0]) == 0 ||
     scamper_icmpext_mpls_count_get(exts->exts[0]) != 0)
    return -1;
  return 0;
}

static int len_three(const scamper_icmpexts_t *exts)
{
  if(exts != NULL)
    return -1;
  return 0;
}

static int len_five(const scamper_icmpexts_t *exts)
{
  if(exts == NULL || exts->extc != 1 ||
     exts->exts[0]->ie_cn != 1 ||
     exts->exts[0]->ie_ct != 1 ||
     exts->exts[0]->ie_dl != 1 ||
     exts->exts[0]->ie_data == NULL ||
     exts->exts[0]->ie_data[0] != 0x66 ||
     scamper_icmpext_is_mpls(exts->exts[0]) == 0 ||
     scamper_icmpext_mpls_count_get(exts->exts[0]) != 0)
    return -1;
  return 0;
}

static int len_seven(const scamper_icmpexts_t *exts)
{
  if(exts == NULL || exts->extc != 1 ||
     exts->exts[0]->ie_cn != 1 ||
     exts->exts[0]->ie_ct != 1 ||
     exts->exts[0]->ie_dl != 3 ||
     exts->exts[0]->ie_data == NULL ||
     exts->exts[0]->ie_data[0] != 0x66 ||
     exts->exts[0]->ie_data[1] != 0x55 ||
     exts->exts[0]->ie_data[2] != 0x44 ||
     scamper_icmpext_is_mpls(exts->exts[0]) == 0 ||
     scamper_icmpext_mpls_count_get(exts->exts[0]) != 0)
    return -1;
  return 0;
}

static int none(const scamper_icmpexts_t *exts)
{
  if(exts != NULL)
    return -1;
  return 0;
}

static int check(const char *ext, int (*func)(const scamper_icmpexts_t *))
{
  scamper_icmpexts_t *exts = NULL;
  uint8_t *buf = NULL;
  size_t len;
  int rc = -1;

  if(hex2buf(ext, &buf, &len) != 0 ||
     scamper_icmpext_parse(&exts, buf, len) != 0 ||
     (func != none && in_cksum(buf, len) != 0))
    goto done;

  rc = func(exts);

 done:
  if(exts != NULL) scamper_icmpexts_free(exts);
  if(buf != NULL) free(buf);
  return rc;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {"20009a0b" "00080101" "03ea4101",
     mpls_one},
    {"2000fac0" "000c0101" "032ed001" "00011101",
     mpls_two},
    {"20008814" "0018020F" "00000004" "00010000"
     "C0000201" "03656D30" "00002328",
     rfc5837_one},
    {"20004220" "0018020F" "00000004" "00010000"
     "C0000201" "03656D30" "00002328"
     "00080101" "03ea4101",
     mpls_one_rfc5837_one},
    {"2000ffff" "00080001" "0002DFF4",
     cksum_ffff},
    {"20000000" "00080001" "0002DFF4",
     cksum_ffff},
    {"2000defa" "00040101",
     one_empty},
    {"2000defc" "000301",
     len_three},
    {"200078f9" "00050101" "66",
     len_five},
    {"200034a2" "00070101" "665544",
     len_seven},
    {"2000", none},
    {"20000000", none},
    {"20000000" "0008", none},
    {"20000000" "00080001", none},
    {"20000000" "00080001" "000000", none},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);
  char filename[128];

  /* dump icmpexts if requested */
  if(argc == 3 && strcasecmp(argv[1], "dump") == 0)
    {
      for(i=0; i<testc; i++)
	{
	  snprintf(filename, sizeof(filename),
		   "%s/icmpext-%03x.dat", argv[2], (int)i);
	  if(dump_hex(tests[i].ext, filename) != 0)
	    break;
	}
    }
  else if(argc == 1)
    {
      for(i=0; i<testc; i++)
	if(check(tests[i].ext, tests[i].func) != 0)
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
