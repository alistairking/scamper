/*
 * unit_dl_parse_arp : unit tests for dl_parse_arp function
 *
 * $Id: unit_dl_parse_arp.c,v 1.1 2024/07/02 00:50:12 mjl Exp $
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

#include "scamper_addr.h"
#include "scamper_dl.h"
#include "common.h"
#include "utils.h"

/*
 * function prototype of a normally static function that is not in
 * scamper_dl.h
 */
int dl_parse_arp(scamper_dl_rec_t *dl, uint8_t *pktbuf, size_t pktlen);

typedef struct sc_test
{
  char *pkt;
  int (*func)(uint8_t *pkt, size_t len);
} sc_test_t;

static int empty(uint8_t *pkt, size_t len)
{
  scamper_dl_rec_t dl;
  memset(&dl, 0, sizeof(dl));
  if(dl_parse_arp(&dl, pkt, len) != 0)
    return -1;
  return 0;
}

static int whohas(uint8_t *pkt, size_t len)
{
  scamper_dl_rec_t dl;
  memset(&dl, 0, sizeof(dl));
  if(dl_parse_arp(&dl, pkt, len) == 0 ||
     SCAMPER_DL_IS_ARP_OP_REQ(&dl) == 0 ||
     SCAMPER_DL_IS_ARP_HRD_ETHERNET(&dl) == 0 ||
     SCAMPER_DL_IS_ARP_PRO_IPV4(&dl) == 0)
    return -1;
  return 0;
}

static int isat(uint8_t *pkt, size_t len)
{
  scamper_dl_rec_t dl;
  memset(&dl, 0, sizeof(dl));
  if(dl_parse_arp(&dl, pkt, len) == 0 ||
     SCAMPER_DL_IS_ARP_OP_REPLY(&dl) == 0 ||
     SCAMPER_DL_IS_ARP_HRD_ETHERNET(&dl) == 0 ||
     SCAMPER_DL_IS_ARP_PRO_IPV4(&dl) == 0)
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
    {"",
     empty},
    {"0001080006040001"
     "dca632057787c0a8031b"
     "000000000000c0a8032a"
     "00000000000000000000"
     "0000000000000000",
     whohas},
    {"0001080006040002"
     "848bcd4afbe6c0a80301"
     "b619ed518334c0a8032a",
     isat},
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
