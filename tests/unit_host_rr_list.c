/*
 * unit_dl_parse_ip : unit tests for host_rr_list function
 *
 * $Id: unit_host_rr_list.c,v 1.3 2023/12/02 20:46:00 mjl Exp $
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

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_host.h"
#include "scamper_host_int.h"

#include "utils.h"
#include "mjl_list.h"

/*
 * function prototype of a normally static function that is not in
 * scamper_host.h or 
 */
slist_t *host_rr_list(const uint8_t *buf, size_t off, size_t len);

typedef struct sc_test
{
  char   *pkt;
  size_t  off;
  int    (*func)(const slist_t *rr_list);
} sc_test_t;

static int com_soa(const slist_t *rr_list)
{
  scamper_host_rr_t *rr;
  scamper_host_rr_soa_t *soa;
  slist_node_t *sn;
  int i = 0;

  if(rr_list == NULL)
    return -1;
  for(sn=slist_head_node(rr_list); sn != NULL; sn=slist_node_next(sn))
    {
      rr = slist_node_item(sn);
      if(i == 0)
	{
	  if(scamper_host_rr_data_type(rr->class, rr->type) != SCAMPER_HOST_RR_DATA_TYPE_SOA ||
	     rr->class != SCAMPER_HOST_CLASS_IN ||
	     rr->type != SCAMPER_HOST_TYPE_SOA ||
	     rr->ttl != 509 ||
	     strcmp(rr->name, "com") != 0 ||
	     (soa = scamper_host_rr_soa_get(rr)) == NULL)
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

static int check(const char *pkt, size_t off,
		 int (*func)(const slist_t *list))
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
     "03636f6d00" "00060001" /* com SOA IN */
     "c00c00060001000001fd003d01610c6774"
     "6c642d73657276657273036e657400056e73746c640c76657269"
     "7369676e2d677273c00c6545cde0000007080000038400093a80"
     "000151800000291000000000000000",
     12 + 5 + 4,
     com_soa},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);

  for(i=0; i<testc; i++)
    if(check(tests[i].pkt, tests[i].off, tests[i].func) != 0)
      break;

  if(i != testc)
    {
      printf("test %d failed\n", (int)i);
      return -1;
    }

  printf("OK\n");
  return 0;
}
