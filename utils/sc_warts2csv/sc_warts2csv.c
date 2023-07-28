/*
 * sc_warts2csv.c
 *
 * Copyright (C) 2014 The Regents of the University of California
 * Copyright (C) 2023 Matthew Luckie
 *
 * $Id: sc_warts2csv.c,v 1.6 2023/05/13 23:29:58 mjl Exp $
 *
 * Authors: Vaibhav Bajpai, Matthew Luckie
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

#include "scamper_file.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "trace/scamper_trace.h"
#include "utils.h"

static void csv_trace(scamper_trace_t *trace)
{
  char src[128], dst[128], addr[128], rtt[32], type[32], stop[32];
  const struct timeval *start, *hop_rtt;
  const scamper_trace_hop_t *hop;
  const char *tptr, *sptr;
  scamper_addr_t *hop_addr;
  uint32_t userid;
  uint16_t hop_count;
  uint8_t firsthop;
  int i, hopc = 0;

  firsthop = scamper_trace_firsthop_get(trace);
  hop_count = scamper_trace_hop_count_get(trace);
  for(i=firsthop-1; i<hop_count; i++)
    {
      for(hop = scamper_trace_hop_get(trace, i); hop != NULL;
	  hop = scamper_trace_hop_next_get(hop))
	{
	  hopc++;
	  break;
	}
    }

  if(hopc == 0)
    goto done;

  printf("version;userID;timestamp;src;dst;method;stop;ttl;hopaddr;rtt\n");

  scamper_addr_tostr(scamper_trace_dst_get(trace), dst, sizeof(dst));
  scamper_addr_tostr(scamper_trace_src_get(trace), src, sizeof(src));
  tptr = scamper_trace_type_tostr(trace, type, sizeof(type));
  sptr = scamper_trace_stop_tostr(trace, stop, sizeof(stop));
  userid = scamper_trace_userid_get(trace);
  start = scamper_trace_start_get(trace);

  for(i=firsthop-1; i<hop_count; i++)
    {
      for(hop = scamper_trace_hop_get(trace, i); hop != NULL;
	  hop = scamper_trace_hop_next_get(hop))
	{
	  hop_addr = scamper_trace_hop_addr_get(hop);
	  hop_rtt = scamper_trace_hop_rtt_get(hop);
	  printf("scamper.%s;%u;%d;%s;%s;%s;%s;%u;%s;%s\n", PACKAGE_VERSION,
		 userid, (int)start->tv_sec, src, dst, tptr, sptr,
		 scamper_trace_hop_probe_ttl_get(hop),
		 scamper_addr_tostr(hop_addr, addr, sizeof(addr)),
		 timeval_tostr_us(hop_rtt, rtt, sizeof(rtt)));
	}
    }

 done:
  scamper_trace_free(trace);
  return;
}

int main(int argc, char *argv[])
{
  uint16_t types[] = {
    SCAMPER_FILE_OBJ_TRACE,
  };
  scamper_file_t *in;
  scamper_file_filter_t *filter;
  char **files = NULL;
  int filec;
  uint16_t type;
  void *data;
  int i;

  filter = scamper_file_filter_alloc(types, sizeof(types)/sizeof(uint16_t));
  if(filter == NULL)
    {
      fprintf(stderr, "could not allocate filter\n");
      return -1;
    }

  filec = argc - 1;
  if(filec > 0)
    files = argv + 1;

  for(i=0; i<=filec; i++)
    {
      if(filec == 0)
	{
	  if((in = scamper_file_openfd(STDIN_FILENO,"-",'r',"warts")) == NULL)
	    {
	      fprintf(stderr, "could not use stdin\n");
	      return -1;
	    }
	}
      else if(i < filec)
	{
	  if((in = scamper_file_open(files[i], 'r', NULL)) == NULL)
	    {
	      fprintf(stderr, "could not open %s: %s\n",
		      files[i], strerror(errno));
	      return -1;
	    }
	}
      else break;

      while(scamper_file_read(in, filter, &type, (void *)&data) == 0)
	{
	  if(data == NULL)
	    break; /* EOF */
	  if(type == SCAMPER_FILE_OBJ_TRACE)
	    csv_trace(data);
	}

      scamper_file_close(in);
    }

  scamper_file_filter_free(filter);
  return 0;
}
