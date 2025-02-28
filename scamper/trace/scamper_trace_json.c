/*
 * scamper_trace_json.c
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2011-2013 Internap Network Services Corporation
 * Copyright (C) 2013-2014 The Regents of the University of California
 * Copyright (C) 2015      The University of Waikato
 * Copyright (C) 2016-2025 Matthew Luckie
 *
 * Authors: Brian Hammond, Matthew Luckie
 *
 * $Id: scamper_trace_json.c,v 1.39 2025/02/17 07:57:34 mjl Exp $
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
#include "scamper_list_int.h"
#include "scamper_icmpext.h"
#include "scamper_icmpext_int.h"
#include "scamper_trace.h"
#include "scamper_trace_int.h"
#include "scamper_file.h"
#include "scamper_file_json.h"
#include "scamper_trace_json.h"
#include "utils.h"

static char *hop_tostr(const scamper_trace_t *trace, scamper_trace_hop_t *hop)
{
  char buf[1024], tmp[128];
  scamper_icmpexts_t *exts;
  scamper_icmpext_t *ie;
  size_t off = 0, off2;
  uint32_t u32;
  uint16_t u16;
  int i;

  string_concat3(buf, sizeof(buf), &off, "{\"addr\":\"",
		 scamper_addr_tostr(hop->hop_addr, tmp, sizeof(tmp)), "\"");
  if(hop->hop_name != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"name\":\"",
		   json_esc(hop->hop_name, tmp, sizeof(tmp)), "\"");
  string_concat_u8(buf, sizeof(buf), &off, ", \"probe_ttl\":",
		   hop->hop_probe_ttl);
  string_concat_u8(buf, sizeof(buf), &off, ", \"probe_id\":",
		   hop->hop_probe_id);
  string_concat_u16(buf, sizeof(buf), &off, ", \"probe_size\":",
		    hop->hop_probe_size);
  if(hop->hop_tx.tv_sec != 0)
    {
      string_concat_u32(buf, sizeof(buf), &off, ", \"tx\":{\"sec\":",
			(uint32_t)hop->hop_tx.tv_sec);
      string_concat_u32(buf, sizeof(buf), &off, ", \"usec\":",
			(uint32_t)hop->hop_tx.tv_usec);
      string_concatc(buf, sizeof(buf), &off, '}');
    }
  string_concat2(buf, sizeof(buf), &off, ", \"rtt\":",
		 timeval_tostr_us(&hop->hop_rtt, tmp, sizeof(tmp)));
  string_concat_u8(buf, sizeof(buf), &off, ", \"reply_ttl\":",
		   hop->hop_reply_ttl);
  string_concat_u8(buf, sizeof(buf), &off, ", \"reply_tos\":",
		   hop->hop_reply_tos);

  if(hop->hop_flags != 0)
    {
      tmp[0] = '\0'; off2 = 0;
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_TX)
	string_concat(tmp, sizeof(tmp), &off2, "\"dltxts\"");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_DL_RX)
	string_concat2(tmp, sizeof(tmp), &off2,
		       off2 != 0 ? ", " : "", "\"dlrxts\"");
      if(hop->hop_flags & SCAMPER_TRACE_HOP_FLAG_TS_SOCK_RX)
	string_concat2(tmp, sizeof(tmp), &off2,
		       off2 != 0 ? ", " : "", "\"sockrxts\"");
      if(off2 != 0)
	string_concat3(buf, sizeof(buf), &off, ", \"flags\":[", tmp, "]");
    }

  if((trace->flags & SCAMPER_TRACE_FLAG_RXERR) == 0)
    {
      string_concat_u16(buf, sizeof(buf), &off, ", \"reply_ipid\":",
			hop->hop_reply_ipid);
      string_concat_u16(buf, sizeof(buf), &off, ", \"reply_size\":",
			hop->hop_reply_size);
    }

  if(SCAMPER_TRACE_HOP_IS_ICMP(hop))
    {
      string_concat_u8(buf, sizeof(buf), &off, ", \"icmp_type\":",
		       hop->hop_icmp_type);
      string_concat_u8(buf, sizeof(buf), &off, ", \"icmp_code\":",
		       hop->hop_icmp_code);
      if(SCAMPER_TRACE_HOP_IS_ICMP_Q(hop) &&
	 (trace->flags & SCAMPER_TRACE_FLAG_RXERR) == 0)
	{
	  string_concat_u8(buf, sizeof(buf), &off, ", \"icmp_q_ttl\":",
			   hop->hop_icmp_q_ttl);
	  string_concat_u16(buf, sizeof(buf), &off, ", \"icmp_q_ipl\":",
			    hop->hop_icmp_q_ipl);
	  string_concat_u8(buf, sizeof(buf), &off, ", \"icmp_q_tos\":",
			   hop->hop_icmp_q_tos);
	}
      if(SCAMPER_TRACE_HOP_IS_ICMP_PTB(hop))
	string_concat_u16(buf, sizeof(buf), &off, ", \"icmp_nhmtu:\":",
			  hop->hop_icmp_nhmtu);
    }
  else if(SCAMPER_TRACE_HOP_IS_TCP(hop))
    {
      string_concat_u8(buf, sizeof(buf), &off, ", \"tcp_flags\":",
		       hop->hop_tcp_flags);
    }

  if((exts = hop->hop_icmp_exts) != NULL)
    {
      string_concat(buf, sizeof(buf), &off, ", \"icmpext\":[");
      for(u16=0; u16<exts->extc; u16++)
	{
	  if(u16 > 0)
	    string_concatc(buf, sizeof(buf), &off, ',');
	  ie = exts->exts[u16];
	  string_concat_u8(buf, sizeof(buf), &off, "{\"ie_cn\":", ie->ie_cn);
	  string_concat_u8(buf, sizeof(buf), &off, ",\"ie_ct\":", ie->ie_ct);
	  string_concat_u16(buf, sizeof(buf), &off, ",\"ie_dl\":", ie->ie_dl);
	  if(SCAMPER_ICMPEXT_IS_MPLS(ie))
	    {
	      string_concat(buf, sizeof(buf), &off, ",\"mpls_labels\":[");
	      for(i=0; i<SCAMPER_ICMPEXT_MPLS_COUNT(ie); i++)
		{
		  u32 = SCAMPER_ICMPEXT_MPLS_LABEL(ie, i);
		  if(i > 0)
		    string_concatc(buf, sizeof(buf), &off, ',');
		  string_concat_u8(buf, sizeof(buf), &off, "{\"mpls_ttl\":",
				   SCAMPER_ICMPEXT_MPLS_TTL(ie, i));
		  string_concat_u8(buf, sizeof(buf), &off, ",\"mpls_s\":",
				   SCAMPER_ICMPEXT_MPLS_S(ie, i));
		  string_concat_u8(buf, sizeof(buf), &off, ",\"mpls_exp\":",
				   SCAMPER_ICMPEXT_MPLS_EXP(ie, i));
		  string_concat_u32(buf, sizeof(buf), &off, ",\"mpls_label\":",
				    u32);
		  string_concatc(buf, sizeof(buf), &off, '}');
		}
	      string_concatc(buf, sizeof(buf), &off, ']');
	    }
	  string_concatc(buf, sizeof(buf), &off, '}');
	}
      string_concatc(buf, sizeof(buf), &off, ']');
    }

  string_concatc(buf, sizeof(buf), &off, '}');
  return strdup(buf);
}

static char *header_tostr(const scamper_trace_t *trace)
{
  char buf[512], tmp[128];
  size_t off = 0;
  time_t tt = trace->start.tv_sec;
  uint32_t cs;

  string_concat(buf,sizeof(buf),&off,"\"type\":\"trace\",\"version\":\"0.1\"");
  string_concat_u32(buf, sizeof(buf), &off, ", \"userid\":", trace->userid);
  string_concat3(buf, sizeof(buf), &off, ", \"method\":\"",
		 scamper_trace_type_tostr(trace, tmp, sizeof(tmp)), "\"");
  if(trace->src != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"src\":\"",
		   scamper_addr_tostr(trace->src, tmp, sizeof(tmp)), "\"");
  if(trace->dst != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"dst\":\"",
		   scamper_addr_tostr(trace->dst, tmp, sizeof(tmp)), "\"");
  if(trace->rtr != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"rtr\":\"",
		   scamper_addr_tostr(trace->rtr, tmp, sizeof(tmp)), "\"");
  if(SCAMPER_TRACE_TYPE_IS_UDP(trace) || SCAMPER_TRACE_TYPE_IS_TCP(trace))
    {
      string_concat_u16(buf, sizeof(buf), &off, ", \"sport\":", trace->sport);
      string_concat_u16(buf, sizeof(buf), &off, ", \"dport\":", trace->dport);
    }
  else if(trace->flags & SCAMPER_TRACE_FLAG_ICMPCSUMDP)
    string_concat_u16(buf, sizeof(buf), &off, ", \"icmp_sum\":", trace->dport);
  string_concat2(buf, sizeof(buf), &off, ", \"stop_reason\":\"",
		 scamper_trace_stop_tostr(trace, tmp, sizeof(tmp)));
  string_concat_u16(buf, sizeof(buf), &off, "\", \"stop_data\":",
		    trace->stop_data);
  string_concat_u32(buf, sizeof(buf), &off, ", \"start\":{\"sec\":",
		    (uint32_t)trace->start.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ", \"usec\":",
		    (uint32_t)trace->start.tv_usec);
  strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", localtime(&tt));
  string_concat2(buf, sizeof(buf), &off, ", \"ftime\":\"", tmp);
  string_concat_u16(buf, sizeof(buf), &off, "\"}, \"hop_count\":",
		    trace->stop_hop == 0 ? trace->hop_count : trace->stop_hop);
  string_concat_u8(buf, sizeof(buf), &off, ", \"attempts\":", trace->attempts);
  string_concat_u8(buf, sizeof(buf), &off, ", \"hoplimit\":", trace->hoplimit);
  string_concat_u8(buf, sizeof(buf), &off, ", \"firsthop\":", trace->firsthop);
  string_concat_u32(buf, sizeof(buf), &off, ", \"wait\":",
		    (uint32_t)trace->wait_timeout.tv_sec);
  cs = (trace->wait_probe.tv_sec * 100) + (trace->wait_probe.tv_usec / 10000);
  string_concat_u32(buf, sizeof(buf), &off, ", \"wait_probe\":", cs);
  string_concat_u8(buf, sizeof(buf), &off, ", \"tos\":", trace->tos);
  string_concat_u16(buf, sizeof(buf), &off, ", \"probe_size\":",
		    trace->probe_size);
  string_concat_u16(buf, sizeof(buf), &off, ", \"probe_count\":",
		    trace->probec);
  if(trace->list != NULL && trace->list->monitor != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"monitor\":\"",
		   json_esc(trace->list->monitor, tmp, sizeof(tmp)), "\"");

  return strdup(buf);
}

char *scamper_trace_tojson(const scamper_trace_t *trace, size_t *len_out)
{
  scamper_trace_hop_t *hop;
  size_t len, off = 0;
  char *str = NULL, *header = NULL, **hops = NULL;
  size_t j, hopc = 0, hops_hopc = 0, extra_hopc = 0;
  uint16_t i, hop_count;
  int rc = -1;

  if((header = header_tostr(trace)) == NULL)
    goto cleanup;
  len = strlen(header);

  /* how many responses do we include in the hops array */
  if(trace->stop_hop == 0)
    hop_count = trace->hop_count;
  else
    hop_count = trace->stop_hop;
  for(i=trace->firsthop-1; i<hop_count; i++)
    for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
      hops_hopc++;

  /* how many responses do we include in the extra_hops array */
  if(trace->stop_hop != 0)
    {
      while(i < trace->hop_count)
	{
	  for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
	    extra_hopc++;
	  i++;
	}
    }

  hopc = hops_hopc + extra_hopc;
  if(hopc > 0)
    {
      len += 11; /* , "hops":[] */
      if(extra_hopc > 0)
	len += 17; /* , "extra_hops":[] */
      if((hops = malloc_zero(sizeof(char *) * hopc)) == NULL)
	goto cleanup;
      for(i=trace->firsthop-1, j=0; i<trace->hop_count; i++)
	{
	  for(hop = trace->hops[i]; hop != NULL; hop = hop->hop_next)
	    {
	      if((hops[j] = hop_tostr(trace, hop)) == NULL)
		goto cleanup;
	      len += strlen(hops[j]);
	      j++;
	    }
	}
    }

  /* comma separators for the two hops arrays */
  if(hops_hopc > 1)
    len += (hops_hopc - 1); /* , */
  if(extra_hopc > 1)
    len += (extra_hopc - 1); /* , */

  len += 3; /* {}\0 */

  if((str = malloc_zero(len)) == NULL)
    goto cleanup;

  str[off++] = '{';
  string_concat(str, len, &off, header);
  if(hopc > 0)
    {
      string_concat(str, len, &off, ", \"hops\":[");
      for(j=0; j<hops_hopc; j++)
	{
	  if(j > 0) string_concat(str, len, &off, ",");
	  string_concat(str, len, &off, hops[j]);
	}
      string_concat(str, len, &off, "]");
    }

  if(extra_hopc > 0)
    {
      string_concat(str, len, &off, ", \"extra_hops\":[");
      for(j=0; j<extra_hopc; j++)
	{
	  if(j > 0) string_concat(str, len, &off, ",");
	  string_concat(str, len, &off, hops[hops_hopc + j]);
	}
      string_concat(str, len, &off, "]");
    }

  string_concat(str, len, &off, "}");
  assert(off+1 == len);

  rc = 0;

 cleanup:
  if(hops != NULL)
    {
      for(j=0; j<hopc; j++)
	if(hops[j] != NULL)
	  free(hops[j]);
      free(hops);
    }
  if(header != NULL)
    free(header);

  if(rc != 0)
    {
      if(str != NULL)
	free(str);
      return NULL;
    }

  if(len_out != NULL)
    *len_out = len;
  return str;
}

int scamper_file_json_trace_write(const scamper_file_t *sf,
				  const scamper_trace_t *trace, void *p)
{
  char *str;
  size_t len;
  int rc;

  if((str = scamper_trace_tojson(trace, &len)) == NULL)
    return -1;
  str[len-1] = '\n';
  rc = json_write(sf, str, len, p);
  free(str);

  return rc;
}
