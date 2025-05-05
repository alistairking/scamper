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
 * $Id: scamper_trace_json.c,v 1.45 2025/05/05 00:01:21 mjl Exp $
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

static scamper_trace_reply_t *trace_reply_get(const scamper_trace_t *trace,
					      uint8_t i)
{
  scamper_trace_probettl_t *pttl;
  if((pttl = trace->hops[i]) == NULL)
    return NULL;
  return scamper_trace_probettl_reply_get(pttl);
}

static void probe_json(char *buf, size_t len, size_t *off,
		       const scamper_trace_probe_t *probe, int reply)
{
  string_concatc(buf, len, off, reply == 0 ? '{' : ',');

  string_concat_u8(buf, len, off, "\"probe_ttl\":", probe->ttl);
  string_concat_u8(buf, len, off, ", \"probe_id\":", probe->id);
  string_concat_u16(buf, len, off, ", \"probe_size\":", probe->size);
  if(probe->tx.tv_sec != 0)
    {
      string_concat_u32(buf, len, off, ", \"tx\":{\"sec\":",
			(uint32_t)probe->tx.tv_sec);
      string_concat_u32(buf, len, off, ", \"usec\":",
			(uint32_t)probe->tx.tv_usec);
      string_concatc(buf, len, off, '}');
    }

  if(reply == 0)
    string_concatc(buf, len, off, '}');

  return;
}

static char *probe_tostr(const scamper_trace_probe_t *probe)
{
  char buf[1024];
  size_t off = 0;
  probe_json(buf, sizeof(buf), &off, probe, 0);
  return strdup(buf);
}

static char *hop_tostr(const scamper_trace_t *trace,
		       const scamper_trace_probe_t *probe,
		       const scamper_trace_reply_t *reply)
{
  char buf[1024], tmp[128];
  scamper_icmpexts_t *exts;
  scamper_icmpext_t *ie;
  size_t off = 0, off2;
  uint32_t u32;
  uint16_t u16;
  int i;

  string_concat3(buf, sizeof(buf), &off, "{\"addr\":\"",
		 scamper_addr_tostr(reply->addr, tmp, sizeof(tmp)), "\"");
  if(reply->name != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"name\":\"",
		   json_esc(reply->name, tmp, sizeof(tmp)), "\"");

  probe_json(buf, sizeof(buf), &off, probe, 1);

  string_concat2(buf, sizeof(buf), &off, ", \"rtt\":",
		 timeval_tostr_us(&reply->rtt, tmp, sizeof(tmp)));
  string_concat_u8(buf, sizeof(buf), &off, ", \"reply_ttl\":", reply->ttl);
  string_concat_u8(buf, sizeof(buf), &off, ", \"reply_tos\":", reply->tos);

  if(reply->flags != 0)
    {
      tmp[0] = '\0'; off2 = 0;
      if(reply->flags & SCAMPER_TRACE_REPLY_FLAG_TS_DL_TX)
	string_concat(tmp, sizeof(tmp), &off2, "\"dltxts\"");
      if(reply->flags & SCAMPER_TRACE_REPLY_FLAG_TS_DL_RX)
	string_concat2(tmp, sizeof(tmp), &off2,
		       off2 != 0 ? ", " : "", "\"dlrxts\"");
      if(reply->flags & SCAMPER_TRACE_REPLY_FLAG_TS_SOCK_RX)
	string_concat2(tmp, sizeof(tmp), &off2,
		       off2 != 0 ? ", " : "", "\"sockrxts\"");
      if(off2 != 0)
	string_concat3(buf, sizeof(buf), &off, ", \"flags\":[", tmp, "]");
    }

  if((trace->flags & SCAMPER_TRACE_FLAG_RXERR) == 0)
    {
      string_concat_u16(buf,sizeof(buf),&off,", \"reply_ipid\":", reply->ipid);
      string_concat_u16(buf,sizeof(buf),&off,", \"reply_size\":", reply->size);
    }

  if(SCAMPER_TRACE_REPLY_IS_ICMP(reply))
    {
      string_concat_u8(buf, sizeof(buf), &off, ", \"icmp_type\":",
		       reply->reply_icmp_type);
      string_concat_u8(buf, sizeof(buf), &off, ", \"icmp_code\":",
		       reply->reply_icmp_code);
      if(SCAMPER_TRACE_REPLY_IS_ICMP_Q(reply) &&
	 (trace->flags & SCAMPER_TRACE_FLAG_RXERR) == 0)
	{
	  string_concat_u8(buf, sizeof(buf), &off, ", \"icmp_q_ttl\":",
			   reply->reply_icmp_q_ttl);
	  string_concat_u16(buf, sizeof(buf), &off, ", \"icmp_q_ipl\":",
			    reply->reply_icmp_q_ipl);
	  string_concat_u8(buf, sizeof(buf), &off, ", \"icmp_q_tos\":",
			   reply->reply_icmp_q_tos);
	}
      if(SCAMPER_TRACE_REPLY_IS_ICMP_PTB(reply))
	string_concat_u16(buf, sizeof(buf), &off, ", \"icmp_nhmtu:\":",
			  reply->reply_icmp_nhmtu);
    }
  else if(SCAMPER_TRACE_REPLY_IS_TCP(reply))
    {
      string_concat_u8(buf, sizeof(buf), &off, ", \"tcp_flags\":",
		       reply->reply_tcp_flags);
    }

  if((exts = reply->icmp_exts) != NULL)
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

static size_t pmtud_note_hopid(const scamper_trace_pmtud_t *pmtud,
			       const scamper_trace_reply_t *reply)
{
  scamper_trace_hopiter_t hi;
  scamper_trace_reply_t *r;
  size_t hop_id = 0;

  if(reply == NULL)
    return 0;

  scamper_trace_hopiter_reset(&hi);
  while((r = scamper_trace_pmtud_hopiter_next(pmtud, &hi)) != NULL)
    {
      hop_id++;
      if(r == reply)
	return hop_id;
    }

  return 0;
}

static uint8_t pmtud_note_dist(const scamper_trace_t *trace, uint8_t start,
			       const scamper_trace_pmtud_note_t *note)
{
  const scamper_trace_reply_t *hop, *trace_hop;
  uint16_t i, hop_count;

  if(note->type == SCAMPER_TRACE_PMTUD_NOTE_TYPE_SILENCE)
    {
      if(note->probe != NULL)
	return note->probe->ttl;
      return 0;
    }

  if((hop = note->reply) == NULL)
    return 0;

  if(trace->stop_hop == 0)
    hop_count = trace->hop_count;
  else
    hop_count = trace->stop_hop;

  /*
   * if we observed the address in traceroute, then return the hop
   * where that address is observed
   */
  for(i = start-1; i < hop_count; i++)
    if((trace_hop = trace_reply_get(trace, i)) != NULL &&
       scamper_trace_reply_addr_cmp(trace_hop, hop) == 0)
      return i + 1;

  if(note->probe == NULL || note->probe->ttl <= hop->reply_icmp_q_ttl)
    return 0;

  /* kludge to figure out which hop to put the PTB on */
  i = note->probe->ttl - hop->reply_icmp_q_ttl;

  /*
   * shift the predicted hop back one if the alignment is
   * analytically unlikely.
   */
  if((trace_hop = trace_reply_get(trace, i)) != NULL &&
     ((SCAMPER_ADDR_TYPE_IS_IPV4(hop->addr) &&
       scamper_addr_prefix(trace_hop->addr, hop->addr) >= 30) ||
      (SCAMPER_ADDR_TYPE_IS_IPV6(hop->addr) &&
       scamper_addr_prefix(trace_hop->addr, hop->addr) >= 126)))
    return i;

  return i + 1;
}

static char *pmtud_note_tostr(const scamper_trace_pmtud_note_t *note,
			      uint8_t dist, size_t hop_id)
{
  char buf[256], tmp[256];
  size_t off = 0, len = sizeof(buf);

  string_concat_u16(buf, len, &off, "{\"nhmtu\":", note->nhmtu);
  if(hop_id > 0)
    string_concat_u32(buf, len, &off, ", \"hop_id\":", (uint32_t)(hop_id - 1));
  if(dist > 0)
    string_concat_u8(buf, len, &off, ", \"dist\":", dist);
  scamper_trace_pmtud_note_type_tostr(note, tmp, sizeof(tmp));
  string_concat3(buf, len, &off, ", \"type\":\"", tmp, "\"");

  if(note->reply != NULL)
    {
      if(SCAMPER_TRACE_REPLY_IS_ICMP_PTB(note->reply))
	string_concat_u16(buf, len, &off, ", \"icmp_nhmtu\":",
			  note->reply->reply_icmp_nhmtu);
      if(note->reply->addr != NULL)
	{
	  scamper_addr_tostr(note->reply->addr, tmp, sizeof(tmp));
	  string_concat3(buf, len, &off, ", \"addr\":\"", tmp, "\"");
	}
    }

  string_concatc(buf, len, &off, '}');

  return strdup(buf);
}

static size_t pmtud_header_tostr(const scamper_trace_pmtud_t *pmtud,
				 char *buf, size_t len)
{
  size_t off = 0;

  string_concat_u16(buf, len, &off, ", \"pmtud\":{\"if_mtu\":", pmtud->ifmtu);
  string_concat_u16(buf, len, &off, ", \"out_mtu\":",
		    pmtud->outmtu == 0 ? pmtud->ifmtu : pmtud->outmtu);
  string_concat_u16(buf, len, &off, ", \"path_mtu\":", pmtud->pmtu);
  string_concat_u16(buf, len, &off, ", \"probec\":", pmtud->probec);
  string_concat_u8(buf, len, &off, ", \"notec\":", pmtud->notec);

  return off;
}

static char *pmtud_tostr(const scamper_trace_t *trace)
{
  const scamper_trace_pmtud_t *pmtud = trace->pmtud;
  const scamper_trace_pmtud_note_t *note;
  const scamper_trace_probe_t *probe;
  const scamper_trace_reply_t *reply;
  size_t len, off, hops_hopc = 0, no_hopc = 0, h, nh, hop_id;
  char *str = NULL, hdr[256], **notes = NULL, **hops = NULL, **no_hops = NULL;
  uint16_t p, r;
  uint8_t n, d, dist, notec, x;
  int rc = -1;

  len = pmtud_header_tostr(pmtud, hdr, sizeof(hdr)) + 2; /* }\0 */

  notec = pmtud->notec; n = 0;
  if(pmtud->outmtu != 0 && notec > 0)
    {
      if(pmtud->notec == 0 || pmtud->notes == NULL ||
	 pmtud->notes[0] == NULL ||
	 pmtud->notes[0]->type != SCAMPER_TRACE_PMTUD_NOTE_TYPE_SILENCE)
	notec = 0;
      else
	n = 1;
    }

  if(notec > n && pmtud->notes != NULL)
    {
      len += 12; /* , "notes":[] */
      if((notes = malloc_zero(sizeof(char *) * notec)) == NULL)
	goto cleanup;
      x = 0; d = 1;
      while(n < notec)
	{
	  note = pmtud->notes[n++];
	  if(x > 0)
	    len++; /* , */
	  hop_id = pmtud_note_hopid(pmtud, note->reply);
	  dist = pmtud_note_dist(trace, d, note);
	  if((notes[x] = pmtud_note_tostr(note, dist, hop_id)) == NULL)
	    goto cleanup;
	  if(dist > 0)
	    d = dist;
	  len += strlen(notes[x]);
	  x++;
	}
    }

  if(pmtud->probec > 0)
    {
      for(p=0; p<pmtud->probec; p++)
	{
	  if((probe = pmtud->probes[p]) == NULL)
	    continue;
	  if(probe->replyc > 0)
	    hops_hopc += probe->replyc;
	  else
	    no_hopc++;
	}

      if(hops_hopc > 0)
	{
	  len += 11; /* , "hops":[] */
	  if((hops = malloc_zero(sizeof(char *) * hops_hopc)) == NULL)
	    goto cleanup;
	  len += (hops_hopc - 1); /* , */
	}

      if(no_hopc > 0)
	{
	  len += 14; /* , "no_hops":[] */
	  if((no_hops = malloc_zero(sizeof(char *) * no_hopc)) == NULL)
	    goto cleanup;
	  len += (no_hopc - 1); /* , */
	}

      h = nh = 0;
      for(p=0; p<pmtud->probec; p++)
	{
	  if((probe = pmtud->probes[p]) == NULL)
	    continue;
	  if(probe->replyc > 0)
	    {
	      for(r=0; r<probe->replyc; r++)
		{
		  reply = probe->replies[r];
		  if((hops[h] = hop_tostr(trace, probe, reply)) == NULL)
		    goto cleanup;
		  len += strlen(hops[h]);
		  h++;
		}
	    }
	  else
	    {
	      if((no_hops[nh] = probe_tostr(probe)) == NULL)
		goto cleanup;
	      len += strlen(no_hops[nh]);
	      nh++;
	    }
	}
    }

  if((str = malloc(len)) == NULL)
    goto cleanup;
  off = 0;
  string_concat(str, len, &off, hdr);
  if(notec > 0)
    {
      string_concat(str, len, &off, ", \"notes\":[");
      for(n=0; n<notec; n++)
	{
	  if(n > 0)
	    string_concatc(str, len, &off, ',');
	  string_concat(str, len, &off, notes[n]);
	}
      string_concatc(str, len, &off, ']');
    }

  if(hops_hopc > 0)
    {
      string_concat(str, len, &off, ", \"hops\":[");
      for(h=0; h<hops_hopc; h++)
	{
	  if(h > 0) string_concatc(str, len, &off, ',');
	  string_concat(str, len, &off, hops[h]);
	}
      string_concatc(str, len, &off, ']');
    }

  if(no_hopc > 0)
    {
      string_concat(str, len, &off, ", \"no_hops\":[");
      for(h=0; h<no_hopc; h++)
	{
	  if(h > 0) string_concatc(str, len, &off, ',');
	  string_concat(str, len, &off, no_hops[h]);
	}
      string_concatc(str, len, &off, ']');
    }

  string_concatc(str, len, &off, '}');
  assert(off + 1 == len);

  rc = 0;

 cleanup:
  if(no_hops != NULL)
    {
      for(h=0; h<no_hopc; h++)
	if(no_hops[h] != NULL)
	  free(no_hops[h]);
      free(no_hops);
    }
  if(hops != NULL)
    {
      for(h=0; h<hops_hopc; h++)
	if(hops[h] != NULL)
	  free(hops[h]);
      free(hops);
    }
  if(notes != NULL)
    {
      for(n=0; n<notec; n++)
	if(notes[n] != NULL)
	  free(notes[n]);
      free(notes);
    }
  if(rc != 0)
    {
      if(str != NULL) free(str);
      return NULL;
    }
  return str;
}

char *scamper_trace_tojson(const scamper_trace_t *trace, size_t *len_out)
{
  scamper_trace_probettl_t *pttl;
  scamper_trace_probe_t *probe;
  scamper_trace_reply_t *reply;
  size_t len, off = 0;
  char *str = NULL, *header = NULL, **hops = NULL, **no_hops = NULL;
  size_t h, nh, hopc = 0, hops_hopc = 0, extra_hopc = 0, no_hopc = 0;
  char *pmtud = NULL;
  uint16_t i, hop_count, r;
  uint8_t p;
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
    {
      if((pttl = trace->hops[i]) == NULL)
	continue;
      for(p=0; p<pttl->probec; p++)
	{
	  if((probe = pttl->probes[p]) == NULL)
	    continue;
	  if(probe->replyc > 0)
	    hops_hopc += probe->replyc;
	  else
	    no_hopc++;
	}
    }

  /* how many responses do we include in the extra_hops array */
  if(trace->stop_hop != 0)
    {
      while(i < trace->hop_count)
	{
	  if((pttl = trace->hops[i]) != NULL)
	    {
	      for(p=0; p<pttl->probec; p++)
		{
		  if((probe = pttl->probes[p]) == NULL)
		    continue;
		  extra_hopc += probe->replyc;
		}
	    }
	  i++;
	}
    }

  /* structure around hops arrays */
  if((hopc = hops_hopc + extra_hopc) > 0)
    {
      len += 11; /* , "hops":[] */
      if(extra_hopc > 0)
	len += 17; /* , "extra_hops":[] */
      if((hops = malloc_zero(sizeof(char *) * hopc)) == NULL)
	goto cleanup;

      /* comma separators for the two hops arrays */
      if(hops_hopc > 1)
	len += (hops_hopc - 1); /* , */
      if(extra_hopc > 1)
	len += (extra_hopc - 1); /* , */
    }

  /* structure around no_hops array */
  if(no_hopc > 0)
    {
      len += 14; /* , "no_hops":[] */
      if((no_hops = malloc_zero(sizeof(char *) * no_hopc)) == NULL)
	goto cleanup;
      len += (no_hopc - 1); /* , */
    }

  h = nh = 0;
  for(i=trace->firsthop-1; i<trace->hop_count; i++)
    {
      if((pttl = trace->hops[i]) == NULL)
	continue;
      for(p=0; p<pttl->probec; p++)
	{
	  if((probe = pttl->probes[p]) == NULL)
	    continue;
	  if(probe->replyc > 0)
	    {
	      for(r=0; r<probe->replyc; r++)
		{
		  reply = probe->replies[r];
		  if((hops[h] = hop_tostr(trace, probe, reply)) == NULL)
		    goto cleanup;
		  len += strlen(hops[h]);
		  h++;
		}
	    }
	  else
	    {
	      if((no_hops[nh] = probe_tostr(probe)) == NULL)
		goto cleanup;
	      len += strlen(no_hops[nh]);
	      nh++;
	    }
	}
    }

  if(trace->pmtud != NULL && trace->pmtud->ver == 2)
    {
      if((pmtud = pmtud_tostr(trace)) == NULL)
	goto cleanup;
      len += strlen(pmtud);
    }

  len += 3; /* {}\0 */

  if((str = malloc_zero(len)) == NULL)
    goto cleanup;

  str[off++] = '{';
  string_concat(str, len, &off, header);
  if(hopc > 0)
    {
      string_concat(str, len, &off, ", \"hops\":[");
      for(h=0; h<hops_hopc; h++)
	{
	  if(h > 0) string_concatc(str, len, &off, ',');
	  string_concat(str, len, &off, hops[h]);
	}
      string_concatc(str, len, &off, ']');
    }

  if(extra_hopc > 0)
    {
      string_concat(str, len, &off, ", \"extra_hops\":[");
      for(h=0; h<extra_hopc; h++)
	{
	  if(h > 0) string_concatc(str, len, &off, ',');
	  string_concat(str, len, &off, hops[hops_hopc + h]);
	}
      string_concatc(str, len, &off, ']');
    }

  if(no_hopc > 0)
    {
      string_concat(str, len, &off, ", \"no_hops\":[");
      for(h=0; h<no_hopc; h++)
	{
	  if(h > 0) string_concatc(str, len, &off, ',');
	  string_concat(str, len, &off, no_hops[h]);
	}
      string_concatc(str, len, &off, ']');
    }

  if(pmtud != NULL)
    string_concat(str, len, &off, pmtud);

  string_concatc(str, len, &off, '}');
  assert(off+1 == len);

  rc = 0;

 cleanup:
  if(hops != NULL)
    {
      for(h=0; h<hopc; h++)
	if(hops[h] != NULL)
	  free(hops[h]);
      free(hops);
    }
  if(no_hops != NULL)
    {
      for(h=0; h<no_hopc; h++)
	if(no_hops[h] != NULL)
	  free(no_hops[h]);
      free(no_hops);
    }
  if(header != NULL)
    free(header);
  if(pmtud != NULL)
    free(pmtud);

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
