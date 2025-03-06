/*
 * scamper_ping_json.c
 *
 * Copyright (c) 2005-2006 Matthew Luckie
 * Copyright (c) 2006-2011 The University of Waikato
 * Copyright (c) 2011-2013 Internap Network Services Corporation
 * Copyright (c) 2013      Matthew Luckie
 * Copyright (c) 2013-2015 The Regents of the University of California
 * Copyright (c) 2019-2024 Matthew Luckie
 * Authors: Brian Hammond, Matthew Luckie
 *
 * $Id: scamper_ping_json.c,v 1.43 2024/12/31 04:17:31 mjl Exp $
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
#include "scamper_ifname.h"
#include "scamper_ifname_int.h"
#include "scamper_list.h"
#include "scamper_ping.h"
#include "scamper_ping_int.h"
#include "scamper_file.h"
#include "scamper_file_json.h"
#include "scamper_ping_json.h"

#include "utils.h"

static char *ping_header(const scamper_ping_t *ping)
{
  static const char *flags[] = {
    "v4rr", "spoof", "payload", "tsonly", "tsandaddr", "icmpsum", "dl", "tbt",
    "nosrc", "raw", "sockrx"
  };
  char buf[1024], tmp[512];
  size_t off = 0;
  uint8_t u8, c;

  string_concat3(buf, sizeof(buf), &off,
		 "{\"type\":\"ping\", \"version\":\"0.4\", \"method\":\"",
		 scamper_ping_method_tostr(ping, tmp, sizeof(tmp)), "\"");
  if(ping->src != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"src\":\"",
		   scamper_addr_tostr(ping->src, tmp, sizeof(tmp)), "\"");
  if(ping->dst != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"dst\":\"",
		   scamper_addr_tostr(ping->dst, tmp, sizeof(tmp)), "\"");
  if(ping->rtr != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"rtr\":\"",
		   scamper_addr_tostr(ping->rtr, tmp, sizeof(tmp)), "\"");
  string_concaf(buf, sizeof(buf), &off,
		", \"start\":{\"sec\":%ld,\"usec\":%d}",
		(long)ping->start.tv_sec, (int)ping->start.tv_usec);
  string_concaf(buf, sizeof(buf), &off,
		", \"stop_reason\":\"%s\", \"stop_data\":%u",
		scamper_ping_stop_tostr(ping, tmp, sizeof(tmp)),
		ping->stop_data);
  string_concaf(buf, sizeof(buf), &off,
		", \"ping_sent\":%u, \"probe_size\":%u"
		", \"userid\":%u, \"ttl\":%u, \"tos\":%u, \"wait\":%u",
		ping->ping_sent, ping->probe_size,
		ping->userid, ping->probe_ttl, ping->probe_tos,
		(uint32_t)ping->wait_probe.tv_sec);
  if(ping->wait_probe.tv_usec != 0)
    string_concaf(buf, sizeof(buf), &off, ", \"wait_us\":%u",
		  (uint32_t)ping->wait_probe.tv_usec);
  string_concaf(buf, sizeof(buf), &off, ", \"timeout\":%u",
		(uint32_t)ping->wait_timeout.tv_sec);
  if(ping->wait_timeout.tv_usec != 0)
    string_concaf(buf, sizeof(buf), &off, ", \"timeout_us\":%u",
		  (uint32_t)ping->wait_timeout.tv_usec);

  if(SCAMPER_PING_METHOD_IS_UDP(ping) || SCAMPER_PING_METHOD_IS_TCP(ping))
    string_concaf(buf, sizeof(buf), &off, ", \"sport\":%u, \"dport\":%u",
		  ping->probe_sport, ping->probe_dport);
  if(SCAMPER_PING_METHOD_IS_TCP(ping))
    string_concaf(buf, sizeof(buf), &off,
		  ", \"tcp_seq\":%u, \"tcp_ack\":%u",
		  ping->probe_tcpseq, ping->probe_tcpack);

  if(ping->probe_datalen > 0 && ping->probe_data != NULL)
    {
      string_concat3(buf, sizeof(buf), &off, ", \"",
		     (ping->flags & SCAMPER_PING_FLAG_PAYLOAD) != 0 ?
		     "payload" : "pattern", "\":\"");
      string_byte2hex(buf, sizeof(buf), &off,
		      ping->probe_data, ping->probe_datalen);
      string_concat(buf, sizeof(buf), &off, "\"");
    }

  if(ping->flags != 0)
    {
      c = 0;
      string_concat(buf, sizeof(buf), &off, ", \"flags\":[");
      for(u8=0; u8<sizeof(flags) / sizeof(char *); u8++)
	{
	  if((ping->flags & (0x1 << u8)) == 0)
	    continue;
	  if(c > 0)
	    string_concat(buf, sizeof(buf), &off, ",");
	  string_concat3(buf, sizeof(buf), &off, "\"", flags[u8], "\"");
	  c++;
	}
      string_concat(buf, sizeof(buf), &off, "]");
    }

  if(SCAMPER_PING_METHOD_IS_ICMP(ping) &&
     (ping->flags & SCAMPER_PING_FLAG_ICMPSUM) != 0)
    string_concaf(buf, sizeof(buf), &off,
		  ", \"icmp_csum\": %u",ping->probe_icmpsum);

  if(ping->probe_tsps != NULL)
    {
      string_concat(buf, sizeof(buf), &off, ", \"probe_tsps\":[");
      for(u8=0; u8<ping->probe_tsps->ipc; u8++)
	{
	  if(u8 > 0) string_concat(buf, sizeof(buf), &off, ",");
	  scamper_addr_tostr(ping->probe_tsps->ips[u8], tmp, sizeof(tmp));
	  string_concat3(buf, sizeof(buf), &off, "\"", tmp, "\"");
	}
      string_concat(buf, sizeof(buf), &off, "]");
    }

  return strdup(buf);
}

static void ping_probe_json(char *buf, size_t len, size_t *off,
			    const scamper_ping_t *ping,
			    const scamper_ping_probe_t *probe, int reply)
{
  uint16_t sport, dport;
  char *pt = "bug";
  size_t off2;
  char tmp[64];

  string_concaf(buf, len, off, "%c\"seq\":%u",
		reply == 0 ? '{' : ',', probe->id);

  if(reply == 0)
    {
      off2 = 0;
      if(probe->flags & SCAMPER_PING_REPLY_FLAG_DLTX)
	string_concat(tmp, sizeof(tmp), &off2, "\"dltxts\"");
      if(probe->flags & SCAMPER_PING_REPLY_FLAG_PENDING)
	string_concat2(tmp, sizeof(tmp), &off2,
		       off2 != 0 ? ", " : "", "\"pending\"");
      if(off2 != 0)
	string_concat3(buf, len, off, ", \"probe_flags\":[", tmp, "]");
    }

  if(probe->tx.tv_sec != 0)
    {
      string_concaf(buf, len, off, ", \"tx\":{\"sec\":%ld, \"usec\":%d}",
		    (long)probe->tx.tv_sec, (int)probe->tx.tv_usec);
    }

  if(SCAMPER_PING_METHOD_IS_ICMP(ping))
    {
      string_concaf(buf, len, off, ", \"icmp_id\":%u, \"icmp_seq\":%u",
		    ping->probe_sport, ping->probe_dport + probe->id);
    }
  else
    {
      if(SCAMPER_PING_METHOD_IS_UDP(ping))
	pt = "udp";
      else
	pt = "tcp";

      if(probe->sport == 0)
	{
	  sport = ping->probe_sport;
	  if(SCAMPER_PING_METHOD_IS_VARY_SPORT(ping))
	    sport += probe->id;
	}
      else sport = probe->sport;

      dport = ping->probe_dport;
      if(SCAMPER_PING_METHOD_IS_VARY_DPORT(ping))
	dport += probe->id;

      string_concaf(buf, len, off, ", \"%s_sport\":%u, \"%s_dport\":%u",
		    pt, sport, pt, dport);
    }

  if(probe->flags & SCAMPER_PING_REPLY_FLAG_PROBE_IPID)
    string_concaf(buf, len, off, ", \"probe_ipid\":%u", probe->ipid);

  if(reply == 0)
    string_concat(buf, len, off, "}");

  return;
}

static char *ping_probe(const scamper_ping_t *ping,
			const scamper_ping_probe_t *probe)
{
  char buf[512];
  size_t off = 0;
  ping_probe_json(buf, sizeof(buf), &off, ping, probe, 0);
  return strdup(buf);
}

static char *ping_reply_proto(const scamper_ping_reply_t *reply,
			     char *buf, size_t len)
{
  if(reply->reply_proto == IPPROTO_ICMP || reply->reply_proto == IPPROTO_ICMPV6)
    snprintf(buf, len, "\"icmp\"");
  else if(reply->reply_proto == IPPROTO_TCP)
    snprintf(buf, len, "\"tcp\"");
  else if(reply->reply_proto == IPPROTO_UDP)
    snprintf(buf, len, "\"udp\"");
  else
    snprintf(buf, len, "%d", reply->reply_proto);
  return buf;
}

static char *ping_reply(const scamper_ping_t *ping,
			const scamper_ping_probe_t *probe,
			const scamper_ping_reply_t *reply)
{
  scamper_ping_reply_v4rr_t *v4rr;
  scamper_ping_reply_v4ts_t *v4ts;
  struct timeval tv;
  char buf[512], tmp[64];
  uint8_t i;
  size_t off = 0, off2;

  string_concaf(buf, sizeof(buf), &off, "{\"from\":\"%s\"",
		scamper_addr_tostr(reply->addr, tmp, sizeof(tmp)));
  string_concaf(buf, sizeof(buf), &off,", \"reply_size\":%u, \"reply_ttl\":%u",
		reply->reply_size, reply->reply_ttl);
  string_concat2(buf, sizeof(buf), &off, ", \"reply_proto\":",
		 ping_reply_proto(reply, tmp, sizeof(tmp)));

  ping_probe_json(buf, sizeof(buf), &off, ping, probe, 1);

  if(reply->ifname != NULL && reply->ifname->ifname != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"ifname\":\"",
		   reply->ifname->ifname, "\"");

  if(reply->flags != 0)
    {
      tmp[0] = '\0'; off2 = 0;
      if(reply->flags & SCAMPER_PING_REPLY_FLAG_DLTX)
	string_concat(tmp, sizeof(tmp), &off2, "\"dltxts\"");
      if(reply->flags & SCAMPER_PING_REPLY_FLAG_DLRX)
	string_concat2(tmp, sizeof(tmp), &off2,
		       off2 != 0 ? ", " : "", "\"dlrxts\"");
      if(off2 != 0)
	string_concat3(buf, sizeof(buf), &off, ", \"reply_flags\":[",tmp,"]");
    }

  if(probe->tx.tv_sec != 0)
    {
      timeval_add_tv3(&tv, &probe->tx, &reply->rtt);
      string_concaf(buf, sizeof(buf), &off,
		    ", \"rx\":{\"sec\":%ld, \"usec\":%d}",
		    (long)tv.tv_sec, (int)tv.tv_usec);
    }
  string_concat2(buf, sizeof(buf), &off, ", \"rtt\":",
		 timeval_tostr_us(&reply->rtt, tmp, sizeof(tmp)));

  if(SCAMPER_ADDR_TYPE_IS_IPV4(reply->addr))
    {
      string_concaf(buf, sizeof(buf), &off, ", \"reply_ipid\":%u",
		    reply->reply_ipid);
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(reply->addr) &&
	  (reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID) != 0)
    {
      string_concaf(buf, sizeof(buf), &off,
		    ", \"reply_ipid\":%u", reply->reply_ipid32);
    }

  if(reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_TOS)
    string_concaf(buf, sizeof(buf), &off,
		  ", \"reply_tos\":%u", reply->reply_tos);

  if(SCAMPER_PING_REPLY_IS_ICMP(reply))
    {
      string_concaf(buf, sizeof(buf), &off,
		    ", \"icmp_type\":%u, \"icmp_code\":%u",
		    reply->icmp_type, reply->icmp_code);
    }
  else if(SCAMPER_PING_REPLY_IS_TCP(reply))
    {
      string_concaf(buf, sizeof(buf), &off, ", \"tcp_flags\":%u",
		    reply->tcp_flags);
    }

  if((v4rr = reply->v4rr) != NULL)
    {
      string_concat(buf, sizeof(buf), &off, ", \"RR\":[");
      for(i=0; i<v4rr->ipc; i++)
	{
	  if(i > 0) string_concat(buf, sizeof(buf), &off, ",");
	  scamper_addr_tostr(v4rr->ip[i], tmp, sizeof(tmp));
	  string_concat3(buf, sizeof(buf), &off, "\"", tmp, "\"");
	}
      string_concat(buf, sizeof(buf), &off, "]");
    }

  if((v4ts = reply->v4ts) != NULL)
    {
      if((ping->flags & SCAMPER_PING_FLAG_TSONLY) == 0)
	{
	  string_concat(buf, sizeof(buf), &off, ", \"tsandaddr\":[");
	  for(i=0; i<v4ts->tsc; i++)
	    {
	      if(i > 0) string_concat(buf, sizeof(buf), &off, ",");
	      string_concaf(buf,sizeof(buf),&off, "{\"ip\":\"%s\",\"ts\":%u}",
			    scamper_addr_tostr(v4ts->ips[i], tmp, sizeof(tmp)),
			    v4ts->tss[i]);
	    }
	  string_concat(buf, sizeof(buf), &off, "]");
	}
      else
	{
	  string_concat(buf, sizeof(buf), &off, ", \"tsonly\":[");
	  for(i=0; i<v4ts->tsc; i++)
	    {
	      if(i > 0) string_concat(buf, sizeof(buf), &off, ",");
	      string_concaf(buf, sizeof(buf), &off, "%u", v4ts->tss[i]);
	    }
	  string_concat(buf, sizeof(buf), &off, "]");
	}
    }

  string_concat(buf, sizeof(buf), &off, "}");

  return strdup(buf);
}

static char *ping_stats(const scamper_ping_t *ping)
{
  scamper_ping_stats_t *stats;
  char buf[512], str[64], *dup;
  size_t off = 0;

  if((stats = scamper_ping_stats_alloc(ping)) == NULL)
    return NULL;

  string_concaf(buf, sizeof(buf), &off, "\"statistics\":{\"replies\":%d",
		stats->nreplies);

  if(ping->ping_sent != 0)
    {
      string_concat(buf, sizeof(buf), &off, ", \"loss\":");
      if(stats->nloss == 0)
	string_concat(buf, sizeof(buf), &off, "0");
      else if(stats->nreplies == 0)
	string_concat(buf, sizeof(buf), &off, "1");
      else
	string_concaf(buf, sizeof(buf), &off, "%.2f",
		      (float)(ping->ping_sent - stats->nreplies)
		      / ping->ping_sent);
    }
  if(stats->nreplies > 0)
    {
      string_concat2(buf, sizeof(buf), &off, ", \"min\":",
		     timeval_tostr_us(&stats->min_rtt, str, sizeof(str)));
      string_concat2(buf, sizeof(buf), &off, ", \"max\":",
		     timeval_tostr_us(&stats->max_rtt, str, sizeof(str)));
      string_concat2(buf, sizeof(buf), &off, ", \"avg\":",
		     timeval_tostr_us(&stats->avg_rtt, str, sizeof(str)));
      string_concat2(buf, sizeof(buf), &off, ", \"stddev\":",
		     timeval_tostr_us(&stats->stddev_rtt, str, sizeof(str)));
    }
  if(stats->ndups > 0)
    string_concaf(buf, sizeof(buf), &off, ", \"ndups\":%d", stats->ndups);
  if(stats->nerrs > 0)
    string_concaf(buf, sizeof(buf), &off, ", \"nerrs\":%d", stats->nerrs);

  string_concat(buf, sizeof(buf), &off, "}");
  dup = strdup(buf);
  scamper_ping_stats_free(stats);

  return dup;
}

char *scamper_ping_tojson(const scamper_ping_t *ping, size_t *len_out)
{
  scamper_ping_probe_t *probe;
  scamper_ping_reply_t *reply;
  char     *header      = NULL;
  size_t    header_len  = 0;
  uint32_t  replyc      = 0;
  char    **replies     = NULL;
  size_t   *reply_lens  = NULL;
  char    **noreplies   = NULL;
  size_t   *noreply_lens = NULL;
  uint16_t  noreplyc    = 0;
  char     *stats       = NULL;
  size_t    stats_len   = 0;
  char     *str         = NULL;
  size_t    len         = 0;
  size_t    wc          = 0;
  int       rc          = -1;
  uint32_t  i, j, k;

  /* get the header string */
  if((header = ping_header(ping)) == NULL)
    goto cleanup;
  len = (header_len = strlen(header));

  for(i=0; i<ping->ping_sent; i++)
    {
      if((probe = ping->probes[i]) == NULL)
	continue;
      if(probe->replyc > 0)
	replyc += probe->replyc;
      else
	noreplyc++;
    }

  /* put together a string for each reply */
  len += 15; /* , \"responses\":[" */
  if(replyc > 0)
    {
      if((replies    = malloc_zero(sizeof(char *) * replyc)) == NULL ||
	 (reply_lens = malloc_zero(sizeof(size_t) * replyc)) == NULL)
	{
	  goto cleanup;
	}

      k = 0;
      for(i=0; i<ping->ping_sent; i++)
	{
	  if((probe = ping->probes[i]) == NULL)
	    continue;

	  for(j=0; j<probe->replyc; j++)
	    {
	      /* build string representation of this reply */
	      reply = probe->replies[j];
	      if((replies[k] = ping_reply(ping, probe, reply)) == NULL)
		goto cleanup;
	      len += (reply_lens[k] = strlen(replies[k]));
	      if(k > 0) len++; /* , */
	      k++;
	    }
	}
    }
  len += 2; /* ], */

  /* put together a string for each probe without a reply */
  len += 16; /* \"no_responses\":[" */
  if(noreplyc > 0)
    {
      if((noreplies    = malloc_zero(sizeof(char *) * noreplyc)) == NULL ||
	 (noreply_lens = malloc_zero(sizeof(size_t) * noreplyc)) == NULL)
	goto cleanup;

      k = 0;
      for(i=0; i<ping->ping_sent; i++)
	{
	  if((probe = ping->probes[i]) == NULL || probe->replyc > 0)
	    continue;

	  /* build string representation of this probe */
	  if((noreplies[k] = ping_probe(ping, probe)) == NULL)
	    goto cleanup;
	  len += (noreply_lens[k] = strlen(noreplies[k]));
	  if(k > 0)
	    len++; /* , */
	  k++;
	}
    }
  len += 2; /* ], */

  /* put together a string for the ping statistics */
  if((stats = ping_stats(ping)) != NULL)
    len += (stats_len = strlen(stats));
  len += 2; /* }\0 */

  if((str = malloc_zero(len)) == NULL)
    goto cleanup;
  memcpy(str+wc, header, header_len); wc += header_len;
  memcpy(str+wc, ", \"responses\":[", 15); wc += 15;
  for(i=0; i < replyc; i++)
    {
      if(i > 0)
	str[wc++] = ',';
      memcpy(str+wc, replies[i], reply_lens[i]);
      wc += reply_lens[i];
    }
  memcpy(str+wc, "],", 2); wc += 2;

  memcpy(str+wc, "\"no_responses\":[", 16); wc += 16;
  for(i=0; i < noreplyc; i++)
    {
      if(i > 0)
	str[wc++] = ',';
      memcpy(str+wc, noreplies[i], noreply_lens[i]);
      wc += noreply_lens[i];
    }
  memcpy(str+wc, "],", 2); wc += 2;

  if(stats != NULL)
    {
      memcpy(str+wc, stats, stats_len);
      wc += stats_len;
    }
  memcpy(str+wc, "}\0", 2); wc += 2;

  assert(wc == len);
  rc = 0;

 cleanup:
  if(header != NULL) free(header);
  if(stats != NULL) free(stats);
  if(reply_lens != NULL) free(reply_lens);
  if(replies != NULL)
    {
      for(i=0; i < replyc; i++)
	if(replies[i] != NULL)
	  free(replies[i]);
      free(replies);
    }
  if(noreply_lens != NULL) free(noreply_lens);
  if(noreplies != NULL)
    {
      for(i=0; i < noreplyc; i++)
	if(noreplies[i] != NULL)
	  free(noreplies[i]);
      free(noreplies);
    }

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

int scamper_file_json_ping_write(const scamper_file_t *sf,
				 const scamper_ping_t *ping, void *p)
{
  char *str;
  size_t len;
  int rc;

  if((str = scamper_ping_tojson(ping, &len)) == NULL)
    return -1;
  str[len-1] = '\n';
  rc = json_write(sf, str, len, p);
  free(str);

  return rc;
}
