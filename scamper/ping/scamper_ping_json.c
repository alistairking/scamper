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
 * $Id: scamper_ping_json.c,v 1.39 2024/05/01 07:46:20 mjl Exp $
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
    "nosrc", "raw"
  };
  char buf[1024], tmp[512];
  size_t off = 0;
  uint8_t u8, c;

  string_concat(buf, sizeof(buf), &off,
		"{\"type\":\"ping\", \"version\":\"0.4\", \"method\":\"%s\"",
		scamper_ping_method_tostr(ping, tmp, sizeof(tmp)));
  if(ping->src != NULL)
    string_concat(buf, sizeof(buf), &off, ", \"src\":\"%s\"",
		  scamper_addr_tostr(ping->src, tmp, sizeof(tmp)));
  if(ping->dst != NULL)
    string_concat(buf, sizeof(buf), &off, ", \"dst\":\"%s\"",
		  scamper_addr_tostr(ping->dst, tmp, sizeof(tmp)));
  if(ping->rtr != NULL)
    string_concat(buf, sizeof(buf), &off, ", \"rtr\":\"%s\"",
		  scamper_addr_tostr(ping->rtr, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off,
		", \"start\":{\"sec\":%ld,\"usec\":%d}",
		(long)ping->start.tv_sec, (int)ping->start.tv_usec);
  string_concat(buf, sizeof(buf), &off,
		", \"ping_sent\":%u, \"probe_size\":%u"
		", \"userid\":%u, \"ttl\":%u, \"tos\":%u, \"wait\":%u",
		ping->ping_sent, ping->probe_size,
		ping->userid, ping->probe_ttl, ping->probe_tos,
		(uint32_t)ping->wait_probe.tv_sec);
  if(ping->wait_probe.tv_usec != 0)
    string_concat(buf, sizeof(buf), &off, ", \"wait_us\":%u",
		  (uint32_t)ping->wait_probe.tv_usec);
  string_concat(buf, sizeof(buf), &off, ", \"timeout\":%u",
		(uint32_t)ping->wait_timeout.tv_sec);
  if(ping->wait_timeout.tv_usec != 0)
    string_concat(buf, sizeof(buf), &off, ", \"timeout_us\":%u",
		  (uint32_t)ping->wait_timeout.tv_usec);

  if(SCAMPER_PING_METHOD_IS_UDP(ping) || SCAMPER_PING_METHOD_IS_TCP(ping))
    string_concat(buf, sizeof(buf), &off, ", \"sport\":%u, \"dport\":%u",
		  ping->probe_sport, ping->probe_dport);
  if(SCAMPER_PING_METHOD_IS_TCP(ping))
    string_concat(buf, sizeof(buf), &off,
		  ", \"tcp_seq\":%u, \"tcp_ack\":%u",
		  ping->probe_tcpseq, ping->probe_tcpack);

  if(ping->probe_datalen > 0 && ping->probe_data != NULL)
    {
      string_concat(buf, sizeof(buf), &off, ", \"%s\":\"",
		    (ping->flags & SCAMPER_PING_FLAG_PAYLOAD) != 0 ?
		    "payload" : "pattern");
      string_byte2hex(buf, sizeof(buf), &off,
		      ping->probe_data, ping->probe_datalen);
      string_concat(buf, sizeof(buf), &off, "\"");
    }

  if(ping->flags != 0)
    {
      c = 0;
      string_concat(buf, sizeof(buf), &off, ", \"flags\":[");
      for(u8=0; u8<10; u8++)
	{
	  if((ping->flags & (0x1 << u8)) == 0)
	    continue;
	  if(c > 0)
	    string_concat(buf, sizeof(buf), &off, ",");
	  string_concat(buf, sizeof(buf), &off, "\"%s\"", flags[u8]);
	  c++;
	}
      string_concat(buf, sizeof(buf), &off, "]");
    }

  if(SCAMPER_PING_METHOD_IS_ICMP(ping) &&
     (ping->flags & SCAMPER_PING_FLAG_ICMPSUM) != 0)
    string_concat(buf, sizeof(buf), &off,
		  ", \"icmp_csum\": %u",ping->probe_icmpsum);

  if(ping->probe_tsps != NULL)
    {
      string_concat(buf, sizeof(buf), &off, ", \"probe_tsps\":[");
      for(u8=0; u8<ping->probe_tsps->ipc; u8++)
	{
	  if(u8 > 0) string_concat(buf, sizeof(buf), &off, ",");
	  scamper_addr_tostr(ping->probe_tsps->ips[u8], tmp, sizeof(tmp));
	  string_concat(buf, sizeof(buf), &off, "\"%s\"", tmp);
	}
      string_concat(buf, sizeof(buf), &off, "]");
    }

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
			const scamper_ping_reply_t *reply)
{
  scamper_ping_reply_v4rr_t *v4rr;
  scamper_ping_reply_v4ts_t *v4ts;
  struct timeval tv;
  char buf[512], tmp[64], *pt = "bug";
  uint8_t i;
  size_t off = 0, off2;
  uint16_t sport, dport;

  string_concat(buf, sizeof(buf), &off, "{\"from\":\"%s\", \"seq\":%u",
		scamper_addr_tostr(reply->addr, tmp, sizeof(tmp)),
		reply->probe_id);
  string_concat(buf, sizeof(buf), &off,", \"reply_size\":%u, \"reply_ttl\":%u",
		reply->reply_size, reply->reply_ttl);
  string_concat(buf, sizeof(buf), &off, ", \"reply_proto\":%s",
		ping_reply_proto(reply, tmp, sizeof(tmp)));

  if(reply->ifname != NULL && reply->ifname->ifname != NULL)
    string_concat(buf, sizeof(buf), &off, ", \"ifname\":\"%s\"",
		  reply->ifname->ifname);

  if(reply->flags != 0)
    {
      tmp[0] = '\0'; off2 = 0;
      if(reply->flags & SCAMPER_PING_REPLY_FLAG_DLTX)
	string_concat(tmp, sizeof(tmp), &off2, "\"dltxts\"");
      if(reply->flags & SCAMPER_PING_REPLY_FLAG_DLRX)
	string_concat(tmp, sizeof(tmp), &off2, "%s\"dlrxts\"",
		      off2 != 0 ? ", " : "");
      if(off2 != 0)
	string_concat(buf, sizeof(buf), &off, ", \"reply_flags\":[%s]", tmp);
    }

  if(reply->tx.tv_sec != 0)
    {
      timeval_add_tv3(&tv, &reply->tx, &reply->rtt);
      string_concat(buf, sizeof(buf), &off,
		    ", \"tx\":{\"sec\":%ld, \"usec\":%d}",
		    (long)reply->tx.tv_sec, (int)reply->tx.tv_usec);
      string_concat(buf, sizeof(buf), &off,
		    ", \"rx\":{\"sec\":%ld, \"usec\":%d}",
		    (long)tv.tv_sec, (int)tv.tv_usec);
    }
  string_concat(buf, sizeof(buf), &off, ", \"rtt\":%s",
		timeval_tostr_us(&reply->rtt, tmp, sizeof(tmp)));

  if(SCAMPER_PING_METHOD_IS_ICMP(ping))
    {
      string_concat(buf, sizeof(buf), &off,
		    ", \"icmp_id\":%u, \"icmp_seq\":%u",
		    ping->probe_sport,
		    ping->probe_dport + reply->probe_id);
    }
  else
    {
      if(SCAMPER_PING_METHOD_IS_UDP(ping))
	pt = "udp";
      else
	pt = "tcp";

      if(reply->probe_sport == 0)
	{
	  sport = ping->probe_sport;
	  if(SCAMPER_PING_METHOD_IS_VARY_SPORT(ping))
	    sport += reply->probe_id;
	}
      else sport = reply->probe_sport;

      dport = ping->probe_dport;
      if(SCAMPER_PING_METHOD_IS_VARY_DPORT(ping))
	dport += reply->probe_id;

      string_concat(buf, sizeof(buf), &off,
		    ", \"%s_sport\":%u, \"%s_dport\":%u",
		    pt, sport, pt, dport);
    }

  if(SCAMPER_ADDR_TYPE_IS_IPV4(reply->addr))
    {
      string_concat(buf, sizeof(buf), &off,
		    ", \"probe_ipid\":%u, \"reply_ipid\":%u",
		    reply->probe_ipid, reply->reply_ipid);
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(reply->addr) &&
	  (reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID) != 0)
    {
      string_concat(buf, sizeof(buf), &off,
		    ", \"reply_ipid\":%u", reply->reply_ipid32);
    }

  if(reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_TOS)
    string_concat(buf, sizeof(buf), &off,
		  ", \"reply_tos\":%u", reply->reply_tos);

  if(SCAMPER_PING_REPLY_IS_ICMP(reply))
    {
      string_concat(buf, sizeof(buf), &off,
		    ", \"icmp_type\":%u, \"icmp_code\":%u",
		    reply->icmp_type, reply->icmp_code);
    }
  else if(SCAMPER_PING_REPLY_IS_TCP(reply))
    {
      string_concat(buf, sizeof(buf), &off, ", \"tcp_flags\":%u",
		    reply->tcp_flags);
    }

  if((v4rr = reply->v4rr) != NULL)
    {
      string_concat(buf, sizeof(buf), &off, ", \"RR\":[");
      for(i=0; i<v4rr->ipc; i++)
	{
	  if(i > 0) string_concat(buf, sizeof(buf), &off, ",");
	  string_concat(buf, sizeof(buf), &off, "\"%s\"",
			scamper_addr_tostr(v4rr->ip[i], tmp, sizeof(tmp)));
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
	      string_concat(buf,sizeof(buf),&off, "{\"ip\":\"%s\",\"ts\":%u}",
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
	      string_concat(buf, sizeof(buf), &off, "%u", v4ts->tss[i]);
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

  string_concat(buf, sizeof(buf), &off, "\"statistics\":{\"replies\":%d",
		stats->nreplies);

  if(ping->ping_sent != 0)
    {
      string_concat(buf, sizeof(buf), &off, ", \"loss\":");

      if(stats->nreplies == 0)
	string_concat(buf, sizeof(buf), &off, "1");
      else if(stats->nreplies == ping->ping_sent)
	string_concat(buf, sizeof(buf), &off, "0");
      else
	string_concat(buf, sizeof(buf), &off, "%.2f",
		      (float)(ping->ping_sent - stats->nreplies)
		      / ping->ping_sent);
    }
  if(stats->nreplies > 0)
    {
      string_concat(buf, sizeof(buf), &off, ", \"min\":%s",
		    timeval_tostr_us(&stats->min_rtt, str, sizeof(str)));
      string_concat(buf, sizeof(buf), &off, ", \"max\":%s",
		    timeval_tostr_us(&stats->max_rtt, str, sizeof(str)));
      string_concat(buf, sizeof(buf), &off, ", \"avg\":%s",
		    timeval_tostr_us(&stats->avg_rtt, str, sizeof(str)));
      string_concat(buf, sizeof(buf), &off, ", \"stddev\":%s",
		    timeval_tostr_us(&stats->stddev_rtt, str, sizeof(str)));
    }
  if(stats->ndups > 0)
    string_concat(buf, sizeof(buf), &off, ", \"ndups\":%d", stats->ndups);
  if(stats->nerrs > 0)
    string_concat(buf, sizeof(buf), &off, ", \"nerrs\":%d", stats->nerrs);

  string_concat(buf, sizeof(buf), &off, "}");
  dup = strdup(buf);
  scamper_ping_stats_free(stats);

  return dup;
}

int scamper_file_json_ping_write(const scamper_file_t *sf,
				 const scamper_ping_t *ping, void *p)
{
  scamper_ping_reply_t *reply;
  uint32_t  reply_count = scamper_ping_reply_total(ping);
  char     *header      = NULL;
  size_t    header_len  = 0;
  char    **replies     = NULL;
  size_t   *reply_lens  = NULL;
  char     *stats       = NULL;
  size_t    stats_len   = 0;
  char     *str         = NULL;
  size_t    len         = 0;
  size_t    wc          = 0;
  int       ret         = -1;
  uint32_t  i,j;

  /* get the header string */
  if((header = ping_header(ping)) == NULL)
    goto cleanup;
  len = (header_len = strlen(header));

  /* put together a string for each reply */
  len += 15; /* , \"responses\":[" */
  if(reply_count > 0)
    {
      if((replies    = malloc_zero(sizeof(char *) * reply_count)) == NULL ||
	 (reply_lens = malloc_zero(sizeof(size_t) * reply_count)) == NULL)
	{
	  goto cleanup;
	}

      for(i=0, j=0; i<ping->ping_sent; i++)
	{
	  reply = ping->ping_replies[i];
	  while(reply != NULL)
	    {
	      /* build string representation of this reply */
	      if((replies[j] = ping_reply(ping, reply)) == NULL)
		goto cleanup;
	      len += (reply_lens[j] = strlen(replies[j]));
	      if(j > 0) len++; /* , */
	      reply = reply->next;
	      j++;
	    }
	}
    }
  len += 2; /* ], */
  if((stats = ping_stats(ping)) != NULL)
    len += (stats_len = strlen(stats));
  len += 2; /* }\n */

  if((str = malloc_zero(len)) == NULL)
    goto cleanup;
  memcpy(str+wc, header, header_len); wc += header_len;
  memcpy(str+wc, ", \"responses\":[", 15); wc += 15;
  for(i=0; i<reply_count; i++)
    {
      if(i > 0)
	str[wc++] = ',';
      memcpy(str+wc, replies[i], reply_lens[i]);
      wc += reply_lens[i];
    }
  memcpy(str+wc, "],", 2); wc += 2;
  if(stats != NULL)
    {
      memcpy(str+wc, stats, stats_len);
      wc += stats_len;
    }
  memcpy(str+wc, "}\n", 2); wc += 2;

  assert(wc == len);
  ret = json_write(sf, str, len, p);

 cleanup:
  if(str != NULL) free(str);
  if(header != NULL) free(header);
  if(stats != NULL) free(stats);
  if(reply_lens != NULL) free(reply_lens);
  if(replies != NULL)
    {
      for(i=0; i<reply_count; i++)
	if(replies[i] != NULL)
	  free(replies[i]);
      free(replies);
    }

  return ret;
}
