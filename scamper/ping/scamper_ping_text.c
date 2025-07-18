/*
 * scamper_ping_text.c
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2014 The Regents of the University of California
 * Copyright (C) 2022-2024 Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_ping_text.c,v 1.30 2025/06/02 22:40:41 mjl Exp $
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
#include "scamper_ping.h"
#include "scamper_ping_int.h"
#include "scamper_file.h"
#include "scamper_ping_text.h"

#include "utils.h"

static char *ping_header(const scamper_ping_t *ping)
{
  char header[192], addr[64];
  size_t off = 0;

  string_concat(header, sizeof(header), &off, "ping");
  if(ping->src != NULL)
    string_concat2(header, sizeof(header), &off, " from ",
		   scamper_addr_tostr(ping->src, addr, sizeof(addr)));
  string_concat2(header, sizeof(header), &off, " to ",
		 scamper_addr_tostr(ping->dst, addr, sizeof(addr)));
  string_concat_u16(header, sizeof(header), &off, ": ", ping->size);
  string_concat(header, sizeof(header), &off, " byte packets\n");

  return strdup(header);
}

static char *tsreply_tostr(char *buf, size_t len, uint32_t val)
{
  uint32_t hh, mm, ss, ms;
  ms = val % 1000;
  ss = val / 1000;
  hh = ss / 3600; ss -= (hh * 3600);
  mm = ss / 60; ss -= (mm * 60);
  snprintf(buf, len, "%02d:%02d:%02d.%03d", hh, mm, ss, ms);
  return buf;
}

static char *ping_reply(const scamper_ping_t *ping,
			const scamper_ping_probe_t *probe,
			const scamper_ping_reply_t *reply)
{
  scamper_ping_reply_v4rr_t *v4rr;
  scamper_ping_reply_v4ts_t *v4ts;
  char buf[256], a[64], rtt[32], *tcp, flags[16], tso[32], tsr[32], tst[32];
  uint8_t i;
  size_t off = 0;

  scamper_addr_tostr(reply->addr, a, sizeof(a));
  timeval_tostr_us(&reply->rtt, rtt, sizeof(rtt));

  string_concaf(buf, sizeof(buf), &off, "%d bytes from %s, seq=%d ",
		reply->size, a, probe->id);

  if(SCAMPER_PING_REPLY_IS_ICMP(reply) || SCAMPER_PING_REPLY_IS_UDP(reply))
    {
      string_concaf(buf, sizeof(buf), &off, "ttl=%d time=%s ms",
		    reply->ttl, rtt);
    }

  if(SCAMPER_PING_REPLY_IS_ICMP(reply) && reply->tsreply != NULL)
    {
      string_concaf(buf, sizeof(buf), &off, " tso=%s tsr=%s tst=%s",
		    tsreply_tostr(tso, sizeof(tso), reply->tsreply->tso),
		    tsreply_tostr(tsr, sizeof(tsr), reply->tsreply->tsr),
		    tsreply_tostr(tst, sizeof(tst), reply->tsreply->tst));
    }
  else if(SCAMPER_PING_REPLY_IS_TCP(reply))
    {
      if((reply->tcp_flags & TH_RST) != 0)
	{
	  tcp = "closed";
	}
      else if((reply->tcp_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))
	{
	  if((reply->tcp_flags & TH_ECE) != 0)
	    tcp = "open,ecn";
	  else
	    tcp = "open";
	}
      else
	{
	  snprintf(flags, sizeof(flags), "%0x02x", reply->tcp_flags);
	  tcp = flags;
	}

      string_concaf(buf, sizeof(buf), &off, "tcp=%s ttl=%d time=%s ms",
		    tcp, reply->ttl, rtt);
    }
  string_concat(buf, sizeof(buf), &off, "\n");

  if((v4rr = reply->v4rr) != NULL)
    {
      string_concat3(buf, sizeof(buf), &off, " RR: ",
		     scamper_addr_tostr(v4rr->ip[0], a, sizeof(a)), "\n");
      for(i=1; i<v4rr->ipc; i++)
	string_concat3(buf, sizeof(buf), &off, "     ",
		       scamper_addr_tostr(v4rr->ip[i], a, sizeof(a)), "\n");
    }

  if((v4ts = reply->v4ts) != NULL && v4ts->tsc > 0)
    {
      string_concat(buf, sizeof(buf), &off, " TS: ");
      if(v4ts->ips != NULL)
	string_concaf(buf, sizeof(buf), &off, "%-15s ",
		      scamper_addr_tostr(v4ts->ips[0], a, sizeof(a)));
      string_concaf(buf, sizeof(buf), &off, "%d\n", v4ts->tss[0]);

      for(i=1; i<v4ts->tsc; i++)
	{
	  string_concat(buf, sizeof(buf), &off, "     ");
	  if(v4ts->ips != NULL)
	    string_concaf(buf, sizeof(buf), &off, "%-15s ",
			  scamper_addr_tostr(v4ts->ips[i], a, sizeof(a)));
	  string_concaf(buf, sizeof(buf), &off, "%d\n", v4ts->tss[i]);
	}
    }

  return strdup(buf);
}

static char *ping_stats(const scamper_ping_t *ping)
{
  scamper_ping_stats_t *stats;
  size_t off = 0;
  uint32_t total;
  char str[64], *dup;
  char buf[512];

  if((stats = scamper_ping_stats_alloc(ping)) == NULL)
    return NULL;

  string_concat3(buf, sizeof(buf), &off, "--- ",
		 scamper_addr_tostr(ping->dst, str, sizeof(str)),
		 " ping statistics ---\n");
  string_concaf(buf, sizeof(buf), &off,
		"%d packets transmitted, %d packets received",
		ping->ping_sent, stats->nreplies);
  if(stats->ndups > 0)
    string_concaf(buf, sizeof(buf), &off, ", +%d duplicates", stats->ndups);
  if(stats->nerrs > 0)
    string_concaf(buf, sizeof(buf), &off, ", +%d errors", stats->nerrs);
  if(stats->npend > 0)
    string_concaf(buf, sizeof(buf), &off, ", +%d pending", stats->npend);

  if(ping->ping_sent > stats->npend)
    {
      total = ping->ping_sent - stats->npend;
      string_concaf(buf, sizeof(buf), &off, ", %d%% packet loss",
		    ((total - stats->nreplies) * 100) / total);
    }
  string_concatc(buf, sizeof(buf), &off, '\n');

  if(stats->nreplies > 0)
    {
      string_concat(buf, sizeof(buf), &off, "round-trip min/avg/max/stddev =");
      string_concat2(buf, sizeof(buf), &off, " ",
		     timeval_tostr_us(&stats->min_rtt, str, sizeof(str)));
      string_concat2(buf, sizeof(buf), &off, "/",
		     timeval_tostr_us(&stats->avg_rtt, str, sizeof(str)));
      string_concat2(buf, sizeof(buf), &off, "/",
		     timeval_tostr_us(&stats->max_rtt, str, sizeof(str)));
      string_concat3(buf, sizeof(buf), &off, "/",
		     timeval_tostr_us(&stats->stddev_rtt, str, sizeof(str)),
		     " ms\n");
    }

  dup = strdup(buf);
  scamper_ping_stats_free(stats);

  return dup;
}

char *scamper_ping_totext(const scamper_ping_t *ping, size_t *len_out)
{
  scamper_ping_probe_t *probe;
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
  int       rc          = -1;
  uint32_t  i, j, k;

  /* get the header string */
  if((header = ping_header(ping)) == NULL)
    goto cleanup;
  len = (header_len = strlen(header));

  /* put together a string for each reply */
  if(reply_count > 0)
    {
      if((replies    = malloc_zero(sizeof(char *) * reply_count)) == NULL ||
	 (reply_lens = malloc_zero(sizeof(size_t) * reply_count)) == NULL)
	goto cleanup;

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
	      k++;
	    }
	}
    }

  /* put together the summary stats */
  stats = ping_stats(ping);
  if(stats != NULL)
    len += (stats_len = strlen(stats));

  /* allocate a string long enough to combine the above strings */
  if((str = malloc_zero(len)) == NULL)
    goto cleanup;

  /* combine the strings created above */
  memcpy(str+wc, header, header_len); wc += header_len;
  for(i=0; i<reply_count; i++)
    {
      memcpy(str+wc, replies[i], reply_lens[i]);
      wc += reply_lens[i];
    }

  if(stats != NULL)
    {
      memcpy(str+wc, stats, stats_len);
      wc += stats_len;
    }

  assert(wc > 0);
  assert(wc == len);

  /* remove the trailing \n */
  str[wc-1] = '\0';

  /* we succeeded */
  rc = 0;

 cleanup:
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

int scamper_file_text_ping_write(const scamper_file_t *sf,
				 const scamper_ping_t *ping, void *p)
{
  size_t wc, len;
  off_t off = 0;
  char *str = NULL;
  int fd, rc = -1;

  /* get current position incase trunction is required */
  fd = scamper_file_getfd(sf);
  if(fd != STDOUT_FILENO && (off = lseek(fd, 0, SEEK_CUR)) == -1)
    goto cleanup;

  if((str = scamper_ping_totext(ping, &len)) == NULL)
    goto cleanup;
  str[len-1] = '\n';

  /*
   * try and write the string to disk.  if it fails, then truncate the
   * write and fail
   */
  if(write_wrap(fd, str, &wc, len) != 0)
    {
      if(fd != STDOUT_FILENO)
	{
	  if(ftruncate(fd, off) != 0)
	    goto cleanup;
	}
      goto cleanup;
    }

  rc = 0;

 cleanup:
  if(str != NULL) free(str);
  return rc;
}
