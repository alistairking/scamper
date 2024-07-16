/*
 * scamper_udpprobe_json.c
 *
 * Author: Matthew Luckie
 *
 * $Id: scamper_udpprobe_json.c,v 1.3 2024/04/13 01:25:58 mjl Exp $
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
#include "scamper_list.h"
#include "scamper_udpprobe.h"
#include "scamper_udpprobe_int.h"
#include "scamper_file.h"
#include "scamper_file_json.h"
#include "scamper_udpprobe_json.h"

#include "utils.h"

static char *reply_tostr(const scamper_udpprobe_probe_t *probe,
			 const scamper_udpprobe_reply_t *reply,
			 size_t *len)
{
  struct timeval rtt;
  char buf[(65536 * 2) + 512];
  size_t off = 0;

  if(reply == NULL)
    {
      *len = 2;
      return strdup("{}");
    }

  timeval_diff_tv(&rtt, &probe->tx, &reply->rx);
  string_concat(buf, sizeof(buf), &off,
		"{\"rx\":{\"sec\":%ld,\"usec\":%d}"
		", \"rtt\":{\"sec\":%ld,\"usec\":%d}"
		", \"len\":%u, \"data\":\"",
		(long)reply->rx.tv_sec, (int)reply->rx.tv_usec,
		(long)rtt.tv_sec, (int)rtt.tv_usec,
		reply->len);
  string_byte2hex(buf, sizeof(buf), &off, reply->data, reply->len);
  string_concat(buf, sizeof(buf), &off, "\"}");

  *len = off;
  return strdup(buf);
}

static char *probe_tostr(const scamper_udpprobe_probe_t *probe)
{
  char header[256], **replies = NULL, *str = NULL, *rc = NULL;
  size_t len, wc = 0, header_len = 0, rl, *reply_lens = NULL;
  uint16_t i;

  if(probe == NULL)
    return strdup("{}");

  string_concat(header, sizeof(header), &header_len,
		"{\"tx\":{\"sec\":%ld,\"usec\":%d}, \"sport\":%u,"
		" \"replyc\":%u, \"replies\":[",
		(long)probe->tx.tv_sec, (int)probe->tx.tv_usec,
		probe->sport, probe->replyc);
  len = header_len;

  if(probe->replyc > 0)
    {
      if((replies = malloc_zero(sizeof(char *) * probe->replyc)) == NULL ||
	 (reply_lens = malloc_zero(sizeof(size_t) * probe->replyc)) == NULL)
	goto done;
      for(i=0; i<probe->replyc; i++)
	{
	  if(i > 0) len += 2; /* , */
	  if((replies[i] = reply_tostr(probe, probe->replies[i], &rl)) == NULL)
	    goto done;
	  reply_lens[i] = rl;
	  len += rl;
	}
    }
  len += 3; /* ]}\0 */

  if((str = malloc_zero(len)) == NULL)
    goto done;
  memcpy(str, header, header_len); wc += header_len;
  if(probe->replyc > 0)
    {
      for(i=0; i<probe->replyc; i++)
	{
	  if(i > 0)
	    {
	      memcpy(str+wc, ", ", 2);
	      wc += 2;
	    }
	  memcpy(str+wc, replies[i], reply_lens[i]);
	  wc += reply_lens[i];
	}
    }
  memcpy(str+wc, "]}\0", 3); wc += 3;
  assert(wc == len);

  rc = str;

 done:
  if(rc == NULL && str != NULL)
    free(str);
  if(replies != NULL) {
    for(i=0; i<probe->replyc; i++)
      if(replies[i] != NULL)
	free(replies[i]);
    free(replies);
  }
  if(reply_lens != NULL)
    free(reply_lens);
  return rc;
}

static char *header_tostr(const scamper_udpprobe_t *up)
{
  static const char *stop_m[] = {"none", "done", "halted", "error"};
  char buf[4096], tmp[512];
  size_t off = 0;

  string_concat(buf, sizeof(buf), &off,
		"{\"type\":\"udpprobe\", \"version\":\"0.1\"");
  if(up->src != NULL)
    string_concat(buf, sizeof(buf), &off, ", \"src\":\"%s\"",
		  scamper_addr_tostr(up->src, tmp, sizeof(tmp)));
  if(up->dst != NULL)
    string_concat(buf, sizeof(buf), &off, ", \"dst\":\"%s\"",
		  scamper_addr_tostr(up->dst, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off,
		", \"userid\":%u, \"start\":{\"sec\":%ld,\"usec\":%d}"
		", \"sport\":%u, \"dport\":%u"
		", \"wait_timeout\":{\"sec\":%ld,\"usec\":%d}",
		up->userid, (long)up->start.tv_sec, (int)up->start.tv_usec,
		up->sport, up->dport,
		(long)up->wait_timeout.tv_sec, (int)up->wait_timeout.tv_usec);

  if(up->flags & SCAMPER_UDPPROBE_FLAG_EXITFIRST)
    string_concat(buf, sizeof(buf), &off, ", \"flags\":[\"exitfirst\"]");

  string_concat(buf, sizeof(buf), &off, ", \"stop_reason\":\"");
  if(up->stop >= sizeof(stop_m) / sizeof(char *))
    string_concat(buf, sizeof(buf), &off, "%d", up->stop);
  else
    string_concat(buf, sizeof(buf), &off, "%s", stop_m[up->stop]);
  string_concat(buf, sizeof(buf), &off, "\"");

  string_concat(buf, sizeof(buf), &off, ", \"data\":\"");
  string_byte2hex(buf, sizeof(buf), &off, up->data, up->len);
  string_concat(buf, sizeof(buf), &off, "\", \"len\":%u", up->len);

  string_concat(buf, sizeof(buf), &off,
		", \"probe_count\":%u, \"probe_sent\":%u, \"stop_count\":%u",
		up->probe_count, up->probe_sent, up->stop_count);

  return strdup(buf);
}

int scamper_file_json_udpprobe_write(const scamper_file_t *sf,
				     const scamper_udpprobe_t *up, void *p)
{
  char *header = NULL, *str = NULL;
  char **probes = NULL; size_t *probe_lens = NULL;
  size_t len = 0, header_len = 0;
  size_t wc = 0;
  int ret = -1;
  uint8_t i;

  /* get the header string */
  if((header = header_tostr(up)) == NULL)
    goto cleanup;
  len = (header_len = strlen(header));

  len += 12; /* , \"probes\":[ */

  if(up->probe_sent > 0)
    {
      if((probes = malloc_zero(sizeof(char *) * up->probe_sent)) == NULL ||
	 (probe_lens = malloc_zero(sizeof(size_t) * up->probe_sent)) == NULL)
	goto cleanup;
      for(i=0; i<up->probe_sent; i++)
	{
	  if(i > 0) len++; /* , */
	  if((probes[i] = probe_tostr(up->probes[i])) == NULL)
	    goto cleanup;
	  len += (probe_lens[i] = strlen(probes[i]));
	}
    }

  len += 3; /* ]}\n */

  if((str = malloc_zero(len)) == NULL)
    goto cleanup;
  memcpy(str+wc, header, header_len); wc += header_len;
  memcpy(str+wc, ", \"probes\":[", 12); wc += 12;

  for(i=0; i<up->probe_sent; i++)
    {
      if(i > 0)
	str[wc++] = ',';
      memcpy(str+wc, probes[i], probe_lens[i]);
      wc += probe_lens[i];
    }

  memcpy(str+wc, "]}\n", 3); wc += 3;

  assert(wc == len);
  ret = json_write(sf, str, len, p);

 cleanup:
  if(header != NULL) free(header);
  if(str != NULL) free(str);
  if(probes != NULL)
    {
      for(i=0; i<up->probe_sent; i++)
	if(probes[i] != NULL)
	  free(probes[i]);
      free(probes);
    }
  if(probe_lens != NULL) free(probe_lens);
  return ret;
}
