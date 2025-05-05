/*
 * scamper_udpprobe_json.c
 *
 * Author: Matthew Luckie
 *
 * $Id: scamper_udpprobe_json.c,v 1.10 2025/05/03 09:01:57 mjl Exp $
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
#include "scamper_ifname.h"
#include "scamper_ifname_int.h"
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

  string_concat_u32(buf, sizeof(buf), &off, "{\"rx\":{\"sec\":",
		    (uint32_t)reply->rx.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ", \"usec\":",
		    (uint32_t)reply->rx.tv_usec);
  string_concat_u32(buf, sizeof(buf), &off, "}, \"rtt\":{\"sec\":",
		    (uint32_t)rtt.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ", \"usec\":",
		    (uint32_t)rtt.tv_usec);
  string_concat_u16(buf, sizeof(buf), &off, "}, \"len\":", reply->len);
  if(reply->data != NULL && reply->len > 0)
    {
      string_concat(buf, sizeof(buf), &off, ", \"data\":\"");
      string_byte2hex(buf, sizeof(buf), &off, reply->data, reply->len);
      string_concatc(buf, sizeof(buf), &off, '"');
    }
  if(reply->ifname != NULL && reply->ifname->ifname != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"ifname\":\"",
		   reply->ifname->ifname, "\"");
  string_concatc(buf, sizeof(buf), &off, '}');

  *len = off;
  return strdup(buf);
}

static char *probe_tostr(const scamper_udpprobe_probe_t *probe)
{
  char buf[256], **replies = NULL, *str = NULL, *rc = NULL;
  size_t off = 0, len, wc = 0, header_len = 0, rl, *reply_lens = NULL;
  uint16_t i;

  if(probe == NULL)
    return strdup("{}");

  string_concat_u32(buf, sizeof(buf), &off, "{\"tx\":{\"sec\":",
		    (uint32_t)probe->tx.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ", \"usec\":",
		    (uint32_t)probe->tx.tv_usec);
  string_concat_u16(buf, sizeof(buf), &off, "}, \"sport\":", probe->sport);
  string_concat_u16(buf, sizeof(buf), &off, ", \"replyc\":", probe->replyc);
  string_concat(buf, sizeof(buf), &off, ", \"replies\":[");

  len = header_len = off;

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
  memcpy(str, buf, header_len); wc += header_len;
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
  memcpy(str+wc, "]}", 3); wc += 3;
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
    string_concat3(buf, sizeof(buf), &off, ", \"src\":\"",
		   scamper_addr_tostr(up->src, tmp, sizeof(tmp)), "\"");
  if(up->dst != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"dst\":\"",
		   scamper_addr_tostr(up->dst, tmp, sizeof(tmp)), "\"");

  string_concat_u32(buf, sizeof(buf), &off, ", \"userid\":", up->userid);
  string_concat_u32(buf, sizeof(buf), &off, ", \"start\":{\"sec\":",
		    (uint32_t)up->start.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ", \"usec\":",
		    (uint32_t)up->start.tv_usec);
  string_concat_u16(buf, sizeof(buf), &off, "}, \"sport\":", up->sport);
  string_concat_u16(buf, sizeof(buf), &off, ", \"dport\":", up->dport);
  string_concat_u32(buf, sizeof(buf), &off, ", \"wait_timeout\":{\"sec\":",
		    (uint32_t)up->wait_timeout.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ", \"usec\":",
		    (uint32_t)up->wait_timeout.tv_usec);
  string_concatc(buf, sizeof(buf), &off, '}');

  if(up->flags & SCAMPER_UDPPROBE_FLAG_EXITFIRST)
    string_concat(buf, sizeof(buf), &off, ", \"flags\":[\"exitfirst\"]");

  if(up->stop >= sizeof(stop_m) / sizeof(char *))
    string_concat_u8(buf, sizeof(buf), &off, ", \"stop_reason\":\"", up->stop);
  else
    string_concat2(buf, sizeof(buf), &off, ", \"stop_reason\":\"",
		   stop_m[up->stop]);
  string_concatc(buf, sizeof(buf), &off, '"');

  if(up->data != NULL && up->len > 0)
    {
      string_concat(buf, sizeof(buf), &off, ", \"data\":\"");
      string_byte2hex(buf, sizeof(buf), &off, up->data, up->len);
      string_concatc(buf, sizeof(buf), &off, '"');
    }
  string_concat_u16(buf, sizeof(buf), &off, ", \"len\":", up->len);

  string_concat_u8(buf, sizeof(buf), &off, ", \"probe_count\":",
		   up->probe_count);
  string_concat_u8(buf, sizeof(buf), &off, ", \"probe_sent\":", up->probe_sent);
  string_concat_u8(buf, sizeof(buf), &off, ", \"stop_count\":", up->stop_count);

  return strdup(buf);
}

char *scamper_udpprobe_tojson(const scamper_udpprobe_t *up, size_t *len_out)
{
  char *header = NULL, *str = NULL;
  char **probes = NULL; size_t *probe_lens = NULL;
  size_t len = 0, header_len = 0, wc = 0;
  int rc = -1;
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
  len += 3; /* ]}\0 */

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

  memcpy(str+wc, "]}", 3); wc += 3;

  assert(wc == len);
  rc = 0;

 cleanup:
  if(header != NULL) free(header);
  if(probes != NULL)
    {
      for(i=0; i<up->probe_sent; i++)
	if(probes[i] != NULL)
	  free(probes[i]);
      free(probes);
    }
  if(probe_lens != NULL) free(probe_lens);

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

int scamper_file_json_udpprobe_write(const scamper_file_t *sf,
				     const scamper_udpprobe_t *up, void *p)
{
  char *str;
  size_t len;
  int rc;

  if((str = scamper_udpprobe_tojson(up, &len)) == NULL)
    return -1;
  str[len-1] = '\n';
  rc = json_write(sf, str, len, p);
  free(str);

  return rc;
}
