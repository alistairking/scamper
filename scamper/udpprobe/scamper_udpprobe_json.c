/*
 * scamper_udpprobe_json.c
 *
 * Author: Matthew Luckie
 *
 * $Id$
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

static char *reply_tostr(const scamper_udpprobe_t *up,
			 const scamper_udpprobe_reply_t *ur)
{
  struct timeval rtt;
  char buf[(65536 * 2) + 512];
  size_t off = 0;
  uint16_t i;

  timeval_diff_tv(&rtt, &up->start, &ur->tv);
  string_concat(buf, sizeof(buf), &off, "{\"rx\":{\"sec\":%ld,\"usec\":%d}",
		(long)ur->tv.tv_sec, (int)ur->tv.tv_usec);
  string_concat(buf, sizeof(buf), &off, ", \"rtt\":{\"sec\":%ld,\"usec\":%d}",
		(long)rtt.tv_sec, (int)rtt.tv_usec);
  string_concat(buf, sizeof(buf), &off, ", \"len\":%u, \"data\":\"", ur->len);
  for(i=0; i<ur->len; i++)
    string_concat(buf, sizeof(buf), &off, "%02x", ur->data[i]);
  string_concat(buf, sizeof(buf), &off, "\"}");

  return strdup(buf);
}

static char *header_tostr(const scamper_udpprobe_t *up)
{
  static const char *stop_m[] = {"none", "done", "halted", "error"};
  char buf[4096], tmp[512];
  size_t off = 0;
  uint16_t i;

  string_concat(buf, sizeof(buf), &off,
		"{\"type\":\"udpprobe\", \"version\":\"0.1\"");
  if(up->src != NULL)
    string_concat(buf, sizeof(buf), &off, ", \"src\":\"%s\"",
		  scamper_addr_tostr(up->src, tmp, sizeof(tmp)));
  if(up->dst != NULL)
    string_concat(buf, sizeof(buf), &off, ", \"dst\":\"%s\"",
		  scamper_addr_tostr(up->dst, tmp, sizeof(tmp)));
  string_concat(buf, sizeof(buf), &off,
		", \"userid\":%u, \"start\":{\"sec\":%ld,\"usec\":%d}",
		up->userid, (long)up->start.tv_sec, (int)up->start.tv_usec);
  string_concat(buf, sizeof(buf), &off,
		", \"sport\":%u, \"dport\":%u", up->sport, up->dport);
  string_concat(buf, sizeof(buf), &off,
		", \"wait_timeout\":{\"sec\":%ld,\"usec\":%d}",
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
  for(i=0; i<up->len; i++)
    string_concat(buf, sizeof(buf), &off, "%02x", up->data[i]);
  string_concat(buf, sizeof(buf), &off, "\", \"len\":%u", up->len);

  string_concat(buf, sizeof(buf), &off, ", \"replyc\":%u", up->replyc);

  return strdup(buf);
}

int scamper_file_json_udpprobe_write(const scamper_file_t *sf,
				     const scamper_udpprobe_t *up, void *p)
{
  char *header = NULL, *str = NULL;
  char **replies = NULL; size_t *reply_lens = NULL;
  size_t len = 0, header_len = 0;
  size_t wc = 0;
  int ret = -1;
  uint8_t i;

  /* get the header string */
  if((header = header_tostr(up)) == NULL)
    goto cleanup;
  len = (header_len = strlen(header));

  len += 13; /* , \"replies\":[ */

  if(up->replyc > 0)
    {
      if((replies = malloc_zero(sizeof(char *) * up->replyc)) == NULL ||
	 (reply_lens = malloc_zero(sizeof(size_t) * up->replyc)) == NULL)
	goto cleanup;
      for(i=0; i<up->replyc; i++)
	{
	  if(i > 0) len++; /* , */
	  if((replies[i] = reply_tostr(up, up->replies[i])) == NULL)
	    goto cleanup;
	  len += (reply_lens[i] = strlen(replies[i]));
	}
    }

  len += 3; /* ]}\n */

  if((str = malloc_zero(len)) == NULL)
    goto cleanup;
  memcpy(str+wc, header, header_len); wc += header_len;
  memcpy(str+wc, ", \"replies\":[", 13); wc += 13;

  for(i=0; i<up->replyc; i++)
    {
      if(i > 0)
	str[wc++] = ',';
      memcpy(str+wc, replies[i], reply_lens[i]);
      wc += reply_lens[i];
    }

  memcpy(str+wc, "]}\n", 3); wc += 3;

  assert(wc == len);
  ret = json_write(sf, str, len, p);

 cleanup:
  if(header != NULL) free(header);
  if(str != NULL) free(str);
  if(replies != NULL)
    {
      for(i=0; i<up->replyc; i++)
	if(replies[i] != NULL)
	  free(replies[i]);
      free(replies);
    }
  if(reply_lens != NULL) free(reply_lens);
  return ret;
}
