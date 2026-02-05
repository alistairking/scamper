/*
 * scamper_neighbourdisc_json.c
 *
 * $Id: scamper_neighbourdisc_json.c,v 1.3 2026/01/07 07:13:13 mjl Exp $
 *
 * Copyright (C) 2025-2026 Matthew Luckie
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
#include "scamper_neighbourdisc.h"
#include "scamper_neighbourdisc_int.h"
#include "scamper_file.h"
#include "scamper_file_json.h"
#include "scamper_neighbourdisc_json.h"

#include "utils.h"

static char *header_tostr(const scamper_neighbourdisc_t *nd)
{
  char buf[1024], tmp[512];
  size_t off = 0;
  int c = 0;

  string_concat3(buf, sizeof(buf), &off,
		 "{\"type\":\"neighbourdisc\", \"version\":\"0.1\", \"method\":\"",
		 scamper_neighbourdisc_method_tostr(nd, tmp, sizeof(tmp)), "\"");

  if(nd->src_ip != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"src_ip\":\"",
		   scamper_addr_tostr(nd->src_ip, tmp, sizeof(tmp)), "\"");

  if(nd->src_mac != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"src_mac\":\"",
		   scamper_addr_tostr(nd->src_mac, tmp, sizeof(tmp)), "\"");

  if(nd->dst_ip != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"dst_ip\":\"",
		   scamper_addr_tostr(nd->dst_ip, tmp, sizeof(tmp)), "\"");

  if(nd->dst_mac != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"dst_mac\":\"",
		   scamper_addr_tostr(nd->dst_mac, tmp, sizeof(tmp)), "\"");

  if(nd->ifname != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"ifname\":\"",
		   nd->ifname, "\"");

  string_concat_u32(buf, sizeof(buf), &off, ", \"userid\":", nd->userid);
  string_concat_u16(buf, sizeof(buf), &off, ", \"attempts\":", nd->attempts);
  string_concat_u16(buf, sizeof(buf), &off, ", \"stop_count\":", nd->replyc);

  string_concat_u32(buf, sizeof(buf), &off, ", \"start\":{\"sec\":",
		    (uint32_t)nd->start.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ", \"usec\":",
		    (uint32_t)nd->start.tv_usec);
  string_concatc(buf, sizeof(buf), &off, '}');

  string_concat_u32(buf, sizeof(buf), &off, ", \"wait_timeout\":{\"sec\":",
		    (uint32_t)nd->wait_timeout.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ", \"usec\":",
		    (uint32_t)nd->wait_timeout.tv_usec);
  string_concatc(buf, sizeof(buf), &off, '}');

  if(nd->errmsg != NULL)
    string_concat3(buf, sizeof(buf), &off, ",\"errmsg\":\"",
		   json_esc(nd->errmsg, tmp, sizeof(tmp)), "\"");

  if(nd->flags != 0)
    {
      string_concat(buf, sizeof(buf), &off, ", \"flags\":[");
      if(nd->flags & SCAMPER_NEIGHBOURDISC_FLAG_ALLATTEMPTS)
	{
	  if(c > 0) string_concatc(buf, sizeof(buf), &off, ',');
	  string_concat(buf, sizeof(buf), &off, "\"allattempts\"");
	  c++;
	}
      if(nd->flags & SCAMPER_NEIGHBOURDISC_FLAG_FIRSTRESPONSE)
	{
	  if(c > 0) string_concatc(buf, sizeof(buf), &off, ',');
	  string_concat(buf, sizeof(buf), &off, "\"firstresponse\"");
	  c++;
	}
      string_concatc(buf, sizeof(buf), &off, ']');
    }

  if(nd->list != NULL && nd->list->monitor != NULL)
    string_concat3(buf, sizeof(buf), &off, ",\"monitor\":\"",
		   json_esc(nd->list->monitor, tmp, sizeof(tmp)), "\"");

  return strdup(buf);
}

static char *reply_tostr(const scamper_neighbourdisc_reply_t *r,
			 size_t *len)
{
  char buf[512], tmp[128];
  size_t off = 0;

  string_concat_u32(buf, sizeof(buf), &off, "{\"rx\":{\"sec\":",
		    (uint32_t)r->rx.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ", \"usec\":",
		    (uint32_t)r->rx.tv_usec);
  string_concatc(buf, sizeof(buf), &off, '}');

  if(r->mac != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"mac\":\"",
		   scamper_addr_tostr(r->mac, tmp, sizeof(tmp)), "\"");

  string_concatc(buf, sizeof(buf), &off, '}');

  *len = off;
  return strdup(buf);
}

static char *probe_tostr(const scamper_neighbourdisc_probe_t *p, size_t *len_out)
{
  char buf[128], **replies = NULL, *str = NULL, *rc = NULL;
  size_t off = 0, len, wc = 0, header_len = 0, rl, *reply_lens = NULL;
  uint16_t i;

  string_concat_u32(buf, sizeof(buf), &off, "{\"tx\":{\"sec\":",
		    (uint32_t)p->tx.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ", \"usec\":",
		    (uint32_t)p->tx.tv_usec);
  string_concat_u16(buf, sizeof(buf), &off, "}, \"replyc\":", p->rxc);
  string_concat(buf, sizeof(buf), &off, ", \"replies\":[");

  len = header_len = off;

  if(p->rxc > 0)
    {
      if((replies = malloc_zero(sizeof(char *) * p->rxc)) == NULL ||
	 (reply_lens = malloc_zero(sizeof(size_t) * p->rxc)) == NULL)
	goto done;
      for(i=0; i<p->rxc; i++)
	{
	  if(i > 0) len++; /* , */
	  if((replies[i] = reply_tostr(p->rxs[i], &rl)) == NULL)
	    goto done;
	  reply_lens[i] = rl;
	  len += rl;
	}
    }
  len += 2; /* ]} */

  if((str = malloc_zero(len)) == NULL)
    goto done;
  memcpy(str, buf, header_len); wc += header_len;
  if(p->rxc > 0)
    {
      for(i=0; i<p->rxc; i++)
	{
	  if(i > 0)
	    str[wc++] = ',';
	  memcpy(str+wc, replies[i], reply_lens[i]);
	  wc += reply_lens[i];
	}
    }
  memcpy(str+wc, "]}", 2); wc += 2;
  assert(wc == len);

  rc = str;
  *len_out = wc;

 done:
  if(rc == NULL && str != NULL)
    free(str);
  if(replies != NULL)
    {
      for(i=0; i<p->rxc; i++)
	if(replies[i] != NULL)
	  free(replies[i]);
      free(replies);
    }
  if(reply_lens != NULL)
    free(reply_lens);
  return rc;
}

char *scamper_neighbourdisc_tojson(const scamper_neighbourdisc_t *nd, size_t *len_out)
{
  char *header = NULL, *str = NULL;
  char **probes = NULL; size_t *probe_lens = NULL;
  size_t len = 0, header_len = 0, wc = 0;
  int rc = -1;
  uint16_t i;

  /* get the header string */
  if((header = header_tostr(nd)) == NULL)
    goto cleanup;
  len = (header_len = strlen(header));

  len += 12; /* , \"probes\":[ */

  if(nd->probec > 0)
    {
      if((probes = malloc_zero(sizeof(char *) * nd->probec)) == NULL ||
	 (probe_lens = malloc_zero(sizeof(size_t) * nd->probec)) == NULL)
	goto cleanup;
      for(i=0; i<nd->probec; i++)
	{
	  if(i > 0) len++; /* , */
	  if((probes[i] = probe_tostr(nd->probes[i], &probe_lens[i])) == NULL)
	    goto cleanup;
	  len += probe_lens[i];
	}
    }
  len += 3; /* ]}\0 */

  if((str = malloc_zero(len)) == NULL)
    goto cleanup;
  memcpy(str+wc, header, header_len); wc += header_len;
  memcpy(str+wc, ", \"probes\":[", 12); wc += 12;

  for(i=0; i<nd->probec; i++)
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
      for(i=0; i<nd->probec; i++)
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

int scamper_file_json_neighbourdisc_write(const scamper_file_t *sf,
					  const scamper_neighbourdisc_t *nd,
					  void *p)
{
  char *str;
  size_t len;
  int rc;

  if((str = scamper_neighbourdisc_tojson(nd, &len)) == NULL)
    return -1;
  str[len-1] = '\n';
  rc = json_write(sf, str, len, p);
  free(str);

  return rc;
}
