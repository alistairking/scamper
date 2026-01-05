/*
 * scamper_owamp_json.c
 *
 * Copyright (c) 2025 The Regents of the University of California
 * Author: Matthew Luckie
 *
 * $Id: scamper_owamp_json.c,v 1.1 2025/12/04 08:11:00 mjl Exp $
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
#include "scamper_owamp.h"
#include "scamper_owamp_int.h"
#include "scamper_file.h"
#include "scamper_file_json.h"
#include "scamper_owamp_json.h"

#include "utils.h"

static char *rx_tostr(const scamper_owamp_rx_t *rx)
{
  char buf[256];
  size_t off = 0;

  if(rx == NULL)
    return strdup("{}");

  string_concat_u32(buf, sizeof(buf), &off, "{\"stamp\":{\"sec\":",
		    (uint32_t)rx->stamp.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ",\"usec\":",
		    (uint32_t)rx->stamp.tv_usec);
  string_concatc(buf, sizeof(buf), &off, '}');

  if(rx->flags & SCAMPER_OWAMP_RX_FLAG_ERREST)
    string_concat_u16(buf, sizeof(buf), &off, ",\"errest\":", rx->errest);
  if(rx->flags & SCAMPER_OWAMP_RX_FLAG_DSCP)
    string_concat_u8(buf, sizeof(buf), &off, ",\"dscp\":", rx->dscp);
  if(rx->flags & SCAMPER_OWAMP_RX_FLAG_TTL)
    string_concat_u8(buf, sizeof(buf), &off, ",\"ttl\":", rx->ttl);
  string_concatc(buf, sizeof(buf), &off, '}');

  return strdup(buf);
}

static char *tx_tostr(const scamper_owamp_tx_t *tx)
{
  char buf[256], **rxs = NULL, *str = NULL, *rc = NULL;
  size_t off = 0, len, wc = 0, header_len = 0, *rx_lens = NULL;
  uint8_t i;

  if(tx == NULL)
    return strdup("{}");

  string_concat_u32(buf, sizeof(buf), &off, "{\"stamp\":{\"sec\":",
		    (uint32_t)tx->stamp.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ",\"usec\":",
		    (uint32_t)tx->stamp.tv_usec);
  string_concat_u32(buf, sizeof(buf), &off, "},\"seq\":", tx->seq);
  if(tx->flags & SCAMPER_OWAMP_TX_FLAG_ERREST)
    string_concat_u16(buf, sizeof(buf), &off, ",\"errest\":", tx->errest);
  string_concat_u16(buf, sizeof(buf), &off, ",\"rxc\":", tx->rxc);
  string_concat_u8(buf, sizeof(buf), &off, ",\"sent\":",
		   SCAMPER_OWAMP_TX_FLAG_IS_SENT(tx) ? 1 : 0);
  string_concat(buf, sizeof(buf), &off, ",\"rxs\":[");

  len = header_len = off;

  if(tx->rxc > 0)
    {
      if((rxs = malloc_zero(sizeof(char *) * tx->rxc)) == NULL ||
	 (rx_lens = malloc_zero(sizeof(size_t) * tx->rxc)) == NULL)
	goto done;
      for(i=0; i<tx->rxc; i++)
	{
	  if(i > 0) len++; /* , */
	  if((rxs[i] = rx_tostr(tx->rxs[i])) == NULL)
	    goto done;
	  rx_lens[i] = strlen(rxs[i]);
	  len += rx_lens[i];
	}
    }
  len += 3; /* ]}\0 */

  if((str = malloc_zero(len)) == NULL)
    goto done;
  memcpy(str, buf, header_len); wc += header_len;
  if(tx->rxc > 0)
    {
      for(i=0; i<tx->rxc; i++)
	{
	  if(i > 0)
	    str[wc++] = ',';
	  memcpy(str+wc, rxs[i], rx_lens[i]);
	  wc += rx_lens[i];
	}
    }
  memcpy(str+wc, "]}", 3); wc += 3;
  assert(wc == len);

  rc = str;

 done:
  if(rc == NULL && str != NULL)
    free(str);
  if(rxs != NULL) {
    for(i=0; i<tx->rxc; i++)
      if(rxs[i] != NULL)
	free(rxs[i]);
    free(rxs);
  }
  if(rx_lens != NULL)
    free(rx_lens);
  return rc;
}

static char *sched_tostr(const scamper_owamp_sched_t *sched)
{
  char buf[256], tmp[32];
  size_t off = 0;

  if(sched == NULL)
    return strdup("{}");

  string_concat_u32(buf, sizeof(buf), &off, "{\"value\":{\"sec\":",
		    (uint32_t)sched->tv.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ",\"usec\":",
		    (uint32_t)sched->tv.tv_usec);
  string_concat3(buf, sizeof(buf), &off, "},\"type\":\"",
		 scamper_owamp_sched_type_tostr(sched, tmp, sizeof(tmp)),
		 "\"}");

  return strdup(buf);
}

static char *owamp_header(const scamper_owamp_t *owamp)
{
  char **scheds = NULL; size_t *sched_lens = NULL;
  char buf[1024], tmp[512], *str = NULL;
  size_t off = 0, len = 0;
  uint32_t i;

  string_concat3(buf, sizeof(buf), &off,
		 "{\"type\":\"owamp\",\"dir\":\"",
		 scamper_owamp_dir_tostr(owamp, tmp, sizeof(tmp)), "\"");
  if(owamp->src != NULL)
    string_concat3(buf, sizeof(buf), &off, ",\"src\":\"",
		   scamper_addr_tostr(owamp->src, tmp, sizeof(tmp)), "\"");
  if(owamp->dst != NULL)
    string_concat3(buf, sizeof(buf), &off, ",\"dst\":\"",
		   scamper_addr_tostr(owamp->dst, tmp, sizeof(tmp)), "\"");
  string_concat_u16(buf, sizeof(buf), &off, ",\"dport\":", owamp->dport);
  string_concat_u32(buf, sizeof(buf), &off, ",\"start\":{\"sec\":",
		    (uint32_t)owamp->start.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ",\"usec\":",
		    (uint32_t)owamp->start.tv_usec);
  string_concat_u32(buf, sizeof(buf), &off, "},\"startat\":{\"sec\":",
		    (uint32_t)owamp->startat.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ",\"usec\":",
		    (uint32_t)owamp->startat.tv_usec);
  string_concat_u32(buf, sizeof(buf), &off, "},\"wait_timeout\":{\"sec\":",
		    (uint32_t)owamp->wait_timeout.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ",\"usec\":",
		    (uint32_t)owamp->wait_timeout.tv_usec);
  string_concat_u32(buf, sizeof(buf), &off, "},\"hsrtt\":{\"sec\":",
		    (uint32_t)owamp->hsrtt.tv_sec);
  string_concat_u32(buf, sizeof(buf), &off, ",\"usec\":",
		    (uint32_t)owamp->hsrtt.tv_usec);
  string_concat_u32(buf, sizeof(buf), &off, "},\"userid\":", owamp->userid);
  string_concat_u32(buf, sizeof(buf), &off, ",\"attempts\":", owamp->attempts);
  string_concat_u16(buf, sizeof(buf), &off, ",\"pktsize\":", owamp->pktsize);
  string_concat_u8(buf, sizeof(buf), &off, ",\"dscp\":", owamp->dscp);
  string_concat_u16(buf, sizeof(buf), &off, ",\"udp_sport\":",
		    owamp->udp_sport);
  string_concat_u16(buf, sizeof(buf), &off, ",\"udp_dport\":",
		    owamp->udp_dport);
  string_concat3(buf, sizeof(buf), &off, ",\"result\":\"",
		 scamper_owamp_result_tostr(owamp, tmp, sizeof(tmp)), "\"");
  if(owamp->errmsg != NULL)
    string_concat3(buf, sizeof(buf), &off, ",\"errmsg\":\"",
		   json_esc(owamp->errmsg, tmp, sizeof(tmp)), "\"");
  if(owamp->sched == NULL || owamp->schedc == 0)
    return strdup(buf);

  if((scheds = malloc_zero(sizeof(char *) * owamp->schedc)) == NULL ||
     (sched_lens = malloc_zero(sizeof(size_t) * owamp->schedc)) == NULL)
    goto cleanup;
  string_concat(buf, sizeof(buf), &off, ",\"sched\":[");
  len = off;
  for(i=0; i<owamp->schedc; i++)
    {
      if((scheds[i] = sched_tostr(owamp->sched[i])) == NULL)
	goto cleanup;
      sched_lens[i] = strlen(scheds[i]);
      if(i > 0) len++; /* , */
      len += sched_lens[i];
    }
  len += 2; /* ]\0 */

  if((str = malloc(len)) == NULL)
    goto cleanup;
  memcpy(str, buf, off);
  for(i=0; i<owamp->schedc; i++)
    {
      if(i > 0)
	str[off++] = ',';
      memcpy(str+off, scheds[i], sched_lens[i]);
      off += sched_lens[i];
    }
  str[off++] = ']';
  str[off++] = '\0';

  assert(off == len);

 cleanup:
  if(sched_lens != NULL) free(sched_lens);
  if(scheds != NULL)
    {
      for(i=0; i<owamp->schedc; i++)
	if(scheds[i] != NULL)
	  free(scheds[i]);
      free(scheds);
    }
  return str;
}

char *scamper_owamp_tojson(const scamper_owamp_t *owamp, size_t *len_out)
{
  char *str = NULL, *header = NULL;
  char **txs = NULL; size_t *tx_lens = NULL;
  size_t len = 0, wc = 0, header_len = 0;
  uint32_t i;
  int rc = -1;

  /* get the header string */
  if((header = owamp_header(owamp)) == NULL)
    goto cleanup;
  len = (header_len = strlen(header));

  len += 8; /* ,\"txs\":[ */
  if(owamp->txc > 0)
    {
      if((txs = malloc_zero(sizeof(char *) * owamp->txc)) == NULL ||
	 (tx_lens = malloc_zero(sizeof(size_t) * owamp->txc)) == NULL)
	goto cleanup;
      for(i=0; i<owamp->txc; i++)
	{
	  if(i > 0) len++; /* , */
	  if((txs[i] = tx_tostr(owamp->txs[i])) == NULL)
	    goto cleanup;
	  len += (tx_lens[i] = strlen(txs[i]));
	}
    }

  len += 3; /* ]}\0 */

  if((str = malloc_zero(len)) == NULL)
    goto cleanup;
  memcpy(str+wc, header, header_len); wc += header_len;
  memcpy(str+wc, ",\"txs\":[", 8); wc += 8;
  for(i=0; i<owamp->txc; i++)
    {
      if(i > 0)
	str[wc++] = ',';
      memcpy(str+wc, txs[i], tx_lens[i]);
      wc += tx_lens[i];
    }

  str[wc++] = ']'; str[wc++] = '}'; str[wc++] = '\0';

  assert(wc == len);
  rc = 0;

 cleanup:
  if(header != NULL) free(header);
  if(txs != NULL)
    {
      for(i=0; i<owamp->txc; i++)
	if(txs[i] != NULL)
	  free(txs[i]);
      free(txs);
    }
  if(tx_lens != NULL) free(tx_lens);
  if(rc != 0)
    {
      if(str != NULL) free(str);
      str = NULL;
    }
  if(len_out != NULL)
    *len_out = len;
  return str;
}

int scamper_file_json_owamp_write(const scamper_file_t *sf,
				  const scamper_owamp_t *owamp, void *p)
{
  char *str;
  size_t len;
  int rc;

  if((str = scamper_owamp_tojson(owamp, &len)) == NULL)
    return -1;
  str[len-1] = '\n';
  rc = json_write(sf, str, len, p);
  free(str);

  return rc;
}
