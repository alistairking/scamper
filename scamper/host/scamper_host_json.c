/*
 * scamper_host_json.c
 *
 * Copyright (c) 2023-2025 Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_host_json.c,v 1.18 2025/05/03 09:01:57 mjl Exp $
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
#include "scamper_host.h"
#include "scamper_host_int.h"
#include "scamper_file.h"
#include "scamper_file_json.h"
#include "scamper_host_json.h"

#include "utils.h"

static char *header_tostr(const scamper_host_t *host)
{
  char buf[1024], tmp[512];
  size_t off = 0, off2;
  uint32_t ms;

  string_concat(buf, sizeof(buf), &off,
		"{\"type\":\"host\", \"version\":\"0.1\"");
  if(host->src != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"src\":\"",
		   scamper_addr_tostr(host->src, tmp, sizeof(tmp)), "\"");
  if(host->dst != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"dst\":\"",
		   scamper_addr_tostr(host->dst, tmp, sizeof(tmp)), "\"");
  string_concaf(buf, sizeof(buf), &off,
		", \"userid\":%u, \"start\":{\"sec\":%ld,\"usec\":%d}",
		host->userid,
		(long)host->start.tv_sec, (int)host->start.tv_usec);

  if(host->flags != 0)
    {
      tmp[0] = '\0'; off2 = 0;
      if(host->flags & SCAMPER_HOST_FLAG_NORECURSE)
	string_concat(tmp, sizeof(tmp), &off2, "\"norecurse\"");
      if(host->flags & SCAMPER_HOST_FLAG_TCP)
	string_concat2(tmp, sizeof(tmp), &off2,
		       off2 != 0 ? ", " : "", "\"tcp\"");
      if(host->flags & SCAMPER_HOST_FLAG_NSID)
	string_concat2(tmp, sizeof(tmp), &off2,
		       off2 != 0 ? ", " : "", "\"nsid\"");
      if(off2 != 0)
	string_concat3(buf, sizeof(buf), &off, ", \"flags\":[", tmp, "]");
    }

  ms = (host->wait_timeout.tv_sec * 1000) + (host->wait_timeout.tv_usec / 1000);
  string_concaf(buf, sizeof(buf), &off,
		", \"wait\":%u, \"retries\":%u, \"stop\":\"%s\"", ms,
		host->retries, scamper_host_stop_tostr(host, tmp, sizeof(tmp)));
  if(host->qname != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"qname\":\"",
		   json_esc(host->qname, tmp, sizeof(tmp)), "\"");
  string_concat3(buf, sizeof(buf), &off, ", \"qclass\":\"",
		 scamper_host_qclass_tostr(host->qclass,tmp,sizeof(tmp)),"\"");
  string_concat3(buf, sizeof(buf), &off, ", \"qtype\":\"",
		 scamper_host_qtype_tostr(host->qtype,tmp,sizeof(tmp)), "\"");
  string_concaf(buf, sizeof(buf), &off, ", \"qcount\":%u", host->qcount);
  if(host->ecs != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"ecs\":\"", host->ecs, "\"");

  return strdup(buf);
}

static char *rr_tostr(const scamper_host_rr_t *rr)
{
  char *out = NULL, buf[1024], tmp[512];
  size_t off = 0, len, *lens = NULL;
  uint16_t i;

  string_concat3(buf, sizeof(buf), &off, "{\"class\":\"",
		 scamper_host_qclass_tostr(rr->class, tmp, sizeof(tmp)), "\"");
  string_concaf(buf, sizeof(buf), &off, ", \"type\":\"%s\", \"ttl\":%u",
		scamper_host_qtype_tostr(rr->type, tmp, sizeof(tmp)),
		rr->ttl);
  if(rr->name != NULL)
    string_concat3(buf, sizeof(buf), &off, ", \"name\":\"",
		   json_esc(rr->name, tmp, sizeof(tmp)), "\"");

  switch(scamper_host_rr_data_type(rr->class, rr->type))
    {
    case SCAMPER_HOST_RR_DATA_TYPE_ADDR:
      if(rr->un.addr == NULL)
	break;
      string_concat3(buf, sizeof(buf), &off, ", \"address\":\"",
		     scamper_addr_tostr(rr->un.addr, tmp, sizeof(tmp)), "\"");
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_STR:
      if(rr->un.str == NULL)
	break;
      string_concat3(buf, sizeof(buf), &off, ", \"",
		     scamper_host_rr_data_str_typestr(rr->class, rr->type),
		     "\":\"");
      string_concat2(buf, sizeof(buf), &off,
		     json_esc(rr->un.str, tmp, sizeof(tmp)), "\"");
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_MX:
      if(rr->un.mx == NULL)
	break;
      string_concat_u16(buf, sizeof(buf), &off, ", \"preference\":",
			rr->un.mx->preference);
      if(rr->un.mx->exchange != NULL)
	string_concat3(buf, sizeof(buf), &off, ", \"exchange\":\"",
		       json_esc(rr->un.mx->exchange, tmp, sizeof(tmp)), "\"");
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_SOA:
      if(rr->un.soa == NULL)
	break;
      if(rr->un.soa->mname != NULL)
	string_concat3(buf, sizeof(buf), &off, ", \"mname\":\"",
		       json_esc(rr->un.soa->mname, tmp, sizeof(tmp)), "\"");
      if(rr->un.soa->rname != NULL)
	string_concat3(buf, sizeof(buf), &off, ", \"rname\":\"",
		       json_esc(rr->un.soa->rname, tmp, sizeof(tmp)), "\"");
      string_concat_u32(buf, sizeof(buf), &off, ", \"serial\":",
			rr->un.soa->serial);
      string_concat_u32(buf, sizeof(buf), &off, ", \"refresh\":",
			rr->un.soa->refresh);
      string_concat_u32(buf, sizeof(buf), &off, ", \"retry\":",
			rr->un.soa->retry);
      string_concat_u32(buf, sizeof(buf), &off, ", \"expire\":",
			rr->un.soa->expire);
      string_concat_u32(buf, sizeof(buf), &off, ", \"minimum\":",
			rr->un.soa->minimum);
      break;

    case SCAMPER_HOST_RR_DATA_TYPE_TXT:
      if(rr->un.txt == NULL)
	break;
      string_concaf(buf, sizeof(buf), &off, ", \"strc\":%u, \"strs\":[",
		    rr->un.txt->strc);

      /*
       * figure out how large the total rr string will be, and allocate
       * that much memory
       */
      len = off;
      if(rr->un.txt->strc > 0 && rr->un.txt->strs != NULL)
	{
	  if((lens = malloc(sizeof(size_t) * rr->un.txt->strc)) == NULL)
	    goto err;
	  for(i=0; i<rr->un.txt->strc; i++)
	    {
	      if(rr->un.txt->strs[i] != NULL)
		lens[i] = json_esc_len(rr->un.txt->strs[i]);
	      else
		lens[i] = 0;
	      len += (lens[i] > 0 ? lens[i]-1 : 0) + 2; /* "" */
	    }
	  len += (2 * (rr->un.txt->strc-1)); /* , */
	}
      len += 3; /* ]}\0 */
      if((out = malloc(len)) == NULL)
	goto err;

      /* form the RR string and return it */
      memcpy(out, buf, off);
      if(lens != NULL)
	{
	  out[off++] = '"';
	  if(rr->un.txt->strs[0] != NULL)
	    json_esc(rr->un.txt->strs[0], out+off, len-off);
	  off += (lens[0] > 0 ? lens[0]-1 : 0);
	  out[off++] = '"';
	  for(i=1; i<rr->un.txt->strc; i++)
	    {
	      out[off++] = ','; out[off++] = ' '; out[off++] = '"';
	      if(rr->un.txt->strs[i] != NULL)
		json_esc(rr->un.txt->strs[i], out+off, len-off);
	      off += (lens[i] > 0 ? lens[i]-1 : 0);
	      out[off++] = '"';
	    }
	  free(lens); lens = NULL;
	}
      out[off++] = ']';
      out[off++] = '}';
      out[off++] = '\0';
      assert(off == len);
      return out;
    }

  string_concatc(buf, sizeof(buf), &off, '}');
  return strdup(buf);

 err:
  if(out != NULL) free(out);
  if(lens != NULL) free(lens);
  return NULL;
}

static char *query_tostr(const scamper_host_query_t *query)
{
  static const char *flags[8] = {"CD","AD","Z","RA","RD","TC","AA","0x80"};
  char header[256], **rrs = NULL, *str = NULL, tmp[16];
  size_t header_len, wc = 0, len = 0, off = 0, *rr_lens = NULL;
  uint32_t x, c = 0;
  uint16_t i;

  string_concaf(header, sizeof(header), &off,
		"{\"id\":%u, \"ancount\":%u, \"nscount\":%u, \"arcount\":%u",
		query->id, query->ancount, query->nscount, query->arcount);
  string_concaf(header, sizeof(header), &off,
		", \"tx\":{\"sec\":%ld,\"usec\":%d}",
		(long)query->tx.tv_sec, (int)query->tx.tv_usec);
  if(query->rx.tv_sec != 0 || query->rx.tv_usec != 0)
    {
      string_concaf(header, sizeof(header), &off,
		    ", \"rx\":{\"sec\":%ld,\"usec\":%d}",
		    (long)query->rx.tv_sec, (int)query->rx.tv_usec);
      string_concat3(header, sizeof(header), &off, ", \"rcode\":\"",
		     scamper_host_rcode_tostr(query->rcode, tmp, sizeof(tmp)),
		     "\", \"flags\":[");
      x = 0;
      for(i=0; i<8; i++)
	{
	  if((query->flags & (0x1 << i)) == 0)
	    continue;
	  if(x > 0)
	    string_concatc(header, sizeof(header), &off, ',');
	  string_concat3(header, sizeof(header), &off, "\"", flags[i], "\"");
	  x++;
	}
      string_concatc(header, sizeof(header), &off, ']');
    }

  if((c = query->ancount + query->nscount + query->arcount) == 0)
    {
      string_concatc(header, sizeof(header), &off, '}');
      return strdup(header);
    }

  header_len = strlen(header);
  len = header_len + 2; /* }\0 */

  if((rrs = malloc_zero(sizeof(char *) * c)) == NULL ||
     (rr_lens = malloc_zero(sizeof(size_t) * c)) == NULL)
    goto err;
  x = 0;
  if(query->ancount > 0)
    {
      len += 9; /* , \"an\":[] */
      for(i=0; i<query->ancount; i++)
	{
	  if(i > 0) len++; /* , */
	  if((rrs[x] = rr_tostr(query->an[i])) == NULL)
	    goto err;
	  rr_lens[x] = strlen(rrs[x]);
	  len += rr_lens[x];
	  x++;
	}
    }
  if(query->nscount > 0)
    {
      len += 9; /* , \"ns\":[] */
      for(i=0; i<query->nscount; i++)
	{
	  if(i > 0) len++; /* , */
	  if((rrs[x] = rr_tostr(query->ns[i])) == NULL)
	    goto err;
	  rr_lens[x] = strlen(rrs[x]);
	  len += rr_lens[x];
	  x++;
	}
    }
  if(query->arcount > 0)
    {
      len += 9; /* , \"ar\":[] */
      for(i=0; i<query->arcount; i++)
	{
	  if(i > 0) len++; /* , */
	  if((rrs[x] = rr_tostr(query->ar[i])) == NULL)
	    goto err;
	  rr_lens[x] = strlen(rrs[x]);
	  len += rr_lens[x];
	  x++;
	}
    }

  if((str = malloc(len)) == NULL)
    goto err;
  x = 0;
  memcpy(str+wc, header, header_len); wc += header_len;
  if(query->ancount > 0)
    {
      memcpy(str+wc, ", \"an\":[", 8); wc += 8;
      for(i=0; i<query->ancount; i++)
	{
	  if(i > 0) str[wc++] = ',';
	  memcpy(str+wc, rrs[x], rr_lens[x]);
	  wc += rr_lens[x];
	  x++;
	}
      str[wc++] = ']';
    }
  if(query->nscount > 0)
    {
      memcpy(str+wc, ", \"ns\":[", 8); wc += 8;
      for(i=0; i<query->nscount; i++)
	{
	  if(i > 0) str[wc++] = ',';
	  memcpy(str+wc, rrs[x], rr_lens[x]);
	  wc += rr_lens[x];
	  x++;
	}
      str[wc++] = ']';
    }
  if(query->arcount > 0)
    {
      memcpy(str+wc, ", \"ar\":[", 8); wc += 8;
      for(i=0; i<query->arcount; i++)
	{
	  if(i > 0) str[wc++] = ',';
	  memcpy(str+wc, rrs[x], rr_lens[x]);
	  wc += rr_lens[x];
	  x++;
	}
      str[wc++] = ']';
    }

  str[wc++] = '}';
  str[wc++] = '\0';
  assert(wc == len);

  goto done;

 err:
  if(str != NULL)
    {
      free(str);
      str = NULL;
    }

 done:
  if(rr_lens != NULL) free(rr_lens);
  if(rrs != NULL)
    {
      for(x=0; x<c; x++)
	free(rrs[x]);
      free(rrs);
    }
  return str;
}

char *scamper_host_tojson(const scamper_host_t *host, size_t *len_out)
{
  char *header = NULL, *str = NULL;
  char **queries = NULL; size_t *query_lens = NULL;
  size_t len = 0, header_len = 0, wc = 0;
  int rc = -1;
  uint8_t i;

  /* get the header string */
  if((header = header_tostr(host)) == NULL)
    goto cleanup;
  len = (header_len = strlen(header));

  len += 13; /* , \"queries\":[ */

  if(host->qcount > 0)
    {
      if((queries = malloc_zero(sizeof(char *) * host->qcount)) == NULL ||
	 (query_lens = malloc_zero(sizeof(size_t) * host->qcount)) == NULL)
	goto cleanup;
      for(i=0; i<host->qcount; i++)
	{
	  if(i > 0) len++; /* , */
	  if((queries[i] = query_tostr(host->queries[i])) == NULL)
	    goto cleanup;
	  len += (query_lens[i] = strlen(queries[i]));
	}
    }

  len += 3; /* ]}\0 */

  if((str = malloc_zero(len)) == NULL)
    goto cleanup;
  memcpy(str+wc, header, header_len); wc += header_len;
  memcpy(str+wc, ", \"queries\":[", 13); wc += 13;
  for(i=0; i<host->qcount; i++)
    {
      if(i > 0)
	str[wc++] = ',';
      memcpy(str+wc, queries[i], query_lens[i]);
      wc += query_lens[i];
    }
  memcpy(str+wc, "]}\0", 3); wc += 3;

  assert(wc == len);
  rc = 0;

 cleanup:
  if(header != NULL) free(header);
  if(queries != NULL)
    {
      for(i=0; i<host->qcount; i++)
	if(queries[i] != NULL)
	  free(queries[i]);
      free(queries);
    }
  if(query_lens != NULL) free(query_lens);

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

int scamper_file_json_host_write(const scamper_file_t *sf,
				 const scamper_host_t *host, void *p)
{
  char *str;
  size_t len;
  int rc;

  if((str = scamper_host_tojson(host, &len)) == NULL)
    return -1;
  str[len-1] = '\n';
  rc = json_write(sf, str, len, p);
  free(str);

  return rc;
}
