/*
 * scamper_http_lib.c
 *
 * $Id: scamper_http_lib.c,v 1.13 2024/01/03 03:51:42 mjl Exp $
 *
 * Copyright (C) 2023-2024 The Regents of the University of California
 *
 * Authors: Matthew Luckie
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
#include "scamper_http.h"
#include "scamper_http_int.h"
#include "utils.h"

scamper_list_t *scamper_http_list_get(const scamper_http_t *http)
{
  return http->list;
}

scamper_cycle_t *scamper_http_cycle_get(const scamper_http_t *http)
{
  return http->cycle;
}

uint32_t scamper_http_userid_get(const scamper_http_t *http)
{
  return http->userid;
}

scamper_addr_t *scamper_http_src_get(const scamper_http_t *http)
{
  return http->src;
}

scamper_addr_t *scamper_http_dst_get(const scamper_http_t *http)
{
  return http->dst;
}

uint16_t scamper_http_sport_get(const scamper_http_t *http)
{
  return http->sport;
}

uint16_t scamper_http_dport_get(const scamper_http_t *http)
{
  return http->dport;
}

const struct timeval *scamper_http_start_get(const scamper_http_t *http)
{
  return &http->start;
}

const struct timeval *scamper_http_hsrtt_get(const scamper_http_t *http)
{
  return &http->hsrtt;
}

const struct timeval *scamper_http_maxtime_get(const scamper_http_t *http)
{
  return &http->maxtime;
}

uint32_t scamper_http_flags_get(const scamper_http_t *http)
{
  return http->flags;
}

int scamper_http_flag_is_insecure(const scamper_http_t *http)
{
  return SCAMPER_HTTP_FLAG_IS_INSECURE(http);
}

uint8_t scamper_http_stop_get(const scamper_http_t *http)
{
  return http->stop;
}

char *scamper_http_stop_tostr(const scamper_http_t *http, char *buf, size_t len)
{
  static const char *r[] = {
    "none",
    "halted",
    "noconn",
    "done",
    "error",
    "timeout",
    "insecure",
  };
  if(http->stop >= sizeof(r) / sizeof(char *))
    snprintf(buf, len, "%d", http->stop);
  else
    snprintf(buf, len, "%s", r[http->stop]);
  return buf;
}

uint8_t scamper_http_type_get(const scamper_http_t *http)
{
  return http->type;
}

char *scamper_http_type_tostr(const scamper_http_t *http, char *buf, size_t len)
{
  static const char *t[] = {
    "https",
    "http",
  };
  if(http->type >= sizeof(t) / sizeof(char *))
    snprintf(buf, len, "%d", http->type);
  else
    snprintf(buf, len, "%s", t[http->type]);
  return buf;
}

const char *scamper_http_host_get(const scamper_http_t *http)
{
  return http->host;
}

const char *scamper_http_file_get(const scamper_http_t *http)
{
  return http->file;
}

uint8_t scamper_http_headerc_get(const scamper_http_t *http)
{
  return http->headerc;
}

const char *scamper_http_header_get(const scamper_http_t *http, uint8_t i)
{
  if(http->headers == NULL || i >= http->headerc)
    return NULL;
  return http->headers[i];
}

uint32_t scamper_http_bufc_get(const scamper_http_t *http)
{
  return http->bufc;
}

scamper_http_buf_t *scamper_http_buf_get(const scamper_http_t *http, uint32_t i)
{
  if(http->bufs == NULL || i >= http->bufc)
    return NULL;
  return http->bufs[i];
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_http_buf_t *scamper_http_buf_use(scamper_http_buf_t *htb)
{
  htb->refcnt++;
  return htb;
}
#endif

const struct timeval *scamper_http_buf_tv_get(const scamper_http_buf_t *htb)
{
  return &htb->tv;
}

uint8_t scamper_http_buf_dir_get(const scamper_http_buf_t *htb)
{
  return htb->dir;
}

char *scamper_http_buf_dir_tostr(const scamper_http_buf_t *htb,
				 char *buf, size_t len)
{
  static const char *d[] = {"rx", "tx"};
  if(htb->dir >= sizeof(d) / sizeof(char *))
    snprintf(buf, len, "%d", htb->dir);
  else
    snprintf(buf, len, "%s", d[htb->dir]);
  return buf;
}

uint8_t scamper_http_buf_type_get(const scamper_http_buf_t *htb)
{
  return htb->type;
}

char *scamper_http_buf_type_tostr(const scamper_http_buf_t *htb,
				 char *buf, size_t len)
{
  static const char *t[] = {"data", "hdr", "tls"};
  if(htb->dir >= sizeof(t) / sizeof(char *))
    snprintf(buf, len, "%d", htb->type);
  else
    snprintf(buf, len, "%s", t[htb->type]);
  return buf;
}

uint16_t scamper_http_buf_len_get(const scamper_http_buf_t *htb)
{
  return htb->len;
}

const uint8_t *scamper_http_buf_data_get(const scamper_http_buf_t *htb)
{
  return htb->data;
}

int scamper_http_buf_is_tx(const scamper_http_buf_t *htb)
{
  return SCAMPER_HTTP_BUF_IS_TX(htb);
}

int scamper_http_buf_is_rx(const scamper_http_buf_t *htb)
{
  return SCAMPER_HTTP_BUF_IS_RX(htb);
}

int scamper_http_buf_is_tls(const scamper_http_buf_t *htb)
{
  return SCAMPER_HTTP_BUF_IS_TLS(htb);
}

int scamper_http_buf_is_hdr(const scamper_http_buf_t *htb)
{
  return SCAMPER_HTTP_BUF_IS_HDR(htb);
}

int scamper_http_buf_is_data(const scamper_http_buf_t *htb)
{
  return SCAMPER_HTTP_BUF_IS_DATA(htb);
}

int scamper_http_status_code_get(const scamper_http_t *http, uint16_t *status)
{
  const scamper_http_buf_t *htb;
  size_t off = 0;
  uint8_t buf[128];
  uint32_t i;
  uint16_t j;
  int gothdr = 0;

  for(i=0; i<http->bufc; i++)
    {
      if((htb = http->bufs[i]) == NULL ||
	 htb->dir != SCAMPER_HTTP_BUF_DIR_RX ||
	 htb->type != SCAMPER_HTTP_BUF_TYPE_HDR)
	continue;
      if(htb->data == NULL)
	return -1;
      for(j=0; j<htb->len; j++)
	{
	  if(htb->data[j] == '\r')
	    {
	      buf[off] = '\0';
	      gothdr = 1;
	      break;
	    }
	  buf[off++] = htb->data[j];
	  if(off == sizeof(buf))
	    return -1;
	}
      if(j < htb->len)
	break;
    }

  if(gothdr == 0)
    return -1;

  /*
   * status-line   = HTTP-version SP status-code SP [ reason-phrase ]
   * HTTP-version  = HTTP-name "/" DIGIT "." DIGIT
   * HTTP-name     = %s"HTTP"
   * status-code   = 3DIGIT
   */
  if(buf[0] != 'H' || buf[1] != 'T' || buf[2] != 'T' || buf[3] != 'P' ||
     buf[4] != '/' ||
     isdigit(buf[5]) == 0 || buf[6] != '.' || isdigit(buf[7]) == 0 || /* 1.1 */
     isspace(buf[8]) == 0 || /* SP */
     isdigit(buf[9]) == 0 || isdigit(buf[10]) == 0 || isdigit(buf[11]) == 0 ||
     (isspace(buf[12]) == 0 && buf[12] != '\0'))
    return -1;

  *status = ((buf[9] - '0') * 100) + ((buf[10] - '0') * 10) + (buf[11] - '0');
  return 0;
}

static int http_type_port(const scamper_http_t *http,
			  const char **type, char *port, size_t len)
{
  if(http->type == SCAMPER_HTTP_TYPE_HTTP)
    {
      if(http->dport != 80)
	snprintf(port, len, ":%u", http->dport);
      else
	port[0] = '\0';
      *type = "http";
    }
  else if(http->type == SCAMPER_HTTP_TYPE_HTTPS)
    {
      if(http->dport != 443)
	snprintf(port, len, ":%u", http->dport);
      else
	port[0] = '\0';
      *type = "https";
    }
  else return -1;
  return 0;
}

int scamper_http_url_len_get(const scamper_http_t *http, size_t *len)
{
  char port[8];
  const char *type;

  if(http->host == NULL || http->file == NULL)
    return -1;

  if(http_type_port(http, &type, port, sizeof(port)) != 0)
    return -1;

  *len = strlen(type) + /* http or https */
    3 + /* :// */
    strlen(http->host) + strlen(port) + strlen(http->file) + 1;

  return 0;
}

int scamper_http_url_get(const scamper_http_t *http, char *buf, size_t len)
{
  char port[8];
  const char *type;
  size_t needed;

  /* need both host and file to prepare a correct URL */
  if(http->host == NULL || http->file == NULL)
    return -1;

  /* get type and port strings */
  if(http_type_port(http, &type, port, sizeof(port)) != 0)
    return -1;

  /* make sure the supplied buf is large enough */
  needed = strlen(type) + /* http or https */
    3 + /* :// */
    strlen(http->host) + strlen(port) + strlen(http->file) + 1;
  if(needed < len)
    return -1;

  snprintf(buf, len, "%s://%s%s%s\n", type, http->host, port, http->file);
  return 0;
}

static int htb_len(const scamper_http_t *http, size_t *len,
		   uint8_t dir, uint8_t type)
{
  const scamper_http_buf_t *htb;
  uint32_t i;

  *len = 0;
  for(i=0; i<http->bufc; i++)
    {
      if((htb = http->bufs[i]) == NULL ||
	 htb->dir != dir || htb->type != type)
	continue;
      if(htb->data == NULL)
	return -1;
      *len += htb->len;
    }

  return 0;
}

static int htb_data(const scamper_http_t *http, uint8_t *buf, size_t len,
		    uint8_t dir, uint8_t type, size_t *off)
{
  const scamper_http_buf_t *htb;
  uint32_t i;

  *off = 0;
  for(i=0; i<http->bufc; i++)
    {
      if((htb = http->bufs[i]) == NULL ||
	 htb->dir != dir || htb->type != type)
	continue;
      if(htb->data == NULL || len - *off < htb->len)
	return -1;
      memcpy(buf+(*off), htb->data, htb->len);
      (*off) += htb->len;
    }

  return 0;
}

int scamper_http_rx_hdr_len_get(const scamper_http_t *http, size_t *len)
{
  if(htb_len(http, len,
	     SCAMPER_HTTP_BUF_DIR_RX, SCAMPER_HTTP_BUF_TYPE_HDR) != 0)
    return -1;
  *len = *len + 1; /* for the null terminator */
  return 0;
}

int scamper_http_tx_hdr_len_get(const scamper_http_t *http, size_t *len)
{
  if(htb_len(http, len,
	     SCAMPER_HTTP_BUF_DIR_TX, SCAMPER_HTTP_BUF_TYPE_HDR) != 0)
    return -1;
  *len = *len + 1; /* for the null terminator */
  return 0;
}

int scamper_http_rx_hdr_get(const scamper_http_t *http,uint8_t *buf,size_t len)
{
  size_t off;
  if(htb_data(http, buf, len,
	      SCAMPER_HTTP_BUF_DIR_RX, SCAMPER_HTTP_BUF_TYPE_HDR, &off) != 0)
    return -1;
  if(len - off != 1)
    return -1;
  buf[off] = '\0';
  return 0;
}

int scamper_http_tx_hdr_get(const scamper_http_t *http,uint8_t *buf,size_t len)
{
  size_t off;
  if(htb_data(http, buf, len,
	      SCAMPER_HTTP_BUF_DIR_TX, SCAMPER_HTTP_BUF_TYPE_HDR, &off) != 0)
    return -1;
  if(len - off != 1)
    return -1;
  buf[off] = '\0';
  return 0;
}

static int process_chunked(const scamper_http_t *http,uint8_t *buf,size_t *len)
{
  const scamper_http_buf_t *htb;
  char chunk[8], *endptr;
  size_t chunk_off = 0, off = 0;
  uint32_t i;
  uint16_t j;
  int mode = 0;
  long lo, x;

  for(i=0; i<http->bufc; i++)
    {
      if((htb = http->bufs[i]) == NULL ||
	 htb->dir != SCAMPER_HTTP_BUF_DIR_RX ||
	 htb->type != SCAMPER_HTTP_BUF_TYPE_DATA)
	continue;
      if(htb->data == NULL)
	return -1;

      j = 0;
      while(j < htb->len)
	{
	  if(mode == 0) /* parsing chunk-size */
	    {
	      chunk[chunk_off++] = htb->data[j];
	      if(chunk_off == sizeof(chunk))
		return -1;
	      if(htb->data[j] == '\n')
		{
		  chunk[chunk_off] = '\0';
		  errno = 0;
		  if((lo = strtol(chunk, &endptr, 16)) == 0 && errno != 0)
		    return -1;
		  if(lo == 0)
		    {
		      if(buf == NULL)
			*len = off;
		      else if(off != *len)
			return -1;
		      return 0;
		    }
		  mode = 1;
		  chunk_off = 0;
		}
	      else if(ishex(htb->data[j]) == 0 && htb->data[j] != '\r')
		return -1;
	      j++;
	    }
	  else if(mode == 1) /* processing data */
	    {
	      if((x = htb->len - j) < lo)
		{
		  if(buf != NULL)
		    {
		      if(*len - off < (size_t)x)
			return -1;
		      memcpy(buf+off, htb->data+j, x);
		    }
		  off += x;
		  j += x;
		  lo -= x;
		}
	      else
		{
		  if(buf != NULL)
		    {
		      if(*len - off < (size_t)lo)
			return -1;
		      memcpy(buf+off, htb->data+j, lo);
		    }
		  off += lo;
		  j += lo;
		  lo = 0;
		  mode = 2;
		}
	    }
	  else if(mode == 2) /* processing \r\n after chunk */
	    {
	      if((lo == 0 && htb->data[j] != '\r') ||
		 (lo == 1 && htb->data[j] != '\n'))
		return -1;
	      lo++;
	      j++;
	      if(lo == 2)
		mode = 0;
	    }
	}
    }

  return -1;
}

int scamper_http_rx_data_get(const scamper_http_t *http,uint8_t *buf,size_t len)
{
  char *encoding = NULL;
  int rc = -1;
  size_t off;

  if(scamper_http_rx_hdr_name_get(http, "transfer-encoding", &encoding) != 0)
    goto done;
  if(encoding != NULL && strcasecmp(encoding, "chunked") == 0)
    {
      rc = process_chunked(http, buf, &len);
      goto done;
    }

  rc = htb_data(http, buf, len,
		SCAMPER_HTTP_BUF_DIR_RX, SCAMPER_HTTP_BUF_TYPE_DATA, &off);
  if(off != len)
    rc = -1;

 done:
  if(encoding != NULL) free(encoding);
  return rc;
}

int scamper_http_rx_data_len_get(const scamper_http_t *http, size_t *len)
{
  char *encoding = NULL;
  int rc = -1;

  if(scamper_http_rx_hdr_name_get(http, "transfer-encoding", &encoding) != 0)
    goto done;
  if(encoding != NULL && strcasecmp(encoding, "chunked") == 0)
    {
      rc = process_chunked(http, NULL, len);
      goto done;
    }

  rc = htb_len(http, len, SCAMPER_HTTP_BUF_DIR_RX, SCAMPER_HTTP_BUF_TYPE_DATA);

 done:
  if(encoding != NULL) free(encoding);
  return rc;
}

static scamper_http_hdr_field_t *htf_alloc(const char *start,
					   const char *colon, const char *end)
{
  scamper_http_hdr_field_t *htf = NULL;
  char *name = NULL, *value = NULL;
  size_t len;

  if(colon[0] != ':' || colon[1] != ' ')
    goto err;

  assert(colon > start);
  len = (colon - start) + 1;
  if((name = malloc(len)) == NULL)
    goto err;
  memcpy(name, start, len-1);
  name[len-1] = '\0';

  assert(end - colon > 1);
  len = end - colon - 1;
  if((value = malloc(len)) == NULL)
    goto err;
  memcpy(value, colon + 2, len-1);
  value[len-1] = '\0';

  if((htf = malloc_zero(sizeof(scamper_http_hdr_field_t))) == NULL)
    goto err;
  htf->name = name;
  htf->value = value;

  return htf;

 err:
  if(name != NULL) free(name);
  if(value != NULL) free(value);
  return NULL;
}

static scamper_http_hdr_fields_t *htfs_parse(const char *buf, size_t len)
{
  scamper_http_hdr_fields_t *htfs = NULL;
  scamper_http_hdr_field_t *htf = NULL;
  const char *start, *end, *colon;
  size_t first, off, lf;

  /* skip over the first line, which has either the request or status */
  for(off=0; off<len; off++)
    if(buf[off] == '\n')
      break;
  if(off == len)
    goto err;
  first = off+1;

  /* count the number of header fields */
  lf = 0;
  for(off=first; off<len; off++)
    if(buf[off] == '\n')
      lf++;

  if((htfs = malloc_zero(sizeof(scamper_http_hdr_fields_t))) == NULL)
    goto err;

  if(lf == 0)
    goto done;

  /* allocate structure to store headers */
  htfs->fields = malloc_zero(sizeof(scamper_http_hdr_field_t *) * lf);
  if(htfs->fields == NULL)
    goto err;

  start = buf + first; colon = NULL;
  for(off=first; off<len; off++)
    {
      if(buf[off] != '\n')
	{
	  if(buf[off] == ':' && colon == NULL)
	    colon = buf + off;
	  continue;
	}

      if(colon != NULL && start != colon)
	{
	  if(off > 0 && buf[off-1] == '\r')
	    end = buf + off - 1;
	  else
	    end = buf + off;
	  if((htf = htf_alloc(start, colon, end)) == NULL)
	    goto err;
	  htfs->fields[htfs->fieldc++] = htf; htf = NULL;
	}

      colon = NULL;
      start = buf + off + 1;
    }

 done:
  return htfs;

 err:
  if(htfs != NULL) scamper_http_hdr_fields_free(htfs);
  return NULL;
}

scamper_http_hdr_fields_t *scamper_http_rx_hdr_fields_get(const scamper_http_t *http)
{
  scamper_http_hdr_fields_t *htfs = NULL;
  uint8_t *buf = NULL;
  size_t len;

  if(scamper_http_rx_hdr_len_get(http, &len) != 0 ||
     (buf = malloc(len)) == NULL ||
     scamper_http_rx_hdr_get(http, buf, len) != 0)
    goto done;

  htfs = htfs_parse((const char *)buf, len);

 done:
  if(buf != NULL) free(buf);
  return htfs;
}

scamper_http_hdr_fields_t *scamper_http_tx_hdr_fields_get(const scamper_http_t *http)
{
  scamper_http_hdr_fields_t *htfs = NULL;
  uint8_t *buf = NULL;
  size_t len;

  if(scamper_http_tx_hdr_len_get(http, &len) != 0 ||
     (buf = malloc(len)) == NULL ||
     scamper_http_tx_hdr_get(http, buf, len) != 0)
    goto done;

  htfs = htfs_parse((const char *)buf, len);

 done:
  if(buf != NULL) free(buf);
  return htfs;
}

static int hdr_name_get(const scamper_http_hdr_fields_t *htfs,
			const char *name, char **value)
{
  scamper_http_hdr_field_t *htf;
  size_t i;
  char *tmp;

  for(i=0; i<htfs->fieldc; i++)
    {
      if((htf = htfs->fields[i]) == NULL)
	continue;
      if(htf->name != NULL && strcasecmp(htf->name, name) == 0 &&
	 htf->value != NULL)
	{
	  if((tmp = strdup(htf->value)) == NULL)
	    return -1;
	  *value = tmp;
	  return 0;
	}
    }

  *value = NULL;
  return 0;
}

int scamper_http_rx_hdr_name_get(const scamper_http_t *http,
				 const char *name, char **value)
{
  scamper_http_hdr_fields_t *htfs;
  int rc;
  if((htfs = scamper_http_rx_hdr_fields_get(http)) == NULL)
    return -1;
  rc = hdr_name_get(htfs, name, value);
  scamper_http_hdr_fields_free(htfs);
  return rc;
}

int scamper_http_tx_hdr_name_get(const scamper_http_t *http,
				 const char *name, char **value)
{
  scamper_http_hdr_fields_t *htfs;
  int rc;
  if((htfs = scamper_http_tx_hdr_fields_get(http)) == NULL)
    return -1;
  rc = hdr_name_get(htfs, name, value);
  scamper_http_hdr_fields_free(htfs);
  return rc;
  return 0;
}

static void scamper_http_hdr_field_free(scamper_http_hdr_field_t *htf)
{
  if(htf->name != NULL) free(htf->name);
  if(htf->value != NULL) free(htf->value);
  free(htf);
  return;
}

/* process a set of HTTP header fields */
void scamper_http_hdr_fields_free(scamper_http_hdr_fields_t *htfs)
{
  size_t x;
  if(htfs->fields != NULL)
    {
      for(x=0; x<htfs->fieldc; x++)
	if(htfs->fields[x] != NULL)
	  scamper_http_hdr_field_free(htfs->fields[x]);
      free(htfs->fields);
    }
  free(htfs);
  return;
}

size_t scamper_http_hdr_fields_count_get(const scamper_http_hdr_fields_t *htfs)
{
  return htfs->fieldc;
}

scamper_http_hdr_field_t *scamper_http_hdr_fields_get(const scamper_http_hdr_fields_t *htfs, size_t x)
{
  if(x >= htfs->fieldc)
    return NULL;
  return htfs->fields[x];
}

const char *scamper_http_hdr_field_name_get(const scamper_http_hdr_field_t *htf)
{
  return htf->name;
}

const char *scamper_http_hdr_field_value_get(const scamper_http_hdr_field_t *htf)
{
  return htf->value;
}
