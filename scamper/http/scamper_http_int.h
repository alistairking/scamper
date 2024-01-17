/*
 * scamper_http_int.h
 *
 * $Id: scamper_http_int.h,v 1.6 2024/01/03 03:51:42 mjl Exp $
 *
 * Copyright (C) 2023-2024 The Regents of the University of California
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

#ifndef __SCAMPER_HTTP_INT_H
#define __SCAMPER_HTTP_INT_H

scamper_http_t *scamper_http_alloc(void);
scamper_http_buf_t *scamper_http_buf_alloc(void);

#define SCAMPER_HTTP_BUF_IS_TX(hb) ((hb)->dir == SCAMPER_HTTP_BUF_DIR_TX)
#define SCAMPER_HTTP_BUF_IS_RX(hb) ((hb)->dir == SCAMPER_HTTP_BUF_DIR_RX)
#define SCAMPER_HTTP_BUF_IS_TLS(hb) ((hb)->type == SCAMPER_HTTP_BUF_TYPE_TLS)
#define SCAMPER_HTTP_BUF_IS_HDR(hb) ((hb)->type == SCAMPER_HTTP_BUF_TYPE_HDR)
#define SCAMPER_HTTP_BUF_IS_DATA(hb) ((hb)->type == SCAMPER_HTTP_BUF_TYPE_DATA)

#define SCAMPER_HTTP_FLAG_IS_INSECURE(http) ( \
  ((http)->flags & SCAMPER_HTTP_FLAG_INSECURE))

struct scamper_http_hdr_field
{
  char                      *name;
  char                      *value;
};

struct scamper_http_hdr_fields
{
  scamper_http_hdr_field_t **fields;
  size_t                     fieldc;
};

struct scamper_http_buf
{
  uint8_t                    dir;  /* tx or rx */
  uint8_t                    type; /* http header / data, or TLS */
  uint16_t                   len;
  struct timeval             tv;
  uint8_t                   *data;

#ifdef BUILDING_LIBSCAMPERFILE
  int                        refcnt;
#endif
};

struct scamper_http
{
  scamper_list_t            *list;
  scamper_cycle_t           *cycle;
  uint32_t                   userid;

  scamper_addr_t            *src;
  scamper_addr_t            *dst;
  uint16_t                   sport;
  uint16_t                   dport;
  struct timeval             start;
  struct timeval             hsrtt;   /* rtt of syn -> syn/ack */
  struct timeval             maxtime; /* total length of time to let http run */
  uint32_t                   flags;

  uint8_t                    stop; /* stop reason */
  uint8_t                    type; /* http or https */
  char                      *host; /* domain name portion of host */
  char                      *file; /* resource requested */

  /* headers supplied by the user to set in the request */
  char                     **headers;
  uint8_t                    headerc;

  /* messages sent in the exchange */
  scamper_http_buf_t       **bufs;
  uint32_t                   bufc;
};

#endif /* __SCAMPER_HTTP_INT_H */
