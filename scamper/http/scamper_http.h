/*
 * scamper_http.h
 *
 * $Id: scamper_http.h,v 1.8 2024/01/03 03:51:42 mjl Exp $
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

#ifndef __SCAMPER_HTTP_H
#define __SCAMPER_HTTP_H

typedef struct scamper_http scamper_http_t;
typedef struct scamper_http_buf scamper_http_buf_t;
typedef struct scamper_http_hdr_field scamper_http_hdr_field_t;
typedef struct scamper_http_hdr_fields scamper_http_hdr_fields_t;

#define SCAMPER_HTTP_TYPE_HTTPS 0
#define SCAMPER_HTTP_TYPE_HTTP  1

#define SCAMPER_HTTP_STOP_NONE     0
#define SCAMPER_HTTP_STOP_HALTED   1
#define SCAMPER_HTTP_STOP_NOCONN   2
#define SCAMPER_HTTP_STOP_DONE     3
#define SCAMPER_HTTP_STOP_ERROR    4
#define SCAMPER_HTTP_STOP_TIMEOUT  5
#define SCAMPER_HTTP_STOP_INSECURE 6

#define SCAMPER_HTTP_BUF_DIR_RX  0
#define SCAMPER_HTTP_BUF_DIR_TX  1

#define SCAMPER_HTTP_BUF_TYPE_DATA 0
#define SCAMPER_HTTP_BUF_TYPE_HDR  1
#define SCAMPER_HTTP_BUF_TYPE_TLS  2

#define SCAMPER_HTTP_FLAG_INSECURE 0x0001

/* scamper_http_t functions */
void scamper_http_free(scamper_http_t *http);
scamper_list_t *scamper_http_list_get(const scamper_http_t *http);
scamper_cycle_t *scamper_http_cycle_get(const scamper_http_t *http);
uint32_t scamper_http_userid_get(const scamper_http_t *http);
scamper_addr_t *scamper_http_src_get(const scamper_http_t *http);
scamper_addr_t *scamper_http_dst_get(const scamper_http_t *http);
uint16_t scamper_http_sport_get(const scamper_http_t *http);
uint16_t scamper_http_dport_get(const scamper_http_t *http);
const struct timeval *scamper_http_start_get(const scamper_http_t *http);
const struct timeval *scamper_http_hsrtt_get(const scamper_http_t *http);
const struct timeval *scamper_http_maxtime_get(const scamper_http_t *http);
uint32_t scamper_http_flags_get(const scamper_http_t *http);
int scamper_http_flag_is_insecure(const scamper_http_t *http);
uint8_t scamper_http_stop_get(const scamper_http_t *http);
char *scamper_http_stop_tostr(const scamper_http_t *http,
			      char *buf, size_t len);
uint8_t scamper_http_type_get(const scamper_http_t *http);
char *scamper_http_type_tostr(const scamper_http_t *http,
			      char *buf, size_t len);
const char *scamper_http_host_get(const scamper_http_t *http);
const char *scamper_http_file_get(const scamper_http_t *http);
uint8_t scamper_http_headerc_get(const scamper_http_t *http);
const char *scamper_http_header_get(const scamper_http_t *http, uint8_t i);
uint32_t scamper_http_bufc_get(const scamper_http_t *http);
scamper_http_buf_t *scamper_http_buf_get(const scamper_http_t *http, uint32_t i);

/* scamper_http_buf_t functions */
scamper_http_buf_t *scamper_http_buf_use(scamper_http_buf_t *htb);
void scamper_http_buf_free(scamper_http_buf_t *htb);
const struct timeval *scamper_http_buf_tv_get(const scamper_http_buf_t *htb);
uint8_t scamper_http_buf_dir_get(const scamper_http_buf_t *htb);
char *scamper_http_buf_dir_tostr(const scamper_http_buf_t *htb,
				 char *buf, size_t len);
uint8_t scamper_http_buf_type_get(const scamper_http_buf_t *htb);
char *scamper_http_buf_type_tostr(const scamper_http_buf_t *htb,
				  char *buf, size_t len);
const uint8_t *scamper_http_buf_data_get(const scamper_http_buf_t *htb);
uint16_t scamper_http_buf_len_get(const scamper_http_buf_t *htb);
int scamper_http_buf_is_tx(const scamper_http_buf_t *htb);
int scamper_http_buf_is_rx(const scamper_http_buf_t *htb);
int scamper_http_buf_is_tls(const scamper_http_buf_t *htb);
int scamper_http_buf_is_hdr(const scamper_http_buf_t *htb);
int scamper_http_buf_is_data(const scamper_http_buf_t *htb);

/* convenience functions */
int scamper_http_status_code_get(const scamper_http_t *http, uint16_t *status);
int scamper_http_url_len_get(const scamper_http_t *http, size_t *len);
int scamper_http_url_get(const scamper_http_t *http, char *buf, size_t len);
int scamper_http_rx_hdr_len_get(const scamper_http_t *http, size_t *len);
int scamper_http_rx_hdr_get(const scamper_http_t *http, uint8_t *buf, size_t len);
int scamper_http_rx_data_len_get(const scamper_http_t *http, size_t *len);
int scamper_http_rx_data_get(const scamper_http_t *http, uint8_t *buf, size_t len);
int scamper_http_tx_hdr_len_get(const scamper_http_t *http, size_t *len);
int scamper_http_tx_hdr_get(const scamper_http_t *http, uint8_t *buf, size_t len);

/* get the value of a given header parameter */
int scamper_http_tx_hdr_name_get(const scamper_http_t *http, const char *name, char **value);
int scamper_http_rx_hdr_name_get(const scamper_http_t *http, const char *name, char **value);

/* parse HTTP requests and response headers into components */
scamper_http_hdr_fields_t *scamper_http_rx_hdr_fields_get(const scamper_http_t *http);
scamper_http_hdr_fields_t *scamper_http_tx_hdr_fields_get(const scamper_http_t *http);

/* process a set of HTTP header fields */
void scamper_http_hdr_fields_free(scamper_http_hdr_fields_t *htfs);
size_t scamper_http_hdr_fields_count_get(const scamper_http_hdr_fields_t *htfs);
scamper_http_hdr_field_t *scamper_http_hdr_fields_get(const scamper_http_hdr_fields_t *htfs, size_t x);
const char *scamper_http_hdr_field_name_get(const scamper_http_hdr_field_t *htf);
const char *scamper_http_hdr_field_value_get(const scamper_http_hdr_field_t *htf);

#endif /* __SCAMPER_HTTP_H */
