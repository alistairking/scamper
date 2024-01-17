# scamper python interface - cython interface to scamper_http_t
#
# Author: Matthew Luckie
#
# Copyright (C) 2023 The Regents of the University of California
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

from libc.stdint cimport uint8_t, uint16_t, uint32_t
from posix.time cimport timeval

cdef extern from "scamper_addr.h":
 ctypedef struct scamper_addr_t:
  pass

cdef extern from "scamper_list.h":
 ctypedef struct scamper_list_t:
  pass
 ctypedef struct scamper_cycle_t:
  pass

cdef extern from "scamper_http.h":
 ctypedef struct scamper_http_t:
  pass

 ctypedef struct scamper_http_buf_t:
  pass

 ctypedef struct scamper_http_hdr_field_t:
  pass

 ctypedef struct scamper_http_hdr_fields_t:
  pass

 void scamper_http_free(scamper_http_t *http)

 scamper_list_t *scamper_http_list_get(const scamper_http_t *http)
 scamper_cycle_t *scamper_http_cycle_get(const scamper_http_t *http)
 uint32_t scamper_http_userid_get(const scamper_http_t *http)
 scamper_addr_t *scamper_http_src_get(const scamper_http_t *http)
 scamper_addr_t *scamper_http_dst_get(const scamper_http_t *http)
 uint16_t scamper_http_sport_get(const scamper_http_t *http)
 uint16_t scamper_http_dport_get(const scamper_http_t *http)
 const timeval *scamper_http_start_get(const scamper_http_t *http)
 uint8_t scamper_http_stop_get(const scamper_http_t *http)
 char *scamper_http_stop_tostr(const scamper_http_t *http, char *buf, size_t len)
 uint8_t scamper_http_type_get(const scamper_http_t *http)
 char *scamper_http_type_tostr(const scamper_http_t *http, char *buf, size_t len)
 const char *scamper_http_host_get(const scamper_http_t *http)
 const char *scamper_http_file_get(const scamper_http_t *http)

 uint32_t scamper_http_bufc_get(const scamper_http_t *http)
 scamper_http_buf_t *scamper_http_buf_get(const scamper_http_t *http, uint32_t i)
 void scamper_http_buf_free(scamper_http_buf_t *htb)
 scamper_http_buf_t *scamper_http_buf_use(scamper_http_buf_t *htb)
 const timeval *scamper_http_buf_tv_get(const scamper_http_buf_t *htb)
 const uint8_t *scamper_http_buf_data_get(const scamper_http_buf_t *htb)
 uint16_t scamper_http_buf_len_get(const scamper_http_buf_t *htb)
 bint scamper_http_buf_is_tx(const scamper_http_buf_t *htb)
 bint scamper_http_buf_is_rx(const scamper_http_buf_t *htb)
 bint scamper_http_buf_is_tls(const scamper_http_buf_t *htb)
 bint scamper_http_buf_is_hdr(const scamper_http_buf_t *htb)
 bint scamper_http_buf_is_data(const scamper_http_buf_t *htb)

 int scamper_http_status_code_get(const scamper_http_t *http, uint16_t *status)
 int scamper_http_url_len_get(const scamper_http_t *http, size_t *len)
 int scamper_http_url_get(const scamper_http_t *http, char *buf, size_t len)
 int scamper_http_rx_hdr_len_get(const scamper_http_t *http, size_t *len)
 int scamper_http_rx_hdr_get(const scamper_http_t *http, uint8_t *buf, size_t len)
 int scamper_http_rx_data_len_get(const scamper_http_t *http, size_t *len)
 int scamper_http_rx_data_get(const scamper_http_t *http, uint8_t *buf, size_t len)
 int scamper_http_tx_hdr_len_get(const scamper_http_t *http, size_t *len)
 int scamper_http_tx_hdr_get(const scamper_http_t *http, uint8_t *buf, size_t len)

 int scamper_http_tx_hdr_name_get(const scamper_http_t *http, const char *name, char **value)
 int scamper_http_rx_hdr_name_get(const scamper_http_t *http, const char *name, char **value)

 scamper_http_hdr_fields_t *scamper_http_rx_hdr_fields_get(const scamper_http_t *http)
 scamper_http_hdr_fields_t *scamper_http_tx_hdr_fields_get(const scamper_http_t *http)

 void scamper_http_hdr_fields_free(scamper_http_hdr_fields_t *htfs)
 size_t scamper_http_hdr_fields_count_get(const scamper_http_hdr_fields_t *htfs)
 scamper_http_hdr_field_t *scamper_http_hdr_fields_get(const scamper_http_hdr_fields_t *htfs, size_t x)
 const char *scamper_http_hdr_field_name_get(const scamper_http_hdr_field_t *htf)
 const char *scamper_http_hdr_field_value_get(const scamper_http_hdr_field_t *htf)
