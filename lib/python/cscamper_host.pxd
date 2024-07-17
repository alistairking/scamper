# scamper python interface - cython interface to scamper_host_t
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

cdef extern from "scamper_host.h":
 ctypedef struct scamper_host_t:
  pass
 ctypedef struct scamper_host_rr_t:
  pass
 ctypedef struct scamper_host_query_t:
  pass
 ctypedef struct scamper_host_rr_soa_t:
  pass
 ctypedef struct scamper_host_rr_mx_t:
  pass
 ctypedef struct scamper_host_rr_txt_t:
  pass

 void scamper_host_free(scamper_host_t *host)

 char *scamper_host_stop_tostr(const scamper_host_t *h, char *b, size_t l)
 char *scamper_host_qtype_tostr(uint16_t qtype, char *b, size_t l)
 char *scamper_host_qclass_tostr(uint16_t qclass, char *b, size_t l)
 char *scamper_host_rcode_tostr(uint8_t rcode, char *b, size_t l)

 scamper_list_t *scamper_host_list_get(const scamper_host_t *host)
 scamper_cycle_t *scamper_host_cycle_get(const scamper_host_t *host)
 scamper_addr_t *scamper_host_src_get(const scamper_host_t *host)
 scamper_addr_t *scamper_host_dst_get(const scamper_host_t *host)
 uint32_t scamper_host_userid_get(const scamper_host_t *host)
 const timeval *scamper_host_start_get(const scamper_host_t *host)
 uint16_t scamper_host_flags_get(const scamper_host_t *host)
 uint16_t scamper_host_wait_get(const scamper_host_t *host)
 uint8_t scamper_host_stop_get(const scamper_host_t *host)
 uint8_t scamper_host_retries_get(const scamper_host_t *host)
 uint16_t scamper_host_qtype_get(const scamper_host_t *host)
 uint16_t scamper_host_qclass_get(const scamper_host_t *host)
 const char *scamper_host_qname_get(const scamper_host_t *host)
 uint8_t scamper_host_qcount_get(const scamper_host_t *host)
 scamper_host_query_t *scamper_host_query_get(const scamper_host_t *host, uint8_t i)

 scamper_host_query_t *scamper_host_query_use(scamper_host_query_t *q)
 void scamper_host_query_free(scamper_host_query_t *q)
 const timeval *scamper_host_query_tx_get(const scamper_host_query_t *q)
 const timeval *scamper_host_query_rx_get(const scamper_host_query_t *q)
 uint8_t scamper_host_query_rcode_get(const scamper_host_query_t *q)
 uint8_t scamper_host_query_flags_get(const scamper_host_query_t *q)
 uint16_t scamper_host_query_id_get(const scamper_host_query_t *q)
 uint16_t scamper_host_query_ancount_get(const scamper_host_query_t *q)
 uint16_t scamper_host_query_nscount_get(const scamper_host_query_t *q)
 uint16_t scamper_host_query_arcount_get(const scamper_host_query_t *q)
 scamper_host_rr_t *scamper_host_query_an_get(const scamper_host_query_t *q, uint16_t i)
 scamper_host_rr_t *scamper_host_query_ns_get(const scamper_host_query_t *q, uint16_t i)
 scamper_host_rr_t *scamper_host_query_ar_get(const scamper_host_query_t *q, uint16_t i)

 scamper_host_rr_t *scamper_host_rr_use(scamper_host_rr_t *rr)
 void scamper_host_rr_free(scamper_host_rr_t *rr)
 int scamper_host_rr_data_type(uint16_t class_n, uint16_t type_n)
 const char *scamper_host_rr_data_str_typestr(uint16_t qclass, uint16_t qtype)
 uint16_t scamper_host_rr_class_get(const scamper_host_rr_t *rr)
 uint16_t scamper_host_rr_type_get(const scamper_host_rr_t *rr)
 const char *scamper_host_rr_name_get(const scamper_host_rr_t *rr)
 uint32_t scamper_host_rr_ttl_get(const scamper_host_rr_t *rr)
 const void *scamper_host_rr_v_get(const scamper_host_rr_t *rr)
 scamper_addr_t *scamper_host_rr_addr_get(const scamper_host_rr_t *rr)
 const char *scamper_host_rr_str_get(const scamper_host_rr_t *rr)
 scamper_host_rr_soa_t *scamper_host_rr_soa_get(const scamper_host_rr_t *rr)
 scamper_host_rr_mx_t *scamper_host_rr_mx_get(const scamper_host_rr_t *rr)
 scamper_host_rr_txt_t *scamper_host_rr_txt_get(const scamper_host_rr_t *rr)

 scamper_host_rr_mx_t *scamper_host_rr_mx_use(scamper_host_rr_mx_t *mx)
 void scamper_host_rr_mx_free(scamper_host_rr_mx_t *mx)
 uint16_t scamper_host_rr_mx_preference_get(const scamper_host_rr_mx_t *mx)
 const char *scamper_host_rr_mx_exchange_get(const scamper_host_rr_mx_t *mx)

 scamper_host_rr_soa_t *scamper_host_rr_soa_use(scamper_host_rr_soa_t *soa)
 void scamper_host_rr_soa_free(scamper_host_rr_soa_t *soa)
 const char *scamper_host_rr_soa_mname_get(const scamper_host_rr_soa_t *soa)
 const char *scamper_host_rr_soa_rname_get(const scamper_host_rr_soa_t *soa)
 uint32_t scamper_host_rr_soa_serial_get(const scamper_host_rr_soa_t *soa)
 uint32_t scamper_host_rr_soa_refresh_get(const scamper_host_rr_soa_t *soa)
 uint32_t scamper_host_rr_soa_retry_get(const scamper_host_rr_soa_t *soa)
 uint32_t scamper_host_rr_soa_expire_get(const scamper_host_rr_soa_t *soa)
 uint32_t scamper_host_rr_soa_minimum_get(const scamper_host_rr_soa_t *soa)

 scamper_host_rr_txt_t *scamper_host_rr_txt_use(scamper_host_rr_txt_t *txt)
 void scamper_host_rr_txt_free(scamper_host_rr_txt_t *txt)
 uint16_t scamper_host_rr_txt_strc_get(const scamper_host_rr_txt_t *txt)
 const char *scamper_host_rr_txt_str_get(const scamper_host_rr_txt_t *txt, uint16_t i)
