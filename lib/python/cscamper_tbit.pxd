# scamper python interface - cython interface to scamper_tbit_t
#
# Author: Matthew Luckie
#
# Copyright (C) 2023-2024 The Regents of the University of California
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

cdef extern from "scamper_tbit.h":
 ctypedef struct scamper_tbit_t:
  pass

 ctypedef struct scamper_tbit_pkt_t:
  pass

 char *scamper_tbit_tojson(const scamper_tbit_t *tbit, size_t *l)

 void scamper_tbit_free(scamper_tbit_t *tbit)
 scamper_list_t *scamper_tbit_list_get(const scamper_tbit_t *tbit)
 scamper_cycle_t *scamper_tbit_cycle_get(const scamper_tbit_t *tbit)
 uint32_t scamper_tbit_userid_get(const scamper_tbit_t *tbit)
 scamper_addr_t *scamper_tbit_src_get(const scamper_tbit_t *tbit)
 scamper_addr_t *scamper_tbit_dst_get(const scamper_tbit_t *tbit)
 uint16_t scamper_tbit_sport_get(const scamper_tbit_t *tbit)
 uint16_t scamper_tbit_dport_get(const scamper_tbit_t *tbit)
 const timeval *scamper_tbit_start_get(const scamper_tbit_t *tbit)
 char *scamper_tbit_result_tostr(const scamper_tbit_t *tbit,char *buf,size_t len)
 scamper_tbit_pkt_t *scamper_tbit_pkt_get(const scamper_tbit_t *tbit,uint32_t i)
 uint32_t scamper_tbit_pktc_get(const scamper_tbit_t *tbit)
 uint8_t scamper_tbit_type_get(const scamper_tbit_t *tbit)
 uint8_t scamper_tbit_app_proto_get(const scamper_tbit_t *tbit)
 uint32_t scamper_tbit_options_get(const scamper_tbit_t *tbit)
 uint16_t scamper_tbit_client_mss_get(const scamper_tbit_t *tbit)
 const uint8_t *scamper_tbit_client_fo_cookie_get(const scamper_tbit_t *tbit)
 uint8_t scamper_tbit_client_fo_cookielen_get(const scamper_tbit_t *tbit)
 uint8_t scamper_tbit_client_wscale_get(const scamper_tbit_t *tbit)
 uint8_t scamper_tbit_client_ipttl_get(const scamper_tbit_t *tbit)
 uint8_t scamper_tbit_client_syn_retx_get(const scamper_tbit_t *tbit)
 uint8_t scamper_tbit_client_dat_retx_get(const scamper_tbit_t *tbit)
 uint16_t scamper_tbit_server_mss_get(const scamper_tbit_t *tbit)
 int scamper_tbit_server_fo_cookie_get(scamper_tbit_t *tbit,
			               uint8_t *cookie, uint8_t *cookie_len)

 scamper_tbit_pkt_t *scamper_tbit_pkt_use(scamper_tbit_pkt_t *pkt)
 void scamper_tbit_pkt_free(scamper_tbit_pkt_t *pkt)
 const timeval *scamper_tbit_pkt_tv_get(const scamper_tbit_pkt_t *pkt)
 uint8_t scamper_tbit_pkt_dir_get(const scamper_tbit_pkt_t *pkt)
 uint16_t scamper_tbit_pkt_len_get(const scamper_tbit_pkt_t *pkt)
 const uint8_t *scamper_tbit_pkt_data_get(const scamper_tbit_pkt_t *pkt)
