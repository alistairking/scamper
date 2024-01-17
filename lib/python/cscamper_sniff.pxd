# scamper python interface - cython interface to scamper_sniff_t
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

cdef extern from "scamper_sniff.h":
 ctypedef struct scamper_sniff_t:
  pass
 ctypedef struct scamper_sniff_pkt_t:
  pass

 void scamper_sniff_free(scamper_sniff_t *sniff)

 scamper_list_t *scamper_sniff_list_get(const scamper_sniff_t *sniff)
 scamper_cycle_t *scamper_sniff_cycle_get(const scamper_sniff_t *sniff)
 uint32_t scamper_sniff_userid_get(const scamper_sniff_t *sniff)
 const timeval *scamper_sniff_start_get(const scamper_sniff_t *sniff)
 const timeval *scamper_sniff_finish_get(const scamper_sniff_t *sniff)
 uint8_t scamper_sniff_stop_reason_get(const scamper_sniff_t *sniff)
 uint32_t scamper_sniff_limit_pktc_get(const scamper_sniff_t *sniff)
 const timeval *scamper_sniff_limit_time_get(const scamper_sniff_t *sniff)
 scamper_addr_t *scamper_sniff_src_get(const scamper_sniff_t *sniff)
 uint16_t scamper_sniff_icmpid_get(const scamper_sniff_t *sniff)
 scamper_sniff_pkt_t *scamper_sniff_pkt_get(const scamper_sniff_t *sniff, uint32_t i)
 uint32_t scamper_sniff_pktc_get(const scamper_sniff_t *sniff)

 scamper_sniff_pkt_t *scamper_sniff_pkt_use(scamper_sniff_pkt_t *pkt)
 void scamper_sniff_pkt_free(scamper_sniff_pkt_t *pkt)
 const timeval *scamper_sniff_pkt_tv_get(const scamper_sniff_pkt_t *pkt)
 const uint8_t *scamper_sniff_pkt_data_get(const scamper_sniff_pkt_t *pkt)
 uint16_t scamper_sniff_pkt_len_get(const scamper_sniff_pkt_t *pkt)
