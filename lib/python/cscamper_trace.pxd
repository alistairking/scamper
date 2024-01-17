# scamper python interface - cython interface to scamper_trace_t
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

cdef extern from "scamper_icmpext.h":
 ctypedef struct scamper_icmpext_t:
  pass

cdef extern from "scamper_list.h":
 ctypedef struct scamper_list_t:
  pass
 ctypedef struct scamper_cycle_t:
  pass

cdef extern from "scamper_trace.h":
 ctypedef struct scamper_trace_t:
  pass

 ctypedef struct scamper_trace_hop_t:
  pass

 ctypedef struct scamper_trace_pmtud_t:
  pass

 void scamper_trace_free(scamper_trace_t *trace)

 scamper_list_t *scamper_trace_list_get(const scamper_trace_t *trace)
 scamper_cycle_t *scamper_trace_cycle_get(const scamper_trace_t *trace)
 scamper_addr_t *scamper_trace_src_get(const scamper_trace_t *trace)
 scamper_addr_t *scamper_trace_dst_get(const scamper_trace_t *trace)
 scamper_addr_t *scamper_trace_rtr_get(const scamper_trace_t *trace)
 uint32_t scamper_trace_userid_get(const scamper_trace_t *trace)
 const timeval *scamper_trace_start_get(const scamper_trace_t *trace)
 uint8_t scamper_trace_stop_reason_get(const scamper_trace_t *trace)
 uint8_t scamper_trace_stop_data_get(const scamper_trace_t *trace)
 scamper_trace_hop_t *scamper_trace_hop_get(const scamper_trace_t *trace,
					    uint8_t i)
 uint16_t scamper_trace_hop_count_get(const scamper_trace_t *trace)

 uint8_t scamper_trace_type_get(const scamper_trace_t *trace)
 uint8_t scamper_trace_attempts_get(const scamper_trace_t *trace)
 uint8_t scamper_trace_hoplimit_get(const scamper_trace_t *trace)
 uint8_t scamper_trace_squeries_get(const scamper_trace_t *trace)
 uint8_t scamper_trace_gaplimit_get(const scamper_trace_t *trace)
 uint8_t scamper_trace_gapaction_get(const scamper_trace_t *trace)
 uint8_t scamper_trace_firsthop_get(const scamper_trace_t *trace)
 uint8_t scamper_trace_tos_get(const scamper_trace_t *trace)
 const timeval *scamper_trace_wait_timeout_get(const scamper_trace_t *trace)
 const timeval *scamper_trace_wait_probe_get(const scamper_trace_t *trace)
 uint8_t scamper_trace_loops_get(const scamper_trace_t *trace)
 uint8_t scamper_trace_loopaction_get(const scamper_trace_t *trace)
 uint8_t scamper_trace_confidence_get(const scamper_trace_t *trace)
 uint16_t scamper_trace_probe_size_get(const scamper_trace_t *trace)
 uint16_t scamper_trace_sport_get(const scamper_trace_t *trace)
 uint16_t scamper_trace_dport_get(const scamper_trace_t *trace)
 uint16_t scamper_trace_offset_get(const scamper_trace_t *trace)
 uint32_t scamper_trace_flags_get(const scamper_trace_t *trace)
 uint16_t scamper_trace_payload_len_get(const scamper_trace_t *trace)
 const uint8_t *scamper_trace_payload_get(const scamper_trace_t *trace)
 uint16_t scamper_trace_probec_get(const scamper_trace_t *trace)
 bint scamper_trace_type_is_udp(const scamper_trace_t *trace)
 bint scamper_trace_type_is_tcp(const scamper_trace_t *trace)
 bint scamper_trace_type_is_icmp(const scamper_trace_t *trace)
 bint scamper_trace_flag_is_icmpcsumdp(const scamper_trace_t *trace)

 scamper_trace_hop_t *scamper_trace_hop_use(scamper_trace_hop_t *hop)
 void scamper_trace_hop_free(scamper_trace_hop_t *hop)
 scamper_addr_t *scamper_trace_hop_addr_get(const scamper_trace_hop_t *hop)
 const char *scamper_trace_hop_name_get(const scamper_trace_hop_t *hop)
 uint32_t scamper_trace_hop_flags_get(const scamper_trace_hop_t *hop)
 const timeval *scamper_trace_hop_tx_get(const scamper_trace_hop_t *hop)
 const timeval *scamper_trace_hop_rtt_get(const scamper_trace_hop_t *hop)
 uint8_t scamper_trace_hop_probe_id_get(const scamper_trace_hop_t *hop)
 uint8_t scamper_trace_hop_probe_ttl_get(const scamper_trace_hop_t *hop)
 uint16_t scamper_trace_hop_probe_size_get(const scamper_trace_hop_t *hop)
 uint8_t scamper_trace_hop_reply_ttl_get(const scamper_trace_hop_t *hop)
 uint8_t scamper_trace_hop_reply_tos_get(const scamper_trace_hop_t *hop)
 uint16_t scamper_trace_hop_reply_size_get(const scamper_trace_hop_t *hop)
 uint16_t scamper_trace_hop_reply_ipid_get(const scamper_trace_hop_t *hop)
 uint8_t scamper_trace_hop_icmp_type_get(const scamper_trace_hop_t *hop)
 uint8_t scamper_trace_hop_icmp_code_get(const scamper_trace_hop_t *hop)
 bint scamper_trace_hop_is_tcp(const scamper_trace_hop_t *hop)
 bint scamper_trace_hop_is_icmp(const scamper_trace_hop_t *hop)
 bint scamper_trace_hop_is_icmp_q(const scamper_trace_hop_t *hop)
 bint scamper_trace_hop_is_icmp_unreach_port(const scamper_trace_hop_t *hop)
 bint scamper_trace_hop_is_icmp_echo_reply(const scamper_trace_hop_t *hop)
 bint scamper_trace_hop_is_icmp_ttl_exp(const scamper_trace_hop_t *hop)
 bint scamper_trace_hop_is_icmp_ptb(const scamper_trace_hop_t *hop)
 uint16_t scamper_trace_hop_icmp_nhmtu_get(const scamper_trace_hop_t *hop)
 uint8_t scamper_trace_hop_icmp_q_ttl_get(const scamper_trace_hop_t *hop)
 uint8_t scamper_trace_hop_icmp_q_tos_get(const scamper_trace_hop_t *hop)
 uint16_t scamper_trace_hop_icmp_q_ipl_get(const scamper_trace_hop_t *hop)
 uint8_t scamper_trace_hop_tcp_flags_get(const scamper_trace_hop_t *hop)
 scamper_icmpext_t *scamper_trace_hop_icmpext_get(const scamper_trace_hop_t *hop)

 scamper_trace_pmtud_t *scamper_trace_pmtud_get(const scamper_trace_t *trace)
 void scamper_trace_pmtud_free(scamper_trace_pmtud_t *pmtud)
 scamper_trace_pmtud_t *scamper_trace_pmtud_use(scamper_trace_pmtud_t *pmtud)
 uint8_t scamper_trace_pmtud_ver_get(const scamper_trace_pmtud_t *pmtud)
 uint16_t scamper_trace_pmtud_pmtu_get(const scamper_trace_pmtud_t *pmtud)
 uint16_t scamper_trace_pmtud_ifmtu_get(const scamper_trace_pmtud_t *pmtud)
 uint16_t scamper_trace_pmtud_outmtu_get(const scamper_trace_pmtud_t *pmtud)
