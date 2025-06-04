# scamper python interface - cython interface to scamper_trace_t
#
# Author: Matthew Luckie
#
# Copyright (C) 2023-2025 The Regents of the University of California
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
 ctypedef struct scamper_icmpexts_t:
  pass

cdef extern from "scamper_list.h":
 ctypedef struct scamper_list_t:
  pass
 ctypedef struct scamper_cycle_t:
  pass

cdef extern from "scamper_trace.h":
 ctypedef struct scamper_trace_t:
  pass

 ctypedef struct scamper_trace_probe_t:
  pass

 ctypedef struct scamper_trace_reply_t:
  pass

 ctypedef struct scamper_trace_hopiter_t:
  pass

 ctypedef struct scamper_trace_pmtud_t:
  pass

 ctypedef struct scamper_trace_pmtud_note_t:
  pass

 ctypedef struct scamper_trace_pmtud_noteiter_t:
  pass

 char *scamper_trace_tojson(const scamper_trace_t *trace, size_t *l)
 char *scamper_trace_totext(const scamper_trace_t *trace, size_t *l)

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
 char *scamper_trace_stop_tostr(const scamper_trace_t *trace,
                                char *buf, size_t len)
 uint16_t scamper_trace_hop_count_get(const scamper_trace_t *trace)
 uint8_t  scamper_trace_stop_hop_get(const scamper_trace_t *trace)

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
 uint16_t scamper_trace_size_get(const scamper_trace_t *trace)
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

 scamper_trace_hopiter_t *scamper_trace_hopiter_alloc()
 void scamper_trace_hopiter_free(scamper_trace_hopiter_t *hi)
 void scamper_trace_hopiter_reset(scamper_trace_hopiter_t *hi)
 int scamper_trace_hopiter_ttl_set(scamper_trace_hopiter_t *hi, uint8_t ttl, uint8_t max)
 scamper_trace_probe_t *scamper_trace_hopiter_probe_get(const scamper_trace_hopiter_t *hi)
 scamper_trace_reply_t *scamper_trace_hopiter_next(const scamper_trace_t *trace, scamper_trace_hopiter_t *hi)

 scamper_trace_probe_t *scamper_trace_probe_use(scamper_trace_probe_t *probe)
 void scamper_trace_probe_free(scamper_trace_probe_t *probe)
 uint8_t scamper_trace_probe_id_get(const scamper_trace_probe_t *probe)
 uint8_t scamper_trace_probe_ttl_get(const scamper_trace_probe_t *probe)
 uint16_t scamper_trace_probe_size_get(const scamper_trace_probe_t *probe)
 const timeval *scamper_trace_probe_tx_get(const scamper_trace_probe_t *probe)

 scamper_trace_reply_t *scamper_trace_reply_use(scamper_trace_reply_t *reply)
 void scamper_trace_reply_free(scamper_trace_reply_t *reply)
 scamper_addr_t *scamper_trace_reply_addr_get(const scamper_trace_reply_t *reply)
 const char *scamper_trace_reply_name_get(const scamper_trace_reply_t *reply)
 uint32_t scamper_trace_reply_flags_get(const scamper_trace_reply_t *reply)
 const timeval *scamper_trace_reply_rtt_get(const scamper_trace_reply_t *reply)

 uint8_t scamper_trace_reply_ttl_get(const scamper_trace_reply_t *reply)
 uint8_t scamper_trace_reply_tos_get(const scamper_trace_reply_t *reply)
 uint16_t scamper_trace_reply_size_get(const scamper_trace_reply_t *reply)
 uint16_t scamper_trace_reply_ipid_get(const scamper_trace_reply_t *reply)
 uint8_t scamper_trace_reply_icmp_type_get(const scamper_trace_reply_t *reply)
 uint8_t scamper_trace_reply_icmp_code_get(const scamper_trace_reply_t *reply)
 bint scamper_trace_reply_is_tcp(const scamper_trace_reply_t *reply)
 bint scamper_trace_reply_is_icmp(const scamper_trace_reply_t *reply)
 bint scamper_trace_reply_is_icmp_q(const scamper_trace_reply_t *reply)
 bint scamper_trace_reply_is_icmp_unreach_port(const scamper_trace_reply_t *reply)
 bint scamper_trace_reply_is_icmp_echo_reply(const scamper_trace_reply_t *reply)
 bint scamper_trace_reply_is_icmp_ttl_exp(const scamper_trace_reply_t *reply)
 bint scamper_trace_reply_is_icmp_ptb(const scamper_trace_reply_t *reply)
 uint16_t scamper_trace_reply_icmp_nhmtu_get(const scamper_trace_reply_t *reply)
 uint8_t scamper_trace_reply_icmp_q_ttl_get(const scamper_trace_reply_t *reply)
 uint8_t scamper_trace_reply_icmp_q_tos_get(const scamper_trace_reply_t *reply)
 uint16_t scamper_trace_reply_icmp_q_ipl_get(const scamper_trace_reply_t *reply)
 uint8_t scamper_trace_reply_tcp_flags_get(const scamper_trace_reply_t *reply)
 scamper_icmpexts_t *scamper_trace_reply_icmp_exts_get(const scamper_trace_reply_t *reply)

 scamper_trace_pmtud_t *scamper_trace_pmtud_get(const scamper_trace_t *trace)
 void scamper_trace_pmtud_free(scamper_trace_pmtud_t *pmtud)
 scamper_trace_pmtud_t *scamper_trace_pmtud_use(scamper_trace_pmtud_t *pmtud)
 uint8_t scamper_trace_pmtud_ver_get(const scamper_trace_pmtud_t *pmtud)
 uint16_t scamper_trace_pmtud_pmtu_get(const scamper_trace_pmtud_t *pmtud)
 uint16_t scamper_trace_pmtud_ifmtu_get(const scamper_trace_pmtud_t *pmtud)
 uint16_t scamper_trace_pmtud_outmtu_get(const scamper_trace_pmtud_t *pmtud)

 scamper_trace_pmtud_note_t *scamper_trace_pmtud_note_use(scamper_trace_pmtud_note_t *n)
 void scamper_trace_pmtud_note_free(scamper_trace_pmtud_note_t *n)
 scamper_trace_probe_t *scamper_trace_pmtud_note_probe_get(const scamper_trace_pmtud_note_t *n)
 scamper_trace_reply_t *scamper_trace_pmtud_note_reply_get(const scamper_trace_pmtud_note_t *n)
 uint16_t scamper_trace_pmtud_note_nhmtu_get(const scamper_trace_pmtud_note_t *n)
 uint8_t scamper_trace_pmtud_note_type_get(const scamper_trace_pmtud_note_t *n)
 char *scamper_trace_pmtud_note_type_tostr(const scamper_trace_pmtud_note_t *n, char *buf, size_t len)

 scamper_trace_pmtud_noteiter_t *scamper_trace_pmtud_noteiter_alloc()
 void scamper_trace_pmtud_noteiter_free(scamper_trace_pmtud_noteiter_t *ni)
 scamper_trace_pmtud_note_t *scamper_trace_pmtud_noteiter_next(const scamper_trace_t *trace, scamper_trace_pmtud_noteiter_t *ni)
 uint8_t scamper_trace_pmtud_noteiter_dist_get(const scamper_trace_t *trace, scamper_trace_pmtud_noteiter_t *ni)
