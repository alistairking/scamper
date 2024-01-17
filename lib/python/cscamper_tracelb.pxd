# scamper python interface - cython interface to scamper_tracelb_t
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

cdef extern from "scamper_tracelb.h":
 ctypedef struct scamper_tracelb_t:
  pass
 ctypedef struct scamper_tracelb_node_t:
  pass
 ctypedef struct scamper_tracelb_link_t:
  pass
 ctypedef struct scamper_tracelb_probe_t:
  pass
 ctypedef struct scamper_tracelb_reply_t:
  pass
 ctypedef struct scamper_tracelb_probeset_t:
  pass
 ctypedef struct scamper_tracelb_probeset_summary_t:
  pass

 void scamper_tracelb_free(scamper_tracelb_t *tracelb)
 char *scamper_tracelb_type_tostr(const scamper_tracelb_t *trace, char *buf, size_t len)
 scamper_list_t *scamper_tracelb_list_get(const scamper_tracelb_t *trace)
 scamper_cycle_t *scamper_tracelb_cycle_get(const scamper_tracelb_t *trace)
 uint32_t scamper_tracelb_userid_get(const scamper_tracelb_t *trace)
 scamper_addr_t *scamper_tracelb_src_get(const scamper_tracelb_t *trace)
 scamper_addr_t *scamper_tracelb_dst_get(const scamper_tracelb_t *trace)
 scamper_addr_t *scamper_tracelb_rtr_get(const scamper_tracelb_t *trace)
 const timeval *scamper_tracelb_start_get(const scamper_tracelb_t *trace)
 uint16_t scamper_tracelb_sport_get(const scamper_tracelb_t *trace)
 uint16_t scamper_tracelb_dport_get(const scamper_tracelb_t *trace)
 uint16_t scamper_tracelb_probe_size_get(const scamper_tracelb_t *trace)
 uint8_t scamper_tracelb_type_get(const scamper_tracelb_t *trace)
 uint8_t scamper_tracelb_firsthop_get(const scamper_tracelb_t *trace)
 const timeval *scamper_tracelb_wait_timeout_get(const scamper_tracelb_t *trace)
 const timeval *scamper_tracelb_wait_probe_get(const scamper_tracelb_t *trace)
 uint8_t scamper_tracelb_attempts_get(const scamper_tracelb_t *trace)
 uint8_t scamper_tracelb_confidence_get(const scamper_tracelb_t *trace)
 uint8_t scamper_tracelb_tos_get(const scamper_tracelb_t *trace)
 uint8_t scamper_tracelb_gaplimit_get(const scamper_tracelb_t *trace)
 uint32_t scamper_tracelb_flags_get(const scamper_tracelb_t *trace)
 uint32_t scamper_tracelb_probec_max_get(const scamper_tracelb_t *trace)
 uint16_t scamper_tracelb_nodec_get(const scamper_tracelb_t *trace)
 scamper_tracelb_node_t *scamper_tracelb_node_get(const scamper_tracelb_t *trace, uint16_t i)
 uint16_t scamper_tracelb_linkc_get(const scamper_tracelb_t *trace)
 scamper_tracelb_link_t *scamper_tracelb_link_get(const scamper_tracelb_t *trace, uint16_t i)
 uint32_t scamper_tracelb_probec_get(const scamper_tracelb_t *trace)
 uint32_t scamper_tracelb_error_get(const scamper_tracelb_t *trace)
 bint scamper_tracelb_type_is_udp(const scamper_tracelb_t *trace)
 bint scamper_tracelb_type_is_tcp(const scamper_tracelb_t *trace)
 bint scamper_tracelb_type_is_icmp(const scamper_tracelb_t *trace)
 bint scamper_tracelb_type_is_vary_sport(const scamper_tracelb_t *trace)

 scamper_tracelb_node_t *scamper_tracelb_node_use(scamper_tracelb_node_t *node)
 void scamper_tracelb_node_free(scamper_tracelb_node_t *node)
 scamper_addr_t *scamper_tracelb_node_addr_get(const scamper_tracelb_node_t *node)
 const char *scamper_tracelb_node_name_get(const scamper_tracelb_node_t *node)
 uint32_t scamper_tracelb_node_flags_get(const scamper_tracelb_node_t *node)
 uint8_t scamper_tracelb_node_q_ttl_get(const scamper_tracelb_node_t *node)
 scamper_tracelb_link_t *scamper_tracelb_node_link_get(const scamper_tracelb_node_t *node, uint16_t i)
 uint16_t scamper_tracelb_node_linkc_get(const scamper_tracelb_node_t *node)
 bint scamper_tracelb_node_is_q_ttl(const scamper_tracelb_node_t *node)

 scamper_tracelb_link_t *scamper_tracelb_link_use(scamper_tracelb_link_t *link)
 void scamper_tracelb_link_free(scamper_tracelb_link_t *link)
 scamper_tracelb_node_t *scamper_tracelb_link_from_get(const scamper_tracelb_link_t *link)
 scamper_tracelb_node_t *scamper_tracelb_link_to_get(const scamper_tracelb_link_t *link)
 uint8_t scamper_tracelb_link_hopc_get(const scamper_tracelb_link_t *link)
 scamper_tracelb_probeset_t *scamper_tracelb_link_probeset_get(const scamper_tracelb_link_t *link, uint8_t hop)

 scamper_tracelb_probeset_t *scamper_tracelb_probeset_use(scamper_tracelb_probeset_t *pset)
 void scamper_tracelb_probeset_free(scamper_tracelb_probeset_t *pset)

 scamper_tracelb_probe_t *scamper_tracelb_probeset_probe_get(const scamper_tracelb_probeset_t *pset, uint16_t i)
 uint16_t scamper_tracelb_probeset_probec_get(const scamper_tracelb_probeset_t *pset)

 scamper_tracelb_probe_t *scamper_tracelb_probe_use(scamper_tracelb_probe_t *probe)
 void scamper_tracelb_probe_free(scamper_tracelb_probe_t *probe)
 const timeval *scamper_tracelb_probe_tx_get(const scamper_tracelb_probe_t *probe)
 uint16_t scamper_tracelb_probe_flowid_get(const scamper_tracelb_probe_t *probe)
 uint8_t scamper_tracelb_probe_ttl_get(const scamper_tracelb_probe_t *probe)
 uint8_t scamper_tracelb_probe_attempt_get(const scamper_tracelb_probe_t *probe)
 scamper_tracelb_reply_t *scamper_tracelb_probe_rx_get(const scamper_tracelb_probe_t *probe, uint16_t i)
 uint16_t scamper_tracelb_probe_rxc_get(const scamper_tracelb_probe_t *probe)

 scamper_tracelb_reply_t *scamper_tracelb_reply_use(scamper_tracelb_reply_t *reply)
 void scamper_tracelb_reply_free(scamper_tracelb_reply_t *reply)
 scamper_addr_t *scamper_tracelb_reply_from_get(const scamper_tracelb_reply_t *reply)
 const timeval *scamper_tracelb_reply_rx_get(const scamper_tracelb_reply_t *reply)
 uint16_t scamper_tracelb_reply_ipid_get(const scamper_tracelb_reply_t *reply)
 uint8_t scamper_tracelb_reply_ttl_get(const scamper_tracelb_reply_t *reply)
 uint32_t scamper_tracelb_reply_flags_get(const scamper_tracelb_reply_t *reply)
 uint8_t scamper_tracelb_reply_icmp_type_get(const scamper_tracelb_reply_t *reply)
 uint8_t scamper_tracelb_reply_icmp_code_get(const scamper_tracelb_reply_t *reply)
 uint8_t scamper_tracelb_reply_icmp_q_tos_get(const scamper_tracelb_reply_t *reply)
 uint8_t scamper_tracelb_reply_icmp_q_ttl_get(const scamper_tracelb_reply_t *reply)
 uint8_t scamper_tracelb_reply_tcp_flags_get(const scamper_tracelb_reply_t *reply)
 bint scamper_tracelb_reply_is_icmp(const scamper_tracelb_reply_t *reply)
 bint scamper_tracelb_reply_is_icmp_q(const scamper_tracelb_reply_t *reply)
 bint scamper_tracelb_reply_is_icmp_ttl_exp(const scamper_tracelb_reply_t *reply)
 bint scamper_tracelb_reply_is_icmp_unreach(const scamper_tracelb_reply_t *reply)
 bint scamper_tracelb_reply_is_tcp(const scamper_tracelb_reply_t *reply)
 bint scamper_tracelb_reply_is_reply_ttl(const scamper_tracelb_reply_t *reply)
 scamper_icmpext_t *scamper_tracelb_reply_icmp_ext_get(const scamper_tracelb_reply_t *reply)

 scamper_tracelb_probeset_summary_t *scamper_tracelb_probeset_summary_alloc(const scamper_tracelb_probeset_t *set)
 void scamper_tracelb_probeset_summary_free(scamper_tracelb_probeset_summary_t *sum)
 uint16_t scamper_tracelb_probeset_summary_addrc_get(const scamper_tracelb_probeset_summary_t *sum)
 scamper_addr_t *scamper_tracelb_probeset_summary_addr_get(const scamper_tracelb_probeset_summary_t *sum, uint16_t i)
 uint16_t scamper_tracelb_probeset_summary_nullc_get(const scamper_tracelb_probeset_summary_t *sum)
