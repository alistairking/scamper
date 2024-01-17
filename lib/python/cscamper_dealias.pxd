# scamper python interface - cython interface to scamper_dealias_t
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

cdef extern from "scamper_dealias.h":
 ctypedef struct scamper_dealias_t:
  pass
 ctypedef struct scamper_dealias_mercator_t:
  pass
 ctypedef struct scamper_dealias_ally_t:
  pass
 ctypedef struct scamper_dealias_radargun_t:
  pass
 ctypedef struct scamper_dealias_prefixscan_t:
  pass
 ctypedef struct scamper_dealias_bump_t:
  pass
 ctypedef struct scamper_dealias_midarest_t:
  pass
 ctypedef struct scamper_dealias_midardisc_t:
  pass
 ctypedef struct scamper_dealias_midardisc_round_t:
  pass
 ctypedef struct scamper_dealias_probe_t:
  pass
 ctypedef struct scamper_dealias_probedef_udp_t:
  pass
 ctypedef struct scamper_dealias_probedef_icmp_t:
  pass
 ctypedef struct scamper_dealias_probedef_tcp_t:
  pass
 ctypedef struct scamper_dealias_probedef_t:
  pass
 ctypedef struct scamper_dealias_reply_t:
  pass

 void scamper_dealias_free(scamper_dealias_t *dealias)

 scamper_list_t *scamper_dealias_list_get(const scamper_dealias_t *dealias)
 scamper_cycle_t *scamper_dealias_cycle_get(const scamper_dealias_t *dealias)
 uint32_t scamper_dealias_userid_get(const scamper_dealias_t *dealias)
 const timeval *scamper_dealias_start_get(const scamper_dealias_t *dealias)
 scamper_dealias_ally_t *scamper_dealias_ally_get(const scamper_dealias_t *dealias)
 scamper_dealias_mercator_t *scamper_dealias_mercator_get(const scamper_dealias_t *dealias)
 scamper_dealias_radargun_t *scamper_dealias_radargun_get(const scamper_dealias_t *dealias)
 scamper_dealias_prefixscan_t *scamper_dealias_prefixscan_get(const scamper_dealias_t *dealias)
 scamper_dealias_bump_t *scamper_dealias_bump_get(const scamper_dealias_t *dealias)
 scamper_dealias_midarest_t *scamper_dealias_midarest_get(const scamper_dealias_t *dealias)
 scamper_dealias_midardisc_t *scamper_dealias_midardisc_get(const scamper_dealias_t *dealias)
 scamper_dealias_probe_t *scamper_dealias_probe_get(const scamper_dealias_t *dealias, uint32_t i)
 uint32_t scamper_dealias_probec_get(const scamper_dealias_t *dealias)

 bint scamper_dealias_method_is_mercator(const scamper_dealias_t *dealias)
 bint scamper_dealias_method_is_ally(const scamper_dealias_t *dealias)
 bint scamper_dealias_method_is_radargun(const scamper_dealias_t *dealias)
 bint scamper_dealias_method_is_prefixscan(const scamper_dealias_t *dealias)
 bint scamper_dealias_method_is_bump(const scamper_dealias_t *dealias)
 bint scamper_dealias_method_is_midarest(const scamper_dealias_t *dealias)
 bint scamper_dealias_method_is_midardisc(const scamper_dealias_t *dealias)

 uint8_t scamper_dealias_result_get(const scamper_dealias_t *dealias)
 bint scamper_dealias_result_is_aliases(const scamper_dealias_t *dealias)

 scamper_dealias_probedef_t *scamper_dealias_mercator_def_get(const scamper_dealias_mercator_t *mc)
 uint8_t scamper_dealias_mercator_attempts_get(const scamper_dealias_mercator_t *mc)
 const timeval *scamper_dealias_mercator_wait_timeout_get(const scamper_dealias_mercator_t *mc)

 scamper_dealias_probedef_t *scamper_dealias_ally_def0_get(const scamper_dealias_ally_t *ally)
 scamper_dealias_probedef_t *scamper_dealias_ally_def1_get(const scamper_dealias_ally_t *ally)
 const timeval *scamper_dealias_ally_wait_probe_get(const scamper_dealias_ally_t *ally)
 const timeval *scamper_dealias_ally_wait_timeout_get(const scamper_dealias_ally_t *ally)
 uint8_t scamper_dealias_ally_attempts_get(const scamper_dealias_ally_t *ally)
 uint8_t scamper_dealias_ally_flags_get(const scamper_dealias_ally_t *ally)
 uint16_t scamper_dealias_ally_fudge_get(const scamper_dealias_ally_t *ally)
 bint scamper_dealias_ally_is_nobs(const scamper_dealias_ally_t *ally)

 scamper_dealias_probedef_t *scamper_dealias_radargun_def_get(const scamper_dealias_radargun_t *rg, uint32_t i)
 uint32_t scamper_dealias_radargun_defc_get(const scamper_dealias_radargun_t *rg)
 uint16_t scamper_dealias_radargun_rounds_get(const scamper_dealias_radargun_t *rg)
 const timeval *scamper_dealias_radargun_wait_probe_get(const scamper_dealias_radargun_t *rg)
 const timeval *scamper_dealias_radargun_wait_round_get(const scamper_dealias_radargun_t *rg)
 const timeval *scamper_dealias_radargun_wait_timeout_get(const scamper_dealias_radargun_t *rg)
 uint8_t scamper_dealias_radargun_flags_get(const scamper_dealias_radargun_t *rg)

 scamper_addr_t *scamper_dealias_prefixscan_a_get(const scamper_dealias_prefixscan_t *pf)
 scamper_addr_t *scamper_dealias_prefixscan_b_get(const scamper_dealias_prefixscan_t *pf)
 scamper_addr_t *scamper_dealias_prefixscan_ab_get(const scamper_dealias_prefixscan_t *pf)
 scamper_addr_t *scamper_dealias_prefixscan_xs_get(const scamper_dealias_prefixscan_t *pf, uint16_t i)
 uint16_t scamper_dealias_prefixscan_xc_get(const scamper_dealias_prefixscan_t *pf)
 uint8_t scamper_dealias_prefixscan_prefix_get(const scamper_dealias_prefixscan_t *pf)
 uint8_t scamper_dealias_prefixscan_attempts_get(const scamper_dealias_prefixscan_t *pf)
 uint8_t scamper_dealias_prefixscan_replyc_get(const scamper_dealias_prefixscan_t *pf)
 uint16_t scamper_dealias_prefixscan_fudge_get(const scamper_dealias_prefixscan_t *pf)
 const timeval *scamper_dealias_prefixscan_wait_probe_get(const scamper_dealias_prefixscan_t *pf)
 const timeval *scamper_dealias_prefixscan_wait_timeout_get(const scamper_dealias_prefixscan_t *pf)
 uint8_t scamper_dealias_prefixscan_flags_get(const scamper_dealias_prefixscan_t *pf)
 scamper_dealias_probedef_t *scamper_dealias_prefixscan_def_get(const scamper_dealias_prefixscan_t *pf, uint16_t i)
 uint16_t scamper_dealias_prefixscan_defc_get(const scamper_dealias_prefixscan_t *pf)
 bint scamper_dealias_prefixscan_is_csa(const scamper_dealias_prefixscan_t *pfs)
 bint scamper_dealias_prefixscan_is_nobs(const scamper_dealias_prefixscan_t *pfs)

 scamper_dealias_probedef_t *scamper_dealias_bump_def0_get(const scamper_dealias_bump_t *bump)
 scamper_dealias_probedef_t *scamper_dealias_bump_def1_get(const scamper_dealias_bump_t *bump)
 const timeval *scamper_dealias_bump_wait_probe_get(const scamper_dealias_bump_t *bump)
 const timeval *scamper_dealias_bump_limit_get(const scamper_dealias_bump_t *bump)
 uint8_t scamper_dealias_bump_attempts_get(const scamper_dealias_bump_t *bump)

 scamper_dealias_probedef_t *scamper_dealias_midarest_def_get(const scamper_dealias_midarest_t *me, uint16_t i)
 uint16_t scamper_dealias_midarest_defc_get(const scamper_dealias_midarest_t *me)
 uint8_t scamper_dealias_midarest_rounds_get(const scamper_dealias_midarest_t *me)
 const timeval *scamper_dealias_midarest_wait_probe_get(const scamper_dealias_midarest_t *me)
 const timeval *scamper_dealias_midarest_wait_round_get(const scamper_dealias_midarest_t *me)
 const timeval *scamper_dealias_midarest_wait_timeout_get(const scamper_dealias_midarest_t *me)

 scamper_dealias_probedef_t *scamper_dealias_midardisc_def_get(const scamper_dealias_midardisc_t *md, uint32_t i)
 uint32_t scamper_dealias_midardisc_defc_get(const scamper_dealias_midardisc_t *md)
 const timeval *scamper_dealias_midardisc_wait_timeout_get(const scamper_dealias_midardisc_t *md)
 const timeval *scamper_dealias_midardisc_startat_get(const scamper_dealias_midardisc_t *md)

 scamper_dealias_midardisc_round_t *scamper_dealias_midardisc_round_alloc()
 void scamper_dealias_midardisc_round_free(scamper_dealias_midardisc_round_t *r)
 void scamper_dealias_midardisc_round_begin_set(scamper_dealias_midardisc_round_t *r, uint32_t begin)
 void scamper_dealias_midardisc_round_end_set(scamper_dealias_midardisc_round_t *r, uint32_t end)
 void scamper_dealias_midardisc_round_start_set(scamper_dealias_midardisc_round_t *r, const timeval *start)
 uint32_t scamper_dealias_midardisc_round_begin_get(const scamper_dealias_midardisc_round_t *r)
 uint32_t scamper_dealias_midardisc_round_end_get(const scamper_dealias_midardisc_round_t *r)
 const timeval *scamper_dealias_midardisc_round_start_get(const scamper_dealias_midardisc_round_t *r)

 scamper_dealias_probedef_t *scamper_dealias_probe_def_get(const scamper_dealias_probe_t *probe)
 uint32_t scamper_dealias_probe_seq_get(const scamper_dealias_probe_t *probe)
 const timeval *scamper_dealias_probe_tx_get(const scamper_dealias_probe_t *probe)
 scamper_dealias_reply_t *scamper_dealias_probe_reply_get(const scamper_dealias_probe_t *probe, uint16_t i)
 uint16_t scamper_dealias_probe_replyc_get(const scamper_dealias_probe_t *probe)
 uint16_t scamper_dealias_probe_ipid_get(const scamper_dealias_probe_t *probe)

 scamper_addr_t *scamper_dealias_probedef_src_get(const scamper_dealias_probedef_t *pd)
 scamper_addr_t *scamper_dealias_probedef_dst_get(const scamper_dealias_probedef_t *pd)
 uint32_t scamper_dealias_probedef_id_get(const scamper_dealias_probedef_t *pd)
 uint8_t scamper_dealias_probedef_method_get(const scamper_dealias_probedef_t *pd)
 char *scamper_dealias_probedef_method_tostr(const scamper_dealias_probedef_t *pd, char *buf, size_t l)
 int scamper_dealias_probedef_method_fromstr(const char *buf, uint8_t *meth)
 bint scamper_dealias_probedef_is_udp(const scamper_dealias_probedef_t *pd)
 bint scamper_dealias_probedef_is_icmp(const scamper_dealias_probedef_t *pd)
 bint scamper_dealias_probedef_is_tcp(const scamper_dealias_probedef_t *pd)
 uint8_t scamper_dealias_probedef_ttl_get(const scamper_dealias_probedef_t *pd)
 uint8_t scamper_dealias_probedef_tos_get(const scamper_dealias_probedef_t *pd)
 uint16_t scamper_dealias_probedef_size_get(const scamper_dealias_probedef_t *pd)
 uint16_t scamper_dealias_probedef_mtu_get(const scamper_dealias_probedef_t *pd)
 scamper_dealias_probedef_udp_t *scamper_dealias_probedef_udp_get(const scamper_dealias_probedef_t *pd)
 scamper_dealias_probedef_tcp_t *scamper_dealias_probedef_tcp_get(const scamper_dealias_probedef_t *pd)
 scamper_dealias_probedef_icmp_t *scamper_dealias_probedef_icmp_get(const scamper_dealias_probedef_t *pd)
 uint16_t scamper_dealias_probedef_udp_sport_get(const scamper_dealias_probedef_udp_t *udp)
 uint16_t scamper_dealias_probedef_udp_dport_get(const scamper_dealias_probedef_udp_t *udp)
 uint16_t scamper_dealias_probedef_icmp_csum_get(const scamper_dealias_probedef_icmp_t *icmp)
 uint16_t scamper_dealias_probedef_icmp_id_get(const scamper_dealias_probedef_icmp_t *icmp)
 uint16_t scamper_dealias_probedef_tcp_sport_get(const scamper_dealias_probedef_tcp_t *tcp)
 uint16_t scamper_dealias_probedef_tcp_dport_get(const scamper_dealias_probedef_tcp_t *tcp)
 uint8_t scamper_dealias_probedef_tcp_flags_get(const scamper_dealias_probedef_tcp_t *tcp)

 scamper_dealias_probedef_t *scamper_dealias_probedef_alloc()
 int scamper_dealias_probedef_method_set(scamper_dealias_probedef_t *pd, const char *meth)
 int scamper_dealias_probedef_src_set(scamper_dealias_probedef_t *pd, scamper_addr_t *src)
 int scamper_dealias_probedef_dst_set(scamper_dealias_probedef_t *pd, scamper_addr_t *dst)
 void scamper_dealias_probedef_ttl_set(scamper_dealias_probedef_t *pd, uint8_t ttl)
 void scamper_dealias_probedef_tos_set(scamper_dealias_probedef_t *pd, uint8_t tos)
 void scamper_dealias_probedef_size_set(scamper_dealias_probedef_t *pd, uint16_t size)
 void scamper_dealias_probedef_mtu_set(scamper_dealias_probedef_t *pd, uint16_t mtu)
 void scamper_dealias_probedef_icmp_csum_set(scamper_dealias_probedef_icmp_t *icmp, uint16_t cs)
 void scamper_dealias_probedef_icmp_id_set(scamper_dealias_probedef_icmp_t *icmp, uint16_t icmp_id)
 void scamper_dealias_probedef_udp_sport_set(scamper_dealias_probedef_udp_t *udp, uint16_t sp)
 void scamper_dealias_probedef_udp_dport_set(scamper_dealias_probedef_udp_t *udp, uint16_t dp)
 void scamper_dealias_probedef_tcp_sport_set(scamper_dealias_probedef_tcp_t *tcp, uint16_t sp)
 void scamper_dealias_probedef_tcp_dport_set(scamper_dealias_probedef_tcp_t *tcp, uint16_t dp)

 scamper_addr_t *scamper_dealias_reply_src_get(const scamper_dealias_reply_t *reply)
 const timeval *scamper_dealias_reply_rx_get(const scamper_dealias_reply_t *reply)
 uint8_t scamper_dealias_reply_flags_get(const scamper_dealias_reply_t *reply)
 uint8_t scamper_dealias_reply_proto_get(const scamper_dealias_reply_t *reply)
 uint8_t scamper_dealias_reply_ttl_get(const scamper_dealias_reply_t *reply)
 uint16_t scamper_dealias_reply_size_get(const scamper_dealias_reply_t *reply)
 uint8_t scamper_dealias_reply_icmp_type_get(const scamper_dealias_reply_t *reply)
 uint8_t scamper_dealias_reply_icmp_code_get(const scamper_dealias_reply_t *reply)
 uint8_t scamper_dealias_reply_icmp_q_ttl_get(const scamper_dealias_reply_t *reply)
 uint8_t scamper_dealias_reply_tcp_flags_get(const scamper_dealias_reply_t *reply)
 uint16_t scamper_dealias_reply_ipid_get(const scamper_dealias_reply_t *reply)
 uint32_t scamper_dealias_reply_ipid32_get(const scamper_dealias_reply_t *reply)
 bint scamper_dealias_reply_is_ipid32(const scamper_dealias_reply_t *reply)
 bint scamper_dealias_reply_is_icmp(const scamper_dealias_reply_t *reply)
 bint scamper_dealias_reply_is_icmp_q(const scamper_dealias_reply_t *reply)
 bint scamper_dealias_reply_is_icmp_unreach(const scamper_dealias_reply_t *reply)
 bint scamper_dealias_reply_is_icmp_unreach_port(const scamper_dealias_reply_t *reply)
 bint scamper_dealias_reply_is_icmp_ttl_exp(const scamper_dealias_reply_t *reply)
 bint scamper_dealias_reply_is_tcp(const scamper_dealias_reply_t *reply)
 bint scamper_dealias_reply_from_target(const scamper_dealias_probe_t *probe,
				        const scamper_dealias_reply_t *reply)

 scamper_dealias_probe_t *scamper_dealias_probe_use(scamper_dealias_probe_t *probe)
 void scamper_dealias_probe_free(scamper_dealias_probe_t *probe)
 scamper_dealias_probedef_t *scamper_dealias_probedef_use(scamper_dealias_probedef_t *pd)
 void scamper_dealias_probedef_free(scamper_dealias_probedef_t *pd)
 scamper_dealias_reply_t *scamper_dealias_reply_use(scamper_dealias_reply_t *reply)
 void scamper_dealias_reply_free(scamper_dealias_reply_t *reply)
 scamper_dealias_mercator_t *scamper_dealias_mercator_use(scamper_dealias_mercator_t *mc)
 void scamper_dealias_mercator_free(scamper_dealias_mercator_t *mc)
 scamper_dealias_ally_t *scamper_dealias_ally_use(scamper_dealias_ally_t *ally)
 void scamper_dealias_ally_free(scamper_dealias_ally_t *ally)
 scamper_dealias_radargun_t *scamper_dealias_radargun_use(scamper_dealias_radargun_t *rg)
 void scamper_dealias_radargun_free(scamper_dealias_radargun_t *rg)
 scamper_dealias_prefixscan_t *scamper_dealias_prefixscan_use(scamper_dealias_prefixscan_t *pf)
 void scamper_dealias_prefixscan_free(scamper_dealias_prefixscan_t *pf)
