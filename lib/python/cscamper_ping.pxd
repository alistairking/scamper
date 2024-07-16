# scamper python interface - cython interface to scamper_ping_t
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

cdef extern from "scamper_ping.h":
 ctypedef struct scamper_ping_t:
  pass
 ctypedef struct scamper_ping_v4ts_t:
  pass
 ctypedef struct scamper_ping_reply_t:
  pass
 ctypedef struct scamper_ping_reply_v4rr_t:
  pass
 ctypedef struct scamper_ping_reply_v4ts_t:
  pass
 ctypedef struct scamper_ping_reply_tsreply_t:
  pass
 ctypedef struct scamper_ping_stats_t:
  pass

 void scamper_ping_free(scamper_ping_t *ping)

 scamper_list_t *scamper_ping_list_get(const scamper_ping_t *ping)
 scamper_cycle_t *scamper_ping_cycle_get(const scamper_ping_t *ping)
 uint32_t scamper_ping_userid_get(const scamper_ping_t *ping)
 scamper_addr_t *scamper_ping_dst_get(const scamper_ping_t *ping)
 scamper_addr_t *scamper_ping_src_get(const scamper_ping_t *ping)
 scamper_addr_t *scamper_ping_rtr_get(const scamper_ping_t *ping)
 const timeval *scamper_ping_start_get(const scamper_ping_t *ping)
 uint8_t scamper_ping_stop_reason_get(const scamper_ping_t *ping)
 uint8_t scamper_ping_stop_data_get(const scamper_ping_t *ping)
 const uint8_t *scamper_ping_probe_data_get(const scamper_ping_t *ping)
 uint16_t scamper_ping_probe_datalen_get(const scamper_ping_t *ping)
 uint16_t scamper_ping_probe_count_get(const scamper_ping_t *ping)
 uint16_t scamper_ping_probe_size_get(const scamper_ping_t *ping)
 uint8_t scamper_ping_probe_method_get(const scamper_ping_t *ping)
 char *scamper_ping_method_tostr(const scamper_ping_t *, char *, size_t)
 bint scamper_ping_method_is_icmp(const scamper_ping_t *ping)
 bint scamper_ping_method_is_icmp_time(const scamper_ping_t *ping)
 bint scamper_ping_method_is_tcp(const scamper_ping_t *ping)
 bint scamper_ping_method_is_tcp_ack_sport(const scamper_ping_t *ping)
 bint scamper_ping_method_is_udp(const scamper_ping_t *ping)
 bint scamper_ping_method_is_vary_sport(const scamper_ping_t *ping)
 bint scamper_ping_method_is_vary_dport(const scamper_ping_t *ping)
 const timeval *scamper_ping_wait_probe_get(const scamper_ping_t *ping)
 const timeval *scamper_ping_wait_timeout_get(const scamper_ping_t *ping)
 uint8_t scamper_ping_probe_ttl_get(const scamper_ping_t *ping)
 uint8_t scamper_ping_probe_tos_get(const scamper_ping_t *ping)
 uint16_t scamper_ping_probe_sport_get(const scamper_ping_t *ping)
 uint16_t scamper_ping_probe_dport_get(const scamper_ping_t *ping)
 uint16_t scamper_ping_probe_icmpsum_get(const scamper_ping_t *ping)
 uint32_t scamper_ping_probe_tcpseq_get(const scamper_ping_t *ping)
 uint32_t scamper_ping_probe_tcpack_get(const scamper_ping_t *ping)
 scamper_ping_v4ts_t *scamper_ping_probe_tsps_get(const scamper_ping_t *ping)
 uint32_t scamper_ping_flags_get(const scamper_ping_t *ping)
 uint16_t scamper_ping_reply_count_get(const scamper_ping_t *ping)
 uint16_t scamper_ping_reply_pmtu_get(const scamper_ping_t *ping)
 uint16_t scamper_ping_sent_get(const scamper_ping_t *ping)
 scamper_ping_reply_t *scamper_ping_reply_get(const scamper_ping_t *ping, uint16_t i)

 void scamper_ping_reply_free(scamper_ping_reply_t *reply)
 scamper_ping_reply_t *scamper_ping_reply_use(scamper_ping_reply_t *reply)

 bint scamper_ping_reply_is_from_target(const scamper_ping_t *ping, const scamper_ping_reply_t *reply)
 scamper_addr_t *scamper_ping_reply_addr_get(const scamper_ping_reply_t *reply)
 uint16_t scamper_ping_reply_probe_id_get(const scamper_ping_reply_t *reply)
 uint16_t scamper_ping_reply_probe_ipid_get(const scamper_ping_reply_t *reply)
 uint8_t scamper_ping_reply_proto_get(const scamper_ping_reply_t *reply)
 uint8_t scamper_ping_reply_ttl_get(const scamper_ping_reply_t *reply)
 uint16_t scamper_ping_reply_size_get(const scamper_ping_reply_t *reply)
 uint16_t scamper_ping_reply_ipid_get(const scamper_ping_reply_t *reply)
 uint32_t scamper_ping_reply_ipid32_get(const scamper_ping_reply_t *reply)
 uint32_t scamper_ping_reply_flags_get(const scamper_ping_reply_t *reply)
 bint scamper_ping_reply_flag_is_reply_ipid(const scamper_ping_reply_t *reply)
 uint8_t scamper_ping_reply_icmp_type_get(const scamper_ping_reply_t *reply)
 uint8_t scamper_ping_reply_icmp_code_get(const scamper_ping_reply_t *reply)
 uint8_t scamper_ping_reply_tcp_flags_get(const scamper_ping_reply_t *reply)
 bint scamper_ping_reply_is_icmp(const scamper_ping_reply_t *reply)
 bint scamper_ping_reply_is_tcp(const scamper_ping_reply_t *reply)
 bint scamper_ping_reply_is_udp(const scamper_ping_reply_t *reply)
 bint scamper_ping_reply_is_icmp_echo_reply(const scamper_ping_reply_t *reply)
 bint scamper_ping_reply_is_icmp_unreach(const scamper_ping_reply_t *reply)
 bint scamper_ping_reply_is_icmp_unreach_port(const scamper_ping_reply_t *reply)
 bint scamper_ping_reply_is_icmp_ttl_exp(const scamper_ping_reply_t *reply)
 bint scamper_ping_reply_is_icmp_tsreply(const scamper_ping_reply_t *reply)
 const timeval *scamper_ping_reply_tx_get(const scamper_ping_reply_t *reply)
 const timeval *scamper_ping_reply_rtt_get(const scamper_ping_reply_t *reply)
 scamper_ping_reply_t *scamper_ping_reply_next_get(const scamper_ping_reply_t *reply)
 scamper_ping_reply_v4rr_t *scamper_ping_reply_v4rr_get(const scamper_ping_reply_t *reply)
 scamper_ping_reply_v4ts_t *scamper_ping_reply_v4ts_get(const scamper_ping_reply_t *reply)
 scamper_ping_reply_tsreply_t *scamper_ping_reply_tsreply_get(const scamper_ping_reply_t *reply)
 const char *scamper_ping_reply_ifname_get(const scamper_ping_reply_t *reply)

 void scamper_ping_reply_tsreply_free(scamper_ping_reply_tsreply_t *tsr)
 uint32_t scamper_ping_reply_tsreply_tso_get(const scamper_ping_reply_tsreply_t *tsr)
 uint32_t scamper_ping_reply_tsreply_tsr_get(const scamper_ping_reply_tsreply_t *tsr)
 uint32_t scamper_ping_reply_tsreply_tst_get(const scamper_ping_reply_tsreply_t *tsr)

 void scamper_ping_reply_v4rr_free(scamper_ping_reply_v4rr_t *rr)
 uint8_t scamper_ping_reply_v4rr_ipc_get(const scamper_ping_reply_v4rr_t *rr)
 scamper_addr_t *scamper_ping_reply_v4rr_ip_get(const scamper_ping_reply_v4rr_t *rr, uint8_t i)

 void scamper_ping_reply_v4ts_free(scamper_ping_reply_v4ts_t *ts)
 uint8_t scamper_ping_reply_v4ts_tsc_get(const scamper_ping_reply_v4ts_t *ts)
 uint32_t scamper_ping_reply_v4ts_ts_get(const scamper_ping_reply_v4ts_t *ts, uint8_t i)
 bint scamper_ping_reply_v4ts_hasip(const scamper_ping_reply_v4ts_t *ts)
 scamper_addr_t *scamper_ping_reply_v4ts_ip_get(const scamper_ping_reply_v4ts_t *ts, uint8_t i)

 void scamper_ping_v4ts_free(scamper_ping_v4ts_t *ts)
 uint8_t scamper_ping_v4ts_ipc_get(const scamper_ping_v4ts_t *ts)
 scamper_addr_t *scamper_ping_v4ts_ip_get(const scamper_ping_v4ts_t *ts, uint8_t i)

 scamper_ping_stats_t *scamper_ping_stats_alloc(const scamper_ping_t *ping)
 void scamper_ping_stats_free(scamper_ping_stats_t *stats)
 uint32_t scamper_ping_stats_nreplies_get(const scamper_ping_stats_t *stats)
 uint32_t scamper_ping_stats_ndups_get(const scamper_ping_stats_t *stats)
 uint32_t scamper_ping_stats_nloss_get(const scamper_ping_stats_t *stats)
 uint32_t scamper_ping_stats_nerrs_get(const scamper_ping_stats_t *stats)
 const timeval *scamper_ping_stats_min_rtt_get(const scamper_ping_stats_t *stats)
 const timeval *scamper_ping_stats_max_rtt_get(const scamper_ping_stats_t *stats)
 const timeval *scamper_ping_stats_avg_rtt_get(const scamper_ping_stats_t *stats)
 const timeval *scamper_ping_stats_stddev_rtt_get(const scamper_ping_stats_t *stats)
