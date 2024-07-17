# scamper python interface - cython interface to scamper_udpprobe_t
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

cdef extern from "scamper_udpprobe.h":
 ctypedef struct scamper_udpprobe_t:
  pass
 ctypedef struct scamper_udpprobe_probe_t:
  pass
 ctypedef struct scamper_udpprobe_reply_t:
  pass

 void scamper_udpprobe_free(scamper_udpprobe_t *up)

 scamper_list_t *scamper_udpprobe_list_get(const scamper_udpprobe_t *up)
 scamper_cycle_t *scamper_udpprobe_cycle_get(const scamper_udpprobe_t *up)
 uint32_t scamper_udpprobe_userid_get(const scamper_udpprobe_t *up)
 scamper_addr_t *scamper_udpprobe_src_get(const scamper_udpprobe_t *up)
 scamper_addr_t *scamper_udpprobe_dst_get(const scamper_udpprobe_t *up)
 uint16_t scamper_udpprobe_sport_get(const scamper_udpprobe_t *up)
 uint16_t scamper_udpprobe_dport_get(const scamper_udpprobe_t *up)
 const timeval *scamper_udpprobe_start_get(const scamper_udpprobe_t *up)
 const timeval *scamper_udpprobe_wait_timeout_get(const scamper_udpprobe_t *up)
 const timeval *scamper_udpprobe_wait_probe_get(const scamper_udpprobe_t *up)
 int scamper_udpprobe_flag_is_exitfirst(const scamper_udpprobe_t *up)
 const uint8_t *scamper_udpprobe_data_get(const scamper_udpprobe_t *up)
 uint16_t scamper_udpprobe_len_get(const scamper_udpprobe_t *up)
 uint8_t scamper_udpprobe_probe_count_get(const scamper_udpprobe_t *up);
 uint8_t scamper_udpprobe_probe_sent_get(const scamper_udpprobe_t *up);
 uint8_t scamper_udpprobe_stop_count_get(const scamper_udpprobe_t *up);
 scamper_udpprobe_probe_t *scamper_udpprobe_probe_get(const scamper_udpprobe_t *up, uint8_t i);

 void scamper_udpprobe_probe_free(scamper_udpprobe_probe_t *probe);
 scamper_udpprobe_probe_t *scamper_udpprobe_probe_use(scamper_udpprobe_probe_t *probe);
 const timeval *scamper_udpprobe_probe_tx_get(const scamper_udpprobe_probe_t *probe);
 uint16_t scamper_udpprobe_probe_sport_get(const scamper_udpprobe_probe_t *probe);
 scamper_udpprobe_reply_t *scamper_udpprobe_probe_reply_get(const scamper_udpprobe_probe_t *probe, uint8_t i);
 uint8_t scamper_udpprobe_probe_replyc_get(const scamper_udpprobe_probe_t *probe);

 void scamper_udpprobe_reply_free(scamper_udpprobe_reply_t *ur)
 scamper_udpprobe_reply_t *scamper_udpprobe_reply_use(scamper_udpprobe_reply_t *ur)
 const uint8_t *scamper_udpprobe_reply_data_get(const scamper_udpprobe_reply_t *ur)
 uint16_t scamper_udpprobe_reply_len_get(const scamper_udpprobe_reply_t *ur)
 const timeval *scamper_udpprobe_reply_rx_get(const scamper_udpprobe_reply_t *ur)
