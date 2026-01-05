# scamper python interface - cython interface to scamper_owamp_t
#
# Author: Matthew Luckie
#
# Copyright (C) 2025 The Regents of the University of California
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

cdef extern from "scamper_owamp.h":
 ctypedef struct scamper_owamp_t:
  pass

 ctypedef struct scamper_owamp_sched_t:
  pass

 ctypedef struct scamper_owamp_tx_t:
  pass

 ctypedef struct scamper_owamp_rx_t:
  pass

 cdef uint8_t SCAMPER_OWAMP_RESULT_NONE
 cdef uint8_t SCAMPER_OWAMP_RESULT_DONE
 cdef uint8_t SCAMPER_OWAMP_RESULT_HALTED
 cdef uint8_t SCAMPER_OWAMP_RESULT_ERROR
 cdef uint8_t SCAMPER_OWAMP_RESULT_NOCONN
 cdef uint8_t SCAMPER_OWAMP_RESULT_NOTACCEPTED
 cdef uint8_t SCAMPER_OWAMP_RESULT_NOMODE
 cdef uint8_t SCAMPER_OWAMP_RESULT_TIMEOUT

 cdef uint8_t SCAMPER_OWAMP_DIR_TX
 cdef uint8_t SCAMPER_OWAMP_DIR_RX

 cdef uint16_t SCAMPER_OWAMP_FLAG_ZERO

 cdef uint8_t SCAMPER_OWAMP_TX_FLAG_NOTSENT
 cdef uint8_t SCAMPER_OWAMP_TX_FLAG_ERREST

 cdef uint8_t SCAMPER_OWAMP_RX_FLAG_DSCP
 cdef uint8_t SCAMPER_OWAMP_RX_FLAG_TTL
 cdef uint8_t SCAMPER_OWAMP_RX_FLAG_ERREST

 cdef uint8_t SCAMPER_OWAMP_SCHED_TYPE_FIXED
 cdef uint8_t SCAMPER_OWAMP_SCHED_TYPE_EXP

 char *scamper_owamp_tojson(const scamper_owamp_t *owamp, size_t *len)

 void scamper_owamp_free(scamper_owamp_t *owamp)
 scamper_list_t *scamper_owamp_list_get(const scamper_owamp_t *owamp)
 scamper_cycle_t *scamper_owamp_cycle_get(const scamper_owamp_t *owamp)
 uint32_t scamper_owamp_userid_get(const scamper_owamp_t *owamp)
 scamper_addr_t *scamper_owamp_dst_get(const scamper_owamp_t *owamp)
 scamper_addr_t *scamper_owamp_src_get(const scamper_owamp_t *owamp)
 uint16_t scamper_owamp_dport_get(const scamper_owamp_t *owamp)
 uint16_t scamper_owamp_flags_get(const scamper_owamp_t *owamp)
 const timeval *scamper_owamp_start_get(const scamper_owamp_t *owamp)
 const timeval *scamper_owamp_startat_get(const scamper_owamp_t *owamp)
 const timeval *scamper_owamp_wait_timeout_get(const scamper_owamp_t *owamp)
 uint32_t scamper_owamp_schedc_get(const scamper_owamp_t *owamp)
 scamper_owamp_sched_t *scamper_owamp_sched_get(const scamper_owamp_t *owamp, uint32_t i)
 uint32_t scamper_owamp_attempts_get(const scamper_owamp_t *owamp)
 uint16_t scamper_owamp_pktsize_get(const scamper_owamp_t *owamp)
 uint8_t scamper_owamp_dir_get(const scamper_owamp_t *owamp)
 char *scamper_owamp_dir_tostr(const scamper_owamp_t *owamp, char *buf, size_t len)
 uint8_t scamper_owamp_dscp_get(const scamper_owamp_t *owamp)
 uint8_t scamper_owamp_ttl_get(const scamper_owamp_t *owamp)
 const timeval *scamper_owamp_hsrtt_get(const scamper_owamp_t *owamp)
 uint8_t scamper_owamp_result_get(const scamper_owamp_t *owamp)
 char *scamper_owamp_result_tostr(const scamper_owamp_t *owamp, char *buf, size_t len)
 char *scamper_owamp_errmsg_get(const scamper_owamp_t *owamp)
 uint16_t scamper_owamp_udp_sport_get(const scamper_owamp_t *owamp)
 uint16_t scamper_owamp_udp_dport_get(const scamper_owamp_t *owamp)
 uint32_t scamper_owamp_txc_get(const scamper_owamp_t *owamp)
 scamper_owamp_tx_t *scamper_owamp_tx_get(const scamper_owamp_t *owamp, uint32_t i)

 scamper_owamp_tx_t *scamper_owamp_tx_use(scamper_owamp_tx_t *tx)
 void scamper_owamp_tx_free(scamper_owamp_tx_t *tx)
 const timeval *scamper_owamp_tx_sched_get(const scamper_owamp_tx_t *tx)
 const timeval *scamper_owamp_tx_stamp_get(const scamper_owamp_tx_t *tx)
 uint32_t scamper_owamp_tx_seq_get(const scamper_owamp_tx_t *tx)
 uint16_t scamper_owamp_tx_errest_get(const scamper_owamp_tx_t *tx)
 uint16_t scamper_owamp_tx_flags_get(const scamper_owamp_tx_t *tx)
 uint8_t scamper_owamp_tx_rxc_get(const scamper_owamp_tx_t *tx)
 scamper_owamp_rx_t *scamper_owamp_tx_rx_get(const scamper_owamp_tx_t *tx, uint8_t i)

 scamper_owamp_rx_t *scamper_owamp_rx_use(scamper_owamp_rx_t *rx)
 void scamper_owamp_rx_free(scamper_owamp_rx_t *rx)
 const timeval *scamper_owamp_rx_stamp_get(const scamper_owamp_rx_t *rx)
 uint16_t scamper_owamp_rx_errest_get(const scamper_owamp_rx_t *rx)
 uint8_t scamper_owamp_rx_flags_get(const scamper_owamp_rx_t *rx)
 uint8_t scamper_owamp_rx_dscp_get(const scamper_owamp_rx_t *rx)
 uint8_t scamper_owamp_rx_ttl_get(const scamper_owamp_rx_t *rx)

 scamper_owamp_sched_t *scamper_owamp_sched_use(scamper_owamp_sched_t *sched)
 void scamper_owamp_sched_free(scamper_owamp_sched_t *sched)
 char *scamper_owamp_sched_type_tostr(const scamper_owamp_sched_t *sched, char *buf, size_t len)
 uint8_t scamper_owamp_sched_type_get(const scamper_owamp_sched_t *sched)
 const timeval *scamper_owamp_sched_tv_get(const scamper_owamp_sched_t *sched)
