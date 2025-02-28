# scamper python interface: cython interface to libscamperctrl
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

cdef extern from "libscamperctrl.h":
 ctypedef struct scamper_ctrl_t:
  pass

 ctypedef struct scamper_inst_t:
  pass

 ctypedef struct scamper_attp_t:
  pass

 ctypedef struct scamper_task_t:
  pass

 ctypedef struct scamper_mux_t:
  pass

 ctypedef struct scamper_vpset_t:
  pass

 ctypedef struct scamper_vp_t:
  pass

 ctypedef void (*scamper_ctrl_cb_t)(scamper_inst_t *inst, uint8_t type,
				    scamper_task_t *task,
				    const void *data, size_t len)

 scamper_ctrl_t *scamper_ctrl_alloc(scamper_ctrl_cb_t cb)
 int scamper_ctrl_wait(scamper_ctrl_t *ctrl, timeval *to)
 void scamper_ctrl_free(scamper_ctrl_t *ctrl)
 bint scamper_ctrl_isdone(scamper_ctrl_t *ctrl)
 void *scamper_ctrl_param_get(const scamper_ctrl_t *ctrl)
 void scamper_ctrl_param_set(scamper_ctrl_t *ctrl, void *param)
 const char *scamper_ctrl_strerror(const scamper_ctrl_t *ctrl)

 scamper_inst_t *scamper_inst_vp(scamper_ctrl_t *ctrl, const scamper_vp_t *vp)
 scamper_inst_t *scamper_inst_unix(scamper_ctrl_t *ctrl,
				   const scamper_attp_t *attp,
				   const char *path)
 scamper_inst_t *scamper_inst_inet(scamper_ctrl_t *ctrl,
				   const scamper_attp_t *attp,
				   const char *addr, uint16_t port)
 scamper_inst_t *scamper_inst_remote(scamper_ctrl_t *ctrl, const char *path)

 void scamper_inst_free(scamper_inst_t *inst)
 scamper_task_t *scamper_inst_do(scamper_inst_t *inst, const char *cmd, void *p)
 int scamper_inst_done(scamper_inst_t *inst)
 void *scamper_inst_param_get(const scamper_inst_t *inst)
 void scamper_inst_param_set(scamper_inst_t *inst, void *param)
 scamper_ctrl_t *scamper_inst_ctrl_get(const scamper_inst_t *inst)
 const char *scamper_inst_name_get(const scamper_inst_t *inst)
 scamper_vp_t *scamper_inst_vp_get(const scamper_inst_t *inst)

 bint scamper_inst_is_muxvp(const scamper_inst_t *inst)
 bint scamper_inst_is_inet(const scamper_inst_t *inst)
 bint scamper_inst_is_unix(const scamper_inst_t *inst)
 bint scamper_inst_is_remote(const scamper_inst_t *inst)

 int scamper_task_halt(scamper_task_t *task)
 void *scamper_task_param_get(const scamper_task_t *task)
 void scamper_task_param_set(scamper_task_t *task, void *param)
 void scamper_task_free(scamper_task_t *task)
 scamper_task_t *scamper_task_use(scamper_task_t *task)

 scamper_mux_t *scamper_mux_add(scamper_ctrl_t *ctrl, const char *path)

 scamper_vpset_t *scamper_vpset_get(const scamper_mux_t *mux)
 void scamper_vpset_free(scamper_vpset_t *vps)
 size_t scamper_vpset_vp_count(const scamper_vpset_t *vps)
 scamper_vp_t *scamper_vpset_vp_get(const scamper_vpset_t *vps, size_t i)

 void scamper_vp_free(scamper_vp_t *vp)
 scamper_vp_t *scamper_vp_use(scamper_vp_t *vp)
 const char *scamper_vp_name_get(const scamper_vp_t *vp)
 const char *scamper_vp_shortname_get(const scamper_vp_t *vp)
 const char *scamper_vp_ipv4_get(const scamper_vp_t *vp)
 const char *scamper_vp_asn4_get(const scamper_vp_t *vp)
 const char *scamper_vp_cc_get(const scamper_vp_t *vp)
 const char *scamper_vp_st_get(const scamper_vp_t *vp)
 const char *scamper_vp_place_get(const scamper_vp_t *vp)
 const char *scamper_vp_latlong_get(const scamper_vp_t *vp)
 size_t scamper_vp_tagc_get(const scamper_vp_t *vp)
 const char *scamper_vp_tag_get(const scamper_vp_t *vp, size_t i)

 scamper_attp_t *scamper_attp_alloc()
 void scamper_attp_listid_set(scamper_attp_t *attp, uint32_t list_id)
 int scamper_attp_listname_set(scamper_attp_t *attp, char *list_name)
 int scamper_attp_listdescr_set(scamper_attp_t *attp, char *list_descr)
 int scamper_attp_listmonitor_set(scamper_attp_t *attp, char *list_monitor)
 void scamper_attp_cycleid_set(scamper_attp_t *attp, uint32_t cycle_id)
 void scamper_attp_priority_set(scamper_attp_t *attp, uint32_t priority)
 void scamper_attp_free(scamper_attp_t *attp)
