# scamper python interface: cython interface to libscamperctrl
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

cdef extern from "libscamperctrl.h":
 ctypedef struct scamper_ctrl_t:
  pass

 ctypedef struct scamper_inst_t:
  pass

 ctypedef struct scamper_attp_t:
  pass

 ctypedef struct scamper_task_t:
  pass

 ctypedef void (*scamper_ctrl_cb_t)(scamper_inst_t *inst, uint8_t type,
				    scamper_task_t *task,
				    const void *data, size_t len)

 scamper_ctrl_t *scamper_ctrl_alloc(scamper_ctrl_cb_t cb)
 int scamper_ctrl_wait(scamper_ctrl_t *ctrl, timeval *to)
 void scamper_ctrl_free(scamper_ctrl_t *ctrl)
 bint scamper_ctrl_isdone(scamper_ctrl_t *ctrl)
 void *scamper_ctrl_getparam(const scamper_ctrl_t *ctrl)
 void scamper_ctrl_setparam(scamper_ctrl_t *ctrl, void *param)
 const char *scamper_ctrl_strerror(const scamper_ctrl_t *ctrl)

 scamper_inst_t *scamper_inst_unix(scamper_ctrl_t *ctrl,
				   const scamper_attp_t *attp,
				   const char *path)
 scamper_inst_t *scamper_inst_inet(scamper_ctrl_t *ctrl,
				   const scamper_attp_t *attp,
				   const char *addr, uint16_t port)
 scamper_inst_t *scamper_inst_remote(scamper_ctrl_t *ctrl, const char *path)

 void scamper_inst_free(scamper_inst_t *inst)
 scamper_task_t *scamper_inst_do(scamper_inst_t *inst, const char *cmd, void *p)
 int scamper_inst_halt(scamper_inst_t *inst, scamper_task_t *task)
 int scamper_inst_done(scamper_inst_t *inst)
 void *scamper_inst_getparam(const scamper_inst_t *inst)
 void scamper_inst_setparam(scamper_inst_t *inst, void *param)
 scamper_ctrl_t *scamper_inst_getctrl(const scamper_inst_t *inst)
 const char *scamper_inst_getname(const scamper_inst_t *inst)

 void *scamper_task_getparam(const scamper_task_t *task)
 void scamper_task_setparam(scamper_task_t *task, void *param)
 void scamper_task_free(scamper_task_t *task)
 void scamper_task_use(scamper_task_t *task)

 scamper_attp_t *scamper_attp_alloc()
 void scamper_attp_set_listid(scamper_attp_t *attp, uint32_t list_id)
 int scamper_attp_set_listname(scamper_attp_t *attp, char *list_name)
 int scamper_attp_set_listdescr(scamper_attp_t *attp, char *list_descr)
 int scamper_attp_set_listmonitor(scamper_attp_t *attp, char *list_monitor)
 void scamper_attp_set_cycleid(scamper_attp_t *attp, uint32_t cycle_id)
 void scamper_attp_set_priority(scamper_attp_t *attp, uint32_t priority)
 void scamper_attp_free(scamper_attp_t *attp)
