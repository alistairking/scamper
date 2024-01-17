# scamper python interface - cython interface to scamper_list_t
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

from libc.stdint cimport uint32_t
from posix.time cimport time_t

cdef extern from "scamper_list.h":
 ctypedef struct scamper_list_t:
  pass
 ctypedef struct scamper_cycle_t:
  pass

 scamper_list_t *scamper_list_use(scamper_list_t *list)
 void scamper_list_free(scamper_list_t *list)
 uint32_t scamper_list_id_get(const scamper_list_t *list)
 const char *scamper_list_name_get(const scamper_list_t *list)
 const char *scamper_list_descr_get(const scamper_list_t *list)
 const char *scamper_list_monitor_get(const scamper_list_t *list)
 int scamper_list_cmp(const scamper_list_t *a, const scamper_list_t *b)

 scamper_cycle_t *scamper_cycle_use(scamper_cycle_t *cycle)
 void scamper_cycle_free(scamper_cycle_t *cycle)
 scamper_list_t *scamper_cycle_list_get(const scamper_cycle_t *cycle)
 uint32_t scamper_cycle_id_get(const scamper_cycle_t *cycle)
 time_t scamper_cycle_start_time_get(const scamper_cycle_t *cycle)
 time_t scamper_cycle_stop_time_get(const scamper_cycle_t *cycle)
 const char *scamper_cycle_hostname_get(const scamper_cycle_t *cycle)
 int scamper_cycle_cmp(scamper_cycle_t *a, scamper_cycle_t *b)
