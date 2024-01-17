# scamper python interface - cython interface to scamper_icmpext_t
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

cdef extern from "scamper_icmpext.h":
 ctypedef struct scamper_icmpext_t:
  pass

 scamper_icmpext_t *scamper_icmpext_use(scamper_icmpext_t *ie)
 void scamper_icmpext_free(scamper_icmpext_t *exts)

 int scamper_icmpext_cmp(const scamper_icmpext_t *a, const scamper_icmpext_t *b)

 const scamper_icmpext_t *scamper_icmpext_next_get(const scamper_icmpext_t *ie)

 bint scamper_icmpext_is_mpls(const scamper_icmpext_t *ie)
 uint16_t scamper_icmpext_mpls_count_get(const scamper_icmpext_t *ie)
 uint32_t scamper_icmpext_mpls_label_get(const scamper_icmpext_t *ie, uint16_t i)
 uint8_t scamper_icmpext_mpls_ttl_get(const scamper_icmpext_t *ie, uint16_t i)
 uint8_t scamper_icmpext_mpls_exp_get(const scamper_icmpext_t *ie, uint16_t i)
 uint8_t scamper_icmpext_mpls_s_get(const scamper_icmpext_t *ie, uint16_t i)
