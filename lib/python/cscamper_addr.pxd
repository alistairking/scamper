# scamper python interface - cython interface to scamper_addr_t
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

cdef extern from "scamper_addr.h":
 ctypedef struct scamper_addr_t:
  pass

 void scamper_addr_free(scamper_addr_t *sa)
 scamper_addr_t *scamper_addr_use(scamper_addr_t *sa)
 scamper_addr_t *scamper_addr_fromstr(int kind, const char *addr)
 scamper_addr_t *scamper_addr_alloc(int kind, const void *addr)

 const char *scamper_addr_tostr(const scamper_addr_t *sa,
			        char *dst, const size_t size)
 int scamper_addr_cmp(const scamper_addr_t *a, const scamper_addr_t *b)
 int scamper_addr_human_cmp(const scamper_addr_t *a, const scamper_addr_t *b)

 bint scamper_addr_islinklocal(const scamper_addr_t *a)
 bint scamper_addr_isrfc1918(const scamper_addr_t *a)
 bint scamper_addr_isunicast(const scamper_addr_t *a)
 bint scamper_addr_is6to4(const scamper_addr_t *a)
 bint scamper_addr_isreserved(const scamper_addr_t *a)
 bint scamper_addr_isipv4(const scamper_addr_t *a)
 bint scamper_addr_isipv6(const scamper_addr_t *a)
 bint scamper_addr_isethernet(const scamper_addr_t *a)
 bint scamper_addr_isfirewire(const scamper_addr_t *a)

 const void *scamper_addr_addr_get(const scamper_addr_t *addr)
 int scamper_addr_type_get(const scamper_addr_t *addr)
 size_t scamper_addr_len_get(const scamper_addr_t *addr)
