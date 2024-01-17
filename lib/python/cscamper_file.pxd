# scamper python interface - cython interface to scamper_file_t
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

from libc.stdint cimport uint8_t, uint16_t

cdef extern from "scamper_file.h":
 ctypedef struct scamper_file_t:
  pass

 ctypedef struct scamper_file_filter_t:
  pass

 ctypedef struct scamper_file_readbuf_t:
  pass

 ctypedef int (*scamper_file_readfunc_t)(void *param,
				         uint8_t **data, size_t len)

 scamper_file_t *scamper_file_open(const char *filename,
                                   char mode, const char *type)
 scamper_file_t *scamper_file_opennull(char mode, const char *type)
 char *scamper_file_type_tostr(scamper_file_t *sf, char *buf, size_t len)
 void scamper_file_close(scamper_file_t *sf)
 char *scamper_file_getfilename(scamper_file_t *sf)
 int scamper_file_read(scamper_file_t *sf, const scamper_file_filter_t *filter,
                       uint16_t *obj_type, void **obj_data)
 void scamper_file_setreadfunc(scamper_file_t *sf, void *param,
			       scamper_file_readfunc_t readfunc)

 scamper_file_filter_t *scamper_file_filter_alloc(const uint16_t *types,
						  uint16_t num)
 void scamper_file_filter_free(scamper_file_filter_t *filter)

 scamper_file_readbuf_t *scamper_file_readbuf_alloc()
 int scamper_file_readbuf_add(scamper_file_readbuf_t *rb,
			      const void *data, size_t len)
 void scamper_file_readbuf_free(scamper_file_readbuf_t *rb)
 int scamper_file_readbuf_read(void *param, uint8_t **data, size_t len)

 int scamper_file_write_obj(scamper_file_t *sf,
			    uint16_t o_type, void *o_data)
