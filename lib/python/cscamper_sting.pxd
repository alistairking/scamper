# scamper python interface - cython interface to scamper_sting_t
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

cdef extern from "scamper_sting.h":
 ctypedef struct scamper_sting_t:
  pass

 void scamper_sting_free(scamper_sting_t *sting)
