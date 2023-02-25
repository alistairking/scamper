/*
 * scamper_file_arts.h
 *
 * $Id: scamper_file_arts.h,v 1.10 2022/07/02 21:21:56 mjl Exp $
 *
 * code to read the legacy arts data file format into scamper_trace structures.
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2008 The University of Waikato
 * Copyright (C) 2022      Matthew Luckie
 * Author: Matthew Luckie
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _SCAMPER_FILE_ARTS_H
#define _SCAMPER_FILE_ARTS_H

int scamper_file_arts_read(scamper_file_t *sf,
			   const scamper_file_filter_t *filter,
			   uint16_t *type, void **data);

int scamper_file_arts_init_read(scamper_file_t *file);

void scamper_file_arts_free_state(scamper_file_t *file);

#endif /* _SCAMPER_FILE_ARTS_H */
