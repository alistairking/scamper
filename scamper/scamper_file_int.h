/*
 * scamper_file_int.h
 *
 * $Id: scamper_file_int.h,v 1.1 2026/08/31 07:34:35 mjl Exp $
 *
 * Copyright (C) 2026 Matthew Luckie
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

#ifndef __SCAMPER_FILE_INT_H
#define __SCAMPER_FILE_INT_H

void scamper_file_free(scamper_file_t *sf);

void scamper_file_seteof(scamper_file_t *sf);

int scamper_file_getfd(const scamper_file_t *sf);

#endif /* __SCAMPER_FILE_INT_H */
