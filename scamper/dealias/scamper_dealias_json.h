/*
 * scamper_dealias_json.h
 *
 * $Id: scamper_dealias_json.h,v 1.2 2022/02/13 08:48:15 mjl Exp $
 *
 * Copyright (c) 2013 The Regents of the University of California
 * Copyright (c) 2022 Matthew Luckie
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

#ifndef __SCAMPER_DEALIAS_JSON_H
#define __SCAMPER_DEALIAS_JSON_H

int scamper_file_json_dealias_write(const scamper_file_t *sf,
				    const struct scamper_dealias *dealias,
				    void *p);

#endif
