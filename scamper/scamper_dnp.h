/*
 * scamper_dnp.h
 *
 * $Id: scamper_dnp.h,v 1.3 2025/08/04 01:54:05 mjl Exp $
 *
 * Copyright (C) 2025 The Regents of the University of California
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

#ifndef __SCAMPER_DNP_H
#define __SCAMPER_DNP_H

int scamper_dnp_canprobe(scamper_addr_t *dst);
int scamper_dnp_reload(const char **files, size_t filec);

int scamper_dnp_init(const char **files, size_t filec);
void scamper_dnp_cleanup(void);

#endif /* __SCAMPER_DNP_H */
