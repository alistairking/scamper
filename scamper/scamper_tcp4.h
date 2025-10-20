/*
 * scamper_tcp4.h
 *
 * $Id: scamper_tcp4.h,v 1.18 2025/10/15 01:29:55 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2023      Matthew Luckie
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

#ifndef __SCAMPER_TCP4_H
#define __SCAMPER_TCP4_H

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_tcp4_open(const void *addr, int sport, scamper_err_t *err);
#else
SOCKET scamper_tcp4_open(const void *addr, int sport, scamper_err_t *err);
#endif

void scamper_tcp4_cleanup(void);

#ifdef __SCAMPER_PROBE_H
size_t scamper_tcp4_hlen(scamper_probe_t *probe);
int scamper_tcp4_build(scamper_probe_t *probe, uint8_t *buf, size_t *len);
int scamper_tcp4_probe(scamper_probe_t *probe, scamper_err_t *err);
#endif

#endif /* __SCAMPER_TCP4_H */
