/*
 * scamper_tcp6.h
 *
 * $Id: scamper_tcp6.h,v 1.14 2025/10/12 01:53:38 mjl Exp $
 *
 * Copyright (C) 2006 Matthew Luckie
 * Copyright (C) 2006-2009 The University of Waikato
 * Copyright (C) 2023 Matthew Luckie
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

#ifndef __SCAMPER_TCP6_H
#define __SCAMPER_TCP6_H

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_tcp6_open(const void *addr, int sport, scamper_err_t *err);
#else
SOCKET scamper_tcp6_open(const void *addr, int sport, scamper_err_t *err);
#endif

#ifdef __SCAMPER_PROBE_H
size_t scamper_tcp6_hlen(scamper_probe_t *probe);
int scamper_tcp6_build(scamper_probe_t *probe, uint8_t *buf, size_t *len);
#endif

#endif /* __SCAMPER_TCP6_H */
