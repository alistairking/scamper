/*
 * scamper_udp6.h
 *
 * $Id: scamper_udp6.h,v 1.23 2024/02/21 04:58:05 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2009 The University of Waikato
 * Copyright (C) 2020-2023 Matthew Luckie
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

#ifndef __SCAMPER_UDP6_H
#define __SCAMPER_UDP6_H

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_udp6_open(const void *addr, int sport);
int scamper_udp6_open_err(const void *addr, int sport);
void scamper_udp6_read_cb(int fd, void *param);
void scamper_udp6_read_err_cb(int fd, void *param);
#else
SOCKET scamper_udp6_open(const void *addr, int sport);
SOCKET scamper_udp6_open_err(const void *addr, int sport);
void scamper_udp6_read_cb(SOCKET fd, void *param);
void scamper_udp6_read_err_cb(SOCKET fd, void *param);
#endif

#ifdef __SCAMPER_PROBE_H
int scamper_udp6_probe(scamper_probe_t *probe);
int scamper_udp6_build(scamper_probe_t *probe, uint8_t *buf, size_t *len);
uint16_t scamper_udp6_cksum(scamper_probe_t *probe);
#endif

#endif /* __SCAMPER_UDP6_H */
