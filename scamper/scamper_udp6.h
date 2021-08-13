/*
 * scamper_udp6.h
 *
 * $Id: scamper_udp6.h,v 1.21 2020/04/27 07:32:21 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2009 The University of Waikato
 * Copyright (C) 2020      Matthew Luckie
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

int scamper_udp6_open(const void *addr, int sport);
void scamper_udp6_close(int fd);

int scamper_udp6_open_err(const void *addr, int sport);
void scamper_udp6_read_err_cb(const int fd, void *param);

#ifdef __SCAMPER_PROBE_H
int scamper_udp6_probe(scamper_probe_t *probe);
int scamper_udp6_build(scamper_probe_t *probe, uint8_t *buf, size_t *len);
uint16_t scamper_udp6_cksum(scamper_probe_t *probe);
#endif

#endif /* __SCAMPER_UDP6_H */
