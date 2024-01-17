/*
 * scamper_icmp6.h
 *
 * $Id: scamper_icmp6.h,v 1.21 2023/08/20 01:21:17 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2009 The University of Waikato
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

#ifndef __SCAMPER_ICMP6_H
#define __SCAMPER_ICMP6_H

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_icmp6_open(const void *addr);
int scamper_icmp6_open_fd(void);
void scamper_icmp6_read_cb(int fd, void *param);
#else
SOCKET scamper_icmp6_open(const void *addr);
SOCKET scamper_icmp6_open_fd(void);
void scamper_icmp6_read_cb(SOCKET fd, void *param);
#endif

void scamper_icmp6_cleanup(void);

#ifdef __SCAMPER_PROBE_H
int scamper_icmp6_probe(scamper_probe_t *probe);
int scamper_icmp6_build(scamper_probe_t *probe, uint8_t *buf, size_t *len);
uint16_t scamper_icmp6_cksum(scamper_probe_t *probe);
#endif

#ifdef __SCAMPER_ICMP_RESP_H
#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_icmp6_recv(int fd, scamper_icmp_resp_t *resp);
#else
int scamper_icmp6_recv(SOCKET fd, scamper_icmp_resp_t *resp);
#endif
#endif

#endif /* __SCAMPER_ICMP6_H */
