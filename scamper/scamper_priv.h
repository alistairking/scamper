/*
 * scamper_priv : operations that require privilege
 *
 * $Id: scamper_priv.h,v 1.1 2025/03/29 18:46:03 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2025 Matthew Luckie
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

#ifndef __SCAMPER_PRIV_H
#define __SCAMPER_PRIV_H

int scamper_priv_open(const char *filename, int flags, mode_t mode);
int scamper_priv_unlink(const char *filename);

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_priv_icmp4(void);
int scamper_priv_icmp6(void);
int scamper_priv_ip4raw(void);
int scamper_priv_udp4raw(const void *addr);
int scamper_priv_rtsock(void);
int scamper_priv_dl(int ifindex);
int scamper_priv_unix_bind(const char *filename);
#else
SOCKET scamper_priv_icmp4(void);
SOCKET scamper_priv_icmp6(void);
SOCKET scamper_priv_ip4raw(void);
SOCKET scamper_priv_udp4raw(const void *addr);
#endif

#endif /* __SCAMPER_PRIV_H */
