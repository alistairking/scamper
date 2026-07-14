/*
 * sc_rxifd: reply to query with received interface name
 *
 * $Id: sc_rxifd.h,v 1.3 2026/05/24 22:38:56 mjl Exp $
 *
 *         Matthew Luckie
 *         mjl@luckie.org.nz
 *
 * Copyright (C) 2026 The Regents of the University of California
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

#ifndef __SC_RXIFD_H
#define __SC_RXIFD_H

#define SC_QUICSTREAM_FLAG_BIDI  0x01
#define SC_QUICSTREAM_FLAG_DONE  0x02
#define SC_QUICSTREAM_FLAG_RXEOF 0x04

typedef struct sc_quicstream
{
#ifdef HAVE_OPENSSL
  SSL                 *ssl;
#endif
  dlist_node_t        *dn;
  uint8_t              flags;
  uint8_t             *buf;
  size_t               len;
  unsigned int         ifindex;
  struct sockaddr     *them;
  struct timeval       begin;
} sc_quicstream_t;

#endif /* __SC_RXIFD_H */
