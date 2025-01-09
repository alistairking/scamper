/*
 * scamper_icmp_resp.h
 *
 * $Id: scamper_udp_resp.h,v 1.2 2024/09/06 01:34:54 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2013      The Regents of the University of California
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

#ifndef __SCAMPER_UDP_RESP_H
#define __SCAMPER_UDP_RESP_H

#define SCAMPER_UDP_RESP_FLAG_IFINDEX 0x01

typedef struct scamper_udp_resp
{
  int              af;
  void            *addr;
  uint16_t         sport;
  int              fd;
  struct timeval   rx;
  int              ttl;
  uint8_t         *data;
  uint16_t         datalen;
  unsigned int     ifindex;
  uint8_t          flags;
} scamper_udp_resp_t;

#endif /* __SCAMPER_UDP_RESP_H */
