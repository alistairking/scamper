/*
 * scamper_addr_int.h
 *
 * $Id: scamper_addr_int.h,v 1.1 2023/05/29 21:22:26 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2013      The Regents of the University of California
 * Copyright (C) 2016-2020 Matthew Luckie
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

#ifndef __SCAMPER_ADDR_INT_H
#define __SCAMPER_ADDR_INT_H

#define SCAMPER_ADDR_TYPE_IS_IPV4(a) ((a)->type == SCAMPER_ADDR_TYPE_IPV4)
#define SCAMPER_ADDR_TYPE_IS_IPV6(a) ((a)->type == SCAMPER_ADDR_TYPE_IPV6)

#define SCAMPER_ADDR_TYPE_IS_IP(a) ((a)->type == SCAMPER_ADDR_TYPE_IPV4 || \
				    (a)->type == SCAMPER_ADDR_TYPE_IPV6)

struct scamper_addr
{
  int   type;
  void *addr;
  int   refcnt;
  void *internal;
};

#endif /* __SCAMPER_ADDR_INT_H */
