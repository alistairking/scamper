/*
 * scamper_ifname.h
 *
 * $Id: scamper_ifname.h,v 1.1 2024/05/01 07:46:20 mjl Exp $
 *
 * Copyright (C) 2024 The Regents of the University of California
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

#ifndef __SCAMPER_IFNAME_H
#define __SCAMPER_IFNAME_H

typedef struct scamper_ifname scamper_ifname_t;

scamper_ifname_t *scamper_ifname_use(scamper_ifname_t *ifn);
const char *scamper_ifname_name_get(scamper_ifname_t *ifn);
void scamper_ifname_free(scamper_ifname_t *ifn);
int scamper_ifname_cmp(const scamper_ifname_t *a, const scamper_ifname_t *b);

#endif /* __SCAMPER_IFNAME_H */
