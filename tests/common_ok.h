/*
 * common_ok.h : functions common to unit tests that do comparisons
 *
 * $Id: common_ok.h,v 1.3 2025/04/23 09:54:19 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024-2025 Matthew Luckie
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

int addr_ok(const scamper_addr_t *a, const scamper_addr_t *b);
int buf_ok(const uint8_t *a, const uint8_t *b, size_t len);
int str_ok(const char *a, const char *b);
int ptr_ok(const void *a, const void *b);

#ifdef __SCAMPER_IFNAME_H
int ifname_ok(const scamper_ifname_t *a, const scamper_ifname_t *b);
#endif

#ifdef __SCAMPER_ICMPEXT_H
int icmpexts_ok(const scamper_icmpexts_t *a, const scamper_icmpexts_t *b);
#endif
