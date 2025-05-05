/*
 * common_ping : common functions for unit testing ping
 *
 * $Id: common_ping.h,v 1.2 2025/04/20 07:31:58 mjl Exp $
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

scamper_ping_t *ping_makers(size_t i);
size_t ping_makerc(void);
int ping_ok(const scamper_ping_t *in, const scamper_ping_t *out);
