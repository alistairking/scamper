/*
 * common_neighbourdisc : common functions for unit testing neighbourdisc
 *
 * $Id: common_neighbourdisc.h,v 1.1 2025/06/29 21:52:12 mjl Exp $
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

scamper_neighbourdisc_t *neighbourdisc_makers(size_t i);
size_t neighbourdisc_makerc(void);
int neighbourdisc_ok(const scamper_neighbourdisc_t *in,
		     const scamper_neighbourdisc_t *out);
