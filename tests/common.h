/*
 * common.h : functions common to unit tests
 *
 * $Id: common.h,v 1.5 2025/05/02 04:39:00 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2023 Matthew Luckie
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

int dump_string(const char *cmd, const char *filename);
int dump_hex(const char *str, const char *filename);
int hex2buf(const char *str, uint8_t **buf_out, size_t *len_out);

#ifdef __SCAMPER_ADDR_H
int check_addr(const scamper_addr_t *sa, const char *str);
#endif
