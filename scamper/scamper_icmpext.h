/*
 * scamper_icmpext.h
 *
 * $Id: scamper_icmpext.h,v 1.13 2025/02/17 22:29:29 mjl Exp $
 *
 * Copyright (C) 2008 The University of Waikato
 * Copyright (C) 2012 Matthew Luckie
 * Copyright (C) 2023-2025 Matthew Luckie
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

#ifndef __SCAMPER_ICMPEXT_H
#define __SCAMPER_ICMPEXT_H

typedef struct scamper_icmpexts scamper_icmpexts_t;
typedef struct scamper_icmpext scamper_icmpext_t;

scamper_icmpexts_t *scamper_icmpexts_dup(const scamper_icmpexts_t *exts);
scamper_icmpexts_t *scamper_icmpexts_use(scamper_icmpexts_t *exts);
void scamper_icmpexts_free(scamper_icmpexts_t *exts);
int scamper_icmpexts_cmp(const scamper_icmpexts_t *a,
			 const scamper_icmpexts_t *b);
uint16_t scamper_icmpexts_count_get(const scamper_icmpexts_t *exts);
scamper_icmpext_t *scamper_icmpexts_ext_get(const scamper_icmpexts_t *exts,
					    uint16_t i);

scamper_icmpext_t *scamper_icmpext_dup(const scamper_icmpext_t *ie);
scamper_icmpext_t *scamper_icmpext_use(scamper_icmpext_t *ie);
void scamper_icmpext_free(scamper_icmpext_t *ie);

uint8_t scamper_icmpext_cn_get(const scamper_icmpext_t *ie);
uint8_t scamper_icmpext_ct_get(const scamper_icmpext_t *ie);
uint16_t scamper_icmpext_dl_get(const scamper_icmpext_t *ie);
const uint8_t *scamper_icmpext_data_get(const scamper_icmpext_t *ie);
int scamper_icmpext_cmp(const scamper_icmpext_t *a, const scamper_icmpext_t *b);

int scamper_icmpext_is_mpls(const scamper_icmpext_t *ie);
uint16_t scamper_icmpext_mpls_count_get(const scamper_icmpext_t *ie);
uint32_t scamper_icmpext_mpls_label_get(const scamper_icmpext_t *ie,uint16_t i);
uint8_t scamper_icmpext_mpls_ttl_get(const scamper_icmpext_t *ie, uint16_t i);
uint8_t scamper_icmpext_mpls_exp_get(const scamper_icmpext_t *ie, uint16_t i);
uint8_t scamper_icmpext_mpls_s_get(const scamper_icmpext_t *ie, uint16_t i);

#endif /* __SCAMPER_ICMPEXT_H */
