/*
 * scamper_icmpext.h
 *
 * $Id: scamper_icmpext.h,v 1.9 2023/08/08 06:19:31 mjl Exp $
 *
 * Copyright (C) 2008 The University of Waikato
 * Copyright (C) 2012 Matthew Luckie
 * Copyright (C) 2023 Matthew Luckie
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

typedef struct scamper_icmpext scamper_icmpext_t;

uint8_t scamper_icmpext_cn_get(const scamper_icmpext_t *ie);
uint8_t scamper_icmpext_ct_get(const scamper_icmpext_t *ie);
uint16_t scamper_icmpext_dl_get(const scamper_icmpext_t *ie);
const uint8_t *scamper_icmpext_data_get(const scamper_icmpext_t *ie);
const scamper_icmpext_t *scamper_icmpext_next_get(const scamper_icmpext_t *ie);
int scamper_icmpext_cmp(const scamper_icmpext_t *a, const scamper_icmpext_t *b);

int scamper_icmpext_is_mpls(const scamper_icmpext_t *ie);
uint16_t scamper_icmpext_mpls_count_get(const scamper_icmpext_t *ie);
uint32_t scamper_icmpext_mpls_label_get(const scamper_icmpext_t *ie,uint16_t i);
uint8_t scamper_icmpext_mpls_ttl_get(const scamper_icmpext_t *ie, uint16_t i);
uint8_t scamper_icmpext_mpls_exp_get(const scamper_icmpext_t *ie, uint16_t i);
uint8_t scamper_icmpext_mpls_s_get(const scamper_icmpext_t *ie, uint16_t i);

scamper_icmpext_t *scamper_icmpext_use(scamper_icmpext_t *ie);
void scamper_icmpext_free(scamper_icmpext_t *exts);

#endif /* __SCAMPER_ICMPEXT_H */
