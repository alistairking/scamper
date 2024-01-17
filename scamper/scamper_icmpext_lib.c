/*
 * scamper_icmpext_lib.c
 *
 * $Id: scamper_icmpext_lib.c,v 1.4 2023/07/29 21:22:22 mjl Exp $
 *
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_icmpext.h"
#include "scamper_icmpext_int.h"

int scamper_icmpext_cmp(const scamper_icmpext_t *a, const scamper_icmpext_t *b)
{
  if(a->ie_cn < b->ie_cn) return -1;
  if(a->ie_cn > b->ie_cn) return  1;
  if(a->ie_ct < b->ie_ct) return -1;
  if(a->ie_ct > b->ie_ct) return  1;
  if(a->ie_dl < b->ie_dl) return -1;
  if(a->ie_dl > b->ie_dl) return -1;
  return memcmp(a->ie_data, b->ie_data, a->ie_dl);
}

uint8_t scamper_icmpext_cn_get(const scamper_icmpext_t *ie)
{
  return ie->ie_cn;
}

uint8_t scamper_icmpext_ct_get(const scamper_icmpext_t *ie)
{
  return ie->ie_ct;
}

uint16_t scamper_icmpext_dl_get(const scamper_icmpext_t *ie)
{
  return ie->ie_dl;
}

const uint8_t *scamper_icmpext_data_get(const scamper_icmpext_t *ie)
{
  return ie->ie_data;
}

const scamper_icmpext_t *scamper_icmpext_next_get(const scamper_icmpext_t *ie)
{
  return ie->ie_next;
}

int scamper_icmpext_is_mpls(const scamper_icmpext_t *ie)
{
  return SCAMPER_ICMPEXT_IS_MPLS(ie);
}

uint16_t scamper_icmpext_mpls_count_get(const scamper_icmpext_t *ie)
{
  return SCAMPER_ICMPEXT_MPLS_COUNT(ie);
}

uint32_t scamper_icmpext_mpls_label_get(const scamper_icmpext_t *ie, uint16_t i)
{
  return SCAMPER_ICMPEXT_MPLS_LABEL(ie, i);
}

uint8_t scamper_icmpext_mpls_ttl_get(const scamper_icmpext_t *ie, uint16_t i)
{
  return SCAMPER_ICMPEXT_MPLS_TTL(ie, i);
}

uint8_t scamper_icmpext_mpls_exp_get(const scamper_icmpext_t *ie, uint16_t i)
{
  return SCAMPER_ICMPEXT_MPLS_EXP(ie, i);
}

uint8_t scamper_icmpext_mpls_s_get(const scamper_icmpext_t *ie, uint16_t i)
{
  return SCAMPER_ICMPEXT_MPLS_S(ie, i);
}

scamper_icmpext_t *scamper_icmpext_use(scamper_icmpext_t *ie)
{
  ie->refcnt++;
  return ie;
}
