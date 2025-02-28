/*
 * scamper_icmpext_lib.c
 *
 * $Id: scamper_icmpext_lib.c,v 1.7 2025/02/13 18:32:43 mjl Exp $
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
  if(a->ie_dl > b->ie_dl) return  1;
  if(a->ie_data != NULL)
    return memcmp(a->ie_data, b->ie_data, a->ie_dl);
  return 0;
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

#ifdef BUILDING_LIBSCAMPERFILE
scamper_icmpext_t *scamper_icmpext_use(scamper_icmpext_t *ie)
{
  ie->refcnt++;
  return ie;
}
#endif

int scamper_icmpexts_cmp(const scamper_icmpexts_t *a,
			 const scamper_icmpexts_t *b)
{
  uint16_t i, c = a->extc <= b->extc ? a->extc : b->extc;
  int x;

  for(i=0; i<c; i++)
    if((x = scamper_icmpext_cmp(a->exts[i], b->exts[i])) != 0)
      return x;

  if(a->extc < b->extc) return -1;
  if(a->extc > b->extc) return  1;
  return 0;
}

uint16_t scamper_icmpexts_count_get(const scamper_icmpexts_t *exts)
{
  if(exts != NULL)
    return exts->extc;
  return 0;
}

scamper_icmpext_t *
scamper_icmpexts_ext_get(const scamper_icmpexts_t *exts, uint16_t i)
{
  if(exts != NULL && exts->exts != NULL && i < exts->extc)
    return exts->exts[i];
  return NULL;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_icmpexts_t *scamper_icmpexts_use(scamper_icmpexts_t *exts)
{
  if(exts != NULL)
    exts->refcnt++;
  return exts;
}
#endif
