/*
 * scamper_icmpext.c
 *
 * $Id: scamper_icmpext.c,v 1.19 2025/02/13 18:32:43 mjl Exp $
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2014      The Regents of the University of California
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_icmpext.h"
#include "scamper_icmpext_int.h"
#include "utils.h"

scamper_icmpext_t *scamper_icmpext_dup(const scamper_icmpext_t *in)
{
  scamper_icmpext_t *out = NULL;

  if((out = memdup(in, sizeof(scamper_icmpext_t))) == NULL)
    goto err;
  out->ie_data = NULL;

#ifdef BUILDING_LIBSCAMPERFILE
  out->refcnt = 1;
#endif

  if(in->ie_data != NULL &&
     (out->ie_data = memdup(in->ie_data, in->ie_dl)) == NULL)
    goto err;

  return out;

 err:
  if(out != NULL) scamper_icmpext_free(out);
  return NULL;
}

scamper_icmpext_t *scamper_icmpext_alloc(uint8_t cn, uint8_t ct, uint16_t dl,
					 const void *data)
{
  scamper_icmpext_t *ie;

  if((ie = malloc_zero(sizeof(scamper_icmpext_t))) == NULL)
    return NULL;

  if(dl != 0 && (ie->ie_data = memdup(data, dl)) == NULL)
    {
      free(ie);
      return NULL;
    }

  ie->ie_cn = cn;
  ie->ie_ct = ct;
  ie->ie_dl = dl;

#ifdef BUILDING_LIBSCAMPERFILE
  ie->refcnt = 1;
#endif

  return ie;
}

void scamper_icmpext_free(scamper_icmpext_t *ie)
{
#ifdef BUILDING_LIBSCAMPERFILE
  if(--ie->refcnt > 0)
    return;
#endif

  if(ie->ie_data != NULL)
    free(ie->ie_data);
  free(ie);

  return;
}

scamper_icmpexts_t *scamper_icmpexts_alloc(uint16_t c)
{
  scamper_icmpexts_t *exts = NULL;
  size_t size = c * sizeof(scamper_icmpext_t *);

  if((exts = malloc_zero(sizeof(scamper_icmpexts_t))) == NULL ||
     (size > 0 && (exts->exts = malloc_zero(size)) == NULL))
    {
      if(exts != NULL) free(exts);
      return NULL;
    }

#ifdef BUILDING_LIBSCAMPERFILE
  exts->refcnt = 1;
#endif

  return exts;
}

scamper_icmpexts_t *scamper_icmpexts_dup(const scamper_icmpexts_t *in)
{
  scamper_icmpexts_t *out = NULL;
  uint16_t i;

  if((out = scamper_icmpexts_alloc(in->extc)) == NULL)
    return NULL;
  if(in->exts != NULL)
    {
      assert(out->exts != NULL);
      for(i=0; i < in->extc; i++)
	out->exts[i] = scamper_icmpext_dup(in->exts[i]);
    }
  out->extc = in->extc;

  return out;
}

void scamper_icmpexts_free(scamper_icmpexts_t *exts)
{
  uint16_t i;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--exts->refcnt > 0)
    return;
#endif

  if(exts->exts != NULL)
    {
      for(i=0; i<exts->extc; i++)
	if(exts->exts[i] != NULL)
	  scamper_icmpext_free(exts->exts[i]);
      free(exts->exts);
    }
  free(exts);

  return;
}
