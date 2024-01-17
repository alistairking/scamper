/*
 * scamper_icmpext.c
 *
 * $Id: scamper_icmpext.c,v 1.15 2023/07/25 20:22:09 mjl Exp $
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2014      The Regents of the University of California
 * Copyright (C) 2023      Matthew Luckie
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
  scamper_icmpext_t *next;

#ifdef BUILDING_LIBSCAMPERFILE
  if(--ie->refcnt > 0)
    return;
#endif

  while(ie != NULL)
    {
      next = ie->ie_next;
      if(ie->ie_data != NULL)
	free(ie->ie_data);
      free(ie);
      ie = next;
    }

  return;
}
