/*
 * scamper_icmpext_int.c
 *
 * $Id: scamper_icmpext_int.c,v 1.1 2023/05/29 08:05:37 mjl Exp $
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

int scamper_icmpext_parse(scamper_icmpext_t **exts, void *data, uint16_t len)
{
  scamper_icmpext_t *ie, *next;
  uint8_t  *u8 = data;
  uint16_t  dl;
  uint8_t   cn, ct;
  int       off;

  *exts = NULL;
  next = *exts;

  /* start at offset 4 so the extension header is skipped */
  for(off = 4; off + 4 < len; off += dl)
    {
      /* extract the length field */
      memcpy(&dl, u8+off, 2);
      dl = ntohs(dl);

      /* make sure there is enough in the packet left */
      if(off + dl < len)
	break;

      cn = u8[off+2];
      ct = u8[off+3];

      if(dl < 8)
	{
	  continue;
	}

      if((ie = scamper_icmpext_alloc(cn, ct, dl-4, u8+off+4)) == NULL)
	{
	  return -1;
	}

      if(next == NULL)
	{
	  *exts = ie;
	}
      else
	{
	  next->ie_next = ie;
	}
      next = ie;
    }

  return 0;
}
