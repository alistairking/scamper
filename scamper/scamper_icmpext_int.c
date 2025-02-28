/*
 * scamper_icmpext_int.c
 *
 * $Id: scamper_icmpext_int.c,v 1.2 2025/02/11 14:31:43 mjl Exp $
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

#include "mjl_list.h"
#include "utils.h"

int scamper_icmpext_parse(scamper_icmpexts_t **out, uint8_t *data, size_t len)
{
  scamper_icmpexts_t *exts = NULL;
  scamper_icmpext_t *ie = NULL;
  slist_t *list = NULL;
  uint16_t dl;
  uint8_t cn, ct;
  size_t off;
  int extc, rc = -1;

  *out = NULL;

  if((list = slist_alloc()) == NULL)
    goto cleanup;

  /* start at offset 4 so the extension header is skipped */
  for(off = 4; off + 4 < len; off += dl)
    {
      /* extract the length field */
      dl = bytes_ntohs(data+off);

      /* make sure there is enough in the packet left */
      if(off + dl < len)
	break;

      cn = data[off+2];
      ct = data[off+3];

      if(dl < 8)
	continue;

      if((ie = scamper_icmpext_alloc(cn, ct, dl-4, data+off+4)) == NULL ||
	 slist_tail_push(list, ie) == NULL)
	goto cleanup;
      ie = NULL;
    }

  if((extc = slist_count(list)) > 0)
    {
      if((exts = scamper_icmpexts_alloc((uint16_t)extc)) == NULL)
	goto cleanup;
      while((ie = slist_head_pop(list)) != NULL)
	exts->exts[exts->extc++] = ie;
    }

  slist_free(list);

  *out = exts;
  return 0;

 cleanup:
  if(list != NULL) slist_free_cb(list, (slist_free_t)scamper_icmpext_free);
  if(ie != NULL) scamper_icmpext_free(ie);
  return rc;
}
