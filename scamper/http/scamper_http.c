/*
 * scamper_http.c
 *
 * $Id: scamper_http.c,v 1.3 2023/11/29 23:48:13 mjl Exp $
 *
 * Copyright (C) 2023 The Regents of the University of California
 *
 * Authors: Matthew Luckie
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

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_http.h"
#include "scamper_http_int.h"
#include "utils.h"

void scamper_http_buf_free(scamper_http_buf_t *htb)
{
#ifdef BUILDING_LIBSCAMPERFILE
  if(--htb->refcnt > 0)
    return;
#endif
  if(htb->data != NULL) free(htb->data);
  free(htb);
  return;
}

scamper_http_buf_t *scamper_http_buf_alloc(void)
{
  scamper_http_buf_t *htb;
  if((htb = malloc_zero(sizeof(scamper_http_buf_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  htb->refcnt = 1;
#endif
  return htb;
}

void scamper_http_free(scamper_http_t *http)
{
  uint32_t i;
  if(http->list != NULL) scamper_list_free(http->list);
  if(http->cycle != NULL) scamper_cycle_free(http->cycle);
  if(http->src != NULL) scamper_addr_free(http->src);
  if(http->dst != NULL) scamper_addr_free(http->dst);
  if(http->host != NULL) free(http->host);
  if(http->file != NULL) free(http->file);
  if(http->bufs != NULL)
    {
      for(i=0; i<http->bufc; i++)
	if(http->bufs[i] != NULL)
	  scamper_http_buf_free(http->bufs[i]);
      free(http->bufs);
    }
  if(http->headers != NULL)
    {
      for(i=0; i<http->headerc; i++)
	if(http->headers[i] != NULL)
	  free(http->headers[i]);
      free(http->headers);
    }
  free(http);
  return;
}

scamper_http_t *scamper_http_alloc(void)
{
  return malloc_zero(sizeof(scamper_http_t));
}
