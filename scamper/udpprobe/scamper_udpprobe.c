/*
 * scamper_udpprobe.c
 *
 * $Id: scamper_udpprobe.c,v 1.2 2024/04/04 06:55:33 mjl Exp $
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
#include "scamper_udpprobe.h"
#include "scamper_udpprobe_int.h"
#include "utils.h"

void scamper_udpprobe_reply_free(scamper_udpprobe_reply_t *ur)
{
#ifdef BUILDING_LIBSCAMPERFILE
  if(--ur->refcnt > 0)
    return;
#endif
  if(ur->data != NULL) free(ur->data);
  free(ur);
  return;
}

scamper_udpprobe_reply_t *scamper_udpprobe_reply_alloc(void)
{
  scamper_udpprobe_reply_t *ur;
  if((ur = malloc_zero(sizeof(scamper_udpprobe_reply_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  ur->refcnt = 1;
#endif
  return ur;
}

void scamper_udpprobe_probe_free(scamper_udpprobe_probe_t *probe)
{
  uint8_t i;
#ifdef BUILDING_LIBSCAMPERFILE
  if(--probe->refcnt > 0)
    return;
#endif
  if(probe->replies != NULL)
    {
      for(i=0; i<probe->replyc; i++)
	if(probe->replies[i] != NULL)
	  scamper_udpprobe_reply_free(probe->replies[i]);
      free(probe->replies);
    }
  free(probe);
  return;
}

scamper_udpprobe_probe_t *scamper_udpprobe_probe_alloc(void)
{
  scamper_udpprobe_probe_t *pr;
  if((pr = malloc_zero(sizeof(scamper_udpprobe_probe_t))) == NULL)
    return NULL;
#ifdef BUILDING_LIBSCAMPERFILE
  pr->refcnt = 1;
#endif
  return pr;
}

void scamper_udpprobe_free(scamper_udpprobe_t *up)
{
  uint8_t i;

  if(up->list != NULL) scamper_list_free(up->list);
  if(up->cycle != NULL) scamper_cycle_free(up->cycle);
  if(up->src != NULL) scamper_addr_free(up->src);
  if(up->dst != NULL) scamper_addr_free(up->dst);
  if(up->data != NULL) free(up->data);
  if(up->probes != NULL)
    {
      for(i=0; i<up->probe_sent; i++)
	if(up->probes[i] != NULL)
	  scamper_udpprobe_probe_free(up->probes[i]);
      free(up->probes);
    }

  free(up);
  return;
}

scamper_udpprobe_t *scamper_udpprobe_alloc(void)
{
  return malloc_zero(sizeof(scamper_udpprobe_t));
}
