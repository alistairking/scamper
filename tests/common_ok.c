/*
 * common_ok.c : functions common to unit tests that do comparisons
 *
 * $Id: common_ok.c,v 1.2 2025/04/17 02:43:39 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024-2025 Matthew Luckie
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
#include "scamper_ifname.h"
#include "scamper_icmpext.h"
#include "common_ok.h"

int addr_ok(const scamper_addr_t *a, const scamper_addr_t *b)
{
  if(a == NULL && b == NULL)
    return 0;
  if((a == NULL && b != NULL) ||
     (a != NULL && b == NULL))
    return -1;
  return scamper_addr_cmp(a, b);
}

int ifname_ok(const scamper_ifname_t *a, const scamper_ifname_t *b)
{
  if(a == NULL && b == NULL)
    return 0;
  if((a == NULL && b != NULL) ||
     (a != NULL && b == NULL))
    return -1;
  return scamper_ifname_cmp(a, b);
}

int buf_ok(const uint8_t *a, const uint8_t *b, size_t len)
{
  if((a == NULL && b != NULL) ||
     (a != NULL && b == NULL) ||
     (a == NULL && len != 0) ||
     (a != NULL && len == 0) ||
     (a != NULL && memcmp(a, b, len) != 0))
    return -1;
  return 0;
}

int str_ok(const char *a, const char *b)
{
  if((a == NULL && b != NULL) ||
     (a != NULL && b == NULL) ||
     (a != NULL && strcmp(a, b) != 0))
    return -1;
  return 0;
}

int ptr_ok(const void *a, const void *b)
{
  if((a == NULL && b != NULL) ||
     (a != NULL && b == NULL))
    return -1;
  return 0;
}

int icmpexts_ok(const scamper_icmpexts_t *a, const scamper_icmpexts_t *b)
{
  if((a == NULL && b != NULL) ||
     (a != NULL && b == NULL) ||
     (a != NULL && scamper_icmpexts_cmp(a, b) != 0))
    return -1;
  return 0;
}
