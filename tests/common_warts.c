/*
 * common.c: common functions that we might need for linking warts unit tests
 *
 * $Id: common_warts.c,v 1.1 2024/10/13 02:17:43 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024 Matthew Luckie
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

int addr_ok(const scamper_addr_t *in, const scamper_addr_t *out)
{
  if(in == NULL && out == NULL)
    return 0;
  if((in == NULL && out != NULL) ||
     (in != NULL && out == NULL))
    return -1;
  return scamper_addr_cmp(in, out);
}

int ifname_ok(const scamper_ifname_t *in, const scamper_ifname_t *out)
{
  if(in == NULL && out == NULL)
    return 0;
  if((in == NULL && out != NULL) ||
     (in != NULL && out == NULL))
    return -1;
  return scamper_ifname_cmp(in, out);
}
