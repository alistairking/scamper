/*
 * scamper_addr_int.h
 *
 * $Id: scamper_addr_int.h,v 1.5 2024/01/09 06:16:19 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2013      The Regents of the University of California
 * Copyright (C) 2016-2023 Matthew Luckie
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

#ifndef __SCAMPER_ADDR_INT_H
#define __SCAMPER_ADDR_INT_H

#define SCAMPER_ADDR_TYPE_IS_IPV4(a) ((a)->type == SCAMPER_ADDR_TYPE_IPV4)
#define SCAMPER_ADDR_TYPE_IS_IPV6(a) ((a)->type == SCAMPER_ADDR_TYPE_IPV6)
#define SCAMPER_ADDR_TYPE_IS_ETHERNET(a) \
  ((a)->type == SCAMPER_ADDR_TYPE_ETHERNET)
#define SCAMPER_ADDR_TYPE_IS_FIREWIRE(a) \
  ((a)->type == SCAMPER_ADDR_TYPE_FIREWIRE)

#define SCAMPER_ADDR_TYPE_IS_IP(a) ((a)->type == SCAMPER_ADDR_TYPE_IPV4 || \
				    (a)->type == SCAMPER_ADDR_TYPE_IPV6)

struct scamper_addr
{
  int   type;
  void *addr;
  int   refcnt;
#ifdef BUILDING_SCAMPER
  void *internal;
#endif
};

/*
 * scamper_addrcache:
 *  store identical addresses just once in this structure
 *
 * scamper_addrcache_alloc:
 *  allocate an empty address cache and return a pointer to it
 *
 * scamper_addrcache_free:
 *  free the address cache structure.  all addresses have their reference
 *  count decremented; if their reference count is zero, the underlying
 *  address is freed as well.
 */
typedef struct scamper_addrcache scamper_addrcache_t;
scamper_addrcache_t *scamper_addrcache_alloc(void);
void scamper_addrcache_free(scamper_addrcache_t *ac);

/*
 * scamper_addrcache_get:
 *  return a pointer to a scamper_addr_t which corresponds to the address
 *  out of the cache; allocate the address from scratch if necessary
 */
#ifndef DMALLOC
scamper_addr_t *scamper_addrcache_get(scamper_addrcache_t *ac,
				      const int type, const void *addr);
scamper_addr_t *scamper_addrcache_resolve(scamper_addrcache_t *ac,
					  const int af, const char *addr);
#else
scamper_addr_t *scamper_addrcache_get_dm(scamper_addrcache_t *ac,
					 const int type, const void *addr,
					 const char *file, const int line);
scamper_addr_t *scamper_addrcache_resolve_dm(scamper_addrcache_t *ac,
					     const int af, const char *addr,
					     const char *file, const int line);
#define scamper_addrcache_get(ac, type, addr) \
  scamper_addrcache_get_dm((ac), (type), (addr), __FILE__, __LINE__)
#define scamper_addrcache_resolve(ac, af, addr) \
  scamper_addrcache_resolve_dm((ac), (af), (addr), __FILE__, __LINE__)
#endif

/*
 * scamper_addrcache_get_[ipv4|ipv6|ethernet|firewire]
 *
 * these macros are provided as a convenience as the type constants can
 * become unwieldy to use
 */
#define scamper_addrcache_get_ipv4(addrcache, addr) \
 scamper_addrcache_get(addrcache, SCAMPER_ADDR_TYPE_IPV4, addr)

#define scamper_addrcache_get_ipv6(addrcache, addr) \
 scamper_addrcache_get(addrcache, SCAMPER_ADDR_TYPE_IPV6, addr)

#define scamper_addrcache_get_ethernet(addrcache, addr) \
 scamper_addrcache_get(addrcache, SCAMPER_ADDR_TYPE_ETHERNET, addr)

#define scamper_addrcache_get_firewire(addrcache, addr) \
 scamper_addrcache_get(addrcache, SCAMPER_ADDR_TYPE_FIREWIRE, addr)

#endif /* __SCAMPER_ADDR_INT_H */
