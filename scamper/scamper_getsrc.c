/*
 * scamper_getsrc.c
 *
 * $Id: scamper_getsrc.c,v 1.25 2024/02/19 07:29:36 mjl Exp $
 *
 * Copyright (C) 2005 Matthew Luckie
 * Copyright (C) 2007-2010 The University of Waikato
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

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_debug.h"
#include "scamper_getsrc.h"
#include "utils.h"

#ifndef _WIN32 /* SOCKET vs int on windows */
static int udp4 = -1;
static int udp6 = -1;
#else
static SOCKET udp4 = INVALID_SOCKET;
static SOCKET udp6 = INVALID_SOCKET;
#endif

extern scamper_addrcache_t *addrcache;

/*
 * scamper_getsrc
 *
 * given a destination address, determine the src address used in the IP
 * header to transmit probes to it.
 */
scamper_addr_t *scamper_getsrc(const scamper_addr_t *dst, int ifindex,
			       char *errbuf, size_t errlen)
{
  struct sockaddr_storage sas;
  scamper_addr_t *src;
  socklen_t socklen, sockleno;
  void *addr;
  char buf[64];

#ifndef _WIN32 /* SOCKET vs int on windows */
  int sock;
#else
  SOCKET sock;
#endif

  if(dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      if(socket_isinvalid(udp4))
	{
	  udp4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	  if(socket_isinvalid(udp4))
	    {
	      strerror_wrap(errbuf, errlen, "getsrc could not open udp4 sock");
	      return NULL;
	    }
	}

      sock = udp4;
      addr = &((struct sockaddr_in *)&sas)->sin_addr;
      socklen = sizeof(struct sockaddr_in);

      sockaddr_compose((struct sockaddr *)&sas, AF_INET, dst->addr, 80);
    }
  else if(dst->type == SCAMPER_ADDR_TYPE_IPV6)
    {
      if(socket_isinvalid(udp6))
	{
	  udp6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	  if(socket_isinvalid(udp6))
	    {
	      strerror_wrap(errbuf, errlen, "getsrc could not open udp6 sock");
	      return NULL;
	    }
	}

      sock = udp6;
      addr = &((struct sockaddr_in6 *)&sas)->sin6_addr;
      socklen = sizeof(struct sockaddr_in6);

      sockaddr_compose((struct sockaddr *)&sas, AF_INET6, dst->addr, 80);

      if(scamper_addr_islinklocal(dst) != 0)
	{
	  ((struct sockaddr_in6 *)&sas)->sin6_scope_id = ifindex;
	}
    }
  else
    {
      snprintf(errbuf, errlen, "unhandled address type in getsrc");
      return NULL;
    }

  if(connect(sock, (struct sockaddr *)&sas, socklen) != 0)
    {
      strerror_wrap(errbuf, errlen, "getsrc connect to dst failed for %s",
		    scamper_addr_tostr(dst, buf, sizeof(buf)));
      return NULL;
    }

  sockleno = socklen;
  if(getsockname(sock, (struct sockaddr *)&sas, &sockleno) != 0)
    {
      strerror_wrap(errbuf, errlen, "getsrc could not getsockname for %s",
		 scamper_addr_tostr(dst, buf, sizeof(buf)));
      return NULL;
    }

  src = scamper_addrcache_get(addrcache, dst->type, addr);

  memset(&sas, 0, sizeof(sas));
  connect(sock, (struct sockaddr *)&sas, socklen);
  return src;
}

int scamper_getsrc_init()
{
  return 0;
}

void scamper_getsrc_cleanup()
{
  if(udp4 != -1)
    {
      socket_close(udp4);
      udp4 = socket_invalid();
    }

  if(udp6 != -1)
    {
      socket_close(udp6);
      udp6 = socket_invalid();
    }

  return;
}
