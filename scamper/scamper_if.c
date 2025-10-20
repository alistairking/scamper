/*
 * scamper_if.c
 *
 * $Id: scamper_if.c,v 1.37 2025/10/20 00:46:53 mjl Exp $
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2014      The Regents of the University of California
 * Copyright (C) 2023      The Regents of the University of California
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

#include "scamper_debug.h"
#include "scamper_fds.h"
#include "scamper_if.h"
#include "scamper_priv.h"
#include "utils.h"

int scamper_if_getifindex(const char *ifname, int *ifindex)
{
#ifndef _WIN32 /* windows does not have if_nametoindex */
  unsigned int i;

  if((i = if_nametoindex(ifname)) == 0)
    return -1;

  *ifindex = i;
  return 0;
#else
  errno = EINVAL;
  return -1;
#endif
}

int scamper_if_getifname(char *str, size_t len, int ifindex,
			 scamper_err_t *error)
{
#ifndef _WIN32 /* windows does not have if_indextoname */
  char ifname[IFNAMSIZ];

  if(if_indextoname(ifindex, ifname) == NULL)
    {
      scamper_err_make(error, errno, "could not get ifname for %d", ifindex);
      return -1;
    }

  if(strlen(ifname) + 1 > len)
    {
      scamper_err_make(error, 0, "getifname input buffer too small");
      return -1;
    }

  strncpy(str, ifname, len);
  return 0;
#else
  scamper_err_make(error, 0, "getifname not implemented");
  return -1;
#endif
}

/*
 * scamper_if_getmtu
 *
 * given an interface index, return the MTU of it.  return zero if
 * we can't get the interface's MTU.
 */
#ifndef _WIN32 /* windows returns MTU with GetIfEntry */
int scamper_if_getmtu(int ifindex, uint16_t *ifmtu, scamper_err_t *error)
{
  scamper_fd_t *fd;
  struct ifreq ifr;
  int mtu;

  assert(ifindex >= 0);

  /* given the index, return the interface name to query */
  if(if_indextoname((unsigned int)ifindex, ifr.ifr_name) == NULL)
    {
      scamper_err_make(error, errno, "getmtu could not if_indextoname");
      return -1;
    }

  if((fd = scamper_fd_ifsock(error)) == NULL)
    return -1;

  if(ioctl(scamper_fd_fd_get(fd), SIOCGIFMTU, &ifr) == -1)
    {
      scamper_err_make(error, errno, "could not SIOCGIFMTU %s", ifr.ifr_name);
      scamper_fd_free(fd);
      return -1;
    }
  scamper_fd_free(fd);

#ifdef __sun
  mtu = ifr.ifr_metric;
#else
  mtu = ifr.ifr_mtu;
#endif

  if(mtu < 0 || mtu > 65535)
    {
      scamper_err_make(error, 0, "invalid MTU %d", mtu);
      return -1;
    }

  *ifmtu = mtu;
  return 0;
}
#endif

#ifdef _WIN32 /* windows returns MTU with GetIfEntry */
int scamper_if_getmtu(int ifindex, uint16_t *ifmtu, scamper_err_t *error)
{
  MIB_IFROW row;
  row.dwIndex = ifindex;
  if(GetIfEntry(&row) != NO_ERROR)
    {
      scamper_err_make(error, 0, "getmtu could not GetIfEntry %d", ifindex);
      return -1;
    }
  *ifmtu = (uint16_t)row.dwMtu;
  return 0;
}
#endif

#if defined(__linux__)
int scamper_if_getmac(int ifindex, uint8_t *mac, scamper_err_t *error)
{
  scamper_fd_t *fd = NULL;
  struct ifreq ifr;

  if(if_indextoname(ifindex, ifr.ifr_name) == NULL)
    {
      scamper_err_make(error, errno, "getmac could not if_indextoname");
      goto err;
    }

  if((fd = scamper_fd_ifsock(error)) == NULL)
    {
      scamper_err_make(error, errno, "getmac could not get ifsock");
      goto err;
    }

  if(ioctl(scamper_fd_fd_get(fd), SIOCGIFHWADDR, &ifr) == -1)
    {
      scamper_err_make(error, errno, "could not SIOCGIFHWADDR %s",
		       ifr.ifr_name);
      goto err;
    }
  memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

  scamper_fd_free(fd);
  return 0;

 err:
  if(fd != NULL) scamper_fd_free(fd);
  return -1;
}
#elif defined(_WIN32) /* windows returns MAC address with GetIfEntry */
int scamper_if_getmac(int ifindex, uint8_t *mac, scamper_err_t *error)
{
  MIB_IFROW row;
  row.dwIndex = ifindex;
  if(GetIfEntry(&row) != NO_ERROR)
    {
      scamper_err_make(error, 0, "could not GetIfEntry %d", ifindex);
      return -1;
    }
  memcpy(mac, row.bPhysAddr, 6);
  return 0;
}
#elif defined(__sun)
int scamper_if_getmac(int ifindex, uint8_t *mac, scamper_err_t *error)
{
  union	DL_primitives *dlp;
  uint8_t reqbuf[DL_PHYS_ADDR_REQ_SIZE];
  uint8_t ackbuf[DL_PHYS_ADDR_ACK_SIZE + 64];
  dl_phys_addr_req_t *req = (dl_phys_addr_req_t *)reqbuf;
  dl_phys_addr_ack_t *ack = (dl_phys_addr_ack_t *)ackbuf;
  struct strbuf ctl;
  int fd = -1, flags;

  if((fd = scamper_priv_dl(ifindex)) == -1)
    {
      scamper_err_make(error, errno, "getmac could not open %d", ifindex);
      goto err;
    }

  memset(reqbuf, 0, sizeof(reqbuf));
  req->dl_primitive = DL_PHYS_ADDR_REQ;
  req->dl_addr_type = DL_CURR_PHYS_ADDR;
  memset(&ctl, 0, sizeof(ctl));
  ctl.len = sizeof(reqbuf);
  ctl.buf = (char *)req;
  if(putmsg(fd, &ctl, NULL, 0) == -1)
    {
      scamper_err_make(error, errno, "getmac could not putmsg");
      goto err;
    }

  flags = 0;
  memset(&ctl, 0, sizeof(ctl));
  ctl.maxlen = sizeof(ackbuf);
  ctl.buf = (char *)ack;
  if(getmsg(fd, &ctl, NULL, &flags) == -1)
    {
      scamper_err_make(error, errno, "getmac could not getmsg");
      goto err;
    }
  close(fd); fd = -1;

  dlp = (void *)ack;
  if(dlp->dl_primitive != DL_PHYS_ADDR_ACK)
    {
      scamper_err_make(error, 0, "getmac primitive not DL_PHYS_ADDR_ACK");
      goto err;
    }
  memcpy(mac, ctl.buf+ack->dl_addr_offset, 6);

  return 0;

 err:
  if(fd != -1) close(fd);
  return -1;
}
#else
int scamper_if_getmac(int ifindex, uint8_t *mac, scamper_err_t *error)
{
  struct sockaddr_dl *sdl;
  int                 mib[6];
  size_t              len;
  uint8_t            *buf;

  mib[0] = CTL_NET;
  mib[1] = AF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_LINK;
  mib[4] = NET_RT_IFLIST;
  mib[5] = ifindex;

  if(sysctl(mib, 6, NULL, &len, NULL, 0) == -1)
    {
      scamper_err_make(error, errno, "getmac could not sysctl buflen");
      return -1;
    }

  if((buf = malloc_zero(len)) == NULL)
    {
      scamper_err_make(error, errno, "getmac could not malloc buf");
      return -1;
    }

  if(sysctl(mib, 6, buf, &len, NULL, 0) < 0)
    {
      scamper_err_make(error, errno, "getmac could not sysctl data");
      free(buf);
      return -1;
    }

  sdl = (struct sockaddr_dl *)(buf+sizeof(struct if_msghdr));
  memcpy(mac, LLADDR(sdl), 6);

  free(buf);
  return 0;
}
#endif

#ifdef HAVE_GETIFADDRS
int scamper_if_getifindex_byaddr(const struct sockaddr *addr, int *ifindex,
				 scamper_err_t *error)
{
  struct ifaddrs *ifa = NULL, *ifp;
  char buf[128];
  int rc;

  if(addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
    {
      scamper_err_make(error, 0, "getifindex_byaddr af %d", addr->sa_family);
      goto err;
    }

  if(getifaddrs(&ifa) != 0)
    {
      scamper_err_make(error, errno, "getifindex_byaddr could not getifaddrs");
      goto err;
    }

  for(ifp = ifa; ifp != NULL; ifp = ifp->ifa_next)
    {
      if(ifp->ifa_addr == NULL || ifp->ifa_addr->sa_family != addr->sa_family)
	continue;

      if(addr->sa_family == AF_INET)
	rc = addr4_cmp(&((struct sockaddr_in *)addr)->sin_addr,
		       &((struct sockaddr_in *)ifp->ifa_addr)->sin_addr);
      else
	rc = addr6_cmp(&((struct sockaddr_in6 *)addr)->sin6_addr,
		       &((struct sockaddr_in6 *)ifp->ifa_addr)->sin6_addr);

      if(rc == 0)
	break;
    }

  if(ifp == NULL)
    {
      scamper_err_make(error, ENOENT, "getifindex_byaddr no interface with %s",
		       sockaddr_tostr(addr, buf, sizeof(buf), 0));
      goto err;
    }

  rc = scamper_if_getifindex(ifp->ifa_name, ifindex);
  freeifaddrs(ifa);
  return rc;

 err:
  if(ifa != NULL) freeifaddrs(ifa);
  return -1;
}
#else
int scamper_if_getifindex_byaddr(const struct sockaddr *addr, int *ifindex)
{
  scamper_err_make(error, 0, "getifindex_byaddr not implemented");
  return -1;
}
#endif
