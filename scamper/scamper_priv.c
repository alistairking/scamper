/*
 * scamper_priv : operations that require privilege
 *
 * $Id: scamper_priv.c,v 1.3 2025/03/29 19:55:24 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2025 Matthew Luckie
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
#include "scamper_priv.h"
#ifndef DISABLE_SCAMPER_PRIVSEP
#include "scamper_privsep.h"
#endif
#include "scamper_dl.h"
#include "scamper_rtsock.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_ip4.h"
#include "scamper_udp4.h"
#include "utils.h"

#ifndef DISABLE_SCAMPER_PRIVSEP
extern int privsep_do;
#endif

int scamper_priv_open(const char *filename, int flags, mode_t mode)
{
#ifndef DISABLE_SCAMPER_PRIVSEP
  if(privsep_do == 1)
    return scamper_privsep_open_file(filename, flags, mode);
#endif

  return open(filename, flags, mode);
}

int scamper_priv_unlink(const char *filename)
{
#ifndef DISABLE_SCAMPER_PRIVSEP
  if(privsep_do == 1)
    return scamper_privsep_unlink(filename);
#endif

  return unlink(filename);
}

int scamper_priv_unix_bind(const char *filename)
{
#ifndef DISABLE_SCAMPER_PRIVSEP
  if(privsep_do == 1)
    return scamper_privsep_open_unix(filename);
#endif
  return unix_bind_listen(filename, -1);
}

int scamper_priv_dl(int ifindex)
{
  int fd;

#ifdef HAVE_SETEUID
  uid_t uid, euid;
#endif

#ifndef DISABLE_SCAMPER_PRIVSEP
  if(privsep_do == 1)
    return scamper_privsep_open_datalink(ifindex);
#endif

#ifdef HAVE_SETEUID
  if(scamper_seteuid_raise(&uid, &euid) != 0)
    return -1;
#endif

  fd = scamper_dl_open_fd(ifindex);

#ifdef HAVE_SETEUID
  scamper_seteuid_lower(&uid, &euid);
#endif

  return fd;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_priv_icmp4(void)
#else
SOCKET scamper_priv_icmp4(void)
#endif
{
#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

#ifdef HAVE_SETEUID
  uid_t uid, euid;
#endif

#ifndef DISABLE_SCAMPER_PRIVSEP
  if(privsep_do == 1)
    return scamper_privsep_open_icmp(AF_INET);
#endif

#ifdef HAVE_SETEUID
  if(scamper_seteuid_raise(&uid, &euid) != 0)
    return -1;
#endif

  fd = scamper_icmp4_open_fd();

#ifdef HAVE_SETEUID
  scamper_seteuid_lower(&uid, &euid);
#endif

  return fd;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_priv_icmp6(void)
#else
SOCKET scamper_priv_icmp6(void)
#endif
{
#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

#ifdef HAVE_SETEUID
  uid_t uid, euid;
#endif

#ifndef DISABLE_SCAMPER_PRIVSEP
  if(privsep_do == 1)
    return scamper_privsep_open_icmp(AF_INET6);
#endif

#ifdef HAVE_SETEUID
  if(scamper_seteuid_raise(&uid, &euid) != 0)
    return -1;
#endif

  fd = scamper_icmp6_open_fd();

#ifdef HAVE_SETEUID
  scamper_seteuid_lower(&uid, &euid);
#endif

  return fd;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_priv_ip4raw(void)
#else
SOCKET scamper_priv_ip4raw(void)
#endif
{
#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

#ifdef HAVE_SETEUID
  uid_t uid, euid;
#endif

#ifndef DISABLE_SCAMPER_PRIVSEP
  if(privsep_do == 1)
    return scamper_privsep_open_rawip();
#endif

#ifdef HAVE_SETEUID
  if(scamper_seteuid_raise(&uid, &euid) != 0)
    return -1;
#endif

  fd = scamper_ip4_openraw_fd();

#ifdef HAVE_SETEUID
  scamper_seteuid_lower(&uid, &euid);
#endif

  return fd;
}

int scamper_priv_rtsock(void)
{
  int fd;

#ifdef HAVE_SETEUID
  uid_t uid, euid;
#endif

#ifndef DISABLE_SCAMPER_PRIVSEP
  if(privsep_do == 1)
    return scamper_privsep_open_rtsock();
#endif

#ifdef HAVE_SETEUID
  if(scamper_seteuid_raise(&uid, &euid) != 0)
    return -1;
#endif

  fd = scamper_rtsock_open_fd();

#ifdef HAVE_SETEUID
  scamper_seteuid_lower(&uid, &euid);
#endif

  return fd;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_priv_udp4raw(const void *addr)
#else
SOCKET scamper_priv_udp4raw(const void *addr)
#endif
{
#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

#ifdef HAVE_SETEUID
  uid_t uid, euid;
#endif

#ifndef DISABLE_SCAMPER_PRIVSEP
  if(privsep_do == 1)
    return scamper_privsep_open_rawudp(addr);
#endif

#ifdef HAVE_SETEUID
  if(scamper_seteuid_raise(&uid, &euid) != 0)
    return -1;
#endif

  fd = scamper_udp4_openraw_fd(addr);

#ifdef HAVE_SETEUID
  scamper_seteuid_lower(&uid, &euid);
#endif

  return fd;
}
