/*
 * scamper_udp4.c
 *
 * $Id: scamper_udp4.c,v 1.85 2024/02/21 05:06:43 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
 * Copyright (C) 2022-2023 Matthew Luckie
 * Copyright (C) 2023-2024 The Regents of the University of California
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
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_ip4.h"
#include "scamper_udp4.h"
#include "scamper_privsep.h"
#include "scamper_task.h"
#include "scamper_udp_resp.h"
#include "scamper_debug.h"
#include "utils.h"

/*
 * these variables are used to store a packet buffer that is allocated
 * in the scamper_udp4_probe function large enough for the largest probe
 * the routine sends
 */
static uint8_t *pktbuf = NULL;
static size_t   pktbuf_len = 0;

uint16_t scamper_udp4_cksum(scamper_probe_t *probe)
{
  uint16_t tmp, *w;
  int i, sum = 0;

  /* compute the checksum over the psuedo header */
  w = (uint16_t *)probe->pr_ip_src->addr;
  sum += *w++; sum += *w++;
  w = (uint16_t *)probe->pr_ip_dst->addr;
  sum += *w++; sum += *w++;
  sum += htons(IPPROTO_UDP);
  sum += htons(probe->pr_len + 8);

  /* main UDP header */
  sum += htons(probe->pr_udp_sport);
  sum += htons(probe->pr_udp_dport);
  sum += htons(probe->pr_len + 8);

  /* compute the checksum over the payload of the UDP message */
  w = (uint16_t *)probe->pr_data;
  for(i = probe->pr_len; i > 1; i -= 2)
    {
      sum += *w++;
    }
  if(i != 0)
    {
      sum += ((uint8_t *)w)[0];
    }

  /* fold the checksum */
  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  if((tmp = ~sum) == 0)
    {
      tmp = 0xffff;
    }

  return tmp;
}

static void udp4_build(scamper_probe_t *probe, uint8_t *buf)
{
  struct udphdr *udp = (struct udphdr *)buf;

  udp->uh_sport = htons(probe->pr_udp_sport);
  udp->uh_dport = htons(probe->pr_udp_dport);
  udp->uh_ulen  = htons(8 + probe->pr_len);
  udp->uh_sum = scamper_udp4_cksum(probe);

  /* if there is data to include in the payload, copy it in now */
  if(probe->pr_len > 0)
    {
      memcpy(buf + 8, probe->pr_data, probe->pr_len);
    }

  return;
}

int scamper_udp4_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  size_t ip4hlen, req;
  int rc = 0;

  ip4hlen = *len;
  scamper_ip4_build(probe, buf, &ip4hlen);
  req = ip4hlen + 8 + probe->pr_len;

  if(req <= *len)
    udp4_build(probe, buf + ip4hlen);
  else
    rc = -1;

  *len = req;
  return rc;
}

int scamper_udp4_probe(scamper_probe_t *probe)
{
  struct sockaddr_in  sin4;
  int                 i;
  char                addr[128];
  size_t              ip4hlen, len, tmp;
  uint8_t            *buf;

#if !defined(IP_HDR_HTONS)
  struct ip          *ip;
#endif

  assert(probe != NULL);
  assert(probe->pr_ip_proto == IPPROTO_UDP);
  assert(probe->pr_ip_dst != NULL);
  assert(probe->pr_ip_src != NULL);
  assert(probe->pr_len > 0 || probe->pr_data == NULL);

  scamper_ip4_hlen(probe, &ip4hlen);

  /* compute length, for sake of readability */
  len = ip4hlen + sizeof(struct udphdr) + probe->pr_len;

  if(pktbuf_len < len)
    {
      if((buf = realloc(pktbuf, len)) == NULL)
	{
	  printerror(__func__, "could not realloc");
	  return -1;
	}
      pktbuf     = buf;
      pktbuf_len = len;
    }

  tmp = len;
  scamper_ip4_build(probe, pktbuf, &tmp);

#if !defined(IP_HDR_HTONS)
  ip = (struct ip *)pktbuf;
  ip->ip_len = ntohs(ip->ip_len);
  ip->ip_off = ntohs(ip->ip_off);
#endif

  udp4_build(probe, pktbuf + ip4hlen);

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET,
		   probe->pr_ip_dst->addr, probe->pr_udp_dport);

  /* get the transmit time immediately before we send the packet */
  gettimeofday_wrap(&probe->pr_tx);

  i = sendto(probe->pr_fd, pktbuf, len, 0, (struct sockaddr *)&sin4,
	     sizeof(struct sockaddr_in));

  if(i < 0)
    {
      /* error condition, could not send the packet at all */
      probe->pr_errno = errno;
      printerror(__func__, "could not send to %s (%d ttl, %d dport, %d len)",
		 scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)),
		 probe->pr_ip_ttl, probe->pr_udp_dport, (int)len);
      return -1;
    }
  else if((size_t)i != len)
    {
      /* error condition, sent a portion of the probe */
      printerror_msg(__func__, "sent %d bytes of %d byte packet to %s",
		     i, (int)len,
		     scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)));
      return -1;
    }

  return 0;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
void scamper_udp4_read_cb(int fd, void *param)
#else
void scamper_udp4_read_cb(SOCKET fd, void *param)
#endif
{
  scamper_udp_resp_t ur;
  struct sockaddr_in from;
  uint8_t buf[8192], ctrlbuf[256];
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct iovec iov;
  ssize_t rrc;

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (caddr_t)buf;
  iov.iov_len  = sizeof(buf);

  msg.msg_name       = (caddr_t)&from;
  msg.msg_namelen    = sizeof(from);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (caddr_t)ctrlbuf;
  msg.msg_controllen = sizeof(ctrlbuf);

  if((rrc = recvmsg(fd, &msg, 0)) <= 0)
    return;

  memset(&ur, 0, sizeof(ur));
  ur.ttl = -1;

  if(msg.msg_controllen >= sizeof(struct cmsghdr))
    {
      cmsg = (struct cmsghdr *)CMSG_FIRSTHDR(&msg);
      while(cmsg != NULL)
	{
	  if(cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMP)
	    timeval_cpy(&ur.rx, (struct timeval *)CMSG_DATA(cmsg));
	  else if(cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL)
	    ur.ttl = *((int *)CMSG_DATA(cmsg));
	  cmsg = (struct cmsghdr *)CMSG_NXTHDR(&msg, cmsg);
	}
    }

  ur.af = AF_INET;
  ur.addr = &from.sin_addr;
  ur.sport = ntohs(from.sin_port);
  ur.data = buf;
  ur.datalen = rrc;
  ur.fd = fd;

  scamper_task_handleudp(&ur);

  return;
}

void scamper_udp4_cleanup()
{
  if(pktbuf != NULL)
    {
      free(pktbuf);
      pktbuf = NULL;
    }

  return;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_udp4_opendgram(const void *addr, int sport)
#else
SOCKET scamper_udp4_opendgram(const void *addr, int sport)
#endif
{
  struct sockaddr_in sin4;
  char tmp[32];
  int opt;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(socket_isinvalid(fd))
    {
      printerror(__func__, "could not open socket");
      goto err;
    }

  opt = 1;
  if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt)) != 0)
    {
      printerror(__func__, "could not set SO_REUSEADDR");
      goto err;
    }

#if defined(SO_TIMESTAMP)
  opt = 1;
  if(setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, (void *)&opt, sizeof(opt)) != 0)
    printerror(__func__, "could not set SO_TIMESTAMP");
#endif

  opt = 1;
  if(setsockopt(fd, IPPROTO_IP, IP_RECVTTL, (void *)&opt, sizeof(opt)) == -1)
    printerror(__func__, "could not set IP_RECVTTL");

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET, addr, sport);
  if(bind(fd, (struct sockaddr *)&sin4, sizeof(sin4)) == -1)
    {
      printerror(__func__, "could not bind %s",
		 sockaddr_tostr((struct sockaddr *)&sin4, tmp, sizeof(tmp)));
      goto err;
    }

  return fd;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  return socket_invalid();
}

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_udp4_openraw_fd(const void *addr)
#else
SOCKET scamper_udp4_openraw_fd(const void *addr)
#endif
{
  struct sockaddr_in sin4;
  int hdr;
  char tmp[32];

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

  fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  if(socket_isinvalid(fd))
    {
      printerror(__func__, "could not open socket");
      goto err;
    }
  hdr = 1;
  if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, (void *)&hdr, sizeof(hdr)) == -1)
    {
      printerror(__func__, "could not IP_HDRINCL");
      goto err;
    }
  sockaddr_compose((struct sockaddr *)&sin4, AF_INET, addr, 0);
  if(bind(fd, (struct sockaddr *)&sin4, sizeof(sin4)) == -1)
    {
      printerror(__func__, "could not bind %s",
		 sockaddr_tostr((struct sockaddr *)&sin4, tmp, sizeof(tmp)));
      goto err;
    }

  return fd;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  return socket_invalid();
}

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_udp4_openraw(const void *addr)
#else
SOCKET scamper_udp4_openraw(const void *addr)
#endif
{
  int opt;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd = -1;
#else
  SOCKET fd = INVALID_SOCKET;
#endif

#ifdef DISABLE_PRIVSEP
#ifdef HAVE_SETEUID
  uid_t uid = scamper_getuid();
  uid_t euid = scamper_geteuid();
  if(uid != euid && seteuid(euid) != 0)
    {
      printerror(__func__, "could not claim euid");
      goto err;
    }
#endif
  fd = scamper_udp4_openraw_fd(addr);
#ifdef HAVE_SETEUID
  if(uid != euid && seteuid(uid) != 0)
    {
      printerror(__func__, "could not return to uid");
      exit(-errno);
    }
#endif
#else
  fd = scamper_privsep_open_rawudp(addr);
#endif
  if(socket_isinvalid(fd))
    goto err;

  opt = 65535 + 128;
  if(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set SO_SNDBUF");
      goto err;
    }
  return fd;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  return socket_invalid();
}
