/*
 * scamper_udp4.c
 *
 * $Id: scamper_udp4.c,v 1.112 2026/07/03 21:57:47 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
 * Copyright (C) 2022-2024 Matthew Luckie
 * Copyright (C) 2023-2024 The Regents of the University of California
 * Copyright (C) 2026      Matthew Luckie
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
#include "scamper_debug.h"
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_dl.h"
#include "scamper_dlhdr.h"
#include "scamper_task.h"
#include "scamper_probe.h"
#include "scamper_ip4.h"
#include "scamper_udp4.h"
#include "scamper_priv.h"
#include "scamper_udp_resp.h"
#include "utils.h"

#ifdef BUILDING_SCAMPER
/*
 * these variables are used to store a packet buffer that is allocated
 * in the scamper_udp4_probe function large enough for the largest probe
 * the routine sends
 */
static uint8_t *pktbuf = NULL;
static size_t   pktbuf_len = 0;
#endif

uint16_t scamper_udp4_cksum(scamper_probe_t *probe)
{
  uint16_t tmp, *w;
  uint32_t sum = 0;

  /* compute the checksum over the pseudo header */
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
  sum += in_cksum_sum((uint16_t *)probe->pr_data, probe->pr_len);

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

#ifdef BUILDING_SCAMPER
int scamper_udp4_probe(scamper_probe_t *pr, scamper_err_t *error)
{
  struct sockaddr_in  sin4;
  int                 i;
  char                addr[128];
  size_t              ip4hlen, len, tmp;
  uint8_t            *buf;

#if !defined(IP_HDR_HTONS)
  struct ip          *ip;
#endif

  assert(pr != NULL);
  assert(pr->pr_ip_proto == IPPROTO_UDP);
  assert(pr->pr_ip_dst != NULL);
  assert(pr->pr_ip_src != NULL);
  assert(pr->pr_len > 0 || pr->pr_data == NULL);

  if((ip4hlen = scamper_ip4_hlen(pr, error)) == 0)
    return -1;

  /* compute length, for sake of readability */
  len = ip4hlen + sizeof(struct udphdr) + pr->pr_len;

  if(pktbuf_len < len)
    {
      if((buf = realloc(pktbuf, len)) == NULL)
	{
	  scamper_err_make(error, errno, "udp4_probe could not realloc");
	  return -1;
	}
      pktbuf     = buf;
      pktbuf_len = len;
    }

  tmp = len;
  scamper_ip4_build(pr, pktbuf, &tmp);

#if !defined(IP_HDR_HTONS)
  ip = (struct ip *)pktbuf;
  ip->ip_len = ntohs(ip->ip_len);
  ip->ip_off = ntohs(ip->ip_off);
#endif

  udp4_build(pr, pktbuf + ip4hlen);

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET,
		   pr->pr_ip_dst->addr, pr->pr_udp_dport);

  /* get the transmit time immediately before we send the packet */
  gettimeofday_wrap(&pr->pr_tx);

  i = sendto(pr->pr_fd, pktbuf, len, 0, (struct sockaddr *)&sin4,
	     sizeof(struct sockaddr_in));

  if(i < 0)
    {
      /* error condition, could not send the packet at all */
      scamper_err_make(error, errno,
		       "udp4_probe could not send to %s (%d ttl, %d dport, %d len)",
		       scamper_addr_tostr(pr->pr_ip_dst, addr, sizeof(addr)),
		       pr->pr_ip_ttl, pr->pr_udp_dport, (int)len);
      return -1;
    }
  else if((size_t)i != len)
    {
      /* error condition, sent a portion of the probe */
      scamper_err_make(error, 0,
		       "udp4_probe sent %d bytes of %d byte packet to %s",
		       i, (int)len,
		       scamper_addr_tostr(pr->pr_ip_dst, addr, sizeof(addr)));
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
  uint8_t buf[8192];
  ssize_t rrc;

#ifndef _WIN32 /* windows does not have msghdr or iovec */
  uint8_t ctrlbuf[256];
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct iovec iov;

#if defined(IP_PKTINFO)
  struct in_pktinfo *pi;
#elif defined(IP_RECVIF)
  struct sockaddr_dl *sdl;
#endif

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (void *)buf;
  iov.iov_len  = sizeof(buf);

  memset(&msg, 0, sizeof(msg));
  msg.msg_name       = (void *)&from;
  msg.msg_namelen    = sizeof(from);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (void *)ctrlbuf;
  msg.msg_controllen = sizeof(ctrlbuf);

  if((rrc = recvmsg(fd, &msg, 0)) <= 0)
    return;
#else
  socklen_t fromlen = sizeof(from);
  if((rrc = recvfrom(fd, buf, sizeof(buf), 0,
		     (struct sockaddr *)&from, &fromlen)) <= 0)
    return;
#endif

  memset(&ur, 0, sizeof(ur));

#ifndef _WIN32 /* windows does not have msghdr or iovec */
  if(msg.msg_controllen >= sizeof(struct cmsghdr))
    {
      cmsg = (struct cmsghdr *)CMSG_FIRSTHDR(&msg);
      while(cmsg != NULL)
	{
	  if(cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMP)
	    {
	      timeval_cpy(&ur.rx, (struct timeval *)CMSG_DATA(cmsg));
	    }
	  else if(cmsg->cmsg_level == IPPROTO_IP &&
		 (cmsg->cmsg_type == IP_TTL
#ifdef IP_RECVTTL
		  || cmsg->cmsg_type == IP_RECVTTL
#endif
		  ))
	    {
	      /*
	       * IP_RECVTTL (since Linux 2.2)
	       * When this flag is set, pass a IP_TTL control message
	       * with the time-to-live field of the received packet as
	       * a 32 bit integer.
	       *
	       * FreeBSD, OpenBSD, NetBSD:
	       * If the IP_RECVTTL option is enabled on a SOCK_DGRAM
	       * socket, the recvmsg(2) call will return the IP TTL
	       * (time to live) field for a UDP datagram.  The
	       * msg_control field in the msghdr structure points to a
	       * buffer that contains a cmsghdr structure followed by
	       * the TTL.  The cmsghdr fields have the following
	       * values:
	       *   cmsg_len = CMSG_LEN(sizeof(u_char))
	       *   cmsg_level = IPPROTO_IP
	       *   cmsg_type = IP_RECVTTL
	       */
	      if((ur.flags & SCAMPER_UDP_RESP_FLAG_TTL) == 0 &&
		 cmsg_data_as_uint8(cmsg, &ur.ttl) == 0)
		ur.flags |= SCAMPER_UDP_RESP_FLAG_TTL;
	    }
	  else if(cmsg->cmsg_level == IPPROTO_IP &&
		  (cmsg->cmsg_type == IP_TOS
#if defined(IP_RECVTOS)
		   || cmsg->cmsg_type == IP_RECVTOS
#endif
		   ))
	    {
	      if((ur.flags & SCAMPER_UDP_RESP_FLAG_TOS) == 0 &&
		 cmsg_data_as_uint8(cmsg, &ur.tos) == 0)
		ur.flags |= SCAMPER_UDP_RESP_FLAG_TOS;
	    }
#if defined(IP_PKTINFO)
	  else if(cmsg->cmsg_level == IPPROTO_IP &&
		  cmsg->cmsg_type == IP_PKTINFO)
	    {
	      pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
	      ur.ifindex = pi->ipi_ifindex;
	      ur.flags |= SCAMPER_UDP_RESP_FLAG_IFINDEX;
	    }
#elif defined(IP_RECVIF)
	  else if(cmsg->cmsg_level == IPPROTO_IP &&
		  cmsg->cmsg_type == IP_RECVIF)
	    {
	      sdl = (struct sockaddr_dl *)CMSG_DATA(cmsg);
	      ur.ifindex = sdl->sdl_index;
	      ur.flags |= SCAMPER_UDP_RESP_FLAG_IFINDEX;
	    }
#endif

	  cmsg = (struct cmsghdr *)CMSG_NXTHDR(&msg, cmsg);
	}
    }
#endif /* _WIN32 */

  if(timeval_iszero(&ur.rx))
    gettimeofday_wrap(&ur.rx);

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
int scamper_udp4_opendgram(const void *addr, int sport, scamper_err_t *error)
#else
SOCKET scamper_udp4_opendgram(const void *addr, int sport, scamper_err_t *error)
#endif
{
  struct sockaddr_in sin4;
  char tmp[32];

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(socket_isinvalid(fd))
    {
      scamper_err_make(error, errno, "could not open udp4dgram socket");
      goto err;
    }

  if(setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1) != 0)
    {
      scamper_err_make(error, errno, "could not set SO_REUSEADDR on udp4dgram");
      goto err;
    }

#if defined(SO_TIMESTAMP)
  if(setsockopt_int(fd, SOL_SOCKET, SO_TIMESTAMP, 1) != 0)
    printerror(__func__, "could not set SO_TIMESTAMP");
#endif

#if defined(IP_RECVTTL)
  if(setsockopt_int(fd, IPPROTO_IP, IP_RECVTTL, 1) != 0)
    printerror(__func__, "could not set IP_RECVTTL");
#endif

#if defined(IP_RECVTOS)
  if(setsockopt_int(fd, IPPROTO_IP, IP_RECVTOS, 1) != 0)
    printerror(__func__, "could not set IP_RECVTOS");
#endif

  /*
   * ask the udp4 socket to supply the interface on which it receives
   * a packet.
   */
#if defined(IP_RECVPKTINFO)
  if(setsockopt_int(fd, IPPROTO_IP, IP_RECVPKTINFO, 1) != 0)
    printerror(__func__, "could not set IP_RECVPKTINFO");
#elif defined(IP_PKTINFO)
  if(setsockopt_int(fd, IPPROTO_IP, IP_PKTINFO, 1) != 0)
    printerror(__func__, "could not set IP_PKTINFO");
#elif defined(IP_RECVIF)
  if(setsockopt_int(fd, IPPROTO_IP, IP_RECVIF, 1) != 0)
    printerror(__func__, "could not set IP_RECVIF");
#endif

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET, addr, sport);
  if(bind(fd, (struct sockaddr *)&sin4, sizeof(sin4)) == -1)
    {
      sockaddr_tostr((struct sockaddr *)&sin4, tmp, sizeof(tmp), 1);
      scamper_err_make(error, errno, "could not bind udp4dgram %s", tmp);
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
  if(setsockopt_int(fd, IPPROTO_IP, IP_HDRINCL, 1) != 0)
    {
      printerror(__func__, "could not IP_HDRINCL");
      goto err;
    }
  sockaddr_compose((struct sockaddr *)&sin4, AF_INET, addr, 0);
  if(bind(fd, (struct sockaddr *)&sin4, sizeof(sin4)) == -1)
    {
      printerror(__func__, "could not bind %s",
		 sockaddr_tostr((struct sockaddr *)&sin4, tmp, sizeof(tmp), 1));
      goto err;
    }

  return fd;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  return socket_invalid();
}

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_udp4_openraw(const void *addr, scamper_err_t *error)
#else
SOCKET scamper_udp4_openraw(const void *addr, scamper_err_t *error)
#endif
{
#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

  fd = scamper_priv_udp4raw(addr);
  if(socket_isinvalid(fd))
    {
      scamper_err_make(error, errno, "could not open udp4raw socket");
      goto err;
    }

  if(setsockopt_raise(fd, SOL_SOCKET, SO_SNDBUF, 65535 + 128) != 0)
    {
      scamper_err_make(error, errno, "could not raise SO_SNDBUF on udp4raw");
      goto err;
    }
  return fd;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  return socket_invalid();
}
#endif /* BUILDING_SCAMPER */
