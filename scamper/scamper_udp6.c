/*
 * scamper_udp6.c
 *
 * $Id: scamper_udp6.c,v 1.87 2025/10/23 18:54:23 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
 * Copyright (C) 2020-2023 Matthew Luckie
 * Copyright (C) 2024      The Regents of the University of California
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
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_task.h"
#include "scamper_dl.h"
#include "scamper_dlhdr.h"
#include "scamper_probe.h"
#include "scamper_ip6.h"
#include "scamper_udp6.h"
#include "scamper_icmp_resp.h"
#include "scamper_udp_resp.h"
#include "scamper_fds.h"
#include "utils.h"

#if defined(BUILDING_SCAMPER) && defined(IPV6_RECVERR)
static uint8_t rxbuf[65536];
#endif

uint16_t scamper_udp6_cksum(scamper_probe_t *probe)
{
  uint16_t *w, tmp;
  int i, sum = 0;

  /* compute the checksum over the psuedo header */
  w = (uint16_t *)probe->pr_ip_src->addr;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  w = (uint16_t *)probe->pr_ip_dst->addr;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += *w++; sum += *w++; sum += *w++; sum += *w++;
  sum += htons(probe->pr_len + 8);
  sum += htons(IPPROTO_UDP);

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

int scamper_udp6_build(scamper_probe_t *probe, uint8_t *buf, size_t *len)
{
  struct ip6_hdr *ip6;
  struct udphdr  *udp;
  size_t          ip6hlen, req;

  /* build the IPv6 header */
  ip6hlen = *len;
  scamper_ip6_build(probe, buf, &ip6hlen);

  /* calculate the total number of bytes required for this packet */
  req = ip6hlen + 8 + probe->pr_len;

  if(req <= *len)
    {
      /* calculate and record the plen value */
      ip6 = (struct ip6_hdr *)buf;
      ip6->ip6_plen = htons(ip6hlen - 40 + 8 + probe->pr_len);

      udp = (struct udphdr *)(buf + ip6hlen);
      udp->uh_sport = htons(probe->pr_udp_sport);
      udp->uh_dport = htons(probe->pr_udp_dport);
      udp->uh_ulen  = htons(sizeof(struct udphdr) + probe->pr_len);
      udp->uh_sum   = scamper_udp6_cksum(probe);

      /* if there is data to include in the payload, copy it in now */
      if(probe->pr_len != 0)
	{
	  memcpy(buf + ip6hlen + 8, probe->pr_data, probe->pr_len);
	}

      *len = req;
      return 0;
    }

  *len = req;
  return -1;
}

#ifdef BUILDING_SCAMPER
/*
 * scamper_udp6_probe:
 *
 * given the address, hop limit, destination UDP port number, and size, send
 * a UDP probe packet encapsulated in an IPv6 header.
 *
 * the size parameter is useful when doing path MTU discovery, and represents
 * how large the packet should be including IPv6 and UDP headers
 *
 * this function returns 0 on success, -1 otherwise
 */
int scamper_udp6_probe(scamper_probe_t *pr, scamper_err_t *error)
{
  struct sockaddr_in6  sin6;
  int                  i, j, k;
  char                 addr[128];

  assert(pr != NULL);
  assert(pr->pr_ip_proto == IPPROTO_UDP);
  assert(pr->pr_ip_dst != NULL);
  assert(pr->pr_ip_src != NULL);
  assert(pr->pr_len != 0 || pr->pr_data == NULL);

  if(setsockopt_int(pr->pr_fd,
		    IPPROTO_IPV6, IPV6_UNICAST_HOPS, pr->pr_ip_ttl) != 0)
    {
      scamper_err_make(error, errno, "udp6_probe could not set hlim to %d",
		       pr->pr_ip_ttl);
      return -1;
    }

#ifdef IPV6_TCLASS
  if(setsockopt_int(pr->pr_fd, IPPROTO_IPV6, IPV6_TCLASS, pr->pr_ip_tos) != 0)
    {
      scamper_err_make(error, errno, "udp6_probe could not set tclass to %d",
		       pr->pr_ip_tos);
      return -1;
    }
#endif /* IPV6_TCLASS */

  sockaddr_compose((struct sockaddr *)&sin6, AF_INET6,
		   pr->pr_ip_dst->addr, pr->pr_udp_dport);

  /* get the transmit time immediately before we send the packet */
  gettimeofday_wrap(&pr->pr_tx);

  /*
   * if we are using RECVERR socket, then we might need to try probing
   * multiple times to get the packet to send.
   */
  if((pr->pr_flags & SCAMPER_PROBE_FLAG_RXERR) == 0)
    k = 1;
  else
    k = 5;

  for(j=0; j<k; j++)
    {
      i = sendto(pr->pr_fd, pr->pr_data, pr->pr_len, 0,
		 (struct sockaddr *)&sin6, sizeof(struct sockaddr_in6));

      /*
       * if we sent the probe successfully, there is nothing more to
       * do here
       */
      if(i == pr->pr_len)
	return 0;
      else if(i != -1)
	break;
    }

  if(i == -1)
    {
      /* error condition, could not send the packet at all */
      scamper_err_make(error, errno,
		       "udp6_probe could not send to %s (%d hlim, %d dport, %d len)",
		       scamper_addr_tostr(pr->pr_ip_dst, addr, sizeof(addr)),
		       pr->pr_ip_ttl, pr->pr_udp_dport, pr->pr_len);
    }
  else
    {
      /* error condition, sent a portion of the probe */
      scamper_err_make(error, 0,
		       "udp6_probe sent %d bytes of %d byte packet to %s",
		       i, (int)pr->pr_len,
		       scamper_addr_tostr(pr->pr_ip_dst, addr, sizeof(addr)));
    }

  return -1;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
void scamper_udp6_read_cb(int fd, void *param)
#else
void scamper_udp6_read_cb(SOCKET fd, void *param)
#endif
{
  scamper_udp_resp_t ur;
  struct sockaddr_in6 from;
  uint8_t buf[8192], ctrlbuf[256];
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct iovec iov;
  ssize_t rrc;
  int v;

#ifdef IP_PKTINFO
  struct in_pktinfo *pi;
#endif

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
#if defined(IPV6_HOPLIMIT)
	  else if(cmsg->cmsg_level == IPPROTO_IPV6 &&
		  cmsg->cmsg_type == IPV6_HOPLIMIT)
	    {
	      v = *((int *)CMSG_DATA(cmsg));
	      ur.ttl = (uint8_t)v;
	    }
#endif
#if defined(IP_PKTINFO)
	  else if(cmsg->cmsg_level == IPPROTO_IPV6 &&
		  cmsg->cmsg_type == IP_PKTINFO)
	    {
	      pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
	      ur.ifindex = pi->ipi_ifindex;
	      ur.flags |= SCAMPER_UDP_RESP_FLAG_IFINDEX;
	    }
#endif
	  cmsg = (struct cmsghdr *)CMSG_NXTHDR(&msg, cmsg);
	}
    }

  ur.af = AF_INET6;
  ur.addr = &from.sin6_addr;
  ur.sport = ntohs(from.sin6_port);
  ur.data = buf;
  ur.datalen = rrc;
  ur.fd = fd;

  scamper_task_handleudp(&ur);

  return;
}

#if defined(IPV6_RECVERR) && !defined(_WIN32)
static int scamper_udp6_read_err(int fd, scamper_icmp_resp_t *resp)
{
  struct sock_extended_err *ee = NULL;
  struct sockaddr_in6 from, *sin6;
  struct cmsghdr *cm;
  struct msghdr msg;
  struct iovec iov;
  ssize_t pbuflen;
  uint8_t ctrlbuf[2048];
  int v;

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (caddr_t)rxbuf;
  iov.iov_len  = sizeof(rxbuf);

  msg.msg_name       = (caddr_t)&from;
  msg.msg_namelen    = sizeof(from);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (caddr_t)ctrlbuf;
  msg.msg_controllen = sizeof(ctrlbuf);

  /* two calls to recvmsg, first one looking in the error queue */
  if((pbuflen = recvmsg(fd, &msg, MSG_ERRQUEUE)) == -1)
    {
      recvmsg(fd, &msg, 0);
      return -1;
    }

  if(msg.msg_controllen < sizeof(struct cmsghdr))
    return -1;

  memset(resp, 0, sizeof(scamper_icmp_resp_t));
  resp->ir_ip_ttl = -1;

  cm = (struct cmsghdr *)CMSG_FIRSTHDR(&msg);
  while(cm != NULL)
    {
      if(cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_TIMESTAMP)
	{
	  timeval_cpy(&resp->ir_rx, (struct timeval *)CMSG_DATA(cm));
	  resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_KERNRX;
	}
      else if(cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_RECVERR)
	{
	  ee = (struct sock_extended_err *)CMSG_DATA(cm);
	  if(ee->ee_origin == SO_EE_ORIGIN_ICMP6)
	    {
	      resp->ir_icmp_type = ee->ee_type;
	      resp->ir_icmp_code = ee->ee_code;
	      sin6 = (struct sockaddr_in6 *)SO_EE_OFFENDER(ee);
	      memcpy(&resp->ir_ip_src.v6, &sin6->sin6_addr,
		     sizeof(struct in6_addr));
	    }
	}
#if defined(IPV6_HOPLIMIT)
      else if(cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_HOPLIMIT)
	{
	  v = *((int *)CMSG_DATA(cm));
	  resp->ir_ip_ttl = (uint8_t)v;
	}
#endif
#if defined(IPV6_TCLASS)
      else if(cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_TCLASS)
	{
	  v = *((int *)CMSG_DATA(cm));
	  resp->ir_ip_tos = (uint8_t)v;
	  resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_TCLASS;
	}
#endif
      cm = (struct cmsghdr *)CMSG_NXTHDR(&msg, cm);
    }

  if(ee == NULL ||
     (resp->ir_icmp_type != ICMP6_TIME_EXCEEDED &&
      resp->ir_icmp_type != ICMP6_DST_UNREACH))
     return -1;

  resp->ir_fd = fd;
  resp->ir_af = AF_INET6;
  memcpy(&resp->ir_inner_ip_dst.v6, &from.sin6_addr, sizeof(struct in6_addr));
  resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_RXERR;
  resp->ir_flags |= SCAMPER_ICMP_RESP_FLAG_INNER_IP;
  resp->ir_inner_udp_dport = ntohs(from.sin6_port);
  resp->ir_inner_ip_proto = IPPROTO_UDP;
  resp->ir_inner_udp_data = rxbuf;
  resp->ir_inner_udp_datalen = pbuflen;
  resp->ir_inner_ip_size = 40 + 8 + pbuflen;

  if((resp->ir_flags & SCAMPER_ICMP_RESP_FLAG_KERNRX) == 0)
    gettimeofday_wrap(&resp->ir_rx);

  return 0;
}

#endif

#ifndef _WIN32 /* SOCKET vs int on windows */
void scamper_udp6_read_err_cb(int fd, void *param)
#else
void scamper_udp6_read_err_cb(SOCKET fd, void *param)
#endif
{
#if defined(IPV6_RECVERR) && !defined(_WIN32)
  scamper_icmp_resp_t ir;
  memset(&ir, 0, sizeof(ir));
  if(scamper_udp6_read_err(fd, &ir) == 0 &&
     scamper_fd_sport((const scamper_fd_t *)param,&ir.ir_inner_udp_sport) == 0)
    scamper_task_handleicmp(&ir);
  scamper_icmp_resp_clean(&ir);
#endif
  return;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_udp6_open(const void *addr, int sport, scamper_err_t *error)
#else
SOCKET scamper_udp6_open(const void *addr, int sport, scamper_err_t *error)
#endif
{
  struct sockaddr_in6 sin6;
  char buf[128];

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd = -1;
#else
  SOCKET fd = INVALID_SOCKET;
#endif

  fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if(socket_isinvalid(fd))
    {
      scamper_err_make(error, errno, "could not open udp6 socket");
      goto err;
    }

#ifdef IPV6_V6ONLY
  if(setsockopt_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1) != 0)
    {
      scamper_err_make(error, errno, "could not set IPV6_V6ONLY on udp6");
      goto err;
    }
#endif

  sockaddr_compose((struct sockaddr *)&sin6, AF_INET6, addr, sport);
  if(bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) == -1)
    {
      if(addr == NULL || addr_tostr(AF_INET6, addr, buf, sizeof(buf)) == NULL)
	scamper_err_make(error, errno, "could not bind udp6 port %d", sport);
      else
	scamper_err_make(error, errno, "could not bind udp6 [%s.%d]",
			 buf, sport);
      goto err;
    }

  if(setsockopt_raise(fd, SOL_SOCKET, SO_SNDBUF, 65535 + 128) != 0)
    {
      scamper_err_make(error, errno, "could not raise SO_SNDBUF on udp6");
      goto err;
    }

#if defined(IPV6_DONTFRAG)
  if(setsockopt_int(fd, IPPROTO_IPV6, IPV6_DONTFRAG, 1) != 0)
    {
      scamper_err_make(error, errno, "could not set IPV6_DONTFRAG on udp6");
      goto err;
    }
#endif

#if defined(IPV6_RECVHOPLIMIT)
  if(setsockopt_int(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1) != 0)
    printerror(__func__, "could not set IPV6_RECVHOPLIMIT");
#elif defined(IPV6_HOPLIMIT)
  if(setsockopt_int(fd, IPPROTO_IPV6, IPV6_HOPLIMIT, 1) != 0)
    printerror(__func__, "could not set IPV6_HOPLIMIT");
#endif

#if defined(SO_TIMESTAMP)
  if(setsockopt_int(fd, SOL_SOCKET, SO_TIMESTAMP, 1) != 0)
    printerror(__func__, "could not set SO_TIMESTAMP");
#endif

  /*
   * ask the udp6 socket to supply the interface on which it receives
   * a packet.
   */
#if defined(IPV6_RECVPKTINFO)
  if(setsockopt_int(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1) != 0)
    printerror(__func__, "could not set IPV6_RECVPKTINFO");
#elif defined(IPV6_PKTINFO)
  if(setsockopt_int(fd, IPPROTO_IPV6, IPV6_PKTINFO, 1) != 0)
    printerror(__func__, "could not set IPV6_PKTINFO");
#endif

  return fd;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  return socket_invalid();
}

#ifndef _WIN32 /* SOCKET vs int on windows */
int scamper_udp6_open_err(const void *addr, int sport, scamper_err_t *error)
#else
SOCKET scamper_udp6_open_err(const void *addr, int sport, scamper_err_t *error)
#endif
{
#ifdef IPV6_RECVERR

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

  fd = scamper_udp6_open(addr, sport, error);
  if(socket_isinvalid(fd))
    return socket_invalid();

  if(setsockopt_raise(fd, SOL_SOCKET, SO_RCVBUF, 65535 + 128) != 0)
    {
      scamper_err_make(error, errno, "could not raise SO_RCVBUF on udp6err");
      goto err;
    }

  if(setsockopt_int(fd, IPPROTO_IPV6, IPV6_RECVERR, 1) != 0)
    {
      scamper_err_make(error, errno, "could not set IPV6_RECVERR on udp6err");
      goto err;
    }

  return fd;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
#endif /* #ifdef IPV6_RECVERR */
  return socket_invalid();
}
#endif /* BUILDING_SCAMPER */
