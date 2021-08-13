/*
 * scamper_udp6.c
 *
 * $Id: scamper_udp6.c,v 1.62 2020/06/12 23:57:02 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
 * Copyright (C) 2020      Matthew Luckie
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

#include "scamper_addr.h"
#include "scamper_dl.h"
#include "scamper_probe.h"
#include "scamper_ip6.h"
#include "scamper_udp6.h"
#include "scamper_icmp_resp.h"
#include "scamper_fds.h"

#include "scamper_debug.h"
#include "utils.h"

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
int scamper_udp6_probe(scamper_probe_t *probe)
{
  struct sockaddr_in6  sin6;
  int                  i, j, k;
  char                 addr[128];

  assert(probe != NULL);
  assert(probe->pr_ip_proto == IPPROTO_UDP);
  assert(probe->pr_ip_dst != NULL);
  assert(probe->pr_ip_src != NULL);
  assert(probe->pr_len != 0 || probe->pr_data == NULL);

  i = probe->pr_ip_ttl;
  if(setsockopt(probe->pr_fd,
		IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&i, sizeof(i)) == -1)
    {
      printerror(__func__, "could not set hlim to %d", i);
      return -1;
    }

  sockaddr_compose((struct sockaddr *)&sin6, AF_INET6,
		   probe->pr_ip_dst->addr, probe->pr_udp_dport);

  /* get the transmit time immediately before we send the packet */
  gettimeofday_wrap(&probe->pr_tx);

  /*
   * if we are using RECVERR socket, then we might need to try probing
   * multiple times to get the packet to send.
   */
  if((probe->pr_flags & SCAMPER_PROBE_FLAG_RXERR) == 0)
    k = 1;
  else
    k = 5;

  for(j=0; j<k; j++)
    {
      i = sendto(probe->pr_fd, probe->pr_data, probe->pr_len, 0,
		 (struct sockaddr *)&sin6, sizeof(struct sockaddr_in6));

      /*
       * if we sent the probe successfully, there is nothing more to
       * do here
       */
      if(i == probe->pr_len)
	return 0;
      else if(i != -1)
	break;
    }

  /* get a copy of the errno variable as it is immediately after the sendto */
  probe->pr_errno = errno;

  /* error condition, could not send the packet at all */
  if(i == -1)
    {
      printerror(__func__, "could not send to %s (%d hlim, %d dport, %d len)",
		 scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)),
		 probe->pr_ip_ttl, probe->pr_udp_dport, probe->pr_len);
    }
  /* error condition, sent a portion of the probe */
  else
    {
      printerror_msg(__func__, "sent %d bytes of %d byte packet to %s",
		     i, (int)probe->pr_len,
		     scamper_addr_tostr(probe->pr_ip_dst, addr, sizeof(addr)));
    }

  return -1;
}

#if defined(IPV6_RECVERR)
static int scamper_udp6_read_err(int fd, scamper_icmp_resp_t *resp)
{
  struct sock_extended_err *ee = NULL;
  struct sockaddr_in6 from, *sin6;  
  struct cmsghdr *cm;
  struct msghdr msg;
  struct iovec iov;
  ssize_t pbuflen;
  uint8_t ctrlbuf[2048];
  uint8_t rxbuf[65536];

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
	  resp->ir_ip_ttl = *((uint8_t *)CMSG_DATA(cm));
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

void scamper_udp6_read_err_cb(int fd, void *param)
{
#if defined(IPV6_RECVERR)
  scamper_icmp_resp_t ir;
  memset(&ir, 0, sizeof(ir));
  if(scamper_udp6_read_err(fd, &ir) == 0 &&
     scamper_fd_sport((const scamper_fd_t *)param,&ir.ir_inner_udp_sport) == 0)
    scamper_icmp_resp_handle(&ir);
  scamper_icmp_resp_clean(&ir);
#endif
  return;
}

void scamper_udp6_close(int fd)
{
#ifndef _WIN32
  close(fd);
#else
  closesocket(fd);
#endif
  return;
}

int scamper_udp6_open(const void *addr, int sport)
{
  struct sockaddr_in6 sin6;
  char buf[128];
  int opt, fd = -1;

  if((fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
      printerror(__func__, "could not open socket");
      goto err;
    }

#ifdef IPV6_V6ONLY
  opt = 1;
  if(setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY, (char *)&opt,sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set IPV6_V6ONLY");
      goto err;
    }
#endif

  sockaddr_compose((struct sockaddr *)&sin6, AF_INET6, addr, sport);
  if(bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) == -1)
    {
      if(addr == NULL || addr_tostr(AF_INET6, addr, buf, sizeof(buf)) == NULL)
	printerror(__func__, "could not bind port %d", sport);
      else
	printerror(__func__, "could not bind %s:%d", buf, sport);
      goto err;
    }

  opt = 65535 + 128;
  if(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set SO_SNDBUF");
      return -1;
    }

#if defined(IPV6_DONTFRAG)
  opt = 1;
  if(setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG,
		(char *)&opt, sizeof(opt)) == -1)
    {
      printerror(__func__, "could not set IPV6_DONTFRAG");
      goto err;
    }
#endif

  return fd;

 err:
  if(fd != -1) scamper_udp6_close(fd);
  return -1;
}

#if defined(IPV6_RECVERR)
int scamper_udp6_open_err(const void *addr, int sport)
{
  int opt, fd;

  if((fd = scamper_udp6_open(addr, sport)) == -1)
    return -1;

  opt = 65535 + 128;
  if(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *)&opt, sizeof(opt)) != 0)
    {
      printerror(__func__, "could not set SO_RCVBUF");
      goto err;
    }

  opt = 1;
  if(setsockopt(fd, IPPROTO_IPV6, IPV6_RECVERR, &opt, sizeof(opt)) != 0)
    {
      printerror(__func__, "could not set IPV6_RECVERR");
      goto err;
    }

#if defined(IPV6_HOPLIMIT)
  opt = 1;
  if(setsockopt(fd,IPPROTO_IPV6,IPV6_HOPLIMIT,(char *)&opt,sizeof(opt)) != 0)
    {
      printerror(__func__, "could not set IPV6_HOPLIMIT");
    }
#endif

#if defined(SO_TIMESTAMP)
  opt = 1;
  if(setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt)) != 0)
    {
      printerror(__func__, "could not set SO_TIMESTAMP");
      goto err;
    }
#endif

  return fd;

 err:
  if(fd != -1) scamper_udp6_close(fd);
  return -1;
}
#else
int scamper_udp6_open_err(const void *addr, int sport)
{
  return -1;
}
#endif
