/*
 * sc_rxifd: reply to query with received interface name
 *
 * $Id: sc_rxifd.c,v 1.13 2026/04/17 19:51:39 mjl Exp $
 *
 *         Matthew Luckie
 *         mjl@luckie.org.nz
 *
 * Copyright (C) 2026 The Regents of the University of California
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

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#include <assert.h>

#include "utils.h"

#if defined(IP_PKTINFO) || \
  (defined(IP_RECVIF) && defined(IP_RECVDSTADDR) && defined(IP_SENDSRCADDR))
#define HAVE_RXIF4
#endif

#if defined(IPV6_PKTINFO)
#define HAVE_RXIF6
#endif

#define OPT_HELP        0x0001
#define OPT_PORT        0x0002
#define OPT_NAME        0x0004
#define OPT_PPS         0x0008

#ifdef HAVE_RXIF4
#define OPT_IPV4        0x1000
#endif
#ifdef HAVE_RXIF6
#define OPT_IPV6        0x2000
#endif
#ifdef HAVE_DAEMON
#define OPT_DAEMON      0x4000
#endif
#ifdef PACKAGE_VERSION
#define OPT_VERSION     0x8000
#endif

#define OPT_ALL         0xFFFF

#if defined(HAVE_RXIF4) || defined(HAVE_RXIF6)
static uint32_t        options  = 0;
static uint16_t        sport    = 0;
static char           *name     = NULL;
static struct timeval  now;
static int             stop     = 0;
static int             in_loop  = 0;
static int             pps      = 100;
static int             pps_cur  = 0;
static time_t          pps_sec  = 0;
#endif

#ifdef HAVE_RXIF4
static int             fd4      = socket_invalid();
#endif
#ifdef HAVE_RXIF6
static int             fd6      = socket_invalid();
#endif

#if defined(HAVE_RXIF4) || defined(HAVE_RXIF6)
static void usage(uint32_t opt_mask)
{
  fprintf(stderr, "sc_rxifd [-?"
#ifdef OPT_IPV4
	  "4"
#endif
#ifdef OPT_IPV6
	  "6"
#endif
#ifdef OPT_DAEMON
	  "D"
#endif
#ifdef OPT_VERSION
	  "v"
#endif
	  "] [-n qname] [-p pps] [-P port]\n\n");

  if(opt_mask == 0)
    return;

#ifdef OPT_IPV4
  if(opt_mask & OPT_IPV4)
    fprintf(stderr, "     -4 only listen for connections over IPv4\n");
#endif

#ifdef OPT_IPV6
  if(opt_mask & OPT_IPV6)
    fprintf(stderr, "     -6 only listen for connections over IPv6\n");
#endif

#ifdef OPT_DAEMON
  if(opt_mask & OPT_DAEMON)
    fprintf(stderr, "     -D operate as a daemon\n");
#endif

  if(opt_mask & OPT_NAME)
    fprintf(stderr, "     -n name to answer queries for\n");

  if(opt_mask & OPT_PPS)
    fprintf(stderr, "     -p responses per second allowed\n");

  if(opt_mask & OPT_PORT)
    fprintf(stderr, "     -P port to listen on\n");

#ifdef OPT_VERSION
  if(opt_mask & OPT_VERSION)
    fprintf(stderr, "     -v display version and exit\n");
#endif

  return;
}
#endif

#if defined(HAVE_RXIF4) || defined(HAVE_RXIF6)
static int check_options(int argc, char *argv[])
{
  char *opts = "?"
#ifdef OPT_IPV4
    "4"
#endif
#ifdef OPT_IPV6
    "6"
#endif
#ifdef OPT_DAEMON
    "D"
#endif
    "n:p:P:"
#ifdef OPT_VERSION
    "v"
#endif
    ;
  char *opt_sport = NULL, *opt_name = NULL, *opt_pps = NULL;
  long lo;
  int ch;

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
#ifdef OPT_IPV4
	case '4':
	  options |= OPT_IPV4;
	  break;
#endif

#ifdef OPT_IPV6
	case '6':
	  options |= OPT_IPV6;
	  break;
#endif

#ifdef OPT_DAEMON
	case 'D':
	  options |= OPT_DAEMON;
	  break;
#endif

	case 'n':
	  opt_name = optarg;
	  break;

	case 'p':
	  opt_pps = optarg;
	  break;

	case 'P':
	  opt_sport = optarg;
	  break;

#ifdef OPT_VERSION
	case 'v':
	  options |= OPT_VERSION;
	  return 0;
#endif

	case '?':
	default:
	  usage(OPT_ALL);
	  return -1;
	}
    }

  if(argc - optind > 0)
    {
      usage(0);
      fprintf(stderr, "sc_rxifd does not accept positional arguments\n");
      return -1;
    }

  if(opt_sport == NULL && opt_name == NULL && opt_pps == NULL)
    {
      usage(OPT_PORT|OPT_NAME|OPT_PPS);
      return -1;
    }

#if defined(OPT_IPV4) && defined(OPT_IPV6)
  if(countbits32(options & (OPT_IPV4|OPT_IPV6)) == 2)
    {
      usage(OPT_IPV4|OPT_IPV6);
      return -1;
    }
#endif

  /* source-port is a required argument */
  if(opt_sport == NULL ||
     string_tolong(opt_sport, &lo) != 0 || lo < 1 || lo > UINT16_MAX)
    {
      usage(OPT_PORT);
      return -1;
    }
  sport = (uint16_t)lo;

  /* name is a required argument */
  if(opt_name == NULL ||
     strlen(opt_name) >= 255 ||
     (name = strdup(opt_name)) == NULL)
    {
      usage(OPT_NAME);
      return -1;
    }

  /* PPS is a required argument */
  if(opt_pps == NULL ||
     string_tolong(opt_pps, &lo) != 0 || lo < 0)
    {
      usage(OPT_PPS);
      return -1;
    }
  pps = (int)lo;

  return 0;
}
#endif

#if defined(HAVE_RXIF4) || defined(HAVE_RXIF6)
static void rxifd_stderr(const char *func, const char *format, va_list ap)
{
  char message[512], ts[16];

#ifdef OPT_DAEMON
  if(options & OPT_DAEMON)
    return;
#endif

  vsnprintf(message, sizeof(message), format, ap);

  if(in_loop != 0)
    fprintf(stderr, "[%s] ", timeval_tostr_hhmmssms(&now, ts));
  fprintf(stderr, "%s: %s\n", func, message);
  fflush(stderr);

  return;
}
#endif

#if defined(HAVE_RXIF4) || defined(HAVE_RXIF6)
#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
static void rxifd_error(const char *func, const char *format, ...)
  __attribute__((format(printf, 2, 3)));
#endif
static void rxifd_error(const char *func, const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  rxifd_stderr(func, format, ap);
  va_end(ap);

  return;
}
#endif

#ifdef HAVE_RXIF6
static int udp6_open(void)
{
  struct sockaddr_in6 sin6;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd = -1;
#else
  SOCKET fd = INVALID_SOCKET;
#endif

#ifdef OPT_IPV4
  /* if we've been told to only open IPv4 socket, then we're done */
  if(options & OPT_IPV4)
    return 0;
#endif

  fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if(socket_isinvalid(fd))
    {
      rxifd_error(__func__, "could not open udp6 socket: %s", strerror(errno));
      goto err;
    }

#ifdef IPV6_V6ONLY
  if(setsockopt_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1) != 0)
    {
      rxifd_error(__func__, "could not set IPV6_V6ONLY on udp6: %s",
		  strerror(errno));
      goto err;
    }
#endif

  sockaddr_compose((struct sockaddr *)&sin6, AF_INET6, NULL, sport);
  if(bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) != 0)
    {
      rxifd_error(__func__, "could not bind udp6 port %u: %s", sport,
		  strerror(errno));
      goto err;
    }

  /*
   * ask the udp6 socket to supply the interface on which it receives
   * a packet.
   */
#if defined(IPV6_RECVPKTINFO)
  if(setsockopt_int(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1) != 0)
    {
      rxifd_error(__func__, "could not set IPV6_RECVPKTINFO: %s",
		  strerror(errno));
      goto err;
    }
#elif defined(IPV6_PKTINFO)
  if(setsockopt_int(fd, IPPROTO_IPV6, IPV6_PKTINFO, 1) != 0)
    {
      rxifd_error(__func__, "could not set IPV6_PKTINFO: %s",
		  strerror(errno));
      goto err;
    }
#endif

  fd6 = fd;
  return 0;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  return -1;
}
#endif /* HAVE_RXIF6 */

#ifdef HAVE_RXIF4
int udp4_open(void)
{
  struct sockaddr_in sin4;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

#ifdef OPT_IPV6
  /* if we've been told to only open IPv6 socket, then we're done */
  if(options & OPT_IPV6)
    return 0;
#endif

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(socket_isinvalid(fd))
    {
      rxifd_error(__func__, "could not open udp4 socket: %s", strerror(errno));
      goto err;
    }

  if(setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1) != 0)
    {
      rxifd_error(__func__, "could not set SO_REUSEADDR on udp4: %s",
		  strerror(errno));
      goto err;
    }

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET, NULL, sport);
  if(bind(fd, (struct sockaddr *)&sin4, sizeof(sin4)) == -1)
    {
      rxifd_error(__func__, "could not bind udp4 port %u: %s", sport,
		  strerror(errno));
      goto err;
    }

  /*
   * ask the udp4 socket to supply the interface on which it receives
   * a packet.
   */
#if defined(IP_RECVPKTINFO)
  if(setsockopt_int(fd, IPPROTO_IP, IP_RECVPKTINFO, 1) != 0)
    {
      rxifd_error(__func__, "could not set IP_RECVPKTINFO: %s",
		  strerror(errno));
      goto err;
    }
#elif defined(IP_PKTINFO)
  if(setsockopt_int(fd, IPPROTO_IP, IP_PKTINFO, 1) != 0)
    {
      rxifd_error(__func__, "could not set IP_PKTINFO: %s",
		  strerror(errno));
      goto err;
    }
#elif defined(IP_RECVIF) && defined(IP_RECVDSTADDR)
  if(setsockopt_int(fd, IPPROTO_IP, IP_RECVIF, 1) != 0)
    {
      rxifd_error(__func__, "could not set IP_RECVIF: %s",
		  strerror(errno));
      goto err;
    }
  if(setsockopt_int(fd, IPPROTO_IP, IP_RECVDSTADDR, 1) != 0)
    {
      rxifd_error(__func__, "could not set IP_RECVDSTADDR: %s",
		  strerror(errno));
      goto err;
    }
#endif

  fd4 = fd;
  return 0;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  return -1;
}
#endif /* HAVE_RXIF4 */

#if defined(HAVE_RXIF4) || defined(HAVE_RXIF6)
static size_t is_valid_query(const uint8_t *rxbuf, size_t rrc)
{
  char qname[256];
  size_t qoff = 0, off;
  uint8_t label_len;

  /* make sure we got a reasonable header */
  if(rrc < 12 ||
     (bytes_ntohs(rxbuf+2) & 0xF800) != 0 || /* QR=0, Opcode=0 */
     bytes_ntohs(rxbuf+4) != 1 || /* QDCOUNT == 1 */
     bytes_ntohs(rxbuf+6) != 0 || /* ANCOUNT == 0 */
     bytes_ntohs(rxbuf+8) != 0)   /* NSCOUNT == 0 */
    return 0;

  /* extract qname in form to compare with [-n name] option */
  off = 12;
  for(;;)
    {
      if(off >= rrc)
	return 0;
      label_len = rxbuf[off++];
      if(label_len >= 64)
	return 0;
      if(label_len == 0)
	{
	  qname[--qoff] = '\0';
	  break;
	}
      if(rrc - off < (size_t)label_len ||
	 sizeof(qname) - qoff < (size_t)(label_len + 1))
	return 0;
      memcpy(qname+qoff, rxbuf+off, label_len);
      off += label_len;
      qoff += label_len;
      qname[qoff++] = '.';
    }

  /* check qname is expected */
  if(strcasecmp(name, qname) != 0)
    return 0;

  /* need qtype, qclass */
  if(rrc - off < 4 ||
     bytes_ntohs(rxbuf+off) != 16 || /* qtype = TXT */
     bytes_ntohs(rxbuf+off+2) != 1)  /* qtype = IN */
    return 0;
  off += 4;

  return off - 12;  
}
#endif

#if defined(HAVE_RXIF4) || defined(HAVE_RXIF6)
static size_t build_tx(struct sockaddr *sa, unsigned int ifindex,
		       const uint8_t *rxbuf, size_t rxlen,
		       uint8_t *txbuf, size_t txlen)
{
  char ifname[IF_NAMESIZE];
  char sastr[128];
  size_t off, qlen, iflen, salen, rdlength;

  /* if we're on to a new second, reset pps counter */
  if(now.tv_sec != pps_sec)
    {
      pps_sec = now.tv_sec;
      pps_cur = 0;
    }

  /*
   * check that
   * - we can send response according to PPS rate,
   * - the query is valid,
   * - we can get the interface name and address of sender.
   */
  if((pps != 0 && pps_cur >= pps) ||
     (qlen = is_valid_query(rxbuf, rxlen)) == 0 ||
     if_indextoname(ifindex, ifname) == NULL ||
     sockaddr_tostr(sa, sastr, sizeof(sastr), 0) == NULL)
    return 0;

  /* length of the RR data */
  salen = strlen(sastr);
  iflen = strlen(ifname);
  if(4 + salen > UINT8_MAX || 5 + iflen > UINT8_MAX)
    return 0;
  rdlength = 1 + 4 + salen + 1 + 5 + iflen;

  /* make sure we have space in txbuf */
  if(12 + qlen + 12 + rdlength > txlen)
    return 0;

  /* copy query ID */
  memcpy(txbuf, rxbuf, 2);

  /* copy RD flag from query, set QR=1 and AA=1 */
  bytes_htons(txbuf+2, (bytes_ntohs(rxbuf+2) & 0x0100) | 0x8400);

  /* one question, one answer */
  bytes_htons(txbuf+4, 1);      /* QDCOUNT */
  bytes_htons(txbuf+6, 1);      /* ANCOUNT */
  bytes_htons(txbuf+8, 0);      /* NSCOUNT */
  bytes_htons(txbuf+10, 0);     /* ARCOUNT */

  /* copy question section */
  memcpy(txbuf+12, rxbuf+12, qlen);
  off = 12 + qlen;

  /* answer question */
  bytes_htons(txbuf+off, 0xC00C); off += 2; /* point at offset 12 */
  bytes_htons(txbuf+off, 16); off += 2; /* TXT */
  bytes_htons(txbuf+off, 1); off += 2; /* IN */
  bytes_htonl(txbuf+off, 60); off += 4; /* TTL */
  bytes_htons(txbuf+off, rdlength); off += 2;
  txbuf[off++] = 4 + salen;
  memcpy(txbuf+off, "src=", 4); off += 4;
  memcpy(txbuf+off, sastr, salen); off += salen;
  txbuf[off++] = 5 + iflen;
  memcpy(txbuf+off, "rxif=", 5); off += 5;
  memcpy(txbuf+off, ifname, iflen); off += iflen;

  return off;
}
#endif

#ifdef HAVE_RXIF4
static void udp4_handle(void)
{
  struct sockaddr_in them;
  struct in_addr us;
  uint8_t rxbuf[8192], txbuf[512], ctrlbuf[256];
  struct msghdr msg;
  struct cmsghdr *cmsg;
  size_t txlen;
  unsigned int ifindex = 0;
  struct iovec iov;
  ssize_t rrc;
  int gotifindex = 0, gotaddr = 0;

#if defined(IP_PKTINFO)
  struct in_pktinfo *pi, pibuf;
#elif defined(IP_RECVIF) && defined(IP_RECVDSTADDR)
  struct sockaddr_dl *sdl;
  struct in_addr *ip4;
#endif

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (caddr_t)rxbuf;
  iov.iov_len  = sizeof(rxbuf);

  msg.msg_name       = (caddr_t)&them;
  msg.msg_namelen    = sizeof(them);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (caddr_t)ctrlbuf;
  msg.msg_controllen = sizeof(ctrlbuf);

  if((rrc = recvmsg(fd4, &msg, 0)) <= 0)
    return;

  if(msg.msg_controllen >= sizeof(struct cmsghdr))
    {
      cmsg = (struct cmsghdr *)CMSG_FIRSTHDR(&msg);
      while(cmsg != NULL)
	{
#if defined(IP_PKTINFO)
	  if(cmsg->cmsg_level == IPPROTO_IP &&
	     cmsg->cmsg_type == IP_PKTINFO)
	    {
	      pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
	      ifindex = pi->ipi_ifindex;
	      memcpy(&us, &pi->ipi_addr, sizeof(struct in_addr));
	      gotifindex = 1;
	      gotaddr = 1;
	    }
#elif defined(IP_RECVIF) && defined(IP_RECVDSTADDR)
	  if(cmsg->cmsg_level == IPPROTO_IP &&
	     cmsg->cmsg_type == IP_RECVIF)
	    {
	      sdl = (struct sockaddr_dl *)CMSG_DATA(cmsg);
	      ifindex = sdl->sdl_index;
	      gotifindex = 1;
	    }
	  else if(cmsg->cmsg_level == IPPROTO_IP &&
		  cmsg->cmsg_type == IP_RECVDSTADDR)
	    {
	      ip4 = (struct in_addr *)CMSG_DATA(cmsg);
	      memcpy(&us, ip4, sizeof(struct in_addr));
	      gotaddr = 1;
	    }
#endif
	  if(gotifindex && gotaddr)
	    break;
	  cmsg = (struct cmsghdr *)CMSG_NXTHDR(&msg, cmsg);
	}
    }

  if(gotifindex == 0 || gotaddr == 0)
    return;

  if((txlen = build_tx((struct sockaddr *)&them, ifindex, rxbuf, (size_t)rrc,
		       txbuf, sizeof(txbuf))) == 0)
    return;

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (caddr_t)txbuf;
  iov.iov_len  = txlen;

  msg.msg_name       = (caddr_t)&them;
  msg.msg_namelen    = sizeof(them);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (caddr_t)ctrlbuf;

#if defined(IP_PKTINFO)
  msg.msg_controllen = CMSG_SPACE(sizeof(pibuf));
  memset(&pibuf, 0, sizeof(pibuf));
  memcpy(&pibuf.ipi_addr, &us, sizeof(struct in_addr));
  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(pibuf));
  cmsg->cmsg_level = IPPROTO_IP;
  cmsg->cmsg_type = IP_PKTINFO;
  memcpy(CMSG_DATA(cmsg), &pibuf, sizeof(pibuf));
#elif defined(IP_RECVDSTADDR)
  msg.msg_controllen = CMSG_SPACE(sizeof(struct in_addr));
  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
  cmsg->cmsg_level = IPPROTO_IP;
  cmsg->cmsg_type = IP_SENDSRCADDR;
  memcpy(CMSG_DATA(cmsg), &us, sizeof(struct in_addr));
#endif

  if(sendmsg(fd4, &msg, 0) == -1)
    rxifd_error(__func__, "could not send response: %s", strerror(errno));

  pps_cur++;
  return;
}
#endif /* HAVE_RXIF4 */

#ifdef HAVE_RXIF6
static void udp6_handle(void)
{
  struct sockaddr_in6 them;
  struct in6_addr us;
  uint8_t rxbuf[8192], txbuf[512], ctrlbuf[256];
  struct msghdr msg;
  struct cmsghdr *cmsg;
  size_t txlen;
  unsigned int ifindex = 0;
  struct iovec iov;
  ssize_t rrc;
  int gotifindex = 0;

#if defined(IPV6_PKTINFO)
  struct in6_pktinfo *pi, pibuf;
#endif

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (caddr_t)rxbuf;
  iov.iov_len  = sizeof(rxbuf);

  msg.msg_name       = (caddr_t)&them;
  msg.msg_namelen    = sizeof(them);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (caddr_t)ctrlbuf;
  msg.msg_controllen = sizeof(ctrlbuf);

  if((rrc = recvmsg(fd6, &msg, 0)) <= 0)
    return;

  if(msg.msg_controllen >= sizeof(struct cmsghdr))
    {
      cmsg = (struct cmsghdr *)CMSG_FIRSTHDR(&msg);
      while(cmsg != NULL)
	{
#if defined(IPV6_PKTINFO)
	  if(cmsg->cmsg_level == IPPROTO_IPV6 &&
	     cmsg->cmsg_type == IPV6_PKTINFO)
	    {
	      pi = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	      ifindex = pi->ipi6_ifindex;
	      memcpy(&us, &pi->ipi6_addr, sizeof(struct in6_addr));
	      gotifindex = 1;
	      break;
	    }
#endif
	  cmsg = (struct cmsghdr *)CMSG_NXTHDR(&msg, cmsg);
	}
    }

  if(gotifindex == 0)
    return;

  if((txlen = build_tx((struct sockaddr *)&them, ifindex, rxbuf, (size_t)rrc,
		       txbuf, sizeof(txbuf))) == 0)
    return;

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (caddr_t)txbuf;
  iov.iov_len  = txlen;

  msg.msg_name       = (caddr_t)&them;
  msg.msg_namelen    = sizeof(them);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (caddr_t)ctrlbuf;

#if defined(IPV6_PKTINFO)
  msg.msg_controllen = CMSG_SPACE(sizeof(pibuf));
  memset(&pibuf, 0, sizeof(pibuf));
  memcpy(&pibuf.ipi6_addr, &us, sizeof(struct in6_addr));
  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(pibuf));
  cmsg->cmsg_level = IPPROTO_IP;
  cmsg->cmsg_type = IPV6_PKTINFO;
  memcpy(CMSG_DATA(cmsg), &pibuf, sizeof(pibuf));
#endif

  if(sendmsg(fd6, &msg, 0) == -1)
    rxifd_error(__func__, "could not send response: %s", strerror(errno));

  pps_cur++;
  return;
}
#endif /* HAVE_RXIF6 */

#if defined(HAVE_RXIF4) || defined(HAVE_RXIF6)
static int select_loop()
{
  fd_set rfds;
  int nfds = -1;
  int count;

  in_loop = 1;
  while(stop == 0)
    {
      FD_ZERO(&rfds);
#ifdef HAVE_RXIF4
      if(socket_isvalid(fd4))
	{
	  FD_SET(fd4, &rfds);
	  nfds = socket_setnfds(nfds, fd4);
	}
#endif
#ifdef HAVE_RXIF6
      if(socket_isvalid(fd6))
	{
	  FD_SET(fd6, &rfds);
	  nfds = socket_setnfds(nfds, fd6);
	}
#endif

      if((count = select(nfds+1, &rfds, NULL, NULL, NULL)) == 0)
	continue;
      gettimeofday_wrap(&now);

      if(count < 0)
	{
	  if(errno == EINTR || errno == EAGAIN)
	    continue;
	  rxifd_error(__func__, "select failed: %s", strerror(errno));
	  return -1;
	}

#ifdef HAVE_RXIF4
      if(socket_isvalid(fd4) && FD_ISSET(fd4, &rfds))
	udp4_handle();
#endif
#ifdef HAVE_RXIF6
      if(socket_isvalid(fd6) && FD_ISSET(fd6, &rfds))
	udp6_handle();
#endif
    }

  return 0;
}

#ifdef HAVE_SIGNAL
static void rxifd_sigint(int signo)
{
  if(signo == SIGINT || signo == SIGTERM || signo == SIGHUP)
    stop = 1;
  return;
}
#endif /* HAVE_SIGNAL */

static void cleanup(void)
{
  if(name != NULL)
    {
      free(name);
      name = NULL;
    }
#ifdef HAVE_RXIF4
  if(socket_isvalid(fd4))
    {
      socket_close(fd4);
      fd4 = socket_invalid();
    }
#endif
#ifdef HAVE_RXIF6
  if(socket_isvalid(fd6))
    {
      socket_close(fd6);
      fd6 = socket_invalid();
    }
#endif
  return;
}

static int rxifd(int argc, char *argv[])
{
  int rc = -1;

#if defined(DMALLOC)
  free(malloc(1));
#endif

  if(check_options(argc, argv) != 0)
    goto done;

#ifdef OPT_VERSION
  if(options & OPT_VERSION)
    {
      printf("sc_rxifd version %s\n", PACKAGE_VERSION);
      return 0;
    }
#endif

#ifdef OPT_DAEMON
  /*
   * daemon:
   *  - first param: do not chdir /
   *  - second param: redirect stdio to /dev/null
   */
  if((options & OPT_DAEMON) != 0 && daemon(1, 0) != 0)
    {
      rxifd_error(__func__, "could not become daemon: %s", strerror(errno));
      goto done;
    }
#endif

  gettimeofday_wrap(&now);

#ifdef HAVE_RXIF4
  if(udp4_open() != 0)
    goto done;
  #endif
#ifdef HAVE_RXIF6
  if(udp6_open() != 0)
    goto done;
#endif

#ifdef HAVE_SIGNAL
  if(signal(SIGINT, rxifd_sigint) == SIG_ERR ||
     signal(SIGHUP, rxifd_sigint) == SIG_ERR ||
     signal(SIGTERM, rxifd_sigint) == SIG_ERR)
    goto done;
#endif

#ifdef HAVE_UNVEIL
  /* we don't need any files in file system */
  if(unveil(NULL, NULL) != 0)
    {
      rxifd_error(__func__, "could not do final unveil: %s", strerror(errno));
      goto done;
    }
#endif

#ifdef HAVE_PLEDGE
  if(pledge("stdio inet", NULL) != 0)
    {
      rxifd_error(__func__, "could not pledge stdio inet: %s",
		  strerror(errno));
      goto done;
    }
#endif

  pps_sec = now.tv_sec;
  rc = select_loop();

 done:
  cleanup();
  return rc;
}
#endif

int main(int argc, char *argv[])
{
#if defined(HAVE_RXIF4) || defined(HAVE_RXIF6)
  return rxifd(argc, argv);
#else
  fprintf(stderr, "this platform does not have necessary socket support.\n");
  return -1;
#endif
}
