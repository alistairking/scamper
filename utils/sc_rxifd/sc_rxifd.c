/*
 * sc_rxifd: reply to query with received interface name
 *
 * $Id: sc_rxifd.c,v 1.32 2026/06/10 06:04:50 mjl Exp $
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
#endif /* HAVE_CONFIG_H */
#include "internal.h"

#include "utils.h"
#include "mjl_list.h"

#if defined(HAVE_OSSL_QUIC_SERVER_METHOD) && !defined(TEST_RXIFD_H3_REQUEST)
#define HAVE_QUIC
#include "utils_tls.h"
#endif /* HAVE_OSSL_QUIC_SERVER_METHOD and not TEST_RXIFD_H3_REQUEST */

#if defined(HAVE_QUIC) || defined(TEST_RXIFD_H3_REQUEST)
#include "mjl_huffman.h"
#include "sc_rxifd.h"
#endif /* HAVE_QUIC or TEST_RXIFD_H3_REQUEST */

#ifndef TEST_RXIFD_H3_REQUEST
#if defined(IP_PKTINFO) || \
  (defined(IP_RECVIF) && defined(IP_RECVDSTADDR) && defined(IP_SENDSRCADDR))
#define HAVE_RXIF4
#endif /* IP_PKTINFO or (IP_RECVIF, IP_RECVDSTADDR, IP_SENDSRCADDR) */

#if defined(IPV6_PKTINFO)
#define HAVE_RXIF6
#endif /* IPV6_PKTINFO */

#if defined(HAVE_RXIF4) || defined(HAVE_RXIF6)
#define HAVE_RXIF
#endif /* HAVE_RXIF4 or HAVE_RXIF6 */
#endif /* not TEST_RXIFD_H3_REQUEST */

#ifdef HAVE_RXIF
#define OPT_HELP        0x0001
#define OPT_DNS_PORT    0x0002
#define OPT_DNS_NAME    0x0004
#define OPT_PPS         0x0008

#ifdef HAVE_QUIC
#define OPT_QUIC_PORT   0x0010
#define OPT_CERT        0x0020
#define OPT_KEY         0x0040
#define OPT_URL         0x0080
#endif /* HAVE_QUIC */

#if defined(HAVE_CHROOT) && defined(HAVE_SETEUID) && !defined(HAVE_UNVEIL)
#define OPT_CHROOT      0x0800
#endif /* HAVE_CHROOT, HAVE_SETEUID, and not HAVE_UNVEIL */

#ifdef HAVE_RXIF4
#define OPT_IPV4        0x1000
#endif /* HAVE_RXIF4 */
#ifdef HAVE_RXIF6
#define OPT_IPV6        0x2000
#endif /* HAVE_RXIF6 */
#ifdef HAVE_DAEMON
#define OPT_DAEMON      0x4000
#endif /* HAVE_DAEMON */
#ifdef PACKAGE_VERSION
#define OPT_VERSION     0x8000
#endif /* PACKAGE_VERSION */

#define OPT_ALL         0xFFFF

static uint32_t        options   = 0;
static uint16_t        dns_port  = 0;
static char           *dns_name  = NULL;
static struct timeval  now;
static volatile sig_atomic_t stop = 0;
static int             in_loop   = 0;
static int             pps       = 100;
static int             pps_cur   = 0;
static time_t          pps_sec   = 0;
#ifdef OPT_CHROOT
static char           *chroot_dir = NULL;
#endif /* OPT_CHROOT */
#ifdef HAVE_RXIF4
static int             dns4      = socket_invalid();
#endif /* HAVE_RXIF4 */
#ifdef HAVE_RXIF6
static int             dns6      = socket_invalid();
#endif /* HAVE_RXIF6 */

#ifdef HAVE_QUIC
static uint16_t        quic_port  = 0;
static char           *certfile   = NULL;
static char           *keyfile    = NULL;
static SSL_CTX        *tls_ctx    = NULL;
static SSL            *quic_ssl   = NULL;
static BIO            *rbio       = NULL;
static BIO            *wbio       = NULL;
static dlist_t        *quic_conns = NULL;
static volatile sig_atomic_t reload = 0;
#ifdef HAVE_RXIF4
static int             quic4     = socket_invalid();
#endif /* HAVE_RXIF4 */
#ifdef HAVE_RXIF6
static int             quic6     = socket_invalid();
#endif /* HAVE_RXIF6 */
#endif /* HAVE_QUIC */
#endif /* HAVE_RXIF */

#if defined(HAVE_QUIC)
static char           *quic_url         = NULL;
static size_t          quic_urllen      = 0;
static huffman_t      *quic_huff        = NULL;
static size_t          quic_hdr_maxsize = 8192;
#elif defined(TEST_RXIFD_H3_REQUEST)
extern char           *quic_url;
extern size_t          quic_urllen;
extern huffman_t      *quic_huff;
extern size_t          quic_hdr_maxsize;
#endif /* HAVE_QUIC or TEST_RXIFD_H3_REQUEST */

#if defined(HAVE_QUIC)
typedef struct sc_quicconn
{
  SSL                 *ssl;
  dlist_t             *streams;
  dlist_node_t        *dn;
  SSL                 *uni[3];
  uint8_t              h3_setup_step;
} sc_quicconn_t;
#endif /* HAVE_QUIC */

#ifdef HAVE_RXIF
static void usage(uint32_t opt_mask)
{
  fprintf(stderr, "sc_rxifd [-?"
#ifdef OPT_IPV4
	  "4"
#endif /* OPT_IPV4 */
#ifdef OPT_IPV6
	  "6"
#endif /* OPT_IPV6 */
#ifdef OPT_DAEMON
	  "D"
#endif /* OPT_DAEMON */
#ifdef OPT_VERSION
	  "v"
#endif /* OPT_VERSION */
	  "]"
#ifdef OPT_CHROOT
	  " [-R chroot-dir]"
#endif /* OPT_CHROOT */
	  "\n         [-P dns-port] [-n dns-name] [-p dns-pps]"
#ifdef HAVE_QUIC
	  "\n         [-Q h3-port] [-U h3-url] [-c certfile] [-k keyfile]"
#endif /* HAVE_QUIC */
	  "\n\n");

  if(opt_mask == 0)
    return;

#ifdef OPT_IPV4
  if(opt_mask & OPT_IPV4)
    fprintf(stderr, "     -4 only listen for connections over IPv4\n");
#endif /* OPT_IPV4 */

#ifdef OPT_IPV6
  if(opt_mask & OPT_IPV6)
    fprintf(stderr, "     -6 only listen for connections over IPv6\n");
#endif /* OPT_IPV6 */

#ifdef OPT_DAEMON
  if(opt_mask & OPT_DAEMON)
    fprintf(stderr, "     -D operate as a daemon\n");
#endif /* OPT_DAEMON */

  if(opt_mask & OPT_DNS_PORT)
    fprintf(stderr, "     -P port to listen on for DNS TXT queries\n");

  if(opt_mask & OPT_DNS_NAME)
    fprintf(stderr, "     -n name to answer DNS TXT queries for\n");

  if(opt_mask & OPT_PPS)
    fprintf(stderr, "     -p DNS responses per second allowed\n");

#ifdef OPT_CHROOT
  if(opt_mask & OPT_CHROOT)
    fprintf(stderr, "     -R directory to chroot into\n");
#endif /* OPT_CHROOT */

#ifdef HAVE_QUIC
  if(opt_mask & OPT_QUIC_PORT)
    fprintf(stderr, "     -Q UDP port to listen on for HTTP/3 clients\n");

  if(opt_mask & OPT_URL)
    fprintf(stderr, "     -U URL to answer for HTTP/3 clients\n");

  if(opt_mask & OPT_CERT)
    fprintf(stderr, "     -c PEM file with the server certificate chain\n");

  if(opt_mask & OPT_KEY)
    fprintf(stderr, "     -k PEM file with the server private key\n");
#endif /* HAVE_QUIC */

#ifdef OPT_VERSION
  if(opt_mask & OPT_VERSION)
    fprintf(stderr, "     -v display version and exit\n");
#endif /* OPT_VERSION */

  return;
}
#endif /* HAVE_RXIF */

#ifdef HAVE_RXIF
static int check_options(int argc, char *argv[])
{
  char *opts = "?"
#ifdef OPT_IPV4
    "4"
#endif /* OPT_IPV4 */
#ifdef OPT_IPV6
    "6"
#endif /* OPT_IPV6 */
#ifdef OPT_DAEMON
    "D"
#endif /* OPT_DAEMON */
    "n:p:P:"
#ifdef OPT_CHROOT
    "R:"
#endif /* OPT_CHROOT */
#ifdef HAVE_QUIC
    "Q:U:c:k:"
#endif /* HAVE_QUIC */
#ifdef OPT_VERSION
    "v"
#endif /* OPT_VERSION */
    ;
  char *opt_dns_port = NULL, *opt_name = NULL, *opt_pps = NULL;
#ifdef HAVE_QUIC
  char *opt_quic_port = NULL, *opt_cert = NULL, *opt_key = NULL;
  char *opt_url = NULL;
#endif /* HAVE_QUIC */
  long lo;
  int ch;
  int transport = 0;
  uint32_t mask;

#ifdef OPT_CHROOT
  struct stat sb;
#endif /* OPT_CHROOT */

  while((ch = getopt(argc, argv, opts)) != -1)
    {
      switch(ch)
	{
#ifdef OPT_IPV4
	case '4':
	  options |= OPT_IPV4;
	  break;
#endif /* OPT_IPV4 */

#ifdef OPT_IPV6
	case '6':
	  options |= OPT_IPV6;
	  break;
#endif /* OPT_IPV6 */

#ifdef OPT_DAEMON
	case 'D':
	  options |= OPT_DAEMON;
	  break;
#endif /* OPT_DAEMON */

	case 'n':
	  options |= OPT_DNS_NAME;
	  opt_name = optarg;
	  break;

	case 'p':
	  options |= OPT_PPS;
	  opt_pps = optarg;
	  break;

	case 'P':
	  options |= OPT_DNS_PORT;
	  opt_dns_port = optarg;
	  break;

#ifdef OPT_CHROOT
	case 'R':
	  chroot_dir = optarg;
	  break;
#endif /* OPT_CHROOT */

#ifdef HAVE_QUIC
	case 'Q':
	  options |= OPT_QUIC_PORT;
	  opt_quic_port = optarg;
	  break;

	case 'U':
	  options |= OPT_URL;
	  opt_url = optarg;
	  break;

	case 'c':
	  options |= OPT_CERT;
	  opt_cert = optarg;
	  break;

	case 'k':
	  options |= OPT_KEY;
	  opt_key = optarg;
	  break;
#endif /* HAVE_QUIC */

#ifdef OPT_VERSION
	case 'v':
	  options |= OPT_VERSION;
	  return 0;
#endif /* OPT_VERSION */

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

#if defined(OPT_IPV4) && defined(OPT_IPV6)
  if(countbits32(options & (OPT_IPV4|OPT_IPV6)) == 2)
    {
      usage(OPT_IPV4|OPT_IPV6);
      return -1;
    }
#endif /* OPT_IPV4 and OPT_IPV6 */

  /* if any of -n/-p/-P is specified, all are required */
  if(opt_dns_port != NULL || opt_name != NULL || opt_pps != NULL)
    {
      if((mask = (~options & (OPT_DNS_PORT|OPT_DNS_NAME|OPT_PPS))) != 0)
	{
	  usage(mask);
	  return -1;
	}
      assert(opt_dns_port != NULL);
      assert(opt_name != NULL);
      assert(opt_pps != NULL);

      if(string_tolong(opt_dns_port, &lo) != 0 || lo < 1 || lo > UINT16_MAX)
	{
	  usage(OPT_DNS_PORT);
	  return -1;
	}
      dns_port = (uint16_t)lo;

      if(strlen(opt_name) >= 255 || (dns_name = strdup(opt_name)) == NULL)
	{
	  usage(OPT_DNS_NAME);
	  return -1;
	}

      if(string_tolong(opt_pps, &lo) != 0 || lo < 0)
	{
	  usage(OPT_PPS);
	  return -1;
	}
      pps = (int)lo;

      transport = 1;
    }

#ifdef HAVE_QUIC
  /* if any of -Q/-c/-k/-U is specified, all are required */
  if(opt_quic_port != NULL || opt_cert != NULL || opt_key != NULL ||
     opt_url != NULL)
    {
      if((mask = (~options & (OPT_QUIC_PORT|OPT_CERT|OPT_KEY|OPT_URL))) != 0)
	{
	  usage(mask);
	  return -1;
	}
      assert(opt_quic_port != NULL);
      assert(opt_cert != NULL);
      assert(opt_key != NULL);
      assert(opt_url != NULL);

      if(opt_url[0] != '/')
	{
	  usage(OPT_URL);
	  fprintf(stderr, "path must begin with /\n");
	  return -1;
	}
      if(strlen(opt_url) >= 128)
	{
	  usage(OPT_URL);
	  fprintf(stderr, "path length limited to 128 characters\n");
	  return -1;
	}

      if(string_tolong(opt_quic_port, &lo) != 0 || lo < 1 || lo > UINT16_MAX)
	{
	  usage(OPT_QUIC_PORT);
	  return -1;
	}
      quic_port = (uint16_t)lo;

      if((options & OPT_DNS_PORT) != 0 && quic_port == dns_port)
	{
	  usage(OPT_QUIC_PORT|OPT_DNS_PORT);
	  fprintf(stderr, "DNS and HTTP/3 must operate on different ports\n");
	  return -1;
	}

      if((certfile = strdup(opt_cert)) == NULL)
	{
	  usage(OPT_CERT);
	  return -1;
	}

      if((keyfile = strdup(opt_key)) == NULL)
	{
	  usage(OPT_KEY);
	  return -1;
	}

      if((quic_url = strdup(opt_url)) == NULL)
	{
	  usage(OPT_URL);
	  return -1;
	}
      quic_urllen = strlen(quic_url);

      transport = 1;
    }
#endif /* HAVE_QUIC */

  if(transport == 0)
    {
      usage(0);
      return -1;
    }

#ifdef OPT_CHROOT
  if(chroot_dir != NULL)
    {
      if(stat(chroot_dir, &sb) != 0)
	{
	  usage(OPT_CHROOT);
	  fprintf(stderr, "stat failed %s: %s\n", chroot_dir, strerror(errno));
	  return -1;
	}
      if(S_ISDIR(sb.st_mode) == 0)
	{
	  usage(OPT_CHROOT);
	  fprintf(stderr, "%s is not a directory\n", chroot_dir);
	  return -1;
	}
    }
#endif /* OPT_CHROOT */

  return 0;
}
#endif /* HAVE_RXIF */

#ifdef HAVE_RXIF
static void rxifd_stderr(const char *func, const char *format, va_list ap)
{
  char message[512], ts[16];

#ifdef OPT_DAEMON
  if(options & OPT_DAEMON)
    return;
#endif /* OPT_DAEMON */

  vsnprintf(message, sizeof(message), format, ap);

  if(in_loop != 0)
    fprintf(stderr, "[%s] ", timeval_tostr_hhmmssms(&now, ts));
  fprintf(stderr, "%s: %s\n", func, message);
  fflush(stderr);

  return;
}
#endif /* HAVE_RXIF */

#ifdef HAVE_RXIF
#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
static void rxifd_error(const char *func, const char *format, ...)
  __attribute__((format(printf, 2, 3)));
#endif /* HAVE_FUNC_ATTRIBUTE_FORMAT */
static void rxifd_error(const char *func, const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  rxifd_stderr(func, format, ap);
  va_end(ap);

  return;
}
#endif /* HAVE_RXIF */

#ifdef HAVE_RXIF6
#ifndef _WIN32 /* SOCKET vs int on windows */
static int udp6_open(uint16_t port)
#else
static SOCKET udp6_open(uint16_t port)
#endif /* _WIN32 */
{
  struct sockaddr_in6 sin6;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd = -1;
#else
  SOCKET fd = INVALID_SOCKET;
#endif /* _WIN32 */

  fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if(socket_isinvalid(fd))
    {
      rxifd_error(__func__, "could not open udp6 socket: %s", strerror(errno));
      goto err;
    }

  if(fcntl_set(fd, O_NONBLOCK) == -1)
    {
      rxifd_error(__func__, "could not set O_NONBLOCK: %s", strerror(errno));
      goto err;
    }

#ifdef IPV6_V6ONLY
  if(setsockopt_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1) != 0)
    {
      rxifd_error(__func__, "could not set IPV6_V6ONLY on udp6: %s",
		  strerror(errno));
      goto err;
    }
#endif /* IPV6_V6ONLY */

  sockaddr_compose((struct sockaddr *)&sin6, AF_INET6, NULL, port);
  if(bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) != 0)
    {
      rxifd_error(__func__, "could not bind udp6 port %u: %s", port,
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
#endif /* IPV6_RECVPKTINFO or IPV6_PKTINFO */

  return fd;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  return socket_invalid();
}

static int udp6_recv(
#ifndef _WIN32 /* SOCKET vs int on windows */
		     int fd,
#else
		     SOCKET fd,
#endif /* _WIN32 */
		     uint8_t *rxbuf, size_t rxbuflen, size_t *rxlen,
		     struct in6_addr *us, struct sockaddr_in6 *them,
		     unsigned int *ifindex)
{
  uint8_t ctrlbuf[256];
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct iovec iov;
  ssize_t rrc;
  int gotifindex = 0;

#if defined(IPV6_PKTINFO)
  struct in6_pktinfo *pi;
#endif /* IPV6_PKTINFO */

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (void *)rxbuf;
  iov.iov_len  = rxbuflen;

  memset(&msg, 0, sizeof(msg));
  msg.msg_name       = (void *)them;
  msg.msg_namelen    = sizeof(struct sockaddr_in6);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (void *)ctrlbuf;
  msg.msg_controllen = sizeof(ctrlbuf);

  if((rrc = recvmsg(fd, &msg, 0)) < 0)
    return -1;
  *rxlen = (size_t)rrc;
  
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
	      *ifindex = pi->ipi6_ifindex;
	      memcpy(us, &pi->ipi6_addr, sizeof(struct in6_addr));
	      gotifindex = 2;
	      break;
	    }
#endif /* IPV6_PKTINFO */
	  cmsg = (struct cmsghdr *)CMSG_NXTHDR(&msg, cmsg);
	}
    }

  return gotifindex;
}

static int udp6_send(
#ifndef _WIN32 /* SOCKET vs int on windows */
		     int fd,
#else
		     SOCKET fd,
#endif /* _WIN32 */
		     uint8_t *txbuf, size_t txlen,
		     struct in6_addr *us, struct sockaddr_in6 *them)
{
  uint8_t ctrlbuf[256];
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct iovec iov;

#if defined(IPV6_PKTINFO)
  struct in6_pktinfo pibuf;
#endif /* IPV6_PKTINFO */

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (void *)txbuf;
  iov.iov_len  = txlen;

  memset(&msg, 0, sizeof(msg));
  msg.msg_name       = (void *)them;
  msg.msg_namelen    = sizeof(struct sockaddr_in6);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (void *)ctrlbuf;

#if defined(IPV6_PKTINFO)
  msg.msg_controllen = CMSG_SPACE(sizeof(pibuf));
  memset(&pibuf, 0, sizeof(pibuf));
  memcpy(&pibuf.ipi6_addr, us, sizeof(struct in6_addr));
  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_len = CMSG_LEN(sizeof(pibuf));
  cmsg->cmsg_level = IPPROTO_IPV6;
  cmsg->cmsg_type = IPV6_PKTINFO;
  memcpy(CMSG_DATA(cmsg), &pibuf, sizeof(pibuf));
#endif /* IPV6_PKTINFO */

  if(sendmsg(fd, &msg, 0) == -1)
    {
      rxifd_error(__func__, "could not send response: %s", strerror(errno));
      return -1;
    }

  return 0;
}
#endif /* HAVE_RXIF6 */

#ifdef HAVE_RXIF4
#ifndef _WIN32 /* SOCKET vs int on windows */
static int udp4_open(uint16_t port)
#else
static SOCKET udp4_open(uint16_t port)
#endif /* _WIN32 */
{
  struct sockaddr_in sin4;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif /* _WIN32 */

  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if(socket_isinvalid(fd))
    {
      rxifd_error(__func__, "could not open udp4 socket: %s", strerror(errno));
      goto err;
    }

  if(fcntl_set(fd, O_NONBLOCK) == -1)
    {
      rxifd_error(__func__, "could not set O_NONBLOCK: %s", strerror(errno));
      goto err;
    }

  if(setsockopt_int(fd, SOL_SOCKET, SO_REUSEADDR, 1) != 0)
    {
      rxifd_error(__func__, "could not set SO_REUSEADDR on udp4: %s",
		  strerror(errno));
      goto err;
    }

  sockaddr_compose((struct sockaddr *)&sin4, AF_INET, NULL, port);
  if(bind(fd, (struct sockaddr *)&sin4, sizeof(sin4)) == -1)
    {
      rxifd_error(__func__, "could not bind udp4 port %u: %s", port,
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
#endif /* IP_RECVPKTINFO, IP_PKTINFO, IP_RECVIF, IP_RECVDSTADDR */

  return fd;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  return socket_invalid();
}

static int udp4_recv(
#ifndef _WIN32 /* SOCKET vs int on windows */
		     int fd,
#else
		     SOCKET fd,
#endif /* _WIN32 */
		     uint8_t *rxbuf, size_t rxbuflen, size_t *rxlen,
		     struct in_addr *us, struct sockaddr_in *them,
		     unsigned int *ifindex)
{
  uint8_t ctrlbuf[256];
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct iovec iov;
  ssize_t rrc;
  int gotifindex = 0, gotaddr = 0;

#if defined(IP_PKTINFO)
  struct in_pktinfo *pi;
#elif defined(IP_RECVIF) && defined(IP_RECVDSTADDR)
  struct sockaddr_dl *sdl;
  struct in_addr *ip4;
#endif /* IP_PKTINFO, IP_RECVIF, IP_RECVDSTADDR */

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (void *)rxbuf;
  iov.iov_len  = rxbuflen;

  memset(&msg, 0, sizeof(msg));
  msg.msg_name       = (void *)them;
  msg.msg_namelen    = sizeof(struct sockaddr_in);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (void *)ctrlbuf;
  msg.msg_controllen = sizeof(ctrlbuf);

  if((rrc = recvmsg(fd, &msg, 0)) < 0)
    return -1;
  *rxlen = (size_t)rrc;

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
	      *ifindex = pi->ipi_ifindex;
	      memcpy(us, &pi->ipi_addr, sizeof(struct in_addr));
	      gotifindex = 1;
	      gotaddr = 1;
	    }
#elif defined(IP_RECVIF) && defined(IP_RECVDSTADDR)
	  if(cmsg->cmsg_level == IPPROTO_IP &&
	     cmsg->cmsg_type == IP_RECVIF)
	    {
	      sdl = (struct sockaddr_dl *)CMSG_DATA(cmsg);
	      *ifindex = sdl->sdl_index;
	      gotifindex = 1;
	    }
	  else if(cmsg->cmsg_level == IPPROTO_IP &&
		  cmsg->cmsg_type == IP_RECVDSTADDR)
	    {
	      ip4 = (struct in_addr *)CMSG_DATA(cmsg);
	      memcpy(us, ip4, sizeof(struct in_addr));
	      gotaddr = 1;
	    }
#endif /* IP_PKTINFO, IP_RECVIF, IP_RECVDSTADDR */
	  if(gotifindex && gotaddr)
	    break;
	  cmsg = (struct cmsghdr *)CMSG_NXTHDR(&msg, cmsg);
	}
    }

  return gotifindex + gotaddr;
}

static int udp4_send(
#ifndef _WIN32 /* SOCKET vs int on windows */
		     int fd,
#else
		     SOCKET fd,
#endif /* _WIN32 */
		     uint8_t *txbuf, size_t txlen,
		     struct in_addr *us, struct sockaddr_in *them)
{
  uint8_t ctrlbuf[256];
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct iovec iov;

#if defined(IP_PKTINFO)
  struct in_pktinfo pibuf;
#endif /* IP_PKTINFO */

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = (void *)txbuf;
  iov.iov_len  = txlen;

  memset(&msg, 0, sizeof(msg));
  msg.msg_name       = (void *)them;
  msg.msg_namelen    = sizeof(struct sockaddr_in);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = (void *)ctrlbuf;

#if defined(IP_PKTINFO)
  msg.msg_controllen = CMSG_SPACE(sizeof(pibuf));
  memset(&pibuf, 0, sizeof(pibuf));
  memcpy(&pibuf.ipi_spec_dst, us, sizeof(struct in_addr));
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
  memcpy(CMSG_DATA(cmsg), us, sizeof(struct in_addr));
#endif /* IP_PKTINFO, IP_RECVDSTADDR */

  if(sendmsg(fd, &msg, 0) == -1)
    {
      rxifd_error(__func__, "could not send response: %s", strerror(errno));
      return -1;
    }

  return 0;
}
#endif /* HAVE_RXIF4 */

#ifdef HAVE_RXIF
static size_t is_valid_query(const uint8_t *rxbuf, size_t rrc)
{
  char qname[256];
  size_t qoff = 0, off, label_len;

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
	  if(qoff > 0)
	    qoff--;
	  qname[qoff] = '\0';
	  break;
	}
      if(rrc - off < label_len || sizeof(qname) - qoff <= label_len)
	return 0;
      memcpy(qname+qoff, rxbuf+off, label_len);
      off += label_len;
      qoff += label_len;
      qname[qoff++] = '.';
    }

  /* check qname is expected */
  if(strcasecmp(dns_name, qname) != 0)
    return 0;

  /* need qtype, qclass */
  if(rrc - off < 4 ||
     bytes_ntohs(rxbuf+off) != 16 || /* qtype = TXT */
     bytes_ntohs(rxbuf+off+2) != 1)  /* qtype = IN */
    return 0;
  off += 4;

  return off - 12;  
}
#endif /* HAVE_RXIF */

#ifdef HAVE_RXIF
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
#endif /* HAVE_RXIF */

#ifdef HAVE_RXIF4
static void dns4_handle(void)
{
  struct sockaddr_in them;
  struct in_addr us;
  uint8_t rxbuf[8192], txbuf[512];
  size_t txlen, rxlen;
  unsigned int ifindex = 0;

  if(udp4_recv(dns4, rxbuf, sizeof(rxbuf), &rxlen, &us, &them, &ifindex) != 2)
    return;

  if((txlen = build_tx((struct sockaddr *)&them, ifindex, rxbuf, rxlen,
		       txbuf, sizeof(txbuf))) == 0)
    return;

  udp4_send(dns4, txbuf, txlen, &us, &them);

  pps_cur++;
  return;
}
#endif /* HAVE_RXIF4 */

#ifdef HAVE_RXIF6
static void dns6_handle(void)
{
  struct sockaddr_in6 them;
  struct in6_addr us;
  uint8_t rxbuf[8192], txbuf[512];
  size_t rxlen, txlen;
  unsigned int ifindex = 0;

  if(udp6_recv(dns6, rxbuf, sizeof(rxbuf), &rxlen, &us, &them, &ifindex) != 2)
    return;

  if((txlen = build_tx((struct sockaddr *)&them, ifindex, rxbuf, rxlen,
		       txbuf, sizeof(txbuf))) == 0)
    return;

  udp6_send(dns6, txbuf, txlen, &us, &them);

  pps_cur++;
  return;
}
#endif /* HAVE_RXIF6 */

#if defined(HAVE_QUIC) || defined(TEST_RXIFD_H3_REQUEST)
static int qpack_prefixint_decode(const uint8_t *buf, size_t len, size_t *off,
				  int n, uint64_t *val)
{
  uint64_t mask = (1ULL << n) - 1ULL;
  uint64_t v;
  unsigned int m = 0;
  uint8_t b;
  size_t o = *off;

  if(len <= o)
    return -1;

  v = (uint64_t)(buf[o++] & mask);
  if(v < mask)
    goto done;

  do
    {
      if(len - o < 1)
	return -1;
      b = buf[o++];
      v += ((uint64_t)(b & 0x7F)) << m;
      m += 7;
      if(m > 63)
	return -1;
    }
  while(b & 0x80);

 done:
  *off = o;
  *val = v;
  return 0;
}

static int qpack_prefixint_decode_assize(const uint8_t *buf, size_t len,
					size_t *off, int n, size_t *val)
{
  uint64_t val_tmp;
  size_t off_tmp = *off;
  if(qpack_prefixint_decode(buf, len, &off_tmp, n, &val_tmp) == 0 &&
     val_tmp <= SIZE_MAX)
    {
      *off = off_tmp;
      *val = (size_t)val_tmp;
      return 0;
    }
  return -1;
}

/*
 * qpack_find_path:
 *
 * decode a QPACK-encoded header block looking only for the path
 * header.  returns 1 if found, 0 otherwise.
 */
static int qpack_find_path(const uint8_t *buf, size_t len,
			   uint8_t *path, size_t path_len)
{
  size_t off = 0, name_off, path_off, val_len, name_len;
  int looking, huff, t, hname;
  uint64_t v, name_index;
  char name[64];
  uint8_t b;

  assert(path_len > 0);

  /* prefix: required-insert-count (N=8), sign+delta-base (N=7) */
  if(qpack_prefixint_decode(buf, len, &off, 8, &v) != 0 ||
     qpack_prefixint_decode(buf, len, &off, 7, &v) != 0)
    return 0;

  while(off < len)
    {
      b = buf[off];
      looking = 0;
      if(b & 0x80)
	{
	  /* indexed field line: 1Tiiiiii */
	  t = (b >> 6) & 1;
	  if(qpack_prefixint_decode(buf, len, &off, 6, &v) != 0)
	    return 0;
	  /*
	   * QPACK static[1] is ":path: /" -- the only static entry
	   * whose name is :path. emit "/" if we hit it.
	   */
	  if(t == 1 && v == 1)
	    {
	      if(path_len < 2)
		return 0;
	      path[0] = '/';
	      path[1] = '\0';
	      return 1;
	    }
	}
      else if((b & 0xC0) == 0x40)
	{
	  /* literal field line with name reference: 01NTiiii */
	  t = (b >> 4) & 1;
	  if(qpack_prefixint_decode(buf, len, &off, 4, &name_index) != 0 ||
	     off >= len)
	    return 0;
	  if(t == 1 && name_index == 1)
	    looking = 1;
	  huff = (buf[off] >> 7) & 1;
	  if(qpack_prefixint_decode_assize(buf, len, &off, 7, &val_len) != 0 ||
	     val_len > len - off)
	    return 0;
	  if(looking)
	    {
	      if(huff)
		{
		  path_off = 0;
		  if(huffman_decode(quic_huff, buf+off, val_len,
				    path, &path_off, path_len - 1) != 0)
		    return 0;
		}
	      else
		{
		  if(val_len >= path_len) /* val_len + 1 > path_len */
		    return 0;
		  path_off = val_len;
		  memcpy(path, buf + off, path_off);
		}
	      path[path_off] = '\0';
	      return 1;
	    }
	  off += val_len;
	}
      else if((b & 0xE0) == 0x20)
	{
	  /* literal field line with literal name: 001NHsss */
	  hname = (b >> 3) & 1;
	  name_off = 0;
	  if(qpack_prefixint_decode_assize(buf, len, &off, 3, &name_len) != 0 ||
	     name_len >= len - off) /* name_len + 1 > len - off */
	    return 0;
	  if(hname)
	    {
	      if(huffman_decode(quic_huff, buf+off, name_len,
				(uint8_t *)name, &name_off, sizeof(name)) != 0)
		return 0;
	    }
	  else if(name_len < sizeof(name))
	    {
	      memcpy(name, buf + off, name_len);
	      name_off = name_len;
	    }
	  off += name_len;
	  if(name_off == 5 && memcmp(name, ":path", 5) == 0)
	    looking = 1;
	  huff = (buf[off] >> 7) & 1;
	  if(qpack_prefixint_decode_assize(buf, len, &off, 7, &val_len) != 0 ||
	     val_len > len - off)
	    return 0;
	  if(looking)
	    {
	      if(huff)
		{
		  path_off = 0;
		  if(huffman_decode(quic_huff, buf+off, val_len,
				    path, &path_off, path_len - 1) != 0)
		    return 0;
		}
	      else
		{
		  if(val_len >= path_len) /* val_len + 1 > path_len */
		    return 0;
		  path_off = val_len;
		  memcpy(path, buf + off, path_off);
		}
	      path[path_off] = '\0';
	      return 1;
	    }
	  off += val_len;
	}
      else
	{
	  /*
	   * indexed-with-post-base / literal-with-post-base: skip
	   * sufficiently to avoid getting stuck
	   */
	  if((b & 0xF0) == 0x10)
	    {
	      if(qpack_prefixint_decode(buf, len, &off, 4, &v) != 0)
		return 0;
	    }
	  else if((b & 0xF0) == 0x00)
	    {
	      if(qpack_prefixint_decode(buf, len, &off, 3, &v) != 0 ||
		 qpack_prefixint_decode_assize(buf,len,&off,7,&val_len) != 0 ||
		 val_len > len - off)
		return 0;
	      off += val_len;
	    }
	  else
	    {
	      return 0;
	    }
	}
    }
  return 0;
}

static int quic_varint_extract(const uint8_t *buf, size_t len, size_t *off, 
			       uint64_t *val)
{
  const uint8_t *ptr = buf + *off;
  size_t reqd_tbl[] = {1, 2, 4, 8}, reqd;
  uint8_t x;

  if(*off >= len)
    return -1;
  x = (uint8_t)(ptr[0] >> 6);
  if(len - *off < (reqd = reqd_tbl[x]))
    return -1;
  if(x == 0)
    *val = ptr[0];
  else if(x == 1)
    *val = bytes_ntohs(ptr) & 0x3FFFU;
  else if(x == 2)
    *val = bytes_ntohl(ptr) & 0x3FFFFFFFU;
  else
    *val = (((uint64_t)bytes_ntohl(ptr) & 0x3FFFFFFFU) << 32) | bytes_ntohl(ptr+4);
  (*off) += reqd;
  return 0;
}
#endif /* HAVE_QUIC or TEST_RXIFD_H3_REQUEST */

#ifdef HAVE_QUIC
static void quic_varint_insert(uint8_t *buf, size_t len, size_t *off,
			       uint64_t val)
{
  uint8_t *ptr = buf + *off;
  size_t reqd;

  assert(*off < len);

  if(val < 0x40U)
    {
      reqd = 1; assert(len - *off >= reqd);
      ptr[0] = (uint8_t)val;
    }
  else if(val < 0x4000U)
    {
      reqd = 2; assert(len - *off >= reqd);
      bytes_htons(ptr, (uint16_t)(val | 0x4000U));
    }
  else if(val < 0x40000000U)
    {
      reqd = 4; assert(len - *off >= reqd);
      bytes_htonl(ptr, (uint32_t)(val | 0x40000000U));
    }
  else
    {
      assert(val < 0x4000000000000000ULL);
      reqd = 8; assert(len - *off >= reqd);
      bytes_htonl(ptr+0, (uint32_t)((val >> 32) | 0xC0000000U));
      bytes_htonl(ptr+4, (uint32_t)val);
    }

  (*off) += reqd;
  return;
}

static BIO_ADDR *bioaddr_from_sockaddr(const struct sockaddr *sa)
{
  const struct sockaddr_in *sin;
  const struct sockaddr_in6 *sin6;
  BIO_ADDR *ba;

  if((ba = BIO_ADDR_new()) == NULL)
    return NULL;
  if(sa->sa_family == AF_INET)
    {
      sin = (const struct sockaddr_in *)sa;
      if(BIO_ADDR_rawmake(ba, AF_INET, &sin->sin_addr,
			  sizeof(sin->sin_addr), sin->sin_port) != 1)
	goto err;
    }
  else if(sa->sa_family == AF_INET6)
    {
      sin6 = (const struct sockaddr_in6 *)sa;
      if(BIO_ADDR_rawmake(ba, AF_INET6, &sin6->sin6_addr,
			  sizeof(sin6->sin6_addr), sin6->sin6_port) != 1)
	goto err;
    }
  else goto err;
  return ba;

 err:
  if(ba != NULL)
    BIO_ADDR_free(ba);
  return NULL;
}

static BIO_ADDR *bioaddr_from_bits(int af, const void *addr, uint16_t port)
{
  BIO_ADDR *ba = NULL;
  size_t addr_len;

  if(af == AF_INET) addr_len = sizeof(struct in_addr);
  else if(af == AF_INET6) addr_len = sizeof(struct in6_addr);
  else goto err;

  if((ba = BIO_ADDR_new()) == NULL ||
     BIO_ADDR_rawmake(ba, af, addr, addr_len, htons(port)) != 1)
    goto err;

  return ba;

 err:
  if(ba != NULL)
    BIO_ADDR_free(ba);
  return NULL;
}

static int sockaddr_from_bioaddr(const BIO_ADDR *ba, struct sockaddr *sa)
{
  int af = BIO_ADDR_family(ba);
  struct in_addr in;
  struct in6_addr in6;
  void *aptr;
  size_t len;

  if(af == AF_INET)
    {
      len = sizeof(in);
      if(BIO_ADDR_rawaddress(ba, &in, &len) != 1)
	return -1;
      aptr = &in;
    }
  else if(af == AF_INET6)
    {
      len = sizeof(in6);
      if(BIO_ADDR_rawaddress(ba, &in6, &len) != 1)
	return -1;
      aptr = &in6;
    }
  else return -1;

  sockaddr_compose(sa, af, aptr, ntohs(BIO_ADDR_rawport(ba)));
  return 0;
}

static void sc_quicstream_free(sc_quicstream_t *qs)
{
  if(qs->them != NULL)
    free(qs->them);
  if(qs->ssl != NULL)
    SSL_free(qs->ssl);
  if(qs->buf != NULL)
    free(qs->buf);
  free(qs);
  return;
}

static void sc_quicconn_free(sc_quicconn_t *qc)
{
  sc_quicstream_t *qs;
  int i;

  for(i=0; i<3; i++)
    if(qc->uni[i] != NULL)
      SSL_free(qc->uni[i]);      

  if(qc->streams != NULL)
    {
      while((qs = dlist_head_pop(qc->streams)) != NULL)
	sc_quicstream_free(qs);
      dlist_free(qc->streams);
    }

  if(qc->ssl != NULL)
    SSL_free(qc->ssl);

  free(qc);
  return;
}

static sc_quicconn_t *sc_quicconn_add(SSL *ssl)
{
  sc_quicconn_t *qc = NULL;
  if((qc = malloc_zero(sizeof(sc_quicconn_t))) == NULL ||
     (qc->streams = dlist_alloc()) == NULL ||
     (qc->dn = dlist_tail_push(quic_conns, qc)) == NULL)
    goto err;
  qc->ssl = ssl;
  return qc;

 err:
  if(qc != NULL) sc_quicconn_free(qc);
  return NULL;
}

static sc_quicstream_t *sc_quicconn_stream_add(sc_quicconn_t *qc, SSL *ssl,
					       BIO_ADDR *them,
					       unsigned int ifindex)
{
  struct sockaddr_storage sas;
  sc_quicstream_t *qs = NULL;
  int bidi = 0, sas_len = 0;

  if(SSL_get_stream_type(ssl) == SSL_STREAM_TYPE_BIDI)
    {
      bidi = 1;
      if(sockaddr_from_bioaddr(them, (struct sockaddr *)&sas) != 0)
	goto err;
      sas_len = sockaddr_len((struct sockaddr *)&sas);
    }

  if((qs = malloc_zero(sizeof(sc_quicstream_t))) == NULL ||
     (sas_len > 0 && (qs->them = memdup(&sas, sas_len)) == NULL) ||
     (qs->dn = dlist_tail_push(qc->streams, qs)) == NULL)
    goto err;
  qs->ssl = ssl;
  if(bidi != 0)
    qs->flags |= SC_QUICSTREAM_FLAG_BIDI;
  qs->ifindex = ifindex;
  gettimeofday_wrap(&qs->begin);

  return qs;

 err:
  if(qs != NULL) sc_quicstream_free(qs);
  return NULL;
}

static void quic_ssl_error(const char *func, const char *msg)
{
#ifdef OPT_DAEMON
  if(options & OPT_DAEMON)
    return;
#endif /* OPT_DAEMON */
  if(ERR_peek_error() != 0)
    {
      rxifd_error(func, "%s", msg);
      ERR_print_errors_fp(stderr);
    }
  return;
}

static int quic_select_alpn_cb(SSL *unused_ssl,
			       const unsigned char **out, unsigned char *outlen,
			       const unsigned char *in, unsigned int inlen,
			       void *arg)
{
  /* needs to be static to work */
  static const unsigned char alpn[] = {2, 'h', '3'};
  if(SSL_select_next_proto((unsigned char **)out, outlen, alpn, sizeof(alpn),
			   in, inlen) == OPENSSL_NPN_NEGOTIATED)
    return SSL_TLSEXT_ERR_OK;
  return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static int quic_load_certs(void)
{
  if(SSL_CTX_use_certificate_chain_file(tls_ctx, certfile) != 1)
    {
      quic_ssl_error(__func__, "could not load certificate chain");
      return -1;
    }
  if(SSL_CTX_use_PrivateKey_file(tls_ctx, keyfile, SSL_FILETYPE_PEM) != 1)
    {
      quic_ssl_error(__func__, "could not load private key");
      return -1;
    }
  if(SSL_CTX_check_private_key(tls_ctx) != 1)
    {
      quic_ssl_error(__func__, "private key does not match certificate");
      return -1;
    }
  return 0;
}

static int quic_init(void)
{
  huffman_entry_t qh[256] = RFC7541_DICT;

  if((quic_conns = dlist_alloc()) == NULL)
    {
      rxifd_error(__func__, "could not alloc quic_conns");
      return -1;
    }

  /*
   * huffman_alloc() processes the dictionary we store on the stack,
   * so subsequent use of quic_huff is correct.
   */
  if((quic_huff = huffman_alloc(qh)) == NULL)
    {
      rxifd_error(__func__, "could not alloc huffman");
      return -1;
    }

  SSL_library_init();
  SSL_load_error_strings();

  if((tls_ctx = SSL_CTX_new(OSSL_QUIC_server_method())) == NULL)
    {
      quic_ssl_error(__func__, "could not create SSL_CTX");
      return -1;
    }
  if(quic_load_certs() != 0)
    return -1;
  SSL_CTX_set_alpn_select_cb(tls_ctx, quic_select_alpn_cb, NULL);

  if((rbio = BIO_new(BIO_s_dgram_mem())) == NULL ||
     (wbio = BIO_new(BIO_s_dgram_mem())) == NULL)
    {
      quic_ssl_error(__func__, "could not create BIO_s_dgram_mem");
      return -1;
    }
  if(BIO_dgram_set_caps(rbio,
			BIO_DGRAM_CAP_HANDLES_DST_ADDR |
			BIO_DGRAM_CAP_PROVIDES_SRC_ADDR |
			BIO_DGRAM_CAP_HANDLES_SRC_ADDR |
			BIO_DGRAM_CAP_PROVIDES_DST_ADDR) != 1 ||
     BIO_dgram_set_caps(wbio,
			BIO_DGRAM_CAP_HANDLES_DST_ADDR |
			BIO_DGRAM_CAP_PROVIDES_SRC_ADDR |
			BIO_DGRAM_CAP_HANDLES_SRC_ADDR |
			BIO_DGRAM_CAP_PROVIDES_DST_ADDR) != 1)
    {
      quic_ssl_error(__func__, "could not set BIO_s_dgram_mem caps");
      return -1;
    }

  if(BIO_dgram_set_local_addr_enable(rbio, 1) != 1)
    {
      quic_ssl_error(__func__, "could not set local_addr_enable on rbio");
      return -1;
    }
  if(BIO_dgram_set_local_addr_enable(wbio, 1) != 1)
    {
      quic_ssl_error(__func__, "could not set local_addr_enable on wbio");
      return -1;
    }

  if((quic_ssl = SSL_new_listener(tls_ctx, 0)) == NULL)
    {
      quic_ssl_error(__func__, "could not create SSL listener");
      return -1;
    }
  SSL_set_bio(quic_ssl, rbio, wbio);

  if(SSL_set_blocking_mode(quic_ssl, 0) != 1)
    {
      quic_ssl_error(__func__, "could not set non-blocking");
      return -1;
    }

  if(SSL_listen(quic_ssl) != 1)
    {
      quic_ssl_error(__func__, "SSL_listen failed");
      return -1;
    }

  return 0;
}

static void quic_check_errors(const char *label)
{
  char ebuf[256];
  unsigned long e;

  while((e = ERR_get_error()) != 0)
    {
      if(BIO_err_is_non_fatal(e))
	continue;
      ERR_error_string_n(e, ebuf, sizeof(ebuf));
      rxifd_error(label, "%s", ebuf);
    }

  return;
}

static size_t quic_h3_reply_headers(uint8_t *buf, size_t len, int status,
				    uint8_t content_len)
{
  size_t off = 0, contentlen_off;

  assert(len > 10);

  buf[off++] = 0;
  buf[off++] = 0;

  if(status == 200)
    buf[off++] = (0xC0 | 25); /* :status 200 */
  else
    buf[off++] = (0xC0 | 27); /* :status 404 */

  buf[off++] = (0xC0 | 46);   /* content-type: application/json */
  buf[off++] = (0xC0 | 35);   /* access-control-allow-origin: * */

  buf[off++] = 0x54;          /* content-length: 0 */
  contentlen_off = off;
  off++;
  string_concat_u8((char *)buf, len, &off, NULL, content_len);
  buf[contentlen_off] = off - contentlen_off - 1;

  return off;
}

static size_t quic_h3_reply_content(char *buf, size_t len, sc_quicstream_t *qs)
{
  char ifname[IF_NAMESIZE], sastr[128], tmp[128];
  size_t off = 0;

  assert((qs->flags & SC_QUICSTREAM_FLAG_BIDI) != 0);
  assert(qs->them != NULL);

  if(if_indextoname(qs->ifindex, ifname) == NULL)
    ifname[0] = '\0';
  if(sockaddr_tostr(qs->them, sastr, sizeof(sastr), 0) == NULL)
    sastr[0] = '\0';
  string_concat2(buf, len, &off, "{\"rxif\":\"",
		 json_esc(ifname, tmp, sizeof(tmp)));
  string_concat3(buf, len, &off, "\",\"src\":\"", sastr, "\"}\n");

  return off;
}

static size_t quic_h3_reply_404(char *buf, size_t len)
{
  size_t off = 0;
  string_concat(buf, len, &off, "{\"error\":\"not found\"}\n");
  return off;
}

static void quic_h3_frame(uint8_t *buf, size_t len, size_t *off,
			  uint8_t type, const uint8_t *data, size_t data_len)
{
  quic_varint_insert(buf, len, off, type);
  quic_varint_insert(buf, len, off, data_len);
  if(data_len > 0)
    {
      memcpy(buf + (*off), data, data_len);
      (*off) += data_len;
    }
  return;
}

static int quic_h3_reply(sc_quicstream_t *qs, int status)
{
  uint8_t hdrs[32], frames[320];
  char    content[255];
  size_t  off = 0, hdrs_len, content_len, written;

  if(status == 200)
    content_len = quic_h3_reply_content(content, sizeof(content), qs);
  else
    content_len = quic_h3_reply_404(content, sizeof(content));
  assert(content_len < 256);

  hdrs_len = quic_h3_reply_headers(hdrs, sizeof(hdrs), status,
				   (uint8_t)content_len);

  quic_h3_frame(frames, sizeof(frames), &off,
		1, hdrs, hdrs_len);
  quic_h3_frame(frames, sizeof(frames), &off,
		0, (const uint8_t *)content, content_len);

  if(SSL_write_ex(qs->ssl, frames, off, &written) != 1)
    {
      quic_ssl_error(__func__, "SSL_write_ex failed");
      return -1;
    }
  if(SSL_stream_conclude(qs->ssl, 0) != 1)
    {
      quic_ssl_error(__func__, "SSL_stream_conclude failed");
      return -1;
    }

  return 0;
}
#endif /* HAVE_QUIC */

#if defined(HAVE_QUIC) || defined(TEST_RXIFD_H3_REQUEST)
#ifdef TEST_RXIFD_H3_REQUEST
void quic_h3_reply(sc_quicstream_t *qs, int status);
void quic_h3_request(sc_quicstream_t *qs)
#else
static void quic_h3_request(sc_quicstream_t *qs)
#endif /* TEST_RXIFD_H3_REQUEST */
{
  uint64_t frame_type, frame_len;
  size_t off;
  char path[256];

  while((qs->flags & SC_QUICSTREAM_FLAG_DONE) == 0)
    {
      off = 0;

      if(quic_varint_extract(qs->buf, qs->len, &off, &frame_type) != 0 ||
	 quic_varint_extract(qs->buf, qs->len, &off, &frame_len) != 0)
	return;

      if(frame_len > quic_hdr_maxsize ||
	 (qs->flags & SC_QUICSTREAM_FLAG_RXEOF) != 0)
	{
	  qs->flags |= SC_QUICSTREAM_FLAG_DONE;
	  break;
	}

      /* we haven't got all the declared frame yet */
      if(qs->len - off < frame_len)
	break;

      if(frame_type == 1 && /* headers */
	 (qs->flags & SC_QUICSTREAM_FLAG_DONE) == 0)
	{
	  path[0] = '\0';
	  if(frame_len <= SIZE_MAX &&
	     qpack_find_path(qs->buf + off, (size_t)frame_len,
			     (uint8_t *)path, sizeof(path)) != 0 &&
	     strncmp(path, quic_url, quic_urllen) == 0 &&
	     (path[quic_urllen] == '\0' ||
	      path[quic_urllen] == '?' ||
	      path[quic_urllen] == '/'))
	    quic_h3_reply(qs, 200);
	  else
	    quic_h3_reply(qs, 404);
	  qs->flags |= SC_QUICSTREAM_FLAG_DONE;
	}

      off += frame_len;
      qs->len = qs->len - off;
      if(qs->len > 0)
	memmove(qs->buf, qs->buf + off, qs->len);
      realloc_wrap((void **)&qs->buf, qs->len);
    }

  return;
}
#endif /* HAVE_QUIC or TEST_RXIFD_H3_REQUEST */

#ifdef HAVE_QUIC
static int quic_h3_setup(sc_quicconn_t *qc)
{
  SSL *ssl;
  uint8_t buf[3];
  size_t len, written;
  uint64_t flags = SSL_STREAM_FLAG_UNI |
    SSL_STREAM_FLAG_NO_BLOCK | SSL_STREAM_FLAG_ADVANCE;

  /* cannot call SSL_new_stream until the connection is initialized */
  if(SSL_is_init_finished(qc->ssl) == 0)
    return 0;

  while(qc->h3_setup_step < 3)
    {
      ERR_clear_error();
      if((ssl = SSL_new_stream(qc->ssl, flags)) == NULL)
	{
	  quic_ssl_error(__func__, "SSL_new_stream");
	  return -1;
	}
      len = 1;
      if(qc->h3_setup_step == 0)
	{
	  buf[0] = 0x00; buf[1] = 0x04; buf[2] = 0x00;
	  len = 3;
	}
      else if(qc->h3_setup_step == 1)
	buf[0] = 0x02;
      else
	buf[0] = 0x03;
      qc->uni[qc->h3_setup_step++] = ssl;
      if(SSL_write_ex(ssl, buf, len, &written) != 1 || written != len)
	{
	  quic_ssl_error(__func__, "SSL_write_ex on SSL_new_stream failed");
	  return -1;
	}
    }

  return 0;
}

static void quic_out(void)
{
  struct sockaddr_storage them_ss, us_ss;
  BIO_ADDR *them_addr = NULL, *us_addr = NULL;
  uint8_t txbuf[1500];
  size_t processed;
  BIO_MSG msg;

#ifndef NDEBUG
  char *them_hostname = NULL, *them_service = NULL;
  char *us_hostname = NULL, *us_service = NULL;
#endif /* NDEBUG */

  if((them_addr = BIO_ADDR_new()) == NULL ||
     (us_addr = BIO_ADDR_new()) == NULL)
    goto done;

  for(;;)
    {
      memset(&msg, 0, sizeof(msg));
      msg.data     = txbuf;
      msg.data_len = sizeof(txbuf);
      msg.peer     = us_addr;
      msg.local    = them_addr;
      BIO_ADDR_clear(them_addr);
      BIO_ADDR_clear(us_addr);

      ERR_clear_error();
      if(BIO_recvmmsg(wbio, &msg, sizeof(BIO_MSG), 1, 0, &processed) != 1)
	break;

#ifndef NDEBUG
      if(BIO_ADDR_family(them_addr) != AF_UNSPEC)
	{
	  them_hostname = BIO_ADDR_hostname_string(them_addr, 1);
	  them_service  = BIO_ADDR_service_string(them_addr, 1);
	}
      if(BIO_ADDR_family(us_addr) != AF_UNSPEC)
	{
	  us_hostname   = BIO_ADDR_hostname_string(us_addr, 1);
	  us_service    = BIO_ADDR_service_string(us_addr, 1);
	}
      printf("tx %s:%s -> %s:%s (%d)\n",
	     us_hostname != NULL ? us_hostname : "null",
	     us_service != NULL ? us_service : "null",
	     them_hostname != NULL ? them_hostname : "null",
	     them_service != NULL ? them_service : "null",
	     (int)msg.data_len);
      if(them_hostname != NULL) OPENSSL_free(them_hostname);
      if(them_service != NULL) OPENSSL_free(them_service);
      if(us_hostname != NULL) OPENSSL_free(us_hostname);
      if(us_service != NULL) OPENSSL_free(us_service);
      them_hostname = them_service = us_hostname = us_service = NULL;
#endif /* NDEBUG */

      if(BIO_ADDR_family(them_addr) != AF_UNSPEC &&
	 BIO_ADDR_family(us_addr) != AF_UNSPEC)
	{
	  if(sockaddr_from_bioaddr(us_addr, (struct sockaddr *)&us_ss) != 0 ||
	     sockaddr_from_bioaddr(them_addr, (struct sockaddr *)&them_ss) != 0)
	    continue;
	  if(them_ss.ss_family == AF_INET)
	    {
	      udp4_send(quic4, txbuf, msg.data_len,
			&((struct sockaddr_in *)&us_ss)->sin_addr,
			(struct sockaddr_in *)&them_ss);
	    }
	  else
	    {
	      udp6_send(quic6, txbuf, msg.data_len,
			&((struct sockaddr_in6 *)&us_ss)->sin6_addr,
			(struct sockaddr_in6 *)&them_ss);
	    }
	}
    }

  quic_check_errors(__func__);

 done:
  if(them_addr != NULL) BIO_ADDR_free(them_addr);
  if(us_addr != NULL) BIO_ADDR_free(us_addr);
  return;
}

static void sc_quicstream_read(sc_quicstream_t *qs)
{
  uint8_t buf[1500];
  size_t got = 0, len;
  int rc, ecode;

  /* don't read if we've got EOF or an error already */
  if((qs->flags & SC_QUICSTREAM_FLAG_RXEOF) != 0 ||
     (qs->flags & SC_QUICSTREAM_FLAG_DONE) != 0)
    return;

  ERR_clear_error();
  while((rc = SSL_read_ex(qs->ssl, buf, sizeof(buf), &got)) == 1)
    {
      /* always read from the stream, even if we just discard */
      if((qs->flags & SC_QUICSTREAM_FLAG_BIDI) == 0 || got == 0)
	continue;

      /* add the content to the stream's buffer */
      len = qs->len + got;
      if(realloc_wrap((void **)&qs->buf, len) != 0)
	{
	  qs->flags |= SC_QUICSTREAM_FLAG_DONE;
	  return;
	}
      memcpy(qs->buf + qs->len, buf, got);
      qs->len = len;
      quic_h3_request(qs);

      /* stream marked done, stop processing it */
      if((qs->flags & SC_QUICSTREAM_FLAG_DONE) != 0)
	return;
    }

  ecode = SSL_get_error(qs->ssl, rc);
  if(ecode == SSL_ERROR_ZERO_RETURN)
    qs->flags |= SC_QUICSTREAM_FLAG_RXEOF;
  else if(ecode != SSL_ERROR_WANT_READ)
    qs->flags |= SC_QUICSTREAM_FLAG_DONE;

  return;
}

static void quic_in(uint8_t *rxbuf, size_t rxlen,
		    BIO_ADDR *them_addr, BIO_ADDR *us_addr,
		    unsigned int ifindex)
{
#ifndef NDEBUG
  char *them_hostname = NULL, *them_service = NULL;
  char *us_hostname = NULL, *us_service = NULL;
#endif /* NDEBUG */

  dlist_node_t *dn, *dn2;
  sc_quicconn_t *qc = NULL;
  sc_quicstream_t *qs = NULL;
  SSL *ssl = NULL;
  size_t processed;
  BIO_MSG msg;
  BIO_ADDR *dup_addr = NULL;

  memset(&msg, 0, sizeof(msg));
  msg.data     = rxbuf;
  msg.data_len = rxlen;
  msg.peer     = us_addr;
  msg.local    = them_addr;

#ifndef NDEBUG
  them_hostname = BIO_ADDR_hostname_string(them_addr, 1);
  them_service  = BIO_ADDR_service_string(them_addr, 1);
  us_hostname   = BIO_ADDR_hostname_string(us_addr, 1);
  us_service    = BIO_ADDR_service_string(us_addr, 1);
  printf("rx %s:%s -> %s:%s (%d)\n", them_hostname, them_service,
	 us_hostname, us_service, (int)rxlen);
#endif /* NDEBUG */

  ERR_clear_error();

  if((dup_addr = BIO_ADDR_dup(us_addr)) == NULL)
    {
      rxifd_error(__func__, "BIO_ADDR_dup failed");
      goto done;
    }
  if(BIO_dgram_set0_local_addr(wbio, dup_addr) != 1)
    {
      quic_ssl_error(__func__, "BIO_dgram_set0_local_addr wbio failed");
      goto done;
    }
  dup_addr = NULL;
  if(BIO_sendmmsg(rbio, &msg, sizeof(BIO_MSG), 1, 0, &processed) != 1)
    {
      quic_ssl_error(__func__, "BIO_sendmmsg into rbio failed");
      goto done;
    }

  if(SSL_handle_events(quic_ssl) != 1)
    {
      quic_ssl_error(__func__, "SSL_handle_events on quic_ssl failed");
      goto done;
    }

  quic_out();

  while((ssl = SSL_accept_connection(quic_ssl,
				     SSL_ACCEPT_CONNECTION_NO_BLOCK)) != NULL)
    {
      ERR_clear_error();

      if(SSL_set_blocking_mode(ssl, 0) != 1)
	{
	  quic_ssl_error(__func__, "SSL_set_blocking_mode on new ssl failed");
	  SSL_free(ssl);
	  continue;
	}
      if(SSL_set_incoming_stream_policy(ssl, SSL_INCOMING_STREAM_POLICY_ACCEPT,
					0) != 1)
	{
	  quic_ssl_error(__func__, "SSL_set_incoming_stream_policy failed");
	  SSL_free(ssl);
	  continue;
	}
      if((qc = sc_quicconn_add(ssl)) == NULL)
	{
	  rxifd_error(__func__, "could not add new connection");
	  SSL_free(ssl);
	  continue;
	}

      if(quic_h3_setup(qc) != 0)
	{
	  dlist_node_pop(quic_conns, qc->dn);
	  sc_quicconn_free(qc);
	  continue;
	}

      quic_out();
    }

  dn = dlist_head_node(quic_conns);
  while((qc = dlist_node_iter(&dn)) != NULL)
    {
      ERR_clear_error();

      if(SSL_handle_events(qc->ssl) != 1)
	{
	  quic_ssl_error(__func__, "SSL_handle_events on qc->ssl failed");
	  SSL_shutdown(qc->ssl);
	  continue;
	}
      if(qc->h3_setup_step < 3 && quic_h3_setup(qc) != 0)
	{
	  SSL_shutdown(qc->ssl);
	  continue;
	}
      quic_out();

      while(SSL_get_accept_stream_queue_len(qc->ssl) > 0)
	{
	  ERR_clear_error();
	  if((ssl = SSL_accept_stream(qc->ssl,
				      SSL_ACCEPT_STREAM_NO_BLOCK)) != NULL)
	    {
	      if(SSL_set_blocking_mode(ssl, 0) != 1)
		{
		  quic_ssl_error(__func__,
				 "SSL_set_blocking_mode on new stream failed");
		  SSL_free(ssl);
		  continue;
		}
	      if((qs = sc_quicconn_stream_add(qc, ssl,
					      them_addr, ifindex)) == NULL)
		{
		  rxifd_error(__func__, "could not add stream");
		  SSL_free(ssl);
		  continue;
		}
	    }
	}

      dn2 = dlist_head_node(qc->streams);
      while((qs = dlist_node_iter(&dn2)) != NULL)
	{
	  sc_quicstream_read(qs);
	  quic_out();
	}
    }

 done:
  if(dup_addr != NULL) BIO_ADDR_free(dup_addr);
#ifndef NDEBUG
  if(them_hostname != NULL) OPENSSL_free(them_hostname);
  if(them_service != NULL) OPENSSL_free(them_service);
  if(us_hostname != NULL) OPENSSL_free(us_hostname);
  if(us_service != NULL) OPENSSL_free(us_service);
#endif /* NDEBUG */
  return;
}
#endif /* HAVE_QUIC */

#if defined(HAVE_QUIC) && defined(HAVE_RXIF4)
static void quic4_handle(void)
{
  struct sockaddr_in them;
  struct in_addr us;
  uint8_t rxbuf[1472];
  size_t rxlen, rxbuflen = sizeof(rxbuf);
  unsigned int ifindex = 0;
  BIO_ADDR *them_addr = NULL, *us_addr = NULL;

  if(udp4_recv(quic4, rxbuf, rxbuflen, &rxlen, &us, &them, &ifindex) != 2 ||
     (us_addr = bioaddr_from_bits(AF_INET, &us, quic_port)) == NULL ||
     (them_addr = bioaddr_from_sockaddr((struct sockaddr *)&them)) == NULL)
    goto done;

  quic_in(rxbuf, rxlen, them_addr, us_addr, ifindex);

 done:
  if(them_addr != NULL) BIO_ADDR_free(them_addr);
  if(us_addr != NULL) BIO_ADDR_free(us_addr);
  return;
}
#endif /* HAVE_QUIC and HAVE_RXIF4 */

#if defined(HAVE_QUIC) && defined(HAVE_RXIF6)
static void quic6_handle(void)
{
  struct sockaddr_in6 them;
  struct in6_addr us;
  uint8_t rxbuf[1472];
  size_t rxlen, rxbuflen = sizeof(rxbuf);
  unsigned int ifindex = 0;
  BIO_ADDR *them_addr = NULL, *us_addr = NULL;

  if(udp6_recv(quic6, rxbuf, rxbuflen, &rxlen, &us, &them, &ifindex) != 2 ||
     (us_addr = bioaddr_from_bits(AF_INET6, &us, quic_port)) == NULL ||
     (them_addr = bioaddr_from_sockaddr((struct sockaddr *)&them)) == NULL)
    goto done;

  quic_in(rxbuf, rxlen, them_addr, us_addr, ifindex);

 done:
  if(them_addr != NULL) BIO_ADDR_free(them_addr);
  if(us_addr != NULL) BIO_ADDR_free(us_addr);
  return;
}
#endif /* HAVE_QUIC and HAVE_RXIF6 */

#ifdef HAVE_QUIC
static void quic_check_streams(sc_quicconn_t *qc)
{
  sc_quicstream_t *qs;
  dlist_node_t *dn, *dn_next;
  struct timeval diff;

  dn = dlist_head_node(qc->streams);
  while(dn != NULL)
    {
      qs = dlist_node_item(dn);
      dn_next = dlist_node_next(dn);
      timeval_diff_tv(&diff, &qs->begin, &now);
      if((qs->flags & SC_QUICSTREAM_FLAG_DONE) != 0 ||
	 ((qs->flags & SC_QUICSTREAM_FLAG_BIDI) != 0 &&
	  timeval_cmp_gt(&diff, 15, 0)))
	{
#ifndef NDEBUG
	  printf("stream done 0x%02x %d.%06d\n", qs->flags,
		 (int)diff.tv_sec, (int)diff.tv_usec);
#endif /* NDEBUG */
	  dlist_node_pop(qc->streams, dn);
	  sc_quicstream_free(qs);
	}
      dn = dn_next;
    }

  return;
}
#endif /* HAVE_QUIC */

#ifdef HAVE_QUIC
static void quic_timeout_one(SSL *ssl,
			     struct timeval *to, struct timeval **to_ptr)
{
  struct timeval tv;
  int is_infinite;

  for(;;)
    {
      if(SSL_get_event_timeout(ssl, &tv, &is_infinite) != 1)
	return;

      /* do we have any events to process now?  if not, break */
      if(timeval_iszero(&tv) == 0 || is_infinite != 0)
	break;

      /* handle events and try again */
      if(SSL_handle_events(ssl) != 1)
	return;
      quic_out();
    }

  if(is_infinite == 0 && (*to_ptr == NULL || timeval_cmp(&tv, *to_ptr) < 0))
    {
      timeval_cpy(to, &tv);
      *to_ptr = to;
    }

  return;
}
#endif /* HAVE_QUIC */

#ifdef HAVE_QUIC
static void quic_timeout(struct timeval *to, struct timeval **to_ptr)
{
  sc_quicconn_t *qc;
  dlist_node_t *dn, *dn_next;

  *to_ptr = NULL;

  quic_timeout_one(quic_ssl, to, to_ptr);
  if((dn = dlist_head_node(quic_conns)) != NULL)
    gettimeofday_wrap(&now);
  while(dn != NULL)
    {
      qc = dlist_node_item(dn);
      dn_next = dlist_node_next(dn);

      quic_check_streams(qc);

      if(SSL_get_shutdown(qc->ssl) != 0)
	{
	  dlist_node_pop(quic_conns, dn);
	  sc_quicconn_free(qc);
	}
      else
	{
	  quic_timeout_one(qc->ssl, to, to_ptr);
	  if(qc->h3_setup_step < 3 && quic_h3_setup(qc) != 0)
	    SSL_shutdown(qc->ssl);
	}
      dn = dn_next;
    }

#ifndef NDEBUG
  if(*to_ptr != NULL)
    printf("%d.%06d\n", (int)to->tv_sec, (int)to->tv_usec);
  else
    printf("infinite\n");
#endif /* NDEBUG */

  return;
}
#endif /* HAVE_QUIC */

#ifdef HAVE_RXIF
static int select_loop()
{
  struct timeval *tv_ptr = NULL;
  fd_set rfds;
  int nfds = -1;
  int count;

#ifdef HAVE_QUIC
  struct timeval tv;
#endif /* HAVE_QUIC */

  in_loop = 1;
  while(stop == 0)
    {
      FD_ZERO(&rfds);
#ifdef HAVE_RXIF4
      if(socket_isvalid(dns4))
	{
	  FD_SET(dns4, &rfds);
	  nfds = socket_setnfds(nfds, dns4);
	}
#ifdef HAVE_QUIC
      if(socket_isvalid(quic4))
	{
	  FD_SET(quic4, &rfds);
	  nfds = socket_setnfds(nfds, quic4);
	}
#endif /* HAVE_QUIC */
#endif /* HAVE_RXIF4 */
#ifdef HAVE_RXIF6
      if(socket_isvalid(dns6))
	{
	  FD_SET(dns6, &rfds);
	  nfds = socket_setnfds(nfds, dns6);
	}
#ifdef HAVE_QUIC
      if(socket_isvalid(quic6))
	{
	  FD_SET(quic6, &rfds);
	  nfds = socket_setnfds(nfds, quic6);
	}
#endif /* HAVE_QUIC */
#endif /* HAVE_RXIF6 */

#ifdef HAVE_QUIC
      if(quic_conns != NULL)
	quic_timeout(&tv, &tv_ptr);
#endif /* HAVE_QUIC */

      /* we don't need to update now when count is zero */
      if((count = select(nfds+1, &rfds, NULL, NULL, tv_ptr)) == 0)
	continue;
      gettimeofday_wrap(&now);

#ifdef HAVE_QUIC
      if(reload != 0)
	{
	  quic_load_certs();
	  reload = 0;
	}
#endif /* HAVE_QUIC */

      if(count < 0)
	{
	  if(errno == EINTR || errno == EAGAIN)
	    continue;
	  rxifd_error(__func__, "select failed: %s", strerror(errno));
	  return -1;
	}

#ifdef HAVE_RXIF4
      if(socket_isvalid(dns4) && FD_ISSET(dns4, &rfds))
	dns4_handle();
#ifdef HAVE_QUIC
      if(socket_isvalid(quic4) && FD_ISSET(quic4, &rfds))
	quic4_handle();
#endif /* HAVE_QUIC */
#endif /* HAVE_RXIF4 */
#ifdef HAVE_RXIF6
      if(socket_isvalid(dns6) && FD_ISSET(dns6, &rfds))
	dns6_handle();
#ifdef HAVE_QUIC
      if(socket_isvalid(quic6) && FD_ISSET(quic6, &rfds))
	quic6_handle();
#endif /* HAVE_QUIC */
#endif /* HAVE_RXIF6 */
    }

  return 0;
}
#endif /* HAVE_RXIF */

#if defined(HAVE_RXIF) && defined(HAVE_SIGNAL)
static void rxifd_signal(int signo)
{
  if(signo == SIGINT || signo == SIGTERM)
    stop = 1;
#ifdef HAVE_QUIC
  else if(signo == SIGHUP)
    reload = 1;
#endif /* HAVE_QUIC */
  return;
}
#endif /* HAVE_RXIF and HAVE_SIGNAL */

#ifdef HAVE_RXIF
static void cleanup(void)
{
#ifdef HAVE_QUIC
  sc_quicconn_t *qc;
#endif /* HAVE_QUIC */

  if(dns_name != NULL)
    {
      free(dns_name);
      dns_name = NULL;
    }
#ifdef HAVE_RXIF4
  if(socket_isvalid(dns4))
    {
      socket_close(dns4);
      dns4 = socket_invalid();
    }
#endif /* HAVE_RXIF4 */
#ifdef HAVE_RXIF6
  if(socket_isvalid(dns6))
    {
      socket_close(dns6);
      dns6 = socket_invalid();
    }
#endif /* HAVE_RXIF6 */
#ifdef HAVE_QUIC
  if(certfile != NULL)
    {
      free(certfile);
      certfile = NULL;
    }
  if(keyfile != NULL)
    {
      free(keyfile);
      keyfile = NULL;
    }
  if(quic_url != NULL)
    {
      free(quic_url);
      quic_url = NULL;
    }
#ifdef HAVE_RXIF4
  if(socket_isvalid(quic4))
    {
      socket_close(quic4);
      quic4 = socket_invalid();
    }
#endif /* HAVE_RXIF4 */
#ifdef HAVE_RXIF6
  if(socket_isvalid(quic6))
    {
      socket_close(quic6);
      quic6 = socket_invalid();
    }
#endif /* HAVE_RXIF6 */
  if(quic_conns != NULL)
    {
      while((qc = dlist_head_pop(quic_conns)) != NULL)
	sc_quicconn_free(qc);
      dlist_free(quic_conns);
      quic_conns = NULL;
    }
  if(quic_ssl != NULL || rbio != NULL || wbio != NULL)
    {
      tls_bio_free(quic_ssl, rbio, wbio);
      quic_ssl = NULL;
      rbio = NULL;
      wbio = NULL;
    }
  if(tls_ctx != NULL)
    {
      SSL_CTX_free(tls_ctx);
      tls_ctx = NULL;
    }
  if(quic_huff != NULL)
    {
      huffman_free(quic_huff);
      quic_huff = NULL;
    }
#endif /* HAVE_QUIC */
  return;
}
#endif /* HAVE_RXIF */

#ifdef HAVE_RXIF
static int rxifd(int argc, char *argv[])
{
  int rc = -1;

#ifdef HAVE_SETEUID
  uid_t uid, euid;
#endif /* HAVE_SETEUID */

#ifdef DMALLOC
  free(malloc(1));
#endif /* DMALLOC */

#ifdef HAVE_SETEUID
  uid = getuid();
  euid = geteuid();
  if(euid != uid && seteuid(uid) != 0)
    {
      rxifd_error(__func__, "could not lower euid: %s", strerror(errno));
      goto done;
    }
#endif /* HAVE_SETEUID */

  if(check_options(argc, argv) != 0)
    goto done;

#ifdef OPT_VERSION
  if(options & OPT_VERSION)
    {
      printf("sc_rxifd version %s\n", PACKAGE_VERSION);
      return 0;
    }
#endif /* OPT_VERSION */

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
#endif /* OPT_DAEMON */

  gettimeofday_wrap(&now);

#ifdef HAVE_SETEUID
  if(euid != uid && seteuid(euid) != 0)
    {
      rxifd_error(__func__, "could not raise euid: %s", strerror(errno));
      goto done;
    }
#endif /* HAVE_SETEUID */

#ifdef HAVE_RXIF4
  if((options & OPT_IPV6) == 0)
    {
      dns4 = udp4_open(dns_port);
      if(socket_isinvalid(dns4))
	goto done;
#ifdef HAVE_QUIC
      if(options & OPT_QUIC_PORT)
	{
	  quic4 = udp4_open(quic_port);
	  if(socket_isinvalid(quic4))
	    goto done;
	}
#endif /* HAVE_QUIC */
    }
#endif /* HAVE_RXIF4 */

#ifdef HAVE_RXIF6
  if((options & OPT_IPV4) == 0)
    {
      dns6 = udp6_open(dns_port);
      if(socket_isinvalid(dns6))
	goto done;
#ifdef HAVE_QUIC
      if(options & OPT_QUIC_PORT)
	{
	  quic6 = udp6_open(quic_port);
	  if(socket_isinvalid(quic6))
	    goto done;
	}
#endif /* HAVE_QUIC */
    }
#endif /* HAVE_RXIF6 */

#ifdef OPT_CHROOT
  if(chroot_dir != NULL &&
     (chroot(chroot_dir) != 0 || chdir("/") != 0))
    {
      rxifd_error(__func__, "could not chroot to %s: %s", chroot_dir,
		  strerror(errno));
      goto done;
    }
#endif /* OPT_CHROOT */

#ifdef HAVE_SETEUID
  if(euid != uid && setuid(uid) != 0)
    {
      rxifd_error(__func__, "could not lower uid: %s", strerror(errno));
      goto done;
    }
#endif /* HAVE_SETEUID */

#ifdef HAVE_QUIC
  if(options & OPT_QUIC_PORT && quic_init() != 0)
    goto done;
#endif /* HAVE_QUIC */

#ifdef HAVE_SIGNAL
  if(signal(SIGINT, rxifd_signal) == SIG_ERR ||
     signal(SIGHUP, rxifd_signal) == SIG_ERR ||
     signal(SIGTERM, rxifd_signal) == SIG_ERR)
    goto done;
#endif /* HAVE_SIGNAL */

#ifdef HAVE_UNVEIL
#ifdef HAVE_QUIC
  if(certfile != NULL && unveil(certfile, "r") != 0)
    {
      rxifd_error(__func__, "could not unveil %s: %s",
		  certfile, strerror(errno));
      goto done;
    }
  if(keyfile != NULL && unveil(keyfile, "r") != 0)
    {
      rxifd_error(__func__, "could not unveil %s: %s",
		  keyfile, strerror(errno));
      goto done;
    }
#endif /* HAVE_QUIC */
  if(unveil(NULL, NULL) != 0)
    {
      rxifd_error(__func__, "could not do final unveil: %s", strerror(errno));
      goto done;
    }
#endif /* HAVE_UNVEIL */

#ifdef HAVE_PLEDGE
  if(pledge("stdio inet", NULL) != 0)
    {
      rxifd_error(__func__, "could not pledge stdio inet: %s",
		  strerror(errno));
      goto done;
    }
#endif /* HAVE_PLEDGE */

  pps_sec = now.tv_sec;
  rc = select_loop();

 done:
  cleanup();
  return rc;
}
#endif /* HAVE_RXIF */

#ifndef TEST_RXIFD_H3_REQUEST
int main(int argc, char *argv[])
{
#ifdef HAVE_RXIF
  return rxifd(argc, argv);
#else
  fprintf(stderr, "this platform does not have necessary socket support.\n");
  return -1;
#endif /* HAVE_RXIF */
}
#endif /* TEST_RXIFD_H3_REQUEST */
