/*
 * internal.h
 *
 * $Id: internal.h,v 1.70 2025/06/10 22:32:49 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2013-2015 The Regents of the University of California
 * Copyright (C) 2014-2016 Matthew Luckie
 * Copyright (C) 2023-2024 Matthew Luckie
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

#ifdef _WIN32 /* use rand_s on windows */
#define _CRT_RAND_S
#define _CRT_SECURE_NO_WARNINGS
#endif

#if defined(__linux__)
/*
 * the following is necessary to get struct in6_pktinfo on modern
 * (2024) linux systems.
 */
#define _GNU_SOURCE
#endif

#if defined(_MSC_VER)
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
typedef __int8 int8_t;
typedef __int16 int16_t;
typedef __int32 int32_t;
typedef int ssize_t;
typedef int pid_t;
typedef int socklen_t;
typedef int mode_t;
typedef unsigned short sa_family_t;
#define __func__ __FUNCTION__
#endif

#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32 /* include windows headers */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <iphlpapi.h>
#include <process.h>
#include <direct.h>
#include <mmsystem.h>
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#elif defined(HAVE_WINGETOPT_H)
#include "wingetopt.h"
#endif
#endif

#if defined(__APPLE__)
#define _BSD_SOCKLEN_T_
#define HAVE_BPF
#define HAVE_BSD_ROUTE_SOCKET
#define __APPLE_USE_RFC_3542 1
#endif

#if defined(__FreeBSD__)
#define HAVE_BPF
#define HAVE_BSD_ROUTE_SOCKET
#endif

#if defined(__NetBSD__)
#define HAVE_BPF
#define HAVE_BSD_ROUTE_SOCKET
#endif

#if defined(__OpenBSD__)
#define HAVE_BPF
#define HAVE_BSD_ROUTE_SOCKET
#endif

#if defined(__DragonFly__)
#define HAVE_BPF
#define HAVE_BSD_ROUTE_SOCKET
#endif

#if defined(__linux__)
/*
 * the following is not necessary on modern (2024) linux systems, but
 * is necessary to get TH_SYN, and uh_sport for older still-supported
 * linux systems.  keep it here for now.  note: we define TH_SYN below
 * if TH_SYN is not defined, so the original reason for including this
 * (according to CVS logs) is no longer true.
 */
#define __FAVOR_BSD
#endif

#ifdef __sun
#define BSD_COMP
#define _XPG4_2
#define __EXTENSIONS__
#define HAVE_BSD_ROUTE_SOCKET
#define RTAX_MAX RTA_NUMBITS
#define RTAX_GATEWAY 1
#define RTAX_IFP 4
#endif

#ifdef HAVE_SYS_EVENT_H
#include <sys/event.h>
#endif

#ifdef HAVE_SYS_EPOLL_H
#include <sys/epoll.h>
#endif

#if defined(HAVE_SYS_EPOLL_H) && defined(HAVE_EPOLL_WAIT) && !defined(__sun)
#define HAVE_EPOLL
#endif

#ifndef _WIN32 /* include headers that are not on windows */
#include <sys/param.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SOCKETVAR_H
#include <sys/socketvar.h>
#endif
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#ifdef HAVE_NETINET_TCP_TIMER_H
#include <netinet/tcp_timer.h>
#endif
#ifdef HAVE_NETINET_TCP_VAR_H
#include <netinet/tcp_var.h>
#endif
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#endif

#if defined(HAVE_SYS_SYSCTL_H) && !defined(__linux__)
#include <sys/sysctl.h>
#endif

#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif

#ifdef HAVE_NET_IF_TYPES_H
#include <net/if_types.h>
#endif

#if defined(HAVE_BPF)
#include <net/bpf.h>
#endif

#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#if defined(__linux__)
#ifdef HAVE_LINUX_IF_PACKET_H
#include <linux/if_packet.h>
#include <sys/mman.h>
#else
#include <netpacket/packet.h>
#endif
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/sockios.h>
#include <linux/errqueue.h>

#ifdef HAVE_LINUX_NETLINK_H
#include <linux/netlink.h>
#endif

#ifndef SOL_PACKET
#define SOL_PACKET 263
#endif
#define HAVE_IPTABLES
#endif

#ifdef __sun
#define HAVE_DLPI
#define MAXDLBUF 8192
#include <sys/bufmod.h>
#include <sys/dlpi.h>
#include <stropts.h>
#endif

#ifdef HAVE_NETINET_IP_FW_H
#define HAVE_IPFW
#endif

#ifdef HAVE_NET_PFVAR_H
#define HAVE_PF
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include <time.h>
#include <math.h>

#if defined(AF_UNIX) && !defined(_WIN32) /* windows does not have sockaddr_un */
#define HAVE_SOCKADDR_UN
#endif

#if defined(_WIN32) || defined(__sun) || defined(__linux__)
#define IP_HDR_HTONS
#endif
#if defined(__OpenBSD__) && OpenBSD >= 199706
#define IP_HDR_HTONS
#endif
#if defined(__FreeBSD__) && __FreeBSD_version >= 1100030
#define IP_HDR_HTONS
#endif

#if defined(HAVE_STDINT_H)
#include <stdint.h>
#endif

#if defined(HAVE_OPENSSL)
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#endif

#if defined(HAVE_ZLIB)
#include <zlib.h>
#endif

#if defined(HAVE_LIBBZ2)
#include <bzlib.h>
#endif

#if defined(HAVE_LIBLZMA)
#include <lzma.h>
#endif

#if defined(DMALLOC)
#include <dmalloc.h>
#endif

#ifdef _WIN32 /* make windows look like other platforms */
#define SHUT_RDWR SD_BOTH
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
#ifndef S_IFIFO
#define S_IFIFO _S_IFIFO
#endif
#ifndef S_IFREG
#define S_IFREG _S_IFREG
#endif
#define MAXHOSTNAMELEN 256
#define close _close
#define fdopen _fdopen
#define fileno _fileno
#define ftruncate _chsize
#define lseek _lseek
#define mkdir(dir,mode) _mkdir(dir)
#define open _open
#define read _read
#define snprintf _snprintf
#define strdup _strdup
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#define write _write
#endif

#include <assert.h>

#if defined(__sun) || defined(_WIN32) /* define ip6_ext on sun and windows */
struct ip6_ext
{
  uint8_t ip6e_nxt;
  uint8_t ip6e_len;
};
#endif

#ifdef _WIN32 /* define various IP headers on windows */
struct ip
{
  uint8_t        ip_vhl;
  uint8_t        ip_tos;
  uint16_t       ip_len;
  uint16_t       ip_id;
  uint16_t       ip_off;
  uint8_t        ip_ttl;
  uint8_t        ip_p;
  uint16_t       ip_sum;
  struct in_addr ip_src;
  struct in_addr ip_dst;
};
struct ip6_hdr
{
  union
  {
    struct ip6_hdrctl
    {
      uint32_t flow;
      uint16_t plen;
      uint8_t  nxt;
      uint8_t  hlim;
    } hdr;
    uint8_t vfc;
  } ip6un;
  struct in6_addr ip6_src;
  struct in6_addr ip6_dst;
};
struct ip6_frag
{
  uint8_t  ip6f_nxt;
  uint8_t  ip6f_reserved;
  uint16_t ip6f_offlg;
  uint32_t ip6f_ident;
};
struct icmp
{
  uint8_t   icmp_type;
  uint8_t   icmp_code;
  uint16_t  icmp_cksum;
  union {
	  uint8_t pptr;
	  struct idseq {
		  uint16_t id;
		  uint16_t seq;
	  } idseq;
  } icmpun;
  struct ip icmp_ip;
};
struct icmp6_hdr
{
  uint8_t  icmp6_type;
  uint8_t  icmp6_code;
  uint16_t icmp6_cksum;
  union
  {
    uint32_t data32[0];
    uint16_t data16[1];
  } icmp6un;
};
struct udphdr
{
  uint16_t uh_sport;
  uint16_t uh_dport;
  uint16_t uh_ulen;
  uint16_t uh_sum;
};
struct tcphdr {
  uint16_t th_sport;
  uint16_t th_dport;
  uint32_t th_seq;
  uint32_t th_ack;
  uint8_t  th_offx2;
  uint8_t  th_flags;
  uint16_t th_win;
  uint16_t th_sum;
  uint16_t th_urp;
};
struct iovec
{
  void   *iov_base;
  size_t  iov_len;
};
#define icmp_id      icmpun.idseq.id
#define icmp_seq     icmpun.idseq.seq
#define icmp_nextmtu icmpun.idseq.seq
#define icmp_pptr    icmpun.pptr
#define ip6_vfc      ip6un.vfc
#define ip6_flow     ip6un.hdr.flow
#define ip6_plen     ip6un.hdr.plen
#define ip6_nxt      ip6un.hdr.nxt
#define ip6_hlim     ip6un.hdr.hlim
#define icmp6_data32 icmp6un.data32
#define icmp6_mtu    icmp6un.data32[0]
#define icmp6_id     icmp6un.data16[0]
#define icmp6_seq    icmp6un.data16[1]
#endif

#if defined(__sun)
# define s6_addr32 _S6_un._S6_u32
#elif !defined(s6_addr32)
# define s6_addr32 __u6_addr.__u6_addr32
#endif

#if defined(__linux__)
#if !defined(HAVE_STRUCT_NLMSGHDR)
struct nlmsghdr
{
  uint32_t        nlmsg_len;
  uint16_t        nlmsg_type;
  uint16_t        nlmsg_flags;
  uint32_t        nlmsg_seq;
  uint32_t        nlmsg_pid;
};
#endif

#if !defined(HAVE_STRUCT_NLMSGERR)
struct nlmsgerr
{
  int             error;
  struct nlmsghdr msg;
};
#endif

#if !defined(HAVE_STRUCT_SOCKADDR_NL)
struct sockaddr_nl
{
  sa_family_t     nl_family;
  unsigned short  nl_pad;
  uint32_t        nl_pid;
  uint32_t        nl_groups;
};
#endif

#ifndef NLMSG_ERROR
#define NLMSG_ERROR         0x2
#endif

#ifndef NLMSG_DONE
#define NLMSG_DONE          0x3
#endif

#ifndef NLMSG_ALIGNTO
#define NLMSG_ALIGNTO       4
#endif

#ifndef NLMSG_ALIGN
#define NLMSG_ALIGN(len)    (((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1))
#endif

#ifndef NLMSG_LENGTH
#define NLMSG_LENGTH(len)   ((len)+NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#endif

#ifndef NLMSG_DATA
#define NLMSG_DATA(nlh)     ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
#endif

#ifndef NLMSG_NEXT
#define NLMSG_NEXT(nlh,len) ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
                             (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#endif

#ifndef NLMSG_OK
#define NLMSG_OK(nlh,len)   ((len) > 0 && (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
                             (nlh)->nlmsg_len <= (len))
#endif

#ifndef NLM_F_REQUEST
#define NLM_F_REQUEST   1
#endif

#ifndef NLM_F_ROOT
#define NLM_F_ROOT      0x100
#endif

#ifndef NLM_F_MATCH
#define NLM_F_MATCH     0x200
#endif

#endif

#ifndef S_ISREG
#define S_ISREG(m) (((m) & S_IFREG) && ((m) & (S_IFIFO|S_IFCHR|S_IFDIR)) == 0)
#endif

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN 6
#endif

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif

#ifndef ND_ROUTER_ADVERT
#define ND_ROUTER_ADVERT 134
#endif

#ifndef ND_NEIGHBOR_SOLICIT
#define ND_NEIGHBOR_SOLICIT 135
#endif

#ifndef ND_NEIGHBOR_ADVERT
#define ND_NEIGHBOR_ADVERT 136
#endif

#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING 43
#endif

#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif

#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS 0
#endif

#ifndef IP_DF
#define IP_DF 0x4000
#endif

#ifndef IP_MF
#define IP_MF 0x2000
#endif

#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff
#endif

#ifndef IPTOS_ECN_ECT1
#define IPTOS_ECN_ECT1 0x01
#endif

#ifndef IPTOS_ECN_ECT0
#define IPTOS_ECN_ECT0 0x02
#endif

#ifndef IPTOS_ECN_CE
#define IPTOS_ECN_CE 0x03
#endif

#ifndef IPTOS_ECN_MASK
#define	IPTOS_ECN_MASK 0x03
#endif

#ifndef TH_FIN
#define TH_FIN 0x01
#endif

#ifndef TH_SYN
#define TH_SYN 0x02
#endif

#ifndef TH_RST
#define TH_RST 0x04
#endif

#ifndef TH_PUSH
#define TH_PUSH 0x08
#endif

#ifndef TH_ACK
#define TH_ACK 0x10
#endif

#ifndef TH_URG
#define TH_URG 0x20
#endif

#ifndef TH_ECE
#define TH_ECE 0x40
#endif

#ifndef TH_CWR
#define TH_CWR 0x80
#endif

#ifndef ICMP_MINLEN
#define	ICMP_MINLEN 8
#endif

#ifndef ICMP_UNREACH
#define ICMP_UNREACH 3
#endif

#ifndef ICMP_UNREACH_NET
#define ICMP_UNREACH_NET 0
#endif

#ifndef ICMP_UNREACH_HOST
#define ICMP_UNREACH_HOST 1
#endif

#ifndef ICMP_UNREACH_PROTOCOL
#define ICMP_UNREACH_PROTOCOL 2
#endif

#ifndef ICMP_UNREACH_PORT
#define ICMP_UNREACH_PORT 3
#endif

#ifndef ICMP_UNREACH_NEEDFRAG
#define ICMP_UNREACH_NEEDFRAG 4
#endif

#ifndef ICMP_UNREACH_SRCFAIL
#define ICMP_UNREACH_SRCFAIL 5
#endif

#ifndef ICMP_UNREACH_NET_UNKNOWN
#define ICMP_UNREACH_NET_UNKNOWN 6
#endif

#ifndef ICMP_UNREACH_HOST_UNKNOWN
#define ICMP_UNREACH_HOST_UNKNOWN 7
#endif

#ifndef ICMP_UNREACH_ISOLATED
#define ICMP_UNREACH_ISOLATED 8
#endif

#ifndef ICMP_UNREACH_NET_PROHIB
#define ICMP_UNREACH_NET_PROHIB 9
#endif

#ifndef ICMP_UNREACH_HOST_PROHIB
#define ICMP_UNREACH_HOST_PROHIB 10
#endif

#ifndef ICMP_UNREACH_TOSNET
#define ICMP_UNREACH_TOSNET 11
#endif

#ifndef ICMP_UNREACH_TOSHOST
#define ICMP_UNREACH_TOSHOST 12
#endif

#ifndef ICMP_UNREACH_FILTER_PROHIB
#define ICMP_UNREACH_FILTER_PROHIB 13
#endif

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

#ifndef ICMP_PARAMPROB
#define ICMP_PARAMPROB 12
#endif

#ifndef ICMP_PARAMPROB_ERRATPTR
#define ICMP_PARAMPROB_ERRATPTR 0
#endif

#ifndef ICMP_PARAMPROB_OPTABSENT
#define ICMP_PARAMPROB_OPTABSENT 1
#endif

#ifndef ICMP_PARAMPROB_LENGTH
#define ICMP_PARAMPROB_LENGTH 2
#endif

#ifndef ICMP_TSTAMP
#define ICMP_TSTAMP 13
#endif

#ifndef ICMP_TSTAMPREPLY
#define ICMP_TSTAMPREPLY 14
#endif

#ifndef ICMP_TIMXCEED
#define ICMP_TIMXCEED 11
#endif

#ifndef ICMP_TIMXCEED_INTRANS
#define ICMP_TIMXCEED_INTRANS 0
#endif

#ifndef ICMP_TIMXCEED_REASS
#define ICMP_TIMXCEED_REASS 1
#endif

#ifndef ICMP6_DST_UNREACH
#define ICMP6_DST_UNREACH 1
#endif

#ifndef ICMP6_PACKET_TOO_BIG
#define ICMP6_PACKET_TOO_BIG 2
#endif

#ifndef ICMP6_TIME_EXCEEDED
#define ICMP6_TIME_EXCEEDED 3
#endif

#ifndef ICMP6_TIME_EXCEED_TRANSIT
#define ICMP6_TIME_EXCEED_TRANSIT 0
#endif

#ifndef ICMP6_TIME_EXCEED_REASSEMBLY
#define ICMP6_TIME_EXCEED_REASSEMBLY 1
#endif

#ifndef ICMP6_DST_UNREACH_NOROUTE
#define ICMP6_DST_UNREACH_NOROUTE 0
#endif

#ifndef ICMP6_DST_UNREACH_ADMIN
#define ICMP6_DST_UNREACH_ADMIN 1
#endif

#ifndef ICMP6_DST_UNREACH_BEYONDSCOPE
#define ICMP6_DST_UNREACH_BEYONDSCOPE 2
#endif

#ifndef ICMP6_DST_UNREACH_ADDR
#define ICMP6_DST_UNREACH_ADDR 3
#endif

#ifndef ICMP6_DST_UNREACH_NOPORT
#define ICMP6_DST_UNREACH_NOPORT 4
#endif

#ifndef ICMP6_ECHO_REQUEST
#define ICMP6_ECHO_REQUEST 128
#endif

#ifndef ICMP6_ECHO_REPLY
#define ICMP6_ECHO_REPLY 129
#endif

#ifndef TCP_MAX_SEQNUM
#define TCP_MAX_SEQNUM 4294967295U
#endif

#ifndef UINT32_MAX
#define UINT32_MAX 4294967295U
#endif

#ifndef UINT16_MAX
#define UINT16_MAX 65535U
#endif

#ifndef SEQ_LT
#define SEQ_LT(a,b) ((int)((a)-(b)) < 0)
#endif

#ifndef SEQ_LEQ
#define SEQ_LEQ(a,b) ((int)((a)-(b)) <= 0)
#endif

#ifndef SEQ_GT
#define SEQ_GT(a,b) ((int)((a)-(b)) > 0)
#endif

#ifndef SEQ_GEQ
#define SEQ_GEQ(a,b) ((int)((a)-(b)) >= 0)
#endif

#ifndef _WIN32 /* interfaces for windows sockets */
#define socket_close(s) close((s))
#define socket_isvalid(s) ((s) != -1)
#define socket_isinvalid(s) ((s) == -1)
#define socket_invalid() (-1)
#define socket_setnfds(nfds, s) ((nfds) < (s) ? (s) : (nfds))
#else
#define socket_close(s) closesocket((s))
#define socket_isvalid(s) ((s) != INVALID_SOCKET)
#define socket_isinvalid(s) ((s) == INVALID_SOCKET)
#define socket_invalid() (INVALID_SOCKET)
#define socket_setnfds(nfds, s) (0)
#endif

#ifndef _WIN32 /* mode parameter */
#define MODE_644 (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#else
#define MODE_644 (_S_IREAD | _S_IWRITE)
#endif
