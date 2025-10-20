/*
 * scamper_rtsock: code to deal with a route socket or equivalent
 *
 * $Id: scamper_rtsock.c,v 1.114 2025/10/20 01:22:20 mjl Exp $
 *
 *          Matthew Luckie
 *
 *          Supported by:
 *           The University of Waikato
 *           NLANR Measurement and Network Analysis
 *           CAIDA
 *           The WIDE Project
 *
 * The purpose of this code is to obtain the outgoing interface's index
 * using whatever mechanisms the operating system supports.  A route
 * socket is created where necessary and is kept open for the lifetime
 * of scamper.
 *
 * scamper_rtsock_getifindex returns the interface index on success.
 * if an error occurs, it returns -1.  as route sockets are unreliable
 * sockets, if we do not get an expected response, we return -2 to
 * indicate to the caller to try again.
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
 * Copyright (C) 2014      The Regents of the University of California
 * Copyright (C) 2016-2024 Matthew Luckie
 * Copyright (C) 2023      The Regents of the University of California
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

/* include support for the netlink socket in linux */
#if defined(__linux__)

struct rtattr
{
  unsigned short  rta_len;
  unsigned short  rta_type;
};

struct rtmsg
{
  unsigned char   rtm_family;
  unsigned char   rtm_dst_len;
  unsigned char   rtm_src_len;
  unsigned char   rtm_tos;
  unsigned char   rtm_table;
  unsigned char   rtm_protocol;
  unsigned char   rtm_scope;
  unsigned char   rtm_type;
  unsigned        rtm_flags;
};

#define RTA_ALIGNTO           4
#define RTA_ALIGN(len)        (((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1))
#define RTA_LENGTH(len)       (RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_DATA(rta)         ((void*)(((char*)(rta)) + RTA_LENGTH(0)))
#define RTA_OK(rta,len)       ((len) > 0 && (rta)->rta_len >= sizeof(struct rtattr) && \
                               (rta)->rta_len <= (len))
#define RTA_NEXT(rta,attrlen) ((attrlen) -= RTA_ALIGN((rta)->rta_len), \
                               (struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_UNSPEC            0
#define RTA_DST               1
#define RTA_SRC               2
#define RTA_IIF               3
#define RTA_OIF               4
#define RTA_GATEWAY           5
#define RTA_PRIORITY          6
#define RTA_PREFSRC           7
#define RTA_METRICS           8
#define RTA_MULTIPATH         9
#define RTA_PROTOINFO         10
#define RTA_FLOW              11
#define RTA_CACHEINFO         12
#define RTA_SESSION           13

#define RTM_RTA(r)         ((struct rtattr*)(((char*)(r)) + \
                            NLMSG_ALIGN(sizeof(struct rtmsg))))
#define RTM_BASE            0x10
#define RTM_NEWROUTE       (RTM_BASE+8)
#define RTM_GETROUTE       (RTM_BASE+10)
#define NETLINK_ROUTE       0

#endif

#include "scamper.h"
#include "scamper_debug.h"
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_fds.h"
#include "scamper_rtsock.h"
#include "scamper_priv.h"
#include "scamper_osinfo.h"
#include "utils.h"
#include "mjl_list.h"

extern scamper_addrcache_t *addrcache;

#ifdef HAVE_BSD_ROUTE_SOCKET
static size_t               roundup_v = 0;
#endif

#ifndef _WIN32 /* windows does not have a routing socket */
typedef struct rtsock_pair
{
  scamper_route_t *route; /* query */
  uint16_t         seq;   /* sequence number used */
  dlist_node_t    *node;  /* pointer to node in pair dlist */
} rtsock_pair_t;

static pid_t    pid;          /* [unprivileged] process id */
static uint16_t seq   = 0;    /* next sequence number to use */
static dlist_t *pairs = NULL; /* list of addresses queried with their seq */

static rtsock_pair_t *rtsock_pair_alloc(scamper_route_t *route, int seq_in)
{
  rtsock_pair_t *pair;
  if((pair = malloc_zero(sizeof(rtsock_pair_t))) == NULL ||
     (pair->node = dlist_head_push(pairs, pair)) == NULL)
    {
      if(pair != NULL) free(pair);
      return NULL;
    }
  pair->route = route;
  pair->seq = seq_in;
  route->internal = pair;
  return pair;
}

static void rtsock_pair_free(rtsock_pair_t *pair)
{
  if(pair == NULL)
    return;
  pair->route->internal = NULL;
  if(pair->node != NULL)
    dlist_node_pop(pairs, pair->node);
  free(pair);
  return;
}

static rtsock_pair_t *rtsock_pair_get(uint16_t seq_in)
{
  rtsock_pair_t *pair;
  dlist_node_t  *node;

  for(node=dlist_head_node(pairs); node != NULL; node=dlist_node_next(node))
    {
      pair = dlist_node_item(node);
      if(pair->seq != seq_in)
	continue;
      dlist_node_pop(pairs, node);
      pair->node = NULL;
      return pair;
    }

  return NULL;
}

#if defined(HAVE_BSD_ROUTE_SOCKET)
#if 0
static void rtmsg_dump(const uint8_t *buf, size_t len)
{
  char str[80];
  size_t i, off = 0;
  int k = 0;

  for(i=0; i<len; i++)
    {
      if(k == 20)
	{
	  printerror_msg(__func__, "%s", str);
	  k = 0;
	  off = 0;
	}

      if(k != 0 && (k % 4) == 0)
	string_concatc(str, sizeof(str), &off, ' ');
      string_concaf(str, sizeof(str), &off, "%02x", buf[i]);
      k++;
    }

  if(k != 0)
    printerror_msg(__func__, "%s", str);
  return;
}
#endif

size_t scamper_rtsock_roundup(size_t len)
{
  assert(roundup_v > 0);
  return ((len > 0) ? (1 + ((len - 1) | (roundup_v - 1))) : roundup_v);
}

/*
 * scamper_rtsock_getifindex
 *
 * figure out the outgoing interface id / route using route sockets
 *
 * route(4) gives an overview of the functions called in here
 */
static int scamper_rtsock_getifindex(int fd, scamper_addr_t *dst,
				     scamper_err_t *error)
{
  struct sockaddr_storage sas;
  struct sockaddr_dl *sdl;
  struct rt_msghdr *rtm;
  uint8_t buf[1024];
  size_t len, slen;
  ssize_t ss;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(dst))
    {
      sockaddr_compose((struct sockaddr *)&sas, AF_INET, dst->addr, 0);
      slen = sizeof(struct sockaddr_in);
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(dst))
    {
      sockaddr_compose((struct sockaddr *)&sas, AF_INET6, dst->addr, 0);
      slen = sizeof(struct sockaddr_in6);
    }
  else
    {
      scamper_err_make(error, 0, "rtsock_getifindex: dst not IP address");
      return -1;
    }

  len = sizeof(struct rt_msghdr) + scamper_rtsock_roundup(slen) +
    scamper_rtsock_roundup(sizeof(struct sockaddr_dl));
  if(len > sizeof(buf))
    {
      scamper_err_make(error, 0, "rtsock_getifindex: buf not large enough");
      return -1;
    }

  memset(buf, 0, len);
  rtm = (struct rt_msghdr *)buf;
  rtm->rtm_msglen  = len;
  rtm->rtm_version = RTM_VERSION;
  rtm->rtm_type    = RTM_GET;
  rtm->rtm_addrs   = RTA_DST | RTA_IFP;
  rtm->rtm_pid     = pid;
  rtm->rtm_seq     = seq;
  memcpy(buf + sizeof(struct rt_msghdr), &sas, slen);

  sdl = (struct sockaddr_dl *)(buf + sizeof(struct rt_msghdr) +
			       scamper_rtsock_roundup(slen));
  sdl->sdl_family = AF_LINK;

#ifndef __sun
  sdl->sdl_len    = sizeof(struct sockaddr_dl);
#endif

  ss = write(fd, buf, len);
  if(ss < 0)
    {
      scamper_err_make(error,errno,"rtsock_getifindex: could not write socket");
      return -1;
    }
  else if((size_t)ss != len)
    {
      scamper_err_make(error, 0, "rtsock_getifindex: wrote %d of %d bytes",
		       (int)ss, (int)len);
      return -1;
    }

  return 0;
}
#endif /* HAVE_BSD_ROUTE_SOCKET */

#if defined(__linux__)
/*
 * scamper_rtsock_getifindex
 *
 * figure out the outgoing interface id / route using linux netlink
 *
 * this works on Linux systems with netlink compiled into the kernel.
 * i think netlink comes compiled into the kernel with most distributions
 * these days.
 *
 * the man pages netlink(3), netlink(7), rtnetlink(3), and rtnetlink(7)
 * give an overview of the functions and structures used in here, but the
 * documentation in those man pages is pretty crap.
 * you'd be better off studying netlink.h and rtnetlink.h
 */
static int scamper_rtsock_getifindex(int fd, scamper_addr_t *dst,
				     scamper_err_t *error)
{
  struct nlmsghdr *nlmsg;
  struct rtmsg    *rtmsg;
  struct rtattr   *rta;
  int              dst_len;
  uint8_t          buf[1024];
  int              af;
  ssize_t          ss;

  if(SCAMPER_ADDR_TYPE_IS_IPV4(dst))
    {
      dst_len  = 4;
      af       = AF_INET;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(dst))
    {
      dst_len  = 16;
      af       = AF_INET6;
    }
  else
    {
      scamper_err_make(error, 0, "rtsock_getifindex: dst not IP address");
      return -1;
    }

  /*
   * fill out a route request.
   * we use the standard netlink header, with a route msg subheader
   * to query for the outgoing interface.
   * the message includes one attribute - the destination address
   * we are querying the route for.
   */
  memset(buf, 0, sizeof(buf));
  nlmsg  = (struct nlmsghdr *)buf;
  nlmsg->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
  nlmsg->nlmsg_type  = RTM_GETROUTE;
  nlmsg->nlmsg_flags = NLM_F_REQUEST;
  nlmsg->nlmsg_seq   = seq;
  nlmsg->nlmsg_pid   = pid;

  /* netlink wants the bit length of each address */
  rtmsg = NLMSG_DATA(nlmsg);
  rtmsg->rtm_family  = af;
  rtmsg->rtm_flags   = 0;
  rtmsg->rtm_dst_len = dst_len * 8;

  rta = (struct rtattr *)(buf + NLMSG_ALIGN(nlmsg->nlmsg_len));
  rta->rta_type = RTA_DST;
  rta->rta_len  = RTA_LENGTH(dst_len);
  nlmsg->nlmsg_len += RTA_LENGTH(dst_len);
  memcpy(RTA_DATA(rta), dst->addr, dst_len);

  /* send the request */
  ss = send(fd, buf, nlmsg->nlmsg_len, 0);
  if(ss < 0)
    {
      scamper_err_make(error,errno,"rtsock_getifindex: could not write socket");
      return -1;
    }
  else if((size_t)ss != nlmsg->nlmsg_len)
    {
      scamper_err_make(error, 0, "rtsock_getifindex: wrote %d of %d bytes",
		       (int)ss, (int)nlmsg->nlmsg_len);
      return -1;
    }

  return 0;
}
#endif

int scamper_rtsock_getroute(scamper_fd_t *fdn, scamper_route_t *route,
			    scamper_err_t *error)
{
  int fd = scamper_fd_fd_get(fdn);

  /* ask the question */
  if(scamper_rtsock_getifindex(fd, route->dst, error) != 0)
    return -1;

  /* keep track of the question */
  if(rtsock_pair_alloc(route, seq++) == NULL)
    {
      scamper_err_make(error, errno, "rtsock_getroute: could not alloc pair");
      return -1;
    }

  return 0;
}

#if defined(__linux__)
#if 0
static void rtattr_dump(struct rtattr *rta)
{
  char *rta_type;
  char  rta_data[64];
  int   i;

  switch(rta->rta_type)
    {
    case RTA_UNSPEC:    rta_type = "unspec";    break;
    case RTA_DST:       rta_type = "dst";       break;
    case RTA_SRC:       rta_type = "src";       break;
    case RTA_IIF:       rta_type = "iif";       break;
    case RTA_OIF:       rta_type = "oif";       break;
    case RTA_GATEWAY:   rta_type = "gateway";   break;
    case RTA_PRIORITY:  rta_type = "priority";  break;
    case RTA_PREFSRC:   rta_type = "prefsrc";   break;
    case RTA_METRICS:   rta_type = "metrics";   break;
    case RTA_MULTIPATH: rta_type = "multipath"; break;
    case RTA_PROTOINFO: rta_type = "protoinfo"; break;
    case RTA_FLOW:      rta_type = "flow";      break;
    case RTA_CACHEINFO: rta_type = "cacheinfo"; break;
    case RTA_SESSION:   rta_type = "session";   break;
    default:            rta_type = "<unknown>"; break;
    }

  for(i=0;i<rta->rta_len-sizeof(struct rtattr)&&i<(sizeof(rta_data)/2)-1;i++)
    {
      snprintf(&rta_data[i*2], 3, "%02x",
	       *(uint8_t *)(((char *)rta) + sizeof(struct rtattr) + i));
    }

  if(i != 0)
    {
      scamper_debug(__func__, "type %s len %d data %s",
		    rta_type, rta->rta_len-sizeof(struct rtattr), rta_data);
    }
  else
    {
      scamper_debug(__func__, "type %s\n", rta_type);
    }

  return;
}
#endif

static void rtsock_parsemsg(uint8_t *buf, size_t len)
{
  struct nlmsghdr *nlmsg;
  struct nlmsgerr *nlerr;
  struct rtmsg    *rtmsg;
  struct rtattr   *rta;
  void            *gwa = NULL;
  int              ifindex = -1;
  scamper_addr_t  *gw = NULL;
  rtsock_pair_t   *pair = NULL;
  scamper_route_t *route = NULL;
  scamper_err_t    error;

  SCAMPER_ERR_INIT(&error);

  if(len < sizeof(struct nlmsghdr))
    {
      scamper_debug(__func__, "len %d != %d",
		    (int)len, (int)sizeof(struct nlmsghdr));
      return;
    }

  nlmsg = (struct nlmsghdr *)buf;

  /* if the message isn't addressed to this pid, drop it */
  if(nlmsg->nlmsg_pid != (uint32_t)pid)
    return;

  if((pair = rtsock_pair_get(nlmsg->nlmsg_seq)) == NULL)
    return;
  route = pair->route;
  rtsock_pair_free(pair);

  if(nlmsg->nlmsg_type == RTM_NEWROUTE)
    {
      rtmsg = NLMSG_DATA(nlmsg);

      /* this is the payload length of the response packet */
      len = nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg));

      /* hunt through the payload for the RTA_OIF entry */
      rta = RTM_RTA(rtmsg);
      while(RTA_OK(rta, len))
	{
	  switch(rta->rta_type)
	    {
	    case RTA_OIF:
	      ifindex = *(unsigned *)RTA_DATA(rta);
	      break;

	    case RTA_GATEWAY:
	      gwa = RTA_DATA(rta);
	      break;
	    }
	  rta = RTA_NEXT(rta, len);
	}

      if(gwa != NULL)
	{
	  if(rtmsg->rtm_family == AF_INET)
	    gw = scamper_addrcache_get_ipv4(addrcache, gwa);
	  else if(rtmsg->rtm_family == AF_INET6)
	    gw = scamper_addrcache_get_ipv6(addrcache, gwa);
	  else
	    {
	      scamper_err_make(&error, 0, "rtsock_parsemsg: gwa not IP");
	      goto err;
	    }
	  if(gw == NULL)
	    {
	      scamper_err_make(&error, errno,
			       "rtsock_parsemsg: could not get gw");
	      goto err;
	    }
	}

      route->gw = gw;
      route->ifindex = ifindex;
      route->cb(route, NULL);
    }
  else if(nlmsg->nlmsg_type == NLMSG_ERROR)
    {
      nlerr = NLMSG_DATA(nlmsg);
      scamper_err_make(&error, nlerr->error, "rtsock_parsemsg: got nlerr");
      goto err;
    }

  return;

 err:
  route->cb(route, &error);
  return;
}
#endif

#if defined(HAVE_BSD_ROUTE_SOCKET)
static void rtsock_parsemsg_route(uint8_t *buf, scamper_route_t *route)
{
  struct rt_msghdr   *rtm = (struct rt_msghdr *)buf;
  struct sockaddr    *addrs[RTAX_MAX];
  struct sockaddr_dl *sdl;
  struct sockaddr    *sa;
  struct in6_addr    *ip6;
  size_t              off;
  int                 i, tmp, ifindex = -1;
  void               *addr = NULL;
  scamper_addr_t     *gw = NULL;
  scamper_err_t       error;

  SCAMPER_ERR_INIT(&error);

  if(rtm->rtm_errno != 0)
    {
      scamper_err_make(&error, rtm->rtm_errno, "rtsock_parsemsg: got err");
      goto err;
    }

  off = sizeof(struct rt_msghdr);
  memset(addrs, 0, sizeof(addrs));
  for(i=0; i<RTAX_MAX; i++)
    {
      if(rtm->rtm_addrs & (1 << i))
	{
	  addrs[i] = sa = (struct sockaddr *)(buf + off);
	  if((tmp = sockaddr_len(sa)) <= 0)
	    {
	      scamper_err_make(&error, 0, "rtsock_parsemsg: unhandled af %d",
			       sa->sa_family);
	      goto err;
	    }
	  off += scamper_rtsock_roundup(tmp);
	}
    }

  if((sdl = (struct sockaddr_dl *)addrs[RTAX_IFP]) != NULL)
    {
      if(sdl->sdl_family != AF_LINK)
	{
	  scamper_err_make(&error, 0, "rtsock_parsemsg: sdl_family %d",
			   sdl->sdl_family);
	  goto err;
	}
      ifindex = sdl->sdl_index;
    }

  if((sa = addrs[RTAX_GATEWAY]) != NULL)
    {
      if(sa->sa_family == AF_INET)
	{
	  i = SCAMPER_ADDR_TYPE_IPV4;
	  addr = &((struct sockaddr_in *)sa)->sin_addr;
	}
      else if(sa->sa_family == AF_INET6)
	{
	  /*
	   * check to see if the gw address is a link local address.  if
	   * it is, then drop the embedded index from the gateway address
	   */
	  ip6 = &((struct sockaddr_in6 *)sa)->sin6_addr;
	  if(IN6_IS_ADDR_LINKLOCAL(ip6))
	    {
	      ip6->s6_addr[2] = 0;
	      ip6->s6_addr[3] = 0;
	    }
	  i = SCAMPER_ADDR_TYPE_IPV6;
	  addr = ip6;
	}
      else if(sa->sa_family == AF_LINK)
	{
	  sdl = (struct sockaddr_dl *)sa;
	  if(sdl->sdl_type == IFT_ETHER && sdl->sdl_alen == ETHER_ADDR_LEN)
	    {
	      i = SCAMPER_ADDR_TYPE_ETHERNET;
	      addr = sdl->sdl_data + sdl->sdl_nlen;
	    }
	}

      /*
       * if we have got a gateway address that we know what to do with,
       * then store it here.
       */
      if(addr != NULL &&
	 (gw = scamper_addrcache_get(addrcache, i, addr)) == NULL)
	{
	  scamper_err_make(&error, errno,
			   "rtsock_parsemsg: could not get gw");	  
	  goto err;
	}
    }

  route->gw      = gw;
  route->ifindex = ifindex;
  route->cb(route, NULL);
  return;

 err:
  route->cb(route, &error);
  return;
}

static void rtsock_parsemsg(uint8_t *buf, size_t len)
{
  struct rt_msghdr *rtm;
  scamper_route_t *route;
  rtsock_pair_t *pair;
  size_t x = 0;

  while(x < len)
    {
      if(len - x < sizeof(struct rt_msghdr))
	{
	  scamper_debug(__func__, "len %d != %d",
			(int)len, (int)sizeof(struct rt_msghdr));
	  return;
	}

      /*
       * check if the message is something we want, and that we have
       * a pair for it
       */
      rtm = (struct rt_msghdr *)(buf + x);
      if(rtm->rtm_pid != pid ||
	 rtm->rtm_msglen > len - x ||
	 rtm->rtm_type != RTM_GET ||
	 (rtm->rtm_flags & RTF_DONE) == 0 ||
	 (pair = rtsock_pair_get(rtm->rtm_seq)) == NULL)
	goto next;

      route = pair->route;
      rtsock_pair_free(pair);
      rtsock_parsemsg_route(buf + x, route);

    next:
      x += rtm->rtm_msglen;
    }

  return;
}
#endif

/*
 * scamper_rtsock_read_cb
 *
 * this callback handles reading a message from the route socket.
 * we check to see if the message is something that we have sent by parsing
 * the message out.  if we did send the message, then we search for the
 * address-sequence pair, which matches the sequence number with a route
 * lookup.
 * if we get a pair back, then we remove it from the list and look for a
 * trace matching the address.  we then take the result from the route
 * lookup and apply it to the trace.
 */
void scamper_rtsock_read_cb(const int fd, void *param)
{
  uint8_t buf[2048];
  ssize_t len;

  if((len = recv(fd, buf, sizeof(buf), 0)) < 0)
    {
      printerror(__func__, "recv failed");
      return;
    }

  if(len > 0)
    rtsock_parsemsg(buf, len);

  return;
}

void scamper_rtsock_close(int fd)
{
  close(fd);
  return;
}

int scamper_rtsock_open_fd()
{
#if defined(HAVE_BSD_ROUTE_SOCKET)
  return socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
#elif defined(__linux__)
  return socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
#else
#error "route socket support for this system not implemented"
#endif
}

int scamper_rtsock_open()
{
  int fd;

  if((fd = scamper_priv_rtsock()) == -1)
    {
      printerror(__func__, "could not open route socket");
      return -1;
    }

  return fd;
}
#endif

#ifdef _WIN32 /* windows does not have a routing socket */
static int scamper_rtsock_getroute4(scamper_route_t *route,
				    scamper_err_t *error)
{
  struct in_addr *in = route->dst->addr;
  MIB_IPFORWARDROW fw;
  DWORD dw;

  if((dw = GetBestRoute(in->s_addr, 0, &fw)) != NO_ERROR)
    {
      scamper_err_make(error, 0, "rtsock_getroute4: could not get route");
      route->error = dw;
      return -1;
    }

  route->ifindex = fw.dwForwardIfIndex;

  /* determine the gateway address to use, if one is specified */
  if((dw = fw.dwForwardNextHop) != 0)
    {
      if((route->gw = scamper_addrcache_get_ipv4(addrcache, &dw)) == NULL)
	{
	  route->error = errno;
	  scamper_err_make(error, errno, "rtsock_getroute4: could not get gw");
	  return -1;
	}
    }

  return 0;
}

int scamper_rtsock_getroute(scamper_route_t *route, scamper_err_t *error)
{
  if(SCAMPER_ADDR_TYPE_IS_IPV4(route->dst))
    {
      if(scamper_rtsock_getroute4(route, error) != 0)
	return -1;
      route->cb(route);
    }
  else
    {
      scamper_err_make(error, errno, "rtsock_getroute: not IPv4 dst");
      return -1;
    }

  return 0;
}
#endif

void scamper_route_free(scamper_route_t *route)
{
  if(route == NULL)
    return;
#ifndef _WIN32 /* windows does not have a routing socket */
  if(route->internal != NULL)
    rtsock_pair_free(route->internal);
#endif
  if(route->dst != NULL)
    scamper_addr_free(route->dst);
  if(route->gw != NULL)
    scamper_addr_free(route->gw);
  free(route);
  return;
}

scamper_route_t *scamper_route_alloc(scamper_addr_t *dst, void *param,
				     void (*cb)(scamper_route_t *,
						const scamper_err_t *))
{
  scamper_route_t *route;
  if((route = malloc_zero(sizeof(scamper_route_t))) == NULL)
    return NULL;
  route->dst = scamper_addr_use(dst);
  route->param = param;
  route->cb = cb;
  return route;
}

int scamper_rtsock_init()
{
#ifdef __APPLE__
  const scamper_osinfo_t *osinfo;
#endif

#ifndef _WIN32 /* windows does not have a routing socket */
  if((pairs = dlist_alloc()) == NULL)
    {
      printerror(__func__, "could not allocate pair list");
      return -1;
    }
  pid = getpid();
#endif

#ifdef __APPLE__
  osinfo = scamper_osinfo_get();
  if(osinfo->os_id == SCAMPER_OSINFO_OS_DARWIN &&
     osinfo->os_rel_dots > 0 && osinfo->os_rel[0] >= 10)
    roundup_v = sizeof(uint32_t);
  else
    roundup_v = sizeof(long);
#elif defined(__NetBSD_Version__) && __NetBSD_Version__ >= 599004500
  roundup_v = sizeof(uint64_t);
#elif defined(__sun)
  roundup_v = sizeof(uint32_t);
#elif defined(HAVE_BSD_ROUTE_SOCKET)
  roundup_v = sizeof(long);
#endif

  return 0;
}

void scamper_rtsock_cleanup()
{
#ifndef _WIN32 /* windows does not have a routing socket */
  rtsock_pair_t *pair;

  if(pairs != NULL)
    {
      while((pair = dlist_head_pop(pairs)) != NULL)
	{
	  pair->node = NULL;
	  rtsock_pair_free(pair);
	}

      dlist_free(pairs);
      pairs = NULL;
    }
#endif

  return;
}
