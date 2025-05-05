/*
 * scamper_do_ping.c
 *
 * $Id: scamper_ping_do.c,v 1.209 2025/05/05 03:34:24 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2016-2023 Matthew Luckie
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
#include "scamper_config.h"
#include "scamper_debug.h"
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_ifname.h"
#include "scamper_ifname_int.h"
#include "scamper_list.h"
#include "scamper_ping.h"
#include "scamper_ping_int.h"
#include "scamper_getsrc.h"
#include "scamper_icmp_resp.h"
#include "scamper_dl.h"
#include "scamper_dlhdr.h"
#include "scamper_fds.h"
#include "scamper_rtsock.h"
#include "scamper_task.h"
#include "scamper_probe.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_ping_do.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "scamper_osinfo.h"
#include "utils.h"

/* the callback functions registered with the ping task */
static scamper_task_funcs_t ping_funcs;

/* running scamper configuration */
extern scamper_config_t *config;

typedef struct ping_state
{
  scamper_addr_t    *last_addr;
  uint16_t           replies;
  uint16_t           seq;
  uint8_t           *payload;
  uint16_t           payload_len;

  /* ip pre-specified timestamp options */
  struct in_addr     tsps_ips[4];
  uint8_t            tsps_ipc;

  /* for too-big-trick */
  uint8_t            ptb;
  uint8_t           *quote;
  uint16_t           quote_len;

  /* probe ports */
  uint16_t          *sports;
  scamper_fd_t     **fds; /* this is only set for TCP/UDP */
  size_t             fdc;

  uint8_t            mode;
#ifndef _WIN32 /* windows does not have a routing socket */
  scamper_fd_t      *rtsock;        /* fd to query route socket with */
#endif
  scamper_fd_t      *icmp;          /* fd to listen to icmp packets with */
  scamper_fd_t      *dl;            /* struct to use with datalink access */
  scamper_fd_t      *raw;           /* raw socket to use with udp/tcp probes */
  scamper_dlhdr_t   *dlhdr;         /* header to use with datalink */
  scamper_route_t   *route;         /* looking up a route */

} ping_state_t;

static const uint8_t MODE_PING   = 0;
static const uint8_t MODE_RTSOCK = 1;
static const uint8_t MODE_DLHDR  = 2;

static scamper_ping_t *ping_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static ping_state_t *ping_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static void ping_stop(scamper_task_t *task, uint8_t reason, uint8_t data)
{
  scamper_ping_t *ping = ping_getdata(task);
  ping->stop_reason = reason;
  ping->stop_data   = data;
  scamper_task_queue_done(task, 0);
  return;
}

static void ping_handleerror(scamper_task_t *task, int error)
{
  ping_stop(task, SCAMPER_PING_STOP_ERROR, error);
  return;
}

/*
 * ping_dltx:
 *
 * if we're relaying probes via a specific router, or sending
 * packet-too-big messages, or running on sunos which overwrites IPIDs
 * in raw sockets, or attempting to spoof the source address, then
 * we'll need to use the datalink interface to transmit.
 */
static int ping_dltx(scamper_ping_t *ping)
{
  if(ping->rtr != NULL || ping->pmtu != 0 ||
     (SCAMPER_ADDR_TYPE_IS_IPV4(ping->dst) && scamper_osinfo_is_sunos()) ||
     SCAMPER_PING_FLAG_IS_DLTX(ping) ||
     SCAMPER_PING_FLAG_IS_SPOOF(ping))
    return 1;
  return 0;
}

static scamper_addr_t *ping_addr(scamper_ping_t *ping,
				 ping_state_t *state, void *addr)
{
  if(scamper_addr_raw_cmp(ping->dst, addr) == 0)
    return scamper_addr_use(ping->dst);
  if(state->last_addr != NULL)
    {
      if(scamper_addr_raw_cmp(state->last_addr, addr) == 0)
	return scamper_addr_use(state->last_addr);
      scamper_addr_free(state->last_addr);
    }
  if((state->last_addr = scamper_addr_alloc(ping->dst->type, addr)) == NULL)
    {
      printerror(__func__, "could not get reply addr");
      return NULL;
    }
  return scamper_addr_use(state->last_addr);
}

static uint16_t match_ipid(scamper_task_t *task, uint16_t ipid)
{
  scamper_ping_t *ping  = ping_getdata(task);
  ping_state_t   *state = ping_getstate(task);
  uint16_t        seq;

  assert(state->seq > 0);

  for(seq = state->seq-1; ping->probes[seq]->ipid != ipid; seq--)
    {
      if(seq == 0 || ping->ping_sent - 5 == seq)
	{
	  seq = state->seq - 1;
	  break;
	}
    }

  return seq;
}

static void do_ping_handle_dl(scamper_task_t *task, scamper_dl_rec_t *dl)
{
  static const int DIR_INBOUND  = 0;
  static const int DIR_OUTBOUND = 1;
  scamper_ping_t       *ping  = ping_getdata(task);
  ping_state_t         *state = ping_getstate(task);
  scamper_ping_probe_t *probe = NULL;
  scamper_ping_reply_t *reply = NULL;
  uint16_t              u16, sport;
  int                   seq;
  int                   direction;
  struct timeval        diff;
  int                   usec;

  if(state == NULL || state->seq == 0)
    return;

  /*
   * do not consider datalink packets if we never opened a datalink
   * interface
   */
  if(state->dl == NULL)
    return;

  if(dl->dl_ip_off != 0)
    return;

  if(SCAMPER_DL_IS_ICMP(dl))
    {
      if(SCAMPER_DL_IS_ICMP_ECHO_REPLY(dl) ||
	 SCAMPER_DL_IS_ICMP_TIME_REPLY(dl))
	{
	  if((SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping) &&
	      SCAMPER_DL_IS_ICMP_ECHO_REPLY(dl) == 0) ||
	     (SCAMPER_PING_METHOD_IS_ICMP_TIME(ping) &&
	      SCAMPER_DL_IS_ICMP_TIME_REPLY(dl) == 0) ||
	     scamper_addr_raw_cmp(ping->src, dl->dl_ip_dst) != 0 ||
	     scamper_addr_raw_cmp(ping->dst, dl->dl_ip_src) != 0 ||
	     dl->dl_icmp_id != ping->sport)
	    return;

	  direction = DIR_INBOUND;
	  seq = dl->dl_icmp_seq;
	  if(seq < ping->dport)
	    seq = seq + 0x10000;
	  seq = seq - ping->dport;

	  /*
	   * keep a quote of an ICMP echo reply if we're trying to get it to
	   * send a fragmented response.
	   */
	  if(ping->pmtu != 0 && ping->pmtu < dl->dl_ip_size &&
	     state->quote == NULL)
	    {
	      if(dl->dl_af == AF_INET)
		u16 = dl->dl_ip_hl + 8;
	      else if(dl->dl_ip_size >= 1280-40-8)
		u16 = 1280 - 40 - 8;
	      else
		u16 = dl->dl_ip_size;

	      if((state->quote = memdup(dl->dl_net_raw, u16)) != NULL)
		{
		  state->quote_len = u16;
		  state->ptb = 1;
		  scamper_task_queue_probe(task);
		}
	    }
	}
      else if(SCAMPER_DL_IS_ICMP_ECHO_REQUEST(dl))
	{
	  if(SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping) == 0 ||
	     dl->dl_icmp_id != ping->sport ||
	     scamper_addr_raw_cmp(ping->src, dl->dl_ip_src) != 0 ||
	     scamper_addr_raw_cmp(ping->dst, dl->dl_ip_dst) != 0)
	    return;

	  direction = DIR_OUTBOUND;
	  seq = dl->dl_icmp_seq;
	  if(seq < ping->dport)
	    seq = seq + 0x10000;
	  seq = seq - ping->dport;
	}
      else if(SCAMPER_DL_IS_ICMP_UNREACH(dl) ||
	      SCAMPER_DL_IS_ICMP_TTL_EXP(dl) ||
	      SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl) ||
	      SCAMPER_DL_IS_ICMP_PARAMPROB(dl))
	{
	  if(scamper_addr_raw_cmp(ping->dst, dl->dl_icmp_ip_dst) != 0)
	    return;

	  direction = DIR_INBOUND;
	  if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	    {
	      if((SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping) &&
		  SCAMPER_DL_IS_ICMP_Q_ICMP_ECHO_REQ(dl) == 0) ||
		 (SCAMPER_PING_METHOD_IS_ICMP_TIME(ping) &&
		  SCAMPER_DL_IS_ICMP_Q_ICMP_TIME_REQ(dl) == 0) ||
		 dl->dl_icmp_icmp_id != ping->sport)
		return;
	      seq = dl->dl_icmp_icmp_seq;
	      if(seq < ping->dport)
		seq = seq + 0x10000;
	      seq = seq - ping->dport;
	    }
	  else if(SCAMPER_PING_METHOD_IS_TCP(ping))
	    {
	      if(SCAMPER_DL_IS_ICMP_Q_TCP(dl) == 0 ||
		 dl->dl_icmp_tcp_dport != ping->dport)
		return;
	      if(SCAMPER_PING_METHOD_IS_VARY_SPORT(ping) == 0)
		{
		  if(dl->dl_icmp_tcp_sport != ping->sport)
		    return;
		  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		    seq = match_ipid(task, dl->dl_icmp_ip_id);
		  else
		    seq = state->seq - 1;
		}
	      else
		{
		  for(u16=0; u16<state->seq; u16++)
		    if(state->sports[u16] == dl->dl_icmp_tcp_sport)
		      break;
		  if(u16 == state->seq)
		    return;
		  seq = u16;
		}
	    }
	  else if(SCAMPER_PING_METHOD_IS_UDP(ping))
	    {
	      if(SCAMPER_DL_IS_ICMP_Q_UDP(dl) == 0)
		return;
	      if(ping->method == SCAMPER_PING_METHOD_UDP)
		{
		  if(dl->dl_icmp_udp_sport != ping->sport ||
		     dl->dl_icmp_udp_dport != ping->dport)
		    return;
		  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		    seq = match_ipid(task, dl->dl_icmp_ip_id);
		  else
		    seq = state->seq - 1;
		}
	      else if(ping->method == SCAMPER_PING_METHOD_UDP_DPORT)
		{
		  if(dl->dl_icmp_udp_sport != ping->sport ||
		     dl->dl_icmp_udp_dport > ping->dport + state->seq ||
		     dl->dl_icmp_udp_dport < ping->dport)
		    return;
		  seq = dl->dl_icmp_udp_dport - ping->dport;
		}
	      else if(ping->method == SCAMPER_PING_METHOD_UDP_SPORT)
		{
		  if(dl->dl_icmp_udp_dport != ping->dport)
		    return;
		  for(u16=0; u16<state->seq; u16++)
		    if(state->sports[u16] == dl->dl_icmp_udp_sport)
		      break;
		  if(u16 == state->seq)
		    return;
		  seq = u16;
		}
	      else return;
	    }
	  else return;
	}
      else return;

      if(direction == DIR_INBOUND && SCAMPER_PING_FLAG_IS_SOCKRX(ping))
	return;
    }
  else if(SCAMPER_DL_IS_TCP(dl))
    {
      if(SCAMPER_PING_METHOD_IS_TCP(ping) == 0)
	return;

      /*
       * TCP ping methods do not currently vary the destination port.
       * therefore, any packet with a destination port matching the
       * destination port we probed is inferred to be an outbound
       * packet.  also check flags field is consistent with the probe
       * method
       */
      if(dl->dl_tcp_dport == ping->dport &&
	 scamper_addr_raw_cmp(ping->src, dl->dl_ip_src) == 0 &&
	 scamper_addr_raw_cmp(ping->dst, dl->dl_ip_dst) == 0 &&
	 ((ping->method == SCAMPER_PING_METHOD_TCP_ACK &&
	   dl->dl_tcp_flags == TH_ACK) ||
	  (ping->method == SCAMPER_PING_METHOD_TCP_ACK_SPORT &&
	   dl->dl_tcp_flags == TH_ACK) ||
	  (ping->method == SCAMPER_PING_METHOD_TCP_SYN &&
	   dl->dl_tcp_flags == TH_SYN) ||
	  (ping->method == SCAMPER_PING_METHOD_TCP_SYNACK &&
	   dl->dl_tcp_flags == (TH_SYN | TH_ACK)) ||
	  (ping->method == SCAMPER_PING_METHOD_TCP_RST &&
	   dl->dl_tcp_flags == TH_RST) ||
	  (ping->method == SCAMPER_PING_METHOD_TCP_SYN_SPORT &&
	   dl->dl_tcp_flags == TH_SYN)))
	{
	  if(SCAMPER_PING_METHOD_IS_VARY_SPORT(ping) == 0)
	    {
	      /* we send a series of probes using the same src port */
	      if(dl->dl_tcp_sport != ping->sport)
		return;

	      /*
	       * for TCP targets that might echo the IPID, use that to match
	       * probes. note that there exists the possibility that replies
	       * might be associated with the wrong probe by random chance.
	       */
	      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		seq = match_ipid(task, dl->dl_ip_id);
	      else
		seq = state->seq - 1;
	    }
	  else
	    {
	      for(u16=0; u16<state->seq; u16++)
		if(state->sports[u16] == dl->dl_tcp_sport)
		  break;
	      if(u16 == state->seq)
		return;
	      seq = u16;
	    }

	  direction = DIR_OUTBOUND;
	}
      else if(dl->dl_tcp_sport == ping->dport &&
	      scamper_addr_raw_cmp(ping->src, dl->dl_ip_dst) == 0 &&
	      scamper_addr_raw_cmp(ping->dst, dl->dl_ip_src) == 0)
	{
	  if(SCAMPER_PING_METHOD_IS_VARY_SPORT(ping) == 0)
	    {
	      /* we send a series of probes using the same src port */
	      if(dl->dl_tcp_dport != ping->sport)
		return;

	      /*
	       * for TCP targets that might echo the IPID, use that to match
	       * probes. note that there exists the possibility that replies
	       * might be associated with the wrong probe by random chance.
	       */
	      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		seq = match_ipid(task, dl->dl_ip_id);
	      else
		seq = state->seq - 1;
	    }
	  else
	    {
	      for(u16=0; u16<state->seq; u16++)
		if(state->sports[u16] == dl->dl_tcp_dport)
		  break;
	      if(u16 == state->seq)
		return;
	      seq = u16;
	    }

	  direction = DIR_INBOUND;
	}
      else return;
    }
  else if(SCAMPER_DL_IS_UDP(dl))
    {
      if(ping->method == SCAMPER_PING_METHOD_UDP)
	{
	  /* make sure the src/dst ports exactly match */
	  if(ping->sport == dl->dl_udp_dport &&
	     ping->dport == dl->dl_udp_sport &&
	     scamper_addr_raw_cmp(ping->src, dl->dl_ip_dst) == 0 &&
	     scamper_addr_raw_cmp(ping->dst, dl->dl_ip_src) == 0)
	    {
	      direction = DIR_INBOUND;
	      seq = state->seq - 1;
	    }
	  else if(ping->sport == dl->dl_udp_sport &&
		  ping->dport == dl->dl_udp_dport &&
		  scamper_addr_raw_cmp(ping->src, dl->dl_ip_src) == 0 &&
		  scamper_addr_raw_cmp(ping->dst, dl->dl_ip_dst) == 0)
	    {
	      direction = DIR_OUTBOUND;
	      seq = state->seq - 1;
	    }
	  else return;
	}
      else if(ping->method == SCAMPER_PING_METHOD_UDP_DPORT)
	{
	  if(ping->sport == dl->dl_udp_dport &&
	     ping->dport <= dl->dl_udp_sport &&
	     scamper_addr_raw_cmp(ping->src, dl->dl_ip_dst) == 0 &&
	     scamper_addr_raw_cmp(ping->dst, dl->dl_ip_src) == 0)
	    {
	      direction = DIR_INBOUND;
	      seq = dl->dl_udp_sport - ping->dport;
	    }
	  else if(ping->sport == dl->dl_udp_sport &&
		  ping->dport <= dl->dl_udp_dport &&
		  scamper_addr_raw_cmp(ping->src, dl->dl_ip_src) == 0 &&
		  scamper_addr_raw_cmp(ping->dst, dl->dl_ip_dst) == 0)
	    {
	      direction = DIR_OUTBOUND;
	      seq = dl->dl_udp_dport - ping->dport;
	    }
	  else return;
	}
      else if(ping->method == SCAMPER_PING_METHOD_UDP_SPORT)
	{
	  if(ping->dport == dl->dl_udp_sport &&
	     scamper_addr_raw_cmp(ping->src, dl->dl_ip_dst) == 0 &&
	     scamper_addr_raw_cmp(ping->dst, dl->dl_ip_src) == 0)
	    {
	      direction = DIR_INBOUND;
	      sport = dl->dl_udp_dport;
	    }
	  else if(ping->dport == dl->dl_udp_dport &&
		  scamper_addr_raw_cmp(ping->src, dl->dl_ip_src) == 0 &&
		  scamper_addr_raw_cmp(ping->dst, dl->dl_ip_dst) == 0)
	    {
	      direction = DIR_OUTBOUND;
	      sport = dl->dl_udp_sport;
	    }
	  else return;
	  for(u16=0; u16<state->seq; u16++)
	    if(state->sports[u16] == sport)
	      break;
	  if(u16 == state->seq)
	    return;
	  seq = u16;
	}
      else return;
    }
  else return;

  if(seq >= state->seq)
    return;

  /* this is probably the probe which goes with the reply */
  probe = ping->probes[seq];
  assert(probe != NULL);

  /* timestamp from the datalink cannot be before when the probe was sent */
  if(timeval_cmp(&dl->dl_tv, &probe->tx) < 0)
    return;

  if(direction == DIR_INBOUND)
    {
      /* allocate a reply structure for the response */
      if((reply = scamper_ping_reply_alloc()) == NULL)
	{
	  printerror(__func__, "could not alloc ping reply");
	  goto err;
	}

      /* record where the response came from */
      if((reply->addr = ping_addr(ping, state, dl->dl_ip_src)) == NULL)
	goto err;

      /* put together details of the reply */
      timeval_diff_tv(&reply->rtt, &probe->tx, &dl->dl_tv);
      reply->flags       = probe->flags;
      reply->size        = dl->dl_ip_size;
      reply->proto       = dl->dl_ip_proto;
      reply->ttl         = dl->dl_ip_ttl;
      reply->flags      |= SCAMPER_PING_REPLY_FLAG_REPLY_TTL;
      reply->flags      |= SCAMPER_PING_REPLY_FLAG_DLRX;

      if(SCAMPER_DL_IS_TCP(dl))
	{
	  scamper_dl_rec_tcp_print(dl);
	  reply->tcp_flags = dl->dl_tcp_flags;
	  reply->tcp_mss   = dl->dl_tcp_mss;
	}
      else if(SCAMPER_DL_IS_ICMP(dl))
	{
	  scamper_dl_rec_icmp_print(dl);
	  reply->icmp_type = dl->dl_icmp_type;
	  reply->icmp_code = dl->dl_icmp_code;

	  if(SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl))
	    reply->icmp_nhmtu = dl->dl_icmp_nhmtu;
	}

      if(dl->dl_af == AF_INET)
	{
	  reply->ipid32 = dl->dl_ip_id;
	  reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_IPID;
	}
      else if(dl->dl_af == AF_INET6 && SCAMPER_DL_IS_IP_FRAG(dl))
	{
	  reply->ipid32 = dl->dl_ip6_id;
	  reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_IPID;
	}

      reply->tos = dl->dl_ip_tos;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_TOS;

      reply->ifname = scamper_ifname_int_get(dl->dl_ifindex, &dl->dl_tv);

      if(probe->replyc == 0)
	{
	  if(SCAMPER_PING_FLAG_IS_TBT(ping) == 0)
	    {
	      /*
	       * if this is the first reply we have for this probe,
	       * then increment the replies counter we keep state with
	       */
	      state->replies++;
	    }
	  else
	    {
	      if(state->replies == 0 &&
		 SCAMPER_PING_REPLY_IS_ICMP_ECHO_REPLY(reply) == 0)
		{
		  /*
		   * when doing TBT, anything that is not an echo reply causes
		   * TBT to halt
		   */
		  ping_stop(task, SCAMPER_PING_STOP_COMPLETED, 0);
		}
	      else if(reply->flags & SCAMPER_PING_REPLY_FLAG_REPLY_IPID)
		{
		  /* when doing TBT, only packets with an IPID count */
		  state->replies++;
		}
	    }
	}

      /* put the reply into the ping table */
      if(scamper_ping_probe_reply_append(probe, reply) != 0)
	goto err;

      /*
       * if only a certain number of replies are required, and we've reached
       * that amount, then stop probing
       */
      if(ping->stop_count != 0 && state->replies >= ping->stop_count)
	ping_stop(task, SCAMPER_PING_STOP_COMPLETED, 0);
    }
  else
    {
      /* outbound packet */
      if((probe->flags & SCAMPER_PING_REPLY_FLAG_DLTX) != 0)
	return;

      timeval_diff_tv(&diff, &probe->tx, &dl->dl_tv);
      scamper_debug(__func__, "outbound %ld.%06d %ld.%06d diff %ld.%06d",
		    (long)probe->tx.tv_sec, (int)probe->tx.tv_usec,
		    (long)dl->dl_tv.tv_sec, (int)dl->dl_tv.tv_usec,
		    (long)diff.tv_sec, (int)diff.tv_usec);

      if(probe->replyc > 0)
	{
	  usec = ((int)diff.tv_sec * 1000000) + diff.tv_usec;
	  for(u16=0; u16 < probe->replyc; u16++)
	    {
	      reply = probe->replies[u16];
	      if(timeval_cmp(&diff, &reply->rtt) > 0)
		continue;
	      timeval_sub_us(&reply->rtt, &reply->rtt, usec);
	      reply->flags |= SCAMPER_PING_REPLY_FLAG_DLTX;
	    }
	}

      probe->flags |= SCAMPER_PING_REPLY_FLAG_DLTX;
      timeval_cpy(&probe->tx, &dl->dl_tv);
    }

  return;

 err:
  ping_handleerror(task, errno);
  return;
}

static void do_ping_handle_icmp(scamper_task_t *task, scamper_icmp_resp_t *ir)
{
  scamper_ping_t            *ping  = ping_getdata(task);
  ping_state_t              *state = ping_getstate(task);
  scamper_ping_reply_t      *reply = NULL;
  scamper_ping_probe_t      *probe;
  int                        seq;
  scamper_addr_t             addr;
  uint8_t                    i, ipc = 0, tsc = 0;
  struct in_addr            *ips = NULL, *tsips = NULL;
  uint32_t                  *tstss = NULL;
  scamper_ping_reply_v4rr_t *v4rr;
  scamper_ping_reply_v4ts_t *v4ts;
  uint16_t                   s;

  /* if we haven't sent a probe yet */
  if(state == NULL || state->seq == 0)
    return;

  /*
   * do not consider ICMP responses if we're going to catch them on
   * the datalink interface
   */
  if(state->dl != NULL && SCAMPER_PING_FLAG_IS_SOCKRX(ping) == 0)
    return;

  /* if this is an echo reply packet, then check the id and sequence */
  if(SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir) || SCAMPER_ICMP_RESP_IS_TIME_REPLY(ir))
    {
      /* if the response is not for us, then move on */
      if(((SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping) &&
	   SCAMPER_ICMP_RESP_IS_ECHO_REPLY(ir)) ||
	  (SCAMPER_PING_METHOD_IS_ICMP_TIME(ping) &&
	   SCAMPER_ICMP_RESP_IS_TIME_REPLY(ir))) == 0)
	return;
      if(ir->ir_icmp_id != ping->sport)
	return;

      seq = ir->ir_icmp_seq;
      if(seq < ping->dport)
	seq = seq + 0x10000;
      seq = seq - ping->dport;

      if(ir->ir_af == AF_INET)
	{
	  if(ir->ir_ipopt_rrc > 0)
	    {
	      ipc = ir->ir_ipopt_rrc;
	      ips = ir->ir_ipopt_rrs;
	    }
	  if(ir->ir_ipopt_tsc > 0)
	    {
	      tsc   = ir->ir_ipopt_tsc;
	      tstss = ir->ir_ipopt_tstss;
	      tsips = ir->ir_ipopt_tsips;
	    }
	}
    }
  else if(SCAMPER_ICMP_RESP_INNER_IS_SET(ir))
    {
      if(SCAMPER_ICMP_RESP_IS_UNREACH(ir) == 0 &&
	 SCAMPER_ICMP_RESP_IS_TTL_EXP(ir) == 0 &&
	 SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir) == 0 &&
	 SCAMPER_ICMP_RESP_IS_PARAMPROB(ir) == 0)
	{
	  return;
	}

      if(ir->ir_inner_ip_off != 0)
	return;

      if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	{
	  if(ir->ir_inner_icmp_id != ping->sport)
	    return;

	  if((SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping) &&
	      SCAMPER_ICMP_RESP_INNER_IS_ICMP_ECHO_REQ(ir) == 0) ||
	     (SCAMPER_PING_METHOD_IS_ICMP_TIME(ping) &&
	      SCAMPER_ICMP_RESP_INNER_IS_ICMP_TIME_REQ(ir) == 0))
	    return;

	  seq = ir->ir_inner_icmp_seq;
	  if(seq < ping->dport)
	    seq = seq + 0x10000;
	  seq = seq - ping->dport;
	}
      else if(SCAMPER_PING_METHOD_IS_TCP(ping))
	{
	  if(SCAMPER_ICMP_RESP_INNER_IS_TCP(ir) == 0 ||
	     ir->ir_inner_tcp_dport != ping->dport)
	    return;

	  if(SCAMPER_PING_METHOD_IS_VARY_SPORT(ping) == 0)
	    {
	      if(ir->ir_inner_tcp_sport != ping->sport)
		return;
	      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		seq = match_ipid(task, ir->ir_inner_ip_id);
	      else
		seq = state->seq - 1;
	    }
	  else
	    {
	      for(s=0; s<state->seq; s++)
		if(state->sports[s] == ir->ir_inner_tcp_sport)
		  break;
	      if(s == state->seq)
		return;
	      seq = s;
	    }
	}
      else if(SCAMPER_PING_METHOD_IS_UDP(ping))
	{
	  if(SCAMPER_ICMP_RESP_INNER_IS_UDP(ir) == 0)
	    return;

	  if(ping->method == SCAMPER_PING_METHOD_UDP)
	    {
	      if(ir->ir_inner_udp_sport != ping->sport ||
		 ir->ir_inner_udp_dport != ping->dport)
		return;
	      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		seq = match_ipid(task, ir->ir_inner_ip_id);
	      else
		seq = state->seq - 1;
	    }
	  else if(ping->method == SCAMPER_PING_METHOD_UDP_DPORT)
	    {
	      if(ir->ir_inner_udp_sport != ping->sport ||
		 ir->ir_inner_udp_dport > ping->dport + state->seq ||
		 ir->ir_inner_udp_dport < ping->dport)
		return;
	      seq = ir->ir_inner_udp_dport - ping->dport;
	    }
	  else if(ping->method == SCAMPER_PING_METHOD_UDP_SPORT)
	    {
	      if(ir->ir_inner_udp_dport != ping->dport)
		return;
	      for(s=0; s<state->seq; s++)
		if(state->sports[s] == ir->ir_inner_udp_sport)
		  break;
	      if(s == state->seq)
		return;
	      seq = s;
	    }
	  else
	    {
	      return;
	    }
	}
      else
	{
	  return;
	}

      if(ir->ir_af == AF_INET)
	{
	  if(ir->ir_inner_ipopt_rrc > 0)
	    {
	      ipc = ir->ir_inner_ipopt_rrc;
	      ips = ir->ir_inner_ipopt_rrs;
	    }
	  if(ir->ir_inner_ipopt_tsc > 0)
	    {
	      tsc   = ir->ir_inner_ipopt_tsc;
	      tstss = ir->ir_inner_ipopt_tstss;
	      tsips = ir->ir_inner_ipopt_tsips;
	    }
	}
    }
  else return;

  if(seq >= state->seq)
    return;

  probe = ping->probes[seq];
  assert(probe != NULL);

  /* allocate a reply structure for the response */
  if((reply = scamper_ping_reply_alloc()) == NULL)
    {
      goto err;
    }

  /* figure out where the response came from */
  if(scamper_icmp_resp_src(ir, &addr) != 0)
    goto err;
  if((reply->addr = ping_addr(ping, state, addr.addr)) == NULL)
    goto err;

  /* put together details of the reply */
  timeval_diff_tv(&reply->rtt, &probe->tx, &ir->ir_rx);
  reply->flags       = probe->flags;
  reply->size        = ir->ir_ip_size;
  reply->icmp_type   = ir->ir_icmp_type;
  reply->icmp_code   = ir->ir_icmp_code;

  if(SCAMPER_ICMP_RESP_IS_PACKET_TOO_BIG(ir))
    {
      reply->icmp_nhmtu = ir->ir_icmp_nhmtu;
    }
  else if(SCAMPER_ICMP_RESP_IS_TIME_REPLY(ir))
    {
      if((reply->tsreply = scamper_ping_reply_tsreply_alloc()) == NULL)
	goto err;
      reply->tsreply->tso = ir->ir_icmp_tso;
      reply->tsreply->tsr = ir->ir_icmp_tsr;
      reply->tsreply->tst = ir->ir_icmp_tst;
    }

  if(ir->ir_af == AF_INET)
    {
      reply->ipid32 = ir->ir_ip_id;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_IPID;
      reply->tos = ir->ir_ip_tos;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_TOS;
      reply->proto = IPPROTO_ICMP;

      if(ips != NULL && ipc > 0)
	{
	  if((v4rr = scamper_ping_reply_v4rr_alloc(ipc)) == NULL)
	    goto err;
	  reply->v4rr = v4rr;

	  for(i=0; i<ipc; i++)
	    if((v4rr->ip[i] = scamper_addr_alloc_ipv4(&ips[i])) == NULL)
	      goto err;
	}

      if((ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_IPOPT_TS) ||
	 (ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_INNER_IPOPT_TS))
	{
	  v4ts = scamper_ping_reply_v4ts_alloc(tsc, tsips != NULL ? 1 : 0);
	  if(v4ts == NULL)
	    goto err;
	  reply->v4ts = v4ts;

	  if(tsc > 0 && tstss != NULL)
	    {
	      v4ts->tsc = tsc;
	      for(i=0; i<tsc; i++)
		{
		  if(tsips != NULL &&
		     (v4ts->ips[i]=scamper_addr_alloc_ipv4(&tsips[i])) == NULL)
		    goto err;
		  v4ts->tss[i] = tstss[i];
		}
	    }
	}
    }
  else if(ir->ir_af == AF_INET6)
    {
      reply->proto = IPPROTO_ICMPV6;
      if(ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_TCLASS)
	{
	  reply->tos = ir->ir_ip_tos;
	  reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_TOS;
	}
    }

  if(ir->ir_ip_ttl != -1)
    {
      reply->ttl = (uint8_t)ir->ir_ip_ttl;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_TTL;
    }

  if(ir->ir_flags & SCAMPER_ICMP_RESP_FLAG_IFINDEX)
    reply->ifname = scamper_ifname_int_get(ir->ir_ifindex, &ir->ir_rx);

  /*
   * if this is the first reply we have for this probe, then increment
   * the replies counter we keep state with
   */
  if(probe->replyc == 0)
    state->replies++;

  /* put the reply into the ping table */
  if(scamper_ping_probe_reply_append(probe, reply) != 0)
    goto err;

  /*
   * if only a certain number of replies are required, and we've reached
   * that amount, then stop probing
   */
  if(ping->stop_count != 0 && state->replies >= ping->stop_count)
    ping_stop(task, SCAMPER_PING_STOP_COMPLETED, 0);

  return;

 err:
  if(reply != NULL) scamper_ping_reply_free(reply);
  ping_handleerror(task, errno);
  return;
}

/*
 * do_ping_handle_timeout
 *
 * the ping object expired on the pending queue
 * that means it is either time to send the next probe, or write the
 * task out
 */
static void do_ping_handle_timeout(scamper_task_t *task)
{
  scamper_ping_t *ping = ping_getdata(task);
  ping_state_t *state = ping_getstate(task);

#ifdef HAVE_SCAMPER_DEBUG
  char buf[128];
#endif

  if(state->mode == MODE_PING)
    {
      if(state->seq == ping->attempts)
	ping_stop(task, SCAMPER_PING_STOP_COMPLETED, 0);
    }
  else
    {
      scamper_debug(__func__, "mode %d dst %s", state->mode,
		    scamper_addr_tostr(ping->dst, buf, sizeof(buf)));
      ping_stop(task, SCAMPER_PING_STOP_NONE, 0);
    }

  return;
}

/*
 * ping_handle_dlhdr:
 *
 * this callback function takes an incoming datalink header and deals with
 * it.
 */
static void ping_handle_dlhdr(scamper_dlhdr_t *dlhdr)
{
  scamper_task_t *task = dlhdr->param;
  ping_state_t *state = ping_getstate(task);

  if(dlhdr->error != 0)
    {
      scamper_task_queue_done(task, 0);
      return;
    }

  state->mode = MODE_PING;
  scamper_task_queue_probe(task);
  return;
}

static void ping_handle_rt(scamper_route_t *rt)
{
  scamper_task_t *task = rt->param;
  scamper_ping_t *ping = ping_getdata(task);
  ping_state_t *state = ping_getstate(task);
  struct timeval tv;
  scamper_dl_t *dl;

  if(state->mode != MODE_RTSOCK || state->route != rt)
    goto done;

#ifndef _WIN32 /* windows does not have a routing socket */
  if(state->rtsock != NULL)
    {
      scamper_fd_free(state->rtsock);
      state->rtsock = NULL;
    }
#endif

  if(rt->error != 0 || rt->ifindex < 0)
    {
      printerror(__func__, "could not get ifindex");
      ping_handleerror(task, errno);
      goto done;
    }

  /*
   * if scamper is supposed to get tx timestamps from the datalink, or
   * scamper needs the datalink to transmit packets, then try and get a
   * datalink on the ifindex specified.
   */
  if((state->dl = scamper_fd_dl(rt->ifindex)) == NULL)
    {
      scamper_debug(__func__, "could not get dl for %d", rt->ifindex);
      ping_handleerror(task, errno);
      goto done;
    }
  dl = scamper_fd_dl_get(state->dl);

  if(scamper_dl_tx_type(dl) == SCAMPER_DL_TX_UNSUPPORTED)
    {
      if(ping_dltx(ping) ||
	 (SCAMPER_PING_METHOD_IS_TCP(ping) &&
	  SCAMPER_ADDR_TYPE_IS_IPV6(ping->dst)))
	{
	  scamper_debug(__func__, "need dltx but unsupported for %d",
			rt->ifindex);
	  ping_handleerror(task, 0);
	  goto done;
	}

      /*
       * when doing tcp ping to an IPv4 destination, it isn't the end
       * of the world if we can't probe using a datalink socket, if we can
       * fall back to a raw socket.
       */
      if(SCAMPER_PING_METHOD_IS_TCP(ping) &&
	 SCAMPER_ADDR_TYPE_IS_IPV4(ping->dst) &&
	 state->raw == NULL && (state->raw = scamper_fd_ip4()) == NULL)
	{
	  scamper_debug(__func__, "cannot get rawtcp");
	  ping_handleerror(task, 0);
	  goto done;
	}
    }

  /*
   * if we will need to use the datalink interface, determine the
   * underlying framing to use with each probe packet that will be
   * sent on the datalink.
   */
  if((SCAMPER_PING_METHOD_IS_TCP(ping) && state->raw == NULL) ||
     ping_dltx(ping))
    {
      state->mode = MODE_DLHDR;
      if((state->dlhdr = scamper_dlhdr_alloc()) == NULL)
	{
	  ping_handleerror(task, errno);
	  goto done;
	}
      if(ping->rtr == NULL)
	state->dlhdr->dst = scamper_addr_use(ping->dst);
      else
	state->dlhdr->dst = scamper_addr_use(ping->rtr);
      state->dlhdr->gw = rt->gw != NULL ? scamper_addr_use(rt->gw) : NULL;
      state->dlhdr->ifindex = rt->ifindex;
      state->dlhdr->txtype = scamper_dl_tx_type(dl);
      state->dlhdr->param = task;
      state->dlhdr->cb = ping_handle_dlhdr;
      if(scamper_dlhdr_get(state->dlhdr) != 0)
	{
	  ping_handleerror(task, errno);
	  goto done;
	}
    }
  else
    {
      state->mode = MODE_PING;
      scamper_task_queue_probe(task);
      return;
    }

  if(state->mode == MODE_DLHDR && scamper_task_queue_isdone(task) == 0)
    {
      gettimeofday_wrap(&tv);
      timeval_add_tv(&tv, &ping->wait_timeout);
      scamper_task_queue_wait_tv(task, &tv);
    }

  assert(state->mode != MODE_RTSOCK);

 done:
  scamper_route_free(rt);
  if(state->route == rt)
    state->route = NULL;
  return;
}

static int ping_state_payload(scamper_ping_t *ping, ping_state_t *state)
{
  scamper_addr_t *src;
  int off = 0, al, hdr;
  char errbuf[256];

  /* payload to send in the probe */
  if(SCAMPER_ADDR_TYPE_IS_IPV4(ping->dst))
    {
      al = 4;
      hdr = 20;
      if(SCAMPER_PING_FLAG_IS_V4RR(ping))
	hdr += 40;
      else if(SCAMPER_PING_FLAG_IS_TSONLY(ping))
	hdr += 40;
      else if(SCAMPER_PING_FLAG_IS_TSANDADDR(ping))
	hdr += 36;
      else if(state->tsps_ipc > 0)
	hdr += (state->tsps_ipc * 4 * 2) + 4;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(ping->dst))
    {
      al = 16;
      hdr = 40;
    }
  else
    {
      return -1;
    }

  if(SCAMPER_PING_METHOD_IS_ICMP(ping))
    {
      state->payload_len = ping->size - hdr - 8;
      if(SCAMPER_PING_METHOD_IS_ICMP_TIME(ping))
	state->payload_len -= 12;
    }
  else if(SCAMPER_PING_METHOD_IS_TCP(ping))
    state->payload_len = ping->size - hdr - 20;
  else if(SCAMPER_PING_METHOD_IS_UDP(ping))
    state->payload_len = ping->size - hdr - 8;
  else
    return -1;

  if(state->payload_len == 0)
    return 0;

  if((state->payload = malloc_zero(state->payload_len)) == NULL)
    return -1;

  if(SCAMPER_PING_METHOD_IS_ICMP_TIME(ping))
    {
      assert(state->payload_len > 12);
      memset(state->payload, 0, 12);
      off += 12;
    }

  if(SCAMPER_PING_FLAG_IS_SPOOF(ping) &&
     SCAMPER_PING_FLAG_IS_NOSRC(ping) == 0 &&
     ping->method != SCAMPER_PING_METHOD_TCP_SYNACK &&
     ping->method != SCAMPER_PING_METHOD_TCP_RST)
    {
      assert(state->payload_len >= al);
      /* get the source IP address to embed in the probe */
      if((src = scamper_getsrc(ping->dst, 0, errbuf, sizeof(errbuf))) == NULL)
	return -1;
      memcpy(state->payload + off, src->addr, al);
      off += al;
      scamper_addr_free(src);
    }

  /* need scratch space in the probe to help fudge icmp checksum */
  if(SCAMPER_PING_FLAG_IS_ICMPSUM(ping))
    {
      assert(state->payload_len >= off + 2);
      state->payload[off++] = 0;
      state->payload[off++] = 0;
    }

  if(ping->data != NULL)
    {
      if(SCAMPER_PING_FLAG_IS_PAYLOAD(ping))
	{
	  assert(state->payload_len >= off + ping->datalen);
	  memcpy(state->payload + off, ping->data, ping->datalen);
	  off += ping->datalen;
	}
      else
	{
	  while((size_t)(off + ping->datalen) < state->payload_len)
	    {
	      memcpy(state->payload + off, ping->data, ping->datalen);
	      off += ping->datalen;
	    }
	  memcpy(state->payload + off, ping->data, state->payload_len - off);
	  off = state->payload_len;
	}
    }

  if(state->payload_len > off)
    memset(state->payload+off, 0, state->payload_len-off);

  return 0;
}

static void ping_state_free(ping_state_t *state)
{
  size_t s;

#ifndef _WIN32 /* windows does not have a routing socket */
  if(state->rtsock != NULL)     scamper_fd_free(state->rtsock);
#endif

  if(state->dl != NULL)         scamper_fd_free(state->dl);
  if(state->icmp != NULL)       scamper_fd_free(state->icmp);
  if(state->raw != NULL)        scamper_fd_free(state->raw);
  if(state->route != NULL)      scamper_route_free(state->route);
  if(state->dlhdr != NULL)      scamper_dlhdr_free(state->dlhdr);

  if(state->fds != NULL)
    {
      for(s=0; s<state->fdc; s++)
	if(state->fds[s] != NULL)
	  scamper_fd_free(state->fds[s]);
      free(state->fds);
    }

  if(state->payload != NULL)
    free(state->payload);

  if(state->last_addr != NULL)
    scamper_addr_free(state->last_addr);

  if(state->sports != NULL)
    free(state->sports);

  free(state);
  return;
}

static int ping_state_alloc(scamper_task_t *task)
{
  scamper_ping_t *ping = ping_getdata(task);
  ping_state_t *state = ping_getstate(task);
  int i;

  if(scamper_ping_probes_alloc(ping, ping->attempts) != 0)
    {
      printerror(__func__, "could not malloc probes");
      goto err;
    }

  /* sort out the payload to attach with each probe */
  if(ping_state_payload(ping, state) != 0)
    goto err;

  if(ping->tsps != NULL)
    for(i=0; i<ping->tsps->ipc; i++)
      memcpy(&state->tsps_ips[i], ping->tsps->ips[i]->addr, 4);

  if(SCAMPER_PING_FLAG_IS_DL(ping) ||
     SCAMPER_PING_METHOD_IS_TCP(ping) ||
     ping_dltx(ping))
    {
      state->mode = MODE_RTSOCK;
#ifndef _WIN32 /* windows does not have a routing socket */
      if((state->rtsock = scamper_fd_rtsock()) == NULL)
	goto err;
#endif
    }
  else
    {
      state->mode = MODE_PING;
    }

  if(SCAMPER_PING_FLAG_IS_SPOOF(ping) == 0)
    {
      if(SCAMPER_ADDR_TYPE_IS_IPV4(ping->dst))
	state->icmp = scamper_fd_icmp4(ping->src->addr);
      else if(SCAMPER_ADDR_TYPE_IS_IPV6(ping->dst))
	state->icmp = scamper_fd_icmp6(ping->src->addr);
      if(state->icmp == NULL)
	goto err;
    }

  if(SCAMPER_ADDR_TYPE_IS_IPV4(ping->dst) &&
     SCAMPER_PING_METHOD_IS_UDP(ping))
    {
      state->raw = scamper_fd_udp4raw(ping->src->addr);
    }
  else if(SCAMPER_PING_FLAG_IS_RAW(ping))
    {
      /* probe using a raw TCP socket */
      state->raw = scamper_fd_ip4();
    }

  return 0;

 err:
  return -1;
}

/*
 * do_ping_probe
 *
 * it is time to send a probe for this task.  figure out the form of the
 * probe to send, and then send it.
 */
static void do_ping_probe(scamper_task_t *task)
{
  scamper_ping_t  *ping  = ping_getdata(task);
  ping_state_t    *state = ping_getstate(task);
  scamper_ping_probe_t *pp = NULL;
  scamper_probe_ipopt_t opt;
  struct timeval   wait_tv;
  scamper_probe_t  probe;
  int              i;
  uint16_t         ipid = 0;
  uint16_t         u16;
  struct timeval   tv;

  if(state == NULL)
    {
      ping_handleerror(task, 0);
      return;
    }

  if(ping->probes == NULL)
    {
      /* timestamp the start time of the ping */
      gettimeofday_wrap(&ping->start);

      if(ping_state_alloc(task) != 0)
	goto err;
    }

  if(state->mode == MODE_RTSOCK)
    {
      if(ping->rtr == NULL)
	state->route = scamper_route_alloc(ping->dst, task, ping_handle_rt);
      else
	state->route = scamper_route_alloc(ping->rtr, task, ping_handle_rt);
      if(state->route == NULL)
	goto err;

#ifndef _WIN32 /* windows does not have a routing socket */
      if(scamper_rtsock_getroute(state->rtsock, state->route) != 0)
	goto err;
#else
      if(scamper_rtsock_getroute(state->route) != 0)
	goto err;
#endif

      if(scamper_task_queue_isdone(task))
	return;

      if(state->mode == MODE_RTSOCK || state->mode == MODE_DLHDR)
	{
	  gettimeofday_wrap(&tv);
	  timeval_add_tv(&tv, &ping->wait_timeout);
	  scamper_task_queue_wait_tv(task, &tv);
	  return;
	}
    }

  memset(&probe, 0, sizeof(probe));
  probe.pr_ip_src = ping->src;
  probe.pr_ip_dst = ping->dst;
  probe.pr_rtr    = ping->rtr;
  probe.pr_fd     = socket_invalid();

  if(state->dl != NULL &&
     ((SCAMPER_PING_METHOD_IS_TCP(ping) && state->raw == NULL) ||
      ping_dltx(ping)))
    {
      probe.pr_dl     = scamper_fd_dl_get(state->dl);
      probe.pr_dlhdr  = state->dlhdr;
    }

  if(state->ptb != 0)
    {
      SCAMPER_PROBE_ICMP_PTB(&probe, ping->pmtu);
      probe.pr_ip_ttl = 255;
      probe.pr_data   = state->quote;
      probe.pr_len    = state->quote_len;

      if(scamper_probe(&probe) != 0)
	{
	  errno = probe.pr_errno;
	  goto err;
	}

      /* don't need the quote anymore */
      free(state->quote); state->quote = NULL;
      state->quote_len = 0;
      state->ptb = 0;
      goto queue;
    }

  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      /* select a random IPID value (not zero).  try up to three times */
      for(i=0; i<3; i++)
	{
	  if(random_u16(&ipid) != 0)
	    {
	      printerror(__func__, "could not rand ipid");
	      goto err;
	    }
	  if(ipid != 0)
	    break;
	}
    }

  probe.pr_ip_tos    = ping->tos;
  probe.pr_ip_ttl    = ping->ttl;
  probe.pr_ip_id     = ipid;
  probe.pr_data      = state->payload;
  probe.pr_len       = state->payload_len;

  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    probe.pr_ip_off  = IP_DF;

  if(SCAMPER_PING_FLAG_IS_V4RR(ping))
    {
      opt.type = SCAMPER_PROBE_IPOPTS_V4RR;
      probe.pr_ipopts = &opt;
      probe.pr_ipoptc = 1;
    }
  else if(SCAMPER_PING_FLAG_IS_TSONLY(ping))
    {
      opt.type = SCAMPER_PROBE_IPOPTS_V4TSO;
      probe.pr_ipopts = &opt;
      probe.pr_ipoptc = 1;
    }
  else if(SCAMPER_PING_FLAG_IS_TSANDADDR(ping))
    {
      opt.type = SCAMPER_PROBE_IPOPTS_V4TSAA;
      probe.pr_ipopts = &opt;
      probe.pr_ipoptc = 1;
    }
  else if(ping->tsps != NULL)
    {
      opt.type = SCAMPER_PROBE_IPOPTS_V4TSPS;
      opt.opt_v4tsps_ipc = ping->tsps->ipc;
      memcpy(&opt.opt_v4tsps_ips, &state->tsps_ips, sizeof(opt.opt_v4tsps_ips));
      probe.pr_ipopts = &opt;
      probe.pr_ipoptc = 1;
    }

  if(SCAMPER_PING_METHOD_IS_ICMP(ping))
    {
      i = 0;
      if(SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping))
	{
	  SCAMPER_PROBE_ICMP_ECHO(&probe, ping->sport,
				  ping->dport + state->seq);
	}
      else if(SCAMPER_PING_METHOD_IS_ICMP_TIME(ping))
	{
	  SCAMPER_PROBE_ICMP_TIME(&probe, ping->sport,
				  ping->dport + state->seq);
	  gettimeofday_wrap(&tv);
	  bytes_htonl(state->payload,
		      ((tv.tv_sec % 86400) * 1000) + (tv.tv_usec / 1000));
	  i += 12;
	}

      if(SCAMPER_PING_FLAG_IS_ICMPSUM(ping))
	{
	  probe.pr_icmp_sum = u16 = htons(ping->icmpsum);
	  if(SCAMPER_PING_FLAG_IS_SPOOF(ping))
	    i += 4;
	  memcpy(state->payload+i, &u16, 2);
	  if(SCAMPER_ADDR_TYPE_IS_IPV4(ping->dst))
	    u16 = scamper_icmp4_cksum(&probe);
	  else
	    u16 = scamper_icmp6_cksum(&probe);
	  memcpy(state->payload+i, &u16, 2);
	}

      if(state->icmp != NULL)
	probe.pr_fd = scamper_fd_fd_get(state->icmp);
    }
  else if(SCAMPER_PING_METHOD_IS_TCP(ping))
    {
      probe.pr_ip_proto  = IPPROTO_TCP;
      probe.pr_tcp_dport = ping->dport;
      probe.pr_tcp_sport = ping->sport;
      probe.pr_tcp_seq   = ping->tcpseq;
      probe.pr_tcp_ack   = ping->tcpack;
      probe.pr_tcp_win   = 65535;
      probe.pr_tcp_mss   = ping->tcpmss;

      if(SCAMPER_PING_METHOD_IS_VARY_SPORT(ping))
	probe.pr_tcp_sport = state->sports[state->seq];

      if(ping->method == SCAMPER_PING_METHOD_TCP_ACK)
	probe.pr_tcp_flags = TH_ACK;
      else if(ping->method == SCAMPER_PING_METHOD_TCP_ACK_SPORT)
	probe.pr_tcp_flags = TH_ACK;
      else if(ping->method == SCAMPER_PING_METHOD_TCP_SYN)
	probe.pr_tcp_flags = TH_SYN;
      else if(ping->method == SCAMPER_PING_METHOD_TCP_SYNACK)
	probe.pr_tcp_flags = TH_SYN | TH_ACK;
      else if(ping->method == SCAMPER_PING_METHOD_TCP_RST)
	probe.pr_tcp_flags = TH_RST;
      else if(ping->method == SCAMPER_PING_METHOD_TCP_SYN_SPORT)
	probe.pr_tcp_flags = TH_SYN;

      if(state->raw != NULL)
	probe.pr_fd = scamper_fd_fd_get(state->raw);
    }
  else if(SCAMPER_PING_METHOD_IS_UDP(ping))
    {
      probe.pr_ip_proto  = IPPROTO_UDP;
      if(ping->method == SCAMPER_PING_METHOD_UDP)
	{
	  probe.pr_udp_sport = ping->sport;
	  probe.pr_udp_dport = ping->dport;
	}
      else if(ping->method == SCAMPER_PING_METHOD_UDP_DPORT)
	{
	  probe.pr_udp_sport = ping->sport;
	  probe.pr_udp_dport = ping->dport + state->seq;
	}
      else if(ping->method == SCAMPER_PING_METHOD_UDP_SPORT)
	{
	  probe.pr_udp_sport = state->sports[state->seq];
	  probe.pr_udp_dport = ping->dport;
	}

      if(state->raw != NULL)
	probe.pr_fd = scamper_fd_fd_get(state->raw);
      else if(state->fds != NULL && SCAMPER_ADDR_TYPE_IS_IPV6(ping->dst))
	{
	  if(SCAMPER_PING_METHOD_IS_VARY_SPORT(ping))
	    probe.pr_fd = scamper_fd_fd_get(state->fds[state->seq]);
	  else
	    probe.pr_fd = scamper_fd_fd_get(state->fds[0]);
	}
    }
  else
    {
      scamper_debug(__func__, "unknown ping method %d", ping->method);
      goto err;
    }

  /*
   * allocate a ping probe state record before we try and send the probe
   * as there is no point sending something into the wild that we can't
   * record
   */
  if((pp = malloc_zero(sizeof(scamper_ping_probe_t))) == NULL)
    goto err;

  if(scamper_probe(&probe) != 0)
    {
      errno = probe.pr_errno;
      goto err;
    }

  /* fill out the details of the probe sent */
  timeval_cpy(&pp->tx, &probe.pr_tx);
  pp->id = state->seq;
  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      pp->flags = SCAMPER_PING_REPLY_FLAG_PROBE_IPID;
      pp->ipid = ipid;
    }
  if(state->sports != NULL && state->seq > 0)
    pp->sport = state->sports[state->seq];
  ping->probes[state->seq] = pp;
  state->seq++;
  ping->ping_sent++;

 queue:
  if(ping->ping_sent < ping->attempts)
    timeval_add_tv3(&wait_tv, &probe.pr_tx, &ping->wait_probe);
  else
    timeval_add_tv3(&wait_tv, &probe.pr_tx, &ping->wait_timeout);

  scamper_task_queue_wait_tv(task, &wait_tv);
  return;

 err:
  if(pp != NULL) free(pp);
  ping_handleerror(task, errno);
  return;
}

static void do_ping_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_file_write_ping(sf, ping_getdata(task), task);
  return;
}

static void do_ping_halt(scamper_task_t *task)
{
  ping_stop(task, SCAMPER_PING_STOP_HALTED, 0);
  return;
}

static void do_ping_free(scamper_task_t *task)
{
  scamper_ping_t *ping;
  ping_state_t *state;

  if((ping = ping_getdata(task)) != NULL)
    scamper_ping_free(ping);

  if((state = ping_getstate(task)) != NULL)
    ping_state_free(state);

  return;
}

static void do_ping_sigs(scamper_task_t *task)
{
  scamper_ping_t *ping = ping_getdata(task);
  ping_state_t *state = ping_getstate(task);
  scamper_task_sig_t *sig = NULL;
  char errbuf[256];
  size_t errlen = sizeof(errbuf);
  size_t i;
  uint16_t sp;

#ifdef HAVE_SCAMPER_DEBUG
  const char *typestr;
#endif

  /*
   * this function might have already been called if the task was held
   * because its signature overlapped with another task.
   */
  if(state != NULL)
    return;

  if((state = malloc_zero(sizeof(ping_state_t))) == NULL)
    {
      scamper_debug(__func__, "could not malloc state");
      goto err;
    }

  /*
   * get the source address we'll use, if we weren't told the source
   * address to use
   */
  if(ping->src == NULL &&
     (ping->src = scamper_getsrc(ping->dst, 0, errbuf, errlen)) == NULL)
    {
      scamper_debug(__func__, "%s", errbuf);
      goto err;
    }

  /*
   * get sports array now, in case we use it to keep track of bound
   * source ports
   */
  if(SCAMPER_PING_METHOD_IS_VARY_SPORT(ping) &&
     (state->sports = malloc_zero(sizeof(uint16_t) * ping->attempts)) == NULL)
    {
      scamper_debug(__func__, "could not malloc sports");
      goto err;
    }

  /*
   * if we're going to bind to sockets, then get the sockets so that
   * we can fill out the task signature
   */
  if(SCAMPER_PING_FLAG_IS_SPOOF(ping) == 0 &&
     (SCAMPER_PING_METHOD_IS_TCP(ping) || SCAMPER_PING_METHOD_IS_UDP(ping)))
    {
      /* allocate a file descriptor for each source port needed */
      if(SCAMPER_PING_METHOD_IS_VARY_SPORT(ping) == 0)
	state->fdc = 1;
      else
	state->fdc = ping->attempts;
      if((state->fds = malloc_zero(sizeof(scamper_fd_t *)*state->fdc)) == NULL)
	{
	  scamper_debug(__func__, "could not malloc fds");
	  goto err;
	}

      for(i=0; i<state->fdc; i++)
	{
	  if(i == 0)
	    sp = ping->sport;
	  else
	    sp = 0;

	  if(SCAMPER_PING_METHOD_IS_TCP(ping))
	    {
#ifdef HAVE_SCAMPER_DEBUG
	      typestr = "tcp";
#endif
	      if(SCAMPER_ADDR_TYPE_IS_IPV4(ping->dst))
		state->fds[i] = scamper_fd_tcp4_dst(NULL, sp,
						    state->sports, i,
						    ping->dst->addr,
						    ping->dport);
	      else
		state->fds[i] = scamper_fd_tcp6_dst(NULL, sp,
						    state->sports, i,
						    ping->dst->addr,
						    ping->dport);
	    }
	  else
	    {
#ifdef HAVE_SCAMPER_DEBUG
	      typestr = "udp";
#endif
	      if(SCAMPER_ADDR_TYPE_IS_IPV4(ping->dst))
		state->fds[i] = scamper_fd_udp4dg_dst(ping->src->addr, sp,
						      state->sports, i,
						      ping->dst->addr,
						      ping->dport);
	      else
		state->fds[i] = scamper_fd_udp6_dst(ping->src->addr, sp,
						    state->sports, i,
						    ping->dst->addr,
						    ping->dport);
	    }
	  if(state->fds[i] == NULL)
	    {
	      scamper_debug(__func__, "could not open %s socket", typestr);
	      goto err;
	    }
	  if(sp == 0)
	    {
	      if(scamper_fd_sport(state->fds[i], &sp) != 0)
		{
		  scamper_debug(__func__, "could not get %s sport", typestr);
		  goto err;
		}
	      if(i == 0)
		ping->sport = sp;
	    }
	  if(state->sports != NULL)
	    state->sports[i] = sp;
	}
    }

  if(state->sports == NULL)
    {
      /* declare task signatures, one for each bound port */
      if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
	{
	  scamper_debug(__func__, "could not alloc task signature");
	  goto err;
	}
      sig->sig_tx_ip_dst = scamper_addr_use(ping->dst);

      if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	{
	  if(ping->method == SCAMPER_PING_METHOD_ICMP_ECHO)
	    SCAMPER_TASK_SIG_ICMP_ECHO(sig, ping->sport);
	  else if(ping->method == SCAMPER_PING_METHOD_ICMP_TIME)
	    SCAMPER_TASK_SIG_ICMP_TIME(sig, ping->sport);
	  else
	    {
	      scamper_debug(__func__, "unhandled icmp probe method");
	      goto err;
	    }

	  if(ping->sport == 0)
	    {
	      ping->sport = scamper_pid_u16();
	      if(ping->method == SCAMPER_PING_METHOD_ICMP_ECHO)
		SCAMPER_TASK_SIG_ICMP_ECHO(sig, ping->sport);
	      else
		SCAMPER_TASK_SIG_ICMP_TIME(sig, ping->sport);
	      if(scamper_task_find(sig) != NULL)
		{
		  /*
		   * then try 5 random 16-bit numbers for the ICMP ID
		   * field.  if they all have current tasks, then this
		   * ping will block on the task with the last random
		   * 16-bit ID value.
		   */
		  for(i=0; i<5; i++)
		    {
		      random_u16(&ping->sport);
		      if(ping->method == SCAMPER_PING_METHOD_ICMP_ECHO)
			SCAMPER_TASK_SIG_ICMP_ECHO(sig, ping->sport);
		      else
			SCAMPER_TASK_SIG_ICMP_TIME(sig, ping->sport);
		      if(scamper_task_find(sig) == NULL)
			break;
		    }
		}
	    }
	}
      else if(SCAMPER_PING_METHOD_IS_UDP(ping))
	{
	  if(ping->method == SCAMPER_PING_METHOD_UDP)
	    SCAMPER_TASK_SIG_UDP(sig, ping->sport, ping->dport);
	  else if(ping->method == SCAMPER_PING_METHOD_UDP_DPORT)
	    SCAMPER_TASK_SIG_UDP_DPORT(sig, ping->sport, ping->dport,
				       ping->dport + ping->attempts - 1);
	  else if(ping->method != SCAMPER_PING_METHOD_UDP_SPORT)
	    {
	      scamper_debug(__func__, "unhandled udp probe method");
	      goto err;
	    }
	}
      else if(SCAMPER_PING_METHOD_IS_TCP(ping))
	{
	  SCAMPER_TASK_SIG_TCP(sig, ping->sport, ping->dport);
	}
      else
	{
	  scamper_debug(__func__, "unhandled probe method %d", ping->method);
	  goto err;
	}

      if(scamper_task_sig_add(task, sig) != 0)
	{
	  scamper_debug(__func__, "could not add signature to task");
	  goto err;
	}
      sig = NULL;
    }
  else
    {
      for(i=0; i<ping->attempts; i++)
	{
	  if((sig=scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
	    {
	      scamper_debug(__func__, "could not alloc task signature");
	      goto err;
	    }
	  sig->sig_tx_ip_dst = scamper_addr_use(ping->dst);
	  if(SCAMPER_PING_METHOD_IS_TCP(ping))
	    SCAMPER_TASK_SIG_TCP(sig, state->sports[i], ping->dport);
	  else
	    SCAMPER_TASK_SIG_UDP(sig, state->sports[i], ping->dport);
	  if(scamper_task_sig_add(task, sig) != 0)
	    {
	      scamper_debug(__func__, "could not add signature to task");
	      goto err;
	    }
	  sig = NULL;
	}
    }

  scamper_task_setstate(task, state);
  return;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  if(state != NULL) ping_state_free(state);
  return;
}

scamper_task_t *scamper_do_ping_alloctask(void *data, scamper_list_t *list,
					  scamper_cycle_t *cycle,
					  char *errbuf, size_t errlen)
{
  scamper_ping_t *ping = (scamper_ping_t *)data;
  scamper_task_t *task = NULL;

  /* allocate a task structure and store the ping with it */
  if((task = scamper_task_alloc(ping, &ping_funcs)) == NULL)
    {
      snprintf(errbuf, errlen, "%s: could not alloc task", __func__);
      return NULL;
    }

  /* associate the list and cycle with the ping */
  ping->list  = scamper_list_use(list);
  ping->cycle = scamper_cycle_use(cycle);

  return task;
}

void scamper_do_ping_free(void *data)
{
  scamper_ping_free((scamper_ping_t *)data);
  return;
}

uint32_t scamper_do_ping_userid(void *data)
{
  return ((scamper_ping_t *)data)->userid;
}

int scamper_do_ping_enabled(void)
{
  return config->ping_enable;
}

void scamper_do_ping_cleanup()
{
  return;
}

int scamper_do_ping_init()
{
  ping_funcs.probe          = do_ping_probe;
  ping_funcs.handle_icmp    = do_ping_handle_icmp;
  ping_funcs.handle_timeout = do_ping_handle_timeout;
  ping_funcs.handle_dl      = do_ping_handle_dl;
  ping_funcs.write          = do_ping_write;
  ping_funcs.task_free      = do_ping_free;
  ping_funcs.halt           = do_ping_halt;
  ping_funcs.sigs           = do_ping_sigs;

  return 0;
}
