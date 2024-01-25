/*
 * scamper_do_ping.c
 *
 * $Id: scamper_ping_do.c,v 1.173 2023/12/24 01:34:46 mjl Exp $
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
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_ping.h"
#include "scamper_ping_int.h"
#include "scamper_getsrc.h"
#include "scamper_icmp_resp.h"
#include "scamper_fds.h"
#include "scamper_rtsock.h"
#include "scamper_task.h"
#include "scamper_dl.h"
#include "scamper_dlhdr.h"
#include "scamper_probe.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_debug.h"
#include "scamper_ping_do.h"
#include "scamper_icmp4.h"
#include "scamper_icmp6.h"
#include "utils.h"

/* the callback functions registered with the ping task */
static scamper_task_funcs_t ping_funcs;

typedef struct ping_probe
{
  struct timeval     tx;
  uint16_t           ipid;
} ping_probe_t;

typedef struct ping_state
{
  ping_probe_t     **probes;
  scamper_addr_t    *last_addr;
  uint16_t           replies;
  uint16_t           seq;
  uint8_t           *payload;
  uint16_t           payload_len;
  struct in_addr     tsps_ips[4];
  uint8_t            tsps_ipc;
  uint8_t            mode;
  uint8_t           *quote;
  uint16_t           quote_len;
} ping_state_t;

#define PING_MODE_PROBE       0
#define PING_MODE_PTB         1

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

  for(seq = state->seq-1; state->probes[seq]->ipid != ipid; seq--)
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
  scamper_ping_t       *ping  = ping_getdata(task);
  ping_state_t         *state = ping_getstate(task);
  scamper_ping_reply_t *reply = NULL;
  ping_probe_t         *probe;
  uint16_t              u16;
  int                   seq = -1;

  if(state == NULL || state->seq == 0)
    return;

  if(dl->dl_ip_off != 0)
    return;

  if(SCAMPER_DL_IS_ICMP(dl))
    {
      if((ping->flags & SCAMPER_PING_FLAG_DL) == 0)
	return;
      
      if(SCAMPER_DL_IS_ICMP_ECHO_REPLY(dl) ||
	 SCAMPER_DL_IS_ICMP_TIME_REPLY(dl))
	{
	  if((SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping) &&
	      SCAMPER_DL_IS_ICMP_ECHO_REPLY(dl) == 0) ||
	     (SCAMPER_PING_METHOD_IS_ICMP_TIME(ping) &&
	      SCAMPER_DL_IS_ICMP_TIME_REPLY(dl) == 0))
	    return;
	  if(dl->dl_icmp_id != ping->probe_sport)
	    return;
	  seq = dl->dl_icmp_seq;
	  if(seq < ping->probe_dport)
	    seq = seq + 0x10000;
	  seq = seq - ping->probe_dport;

	  /*
	   * keep a quote of an ICMP echo reply if we're trying to get it to
	   * send a fragmented response.
	   */
	  if(ping->reply_pmtu != 0 && ping->reply_pmtu < dl->dl_ip_size &&
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
		  state->mode = PING_MODE_PTB;
		  scamper_task_queue_probe(task);
		}
	    }
	}
      else if(SCAMPER_DL_IS_ICMP_UNREACH(dl) ||
	      SCAMPER_DL_IS_ICMP_TTL_EXP(dl) ||
	      SCAMPER_DL_IS_ICMP_PACKET_TOO_BIG(dl) ||
	      SCAMPER_DL_IS_ICMP_PARAMPROB(dl))
	{
	  if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	    {
	      if((SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping) &&
		  SCAMPER_DL_IS_ICMP_Q_ICMP_ECHO_REQ(dl) == 0) ||
		 (SCAMPER_PING_METHOD_IS_ICMP_TIME(ping) &&
		  SCAMPER_DL_IS_ICMP_Q_ICMP_TIME_REQ(dl) == 0))
		return;
	      if(dl->dl_icmp_icmp_id != ping->probe_sport)
		return;
	      seq = dl->dl_icmp_icmp_seq;
	      if(seq < ping->probe_dport)
		seq = seq + 0x10000;
	      seq = seq - ping->probe_dport;
	    }
	  else if(SCAMPER_PING_METHOD_IS_TCP(ping))
	    {
	      if(SCAMPER_DL_IS_ICMP_Q_TCP(dl) == 0 ||
		 dl->dl_icmp_tcp_dport != ping->probe_dport)
		return;
	      if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK)
		{
		  if(dl->dl_icmp_tcp_sport != ping->probe_sport)
		    return;
		  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		    seq = match_ipid(task, dl->dl_icmp_ip_id);
		  else
		    seq = state->seq - 1;
		}
	      else
		{
		  if(dl->dl_icmp_tcp_sport > ping->probe_sport + state->seq ||
		     dl->dl_icmp_tcp_sport < ping->probe_sport)
		    return;
		  seq = dl->dl_icmp_tcp_sport - ping->probe_sport;
		}
	    }
	  else if(SCAMPER_PING_METHOD_IS_UDP(ping))
	    {
	      if(SCAMPER_DL_IS_ICMP_Q_UDP(dl) == 0 ||
		 dl->dl_icmp_udp_sport != ping->probe_sport)
		return;
	      if(ping->probe_method == SCAMPER_PING_METHOD_UDP)
		{
		  if(dl->dl_icmp_udp_dport != ping->probe_dport)
		    return;
		  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		    seq = match_ipid(task, dl->dl_icmp_ip_id);
		  else
		    seq = state->seq - 1;
		}
	      else if(ping->probe_method == SCAMPER_PING_METHOD_UDP_DPORT)
		{
		  if(dl->dl_icmp_udp_dport > ping->probe_dport + state->seq ||
		     dl->dl_icmp_udp_dport < ping->probe_dport)
		    return;
		  seq = dl->dl_icmp_udp_dport - ping->probe_dport;
		}
	    }
	}
    }
  else if(SCAMPER_DL_IS_TCP(dl))
    {
      if(SCAMPER_PING_METHOD_IS_TCP(ping) == 0 ||
	 dl->dl_tcp_sport != ping->probe_dport)
	return;

      if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK ||
	 ping->probe_method == SCAMPER_PING_METHOD_TCP_SYN ||
	 ping->probe_method == SCAMPER_PING_METHOD_TCP_SYNACK ||
	 ping->probe_method == SCAMPER_PING_METHOD_TCP_RST)
	{
	  /* we send a series of probes using the same src port */
	  if(dl->dl_tcp_dport != ping->probe_sport)
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
      else if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK_SPORT ||
	      ping->probe_method == SCAMPER_PING_METHOD_TCP_SYN_SPORT)
	{
	  seq = dl->dl_tcp_dport;
	  if(dl->dl_tcp_dport < ping->probe_sport)
	    seq = seq + 0x10000;
	  seq = seq - ping->probe_sport;
	}
    }
  else if(SCAMPER_DL_IS_UDP(dl))
    {
      if(SCAMPER_PING_METHOD_IS_UDP(ping) == 0)
	return;

      if(ping->probe_method == SCAMPER_PING_METHOD_UDP)
	{
	  if(dl->dl_udp_dport != ping->probe_sport ||
	     dl->dl_udp_sport != ping->probe_dport)
	    return;
	  seq = state->seq - 1;
	}
    }

  if(seq < 0 || seq >= state->seq)
    return;

  /* this is probably the probe which goes with the reply */
  probe = state->probes[seq];
  assert(probe != NULL);

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
  timeval_cpy(&reply->tx, &probe->tx);
  timeval_diff_tv(&reply->rtt, &probe->tx, &dl->dl_tv);
  reply->reply_size  = dl->dl_ip_size;
  reply->reply_proto = dl->dl_ip_proto;
  reply->probe_id    = seq;
  reply->reply_ttl   = dl->dl_ip_ttl;
  reply->flags      |= SCAMPER_PING_REPLY_FLAG_REPLY_TTL;

  if(SCAMPER_DL_IS_TCP(dl))
    {
      scamper_dl_rec_tcp_print(dl);
      reply->tcp_flags = dl->dl_tcp_flags;
    }
  else if(SCAMPER_DL_IS_ICMP(dl))
    {
      scamper_dl_rec_icmp_print(dl);
      reply->icmp_type = dl->dl_icmp_type;
      reply->icmp_code = dl->dl_icmp_code;
    }

  if(dl->dl_af == AF_INET)
    {
      reply->reply_ipid = dl->dl_ip_id;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_IPID;
      reply->probe_ipid = probe->ipid;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_PROBE_IPID;
    }
  else if(dl->dl_af == AF_INET6 && SCAMPER_DL_IS_IP_FRAG(dl))
    {
      reply->reply_ipid32 = dl->dl_ip6_id;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_IPID;
    }

  if(ping->ping_replies[seq] == NULL)
    {
      if((ping->flags & SCAMPER_PING_FLAG_TBT) == 0)
	{
	  /*
	   * if this is the first reply we have for this hop, then increment
	   * the replies counter we keep state with
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
  scamper_ping_reply_append(ping, reply);

  /*
   * if only a certain number of replies are required, and we've reached
   * that amount, then stop probing
   */
  if(ping->reply_count != 0 && state->replies >= ping->reply_count)
    ping_stop(task, SCAMPER_PING_STOP_COMPLETED, 0);

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
  ping_probe_t              *probe;
  int                        seq;
  scamper_addr_t             addr;
  uint8_t                    i, ipc = 0, tsc = 0;
  struct in_addr            *ips = NULL, *tsips = NULL;
  uint32_t                  *tstss = NULL;
  scamper_ping_reply_v4rr_t *v4rr;
  scamper_ping_reply_v4ts_t *v4ts;

  /* if we haven't sent a probe yet */
  if(state == NULL || state->seq == 0)
    return;

  if((ping->flags & SCAMPER_PING_FLAG_DL) != 0)
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
      if(ir->ir_icmp_id != ping->probe_sport)
	return;

      seq = ir->ir_icmp_seq;
      if(seq < ping->probe_dport)
	seq = seq + 0x10000;
      seq = seq - ping->probe_dport;

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
	  if(ir->ir_inner_icmp_id != ping->probe_sport)
	    return;

	  if((SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping) &&
	      SCAMPER_ICMP_RESP_INNER_IS_ICMP_ECHO_REQ(ir) == 0) ||
	     (SCAMPER_PING_METHOD_IS_ICMP_TIME(ping) &&
	      SCAMPER_ICMP_RESP_INNER_IS_ICMP_TIME_REQ(ir) == 0))
	    return;

	  seq = ir->ir_inner_icmp_seq;
	  if(seq < ping->probe_dport)
	    seq = seq + 0x10000;
	  seq = seq - ping->probe_dport;
	}
      else if(SCAMPER_PING_METHOD_IS_TCP(ping))
	{
	  if(SCAMPER_ICMP_RESP_INNER_IS_TCP(ir) == 0 ||
	     ir->ir_inner_tcp_dport != ping->probe_dport)
	    return;

	  if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK)
	    {
	      if(ir->ir_inner_tcp_sport != ping->probe_sport)
		return;
	      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		seq = match_ipid(task, ir->ir_inner_ip_id);
	      else
		seq = state->seq - 1;
	    }
	  else
	    {
	      if(ir->ir_inner_tcp_sport > ping->probe_sport + state->seq ||
		 ir->ir_inner_tcp_sport < ping->probe_sport)
		return;
	      seq = ir->ir_inner_tcp_sport - ping->probe_sport;
	    }
	}
      else if(SCAMPER_PING_METHOD_IS_UDP(ping))
	{
	  if(SCAMPER_ICMP_RESP_INNER_IS_UDP(ir) == 0 ||
	     ir->ir_inner_udp_sport != ping->probe_sport)
	    {
	      return;
	    }

	  if(ping->probe_method == SCAMPER_PING_METHOD_UDP)
	    {
	      if(ir->ir_inner_udp_dport != ping->probe_dport)
		return;
	      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
		seq = match_ipid(task, ir->ir_inner_ip_id);
	      else
		seq = state->seq - 1;
	    }
	  else if(ping->probe_method == SCAMPER_PING_METHOD_UDP_DPORT)
	    {
	      if(ir->ir_inner_udp_dport > ping->probe_dport + state->seq ||
		 ir->ir_inner_udp_dport < ping->probe_dport)
		return;
	      seq = ir->ir_inner_udp_dport - ping->probe_dport;
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

  probe = state->probes[seq];
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
  timeval_cpy(&reply->tx, &probe->tx);
  timeval_diff_tv(&reply->rtt, &probe->tx, &ir->ir_rx);
  reply->reply_size  = ir->ir_ip_size;
  reply->probe_id    = seq;
  reply->icmp_type   = ir->ir_icmp_type;
  reply->icmp_code   = ir->ir_icmp_code;

  if(SCAMPER_ICMP_RESP_IS_TIME_REPLY(ir))
    {
      if((reply->tsreply = scamper_ping_reply_tsreply_alloc()) == NULL)
	goto err;
      reply->tsreply->tso = ir->ir_icmp_tso;
      reply->tsreply->tsr = ir->ir_icmp_tsr;
      reply->tsreply->tst = ir->ir_icmp_tst;
    }

  if(ir->ir_af == AF_INET)
    {
      reply->reply_ipid = ir->ir_ip_id;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_IPID;

      reply->probe_ipid = probe->ipid;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_PROBE_IPID;

      reply->reply_proto = IPPROTO_ICMP;

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
      reply->reply_proto = IPPROTO_ICMPV6;
    }

  if(ir->ir_ip_ttl != -1)
    {
      reply->reply_ttl = (uint8_t)ir->ir_ip_ttl;
      reply->flags |= SCAMPER_PING_REPLY_FLAG_REPLY_TTL;
    }

  /*
   * if this is the first reply we have for this hop, then increment
   * the replies counter we keep state with
   */
  if(ping->ping_replies[seq] == NULL)
    state->replies++;

  /* put the reply into the ping table */
  scamper_ping_reply_append(ping, reply);

  /*
   * if only a certain number of replies are required, and we've reached
   * that amount, then stop probing
   */
  if(ping->reply_count != 0 && state->replies >= ping->reply_count)
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

  if(state->seq == ping->probe_count)
    ping_stop(task, SCAMPER_PING_STOP_COMPLETED, 0);

  return;
}

static int ping_state_payload(scamper_ping_t *ping, ping_state_t *state)
{
  scamper_addr_t *src;
  int off = 0, al, hdr;

  /* payload to send in the probe */
  if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
    {
      al = 4;
      hdr = 20;
      if((ping->flags & SCAMPER_PING_FLAG_V4RR) != 0)
	hdr += 40;
      else if((ping->flags & SCAMPER_PING_FLAG_TSONLY) != 0)
	hdr += 40;
      else if((ping->flags & SCAMPER_PING_FLAG_TSANDADDR) != 0)
	hdr += 36;
      else if(state->tsps_ipc > 0)
	hdr += (state->tsps_ipc * 4 * 2) + 4;
    }
  else if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV6)
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
      state->payload_len = ping->probe_size - hdr - 8;
      if(SCAMPER_PING_METHOD_IS_ICMP_TIME(ping))
	state->payload_len -= 12;
    }
  else if(SCAMPER_PING_METHOD_IS_TCP(ping))
    state->payload_len = ping->probe_size - hdr - 20;
  else if(SCAMPER_PING_METHOD_IS_UDP(ping))
    state->payload_len = ping->probe_size - hdr - 8;
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

  if((ping->flags & SCAMPER_PING_FLAG_SPOOF) != 0 &&
     (ping->flags & SCAMPER_PING_FLAG_NOSRC) == 0 &&
     ping->probe_method != SCAMPER_PING_METHOD_TCP_SYNACK &&
     ping->probe_method != SCAMPER_PING_METHOD_TCP_RST)
    {
      assert(state->payload_len >= al);
      /* get the source IP address to embed in the probe */
      if((src = scamper_getsrc(ping->dst, 0)) == NULL)
	return -1;
      memcpy(state->payload+off, src->addr, al);
      off += al;
      scamper_addr_free(src);
    }

  /* need scratch space in the probe to help fudge icmp checksum */
  if((ping->flags & SCAMPER_PING_FLAG_ICMPSUM) != 0)
    {
      assert(state->payload_len >= off + 2);
      state->payload[off++] = 0;
      state->payload[off++] = 0;
    }

  if(ping->probe_data != NULL)
    {
      if((ping->flags & SCAMPER_PING_FLAG_PAYLOAD) != 0)
	{
	  assert(state->payload_len >= off + ping->probe_datalen);
	  memcpy(state->payload+off, ping->probe_data, ping->probe_datalen);
	  off += ping->probe_datalen;
	}
      else
	{
	  while((size_t)(off + ping->probe_datalen) < state->payload_len)
	    {
	      memcpy(state->payload+off,ping->probe_data,ping->probe_datalen);
	      off += ping->probe_datalen;
	    }
	  memcpy(state->payload+off,ping->probe_data,state->payload_len-off);
	  off = state->payload_len;
	}
    }

  if(state->payload_len > off)
    memset(state->payload+off, 0, state->payload_len-off);

  return 0;
}

static void ping_state_free(ping_state_t *state)
{
  int i;

  if(state->probes != NULL)
    {
      for(i=0; i<state->seq; i++)
	if(state->probes[i] != NULL)
	  free(state->probes[i]);
      free(state->probes);
    }

  if(state->payload != NULL)
    free(state->payload);

  if(state->last_addr != NULL)
    scamper_addr_free(state->last_addr);

  free(state);
  return;
}

static int ping_state_alloc(scamper_task_t *task)
{
  scamper_ping_t *ping = ping_getdata(task);
  ping_state_t *state = NULL;
  size_t size;
  int i;

  if(scamper_ping_replies_alloc(ping, ping->probe_count) != 0)
    {
      printerror(__func__, "could not malloc replies");
      goto err;
    }

  if((state = malloc_zero(sizeof(ping_state_t))) == NULL)
    {
      printerror(__func__, "could not malloc state");
      goto err;
    }
  scamper_task_setstate(task, state);

  size = ping->probe_count * sizeof(ping_probe_t *);
  if((state->probes = malloc_zero(size)) == NULL)
    {
      printerror(__func__, "could not malloc state->probes");
      goto err;
    }

  /* sort out the payload to attach with each probe */
  if(ping_state_payload(ping, state) != 0)
    goto err;

  if(ping->probe_tsps != NULL)
    for(i=0; i<ping->probe_tsps->ipc; i++)
      memcpy(&state->tsps_ips[i], ping->probe_tsps->ips[i]->addr, 4);

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
  scamper_probe_ipopt_t opt;
  struct timeval   wait_tv;
  scamper_ping_t  *ping  = ping_getdata(task);
  ping_state_t    *state = ping_getstate(task);
  ping_probe_t    *pp = NULL;
  scamper_probe_t  probe;
  int              i;
  uint16_t         ipid = 0;
  uint16_t         u16;
  struct timeval   tv;
  int rc = 0;

  if(state == NULL)
    {
      if(ping_state_alloc(task) != 0)
	goto err;
      state = ping_getstate(task);

      /* timestamp the start time of the ping */
      gettimeofday_wrap(&ping->start);
    }

  memset(&probe, 0, sizeof(probe));
  probe.pr_ip_src = ping->src;
  probe.pr_ip_dst = ping->dst;
  probe.pr_rtr = ping->rtr;

  if(ping->flags & SCAMPER_PING_FLAG_DL)
    probe.pr_flags |= SCAMPER_PROBE_FLAG_DL;

  if(state->mode == PING_MODE_PROBE)
    {
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

      probe.pr_flags    |= SCAMPER_PROBE_FLAG_IPID;
      probe.pr_ip_tos    = ping->probe_tos;
      probe.pr_ip_ttl    = ping->probe_ttl;
      probe.pr_ip_id     = ipid;
      probe.pr_data      = state->payload;
      probe.pr_len       = state->payload_len;

      if(ping->dst->type == SCAMPER_ADDR_TYPE_IPV4)
	probe.pr_ip_off  = IP_DF;

      if((ping->flags & SCAMPER_PING_FLAG_SPOOF) != 0)
	probe.pr_flags |= SCAMPER_PROBE_FLAG_SPOOF;

      if((ping->flags & SCAMPER_PING_FLAG_V4RR) != 0)
	{
	  opt.type = SCAMPER_PROBE_IPOPTS_V4RR;
	  probe.pr_ipopts = &opt;
	  probe.pr_ipoptc = 1;
	}
      else if((ping->flags & SCAMPER_PING_FLAG_TSONLY) != 0)
	{
	  opt.type = SCAMPER_PROBE_IPOPTS_V4TSO;
	  probe.pr_ipopts = &opt;
	  probe.pr_ipoptc = 1;
	}
      else if((ping->flags & SCAMPER_PING_FLAG_TSANDADDR) != 0)
	{
	  opt.type = SCAMPER_PROBE_IPOPTS_V4TSAA;
	  probe.pr_ipopts = &opt;
	  probe.pr_ipoptc = 1;
	}
      else if(ping->probe_tsps != NULL)
	{
	  opt.type = SCAMPER_PROBE_IPOPTS_V4TSPS;
	  opt.opt_v4tsps_ipc = ping->probe_tsps->ipc;
	  memcpy(&opt.opt_v4tsps_ips, &state->tsps_ips,
		 sizeof(opt.opt_v4tsps_ips));
	  probe.pr_ipopts = &opt;
	  probe.pr_ipoptc = 1;
	}

      if(SCAMPER_PING_METHOD_IS_ICMP(ping))
	{
	  i = 0;
	  if(SCAMPER_PING_METHOD_IS_ICMP_ECHO(ping))
	    {
	      SCAMPER_PROBE_ICMP_ECHO(&probe, ping->probe_sport,
				      ping->probe_dport + state->seq);
	    }
	  else if(SCAMPER_PING_METHOD_IS_ICMP_TIME(ping))
	    {
	      SCAMPER_PROBE_ICMP_TIME(&probe, ping->probe_sport,
				      ping->probe_dport + state->seq);
	      gettimeofday_wrap(&tv);
	      bytes_htonl(state->payload,
			  ((tv.tv_sec % 86400) * 1000) + (tv.tv_usec / 1000));
	      i += 12;
	    }

	  if((ping->flags & SCAMPER_PING_FLAG_ICMPSUM) != 0)
	    {
	      probe.pr_icmp_sum = u16 = htons(ping->probe_icmpsum);
	      if((ping->flags & SCAMPER_PING_FLAG_SPOOF) != 0)
		i += 4;
	      memcpy(state->payload+i, &u16, 2);
	      if(SCAMPER_ADDR_TYPE_IS_IPV4(ping->dst))
		u16 = scamper_icmp4_cksum(&probe);
	      else
		u16 = scamper_icmp6_cksum(&probe);
	      memcpy(state->payload+i, &u16, 2);
	    }
	}
      else if(SCAMPER_PING_METHOD_IS_TCP(ping))
	{
	  probe.pr_ip_proto  = IPPROTO_TCP;
	  probe.pr_tcp_dport = ping->probe_dport;
	  probe.pr_tcp_sport = ping->probe_sport;
	  probe.pr_tcp_seq   = ping->probe_tcpseq;
	  probe.pr_tcp_ack   = ping->probe_tcpack;
	  probe.pr_tcp_win   = 65535;

	  if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK)
	    {
	      probe.pr_tcp_flags = TH_ACK;
	    }
	  else if(ping->probe_method == SCAMPER_PING_METHOD_TCP_ACK_SPORT)
	    {
	      probe.pr_tcp_flags  = TH_ACK;
	      probe.pr_tcp_sport += state->seq;
	    }
	  else if(ping->probe_method == SCAMPER_PING_METHOD_TCP_SYN)
	    {
	      probe.pr_tcp_flags = TH_SYN;
	    }
	  else if(ping->probe_method == SCAMPER_PING_METHOD_TCP_SYNACK)
	    {
	      probe.pr_tcp_flags = TH_SYN | TH_ACK;
	    }
	  else if(ping->probe_method == SCAMPER_PING_METHOD_TCP_RST)
	    {
	      probe.pr_tcp_flags = TH_RST;
	    }
	  else if(ping->probe_method == SCAMPER_PING_METHOD_TCP_SYN_SPORT)
	    {
	      probe.pr_tcp_flags = TH_SYN;
	      probe.pr_tcp_sport += state->seq;
	    }
	}
      else if(SCAMPER_PING_METHOD_IS_UDP(ping))
	{
	  probe.pr_ip_proto  = IPPROTO_UDP;
	  probe.pr_udp_sport = ping->probe_sport;

	  if(ping->probe_method == SCAMPER_PING_METHOD_UDP)
	    probe.pr_udp_dport = ping->probe_dport;
	  else if(ping->probe_method == SCAMPER_PING_METHOD_UDP_DPORT)
	    probe.pr_udp_dport = ping->probe_dport + state->seq;
	}
      else
	{
	  scamper_debug(__func__,"unknown ping method %d", ping->probe_method);
	  goto err;
	}

      /*
       * allocate a ping probe state record before we try and send the probe
       * as there is no point sending something into the wild that we can't
       * record
       */
      if((pp = malloc_zero(sizeof(ping_probe_t))) == NULL)
	goto err;

      /* if we're generating a random source port, then try a few times in case the
	     * port we pick is already used
	     */
      for(i = 0; i < 10; i++)
	      {
		      if((rc = scamper_probe_task(&probe, task)) == 0)
			      {
				      break;
			      }
		      /* probing failed, should we retry? */
		      if((ping->flags & SCAMPER_PING_FLAG_RANDOM_SPORT) == 0 ||
		         state->seq != 0)
			      {
				      break;
			      }
		      random_u16(&ping->probe_sport);
		      ping->probe_sport = ping->probe_sport | 0x8000;
		      if(SCAMPER_PING_METHOD_IS_TCP(ping))
			      probe.pr_tcp_sport = ping->probe_sport;
		      else
			      probe.pr_udp_sport = ping->probe_sport;
	      }
      if(rc != 0)
	      {
		      printerror(__func__, "failed to probe task");
		      goto err;
	      }

      if(scamper_probe_task(&probe, task) != 0)
	{
	  errno = probe.pr_errno;
	  goto err;
	}

      /* fill out the details of the probe sent */
      timeval_cpy(&pp->tx, &probe.pr_tx);
      pp->ipid = ipid;
      state->probes[state->seq] = pp;
      state->seq++;
      ping->ping_sent++;
    }
  else if(state->mode == PING_MODE_PTB)
    {
      SCAMPER_PROBE_ICMP_PTB(&probe, ping->reply_pmtu);
      probe.pr_ip_ttl = 255;
      probe.pr_data   = state->quote;
      probe.pr_len    = state->quote_len;

      if(scamper_probe_task(&probe, task) != 0)
	{
	  errno = probe.pr_errno;
	  goto err;
	}

      /* don't need the quote anymore */
      free(state->quote); state->quote = NULL;
      state->quote_len = 0;
      state->mode = PING_MODE_PROBE;
    }
  else
    {
      scamper_debug(__func__, "unknown ping mode %d", state->mode);
      goto err;
    }

  if(ping->ping_sent < ping->probe_count)
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

scamper_task_t *scamper_do_ping_alloctask(void *data, scamper_list_t *list,
					  scamper_cycle_t *cycle)
{
  scamper_ping_t *ping = (scamper_ping_t *)data;
  scamper_task_sig_t *sig = NULL;
  scamper_task_t *task = NULL;

  /* allocate a task structure and store the ping with it */
  if((task = scamper_task_alloc(ping, &ping_funcs)) == NULL)
    goto err;

  /* declare the signature of the task */
  if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
    goto err;
  sig->sig_tx_ip_dst = scamper_addr_use(ping->dst);
  if(ping->src == NULL && (ping->src = scamper_getsrc(ping->dst, 0)) == NULL)
    goto err;
  if((ping->flags & SCAMPER_PING_FLAG_SPOOF) == 0)
    sig->sig_tx_ip_src = scamper_addr_use(ping->src);

  switch(ping->probe_method)
    {
    case SCAMPER_PING_METHOD_ICMP_ECHO:
      SCAMPER_TASK_SIG_ICMP_ECHO(sig, ping->probe_sport);
      break;

    case SCAMPER_PING_METHOD_ICMP_TIME:
      SCAMPER_TASK_SIG_ICMP_TIME(sig, ping->probe_sport);
      break;

    case SCAMPER_PING_METHOD_TCP_ACK:
    case SCAMPER_PING_METHOD_TCP_SYN:
    case SCAMPER_PING_METHOD_TCP_SYNACK:
    case SCAMPER_PING_METHOD_TCP_RST:
      SCAMPER_TASK_SIG_TCP(sig, ping->probe_sport, ping->probe_dport);
      break;

    case SCAMPER_PING_METHOD_UDP:
      SCAMPER_TASK_SIG_UDP(sig, ping->probe_sport, ping->probe_dport);
      break;

    case SCAMPER_PING_METHOD_UDP_DPORT:
      SCAMPER_TASK_SIG_UDP_DPORT(sig, ping->probe_sport, ping->probe_dport,
				 ping->probe_dport + ping->probe_count - 1);
      break;

    case SCAMPER_PING_METHOD_TCP_ACK_SPORT:
    case SCAMPER_PING_METHOD_TCP_SYN_SPORT:
      SCAMPER_TASK_SIG_TCP_SPORT(sig, ping->probe_sport,
				 ping->probe_sport + ping->probe_count - 1,
				 ping->probe_dport);
      break;

    default:
      scamper_debug(__func__, "unhandled probe method %d", ping->probe_method);
      goto err;
    }

  if(scamper_task_sig_add(task, sig) != 0)
    goto err;
  sig = NULL;

  /* associate the list and cycle with the ping */
  ping->list  = scamper_list_use(list);
  ping->cycle = scamper_cycle_use(cycle);

  return task;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  if(task != NULL)
    {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
    }
  return NULL;
}

void scamper_do_ping_free(void *data)
{
  scamper_ping_free((scamper_ping_t *)data);
  return;
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
  return 0;
}
