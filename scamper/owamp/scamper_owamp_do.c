/*
 * scamper_owamp_do.c
 *
 * $Id: scamper_owamp_do.c,v 1.3 2026/01/03 03:32:46 mjl Exp $
 *
 * Copyright (C) 2025 The Regents of the University of California
 *
 * Authors: Matthew Luckie
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
#include "scamper_config.h"
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_task.h"
#include "scamper_fds.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_writebuf.h"
#include "scamper_udp_resp.h"
#include "scamper_owamp.h"
#include "scamper_owamp_int.h"
#include "scamper_owamp_do.h"
#include "utils.h"
#include "mjl_list.h"

static scamper_task_funcs_t owamp_funcs;

/* packet buffer for generating the payload of each packet */
extern uint8_t             *txbuf;
extern size_t               txbuf_len;

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

/* running scamper configuration */
extern scamper_config_t    *config;

typedef struct owamp_state
{
  scamper_fd_t       *tcp;
  scamper_fd_t       *udp;
  int                 mode;
  scamper_writebuf_t *wb;
  uint8_t             sid[16];
  uint8_t            *readbuf;
  size_t              readbuf_len;
  size_t              payload_len;
  uint32_t            schedx;
  struct timeval      next_tx;
  struct timeval      timeout;
} owamp_state_t;

#define STATE_MODE_CONNECT       0
#define STATE_MODE_GREETING      1
#define STATE_MODE_SERVERSTART   2
#define STATE_MODE_ACCEPTSESSION 3
#define STATE_MODE_STARTACK      4
#define STATE_MODE_FETCHACK      5
#define STATE_MODE_RX            6
#define STATE_MODE_TX            7
#define STATE_MODE_TXWAIT        8
#define STATE_MODE_DONE          9

#define OWAMP_EPOCH_OFFSET 2208988800UL

static const char *owamp_mode(int mode)
{
  switch(mode)
    {
    case STATE_MODE_CONNECT:       return "connect";
    case STATE_MODE_GREETING:      return "greeting";
    case STATE_MODE_SERVERSTART:   return "server-start";
    case STATE_MODE_ACCEPTSESSION: return "accept-session";
    case STATE_MODE_STARTACK:      return "start-ack";
    case STATE_MODE_FETCHACK:      return "fetch-ack";
    case STATE_MODE_RX:            return "rx";
    case STATE_MODE_TX:            return "tx";
    case STATE_MODE_TXWAIT:        return "tx-wait";
    case STATE_MODE_DONE:          return "done";
    }
  return "unknown";
}

static scamper_owamp_t *owamp_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static owamp_state_t *owamp_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static void owamp_stop(scamper_task_t *task, uint8_t result)
{
  scamper_owamp_t *owamp = owamp_getdata(task);

  /* if we've already set a result, then don't clobber it */
  if(owamp->result != SCAMPER_OWAMP_RESULT_NONE)
    scamper_debug(__func__, "result %d precedes %d", owamp->result, result);
  else
    owamp->result = result;

  scamper_task_queue_done(task);
  return;
}

static void owamp_stop_err(scamper_owamp_t *owamp, const scamper_err_t *err)
{
  char errbuf[512], buf[256], addr[256];

  scamper_err_render(err, errbuf, sizeof(errbuf));

  if(printerror_would())
    {
      snprintf(buf, sizeof(buf), "owamp to %s failed",
	       scamper_addr_tostr(owamp->dst, addr, sizeof(addr)));
      printerror_msg(buf, "%s", errbuf);
    }

  if(owamp->result == SCAMPER_OWAMP_RESULT_NONE)
    {
      owamp->result = SCAMPER_OWAMP_RESULT_ERROR;
      if(owamp->errmsg == NULL)
	owamp->errmsg = strdup(errbuf);
    }

  return;
}

static void owamp_handleerror(scamper_task_t *task, scamper_err_t *error)
{
  owamp_stop_err(owamp_getdata(task), error);
  scamper_task_queue_done(task);
  return;
}

static size_t owamp_roundup(size_t in)
{
  size_t left = in % 16;
  if(left > 0)
    return in + (16 - left);
  return in;
}

static void owamp_queue(scamper_task_t *task)
{
  scamper_owamp_t *owamp = owamp_getdata(task);
  owamp_state_t *state = owamp_getstate(task);
  struct timeval now;

  /* if we've set a result, then the task will be in the done queue */
  if(owamp->result != SCAMPER_OWAMP_RESULT_NONE)
    {
      assert(scamper_task_queue_isdone(task));
      return;
    }

  if(state->mode == STATE_MODE_TX)
    {
      gettimeofday_wrap(&now);
      if(timeval_cmp(&state->next_tx, &now) <= 0)
	scamper_task_queue_probe(task);
      else
	scamper_task_queue_wait_tv(task, &state->next_tx);
      return;
    }

  scamper_task_queue_wait_tv(task, &state->timeout);
  return;
}

static void owamp_state_free(owamp_state_t *state)
{
#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

  if(state->readbuf != NULL)
    free(state->readbuf);
  if(state->wb != NULL)
    scamper_writebuf_free(state->wb);
  if(state->tcp != NULL)
    {
      fd = scamper_fd_fd_get(state->tcp);
      if(socket_isvalid(fd))
	socket_close(fd);
      scamper_fd_free(state->tcp);
    }
  if(state->udp != NULL)
    scamper_fd_free(state->udp);

  free(state);
  return;
}

static void owamp_runtime(scamper_owamp_t *owamp, struct timeval *tv)
{
  uint32_t i, x = 0;

  tv->tv_sec = 0; tv->tv_usec = 0;
  for(i=0; i<owamp->attempts; i++)
    {
      timeval_add_tv(tv, &owamp->sched[x]->tv);
      if(++x == owamp->schedc)
	x = 0;
    }

  return;
}

static void timeval_to_owamp(uint8_t *bytes, const struct timeval *tv)
{
  uint32_t u32;

  bytes_htonl(bytes+0, (uint32_t)tv->tv_sec);
  u32 = (uint32_t)((((uint64_t)tv->tv_usec) << 32) / 1000000ULL);
  bytes_htonl(bytes+4, u32);

  return;
}

static void timeval_from_owamp(struct timeval *tv, const uint8_t *bytes)
{
  uint32_t u32;

  tv->tv_sec = bytes_ntohl(bytes);
  u32 = (uint32_t)(((uint64_t)bytes_ntohl(bytes+4) * 1000000ULL) >> 32);
  tv->tv_usec = u32;

  return;
}

static int tcp_greeting(scamper_task_t *task, scamper_err_t *error)
{
  owamp_state_t *state = owamp_getstate(task);
  uint8_t response[164];

  /*
   * a client opens a TCP connection to the server on a well-known
   * port 861.  The server responds with a server greeting:
   *
   * unused:    12 bytes
   * modes:      4 bytes
   * challenge: 16 bytes
   * salt:      16 bytes
   * count:      4 bytes
   * mbz:       12 bytes
   *            --------
   * total:     64 bytes
   */
  if(state->readbuf_len < 64)
    return 0;

  /* check that the server supports unauthenticated mode */
  if((state->readbuf[15] & 0x1) == 0)
    {
      scamper_debug(__func__, "server does not support unauthenticated mode");
      owamp_stop(task, SCAMPER_OWAMP_RESULT_NOMODE);
      return 0;
    }

  state->readbuf_len = state->readbuf_len - 64;
  memmove(state->readbuf, state->readbuf+64, state->readbuf_len);

  /*
   * client must respond with the following Set-Up-Response message:
   * mode:        4 bytes
   * key_id:     80 bytes
   * token:      64 bytes
   * client_iv:  16 bytes
   *            ---------
   *            164 bytes
   */
  memset(response, 0, sizeof(response));
  response[3] = 1;
  if(scamper_writebuf_send(state->wb, response, sizeof(response)) != 0)
    {
      scamper_err_make(error, errno, "could not send set-up-response");
      return -1;
    }
  state->mode = STATE_MODE_SERVERSTART;
  scamper_fd_write_unpause(state->tcp);

  return 1;
}

static int tcp_serverstart(scamper_task_t *task, scamper_err_t *error)
{
  scamper_owamp_t *owamp = owamp_getdata(task);
  owamp_state_t *state = owamp_getstate(task);
  uint8_t *response = NULL;
  struct timeval startat, runtime;
  size_t response_len, addr_len, off;
  uint32_t i, padding;

  /*
   * the server must respond to a Set-Up-Response with a Server-Start
   * message:
   *
   * mbz:        15 bytes
   * accept:      1 byte
   * server-iv:  16 bytes
   * start-time:  8 bytes
   * mbz:         8 bytes
   *             --------
   * total:      48 bytes
   */
  if(state->readbuf_len < 48)
    return 0;

  if(state->readbuf[15] != 0)
    {
      scamper_debug(__func__, "Set-Up-Response: not accepted");
      owamp_stop(task, SCAMPER_OWAMP_RESULT_NOTACCEPTED);
      return 0;
    }
  scamper_debug(__func__, "Set-Up-Response accepted");

  state->readbuf_len = state->readbuf_len - 48;
  memmove(state->readbuf, state->readbuf+48, state->readbuf_len);

  if(timeval_iszero(&owamp->startat))
    {
      gettimeofday_wrap(&owamp->startat);
      owamp->startat.tv_sec += 1;
    }

  /* determine a timeout that allows for the test to run */
  owamp_runtime(owamp, &runtime);
  timeval_add_tv3(&state->timeout, &owamp->startat, &runtime);
  state->timeout.tv_sec += 10;

  /*
   * Request-Session header:
   * type:                      1 byte
   * ipvn:                      1 byte
   * conf-sender:               1 byte
   * conf-receiver:             1 byte
   * number of schedule slots:  4 bytes
   * number of packets:         4 bytes
   * sender port:               2 bytes
   * receiver port:             2 bytes
   * sender address:           16 bytes
   * receiver address:         16 bytes
   * SID:                      16 bytes
   * padding length:            4 bytes
   * start time:                8 bytes
   * timeout:                   8 bytes
   * type-p descriptor:         4 bytes
   * mbz:                       8 bytes
   * hmac:                     16 bytes
   *                          ---------
   *                          112 bytes
   *
   * slot description:
   * slot type:                 1 byte
   * mbz:                       7 bytes
   * parameter:                 8 bytes
   *                           --------
   *                           16 bytes
   *
   * hmac:                     16 bytes
   */
  response_len = 112 + (16 * owamp->schedc) + 16;
  if((response = malloc_zero(response_len)) == NULL)
    {
      scamper_err_make(error, errno, "could not alloc Request-Session");
      goto err;
    }
  response[0] = 1;                          /* type: request-session */
  bytes_htonl(response+4, owamp->schedc);   /* number of schedule slots */
  bytes_htonl(response+8, owamp->attempts); /* number of packets */

  if(SCAMPER_ADDR_TYPE_IS_IPV4(owamp->dst))
    {
      response[1] = 4; /* ipvn */
      addr_len = 4;
      padding = owamp->pktsize - (20 + 8 + 14);
    }
  else
    {
      response[1] = 6; /* ipvn */
      addr_len = 16;
      padding = owamp->pktsize - (40 + 8 + 14);
    }

  if(owamp->dir == SCAMPER_OWAMP_DIR_TX)
    {
      response[2] = 0;                                 /* conf-sender */
      response[3] = 1;                                 /* conf-receiver */
      bytes_htons(response+12, owamp->udp_sport);      /* sender port */
      memcpy(response+16, owamp->src->addr, addr_len); /* sender address */
      memcpy(response+32, owamp->dst->addr, addr_len); /* receiver address */
    }
  else
    {
      response[2] = 1;                                 /* conf-sender */
      response[3] = 0;                                 /* conf-receiver */
      bytes_htons(response+14, owamp->udp_sport);      /* receiver port */
      memcpy(response+16, owamp->dst->addr, addr_len); /* sender address */
      memcpy(response+32, owamp->src->addr, addr_len); /* receiver address */
    }

  bytes_htonl(response+64, padding);
  timeval_add_s(&startat, &owamp->startat, OWAMP_EPOCH_OFFSET);
  timeval_to_owamp(response+68, &startat);
  timeval_to_owamp(response+76, &owamp->wait_timeout);
  response[84] = owamp->dscp; /* type-p descriptor */

  off = 112;
  for(i=0; i<owamp->schedc; i++)
    {
      response[off] = 1; /* periodic stream */
      timeval_to_owamp(response+off+8, &owamp->sched[i]->tv);
      off += 16;
    }
  assert(off + 16 == response_len);

  if(scamper_writebuf_send(state->wb, response, response_len) != 0)
    {
      scamper_err_make(error, errno, "could not send request-session");
      goto err;
    }
  free(response);
  state->mode = STATE_MODE_ACCEPTSESSION;
  scamper_fd_write_unpause(state->tcp);

  return 1;

 err:
  if(response != NULL) free(response);
  return -1;
}

static int tcp_acceptsession(scamper_task_t *task, scamper_err_t *error)
{
  scamper_owamp_t *owamp = owamp_getdata(task);
  owamp_state_t *state = owamp_getstate(task);
  scamper_task_sig_t *sig = NULL;
  uint8_t response[32];
  uint16_t port;

  /*
   * Accept-Session header:
   *
   * accept:    1 byte
   * mbz:       1 byte
   * port:      2 bytes
   * sid:      16 bytes
   * mbz:      12 bytes
   * hmac:     16 bytes
   *           --------
   *           48 bytes
   */
  if(state->readbuf_len < 48)
    return 0;

  if(state->readbuf[0] != 0)
    {
      scamper_debug(__func__, "Accept-Session: not accepted");
      owamp_stop(task, SCAMPER_OWAMP_RESULT_NOTACCEPTED);
      return 0;
    }

  port = bytes_ntohs(state->readbuf+2);
  scamper_debug(__func__, "Accept-Session: port %u", port);
  owamp->udp_dport = port;

  /*
   * once we know the port to expect responses on, add task signature
   * so that scamper gives us our packets.
   */
  if(owamp->dir == SCAMPER_OWAMP_DIR_RX)
    {
      if((sig = scamper_task_sig_alloc(SCAMPER_TASK_SIG_TYPE_TX_IP)) == NULL)
	{
	  scamper_err_make(error, errno, "could not alloc task signature");
	  goto err;
	}
      sig->sig_tx_ip_dst = scamper_addr_use(owamp->dst);
      SCAMPER_TASK_SIG_UDP(sig, owamp->udp_sport, owamp->udp_dport);
      if(scamper_task_sig_add(task, sig) != 0)
	{
	  scamper_err_make(error, errno, "could not add signature to task");
	  goto err;
	}
      sig = NULL;
      if(scamper_task_sig_install(task) != 0)
	{
	  scamper_err_make(error, errno, "could not add signature to task");
	  goto err;
	}
    }
  else
    {
      memcpy(state->sid, state->readbuf+4, 16);
    }

  state->readbuf_len = state->readbuf_len - 48;
  memmove(state->readbuf, state->readbuf+48, state->readbuf_len);

  /*
   * Start-Sessions header:
   * type:    1 byte
   * mbz:    15 bytes
   * hmac:   16 bytes
   */
  memset(response, 0, sizeof(response));
  response[0] = 2; /* type */
  if(scamper_writebuf_send(state->wb, response, sizeof(response)) != 0)
    {
      scamper_err_make(error, errno, "could not send start-sessions");
      goto err;
    }
  state->mode = STATE_MODE_STARTACK;
  scamper_fd_write_unpause(state->tcp);
  
  return 1;

 err:
  if(sig != NULL) scamper_task_sig_free(sig);
  return -1;
}

static int tcp_startack(scamper_task_t *task, scamper_err_t *error)
{
  scamper_owamp_t *owamp = owamp_getdata(task);
  owamp_state_t *state = owamp_getstate(task);

  /*
   * Start-Ack message:
   * accept:   1 byte
   * mbz:     15 bytes
   * hmac:    16 bytes
   */
  if(state->readbuf_len < 32)
    return 0;

  if(state->readbuf[0] != 0)
    {
      scamper_debug(__func__, "Start-Sessions: not accepted");
      owamp_stop(task, SCAMPER_OWAMP_RESULT_NOTACCEPTED);
      return 0;
    }
  scamper_debug(__func__, "Start-Sessions: accepted");

  state->readbuf_len = state->readbuf_len - 32;
  memmove(state->readbuf, state->readbuf+32, state->readbuf_len);

  if(owamp->dir == SCAMPER_OWAMP_DIR_TX)
    {
      state->mode = STATE_MODE_TX;
      timeval_add_tv3(&state->next_tx, &owamp->startat, &owamp->sched[0]->tv);
      if(owamp->schedc > 1)
	state->schedx = 1;
    }
  else
    {
      state->mode = STATE_MODE_RX;
    }

  return 1;
}

static int tcp_stopsessions(scamper_task_t *task, scamper_err_t *error)
{
  scamper_owamp_t *owamp = owamp_getdata(task);
  owamp_state_t *state = owamp_getstate(task);
  scamper_owamp_tx_t *tx;
  uint32_t num_sessions, num_skipranges, i, seq, skip[2];
  size_t block_size, off;
  uint8_t response[64 + 48];

#ifdef HAVE_SCAMPER_DEBUG
  uint32_t next_seqno;
#endif

  /* wait until we get all of the stop-sessions message header */
  if(state->readbuf_len < 32)
    return 0;
  num_sessions = bytes_ntohl(state->readbuf+4);
  scamper_debug(__func__, "Stop-Sessions accept %d sessions %d",
		state->readbuf[1], num_sessions);

  /* if there's no sessions in here, we're done */
  if(num_sessions == 0)
    {
      /* 16 byte header + 16 byte HMAC */
      state->readbuf_len -= 32;
      memmove(state->readbuf, state->readbuf + 32, state->readbuf_len);

      scamper_debug(__func__, "mode %s", owamp_mode(state->mode));

      if(state->mode == STATE_MODE_TXWAIT)
	{
	  memset(response, 0, sizeof(response));

	  /* send our own stop-sessions ... */
	  response[0] = 3; /* message type: Stop-Sessions */
	  bytes_htonl(response+4, 1);
	  memcpy(response+16, state->sid, 16); /* SID */
	  bytes_htonl(response+32, owamp->txc);

	  /* ... followed by a fetch-session */
	  response[64] = 4; /* message type: Fetch-Session */
	  response[76] = 0xFF; response[77] = 0xFF; /* end sequence */
	  response[78] = 0xFF; response[79] = 0xFF;
	  memcpy(response+80, state->sid, 16); /* SID */

	  if(scamper_writebuf_send(state->wb, response, sizeof(response)) != 0)
	    {
	      scamper_err_make(error, errno, "could not send stop-sessions");
	      return -1;
	    }
	  state->mode = STATE_MODE_FETCHACK;
	  scamper_fd_write_unpause(state->tcp);
	  return 1;
	}

      owamp_stop(task, SCAMPER_OWAMP_RESULT_DONE);
      return 0;
    }

  /*
   * make sure there's enough to read the header of the session
   * description record
   */
  if(state->readbuf_len < 16 + 32)
    return 0;
#ifdef HAVE_SCAMPER_DEBUG
  next_seqno = bytes_ntohl(state->readbuf + 16 + 16);
#endif
  num_skipranges = bytes_ntohl(state->readbuf + 16 + 20);
  block_size = owamp_roundup(16 + 8 + (num_skipranges * 8));
  if(state->readbuf_len < 16 + block_size + 16)
    return 0;

  for(i=0; i<num_skipranges; i++)
    {
      off = 48 + (i * 8);
      skip[0] = bytes_ntohl(state->readbuf + off);
      skip[1] = bytes_ntohl(state->readbuf + off + 4);
      if(skip[0] > skip[1] || skip[1] >= owamp->attempts)
	continue;

      for(seq=skip[0]; seq<skip[1]; seq++)
	{
	  if(owamp->txs[seq] != NULL)
	    continue;
	  if((tx = scamper_owamp_tx_alloc()) == NULL)
	    {
	      scamper_err_make(error, errno, "could not alloc tx");
	      return -1;
	    }
	  tx->seq = seq;
	  tx->flags |= SCAMPER_OWAMP_TX_FLAG_NOTSENT;
	  owamp->txs[seq] = tx;
	  if(seq >= owamp->txc)
	    owamp->txc = seq + 1;
	}
    }

  scamper_debug(__func__, "next_seqno %u skipranges %u", next_seqno,
		num_skipranges);

  state->readbuf_len -= (16 + block_size + 16);
  memmove(state->readbuf, state->readbuf + 16 + block_size + 16,
	  state->readbuf_len);

  owamp_stop(task, SCAMPER_OWAMP_RESULT_DONE);
  return 0;
}

static int tcp_fetchack(scamper_task_t *task, scamper_err_t *error)
{
  scamper_owamp_t *owamp = owamp_getdata(task);
  owamp_state_t *state = owamp_getstate(task);
  scamper_owamp_rx_t *rx;
  uint32_t i, num_skipranges, num_records, num_schedslots, seq;
  size_t reqsess_size, skip_size, record_size, off;

  /*
   * Fetch-Ack message header:
   *  accept:          1 byte
   *  finished:        1 byte
   *  mbz:             2 bytes
   *  next-seqno:      4 bytes
   *  num-skipranges:  4 bytes
   *  num-records:     4 bytes
   *  hmac:           16 bytes
   *                  --
   *                  32 bytes
   *
   * Request-Session command:
   *  total:        ~144 bytes -- tcp_serverstart() sizeof(response)
   *
   * Skip-Ranges:
   *  zero:            0 bytes
   *  hmac:           16 bytes
   *
   * Packet records:
   *  num-records * 25 + padding to 16 bytes
   *  hmac:           16 bytes
   *
   */

  /* wait until we get all of the Fetch-Ack message header */
  if(state->readbuf_len < 32)
    return 0;
  if(state->readbuf[0] != 0)
    {
      scamper_debug(__func__, "Fetch-Ack: not accepted");
      owamp_stop(task, SCAMPER_OWAMP_RESULT_NOTACCEPTED);
      return 0;
    }

  /* need to know number of sched slots to know the size of the request */
  if(state->readbuf_len < 32 + 8)
    return 0;

  num_skipranges = bytes_ntohl(state->readbuf+8);
  num_records = bytes_ntohl(state->readbuf+12);
  num_schedslots = bytes_ntohl(state->readbuf+36);
  scamper_debug(__func__, "Fetch-Ack: %u schedslots, %u skipranges, %u records",
		num_schedslots, num_skipranges, num_records);

  /* wait until we've got the entire fetch-ack */
  reqsess_size = 112 + (num_schedslots * 16) + 16;
  skip_size = owamp_roundup(num_skipranges * 16) + 16;
  record_size = owamp_roundup(num_records * 25) + 16;
  if(state->readbuf_len < 32 + reqsess_size + skip_size + record_size)
    return 0;

  off = 32 + reqsess_size + skip_size;
  for(i=0; i<num_records; i++)
    {
      seq = bytes_ntohl(state->readbuf + off);
      if(seq >= owamp->txc || owamp->txs[seq]->rxc == 255)
	goto next;

      if((rx = scamper_owamp_rx_alloc()) == NULL)
	{
	  scamper_err_make(error, errno, "could not alloc rx");
	  return -1;
	}

      timeval_from_owamp(&rx->stamp, state->readbuf + off + 16);
      rx->stamp.tv_sec -= OWAMP_EPOCH_OFFSET;
      rx->ttl = state->readbuf[off+24];
      rx->errest = bytes_ntohs(state->readbuf + off + 6);
      rx->flags = (SCAMPER_OWAMP_RX_FLAG_TTL | SCAMPER_OWAMP_RX_FLAG_ERREST);

      if(scamper_owamp_tx_rxadd(owamp->txs[seq], rx) != 0)
	{
	  scamper_err_make(error, errno, "could not add rx");
	  scamper_owamp_rx_free(rx);
	  return -1;
	}

    next:
      off += 25;
    }

  owamp_stop(task, SCAMPER_OWAMP_RESULT_DONE);
  state->mode = STATE_MODE_DONE;

  return 0;
}

static int tcp_othermode(scamper_task_t *task, scamper_err_t *error)
{
  owamp_state_t *state = owamp_getstate(task);

  if(state->readbuf[0] == 3)
    return tcp_stopsessions(task, error);

  scamper_debug(__func__, "type %d", state->readbuf[0]);
  return 0;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
static void tcp_read(int fd, void *param)
#else
static void tcp_read(SOCKET fd, void *param)
#endif
{
  scamper_task_t *task = param;
  owamp_state_t *state = owamp_getstate(task);
  scamper_err_t error;
  socklen_t sl;
  ssize_t rrc;
  int ecode, x;

  /* if we get a read event during connect, then we could not connect */
  if(state->mode == STATE_MODE_CONNECT)
    {
      sl = sizeof(ecode);
      if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &ecode, &sl) == 0)
	scamper_debug(__func__, "could not connect: %s", strerror(ecode));
      owamp_stop(task, SCAMPER_OWAMP_RESULT_NOCONN);
      scamper_fd_write_pause(state->tcp);
      state->mode = STATE_MODE_DONE;
      return;
    }

  if(realloc_wrap((void **)&state->readbuf, state->readbuf_len + 8192) != 0)
    {
      scamper_err_make(&error, errno, "could not realloc readbuf");
      goto err;
    }

  if((rrc = recv(fd, state->readbuf + state->readbuf_len, 8192, 0)) < 0)
    {
      if(errno == EAGAIN || errno == EINTR)
	return;
      scamper_err_make(&error, errno, "could not recv from %d", fd);
      goto err;
    }
  if(rrc == 0)
    {
      scamper_err_make(&error, 0, "disconnected fd %d", fd);
      goto err;
    }

  state->readbuf_len += rrc;
  while(state->readbuf_len > 0)
    {
      if(state->mode == STATE_MODE_GREETING)
	x = tcp_greeting(task, &error);
      else if(state->mode == STATE_MODE_SERVERSTART)
	x = tcp_serverstart(task, &error);
      else if(state->mode == STATE_MODE_ACCEPTSESSION)
	x = tcp_acceptsession(task, &error);
      else if(state->mode == STATE_MODE_STARTACK)
	x = tcp_startack(task, &error);
      else if(state->mode == STATE_MODE_FETCHACK)
	x = tcp_fetchack(task, &error);
      else
	x = tcp_othermode(task, &error);

      if(x < 0)
	goto err;
      if(x == 0)
	break;
    }

  owamp_queue(task);
  return;

 err:
  owamp_handleerror(task, &error);
  return;  
}

#ifndef _WIN32 /* SOCKET vs int on windows */
static void tcp_write(int fd, void *param)
#else
static void tcp_write(SOCKET fd, void *param)
#endif
{
  scamper_task_t *task = param;
  scamper_owamp_t *owamp = owamp_getdata(task);
  owamp_state_t *state = owamp_getstate(task);
  scamper_err_t error;
  struct timeval tv;
  int pause = 1;

  SCAMPER_ERR_INIT(&error);

  /*
   * we successfully connected.  nothing else to do now.  wait for
   * server greeting.
   */
  if(state->mode == STATE_MODE_CONNECT)
    {
      gettimeofday_wrap(&tv);
      timeval_diff_tv(&owamp->hsrtt, &owamp->start, &tv);
      state->mode = STATE_MODE_GREETING;
      goto done;
    }

  if(state->mode == STATE_MODE_DONE)
    goto done;

  assert(scamper_writebuf_gtzero(state->wb));

  /* write whatever we have */
  if(scamper_writebuf_write(fd, state->wb) != 0)
    {
      scamper_err_make(&error, errno, "could not write from writebuf, mode %s",
		       owamp_mode(state->mode));
      goto err;
    }

  /*
   * if we were not able to write all of the writebuf, then we do not
   * pause ability to write.
   */
  if(scamper_writebuf_gtzero(state->wb))
    pause = 0;

 done:
  if(pause != 0)
    scamper_fd_write_pause(state->tcp);
  return;

 err:
  scamper_fd_write_pause(state->tcp);
  owamp_handleerror(task, &error);
  return;
}

static void do_owamp_handle_udp(scamper_task_t *task, scamper_udp_resp_t *ur)
{
  scamper_owamp_t *owamp = owamp_getdata(task);
  owamp_state_t *state = owamp_getstate(task);
  scamper_owamp_tx_t *tx = NULL;
  scamper_owamp_rx_t *rx = NULL;
  scamper_err_t error;
  uint32_t seq;

  SCAMPER_ERR_INIT(&error);

  if(owamp->dir != SCAMPER_OWAMP_DIR_RX || state == NULL ||
     state->udp == NULL ||
     ur->fd != scamper_fd_fd_get(state->udp) ||
     ur->sport != owamp->udp_dport ||
     ur->datalen < 14 ||
     (seq = bytes_ntohl(ur->data)) >= owamp->attempts)
    return;

  if((tx = owamp->txs[seq]) == NULL)
    {
      if((tx = scamper_owamp_tx_alloc()) == NULL)
	return;

      timeval_from_owamp(&tx->stamp, ur->data+4);
      tx->stamp.tv_sec -= OWAMP_EPOCH_OFFSET;
      tx->errest = bytes_ntohs(ur->data+12);
      tx->seq = seq;
      tx->flags |= SCAMPER_OWAMP_TX_FLAG_ERREST;

      owamp->txs[seq] = tx;
      if(seq <= owamp->txc)
	owamp->txc = seq + 1;
    }

  if(tx->rxc == 255)
    return;

  if((rx = scamper_owamp_rx_alloc()) == NULL)
    return;
  timeval_cpy(&rx->stamp, &ur->rx);
  rx->ttl = ur->ttl;
  rx->flags |= SCAMPER_OWAMP_RX_FLAG_TTL;
  if(scamper_owamp_tx_rxadd(tx, rx) != 0)
    {
      scamper_owamp_rx_free(rx);
      return;
    }

  return;
}

static int owamp_state_alloc(scamper_task_t *task, scamper_err_t *error)
{
  scamper_owamp_t *owamp = owamp_getdata(task);
  owamp_state_t *state = NULL;
  struct sockaddr_storage ss;
  struct sockaddr *sa;
  socklen_t sl;
  size_t len;
  void *addr;
  int at;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd = -1;
#else
  SOCKET fd = INVALID_SOCKET;
#endif

  if((state = malloc_zero(sizeof(owamp_state_t))) == NULL ||
     (state->wb = scamper_writebuf_alloc()) == NULL)
    {
      scamper_err_make(error, errno, "could not alloc state");
      goto err;
    }

  len = sizeof(scamper_owamp_tx_t *) * owamp->attempts;
  if((owamp->txs = malloc_zero(len)) == NULL)
    {
      scamper_err_make(error, errno, "could not alloc txs");
      goto err;
    }

  /* set timeout */
  timeval_add_s(&state->timeout, &owamp->start, 10);

  sa = (struct sockaddr *)&ss;
  if(scamper_addr_tosockaddr(owamp->dst, owamp->dport, sa) != 0)
    {
      scamper_err_make(error, 0, "could not compose sockaddr");
      goto err;
    }

  fd = socket(sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
  if(socket_isinvalid(fd))
    {
      scamper_err_make(error, errno, "could not allocate socket");
      goto err;
    }

#ifdef HAVE_FCNTL
  if(fcntl_set(fd, O_NONBLOCK) == -1)
    {
      scamper_err_make(error, errno, "could not set O_NONBLOCK");
      goto err;
    }
#endif

  sl = sockaddr_len(sa);
  if(connect(fd, sa, sl) != 0 && errno != EINPROGRESS)
    {
      scamper_err_make(error, errno, "could not connect");
      goto err;
    }

  /* determine the source address for the owamp session */
  if(getsockname(fd, sa, &sl) != 0)
    {
      scamper_err_make(error, errno, "could not getsockname");
      goto err;
    }
  if(sa->sa_family == AF_INET)
    {
      addr = &((struct sockaddr_in *)&ss)->sin_addr;
      at = SCAMPER_ADDR_TYPE_IPV4;
      state->payload_len = owamp->pktsize - 20 - 8;
    }
  else if(sa->sa_family == AF_INET6)
    {
      addr = &((struct sockaddr_in6 *)&ss)->sin6_addr;
      at = SCAMPER_ADDR_TYPE_IPV6;
      state->payload_len = owamp->pktsize - 40 - 8;
    }
  else
    {
      scamper_err_make(error, 0, "unknown af");
      goto err;
    }
  if((owamp->src = scamper_addrcache_get(addrcache, at, addr)) == NULL)
    {
      scamper_err_make(error, errno, "could not get source address");
      goto err;
    }

  if((state->tcp = scamper_fd_private(fd, task, tcp_read, tcp_write)) == NULL)
    {
      scamper_err_make(error, errno, "could not register tcp fd");
      goto err;
    }

  if(owamp->udp_sport == 0)
    owamp->udp_sport = scamper_sport_default();

  if(at == SCAMPER_ADDR_TYPE_IPV4)
    state->udp = scamper_fd_udp4dg(owamp->src->addr, owamp->udp_sport, error);
  else
    state->udp = scamper_fd_udp6(owamp->src->addr, owamp->udp_sport, error);
  if(state->udp == NULL)
    goto err;

  scamper_task_setstate(task, state);
  return 0;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  if(state != NULL) owamp_state_free(state);
  return -1;
}

static void do_owamp_probe(scamper_task_t *task)
{
  scamper_owamp_t *owamp = owamp_getdata(task);
  owamp_state_t *state = owamp_getstate(task);
  scamper_owamp_tx_t *tx = NULL;
  scamper_err_t error;
  struct sockaddr_storage sas;
  struct sockaddr *sa;
  struct timeval tv;
  ssize_t nb;
  int fd;

  SCAMPER_ERR_INIT(&error);

  if(state == NULL)
    {
      gettimeofday_wrap(&owamp->start);
      if(owamp_state_alloc(task, &error) != 0)
	goto err;
      goto done;
    }

  if(state->mode != STATE_MODE_TX)
    {
      scamper_debug(__func__, "state %s not TX", owamp_mode(state->mode));
      goto done;
    }

  if(txbuf_len < state->payload_len)
    {
      if(realloc_wrap((void **)&txbuf, state->payload_len) != 0)
	{
	  scamper_err_make(&error, errno, "could not realloc txbuf");
	  goto err;
	}
      txbuf_len = state->payload_len;
    }

  sa = (struct sockaddr *)&sas;
  if(scamper_addr_tosockaddr(owamp->dst, owamp->udp_dport, sa) != 0)
    {
      scamper_err_make(&error, 0, "invalid destination address");
      goto err;
    }
  fd = scamper_fd_fd_get(state->udp);

  /* set the probe TTL */
  if(SCAMPER_ADDR_TYPE_IS_IPV6(owamp->dst))
    {
      if(setsockopt_int(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 255) != 0)
	{
	  scamper_err_make(&error, errno, "could not set hlim to %u",
			   owamp->ttl);
	  goto err;
	}
#ifdef IPV6_TCLASS
      if(setsockopt_int(fd, IPPROTO_IPV6, IPV6_TCLASS, owamp->dscp << 2) != 0)
	{
	  scamper_err_make(&error, errno, "could not set dscp to %u",
			   owamp->dscp);
	  goto err;
	}
#endif /* IPV6_TCLASS */
    }
  else
    {
      if(setsockopt_int(fd, IPPROTO_IP, IP_TTL, owamp->ttl) != 0)
	{
	  scamper_err_make(&error, errno, "could not set ttl to %u",
			   owamp->ttl);
	  goto err;
	}
      if(setsockopt_int(fd, IPPROTO_IP, IP_TOS, owamp->dscp << 2) != 0)
	{
	  scamper_err_make(&error, errno, "could not set dscp to %u",
			   owamp->dscp);
	  goto err;
	}
    }

  /* set the bits of the txbuf that we can */
  bytes_htonl(txbuf, owamp->txc);
  txbuf[12] = 1;
  txbuf[13] = 64;

  if(state->payload_len > 14)
    {
      if((owamp->flags & SCAMPER_OWAMP_FLAG_ZERO) == 0)
	random_bytes(txbuf + 14, state->payload_len - 14);
      else
	memset(txbuf + 14, 0, state->payload_len - 14);
    }

  /* get a tx record */
  if((tx = scamper_owamp_tx_alloc()) == NULL)
    {
      scamper_err_make(&error, errno, "could not alloc tx");
      goto err;
    }
  gettimeofday_wrap(&tx->stamp);
  tx->seq = owamp->txc;

  /* set the timestamp in the txbuf */
  timeval_add_s(&tv, &tx->stamp, OWAMP_EPOCH_OFFSET);
  timeval_to_owamp(txbuf+4, &tv);
  timeval_cpy(&tx->sched, &state->next_tx);

  /* send the packet */
  nb = sendto(fd, txbuf, state->payload_len, 0, sa, sockaddr_len(sa));
  if(nb != (ssize_t)state->payload_len)
    {
      scamper_err_make(&error, errno, "could not send probe");
      goto err;
    }

  owamp->txs[owamp->txc++] = tx;
  if(owamp->txc < owamp->attempts)
    {
      timeval_add_tv(&state->next_tx, &owamp->sched[state->schedx]->tv);
      if(++state->schedx == owamp->schedc)
	state->schedx = 0;
    }
  else
    {
      state->mode = STATE_MODE_TXWAIT;
      gettimeofday_wrap(&state->timeout);
      state->timeout.tv_sec += 10;
    }

 done:
  owamp_queue(task);
  return;

 err:
  if(tx != NULL) scamper_owamp_tx_free(tx);
  owamp_handleerror(task, &error);
  return;
}

static void do_owamp_handle_timeout(scamper_task_t *task)
{
  owamp_state_t *state = owamp_getstate(task);

  /* timeout in transmit means that we go to probe */
  if(state->mode == STATE_MODE_TX)
    return;

  owamp_stop(task, SCAMPER_OWAMP_RESULT_TIMEOUT);
  return;
}

static void do_owamp_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_file_write_owamp(sf, owamp_getdata(task), task);
  return;
}

static void do_owamp_halt(scamper_task_t *task)
{
  scamper_owamp_t *owamp = owamp_getdata(task);
  owamp->result = SCAMPER_OWAMP_RESULT_HALTED;
  scamper_task_queue_done(task);
  return;
}

static void do_owamp_free(scamper_task_t *task)
{
  scamper_owamp_t *owamp = owamp_getdata(task);
  owamp_state_t *state = owamp_getstate(task);

  if(state != NULL)
    owamp_state_free(state);
  if(owamp != NULL)
    scamper_owamp_free(owamp);

  return;
}

void scamper_do_owamp_free(void *data)
{
  scamper_owamp_free((scamper_owamp_t *)data);
  return;
}

scamper_task_t *scamper_do_owamp_alloctask(void *data,
					   scamper_list_t *list,
					   scamper_cycle_t *cycle,
					   char *errbuf, size_t errlen)
{
  scamper_owamp_t *owamp = (scamper_owamp_t *)data;
  scamper_task_t *task = NULL;

  /* allocate a task structure and store the trace with it */
  if((task = scamper_task_alloc(owamp, &owamp_funcs)) == NULL)
    {
      snprintf(errbuf, errlen, "%s: could not malloc state", __func__);
      goto err;
    }

  /* associate the list and cycle with the owamp structure */
  owamp->list = scamper_list_use(list);
  owamp->cycle = scamper_cycle_use(cycle);

  return task;

 err:
  if(task != NULL)
    {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
    }
  return NULL;
}

uint32_t scamper_do_owamp_userid(void *data)
{
  return ((scamper_owamp_t *)data)->userid;
}

int scamper_do_owamp_enabled(void)
{
  return config->owamp_enable;
}

void scamper_do_owamp_cleanup(void)
{
  return;
}

int scamper_do_owamp_init(void)
{
  owamp_funcs.probe          = do_owamp_probe;
  owamp_funcs.handle_timeout = do_owamp_handle_timeout;
  owamp_funcs.handle_udp     = do_owamp_handle_udp;
  owamp_funcs.write          = do_owamp_write;
  owamp_funcs.task_free      = do_owamp_free;
  owamp_funcs.halt           = do_owamp_halt;

  return 0;
}
