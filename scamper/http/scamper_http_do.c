/*
 * scamper_http_do.c
 *
 * $Id: scamper_http_do.c,v 1.14 2024/02/27 03:34:02 mjl Exp $
 *
 * Copyright (C) 2023-2024 The Regents of the University of California
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
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_task.h"
#include "scamper_fds.h"
#include "scamper_queue.h"
#include "scamper_file.h"
#include "scamper_debug.h"
#include "scamper_writebuf.h"
#include "scamper_http.h"
#include "scamper_http_int.h"
#include "scamper_http_do.h"
#include "utils.h"
#include "mjl_list.h"

#ifdef HAVE_OPENSSL
#include "utils_tls.h"
#endif

static scamper_task_funcs_t http_funcs;

/* address cache used to avoid reallocating the same address multiple times */
extern scamper_addrcache_t *addrcache;

/* TLS context that has certificates loaded and can verify */
#ifdef HAVE_OPENSSL
extern SSL_CTX *default_tls_ctx;
#endif

typedef struct http_state
{
  scamper_fd_t       *fdn;
  int                 mode;
  int                 eoh;
  scamper_writebuf_t *wb;
  slist_t            *htbs;
  struct timeval      finish;
#ifdef HAVE_OPENSSL
  SSL                *ssl;
  BIO                *ssl_rbio;
  BIO                *ssl_wbio;
#endif
} http_state_t;

#define STATE_MODE_CONNECT   0
#define STATE_MODE_CONNECTED 7
#define STATE_MODE_TLS_HS  5 /* doing TLS handshake */
#define STATE_MODE_TLS_EST 6 /* TLS established */
#define STATE_MODE_REQ     2 /* currently sending request */
#define STATE_MODE_WAIT    3 /* waiting for response */
#define STATE_MODE_DATA    4 /* got all of header, reading data */
#define STATE_MODE_DONE    1

static const char *http_mode(int mode)
{
  switch(mode)
    {
    case STATE_MODE_CONNECT:   return "connect";
    case STATE_MODE_CONNECTED: return "connected";
    case STATE_MODE_TLS_HS:    return "tls-hs";
    case STATE_MODE_TLS_EST:   return "tls-est";
    case STATE_MODE_REQ:       return "req";
    case STATE_MODE_WAIT:      return "wait";
    case STATE_MODE_DATA:      return "data";
    case STATE_MODE_DONE:      return "done";
    }
  return "unknown";
}

static scamper_http_t *http_getdata(const scamper_task_t *task)
{
  return scamper_task_getdata(task);
}

static http_state_t *http_getstate(const scamper_task_t *task)
{
  return scamper_task_getstate(task);
}

static void http_stop(scamper_task_t *task, uint8_t reason)
{
  scamper_http_t *http = http_getdata(task);
  http_state_t *state = http_getstate(task);
  scamper_http_buf_t *htb;
  int i, bufc;

  if(http->stop == SCAMPER_HTTP_STOP_NONE)
    http->stop = reason;

  if(state != NULL && http->bufc == 0)
    {
      bufc = slist_count(state->htbs); i = 0;
      if((http->bufs = malloc_zero(sizeof(scamper_http_buf_t *)*bufc)) != NULL)
	{
	  while((htb = slist_head_pop(state->htbs)) != NULL)
	    http->bufs[i++] = htb;
	  http->bufc = i;
	}
    }

  scamper_task_queue_done(task, 0);
  return;
}

static void http_queue(scamper_task_t *task)
{
  http_state_t *state = http_getstate(task);
  if(scamper_task_queue_isdone(task))
    return;
  if(scamper_writebuf_gtzero(state->wb))
    scamper_task_queue_probe(task);
  else
    scamper_task_queue_wait_tv(task, &state->finish);
  return;
}

static void http_state_free(http_state_t *state)
{
#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

#ifdef HAVE_OPENSSL
  /*
   * SSL_free() also calls the free()ing procedures for indirectly
   * affected items, if applicable: the buffering BIO, the read and
   * write BIOs, cipher lists specially created for this ssl, the
   * SSL_SESSION. Do not explicitly free these indirectly freed up
   * items before or after calling SSL_free(), as trying to free
   * things twice may lead to program failure.
   */
  if(state->ssl != NULL)
    {
      SSL_free(state->ssl);
    }
  else
    {
      if(state->ssl_wbio != NULL)
	BIO_free(state->ssl_wbio);
      if(state->ssl_rbio != NULL)
	BIO_free(state->ssl_rbio);
    }
#endif
  if(state->htbs != NULL)
    slist_free_cb(state->htbs, (slist_free_t)scamper_http_buf_free);
  if(state->wb != NULL)
    scamper_writebuf_free(state->wb);
  if(state->fdn != NULL)
    {
      fd = scamper_fd_fd_get(state->fdn);
      if(socket_isvalid(fd))
	socket_close(fd);
      scamper_fd_free(state->fdn);
    }
  free(state);
  return;
}

static int http_buf_add(http_state_t *state, uint8_t dir, uint8_t type,
			const struct timeval *tv,
			const void *buf, uint32_t len)
{
  scamper_http_buf_t *htb;
  if((htb = malloc_zero(sizeof(scamper_http_buf_t))) == NULL ||
     (htb->data = memdup(buf, len)) == NULL ||
     slist_tail_push(state->htbs, htb) == NULL)
    goto err;
  htb->dir = dir;
  htb->type = type;
  htb->len = len;
  timeval_cpy(&htb->tv, tv);
  return 0;

 err:
  if(htb != NULL) scamper_http_buf_free(htb);
  return -1;
}

static int http_read_payload(http_state_t *state, uint8_t *buf, size_t len)
{
  struct timeval tv;
  size_t i;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

  fd = scamper_fd_fd_get(state->fdn);
  shutdown(fd, SHUT_WR);

  gettimeofday_wrap(&tv);

  buf[len+1] = '\0';

  if(state->mode == STATE_MODE_REQ || state->mode == STATE_MODE_WAIT)
    {
      for(i=0; i<len; i++)
	{
	  if(((state->eoh == 0 || state->eoh == 2) && buf[i] == '\r') ||
	     ((state->eoh == 1 || state->eoh == 3) && buf[i] == '\n'))
	    {
	      state->eoh++;
	      if(state->eoh == 4)
		{
		  i++;
		  if(http_buf_add(state, SCAMPER_HTTP_BUF_DIR_RX,
				  SCAMPER_HTTP_BUF_TYPE_HDR, &tv, buf, i) != 0)
		    return -1;
		  state->mode = STATE_MODE_DATA;
		  if(i < len)
		    {
		      if(http_buf_add(state, SCAMPER_HTTP_BUF_DIR_RX,
				      SCAMPER_HTTP_BUF_TYPE_DATA,
				      &tv, buf+i, len-i) != 0)
			return -1;
		    }
		  return 0;
		}
	    }
	  else state->eoh = 0;
	}
      if(http_buf_add(state, SCAMPER_HTTP_BUF_DIR_RX,
		      SCAMPER_HTTP_BUF_TYPE_HDR, &tv, buf, len) != 0)
	return -1;
    }
  else if(state->mode == STATE_MODE_DATA)
    {
      if(http_buf_add(state, SCAMPER_HTTP_BUF_DIR_RX,
		      SCAMPER_HTTP_BUF_TYPE_DATA, &tv, buf, len) != 0)
	return -1;
    }

  return 0;
}

#ifdef HAVE_OPENSSL
static int tls_want_read(http_state_t *state)
{
  uint8_t buf[1024];
  int pending, rc, size, off = 0;
  struct timeval tv;

  if((pending = BIO_pending(state->ssl_wbio)) < 0)
    return -1;

  gettimeofday_wrap(&tv);

  while(off < pending)
    {
      if((size_t)(pending - off) > sizeof(buf))
	size = sizeof(buf);
      else
	size = pending - off;

      if((rc = BIO_read(state->ssl_wbio, buf, size)) <= 0)
	{
	  if(BIO_should_retry(state->ssl_wbio) == 0)
	    scamper_debug(__func__, "BIO_read should not retry");
	  else
	    scamper_debug(__func__, "BIO_read returned %d", rc);
	  return -1;
	}
      off += rc;

      if(state->mode == STATE_MODE_TLS_HS &&
	 http_buf_add(state, SCAMPER_HTTP_BUF_DIR_TX,
		      SCAMPER_HTTP_BUF_TYPE_TLS, &tv, buf, rc) != 0)
	return -1;

      scamper_writebuf_send(state->wb, buf, rc);
    }

  return 0;
}

static int tls_handshake(scamper_task_t *task)
{
  scamper_http_t *http = http_getdata(task);
  http_state_t *state = http_getstate(task);
  int rc;

  /*
   * the order is important because once the BIOs are associated with
   * the ssl structure, SSL_free will clean them up.
   */
  if((state->ssl_wbio = BIO_new(BIO_s_mem())) == NULL ||
     (state->ssl_rbio = BIO_new(BIO_s_mem())) == NULL ||
     (state->ssl = SSL_new(default_tls_ctx)) == NULL)
    return -1;

  SSL_set_bio(state->ssl, state->ssl_rbio, state->ssl_wbio);
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
  if(http->host != NULL) SSL_set_tlsext_host_name(state->ssl, http->host);
#endif
  SSL_set_connect_state(state->ssl);

  rc = SSL_do_handshake(state->ssl);
  assert(rc <= 0);

  if((rc = SSL_get_error(state->ssl, rc)) != SSL_ERROR_WANT_READ)
    {
      scamper_debug(__func__, "SSL_do_handshake error %d", rc);
      return -1;
    }

  state->mode = STATE_MODE_TLS_HS;
  return tls_want_read(state);
}
#endif /* HAVE_OPENSSL */

static int http_read_sock(scamper_task_t *task)
{
  http_state_t *state = http_getstate(task);
  ssize_t rrc;
  uint8_t buf[8192];

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd;
#else
  SOCKET fd;
#endif

#ifdef HAVE_OPENSSL
  scamper_http_t *http;
  struct timeval tv;
  int ecode, ret;
#endif

  fd = scamper_fd_fd_get(state->fdn);

  if((rrc = recv(fd, buf, sizeof(buf)-1, 0)) < 0)
    {
      if(errno == EAGAIN || errno == EINTR)
	return 1;
      printerror(__func__, "could not recv from %d", fd);
      return -1;
    }

  if(rrc == 0)
    {
      scamper_debug(__func__, "disconnected fd %d", fd);
      return 0;
    }

#ifdef HAVE_OPENSSL
  if(state->ssl != NULL)
    {
      BIO_write(state->ssl_rbio, buf, rrc);
      if(state->mode == STATE_MODE_TLS_HS)
	{
	  gettimeofday_wrap(&tv);
	  if(http_buf_add(state, SCAMPER_HTTP_BUF_DIR_RX,
			  SCAMPER_HTTP_BUF_TYPE_TLS, &tv, buf, rrc) != 0)
	    return -1;

	  http = http_getdata(task);

	  if(SSL_is_init_finished(state->ssl) != 0)
	    {
	      if(SCAMPER_HTTP_FLAG_IS_INSECURE(http) == 0 &&
		 tls_is_valid_cert(state->ssl, http->host) == 0)
		{
		  http->stop = SCAMPER_HTTP_STOP_INSECURE;
		  return -1;
		}
	      state->mode = STATE_MODE_TLS_EST;
	      return 1;
	    }

	  ERR_clear_error();
	  if((ret = SSL_do_handshake(state->ssl)) > 0)
	    {
	      if(SCAMPER_HTTP_FLAG_IS_INSECURE(http) == 0 &&
		 tls_is_valid_cert(state->ssl, http->host) == 0)
		{
		  http->stop = SCAMPER_HTTP_STOP_INSECURE;
		  return -1;
		}
	      state->mode = STATE_MODE_TLS_EST;
	      return 1;
	    }
	}
      else
	{
	  ERR_clear_error();
	  while((ret = SSL_read(state->ssl, buf, sizeof(buf))) > 0)
	    {
	      if(http_read_payload(state, buf, (size_t)ret) != 0)
		return -1;
	    }
	}

      if((ecode = SSL_get_error(state->ssl, ret)) == SSL_ERROR_WANT_READ)
	{
	  if(tls_want_read(state) < 0)
	    return -1;
	}
      else if(ecode == SSL_ERROR_ZERO_RETURN)
	{
	  return 0;
	}
      else if(ecode != SSL_ERROR_WANT_WRITE)
	{
	  printerror_ssl(__func__, "mode %s ecode %d",
			 http_mode(state->mode), ecode);
	  return -1;
	}

      return 1;
    }
#endif

  if(http_read_payload(state, buf, (size_t)rrc) != 0)
    return -1;
  return 1;
}

static char *scamper_version(void)
{
  static char out[16];
  char *in = SCAMPER_VERSION;
  size_t off = 0;
  while(*in != '\0' && off < 15)
    {
      if(*in == ' ')
	out[off++] = '-';
      else
	out[off++] = *in;
      in++;
    }
  out[off] = '\0';
  return out;
}

static int http_req(scamper_task_t *task)
{
  scamper_http_t *http = http_getdata(task);
  http_state_t *state = http_getstate(task);
  struct timeval tv;
  size_t off = 0, len;
  char *buf = NULL;
  int rc = -1;
  uint8_t h;
  char *h_ua = NULL, ua_buf[48], *h_acc = NULL;

  len = 15 + /* GET %s HTTP/1.1 */
    strlen(http->file) +
    (http->host != NULL ? 8 + strlen(http->host) : 0) + /* Host: */
    2 + 1; /* empty line + null terminator for string_concat */

  for(h=0; h<http->headerc; h++)
    {
      if(strncasecmp(http->headers[h], "user-agent:", 11) == 0)
	h_ua = http->headers[h];
      else if(strncasecmp(http->headers[h], "accept:", 7) == 0)
	h_acc = http->headers[h];
      else
	len += strlen(http->headers[h]) + 2;
    }

  if(h_ua == NULL)
    {
      snprintf(ua_buf, sizeof(ua_buf),
	       "User-Agent: scamper/%s", scamper_version());
      h_ua = ua_buf;
    }
  len += strlen(h_ua) + 2;

  if(h_acc != NULL)
    len += strlen(h_acc) + 2;
  else
    len += 13;

  if((buf = malloc(len)) == NULL)
    goto done;

  /* form the headers */
  string_concat(buf, len, &off, "GET %s HTTP/1.1\r\n", http->file);
  if(http->host != NULL)
    string_concat(buf, len, &off, "Host: %s\r\n", http->host);
  string_concat(buf, len, &off, "%s\r\n", h_ua);
  if(h_acc != NULL)
    string_concat(buf, len, &off, "%s\r\n", h_acc);
  else
    string_concat(buf, len, &off, "Accept: */*\r\n");
  for(h=0; h<http->headerc; h++)
    {
      if(strncasecmp(http->headers[h], "user-agent:", 11) != 0 &&
	 strncasecmp(http->headers[h], "accept:", 7) != 0)
	string_concat(buf, len, &off, "%s\r\n", http->headers[h]);
    }
  string_concat(buf, len, &off, "\r\n");

  gettimeofday_wrap(&tv);
  if(http_buf_add(state, SCAMPER_HTTP_BUF_DIR_TX,
		  SCAMPER_HTTP_BUF_TYPE_HDR, &tv, buf, len) != 0)
    goto done;

  state->mode = STATE_MODE_REQ;

#ifdef HAVE_OPENSSL
  if(state->ssl != NULL)
    {
      SSL_write(state->ssl, buf, len-1);
      tls_want_read(state);
      rc = 0;
      goto done;
    }
#endif

  if(scamper_writebuf_send(state->wb, buf, len-1) != 0)
    goto done;

  rc = 0;

 done:
  if(buf != NULL) free(buf);
  return rc;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
static void http_read(int fd, void *param)
#else
static void http_read(SOCKET fd, void *param)
#endif
{
  scamper_task_t *task = param;
  http_state_t *state = http_getstate(task);
  socklen_t sl;
  int rc, error;

#ifdef HAVE_OPENSSL
  int enter_mode = state->mode;
#endif

  /* if we get a read event during connect, then we could not connect */
  if(state->mode == STATE_MODE_CONNECT)
    {
      sl = sizeof(error);
      if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &sl) == 0)
	scamper_debug(__func__, "could not connect: %s", strerror(error));
      http_stop(task, SCAMPER_HTTP_STOP_NOCONN);
      state->mode = STATE_MODE_DONE;
      return;
    }

  if((rc = http_read_sock(task)) < 0)
    {
      http_stop(task, SCAMPER_HTTP_STOP_ERROR);
      state->mode = STATE_MODE_DONE;
      return;
    }

  if(rc == 0)
    {
      scamper_debug(__func__, "disconnected fd %d", fd);
      http_stop(task, SCAMPER_HTTP_STOP_DONE);
      state->mode = STATE_MODE_DONE;
      return;
    }

#ifdef HAVE_OPENSSL
  if(state->ssl != NULL && enter_mode == STATE_MODE_TLS_HS &&
     state->mode == STATE_MODE_TLS_EST)
    {
      http_req(task);
    }
#endif

  http_queue(task);
  return;
}

#ifndef _WIN32 /* SOCKET vs int on windows */
static void http_write(int fd, void *param)
#else
static void http_write(SOCKET fd, void *param)
#endif
{
  scamper_task_t *task = param;
  scamper_http_t *http = http_getdata(task);
  http_state_t *state = http_getstate(task);
  struct timeval tv;

  /* always pause -- call unpause from the probe function */
  scamper_fd_write_pause(state->fdn);

  /*
   * we successfully connected.  nothing else to do now.  wait to
   * form first transmission in do_http_probe
   */
  if(state->mode == STATE_MODE_CONNECT)
    {
      gettimeofday_wrap(&tv);
      timeval_diff_tv(&http->hsrtt, &http->start, &tv);
      state->mode = STATE_MODE_CONNECTED;
      scamper_task_queue_probe(task);
      return;
    }

  /*
   * make sure that we have something to write.  otherwise we have a
   * logic error, as we should only be in this function because we
   * unpaused write (i.e., had something in writebuf to send
   */
  if(scamper_writebuf_gtzero(state->wb) == 0)
    {
      scamper_debug(__func__, "nothing in writebuf, mode %s",
		    http_mode(state->mode));
      goto err;
    }

  /* write whatever we have */
  if(scamper_writebuf_write(fd, state->wb) != 0)
    {
      scamper_debug(__func__, "could not write from writebuf, mode %s",
		    http_mode(state->mode));
      goto err;
    }

  http_queue(task);
  return;

 err:
  http_stop(task, SCAMPER_HTTP_STOP_ERROR);
  return;
}

static int http_state_alloc(scamper_task_t *task)
{
  scamper_http_t *http = http_getdata(task);
  http_state_t *state = NULL;
  struct sockaddr_storage ss;
  struct sockaddr *sa;
  void *addr;
  socklen_t sl;
  int at, af;

#ifndef _WIN32 /* SOCKET vs int on windows */
  int fd = -1;
#else
  SOCKET fd = INVALID_SOCKET;
#endif

  if((state = malloc_zero(sizeof(http_state_t))) == NULL)
    {
      printerror(__func__, "could not alloc state");
      goto err;
    }

  /* set timeout */
  timeval_add_tv3(&state->finish, &http->start, &http->maxtime);

  af = scamper_addr_af(http->dst);
  sa = (struct sockaddr *)&ss;
  if(sockaddr_compose(sa, af, http->dst->addr, http->dport) != 0)
    {
      printerror(__func__, "could not compose sockaddr");
      goto err;
    }

  fd = socket(af, SOCK_STREAM, IPPROTO_TCP);
  if(socket_isinvalid(fd))
    {
      printerror(__func__, "could not allocate socket");
      goto err;
    }

#ifdef HAVE_FCNTL
  if(fcntl_set(fd, O_NONBLOCK) == -1)
    {
      printerror(__func__, "could not set O_NONBLOCK");
      goto err;
    }
#endif

  sl = sockaddr_len(sa);
  if(connect(fd, sa, sl) != 0 && errno != EINPROGRESS)
    {
      printerror(__func__, "could not connect");
      goto err;
    }

  if(getsockname(fd, sa, &sl) != 0)
    {
      printerror(__func__, "could not getsockname");
      goto err;
    }

  if(af == AF_INET)
    {
      addr = &((struct sockaddr_in *)&ss)->sin_addr;
      http->sport = ((struct sockaddr_in *)&ss)->sin_port;
      at = SCAMPER_ADDR_TYPE_IPV4;
    }
  else if(af == AF_INET6)
    {
      addr = &((struct sockaddr_in6 *)&ss)->sin6_addr;
      http->sport = ((struct sockaddr_in6 *)&ss)->sin6_port;
      at = SCAMPER_ADDR_TYPE_IPV6;
    }
  else
    {
      scamper_debug(__func__, "unknown af");
      goto err;
    }

  if((http->src = scamper_addrcache_get(addrcache, at, addr)) == NULL ||
     (state->wb = scamper_writebuf_alloc()) == NULL ||
     (state->htbs = slist_alloc()) == NULL)
    {
      scamper_debug(__func__, "allocs failed");
      goto err;
    }

  if((state->fdn = scamper_fd_private(fd,task,http_read,http_write)) == NULL)
    {
      scamper_debug(__func__, "could not register fd");
      goto err;
    }

  scamper_task_setstate(task, state);

  return 0;

 err:
  if(socket_isvalid(fd))
    socket_close(fd);
  if(state != NULL) http_state_free(state);
  return -1;
}

static void do_http_probe(scamper_task_t *task)
{
  scamper_http_t *http = http_getdata(task);
  http_state_t *state = http_getstate(task);

  /* allocate the state -- create a socket so that we can get the 5-tuple */
  if(state == NULL)
    {
      gettimeofday_wrap(&http->start);
      if(http_state_alloc(task) != 0)
	goto err;
      goto done;
    }

  if(state->mode == STATE_MODE_CONNECTED)
    {
#ifdef HAVE_OPENSSL
      if(http->type == SCAMPER_HTTP_TYPE_HTTPS)
	{
	  if(tls_handshake(task) != 0)
	    goto err;
	  goto done;
	}
#endif
      if(http_req(task) != 0)
	goto err;
    }

 done:
  if(state != NULL && scamper_writebuf_gtzero(state->wb))
    scamper_fd_write_unpause(state->fdn);
  http_queue(task);
  return;

 err:
  http_stop(task, SCAMPER_HTTP_STOP_ERROR);
  return;
}

static void do_http_handle_timeout(scamper_task_t *task)
{
  http_stop(task, SCAMPER_HTTP_STOP_TIMEOUT);
  return;
}

static void do_http_write(scamper_file_t *sf, scamper_task_t *task)
{
  scamper_file_write_http(sf, http_getdata(task), task);
  return;
}

static void do_http_halt(scamper_task_t *task)
{
  scamper_http_t *http = http_getdata(task);
  http->stop = SCAMPER_HTTP_STOP_HALTED;
  scamper_task_queue_done(task, 0);
  return;
}

static void do_http_free(scamper_task_t *task)
{
  scamper_http_t *http = http_getdata(task);
  http_state_t *state = http_getstate(task);

  if(state != NULL)
    http_state_free(state);
  if(http != NULL)
    scamper_http_free(http);

  return;
}

void scamper_do_http_free(void *data)
{
  scamper_http_free((scamper_http_t *)data);
  return;
}

scamper_task_t *scamper_do_http_alloctask(void *data,
					  scamper_list_t *list,
					  scamper_cycle_t *cycle,
					  char *errbuf, size_t errlen)
{
  scamper_http_t *http = (scamper_http_t *)data;
  scamper_task_t *task = NULL;

  /* allocate a task structure and store the trace with it */
  if((task = scamper_task_alloc(http, &http_funcs)) == NULL)
    {
      snprintf(errbuf, errlen, "%s: could not malloc state", __func__);
      goto err;
    }

  /* associate the list and cycle with the http structure */
  http->list = scamper_list_use(list);
  http->cycle = scamper_cycle_use(cycle);

  return task;

 err:
  if(task != NULL)
    {
      scamper_task_setdatanull(task);
      scamper_task_free(task);
    }
  return NULL;
}

uint32_t scamper_do_http_userid(void *data)
{
  return ((scamper_http_t *)data)->userid;
}

void scamper_do_http_cleanup(void)
{
  return;
}

int scamper_do_http_init(void)
{
  http_funcs.probe          = do_http_probe;
  http_funcs.handle_timeout = do_http_handle_timeout;
  http_funcs.write          = do_http_write;
  http_funcs.task_free      = do_http_free;
  http_funcs.halt           = do_http_halt;

  return 0;
}
