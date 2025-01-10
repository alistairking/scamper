/*
 * unit_host_warts : unit tests for warts host storage
 *
 * $Id: unit_ping_warts.c,v 1.3 2024/10/14 07:51:42 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024 Matthew Luckie
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

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_file.h"
#include "scamper_ping.h"
#include "scamper_ping_int.h"
#include "scamper_ifname.h"
#include "scamper_ifname_int.h"

#include "utils.h"
#include "mjl_list.h"

#include "common_warts.h"

typedef scamper_ping_t * (*test_func_t)(void);

static int v4rr_ok(const scamper_ping_reply_v4rr_t *in,
		   const scamper_ping_reply_v4rr_t *out)
{
  uint8_t i;

  if(in == NULL && out == NULL)
    return 0;

  if((in != NULL && out == NULL) ||
     (in == NULL && out != NULL) ||
     in->ipc != out->ipc)
    return -1;

  for(i=0; i<in->ipc; i++)
    if(addr_ok(in->ip[i], out->ip[i]) != 0)
      return -1;

  return 0;
}

static int ping_reply_ok(const scamper_ping_reply_t *in,
			 const scamper_ping_reply_t *out)
{
  if(in == NULL && out == NULL)
    return 0;

  if((in != NULL && out == NULL) ||
     (in == NULL && out != NULL) ||
     addr_ok(in->addr, out->addr) != 0 ||
     in->probe_id != out->probe_id ||
     in->probe_ipid != out->probe_ipid ||
     in->probe_sport != out->probe_sport ||
     in->reply_proto != out->reply_proto ||
     in->reply_ttl != out->reply_ttl ||
     in->reply_tos != out->reply_tos ||
     in->reply_size != out->reply_size ||
     in->reply_ipid != out->reply_ipid ||
     in->reply_ipid32 != out->reply_ipid32 ||
     in->flags != out->flags ||
     in->icmp_type != out->icmp_type ||
     in->icmp_code != out->icmp_code ||
     in->tcp_flags != out->tcp_flags ||
     timeval_cmp(&in->tx, &out->tx) != 0 ||
     timeval_cmp(&in->rtt, &out->rtt) != 0 ||
     ifname_ok(in->ifname, out->ifname) != 0 ||
     v4rr_ok(in->v4rr, out->v4rr) != 0)
    return -1;

  return 0;
}

static int ping_ok(const scamper_ping_t *in, const scamper_ping_t *out)
{
  uint16_t i;

  assert(in != NULL);
  if(out == NULL ||
     addr_ok(in->src, out->src) != 0 ||
     addr_ok(in->dst, out->dst) != 0 ||
     addr_ok(in->rtr, out->rtr) != 0 ||
     in->userid != out->userid ||
     timeval_cmp(&in->start, &out->start) != 0 ||
     in->stop_reason != out->stop_reason ||
     timeval_cmp(&in->wait_probe, &out->wait_probe) != 0 ||
     timeval_cmp(&in->wait_timeout, &out->wait_timeout) != 0 ||
     in->probe_count != out->probe_count ||
     in->probe_size != out->probe_size ||
     in->probe_method != out->probe_method ||
     in->probe_ttl != out->probe_ttl ||
     in->probe_tos != out->probe_tos ||
     in->probe_sport != out->probe_sport ||
     in->probe_dport != out->probe_dport ||
     in->probe_icmpsum != out->probe_icmpsum ||
     in->probe_tcpseq != out->probe_tcpseq ||
     in->probe_tcpack != out->probe_tcpack ||
     in->reply_count != out->reply_count ||
     in->reply_pmtu != out->reply_pmtu ||
     in->flags != out->flags ||
     in->ping_sent != out->ping_sent)
    return -1;

  for(i=0; i<in->ping_sent; i++)
    if(ping_reply_ok(in->ping_replies[i], out->ping_replies[i]) != 0)
      return -1;

  return 0;
}

static scamper_ping_t *ping_1(void)
{
  scamper_ping_t *ping = NULL;
  scamper_ping_reply_t *reply;
  uint8_t pd[] = {0xAA, 0xBB, 0xCC, 0xDD};

  if((ping = scamper_ping_alloc()) == NULL ||
     (ping->src = scamper_addr_fromstr_ipv6("2001:db8::1")) == NULL ||
     (ping->dst = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL ||
     (ping->rtr = scamper_addr_fromstr_ipv6("2001:db8::3")) == NULL ||
     (ping->probe_data = memdup(pd, sizeof(pd))) == NULL ||
     (ping->ping_replies = malloc_zero(sizeof(void *) * 4)) == NULL)
    goto err;

  ping->userid               = 123456;
  ping->start.tv_sec         = 1724828853;
  ping->start.tv_usec        = 123456;
  ping->stop_reason          = SCAMPER_PING_STOP_COMPLETED;
  ping->probe_datalen        = sizeof(pd);
  ping->wait_probe.tv_sec    = 1;
  ping->wait_probe.tv_usec   = 0;
  ping->wait_timeout.tv_sec  = 5;
  ping->wait_timeout.tv_usec = 0;
  ping->probe_count          = 4;
  ping->probe_size           = 1400;
  ping->probe_method         = SCAMPER_PING_METHOD_ICMP_ECHO;
  ping->probe_ttl            = 64;
  ping->probe_tos            = 0;
  ping->probe_sport          = 0x1234;
  ping->probe_dport          = 5;
  ping->flags               |= SCAMPER_PING_FLAG_ICMPSUM;
  ping->probe_icmpsum        = 32;
  ping->reply_count          = 1;
  ping->reply_pmtu           = 1280;
  ping->ping_sent            = 4;

  if((ping->ping_replies[3] = reply = scamper_ping_reply_alloc()) == NULL ||
     (reply->addr = scamper_addr_fromstr_ipv6("2001:db8::2")) == NULL ||
     (reply->ifname = scamper_ifname_alloc("em0")) == NULL)
    goto err;
  reply->probe_id    = 3;
  reply->reply_proto = IPPROTO_ICMPV6;
  reply->reply_tos   = 0x1f;
  reply->reply_size  = 1400;
  reply->icmp_type   = ICMP6_ECHO_REPLY;
  reply->tx.tv_sec   = 1724828853;
  reply->tx.tv_usec  = 123567;
  reply->rtt.tv_sec  = 0;
  reply->rtt.tv_usec = 1423;

  return ping;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  return NULL;
}

static scamper_ping_t *ping_2(void)
{
  scamper_ping_t *ping = NULL;
  scamper_ping_reply_t *reply;

  if((ping = scamper_ping_alloc()) == NULL ||
     (ping->src = scamper_addr_fromstr_ipv4("192.0.2.1")) == NULL ||
     (ping->dst = scamper_addr_fromstr_ipv4("192.0.30.64")) == NULL ||
     (ping->ping_replies = malloc_zero(sizeof(void *) * 1)) == NULL)
    goto err;

  ping->userid               = 123457;
  ping->start.tv_sec         = 1724828854;
  ping->start.tv_usec        = 234567;
  ping->stop_reason          = SCAMPER_PING_STOP_COMPLETED;
  ping->wait_probe.tv_sec    = 1;
  ping->wait_probe.tv_usec   = 0;
  ping->wait_timeout.tv_sec  = 5;
  ping->wait_timeout.tv_usec = 0;
  ping->probe_count          = 4;
  ping->probe_size           = 192;
  ping->probe_method         = SCAMPER_PING_METHOD_ICMP_ECHO;
  ping->probe_ttl            = 64;
  ping->probe_tos            = 0;
  ping->probe_sport          = 0x1234;
  ping->probe_dport          = 5;
  ping->flags               |= SCAMPER_PING_FLAG_ICMPSUM;
  ping->probe_icmpsum        = 32;
  ping->reply_count          = 1;
  ping->ping_sent            = 1;

  if((ping->ping_replies[0] = reply = scamper_ping_reply_alloc()) == NULL ||
     (reply->addr = scamper_addr_fromstr_ipv4("192.0.30.64")) == NULL ||
     (reply->ifname = scamper_ifname_alloc("em0")) == NULL ||
     (reply->v4rr = scamper_ping_reply_v4rr_alloc(5)) == NULL ||
     (reply->v4rr->ip[0] = scamper_addr_fromstr_ipv4("192.0.31.4")) == NULL ||
     (reply->v4rr->ip[1] = scamper_addr_fromstr_ipv4("192.0.31.8")) == NULL ||
     (reply->v4rr->ip[2] = scamper_addr_fromstr_ipv4("192.0.31.12")) == NULL ||
     (reply->v4rr->ip[3] = scamper_addr_fromstr_ipv4("192.0.31.16")) == NULL ||
     (reply->v4rr->ip[4] = scamper_addr_fromstr_ipv4("192.0.31.20")) == NULL)
    goto err;
  reply->probe_id    = 0;
  reply->flags      |= SCAMPER_PING_REPLY_FLAG_PROBE_IPID;
  reply->probe_ipid  = 0xaabb;
  reply->reply_proto = IPPROTO_ICMP;
  reply->reply_tos   = 1;
  reply->reply_size  = 192;
  reply->flags      |= SCAMPER_PING_REPLY_FLAG_REPLY_IPID;
  reply->reply_ipid  = 0xbbaa;
  reply->icmp_type   = ICMP_ECHOREPLY;
  reply->tx.tv_sec   = 1724828854;
  reply->tx.tv_usec  = 234789;
  reply->rtt.tv_sec  = 0;
  reply->rtt.tv_usec = 4242;

  return ping;

 err:
  if(ping != NULL) scamper_ping_free(ping);
  return NULL;
}

static int write_file(const char *filename, const scamper_ping_t *ping)
{
  scamper_file_t *file = NULL;
  int rc = -1;

  if((file = scamper_file_open(filename, 'w', "warts")) == NULL ||
     scamper_file_write_ping(file, ping, NULL) != 0)
    {
      printf("could not write\n");
      goto done;
    }
  rc = 0;

 done:
  if(file != NULL) scamper_file_close(file);
  return rc;
}

static int check_file(const char *filename, const scamper_ping_t *in)
{
  scamper_file_t *file = NULL;
  uint16_t obj_type;
  void *obj_data = NULL;
  int rc = -1;

  if((file = scamper_file_open(filename, 'r', "warts")) == NULL ||
     scamper_file_read(file, NULL, &obj_type, &obj_data) != 0 ||
     obj_type != SCAMPER_FILE_OBJ_PING ||
     ping_ok(in, obj_data) != 0)
    goto done;

  rc = 0;

 done:
  if(obj_data != NULL && obj_type == SCAMPER_FILE_OBJ_PING)
    scamper_ping_free(obj_data);
  if(file != NULL) scamper_file_close(file);
  return rc;  
}

int main(int argc, char *argv[])
{
  static test_func_t tests[] = {
    ping_1,
    ping_2,
  };
  size_t i, testc = sizeof(tests) / sizeof(test_func_t);
  scamper_ping_t *ping;
  char filename[128];
  int check = 0;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
#endif

  if(argc != 3 ||
     (strcasecmp(argv[1], "dump") != 0 &&
      strcasecmp(argv[1], "check") != 0))
    {
      fprintf(stderr, "usage: unit_ping_warts dump|check dir\n");
      return -1;
    }

  if(strcasecmp(argv[1], "check") == 0)
    check = 1;

  for(i=0; i<testc; i++)
    {
      snprintf(filename, sizeof(filename),
	       "%s/ping-%03x.warts", argv[2], (int)i);

#ifdef DMALLOC
      if(check != 0)
	dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

      if((ping = tests[i]()) == NULL)
	{
	  printf("could not create ping %d\n", (int)i);
	  return -1;
	}

      if(write_file(filename, ping) != 0)
	{
	  printf("could not write ping %d\n", (int)i);
	  return -1;
	}

      if(check != 0 && check_file(filename, ping) != 0)
	{
	  printf("fail check %d\n", (int)i);
	  return -1;
	}

      scamper_ping_free(ping);

#ifdef DMALLOC
      if(check != 0)
	{
	  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
	  if(start_mem != stop_mem)
	    {
	      printf("memory leak: %d\n", (int)i);
	      return -1;
	    }
	}
#endif
    }

  if(check != 0)
    printf("OK\n");
  return 0;
}
