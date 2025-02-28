/*
 * unit_ping_lib: unit tests for ping library
 *
 * $Id: unit_ping_lib.c,v 1.2 2025/02/25 06:31:24 mjl Exp $
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

#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"
#include "scamper_ping.h"
#include "scamper_ping_int.h"
#include "utils.h"

typedef struct sc_reply_test
{
  char     *dst;
  char     *from;
  uint8_t   at;
  uint8_t   probe_method;
  uint8_t   reply_proto;
  uint8_t   reply_icmp_type;
  uint8_t   reply_icmp_code;
  int       rc;
} sc_reply_test_t;

static int test_reply_is_from_target(void)
{
  sc_reply_test_t tests[] = {
    {"2001:DB8::1", "2001:DB8::2", SCAMPER_ADDR_TYPE_IPV6,
     SCAMPER_PING_METHOD_UDP_SPORT,
     IPPROTO_ICMPV6, ICMP6_TIME_EXCEEDED, 0,
     0
    },
    {"2001:DB8::1", "2001:DB8::2", SCAMPER_ADDR_TYPE_IPV6,
     SCAMPER_PING_METHOD_UDP_SPORT,
     IPPROTO_ICMPV6, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOPORT,
     1
    },
    {"192.0.2.1", "192.0.2.2", SCAMPER_ADDR_TYPE_IPV4,
     SCAMPER_PING_METHOD_UDP_SPORT,
     IPPROTO_ICMP, ICMP_UNREACH, ICMP_UNREACH_PORT,
     1
    },
    {"192.0.2.1", "192.0.2.2", SCAMPER_ADDR_TYPE_IPV4,
     SCAMPER_PING_METHOD_UDP_SPORT,
     IPPROTO_ICMP, ICMP_UNREACH, ICMP_UNREACH_NET,
     0
    },
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_reply_test_t);
  sc_reply_test_t *test;
  scamper_ping_t *ping = NULL;
  scamper_ping_reply_t *reply = NULL;
  int rc = -1;

  for(i=0; i<testc; i++)
    {
      test = &tests[i];
      if((ping = scamper_ping_alloc()) == NULL ||
	 (ping->dst = scamper_addr_fromstr(test->at, test->dst)) == NULL ||
	 (reply = scamper_ping_reply_alloc()) == NULL ||
	 (reply->addr = scamper_addr_fromstr(test->at, test->from)) == NULL)
	goto done;

      ping->method     = test->probe_method;
      reply->proto     = test->reply_proto;
      reply->icmp_type = test->reply_icmp_type;
      reply->icmp_code = test->reply_icmp_code;

      if(SCAMPER_PING_METHOD_IS_ICMP(ping) != 0)
	goto done;

      if(SCAMPER_PING_REPLY_IS_FROM_TARGET(ping, reply) != test->rc)
	goto done;

      if(scamper_ping_reply_is_from_target(ping, reply) != test->rc)
	goto done;

      scamper_ping_free(ping); ping = NULL;
      scamper_ping_reply_free(reply); reply = NULL;
    }

  rc = 0;

 done:
  if(ping != NULL) scamper_ping_free(ping);
  if(reply != NULL) scamper_ping_reply_free(reply);
  return rc;
}

int main(int argc, char *argv[])
{
  static int (* const tests[])(void) = {
    test_reply_is_from_target,
  };
  size_t i, testc = sizeof(tests) / sizeof(void *);

  for(i=0; i<testc; i++)
    if(tests[i]() != 0)
      break;

  if(i != testc)
    return -1;

  printf("OK\n");
  return 0;
}
