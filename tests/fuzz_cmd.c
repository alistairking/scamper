/*
 * fuzz_cmd : simple program to fuzz specific command input paths
 *
 * $Id: fuzz_cmd.c,v 1.11 2024/05/02 02:34:11 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_list.h"

#ifdef FUZZ_DEALIAS
#include "scamper_dealias.h"
#include "scamper_dealias_cmd.h"
#endif

#ifdef FUZZ_HOST
#include "scamper_host.h"
#include "scamper_host_cmd.h"
#endif

#ifdef FUZZ_HTTP
#include "scamper_http.h"
#include "scamper_http_cmd.h"
#endif

#ifdef FUZZ_NEIGHBOURDISC
#include "scamper_neighbourdisc.h"
#include "scamper_neighbourdisc_cmd.h"
#endif

#ifdef FUZZ_PING
#include "scamper_ping.h"
#include "scamper_ping_cmd.h"
#endif

#ifdef FUZZ_SNIFF
#include "scamper_sniff.h"
#include "scamper_sniff_cmd.h"
#endif

#ifdef FUZZ_STING
#include "scamper_sting.h"
#include "scamper_sting_cmd.h"
#endif

#ifdef FUZZ_TBIT
#include "scamper_tbit.h"
#include "scamper_tbit_cmd.h"
#endif

#ifdef FUZZ_TRACE
#include "scamper_trace.h"
#include "scamper_trace_cmd.h"
#endif

#ifdef FUZZ_TRACELB
#include "scamper_tracelb.h"
#include "scamper_tracelb_cmd.h"
#endif

#ifdef FUZZ_UDPPROBE
#include "scamper_udpprobe.h"
#include "scamper_udpprobe_cmd.h"
#endif

#include "utils.h"

#if defined(FUZZ_TRACE) || defined(FUZZ_SNIFF) || defined(FUZZ_DEALIAS) || \
  defined(FUZZ_NEIGHBOURDISC) || defined(FUZZ_HTTP) || defined(FUZZ_STING) || \
  defined(FUZZ_TBIT)
#define HAVE_ADDRCACHE 1
scamper_addrcache_t *addrcache = NULL;
#endif

static void assert_errbuf(const char *errbuf, size_t len)
{
  size_t i;

  assert(errbuf[0] != '\0');
  for(i=0; i<len; i++)
    {
      if(errbuf[i] == '\0')
	break;
      assert(isprint((unsigned char)errbuf[i]));
    }
  assert(i != len);

  return;
}

static int test(char *in, void *param)
{
  char errbuf[256];
  size_t errlen = sizeof(errbuf);
  void *(*allocdata)(char *, char *, size_t) = NULL;
  void (*freedata)(void *) = NULL;
  void *data;

#if defined(FUZZ_DEALIAS)
  allocdata = scamper_do_dealias_alloc;
  freedata  = (void *)scamper_dealias_free;
#elif defined(FUZZ_HOST)
  allocdata = scamper_do_host_alloc;
  freedata  = (void *)scamper_host_free;
#elif defined(FUZZ_HTTP)
  allocdata = scamper_do_http_alloc;
  freedata  = (void *)scamper_http_free;
#elif defined(FUZZ_NEIGHBOURDISC)
  allocdata = scamper_do_neighbourdisc_alloc;
  freedata  = (void *)scamper_neighbourdisc_free;
#elif defined(FUZZ_PING)
  allocdata = scamper_do_ping_alloc;
  freedata  = (void *)scamper_ping_free;
#elif defined(FUZZ_SNIFF)
  allocdata = scamper_do_sniff_alloc;
  freedata  = (void *)scamper_sniff_free;
#elif defined(FUZZ_STING)
  allocdata = scamper_do_sting_alloc;
  freedata  = (void *)scamper_sting_free;
#elif defined(FUZZ_TBIT)
  allocdata = scamper_do_tbit_alloc;
  freedata  = (void *)scamper_tbit_free;
#elif defined(FUZZ_TRACE)
  allocdata = scamper_do_trace_alloc;
  freedata  = (void *)scamper_trace_free;
#elif defined(FUZZ_TRACELB)
  allocdata = scamper_do_tracelb_alloc;
  freedata  = (void *)scamper_tracelb_free;
#elif defined(FUZZ_UDPPROBE)
  allocdata = scamper_do_udpprobe_alloc;
  freedata  = (void *)scamper_udpprobe_free;
#endif

  errbuf[0] = '\0';
  data = allocdata(in, errbuf, errlen);
  if(data != NULL)
    {
      freedata(data);
      assert(errbuf[0] == '\0');
    }
  else
    {
      assert_errbuf(errbuf, errlen);
    }
  return 0;
}

int main(int argc, char *argv[])
{
#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  int assert_mem = 1;
#endif

  if(argc < 2)
    {
      fprintf(stderr, "missing parameter\n");
      return -1;
    }

  if(argc > 2)
    {
#ifdef DMALLOC
      if(strcmp(argv[2], "0") == 0)
	assert_mem = 0;
#else
      fprintf(stderr, "not compiled with dmalloc support\n");
      return -1;
#endif
    }

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

#ifdef HAVE_ADDRCACHE
  if((addrcache = scamper_addrcache_alloc()) == NULL)
    return -1;
#endif

  if(file_lines(argv[1], test, NULL) != 0)
    {
      fprintf(stderr, "could not process %s\n", argv[1]);
      return -1;
    }

#ifdef HAVE_ADDRCACHE
  scamper_addrcache_free(addrcache);
#endif

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(assert_mem != 0)
    assert(start_mem == stop_mem);
#endif

  return 0;
}
