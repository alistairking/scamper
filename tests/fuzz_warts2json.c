/*
 * fuzz_warts2json : fuzzer for reading warts and converting to json
 *
 * $Id: fuzz_warts2json.c,v 1.1 2025/05/03 09:37:13 mjl Exp $
 *
 *        Marcus Luckie, Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024 Marcus Luckie
 * Copyright (C) 2024-2025 Matthew Luckie
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
#include "host/scamper_host.h"
#include "trace/scamper_trace.h"
#include "tracelb/scamper_tracelb.h"
#include "sniff/scamper_sniff.h"
#include "http/scamper_http.h"
#include "neighbourdisc/scamper_neighbourdisc.h"
#include "ping/scamper_ping.h"
#include "dealias/scamper_dealias.h"
#include "udpprobe/scamper_udpprobe.h"
#include "tbit/scamper_tbit.h"
#include "sting/scamper_sting.h"

static void check(const char *filename)
{
  scamper_file_t *file = NULL;
  uint16_t obj_type;
  void *obj_data = NULL;
  size_t json_len;
  char *json;

  if((file = scamper_file_open(filename, 'r', "warts")) == NULL)
    {
      fprintf(stderr, "could not open %s\n", filename);
      return;
    }

  while(scamper_file_read(file, NULL, &obj_type, &obj_data) == 0)
    {
      if(obj_data == NULL)
	break;
      json = NULL;
      switch(obj_type)
	{
	case SCAMPER_FILE_OBJ_LIST:
	  scamper_list_free(obj_data);
	  break;

	case SCAMPER_FILE_OBJ_CYCLE_START:
	case SCAMPER_FILE_OBJ_CYCLE_DEF:
	case SCAMPER_FILE_OBJ_CYCLE_STOP:
	  scamper_cycle_free(obj_data);
	  break;

	case SCAMPER_FILE_OBJ_TRACE:
	  json = scamper_trace_tojson(obj_data, &json_len);
	  scamper_trace_free(obj_data);
	  break;

	case SCAMPER_FILE_OBJ_PING:
	  json = scamper_ping_tojson(obj_data, &json_len);
	  scamper_ping_free(obj_data);
	  break;

	case SCAMPER_FILE_OBJ_TRACELB:
	  json = scamper_tracelb_tojson(obj_data, &json_len);
	  scamper_tracelb_free(obj_data);
	  break;

	case SCAMPER_FILE_OBJ_DEALIAS:
	  json = scamper_dealias_tojson(obj_data, &json_len);
	  scamper_dealias_free(obj_data);
	  break;

	case SCAMPER_FILE_OBJ_NEIGHBOURDISC:
	  scamper_neighbourdisc_free(obj_data);
	  break;

	case SCAMPER_FILE_OBJ_TBIT:
	  json = scamper_tbit_tojson(obj_data, &json_len);
	  scamper_tbit_free(obj_data);
	  break;

	case SCAMPER_FILE_OBJ_STING:
	  scamper_sting_free(obj_data);
	  break;

	case SCAMPER_FILE_OBJ_SNIFF:
	  scamper_sniff_free(obj_data);
	  break;

	case SCAMPER_FILE_OBJ_HOST:
	  json = scamper_host_tojson(obj_data, &json_len);
	  scamper_host_free(obj_data);
	  break;

	case SCAMPER_FILE_OBJ_HTTP:
	  scamper_http_free(obj_data);
	  break;

	case SCAMPER_FILE_OBJ_UDPPROBE:
	  json = scamper_udpprobe_tojson(obj_data, &json_len);
	  scamper_udpprobe_free(obj_data);
	  break;
	}

      if(json != NULL)
	free(json);
    }

  scamper_file_close(file);
  return;
}

int main(int argc, char *argv[])
{
#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  int assert_mem = 1;
#endif

  if(argc < 2)
    {
      printf("missing input\n");
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

  check(argv[1]);

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(assert_mem != 0)
    assert(start_mem == stop_mem);
#endif

  return 0;
}
