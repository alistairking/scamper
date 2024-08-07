/*
 * sc_wartscat
 *
 * This is a utility program to concatenate warts data files together.
 *
 * $Id: sc_wartscat.c,v 1.48 2024/03/04 01:52:23 mjl Exp $
 *
 * Copyright (C) 2007-2011 The University of Waikato
 * Copyright (C) 2022-2023 Matthew Luckie
 * Copyright (C) 2023-2024 The Regents of the University of California
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

#include "scamper_addr.h"
#include "scamper_list.h"
#include "trace/scamper_trace.h"
#include "tracelb/scamper_tracelb.h"
#include "ping/scamper_ping.h"
#include "dealias/scamper_dealias.h"
#include "tbit/scamper_tbit.h"
#include "neighbourdisc/scamper_neighbourdisc.h"
#include "sting/scamper_sting.h"
#include "sniff/scamper_sniff.h"
#include "host/scamper_host.h"
#include "http/scamper_http.h"
#include "udpprobe/scamper_udpprobe.h"
#include "scamper_file.h"
#include "mjl_heap.h"
#include "utils.h"

#define OPT_OUTFILE 0x00000001 /* o: */
#define OPT_SORT    0x00000002 /* s: */
#define OPT_HELP    0x00000004 /* ?: */

static uint32_t                options    = 0;
static int                     infile_cnt = 0;
static scamper_file_t        **infiles    = NULL;
static scamper_file_t         *outfile    = NULL;
static scamper_file_filter_t  *filter     = NULL;

/*
 * sort_struct
 *
 * structure that is used when warts-cat has to sort input data items.
 */
typedef struct sort_struct
{
  /* type type and data just read from the file */
  uint16_t        type;
  void           *data;

  /* timestamp associated with the data object */
  struct timeval  tv;

  /* index into infiles array */
  int             file;
} sort_struct_t;

static void usage(const char *argv0, uint32_t opt_mask)
{
  fprintf(stderr,
	  "usage: sc_wartscat [-?s] [-o outfile] <infile 1, 2, .. N>\n");

  if(opt_mask == 0) return;

  fprintf(stderr, "\n");

  if(opt_mask & OPT_HELP)
    fprintf(stderr, "    -? give an overview of the usage of sc_wartscat\n");

  if(opt_mask & OPT_OUTFILE)
    fprintf(stderr, "    -o output file to concatenate to\n");

  if(opt_mask & OPT_SORT)
    fprintf(stderr, "    -s sort objects in input file by timestamp\n");

  return;
}

static int check_options(int argc, char *argv[])
{
  int   i, ch;
  char *opts = "o:s?";
  char *opt_outfile = NULL;
  char *outfile_type = "warts";
  char m = 'a';

  while((i = getopt(argc, argv, opts)) != -1)
    {
      ch = (char)i;
      switch(ch)
	{
	case 'o':
	  options |= OPT_OUTFILE;
	  opt_outfile = optarg;
	  break;

	case 's':
	  options |= OPT_SORT;
	  break;

	case '?':
	default:
	  usage(argv[0], 0xffffffff);
	  return -1;
	}
    }

  /* figure out how many input files there are to process */
  if((infile_cnt = argc - optind) < 1)
    {
      usage(argv[0], 0);
      return -1;
    }
  if((infiles = malloc_zero(sizeof(scamper_file_t *) * infile_cnt)) == NULL)
    {
      fprintf(stderr, "%s: could not malloc %d infile array\n",
	      __func__, infile_cnt);
      return -1;
    }

  /* open each input file */
  for(i=0; i<infile_cnt; i++)
    {
      if((infiles[i] = scamper_file_open(argv[optind+i], 'r', NULL)) == NULL)
	{
	  usage(argv[0], 0);
	  fprintf(stderr, "%s: could not open infile %s\n",
		  __func__, argv[optind+i]);
	  return -1;
	}
    }

  /* open the output file, which is a regular file */
  if(opt_outfile != NULL)
    {
      if(string_endswith(opt_outfile, ".gz") != 0)
	{
#ifdef HAVE_ZLIB
	  outfile_type = "warts.gz";
#else
	  usage(argv[0], OPT_OUTFILE);
	  fprintf(stderr, "cannot write to %s: did not link against zlib\n",
		  opt_outfile);
	  return -1;
#endif
	}
      else if(string_endswith(opt_outfile, ".bz2") != 0)
	{
#ifdef HAVE_LIBBZ2
	  outfile_type = "warts.bz2";
#else
	  usage(argv[0], OPT_OUTFILE);
	  fprintf(stderr, "cannot write to %s: did not link against libbz2\n",
		  opt_outfile);
	  return -1;
#endif
	}
      else if(string_endswith(opt_outfile, ".xz") != 0)
	{
#ifdef HAVE_LIBLZMA
	  outfile_type = "warts.xz";
#else
	  usage(argv[0], OPT_OUTFILE);
	  fprintf(stderr, "cannot write to %s: did not link against liblzma\n",
		  opt_outfile);
	  return -1;
#endif
	}

      if(strcmp(outfile_type, "warts") != 0)
	{
	  if(access(opt_outfile, F_OK) == 0)
	    {
	      usage(argv[0], OPT_OUTFILE);
	      fprintf(stderr, "cannot write to %s: cannot append to %s file\n",
		      opt_outfile, outfile_type);
	      return -1;
	    }
	  m = 'w';
	}

      if((outfile = scamper_file_open(opt_outfile, m, outfile_type)) == NULL)
	{
	  usage(argv[0], OPT_OUTFILE);
	  return -1;
	}
    }
  else
    {
#ifdef HAVE_ISATTY
      /* writing to stdout; don't dump a binary structure to a tty. */
      if(isatty(STDOUT_FILENO) != 0)
	{
	  fprintf(stderr, "not going to dump warts to a tty, sorry\n");
	  return -1;
	}
#endif

      if((outfile = scamper_file_openfd(STDOUT_FILENO,"-",'w',"warts")) == NULL)
	{
	  fprintf(stderr, "could not wrap scamper_file around stdout\n");
	  return -1;
	}
    }

  return 0;
}

static void cleanup(void)
{
  int i;

  if(filter != NULL)
    {
      scamper_file_filter_free(filter);
      filter = NULL;
    }

  if(outfile != NULL)
    {
      scamper_file_close(outfile);
      outfile = NULL;
    }

  if(infiles != NULL)
    {
      for(i=0; i<infile_cnt; i++)
	{
	  if(infiles[i] != NULL)
	    {
	      scamper_file_close(infiles[i]);
	      infiles[i] = NULL;
	    }
	}
      free(infiles);
    }

  return;
}

static int write_obj(uint16_t type, void *data)
{
  int rc = 0;

  /* write the object out */
  switch(type)
    {
    case SCAMPER_FILE_OBJ_CYCLE_START:
      if(scamper_file_write_cycle_start(outfile, data) != 0)
	rc = -1;
      scamper_cycle_free(data);
      break;

    case SCAMPER_FILE_OBJ_CYCLE_STOP:
      if(scamper_file_write_cycle_stop(outfile, data) != 0)
	rc = -1;
      scamper_cycle_free(data);
      break;

    case SCAMPER_FILE_OBJ_TRACE:
      if(scamper_file_write_trace(outfile, data, NULL) != 0)
	rc = -1;
      scamper_trace_free(data);
      break;

    case SCAMPER_FILE_OBJ_PING:
      if(scamper_file_write_ping(outfile, data, NULL) != 0)
	rc = -1;
      scamper_ping_free(data);
      break;

    case SCAMPER_FILE_OBJ_TRACELB:
      if(scamper_file_write_tracelb(outfile, data, NULL) != 0)
	rc = -1;
      scamper_tracelb_free(data);
      break;

    case SCAMPER_FILE_OBJ_DEALIAS:
      if(scamper_file_write_dealias(outfile, data, NULL) != 0)
	rc = -1;
      scamper_dealias_free(data);
      break;

    case SCAMPER_FILE_OBJ_NEIGHBOURDISC:
      if(scamper_file_write_neighbourdisc(outfile, data, NULL) != 0)
	rc = -1;
      scamper_neighbourdisc_free(data);
      break;

    case SCAMPER_FILE_OBJ_TBIT:
      if(scamper_file_write_tbit(outfile, data, NULL) != 0)
	rc = -1;
      scamper_tbit_free(data);
      break;

    case SCAMPER_FILE_OBJ_STING:
      if(scamper_file_write_sting(outfile, data, NULL) != 0)
	rc = -1;
      scamper_sting_free(data);
      break;

    case SCAMPER_FILE_OBJ_SNIFF:
      if(scamper_file_write_sniff(outfile, data, NULL) != 0)
	rc = -1;
      scamper_sniff_free(data);
      break;

    case SCAMPER_FILE_OBJ_HOST:
      if(scamper_file_write_host(outfile, data, NULL) != 0)
	rc = -1;
      scamper_host_free(data);
      break;

    case SCAMPER_FILE_OBJ_HTTP:
      if(scamper_file_write_http(outfile, data, NULL) != 0)
	rc = -1;
      scamper_http_free(data);
      break;

    case SCAMPER_FILE_OBJ_UDPPROBE:
      if(scamper_file_write_udpprobe(outfile, data, NULL) != 0)
	rc = -1;
      scamper_udpprobe_free(data);
      break;

    default:
      fprintf(stderr, "unhandled data object 0x%04x\n", type);
      rc = -1;
    }

  return rc;
}

static int simple_cat(void)
{
  const char *objtype;
  uint16_t type;
  void *data;
  int i, rc;

  for(i=0; i<infile_cnt; i++)
    {
      while((rc = scamper_file_read(infiles[i], filter, &type, &data)) == 0)
	{
	  /* EOF */
	  if(data == NULL)
	    break;
	  if(write_obj(type, data) != 0)
	    {
	      if((objtype = scamper_file_objtype_tostr(type)) == NULL)
		objtype = "unknown-type";
	      fprintf(stderr, "%s: could not write %s record from %s\n",
		      __func__, objtype, scamper_file_getfilename(infiles[i]));
	      return -1;
	    }
	}

      /* error when reading the input file */
      if(rc != 0)
	{
	  fprintf(stderr, "%s: error reading %s\n", __func__,
		  scamper_file_getfilename(infiles[i]));
	  return -1;
	}

      scamper_file_close(infiles[i]);
      infiles[i] = NULL;
    }

  return 0;
}

/*
 * sort_struct_cmp
 *
 * prioritise sort_struct objects for output to file.
 */
static int sort_struct_cmp(const sort_struct_t *a, const sort_struct_t *b)
{
  int i;

  if((i = timeval_cmp(&b->tv, &a->tv)) != 0)
    return i;

  /* if timestamps are identical, cycle start objects have first priority */
  if(a->type == SCAMPER_FILE_OBJ_CYCLE_START)
    {
      if(b->type == SCAMPER_FILE_OBJ_CYCLE_START) return 0;
      else return 1;
    }
  if(b->type == SCAMPER_FILE_OBJ_CYCLE_START) return -1;

  /* if timestamps are identical, cycle start objects have second priority */
  if(a->type == SCAMPER_FILE_OBJ_CYCLE_STOP)
    {
      if(b->type == SCAMPER_FILE_OBJ_CYCLE_STOP) return 0;
      else return 1;
    }
  if(b->type == SCAMPER_FILE_OBJ_CYCLE_STOP) return -1;

  return 0;
}

static int sort_cat_fill(heap_t *heap, sort_struct_t *s)
{
  const char *objtype;
  int i = s->file;

  if(scamper_file_read(infiles[i], filter, &s->type, &s->data) == 0)
    {
      /* EOF */
      if(s->data == NULL)
	{
	  scamper_file_close(infiles[i]);
	  infiles[i] = NULL;
	  return 0;
	}

      switch(s->type)
	{
	case SCAMPER_FILE_OBJ_CYCLE_START:
	  s->tv.tv_sec = scamper_cycle_start_time_get(s->data);
	  s->tv.tv_usec = 0;
	  break;

	case SCAMPER_FILE_OBJ_CYCLE_STOP:
	  s->tv.tv_sec = scamper_cycle_stop_time_get(s->data);
	  s->tv.tv_usec = 1000000;
	  break;

	case SCAMPER_FILE_OBJ_TRACE:
	  timeval_cpy(&s->tv, scamper_trace_start_get(s->data));
	  break;

	case SCAMPER_FILE_OBJ_PING:
	  timeval_cpy(&s->tv, scamper_ping_start_get(s->data));
	  break;

	case SCAMPER_FILE_OBJ_TRACELB:
	  timeval_cpy(&s->tv, scamper_tracelb_start_get(s->data));
	  break;

	case SCAMPER_FILE_OBJ_DEALIAS:
	  timeval_cpy(&s->tv, scamper_dealias_start_get(s->data));
	  break;

	case SCAMPER_FILE_OBJ_NEIGHBOURDISC:
	  timeval_cpy(&s->tv, scamper_neighbourdisc_start_get(s->data));
	  break;

	case SCAMPER_FILE_OBJ_TBIT:
	  timeval_cpy(&s->tv, scamper_tbit_start_get(s->data));
	  break;

	case SCAMPER_FILE_OBJ_STING:
	  timeval_cpy(&s->tv, scamper_sting_start_get(s->data));
	  break;

	case SCAMPER_FILE_OBJ_SNIFF:
	  timeval_cpy(&s->tv, scamper_sniff_start_get(s->data));
	  break;

	case SCAMPER_FILE_OBJ_HOST:
	  timeval_cpy(&s->tv, scamper_host_start_get(s->data));
	  break;

	case SCAMPER_FILE_OBJ_HTTP:
	  timeval_cpy(&s->tv, scamper_http_start_get(s->data));
	  break;

	case SCAMPER_FILE_OBJ_UDPPROBE:
	  timeval_cpy(&s->tv, scamper_udpprobe_start_get(s->data));
	  break;
	}

      if(heap_insert(heap, s) == NULL)
	{
	  if((objtype = scamper_file_objtype_tostr(s->type)) == NULL)
	    objtype = "unknown-type";
	  fprintf(stderr, "%s: could not add %s from %s to heap\n", __func__,
		  objtype, scamper_file_getfilename(infiles[i]));
	  return -1;
	}
    }
  else
    {
      fprintf(stderr, "%s: could not read from %s\n", __func__,
	      scamper_file_getfilename(infiles[i]));
      return -1;
    }

  return 0;
}

static int sort_cat(void)
{
  const char    *objtype;
  heap_t        *heap = NULL;
  sort_struct_t *ss = NULL;
  sort_struct_t *s;
  int i;

  if((heap = heap_alloc((heap_cmp_t)sort_struct_cmp)) == NULL)
    {
      fprintf(stderr, "%s: could not alloc heap\n", __func__);
      goto err;
    }

  if((ss = malloc_zero(sizeof(sort_struct_t) * infile_cnt)) == NULL)
    {
      fprintf(stderr, "%s: could not alloc sorting %d structures\n",
	      __func__, infile_cnt);
      goto err;
    }

  /*
   * start by filling all file slots with the first data object from
   * each file
   */
  for(i=0; i<infile_cnt; i++)
    {
      ss[i].file = i;
      if(sort_cat_fill(heap, &ss[i]) != 0)
	goto err;
    }

  /*
   * now, read each object off the heap in their appropriate priority and
   * replace each heap object with another from the file until there is
   * nothing left.
   */
  while((s = (sort_struct_t *)heap_remove(heap)) != NULL)
    {
      if(write_obj(s->type, s->data) != 0)
	{
	  if((objtype = scamper_file_objtype_tostr(s->type)) == NULL)
	    objtype = "unknown-type";
	  fprintf(stderr, "%s: could not write %s record from %s\n", __func__,
		  objtype, scamper_file_getfilename(infiles[s->file]));
	  goto err;
	}
      if(sort_cat_fill(heap, s) != 0)
	goto err;
    }

  heap_free(heap, NULL);
  free(ss);

  return 0;

 err:
  if(heap != NULL) heap_free(heap, NULL);
  if(ss != NULL) free(ss);
  return -1;
}

int main(int argc, char *argv[])
{
  uint16_t filter_types[] = {
    SCAMPER_FILE_OBJ_CYCLE_START,
    SCAMPER_FILE_OBJ_CYCLE_STOP,
    SCAMPER_FILE_OBJ_TRACE,
    SCAMPER_FILE_OBJ_PING,
    SCAMPER_FILE_OBJ_TRACELB,
    SCAMPER_FILE_OBJ_DEALIAS,
    SCAMPER_FILE_OBJ_NEIGHBOURDISC,
    SCAMPER_FILE_OBJ_TBIT,
    SCAMPER_FILE_OBJ_STING,
    SCAMPER_FILE_OBJ_SNIFF,
    SCAMPER_FILE_OBJ_HOST,
    SCAMPER_FILE_OBJ_HTTP,
    SCAMPER_FILE_OBJ_UDPPROBE,
  };
  uint16_t filter_cnt = sizeof(filter_types)/sizeof(uint16_t);
  int rc;

#if defined(DMALLOC)
  free(malloc(1));
#endif

  atexit(cleanup);

  if(check_options(argc, argv) == -1)
    return -1;

  if((filter = scamper_file_filter_alloc(filter_types, filter_cnt)) == NULL)
    {
      fprintf(stderr, "could not allocate filter\n");
      return -1;
    }

  if(options & OPT_SORT)
    rc = sort_cat();
  else
    rc = simple_cat();

  return rc;
}
