/*
 * scamper_file.c
 *
 * $Id: scamper_file.c,v 1.89 2023/03/01 01:49:16 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
 * Copyright (C) 2022-2023 Matthew Luckie
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
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_file_text.h"
#include "scamper_file_arts.h"
#include "scamper_file_json.h"

#include "trace/scamper_trace.h"
#include "trace/scamper_trace_text.h"
#include "trace/scamper_trace_warts.h"
#include "trace/scamper_trace_json.h"
#include "ping/scamper_ping.h"
#include "ping/scamper_ping_text.h"
#include "ping/scamper_ping_warts.h"
#include "ping/scamper_ping_json.h"
#include "sting/scamper_sting.h"
#include "sting/scamper_sting_text.h"
#include "sting/scamper_sting_warts.h"
#include "tracelb/scamper_tracelb.h"
#include "tracelb/scamper_tracelb_text.h"
#include "tracelb/scamper_tracelb_warts.h"
#include "tracelb/scamper_tracelb_json.h"
#include "dealias/scamper_dealias.h"
#include "dealias/scamper_dealias_text.h"
#include "dealias/scamper_dealias_warts.h"
#include "dealias/scamper_dealias_json.h"
#include "neighbourdisc/scamper_neighbourdisc.h"
#include "neighbourdisc/scamper_neighbourdisc_warts.h"
#include "tbit/scamper_tbit.h"
#include "tbit/scamper_tbit_text.h"
#include "tbit/scamper_tbit_warts.h"
#include "tbit/scamper_tbit_json.h"
#include "sniff/scamper_sniff.h"
#include "sniff/scamper_sniff_warts.h"
#include "host/scamper_host.h"
#include "host/scamper_host_warts.h"

#include "utils.h"

#define SCAMPER_FILE_NONE       (-1)
#define SCAMPER_FILE_TEXT        0
#define SCAMPER_FILE_ARTS        1
#define SCAMPER_FILE_WARTS       2
#define SCAMPER_FILE_JSON        3

typedef int (*write_obj_func_t)(scamper_file_t *sf, const void *, void *);

#ifdef HAVE_ZLIB
typedef struct scamper_file_zstrm
{
  z_stream                  zs;
  uint8_t                   in[64 * 1024];
  uint8_t                   out[64 * 1024];
  uint8_t                   eof; /* read returned zero */
  uint8_t                   end; /* inflate returned Z_STREAM_END */
} scamper_file_zstrm_t;
#endif

struct scamper_file
{
  char                     *filename;
  int                       fd;
  void                     *state;
  int                       type;
  int                       eof;
  scamper_file_writefunc_t  writefunc;
  void                     *writeparam;
  scamper_file_readfunc_t   readfunc;
  void                     *readparam;

#ifdef HAVE_ZLIB
  scamper_file_zstrm_t     *zstrm;
#endif
};

struct scamper_file_filter
{
  uint32_t *flags;
  uint16_t  max;
};

typedef struct scamper_file_readbuf_n
{
  uint8_t                       *data;
  size_t                         len;
  struct scamper_file_readbuf_n *next;
} scamper_file_readbuf_n_t;

struct scamper_file_readbuf
{
  scamper_file_readbuf_n_t *head;
  scamper_file_readbuf_n_t *tail;
  size_t                    len;
};

struct handler
{
  char *type;

  int (*init_read)(scamper_file_t *sf);
  int (*init_write)(scamper_file_t *sf);
  int (*init_append)(scamper_file_t *sf);

  int (*read)(scamper_file_t *sf, const scamper_file_filter_t *filter,
	      uint16_t *type, void **data);

  int (*write_cycle_start)(const scamper_file_t *sf,
			   scamper_cycle_t *cycle);

  int (*write_cycle_stop)(const scamper_file_t *sf,
			  scamper_cycle_t *cycle);

  int (*write_trace)(const scamper_file_t *sf,
		     const struct scamper_trace *trace, void *p);

  int (*write_ping)(const scamper_file_t *sf,
		    const struct scamper_ping *ping, void *p);

  int (*write_tracelb)(const scamper_file_t *sf,
		       const struct scamper_tracelb *trace, void *p);

  int (*write_sting)(const scamper_file_t *sf,
		     const struct scamper_sting *sting, void *p);

  int (*write_dealias)(const scamper_file_t *sf,
		       const struct scamper_dealias *dealias, void *p);

  int (*write_neighbourdisc)(const scamper_file_t *sf,
			     const struct scamper_neighbourdisc *nd, void *p);

  int (*write_tbit)(const scamper_file_t *sf,
		    const struct scamper_tbit *tbit, void *p);

  int (*write_sniff)(const scamper_file_t *sf,
		     const struct scamper_sniff *sniff, void *p);

  int (*write_host)(const scamper_file_t *sf,
		    const struct scamper_host *host, void *p);

  void (*free_state)(scamper_file_t *sf);
};

static struct handler handlers[] = {
  {"text",                                 /* type */
   NULL,                                   /* init_read */
   NULL,                                   /* init_write */
   NULL,                                   /* init_append */
   NULL,                                   /* read */
   NULL,                                   /* write_cycle_start */
   NULL,                                   /* write_cycle_stop */
   scamper_file_text_trace_write,          /* write_trace */
   scamper_file_text_ping_write,           /* write_ping */
   scamper_file_text_tracelb_write,        /* write_tracelb */
   scamper_file_text_sting_write,          /* write_sting */
   scamper_file_text_dealias_write,        /* write_dealias */
   NULL,                                   /* write_neighbourdisc */
   scamper_file_text_tbit_write,           /* write_tbit */
   NULL,                                   /* write_sniff */
   NULL,                                   /* write_host */
   NULL,                                   /* free_state */
  },
  {"arts",                                 /* type */
   scamper_file_arts_init_read,            /* init_read */
   NULL,                                   /* init_write */
   NULL,                                   /* init_append */
   scamper_file_arts_read,                 /* read */
   NULL,                                   /* write_cycle_start */
   NULL,                                   /* write_cycle_stop */
   NULL,                                   /* write_trace */
   NULL,                                   /* write_ping */
   NULL,                                   /* write_tracelb */
   NULL,                                   /* write_sting */
   NULL,                                   /* write_dealias */
   NULL,                                   /* write_neighbourdisc */
   NULL,                                   /* write_tbit */
   NULL,                                   /* write_sniff */
   NULL,                                   /* write_host */
   scamper_file_arts_free_state,           /* free_state */
  },
  {"warts",                                /* type */
   scamper_file_warts_init_read,           /* init_read */
   scamper_file_warts_init_write,          /* init_write */
   scamper_file_warts_init_append,         /* init_append */
   scamper_file_warts_read,                /* read */
   scamper_file_warts_cyclestart_write,    /* write_cycle_start */
   scamper_file_warts_cyclestop_write,     /* write_cycle_stop */
   scamper_file_warts_trace_write,         /* write_trace */
   scamper_file_warts_ping_write,          /* write_ping */
   scamper_file_warts_tracelb_write,       /* write_tracelb */
   scamper_file_warts_sting_write,         /* write_sting */
   scamper_file_warts_dealias_write,       /* write_dealias */
   scamper_file_warts_neighbourdisc_write, /* write_neighbourdisc */
   scamper_file_warts_tbit_write,          /* write_tbit */
   scamper_file_warts_sniff_write,         /* write_sniff */
   scamper_file_warts_host_write,          /* write_host */
   scamper_file_warts_free_state,          /* free_state */
  },
  {"json",                                 /* type */
   NULL,                                   /* init_read */
   scamper_file_json_init_write,           /* init_write */
   NULL,                                   /* init_append */
   NULL,                                   /* read */
   scamper_file_json_cyclestart_write,     /* write_cycle_start */
   scamper_file_json_cyclestop_write,      /* write_cycle_stop */
   scamper_file_json_trace_write,          /* write_trace */
   scamper_file_json_ping_write,           /* write_ping */
   scamper_file_json_tracelb_write,        /* write_tracelb */
   NULL,                                   /* write_sting */
   scamper_file_json_dealias_write,        /* write_dealias */
   NULL,                                   /* write_neighbourdisc */
   scamper_file_json_tbit_write,           /* write_tbit */
   NULL,                                   /* write_sniff */
   NULL,                                   /* write_host */
   scamper_file_json_free_state,           /* free_state */
  },
};

static int handler_cnt = sizeof(handlers) / sizeof(struct handler);

int scamper_file_getfd(const scamper_file_t *sf)
{
  return sf->fd;
}

void *scamper_file_getstate(const scamper_file_t *sf)
{
  return sf->state;
}

char *scamper_file_getfilename(scamper_file_t *sf)
{
  return sf->filename;
}

void scamper_file_setstate(scamper_file_t *sf, void *state)
{
  sf->state = state;
  return;
}

void scamper_file_setreadfunc(scamper_file_t *sf,
			      void *param, scamper_file_readfunc_t rf)
{
  sf->readfunc  = rf;
  sf->readparam = param;
  return;
}

scamper_file_readfunc_t scamper_file_getreadfunc(const scamper_file_t *sf)
{
  return sf->readfunc;
}

void *scamper_file_getreadparam(const scamper_file_t *sf)
{
  return sf->readparam;
}

void scamper_file_setwritefunc(scamper_file_t *sf,
			       void *param, scamper_file_writefunc_t wf)
{
  sf->writefunc  = wf;
  sf->writeparam = param;
  return;
}

scamper_file_writefunc_t scamper_file_getwritefunc(const scamper_file_t *sf)
{
  return sf->writefunc;
}

void *scamper_file_getwriteparam(const scamper_file_t *sf)
{
  return sf->writeparam;
}

int scamper_file_write_trace(scamper_file_t *sf,
			     const struct scamper_trace *trace, void *p)
{
  assert(sf->type >= -1); assert(sf->type <= handler_cnt);
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_trace != NULL)
    return handlers[sf->type].write_trace(sf, trace, p);
  return -1;
}

int scamper_file_write_ping(scamper_file_t *sf,
			    const struct scamper_ping *ping, void *p)
{
  assert(sf->type >= -1); assert(sf->type <= handler_cnt);
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_ping != NULL)
    return handlers[sf->type].write_ping(sf, ping, p);
  return -1;
}

int scamper_file_write_tracelb(scamper_file_t *sf,
			       const struct scamper_tracelb *trace, void *p)
{
  assert(sf->type >= -1); assert(sf->type <= handler_cnt);
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_tracelb != NULL)
    return handlers[sf->type].write_tracelb(sf, trace, p);
  return -1;
}

int scamper_file_write_sting(scamper_file_t *sf,
			     const struct scamper_sting *sting, void *p)
{
  assert(sf->type >= -1); assert(sf->type <= handler_cnt);
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_sting != NULL)
    return handlers[sf->type].write_sting(sf, sting,  p);
  return -1;
}

int scamper_file_write_dealias(scamper_file_t *sf,
			       const struct scamper_dealias *dealias, void *p)
{
  assert(sf->type >= -1); assert(sf->type <= handler_cnt);
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_dealias != NULL)
    return handlers[sf->type].write_dealias(sf, dealias, p);
  return -1;
}

int scamper_file_write_neighbourdisc(scamper_file_t *sf,
				     const struct scamper_neighbourdisc *nd,
				     void *p)
{
  assert(sf->type >= -1); assert(sf->type <= handler_cnt);
  if(sf->type != SCAMPER_FILE_NONE &&
     handlers[sf->type].write_neighbourdisc != NULL)
    return handlers[sf->type].write_neighbourdisc(sf, nd, p);
  return -1;
}

int scamper_file_write_tbit(scamper_file_t *sf,
			    const struct scamper_tbit *tbit, void *p)
{
  assert(sf->type >= -1); assert(sf->type <= handler_cnt);
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_tbit != NULL)
    return handlers[sf->type].write_tbit(sf, tbit, p);
  return -1;
}

int scamper_file_write_sniff(scamper_file_t *sf,
			     const struct scamper_sniff *sniff, void *p)
{
  assert(sf->type >= -1); assert(sf->type <= handler_cnt);
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_sniff != NULL)
    return handlers[sf->type].write_sniff(sf, sniff, p);
  return -1;
}

int scamper_file_write_host(scamper_file_t *sf,
			    const struct scamper_host *host, void *p)
{
  assert(sf->type >= -1); assert(sf->type <= handler_cnt);
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].write_host != NULL)
    return handlers[sf->type].write_host(sf, host, p);
  return -1;
}

int scamper_file_write_obj(scamper_file_t *sf, uint16_t type, const void *data)
{
  static int (*const func[])(scamper_file_t *sf, const void *, void *) = {
    NULL,
    NULL, /* SCAMPER_FILE_OBJ_LIST */
    NULL, /* SCAMPER_FILE_OBJ_CYCLE_START */
    NULL, /* SCAMPER_FILE_OBJ_CYCLE_DEF */
    NULL, /* SCAMPER_FILE_OBJ_CYCLE_STOP */
    NULL, /* SCAMPER_FILE_OBJ_ADDR */
    (write_obj_func_t)scamper_file_write_trace,
    (write_obj_func_t)scamper_file_write_ping,
    (write_obj_func_t)scamper_file_write_tracelb,
    (write_obj_func_t)scamper_file_write_dealias,
    (write_obj_func_t)scamper_file_write_neighbourdisc,
    (write_obj_func_t)scamper_file_write_tbit,
    (write_obj_func_t)scamper_file_write_sting,
    (write_obj_func_t)scamper_file_write_sniff,
    (write_obj_func_t)scamper_file_write_host,
  };
  if(type > 13)
    return -1;
  if(func[type] != NULL)
    return func[type](sf, data, NULL);
  if(type == SCAMPER_FILE_OBJ_CYCLE_START)
    return scamper_file_write_cycle_start(sf, (scamper_cycle_t *)data);
  if(type == SCAMPER_FILE_OBJ_CYCLE_STOP)
    return scamper_file_write_cycle_stop(sf, (scamper_cycle_t *)data);
  return -1;
}

/*
 * scamper_file_read
 *
 *
 */
int scamper_file_read(scamper_file_t *sf,
		      const scamper_file_filter_t *filter,
		      uint16_t *type, void **object)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].read != NULL)
    {
      return handlers[sf->type].read(sf, filter, type, object);
    }

  return -1;
}

/*
 * scamper_file_filter_isset
 *
 * check to see if the particular type is set in the filter or not
 */
int scamper_file_filter_isset(const scamper_file_filter_t *filter,
			      uint16_t type)
{
  if(filter == NULL || type > filter->max)
    return 0;
  if((filter->flags[type/32] & (0x1 << ((type%32)-1))) == 0)
    return 0;
  return 1;
}

/*
 * scamper_file_filter_alloc
 *
 * allocate a filter for reading data objects from scamper files based on an
 * array of types the caller is interested in.
 */
scamper_file_filter_t *scamper_file_filter_alloc(const uint16_t *types,
						 uint16_t num)
{
  scamper_file_filter_t *filter = NULL;
  size_t size;
  int i, j, k;

  /* sanity checks */
  if(types == NULL || num == 0)
    {
      goto err;
    }

  /* allocate filter structure which will be returned to caller */
  if((filter = malloc_zero(sizeof(scamper_file_filter_t))) == NULL)
    {
      goto err;
    }

  /* first, figure out the maximum type value of interest */
  for(i=0; i<num; i++)
    {
      /* sanity check */
      if(types[i] == 0)
	{
	  goto err;
	}
      if(types[i] > filter->max)
	{
	  filter->max = types[i];
	}
    }

  /* sanity check */
  if(filter->max == 0)
    {
      goto err;
    }

  /* allocate the flags array */
  size = sizeof(uint32_t) * filter->max / 32;
  if((filter->max % 32) != 0) size += sizeof(uint32_t);
  if((filter->flags = malloc_zero(size)) == NULL)
    {
      goto err;
    }

  /* go through each type and set the appropriate flag */
  for(i=0; i<num; i++)
    {
      if(types[i] % 32 == 0)
	{
	  j = ((types[i]) / 32) - 1;
	  k = 32;
	}
      else
	{
	  j = types[i] / 32;
	  k = types[i] % 32;
	}

      filter->flags[j] |= (0x1 << (k-1));
    }

  return filter;

 err:
  if(filter != NULL)
    {
      if(filter->flags != NULL) free(filter->flags);
      free(filter);
    }
  return NULL;
}

void scamper_file_filter_free(scamper_file_filter_t *filter)
{
  if(filter != NULL)
    {
      if(filter->flags != NULL) free(filter->flags);
      free(filter);
    }

  return;
}

int scamper_file_write_cycle_start(scamper_file_t *sf, scamper_cycle_t *cycle)
{
  if(sf->type != SCAMPER_FILE_NONE &&
     handlers[sf->type].write_cycle_start != NULL)
    {
      return handlers[sf->type].write_cycle_start(sf, cycle);
    }
  return -1;
}

int scamper_file_write_cycle_stop(scamper_file_t *sf, scamper_cycle_t *cycle)
{
  if(sf->type != SCAMPER_FILE_NONE &&
     handlers[sf->type].write_cycle_stop != NULL)
    {
      return handlers[sf->type].write_cycle_stop(sf, cycle);
    }
  return -1;
}

/*
 * scamper_file_geteof
 *
 */
int scamper_file_geteof(const scamper_file_t *sf)
{
  if(sf == NULL || sf->fd == -1) return -1;
  return sf->eof;
}

/*
 * scamper_file_seteof
 *
 */
void scamper_file_seteof(scamper_file_t *sf)
{
  if(sf != NULL && sf->fd != -1)
    sf->eof = 1;
  return;
}

/*
 * scamper_file_free
 *
 */
void scamper_file_free(scamper_file_t *sf)
{
  if(sf != NULL)
    {
      if(sf->filename != NULL)
	free(sf->filename);

#ifdef HAVE_ZLIB
      if(sf->zstrm != NULL)
	{
	  inflateEnd(&sf->zstrm->zs);
	  free(sf->zstrm);
	}
#endif

      free(sf);
    }
  return;
}

/*
 * scamper_file_close
 *
 */
void scamper_file_close(scamper_file_t *sf)
{
  /* free state associated with the type of scamper_file_t */
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].free_state != NULL)
    {
      handlers[sf->type].free_state(sf);
    }

  /* close the file descriptor */
  if(sf->fd != -1)
    {
      close(sf->fd);
    }

  /* free general state associated */
  scamper_file_free(sf);

  return;
}

char *scamper_file_type_tostr(scamper_file_t *sf, char *buf, size_t len)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].type != NULL)
    {
      strncpy(buf, handlers[sf->type].type, len);
      return buf;
    }

  return NULL;
}

const char *scamper_file_objtype_tostr(uint16_t type)
{
  static const char *types[] = {
    NULL,
    "list",
    "cycle-start",
    "cycle-def",
    "cycle-stop",
    "addr",
    "trace",
    "ping",
    "tracelb",
    "dealias",
    "neighbourdisc",
    "tbit",
    "sting",
    "sniff",
    "host",
  };
  uint16_t typec = sizeof(types)/sizeof(char *);
  if(typec > type)
    return types[type];
  return NULL;
}

/*
 * zlib_read
 *
 * next_in:   where deflated bytes need to be written
 * avail_in:  how many defated bytes are in the in buffer
 * next_out:  where inflated bytes can be obtained
 * avail_out: 
 */
#ifdef HAVE_ZLIB
static int zlib_read(scamper_file_t *sf, uint8_t **data, size_t len)
{
  uint8_t *tmp = NULL;
  ssize_t readc;
  size_t off = 0;
  size_t b, have;
  int rc;

  *data = NULL;

  if((tmp = malloc(len)) == NULL)
    goto err;

  have = sizeof(sf->zstrm->out) - sf->zstrm->zs.avail_out;
  while(sf->zstrm->end == 0 || have > 0)
    {
      if(have > 0)
	{
	  if(have >= len - off)
	    b = len - off;
	  else
	    b = have;

	  memcpy(tmp+off, sf->zstrm->out, b);
	  memmove(sf->zstrm->out, sf->zstrm->out+b, sizeof(sf->zstrm->out)-b);
	  sf->zstrm->zs.avail_out += b;
	  sf->zstrm->zs.next_out -= b;
	  off += b;
	  have -= b;

	  if(off == len)
	    {
	      *data = tmp;
	      return 0;
	    }
	}

      if(sf->zstrm->zs.avail_in < sizeof(sf->zstrm->in))
	{
	  b = sizeof(sf->zstrm->in) - sf->zstrm->zs.avail_in;
	  memmove(sf->zstrm->in,sf->zstrm->zs.next_in,sf->zstrm->zs.avail_in);
	  readc = read(sf->fd, sf->zstrm->in + sf->zstrm->zs.avail_in, b);
	  if(readc < 0)
	    goto err;
	  else if(readc == 0)
	    sf->zstrm->eof = 1;
	  else
	    sf->zstrm->zs.avail_in += readc;

	  sf->zstrm->zs.next_in = sf->zstrm->in;
	  rc = inflate(&sf->zstrm->zs, Z_NO_FLUSH);
	  if(rc == Z_STREAM_END)
	    sf->zstrm->end = 1;
	  else if(rc != Z_OK)
	    goto err;

	  have = sizeof(sf->zstrm->out) - sf->zstrm->zs.avail_out;
	}
    }

  free(tmp);
  return -2;

 err:
  if(tmp != NULL) free(tmp);
  return -1;
}
#endif

static int file_type_get(const char *type)
{
  int i;
  if(type == NULL)
    return SCAMPER_FILE_NONE;
  for(i=0; i<handler_cnt; i++)
    if(strcasecmp(type, handlers[i].type) == 0)
      return i;
  return SCAMPER_FILE_NONE;
}

static int file_type_detect(scamper_file_t *sf)
{
  uint8_t buf[2], *ptr = buf;

#ifdef HAVE_ZLIB
  ssize_t readc;
  int rc;
#endif

  if(lseek(sf->fd, 0, SEEK_SET) == -1 ||
     read_wrap(sf->fd, buf, NULL, sizeof(buf)) != 0 ||
     lseek(sf->fd, 0, SEEK_SET) == -1)
    return SCAMPER_FILE_NONE;

#ifdef HAVE_ZLIB
  if(buf[0] == 0x1F && buf[1] == 0x8B)
    {
      if((sf->zstrm = malloc_zero(sizeof(scamper_file_zstrm_t))) == NULL)
	return SCAMPER_FILE_NONE;
      if(inflateInit2(&sf->zstrm->zs, MAX_WBITS + 32) != Z_OK)
	return SCAMPER_FILE_NONE;
      sf->readfunc = (scamper_file_readfunc_t)zlib_read;
      sf->readparam = sf;
      sf->zstrm->zs.next_out = sf->zstrm->out;
      sf->zstrm->zs.avail_out = sizeof(sf->zstrm->out);

      readc = read(sf->fd, sf->zstrm->in, sizeof(sf->zstrm->in));
      if(readc <= 0)
	return SCAMPER_FILE_NONE;
      sf->zstrm->zs.next_in = sf->zstrm->in;
      sf->zstrm->zs.avail_in = readc;

      rc = inflate(&sf->zstrm->zs, Z_NO_FLUSH);
      if(rc == Z_STREAM_END)
	sf->zstrm->end = 1;
      else if(rc != Z_OK)
	return SCAMPER_FILE_NONE;
      ptr = sf->zstrm->out;
    }
#endif

  if(ptr[0] == 0x12 && ptr[1] == 0x05)
    return SCAMPER_FILE_WARTS;
  if(ptr[0] == 0xDF && ptr[1] == 0xB0)
    return SCAMPER_FILE_ARTS;

  return SCAMPER_FILE_NONE;
}

static int file_open_read(scamper_file_t *sf)
{
  struct stat sb;

  if(sf->fd != -1)
    {
      if(fstat(sf->fd, &sb) != 0)
	return -1;

      if(sb.st_size != 0 && (sb.st_mode & S_IFIFO) == 0)
	sf->type = file_type_detect(sf);
    }

  if(sf->type == SCAMPER_FILE_NONE)
    return -1;

  if(handlers[sf->type].init_read == NULL)
    return -1;

  return handlers[sf->type].init_read(sf);
}

static int file_open_write(scamper_file_t *sf)
{
  if(sf->type != SCAMPER_FILE_NONE && handlers[sf->type].init_write != NULL)
    return handlers[sf->type].init_write(sf);
  return 0;
}

static int file_open_append(scamper_file_t *sf)
{
  struct stat sb;

  if(fstat(sf->fd, &sb) != 0)
    return -1;

  if(sb.st_size == 0)
    {
      if(sf->type == SCAMPER_FILE_WARTS)
	return handlers[sf->type].init_write(sf);
      else if(sf->type == SCAMPER_FILE_TEXT || sf->type == SCAMPER_FILE_JSON)
	return 0;
      return -1;
    }

  /* can't append to pipes */
  if((sb.st_mode & S_IFIFO) != 0)
    return -1;

  sf->type = file_type_detect(sf);
  if(handlers[sf->type].init_append != NULL)
    return handlers[sf->type].init_append(sf);
  else if(sf->type != SCAMPER_FILE_TEXT && sf->type != SCAMPER_FILE_JSON)
    return -1;

  return 0;
}

static scamper_file_t *file_open(int fd, const char *fn, char mode, int type)
{
  scamper_file_t *sf;
  int (*open_func)(scamper_file_t *);

  if(mode == 'r')      open_func = file_open_read;
  else if(mode == 'w') open_func = file_open_write;
  else if(mode == 'a') open_func = file_open_append;
  else return NULL;

  if((sf = (scamper_file_t *)malloc_zero(sizeof(scamper_file_t))) == NULL)
    {
      return NULL;
    }

  if(fn != NULL && (sf->filename = strdup(fn)) == NULL)
    {
      free(sf);
      return NULL;
    }

  sf->type = type;
  sf->fd   = fd;
  if(open_func(sf) == -1)
    {
      scamper_file_close(sf);
      return NULL;
    }

  return sf;
}

scamper_file_t *scamper_file_opennull(char mode, const char *format)
{
  uint8_t file_type;

  if(strcasecmp(format, "warts") == 0)
    file_type = SCAMPER_FILE_WARTS;
  else if(strcasecmp(format, "json") == 0)
    file_type = SCAMPER_FILE_JSON;
  else
    return NULL;

  return file_open(-1, NULL, mode, file_type);
}

scamper_file_t *scamper_file_openfd(int fd, const char *fn, char mode,
				    const char *type)
{
  return file_open(fd, fn, mode, file_type_get(type));
}

/*
 * scamper_file_open
 *
 * open the file specified with the appropriate mode.
 * the modes that we know about are 'r' read-only, 'w' write-only on a
 * brand new file, and 'a' for appending.
 *
 * in 'w' and 'a' mode, the caller must also specify the type of file
 * to write or append to; the three valid classes are "warts", "text",
 * and "json".
 *
 */
scamper_file_t *scamper_file_open(const char *filename, char mode,
				  const char *type)
{
  scamper_file_t *sf;
  mode_t mo;
  int ft = file_type_get(type);
  int flags = 0;
  int fd = -1;

#ifndef _WIN32
  mo = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
#else
  mo = _S_IREAD | _S_IWRITE;
#endif

  if(mode == 'r')
    {
      if(string_isdash(filename) != 0)
	fd = STDIN_FILENO;
      else
	flags = O_RDONLY;
    }
  else if(mode == 'w' || mode == 'a')
    {
      /* sanity check the type of file to be written */
      if(ft == SCAMPER_FILE_NONE || ft == SCAMPER_FILE_ARTS)
	{
	  return NULL;
	}

      if(string_isdash(filename) != 0)
	{
	  fd = STDIN_FILENO;
	}
      else
	{
	  if(mode == 'w') flags = O_WRONLY | O_TRUNC | O_CREAT;
	  else            flags = O_RDWR | O_APPEND | O_CREAT;
	}
    }
  else
    {
      return NULL;
    }

#ifdef _WIN32
  flags |= O_BINARY;
#endif

  if(fd == -1)
    {
      if(mode == 'r') fd = open(filename, flags);
      else            fd = open(filename, flags, mo);

      if(fd == -1)
	{
	  return NULL;
	}
    }

  sf = file_open(fd, filename, mode, ft);

  return sf;
}

void scamper_file_readbuf_n_free(scamper_file_readbuf_n_t *node)
{
  if(node->data != NULL) free(node->data);
  free(node);
  return;
}

scamper_file_readbuf_t *scamper_file_readbuf_alloc(void)
{
  return malloc_zero(sizeof(scamper_file_readbuf_t));
}

void scamper_file_readbuf_free(scamper_file_readbuf_t *rb)
{
  scamper_file_readbuf_n_t *node;
  while(rb->head != NULL)
    {
      node = rb->head;
      rb->head = rb->head->next;
      scamper_file_readbuf_n_free(node);
    }
  free(rb);
  return;
}

int scamper_file_readbuf_add(scamper_file_readbuf_t *rb,
			     const void *data, size_t len)
{
  scamper_file_readbuf_n_t *node = NULL;

  if((node = malloc_zero(sizeof(scamper_file_readbuf_n_t))) == NULL ||
     (node->data = memdup(data, len)) == NULL)
    goto err;
  node->len = len;

  if(rb->head == NULL)
    {
      rb->head = rb->tail = node;
    }
  else
    {
      rb->tail->next = node;
      rb->tail = node;
    }

  rb->len += len;

  return 0;

 err:
  if(node != NULL) scamper_file_readbuf_n_free(node);
  return -1;
}

int scamper_file_readbuf_read(void *param, uint8_t **out, size_t len)
{
  scamper_file_readbuf_t *rb = param;
  scamper_file_readbuf_n_t *node;
  uint8_t *buf = NULL;
  size_t off = 0, x;

  *out = NULL;

  if(rb->len < len)
    return 0;

  if((buf = malloc(len)) == NULL)
    return -1;

  while(off < len)
    {
      assert(rb->head != NULL);
      node = rb->head;

      if(len - off >= node->len)
	{
	  rb->len -= node->len;
	  memcpy(buf+off, node->data, node->len);
	  off += node->len;
	  rb->head = node->next;
	  free(node->data);
	  free(node);
	}
      else
	{
	  x = len - off;
	  rb->len -= x;
	  memcpy(buf+off, node->data, x);
	  node->len -= x;
	  off += x;
	  memmove(node->data, node->data+x, node->len);
	}
    }

  if(rb->head == NULL)
    rb->tail = NULL;

  *out = buf;
  return 0;
}
