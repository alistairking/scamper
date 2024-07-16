/*
 * scamper_file.c
 *
 * $Id: scamper_file.c,v 1.127 2024/03/21 22:44:03 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
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
#include "scamper_file.h"
#include "scamper_file_warts.h"
#include "scamper_file_text.h"
#include "scamper_file_arts.h"
#include "scamper_file_json.h"
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACE)
#include "trace/scamper_trace.h"
#include "trace/scamper_trace_text.h"
#include "trace/scamper_trace_warts.h"
#include "trace/scamper_trace_json.h"
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_PING)
#include "ping/scamper_ping.h"
#include "ping/scamper_ping_text.h"
#include "ping/scamper_ping_warts.h"
#include "ping/scamper_ping_json.h"
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACELB)
#include "tracelb/scamper_tracelb.h"
#include "tracelb/scamper_tracelb_text.h"
#include "tracelb/scamper_tracelb_warts.h"
#include "tracelb/scamper_tracelb_json.h"
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_DEALIAS)
#include "dealias/scamper_dealias.h"
#include "dealias/scamper_dealias_text.h"
#include "dealias/scamper_dealias_warts.h"
#include "dealias/scamper_dealias_json.h"
#endif
#include "neighbourdisc/scamper_neighbourdisc.h"
#include "neighbourdisc/scamper_neighbourdisc_warts.h"
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TBIT)
#include "tbit/scamper_tbit.h"
#include "tbit/scamper_tbit_text.h"
#include "tbit/scamper_tbit_warts.h"
#include "tbit/scamper_tbit_json.h"
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_STING)
#include "sting/scamper_sting.h"
#include "sting/scamper_sting_text.h"
#include "sting/scamper_sting_warts.h"
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_SNIFF)
#include "sniff/scamper_sniff.h"
#include "sniff/scamper_sniff_warts.h"
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HOST)
#include "host/scamper_host.h"
#include "host/scamper_host_warts.h"
#include "host/scamper_host_json.h"
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HTTP)
#include "http/scamper_http.h"
#include "http/scamper_http_warts.h"
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_UDPPROBE)
#include "udpprobe/scamper_udpprobe.h"
#include "udpprobe/scamper_udpprobe_warts.h"
#include "udpprobe/scamper_udpprobe_json.h"
#endif

#include "utils.h"

#define SCAMPER_FILE_TYPE_NONE        0
#define SCAMPER_FILE_TYPE_TEXT        1
#define SCAMPER_FILE_TYPE_ARTS        2
#define SCAMPER_FILE_TYPE_WARTS       3
#define SCAMPER_FILE_TYPE_JSON        4
#define SCAMPER_FILE_TYPE_WARTS_GZ    5
#define SCAMPER_FILE_TYPE_WARTS_BZ2   6
#define SCAMPER_FILE_TYPE_WARTS_XZ    7

typedef int (*write_obj_func_t)(scamper_file_t *sf, const void *, void *);

static int init_noop(scamper_file_t *sf);
static int init_fail(scamper_file_t *sf);
static int init_write_warts_gz(scamper_file_t *sf);
static int init_write_warts_bz2(scamper_file_t *sf);
static int init_write_warts_xz(scamper_file_t *sf);

#if defined(HAVE_ZLIB) || defined(HAVE_LIBBZ2) || defined(HAVE_LIBLZMA)
#define HAVE_SCAMPER_FILE_Z
typedef struct scamper_file_z
{
  union
  {
#ifdef HAVE_ZLIB
    z_stream               *gzs;
#endif
#ifdef HAVE_LIBBZ2
    bz_stream              *bzs;
#endif
#ifdef HAVE_LIBLZMA
    lzma_stream            *xzs;
#endif
  } s;
  uint8_t                   in[64 * 1024];
  uint8_t                   out[64 * 1024];
  uint8_t                   eof; /* read returned zero */
  uint8_t                   end; /* decompression stream ended */
  char                      type; /* g(z) / b(zip2) / x(z) */
} scamper_file_z_t;
#endif

struct scamper_file
{
  char                     *filename;
  int                       fd;
  void                     *state;
  size_t                    type;
  int                       eof;
  char                      mode;
  scamper_file_writefunc_t  writefunc;
  void                     *writeparam;
  scamper_file_readfunc_t   readfunc;
  void                     *readparam;

#ifdef HAVE_SCAMPER_FILE_Z
  scamper_file_z_t         *z;
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

typedef struct write_handlers
{
  int (*cycle_start)(const scamper_file_t *sf, scamper_cycle_t *cycle);
  int (*cycle_stop)(const scamper_file_t *sf, scamper_cycle_t *cycle);
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACE)
  int (*trace)(const scamper_file_t *sf, const scamper_trace_t *trace, void *p);
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_PING)
  int (*ping)(const scamper_file_t *sf, const scamper_ping_t *ping, void *p);
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACELB)
  int (*tracelb)(const scamper_file_t *sf,
		 const scamper_tracelb_t *trace, void *p);
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_DEALIAS)
  int (*dealias)(const scamper_file_t *sf,
		 const scamper_dealias_t *dealias, void *p);
#endif
  int (*neighbourdisc)(const scamper_file_t *sf,
		       const scamper_neighbourdisc_t *nd, void *p);
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TBIT)
  int (*tbit)(const scamper_file_t *sf, const scamper_tbit_t *tbit, void *p);
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_STING)
  int (*sting)(const scamper_file_t *sf, const scamper_sting_t *sting, void *p);
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_SNIFF)
  int (*sniff)(const scamper_file_t *sf, const scamper_sniff_t *sniff, void *p);
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HOST)
  int (*host)(const scamper_file_t *sf, const scamper_host_t *host, void *p);
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HTTP)
  int (*http)(const scamper_file_t *sf, const scamper_http_t *http, void *p);
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_UDPPROBE)
  int (*udpprobe)(const scamper_file_t *sf,
		  const scamper_udpprobe_t *up, void *p);
#endif
} write_handlers_t;

static write_handlers_t warts_write_handlers =
{
  scamper_file_warts_cyclestart_write,    /* cycle_start */
  scamper_file_warts_cyclestop_write,     /* cycle_stop */
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACE)
  scamper_file_warts_trace_write,         /* trace */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_PING)
  scamper_file_warts_ping_write,          /* ping */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACELB)
  scamper_file_warts_tracelb_write,       /* tracelb */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_DEALIAS)
  scamper_file_warts_dealias_write,       /* dealias */
#endif
  scamper_file_warts_neighbourdisc_write, /* neighbourdisc */
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TBIT)
  scamper_file_warts_tbit_write,          /* tbit */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_STING)
  scamper_file_warts_sting_write,         /* sting */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_SNIFF)
  scamper_file_warts_sniff_write,         /* sniff */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HOST)
  scamper_file_warts_host_write,          /* host */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HTTP)
  scamper_file_warts_http_write,          /* http */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_UDPPROBE)
  scamper_file_warts_udpprobe_write,      /* udpprobe */
#endif
};

static write_handlers_t json_write_handlers =
{
  scamper_file_json_cyclestart_write,     /* cycle_start */
  scamper_file_json_cyclestop_write,      /* cycle_stop */
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACE)
  scamper_file_json_trace_write,          /* trace */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_PING)
  scamper_file_json_ping_write,           /* ping */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACELB)
  scamper_file_json_tracelb_write,        /* tracelb */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_DEALIAS)
  scamper_file_json_dealias_write,        /* dealias */
#endif
  NULL,                                   /* neighbourdisc */
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TBIT)
  scamper_file_json_tbit_write,           /* tbit */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_STING)
  NULL,                                   /* sting */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_SNIFF)
  NULL,                                   /* sniff */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HOST)
  scamper_file_json_host_write,           /* host */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HTTP)
  NULL,                                   /* http */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_UDPPROBE)
 scamper_file_json_udpprobe_write,        /* udpprobe */
#endif
};

static write_handlers_t text_write_handlers =
{
  NULL,                                   /* cycle_start */
  NULL,                                   /* cycle_stop */
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACE)
  scamper_file_text_trace_write,          /* trace */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_PING)
  scamper_file_text_ping_write,           /* ping */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACELB)
  scamper_file_text_tracelb_write,        /* tracelb */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_DEALIAS)
  scamper_file_text_dealias_write,        /* dealias */
#endif
  NULL,                                   /* neighbourdisc */
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TBIT)
  scamper_file_text_tbit_write,           /* tbit */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_STING)
  scamper_file_text_sting_write,          /* sting */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_SNIFF)
  NULL,                                   /* sniff */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HOST)
  NULL,                                   /* host */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HTTP)
  NULL,                                   /* http */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_UDPPROBE)
  NULL,                                   /* udpprobe */
#endif
};

static write_handlers_t null_write_handlers =
{
  NULL,                                   /* cycle_start */
  NULL,                                   /* cycle_stop */
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACE)
  NULL,                                   /* trace */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_PING)
  NULL,                                   /* ping */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACELB)
  NULL,                                   /* tracelb */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_DEALIAS)
  NULL,                                   /* dealias */
#endif
  NULL,                                   /* neighbourdisc */
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TBIT)
  NULL,                                   /* tbit */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_STING)
  NULL,                                   /* sting */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_SNIFF)
  NULL,                                   /* sniff */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HOST)
  NULL,                                   /* host */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HTTP)
  NULL,                                   /* http */
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_UDPPROBE)
  NULL,                                   /* udpprobe */
#endif
};

struct handler
{
  char *type;

  int (*init_read)(scamper_file_t *sf);
  int (*init_write)(scamper_file_t *sf);
  int (*init_append)(scamper_file_t *sf);

#ifndef BUILDING_SCAMPER
  int (*read)(scamper_file_t *sf, const scamper_file_filter_t *filter,
	      uint16_t *type, void **data);
#endif

  write_handlers_t *write;

  void (*free_state)(scamper_file_t *sf);
};

static struct handler handlers[] = {
  {NULL,                                   /* type, null for type_tostr */
   init_fail,                              /* init_read */
   init_fail,                              /* init_write */
   init_fail,                              /* init_append */
#ifndef BUILDING_SCAMPER
   NULL,                                   /* read */
#endif
   &null_write_handlers,                   /* write */
   NULL,                                   /* free_state */
  },
  {"text",                                 /* type */
   init_fail,                              /* init_read */
   init_noop,                              /* init_write */
   init_noop,                              /* init_append */
#ifndef BUILDING_SCAMPER
   NULL,                                   /* read */
#endif
   &text_write_handlers,                   /* write */
   NULL,                                   /* free_state */
  },
  {"arts",                                 /* type */
#ifndef BUILDING_SCAMPER
   scamper_file_arts_init_read,            /* init_read */
#else
   init_fail,
#endif
   init_fail,                              /* init_write */
   init_fail,                              /* init_append */
#ifndef BUILDING_SCAMPER
   scamper_file_arts_read,                 /* read */
#endif
   &null_write_handlers,                   /* write */
#ifndef BUILDING_SCAMPER
   scamper_file_arts_free_state,           /* free_state */
#else
   NULL,
#endif
  },
  {"warts",                                /* type */
   scamper_file_warts_init_read,           /* init_read */
   scamper_file_warts_init_write,          /* init_write */
   scamper_file_warts_init_append,         /* init_append */
#ifndef BUILDING_SCAMPER
   scamper_file_warts_read,                /* read */
#endif
   &warts_write_handlers,                  /* write */
   scamper_file_warts_free_state,          /* free_state */
  },
  {"json",                                 /* type */
   init_fail,                              /* init_read */
   scamper_file_json_init_write,           /* init_write */
   scamper_file_json_init_write,           /* init_append */
#ifndef BUILDING_SCAMPER
   NULL,                                   /* read */
#endif
   &json_write_handlers,                   /* write */
   scamper_file_json_free_state,           /* free_state */
  },
  {"warts.gz",                             /* type */
   init_fail,                              /* init_read */
   init_write_warts_gz,                    /* init_write */
   init_fail,                              /* init_append */
#ifndef BUILDING_SCAMPER
   NULL,                                   /* read */
#endif
   &warts_write_handlers,                  /* write */
   scamper_file_warts_free_state,          /* free_state */
  },
  {"warts.bz2",                            /* type */
   init_fail,                              /* init_read */
   init_write_warts_bz2,                   /* init_write */
   init_fail,                              /* init_append */
#ifndef BUILDING_SCAMPER
   NULL,                                   /* read */
#endif
   &warts_write_handlers,                  /* write */
   scamper_file_warts_free_state,          /* free_state */
  },
  {"warts.xz",                             /* type */
   init_fail,                              /* init_read */
   init_write_warts_xz,                    /* init_write */
   init_fail,                              /* init_append */
#ifndef BUILDING_SCAMPER
   NULL,                                   /* read */
#endif
   &warts_write_handlers,                  /* write */
   scamper_file_warts_free_state,          /* free_state */
  },
};

static size_t handler_cnt = sizeof(handlers) / sizeof(struct handler);

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

int scamper_file_write_cycle_start(scamper_file_t *sf, scamper_cycle_t *cycle)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].write->cycle_start != NULL)
    return handlers[sf->type].write->cycle_start(sf, cycle);
  return -1;
}

int scamper_file_write_cycle_stop(scamper_file_t *sf, scamper_cycle_t *cycle)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].write->cycle_stop != NULL)
    return handlers[sf->type].write->cycle_stop(sf, cycle);
  return -1;
}

#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACE)
int scamper_file_write_trace(scamper_file_t *sf,
			     const scamper_trace_t *trace, void *p)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].write->trace != NULL)
    return handlers[sf->type].write->trace(sf, trace, p);
  return -1;
}
#endif

#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_PING)
int scamper_file_write_ping(scamper_file_t *sf,
			    const scamper_ping_t *ping, void *p)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].write->ping != NULL)
    return handlers[sf->type].write->ping(sf, ping, p);
  return -1;
}
#endif

#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACELB)
int scamper_file_write_tracelb(scamper_file_t *sf,
			       const scamper_tracelb_t *trace, void *p)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].write->tracelb != NULL)
    return handlers[sf->type].write->tracelb(sf, trace, p);
  return -1;
}
#endif

#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_DEALIAS)
int scamper_file_write_dealias(scamper_file_t *sf,
			       const scamper_dealias_t *dealias, void *p)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].write->dealias != NULL)
    return handlers[sf->type].write->dealias(sf, dealias, p);
  return -1;
}
#endif

int scamper_file_write_neighbourdisc(scamper_file_t *sf,
				     const scamper_neighbourdisc_t *nd,
				     void *p)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].write->neighbourdisc != NULL)
    return handlers[sf->type].write->neighbourdisc(sf, nd, p);
  return -1;
}

#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TBIT)
int scamper_file_write_tbit(scamper_file_t *sf,
			    const scamper_tbit_t *tbit, void *p)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].write->tbit != NULL)
    return handlers[sf->type].write->tbit(sf, tbit, p);
  return -1;
}
#endif

#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_STING)
int scamper_file_write_sting(scamper_file_t *sf,
			     const scamper_sting_t *sting, void *p)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].write->sting != NULL)
    return handlers[sf->type].write->sting(sf, sting,  p);
  return -1;
}
#endif

#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_SNIFF)
int scamper_file_write_sniff(scamper_file_t *sf,
			     const scamper_sniff_t *sniff, void *p)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].write->sniff != NULL)
    return handlers[sf->type].write->sniff(sf, sniff, p);
  return -1;
}
#endif

#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HOST)
int scamper_file_write_host(scamper_file_t *sf,
			    const scamper_host_t *host, void *p)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].write->host != NULL)
    return handlers[sf->type].write->host(sf, host, p);
  return -1;
}
#endif

#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HTTP)
int scamper_file_write_http(scamper_file_t *sf,
			    const scamper_http_t *http, void *p)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].write->http != NULL)
    return handlers[sf->type].write->http(sf, http, p);
  return -1;
}
#endif

#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_UDPPROBE)
int scamper_file_write_udpprobe(scamper_file_t *sf,
				const scamper_udpprobe_t *up, void *p)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].write->udpprobe != NULL)
    return handlers[sf->type].write->udpprobe(sf, up, p);
  return -1;
}
#endif

int scamper_file_write_obj(scamper_file_t *sf, uint16_t type, const void *data)
{
  static int (*const func[])(scamper_file_t *sf, const void *, void *) = {
    NULL,
    NULL, /* SCAMPER_FILE_OBJ_LIST */
    NULL, /* SCAMPER_FILE_OBJ_CYCLE_START */
    NULL, /* SCAMPER_FILE_OBJ_CYCLE_DEF */
    NULL, /* SCAMPER_FILE_OBJ_CYCLE_STOP */
    NULL, /* SCAMPER_FILE_OBJ_ADDR */
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACE)
    (write_obj_func_t)scamper_file_write_trace,
#else
    NULL,
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_PING)
    (write_obj_func_t)scamper_file_write_ping,
#else
    NULL,
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TRACELB)
    (write_obj_func_t)scamper_file_write_tracelb,
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_DEALIAS)
    (write_obj_func_t)scamper_file_write_dealias,
#endif
    (write_obj_func_t)scamper_file_write_neighbourdisc,
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_TBIT)
    (write_obj_func_t)scamper_file_write_tbit,
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_STING)
    (write_obj_func_t)scamper_file_write_sting,
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_SNIFF)
    (write_obj_func_t)scamper_file_write_sniff,
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HOST)
    (write_obj_func_t)scamper_file_write_host,
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_HTTP)
    (write_obj_func_t)scamper_file_write_http,
#endif
#if !defined(BUILDING_SCAMPER) || !defined(DISABLE_SCAMPER_UDPPROBE)
    (write_obj_func_t)scamper_file_write_udpprobe,
#endif
  };
  if(type > SCAMPER_FILE_OBJ_MAX)
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
#ifndef BUILDING_SCAMPER
int scamper_file_read(scamper_file_t *sf,
		      const scamper_file_filter_t *filter,
		      uint16_t *type, void **object)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].read != NULL)
    return handlers[sf->type].read(sf, filter, type, object);
  return -1;
}
#endif

/*
 * scamper_file_filter_isset
 *
 * check to see if the particular type is set in the filter or not
 */
int scamper_file_filter_isset(const scamper_file_filter_t *filter,
			      uint16_t type)
{
  /* no object with type zero */
  if(type == 0)
    return 0;

  /* if no filter passed, return the object if we know about it */
  if(filter == NULL)
    {
      if(type <= SCAMPER_FILE_OBJ_MAX && type != SCAMPER_FILE_OBJ_ADDR)
	return 1;
    }
  else
    {
      if(type <= filter->max &&
	 (filter->flags[type/32] & (0x1 << ((type%32)-1))) != 0)
	return 1;
    }

  return 0;
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

#ifdef HAVE_SCAMPER_FILE_Z
static void z_free(scamper_file_z_t *z, char mode)
{
  switch(z->type)
    {
#ifdef HAVE_ZLIB
    case 'g':
      if(z->s.gzs != NULL)
	{
	  if(mode == 'r')
	    inflateEnd(z->s.gzs);
	  else if(mode == 'w')
	    deflateEnd(z->s.gzs);
	  free(z->s.gzs);
	}
      break;
#endif

#ifdef HAVE_LIBBZ2
    case 'b':
      if(z->s.bzs != NULL)
	{
	  if(mode == 'r')
	    BZ2_bzDecompressEnd(z->s.bzs);
	  else if(mode == 'w')
	    BZ2_bzCompressEnd(z->s.bzs);
	  free(z->s.bzs);
	}
      break;
#endif

#ifdef HAVE_LIBLZMA
    case 'x':
      if(z->s.xzs != NULL)
	{
	  lzma_end(z->s.xzs);
	  free(z->s.xzs);
	}
      break;
#endif
    }

  free(z);
  return;
}

static scamper_file_z_t *z_alloc(char type)
{
  scamper_file_z_t *z;
  assert(type == 'g' || type == 'b' || type == 'x');
  if((z = malloc_zero(sizeof(scamper_file_z_t))) == NULL)
    return NULL;
  z->type = type;
  return z;
}

static void z_flush(scamper_file_z_t *z, int fd)
{
  size_t have;

#if defined(HAVE_LIBBZ2) || defined(HAVE_LIBLZMA)
  int rc;
#endif

#ifdef HAVE_ZLIB
  if(z->type == 'g')
    {
      z->s.gzs->next_in = NULL;
      z->s.gzs->avail_in = 0;
      z->s.gzs->avail_out = sizeof(z->out);
      z->s.gzs->next_out = z->out;
      if(deflate(z->s.gzs, Z_FINISH) != Z_STREAM_ERROR)
	{
	  have = sizeof(z->out) - z->s.gzs->avail_out;
	  if(have > 0)
	    write_wrap(fd, z->out, NULL, have);
	}
      return;
    }
#endif

#ifdef HAVE_LIBBZ2
  if(z->type == 'b')
    {
      z->s.bzs->next_in = NULL;
      z->s.bzs->avail_in = 0;
      do
	{
	  z->s.bzs->avail_out = sizeof(z->out);
	  z->s.bzs->next_out = (char *)z->out;
	  rc = BZ2_bzCompress(z->s.bzs, BZ_FINISH);
	  if((rc == BZ_FINISH_OK || rc == BZ_STREAM_END) &&
	     (have = sizeof(z->out) - z->s.bzs->avail_out) > 0)
	    write_wrap(fd, z->out, NULL, have);
	}
      while(rc == BZ_FINISH_OK);
      return;
    }
#endif

#ifdef HAVE_LIBLZMA
  if(z->type == 'x')
    {
      z->s.xzs->next_in = NULL;
      z->s.xzs->avail_in = 0;
      do
	{
	  z->s.xzs->avail_out = sizeof(z->out);
	  z->s.xzs->next_out = z->out;
	  rc = lzma_code(z->s.xzs, LZMA_FINISH);
	  have = sizeof(z->out) - z->s.xzs->avail_out;
	  if(have > 0)
	    write_wrap(fd, z->out, NULL, have);
	}
      while(rc != LZMA_STREAM_END);
      return;
    }
#endif

  return;
}

#endif

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

#ifdef HAVE_SCAMPER_FILE_Z
      if(sf->z != NULL)
	z_free(sf->z, sf->mode);
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
  assert(sf->type < handler_cnt);

#ifdef HAVE_SCAMPER_FILE_Z
  if(sf->z != NULL && sf->mode == 'w')
    z_flush(sf->z, sf->fd);
#endif

  /* free state associated with the type of scamper_file_t */
  if(handlers[sf->type].free_state != NULL)
    handlers[sf->type].free_state(sf);

  /* close the file descriptor */
  if(sf->fd != -1)
    close(sf->fd);

  /* free general state associated */
  scamper_file_free(sf);

  return;
}

char *scamper_file_type_tostr(scamper_file_t *sf, char *buf, size_t len)
{
  assert(sf->type < handler_cnt);
  if(handlers[sf->type].type == NULL)
    return NULL;
  strncpy(buf, handlers[sf->type].type, len);
  return buf;
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
    "http",
    "udpprobe",
  };
  uint16_t typec = sizeof(types)/sizeof(char *);
  if(typec > type)
    return types[type];
  return NULL;
}

#ifdef HAVE_SCAMPER_FILE_Z
static int z_avail_out(scamper_file_z_t *z, size_t *avail_out)
{
#ifdef HAVE_ZLIB
  if(z->type == 'g') { *avail_out = z->s.gzs->avail_out; return 0; }
#endif
#ifdef HAVE_LIBBZ2
  if(z->type == 'b') { *avail_out = z->s.bzs->avail_out; return 0; }
#endif
#ifdef HAVE_LIBLZMA
  if(z->type == 'x') { *avail_out = z->s.xzs->avail_out; return 0; }
#endif
  return -1;
}

static int z_in_pair(scamper_file_z_t *z, size_t *avail_in, uint8_t **next_in)
{
#ifdef HAVE_ZLIB
  if(z->type == 'g')
    {
      *avail_in = z->s.gzs->avail_in;
      *next_in = z->s.gzs->next_in;
      return 0;
    }
#endif
#ifdef HAVE_LIBBZ2
  if(z->type == 'b')
    {
      *avail_in = z->s.bzs->avail_in;
      *next_in = (uint8_t *)z->s.bzs->next_in;
      return 0;
    }
#endif
#ifdef HAVE_LIBLZMA
  if(z->type == 'x')
    {
      *avail_in = z->s.xzs->avail_in;
      *next_in = (uint8_t *)z->s.xzs->next_in;
      return 0;
    }
#endif
  return -1;
}

static int z_out_pair_add(scamper_file_z_t *z, size_t b)
{
#ifdef HAVE_ZLIB
  if(z->type == 'g')
    {
      z->s.gzs->avail_out += b;
      z->s.gzs->next_out -= b;
      return 0;
    }
#endif
#ifdef HAVE_LIBBZ2
  if(z->type == 'b')
    {
      z->s.bzs->avail_out += b;
      z->s.bzs->next_out -= b;
      return 0;
    }
#endif
#ifdef HAVE_LIBLZMA
  if(z->type == 'x')
    {
      z->s.xzs->avail_out += b;
      z->s.xzs->next_out -= b;
      return 0;
    }
#endif
  return -1;
}

static int z_next_in_reset(scamper_file_z_t *z)
{
#ifdef HAVE_ZLIB
  if(z->type == 'g') { z->s.gzs->next_in = z->in; return 0; }
#endif
#ifdef HAVE_LIBBZ2
  if(z->type == 'b') { z->s.bzs->next_in = (char *)z->in; return 0; }
#endif
#ifdef HAVE_LIBLZMA
  if(z->type == 'x') { z->s.xzs->next_in = z->in; return 0; }
#endif
  return -1;
}

static int z_avail_in_add(scamper_file_z_t *z, ssize_t val)
{
#ifdef HAVE_ZLIB
  if(z->type == 'g') { z->s.gzs->avail_in += val; return 0; }
#endif
#ifdef HAVE_LIBBZ2
  if(z->type == 'b') { z->s.bzs->avail_in += val; return 0; }
#endif
#ifdef HAVE_LIBLZMA
  if(z->type == 'x') { z->s.xzs->avail_in += val; return 0; }
#endif
  return -1;
}

static int z_decompress(scamper_file_z_t *z, size_t *have)
{
  int rc;

#ifdef HAVE_ZLIB
  if(z->type == 'g')
    {
      rc = inflate(z->s.gzs, Z_NO_FLUSH);
      if(rc == Z_STREAM_END)
	z->end = 1;
      else if(rc != Z_OK)
	return -1;
      *have = sizeof(z->out) - z->s.gzs->avail_out;
      return 0;
    }
#endif
#ifdef HAVE_LIBBZ2
  if(z->type == 'b')
    {
      rc = BZ2_bzDecompress(z->s.bzs);
      if(rc == BZ_STREAM_END)
	z->end = 1;
      else if(rc != BZ_OK)
	return -1;
      *have = sizeof(z->out) - z->s.bzs->avail_out;
      return 0;
    }
#endif
#ifdef HAVE_LIBLZMA
  if(z->type == 'x')
    {
      rc = lzma_code(z->s.xzs, z->eof == 0 ? LZMA_RUN : LZMA_FINISH);
      if(rc == LZMA_STREAM_END)
	z->end = 1;
      else if(rc != LZMA_OK)
	return -1;
      *have = sizeof(z->out) - z->s.xzs->avail_out;
      return 0;
    }
#endif
  return -1;
}

static int z_read(scamper_file_t *sf, uint8_t **data, size_t len)
{
  uint8_t *tmp = NULL;
  ssize_t readc;
  size_t b, have, avail_in, avail_out, off = 0;
  uint8_t *next_in;

  *data = NULL;

  if((tmp = malloc(len)) == NULL ||
     z_avail_out(sf->z, &avail_out) != 0)
    goto err;
  have = sizeof(sf->z->out) - avail_out;

  while(sf->z->end == 0 || have > 0)
    {
      /* copy data out of the decompression buffer into the data buffer */
      if(have > 0)
	{
	  if(have >= len - off)
	    b = len - off;
	  else
	    b = have;

	  memcpy(tmp+off, sf->z->out, b);
	  memmove(sf->z->out, sf->z->out + b, sizeof(sf->z->out) - b);
	  off += b;
	  have -= b;

	  /* adjust avail_out / next_out according to b */
	  if(z_out_pair_add(sf->z, b) != 0)
	    goto err;

	  /* if we have everything we need, we can return now */
	  if(off == len)
	    {
	      *data = tmp;
	      return 0;
	    }
	}

      /*
       * read until have > 0 (there is data in the decompression
       * output buffer) or we have got to the end of the file
       */
      do
	{
	  if(z_in_pair(sf->z, &avail_in, &next_in) != 0)
	    goto err;

	  /* if there is space to read into the buffer, then read */
	  b = sizeof(sf->z->in) - avail_in;
	  if(b > 0 && sf->z->eof == 0)
	    {
	      /* move input buffer back to start of z->in */
	      memmove(sf->z->in, next_in, avail_in);
	      z_next_in_reset(sf->z);

	      /* make a read, and adjust state according to return value */
	      readc = read(sf->fd, sf->z->in + avail_in, b);
	      if(readc < 0)
		goto err;
	      else if(readc == 0)
		sf->z->eof = 1;
	      else if(z_avail_in_add(sf->z, readc) != 0)
		goto err;
	    }

	  /* decompress */
	  if(z_decompress(sf->z, &have) != 0)
	    goto err;
	}
      while(have == 0 && sf->z->eof == 0);
    }

  free(tmp);
  return -2;

 err:
  if(tmp != NULL) free(tmp);
  return -1;
}

#ifdef HAVE_ZLIB
static int zlib_write(scamper_file_t *sf, const void *buf, size_t len, void *p)
{
  size_t have;

  if(sf->z == NULL || sf->z->s.gzs == NULL)
    return -1;

  sf->z->s.gzs->next_in = (void *)buf;
  sf->z->s.gzs->avail_in = len;

  do
    {
      sf->z->s.gzs->avail_out = sizeof(sf->z->out);
      sf->z->s.gzs->next_out = sf->z->out;
      if(deflate(sf->z->s.gzs, Z_NO_FLUSH) == Z_STREAM_ERROR)
	return -1;

      have = sizeof(sf->z->out) - sf->z->s.gzs->avail_out;
      if(have > 0 && write_wrap(sf->fd, sf->z->out, NULL, have) != 0)
	return -1;
    }
  while(sf->z->s.gzs->avail_out == 0);

  return 0;
}
#endif

#ifdef HAVE_LIBBZ2
static int libbz2_write(scamper_file_t *sf,const void *buf,size_t len,void *p)
{
  size_t have;

  if(sf->z == NULL || sf->z->s.bzs == NULL)
    return -1;

  sf->z->s.bzs->next_in = (void *)buf;
  sf->z->s.bzs->avail_in = len;

  do
    {
      sf->z->s.bzs->avail_out = sizeof(sf->z->out);
      sf->z->s.bzs->next_out = (char *)sf->z->out;
      if(BZ2_bzCompress(sf->z->s.bzs, BZ_RUN) != BZ_RUN_OK)
	return -1;

      have = sizeof(sf->z->out) - sf->z->s.bzs->avail_out;
      if(have > 0 && write_wrap(sf->fd, sf->z->out, NULL, have) != 0)
	return -1;
    }
  while(sf->z->s.bzs->avail_out == 0);

  return 0;
}
#endif

#ifdef HAVE_LIBLZMA
static int xz_write(scamper_file_t *sf, const void *buf, size_t len, void *p)
{
  size_t have;

  if(sf->z == NULL || sf->z->s.xzs == NULL)
    return -1;

  sf->z->s.xzs->next_in = (void *)buf;
  sf->z->s.xzs->avail_in = len;

  do
    {
      sf->z->s.xzs->avail_out = sizeof(sf->z->out);
      sf->z->s.xzs->next_out = sf->z->out;
      if(lzma_code(sf->z->s.xzs, LZMA_RUN) != LZMA_OK)
	return -1;

      have = sizeof(sf->z->out) - sf->z->s.xzs->avail_out;
      if(have > 0 && write_wrap(sf->fd, sf->z->out, NULL, have) != 0)
	return -1;
    }
  while(sf->z->s.xzs->avail_out == 0);

  return 0;
}
#endif
#endif

static size_t file_type_get(const char *type)
{
  size_t i;
  if(type == NULL)
    return SCAMPER_FILE_TYPE_NONE;
  for(i=1; i<handler_cnt; i++)
    if(strcasecmp(type, handlers[i].type) == 0)
      return i;
  return SCAMPER_FILE_TYPE_NONE;
}

static int file_type_detect(scamper_file_t *sf)
{
  uint8_t buf[6], *ptr = buf;

#if defined(HAVE_ZLIB) || defined(HAVE_LIBBZ2) || defined(HAVE_LIBLZMA)
  ssize_t readc;
  int rc;
#endif

  if(lseek(sf->fd, 0, SEEK_SET) == -1 ||
     read_wrap(sf->fd, buf, NULL, sizeof(buf)) != 0 ||
     lseek(sf->fd, 0, SEEK_SET) == -1)
    return SCAMPER_FILE_TYPE_NONE;

  if(buf[0] == 0x1F && buf[1] == 0x8B)
    {
#ifdef HAVE_ZLIB
      if((sf->z = z_alloc('g')) == NULL ||
	 (sf->z->s.gzs = malloc_zero(sizeof(z_stream))) == NULL ||
	 inflateInit2(sf->z->s.gzs, MAX_WBITS + 32) != Z_OK)
	return SCAMPER_FILE_TYPE_NONE;
      sf->readfunc = (scamper_file_readfunc_t)z_read;
      sf->readparam = sf;
      sf->z->s.gzs->next_out = sf->z->out;
      sf->z->s.gzs->avail_out = sizeof(sf->z->out);

      if((readc = read(sf->fd, sf->z->in, sizeof(sf->z->in))) <= 0)
	return SCAMPER_FILE_TYPE_NONE;
      sf->z->s.gzs->next_in = sf->z->in;
      sf->z->s.gzs->avail_in = readc;

      rc = inflate(sf->z->s.gzs, Z_NO_FLUSH);
      if(rc == Z_STREAM_END)
	sf->z->end = 1;
      else if(rc != Z_OK)
	return SCAMPER_FILE_TYPE_NONE;
      ptr = sf->z->out;
#else
      return SCAMPER_FILE_TYPE_NONE;
#endif
    }
  else if(buf[0] == 0x42 && buf[1] == 0x5A)
    {
#ifdef HAVE_LIBBZ2
      if((sf->z = z_alloc('b')) == NULL ||
	 (sf->z->s.bzs = malloc_zero(sizeof(bz_stream))) == NULL ||
	 BZ2_bzDecompressInit(sf->z->s.bzs, 0, 0) != BZ_OK)
	return SCAMPER_FILE_TYPE_NONE;
      sf->readfunc = (scamper_file_readfunc_t)z_read;
      sf->readparam = sf;
      sf->z->s.bzs->next_out = (char *)sf->z->out;
      sf->z->s.bzs->avail_out = sizeof(sf->z->out);

      do
	{
	  if((readc = read(sf->fd, sf->z->in, sizeof(sf->z->in))) <= 0)
	    return SCAMPER_FILE_TYPE_NONE;
	  sf->z->s.bzs->next_in = (char *)sf->z->in;
	  sf->z->s.bzs->avail_in = readc;

	  rc = BZ2_bzDecompress(sf->z->s.bzs);
	  if(rc == BZ_STREAM_END)
	    sf->z->end = 1;
	  else if(rc != BZ_OK)
	    return SCAMPER_FILE_TYPE_NONE;
	}
      while(sf->z->s.bzs->avail_out == sizeof(sf->z->out));

      ptr = sf->z->out;
#else
      return SCAMPER_FILE_TYPE_NONE;
#endif
    }
  else if(buf[0] == 0xFD && buf[1] == 0x37 && buf[2] == 0x7A &&
	  buf[3] == 0x58 && buf[4] == 0x5A && buf[5] == 0x00)
    {
#ifdef HAVE_LIBLZMA
      if((sf->z = z_alloc('x')) == NULL ||
	 (sf->z->s.xzs = malloc_zero(sizeof(lzma_stream))) == NULL ||
	 lzma_stream_decoder(sf->z->s.xzs, UINT64_MAX, 0) != LZMA_OK)
	return SCAMPER_FILE_TYPE_NONE;
      sf->readfunc = (scamper_file_readfunc_t)z_read;
      sf->readparam = sf;
      sf->z->s.xzs->next_out = sf->z->out;
      sf->z->s.xzs->avail_out = sizeof(sf->z->out);

      do
	{
	  if((readc = read(sf->fd, sf->z->in, sizeof(sf->z->in))) <= 0)
	    return SCAMPER_FILE_TYPE_NONE;
	  sf->z->s.xzs->next_in = sf->z->in;
	  sf->z->s.xzs->avail_in = readc;

	  rc = lzma_code(sf->z->s.xzs, LZMA_RUN);
	  if(rc == LZMA_STREAM_END)
	    sf->z->end = 1;
	  else if(rc != LZMA_OK)
	    return SCAMPER_FILE_TYPE_NONE;
	}
      while(sf->z->s.xzs->avail_out == sizeof(sf->z->out));

      ptr = sf->z->out;
#else
      return SCAMPER_FILE_TYPE_NONE;
#endif
    }

  if(ptr[0] == 0x12 && ptr[1] == 0x05)
    return SCAMPER_FILE_TYPE_WARTS;
  if(ptr[0] == 0xDF && ptr[1] == 0xB0)
    return SCAMPER_FILE_TYPE_ARTS;

  return SCAMPER_FILE_TYPE_NONE;
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

  assert(sf->type < handler_cnt);
  return handlers[sf->type].init_read(sf);
}

static int file_open_write(scamper_file_t *sf)
{
  assert(sf->type < handler_cnt);
  return handlers[sf->type].init_write(sf);
}

static int init_noop(scamper_file_t *sf)
{
  return 0;
}

static int init_fail(scamper_file_t *sf)
{
  return -1;
}

static int init_write_warts_gz(scamper_file_t *sf)
{
#ifdef HAVE_ZLIB
  if((sf->z = z_alloc('g')) == NULL ||
     (sf->z->s.gzs = malloc_zero(sizeof(z_stream))) == NULL ||
     deflateInit2(sf->z->s.gzs, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
		  15 | 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
    return -1;
  sf->writefunc = (scamper_file_writefunc_t)zlib_write;
  sf->writeparam = sf;
  return handlers[SCAMPER_FILE_TYPE_WARTS].init_write(sf);
#else
  return -1;
#endif
}

static int init_write_warts_bz2(scamper_file_t *sf)
{
#ifdef HAVE_LIBBZ2
  if((sf->z = z_alloc('b')) == NULL ||
     (sf->z->s.bzs = malloc_zero(sizeof(bz_stream))) == NULL ||
     BZ2_bzCompressInit(sf->z->s.bzs, 6, 0, 0) != BZ_OK)
    return -1;
  sf->writefunc = (scamper_file_writefunc_t)libbz2_write;
  sf->writeparam = sf;
  return handlers[SCAMPER_FILE_TYPE_WARTS].init_write(sf);
#else
  return -1;
#endif
}

static int init_write_warts_xz(scamper_file_t *sf)
{
#ifdef HAVE_LIBLZMA
  if((sf->z = z_alloc('x')) == NULL ||
     (sf->z->s.xzs = malloc_zero(sizeof(lzma_stream))) == NULL ||
     lzma_easy_encoder(sf->z->s.xzs, LZMA_PRESET_DEFAULT,
		       LZMA_CHECK_CRC64) != LZMA_OK)
    return -1;
  sf->writefunc = (scamper_file_writefunc_t)xz_write;
  sf->writeparam = sf;
  return handlers[SCAMPER_FILE_TYPE_WARTS].init_write(sf);
#else
  return -1;
#endif
}

static int file_open_append(scamper_file_t *sf)
{
  struct stat sb;

  /*
   * appending to a zero-sized file is the same as just writing to a
   * new file
   */
  if(fstat(sf->fd, &sb) != 0)
    return -1;
  assert(sf->type < handler_cnt);
  if(sb.st_size == 0)
    return handlers[sf->type].init_write(sf);

  /* can't append to pipes */
  if((sb.st_mode & S_IFIFO) != 0)
    return -1;

  sf->type = file_type_detect(sf);
  assert(sf->type < handler_cnt);
  return handlers[sf->type].init_append(sf);
}

static scamper_file_t *file_open(int fd, const char *fn, char mode, size_t type)
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

  sf->mode = mode;
  sf->type = type;
  sf->fd   = fd;
  if(open_func(sf) == -1)
    {
      scamper_file_close(sf);
      return NULL;
    }

  return sf;
}

scamper_file_t *scamper_file_opennull(char mode, const char *type)
{
  uint8_t file_type;

  if(strcasecmp(type, "warts") == 0)
    file_type = SCAMPER_FILE_TYPE_WARTS;
  else if(strcasecmp(type, "json") == 0)
    file_type = SCAMPER_FILE_TYPE_JSON;
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
 * to write or append to; the valid classes are "warts", "text", "json",
 * "warts.gz"
 *
 */
scamper_file_t *scamper_file_open(const char *filename, char mode,
				  const char *type)
{
  scamper_file_t *sf;
  size_t ft = file_type_get(type);
  int flags = 0;
  int fd = -1;

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
      if(handlers[ft].init_write == init_fail)
	return NULL;

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

#ifdef _WIN32 /* windows needs O_BINARY */
  flags |= O_BINARY;
#endif

  if(fd == -1)
    {
      if(mode == 'r') fd = open(filename, flags);
      else            fd = open(filename, flags, MODE_644);

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
