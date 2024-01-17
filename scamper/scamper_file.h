/*
 * scamper_file.c
 *
 * $Id: scamper_file.h,v 1.45 2023/11/22 04:10:09 mjl Exp $
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

#ifndef __SCAMPER_FILE_H
#define __SCAMPER_FILE_H

/* handle for reading / writing files that scamper understands */
typedef struct scamper_file scamper_file_t;

/* handle for filtering objects from a file when reading */
typedef struct scamper_file_filter scamper_file_filter_t;

typedef int (*scamper_file_writefunc_t)(void *wf_param,
					const void *data, size_t len, void *p);

typedef int (*scamper_file_readfunc_t)(void *param,
				       uint8_t **data, size_t len);

/* handle for maintaining a readbuf */
typedef struct scamper_file_readbuf scamper_file_readbuf_t;

/* types of objects that scamper understands */
#define SCAMPER_FILE_OBJ_LIST          1
#define SCAMPER_FILE_OBJ_CYCLE_START   2
#define SCAMPER_FILE_OBJ_CYCLE_DEF     3
#define SCAMPER_FILE_OBJ_CYCLE_STOP    4
#define SCAMPER_FILE_OBJ_ADDR          5
#define SCAMPER_FILE_OBJ_TRACE         6
#define SCAMPER_FILE_OBJ_PING          7
#define SCAMPER_FILE_OBJ_TRACELB       8
#define SCAMPER_FILE_OBJ_DEALIAS       9
#define SCAMPER_FILE_OBJ_NEIGHBOURDISC 10
#define SCAMPER_FILE_OBJ_TBIT          11
#define SCAMPER_FILE_OBJ_STING         12
#define SCAMPER_FILE_OBJ_SNIFF         13
#define SCAMPER_FILE_OBJ_HOST          14
#define SCAMPER_FILE_OBJ_HTTP          15
#define SCAMPER_FILE_OBJ_UDPPROBE      16

#define SCAMPER_FILE_OBJ_MAX           16

scamper_file_t *scamper_file_open(const char *fn, char mode, const char *type);
scamper_file_t *scamper_file_openfd(int fd, const char *fn, char mode,
				    const char *type);
scamper_file_t *scamper_file_opennull(char mode, const char *type);
void scamper_file_close(scamper_file_t *sf);
void scamper_file_free(scamper_file_t *sf);

scamper_file_filter_t *scamper_file_filter_alloc(const uint16_t *types,
						 uint16_t num);
int scamper_file_filter_isset(const scamper_file_filter_t *filter,
			      uint16_t type);
void scamper_file_filter_free(scamper_file_filter_t *filter);

int scamper_file_read(scamper_file_t *sf,
		      const scamper_file_filter_t *filter,
		      uint16_t *obj_type, void **obj_data);

int scamper_file_write_obj(scamper_file_t *sf,uint16_t type,const void *data);

struct scamper_cycle;
int scamper_file_write_cycle_start(scamper_file_t *sf,
				   struct scamper_cycle *cycle);
int scamper_file_write_cycle_stop(scamper_file_t *sf,
				  struct scamper_cycle *cycle);

struct scamper_trace;
int scamper_file_write_trace(scamper_file_t *sf,
			     const struct scamper_trace *trace, void *p);

struct scamper_tracelb;
int scamper_file_write_tracelb(scamper_file_t *sf,
			       const struct scamper_tracelb *trace, void *p);

struct scamper_ping;
int scamper_file_write_ping(scamper_file_t *sf,
			    const struct scamper_ping *ping, void *p);

struct scamper_sting;
int scamper_file_write_sting(scamper_file_t *sf,
			     const struct scamper_sting *sting, void *p);

struct scamper_dealias;
int scamper_file_write_dealias(scamper_file_t *sf,
			       const struct scamper_dealias *dealias, void *p);

struct scamper_neighbourdisc;
int scamper_file_write_neighbourdisc(scamper_file_t *sf,
				     const struct scamper_neighbourdisc *nd,
				     void *p);

struct scamper_tbit;
int scamper_file_write_tbit(scamper_file_t *sf,
			    const struct scamper_tbit *tbit, void *p);

struct scamper_sniff;
int scamper_file_write_sniff(scamper_file_t *sf,
			     const struct scamper_sniff *sniff, void *p);

struct scamper_host;
int scamper_file_write_host(scamper_file_t *sf,
			    const struct scamper_host *host, void *p);

struct scamper_http;
int scamper_file_write_http(scamper_file_t *sf,
			    const struct scamper_http *http, void *p);

struct scamper_udpprobe;
int scamper_file_write_udpprobe(scamper_file_t *sf,
				const struct scamper_udpprobe *up, void *p);

char *scamper_file_type_tostr(scamper_file_t *sf, char *buf, size_t len);
const char *scamper_file_objtype_tostr(uint16_t type);
char *scamper_file_getfilename(scamper_file_t *sf);

int   scamper_file_geteof(const scamper_file_t *sf);
void  scamper_file_seteof(scamper_file_t *sf);

/* instead of calling read, call the supplied readfunc */
void  scamper_file_setreadfunc(scamper_file_t *sf, void *param,
			       scamper_file_readfunc_t readfunc);
scamper_file_readfunc_t scamper_file_getreadfunc(const scamper_file_t *sf);
void *scamper_file_getreadparam(const scamper_file_t *sf);

/* a set of routines that can be used with scamper_file_setreadfunc */
scamper_file_readbuf_t *scamper_file_readbuf_alloc(void);
void scamper_file_readbuf_free(scamper_file_readbuf_t *rb);
int scamper_file_readbuf_add(scamper_file_readbuf_t *rb,
			     const void *data, size_t len);
int scamper_file_readbuf_read(void *param, uint8_t **data, size_t len);

/* instead of calling write, call the supplied writefunc */
void  scamper_file_setwritefunc(scamper_file_t *sf, void *param,
				scamper_file_writefunc_t writefunc);
scamper_file_writefunc_t scamper_file_getwritefunc(const scamper_file_t *sf);
void *scamper_file_getwriteparam(const scamper_file_t *sf);

int   scamper_file_getfd(const scamper_file_t *sf);
void *scamper_file_getstate(const scamper_file_t *sf);
void  scamper_file_setstate(scamper_file_t *sf, void *state);

#endif /* __SCAMPER_FILE_H */
