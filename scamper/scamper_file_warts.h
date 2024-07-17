/*
 * scamper_file_warts.h
 *
 * the warts file format
 *
 * $Id: scamper_file_warts.h,v 1.34 2024/05/01 07:46:20 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
 * Copyright (C) 2016-2023 Matthew Luckie
 * Copyright (C) 2024      The Regents of the University of California
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

#ifndef __SCAMPER_FILE_WARTS_H
#define __SCAMPER_FILE_WARTS_H

#include "scamper_icmpext.h"
#include "scamper_ifname.h"

/*
 * warts_var
 *
 * warts often stores optional items of data with each object.  it does
 * this by declaring an array of bits that declare which optional bits of
 * data will be stored.  the warts_var structure is a convenient way of
 * encouraging the code for each object to be consistent.
 *
 * the id field corresponds to a bit
 * the size field records how large the field is stored on disk; -1 is variable
 */
typedef struct warts_var
{
  int     id;
  ssize_t size;
} warts_var_t;
#define WARTS_VAR_COUNT(array) (sizeof(array)/sizeof(warts_var_t))
#define WARTS_VAR_MFB(array) ((WARTS_VAR_COUNT(array) / 7) + \
			      (WARTS_VAR_COUNT(array) % 7 == 0 ? 0 : 1))

/*
 * warts_addrtable
 *
 * keep track of addresses and ifnames being written to disk.
 */
typedef struct warts_addrtable warts_addrtable_t;
typedef struct warts_ifnametable warts_ifnametable_t;

/*
 * warts_hdr
 *
 * this object is written at the start of every object.
 * the magic field is a special integer value that signifies a new warts
 * record.
 * the type field says what type of record follows.
 * the length field reports the length of the following record.
 */
typedef struct warts_hdr
{
  uint16_t magic;
  uint16_t type;
  uint32_t len;
} warts_hdr_t;

/*
 * warts_state
 *
 * warts keeps state of lists, cycles, and addresses declared in a warts
 * file.
 */
typedef struct warts_state warts_state_t;

typedef int (*wpr_t)(const uint8_t *,uint32_t *,const uint32_t,void *, void *);
typedef void (*wpw_t)(uint8_t *,uint32_t *,const uint32_t,const void *,void *);

typedef struct warts_param_reader
{
  void       *data;
  wpr_t       read;
  void       *param;
} warts_param_reader_t;

typedef struct warts_param_writer
{
  const void *data;
  wpw_t       write;
  void       *param;
} warts_param_writer_t;

void flag_ij(const int id, int *i, int *j);
void flag_set(uint8_t *flags, const int id, int *max_id);
int flag_isset(const uint8_t *flags, const int id);
uint16_t fold_flags(uint8_t *flags, const int max_id);

int warts_str_size(const char *str, uint16_t *len);

warts_addrtable_t *warts_addrtable_alloc_byaddr(void);
warts_addrtable_t *warts_addrtable_alloc_byid(void);
int warts_addr_size(warts_addrtable_t *t, scamper_addr_t *addr, uint16_t *len);
int warts_addr_size_static(scamper_addr_t *addr, uint16_t *len);
void warts_addrtable_free(warts_addrtable_t *t);

warts_ifnametable_t *warts_ifnametable_alloc_byname(void);
warts_ifnametable_t *warts_ifnametable_alloc_byid(void);
int warts_ifname_size(warts_ifnametable_t *t, scamper_ifname_t *addr,
		      uint16_t *len);
void warts_ifnametable_free(warts_ifnametable_t *t);
void insert_ifname(uint8_t *buf, uint32_t *off, const uint32_t len,
                   const scamper_ifname_t *ifn, warts_ifnametable_t *table);
int extract_ifname(const uint8_t *buf, uint32_t *off, uint32_t len,
		   scamper_ifname_t **out, warts_ifnametable_t *table);

void insert_addr_static(uint8_t *buf, uint32_t *off, const uint32_t len,
			const scamper_addr_t *addr, void *param);
void insert_addr(uint8_t *buf, uint32_t *off, const uint32_t len,
			const scamper_addr_t *addr, warts_addrtable_t *param);
void insert_uint16(uint8_t *buf, uint32_t *off, const uint32_t len,
			  const uint16_t *in, void *param);
void insert_uint32(uint8_t *buf, uint32_t *off, const uint32_t len,
			  const uint32_t *in, void *param);
void insert_int32(uint8_t *buf, uint32_t *off, const uint32_t len,
		  const int32_t *in, void *param);
void insert_wartshdr(uint8_t *buf, uint32_t *off, uint32_t len,
			    uint16_t hdr_type);
void insert_byte(uint8_t *buf, uint32_t *off, const uint32_t len,
			const uint8_t *in, void *param);
void insert_bytes_uint16(uint8_t *buf,uint32_t *off,const uint32_t len,
				const void *vin, uint16_t *count);
void insert_string(uint8_t *buf, uint32_t *off, const uint32_t len,
			  const char *in, void *param);
void insert_timeval(uint8_t *buf, uint32_t *off, const uint32_t len,
			   const struct timeval *in, void *param);
void insert_rtt(uint8_t *buf, uint32_t *off, const uint32_t len,
		       const struct timeval *tv, void *param);

int extract_addr_static(const uint8_t *buf, uint32_t *off,
			const uint32_t len, scamper_addr_t **out, void *param);
int extract_addr(const uint8_t *buf, uint32_t *off, uint32_t len,
		 scamper_addr_t **out, warts_addrtable_t *table);
int extract_string(const uint8_t *buf, uint32_t *off,
			  const uint32_t len, char **out, void *param);
int extract_uint16(const uint8_t *buf, uint32_t *off,
			  const uint32_t len, uint16_t *out, void *param);
int extract_uint32(const uint8_t *buf, uint32_t *off,
		   const uint32_t len, uint32_t *out, void *param);
int extract_int32(const uint8_t *buf, uint32_t *off,
		  const uint32_t len, int32_t *out, void *param);
int extract_byte(const uint8_t *buf, uint32_t *off,
			const uint32_t len, uint8_t *out, void *param);
int extract_bytes_ptr(const uint8_t *buf, uint32_t *off,
			     const uint32_t len, const uint8_t **out,
			     uint16_t *req);
int extract_bytes_alloc(const uint8_t *buf, uint32_t *off,
			       const uint32_t len, uint8_t **out,
			       uint16_t *req);
int extract_bytes(const uint8_t *buf, uint32_t *off, const uint32_t len,
			 uint8_t *out, uint16_t *req);
int extract_addr_gid(const uint8_t *buf, uint32_t *off,
			    const uint32_t len,
			    scamper_addr_t **addr, warts_state_t *state);
int extract_list(const uint8_t *buf, uint32_t *off,
			const uint32_t len,
			scamper_list_t **list, warts_state_t *state);
int extract_cycle(const uint8_t *buf, uint32_t *off,
			 const uint32_t len,
			 scamper_cycle_t **cycle, warts_state_t *state);
int extract_timeval(const uint8_t *buf, uint32_t *off,
			   const uint32_t len, struct timeval *tv, void *param);
int extract_rtt(const uint8_t *buf, uint32_t *off, const uint32_t len,
		       struct timeval *tv, void *param);


int warts_params_read(const uint8_t *buf, uint32_t *off, uint32_t len,
			     warts_param_reader_t *handlers, int handler_cnt);
void warts_params_write(uint8_t *buf, uint32_t *off,
			       const uint32_t len,
			       const uint8_t *flags,
			       const uint16_t flags_len,
			       const uint16_t params_len,
			       const warts_param_writer_t *handlers,
			       const int handler_cnt);


int warts_read(scamper_file_t *sf, uint8_t **buf, size_t len);
int warts_write(const scamper_file_t *sf, const void *buf, size_t len, void *p);



int warts_hdr_read(scamper_file_t *sf, warts_hdr_t *hdr);
int warts_addr_read(scamper_file_t *sf, const warts_hdr_t *hdr,
			   scamper_addr_t **addr_out);
int warts_list_params(const scamper_list_t *list, uint8_t *flags,
		      uint16_t *flags_len, uint16_t *params_len);
int warts_list_params_read(scamper_list_t *list,
			   uint8_t *buf, uint32_t *off, uint32_t len);
void warts_list_params_write(const scamper_list_t *list,
				    uint8_t *buf, uint32_t *off,
				    const uint32_t len,
				    const uint8_t *flags,
				    const uint16_t flags_len,
				    const uint16_t params_len);
int warts_list_read(scamper_file_t *sf, const warts_hdr_t *hdr,
			   scamper_list_t **list_out);
int warts_list_write(const scamper_file_t *sf, scamper_list_t *list,
			    uint32_t *id);
int warts_list_getid(const scamper_file_t *sf, scamper_list_t *list,
			    uint32_t *id);
int warts_cycle_params(const scamper_cycle_t *cycle, uint8_t *flags,
		       uint16_t *flags_len, uint16_t *params_len);
void warts_cycle_params_write(const scamper_cycle_t *cycle,
				     uint8_t *buf, uint32_t *off,
				     const uint32_t len,
				     const uint8_t *flags,
				     const uint16_t flags_len,
				     const uint16_t params_len);
int warts_cycle_params_read(scamper_cycle_t *cycle,
				   uint8_t *buf, uint32_t *off, uint32_t len);
int warts_cycle_read(scamper_file_t *sf, const warts_hdr_t *hdr,
			    scamper_cycle_t **cycle_out);
int warts_cycle_write(const scamper_file_t *sf, scamper_cycle_t *cycle,
			     const int type, uint32_t *id);
int warts_cycle_stop_read(scamper_file_t *sf, const warts_hdr_t *hdr,
				 scamper_cycle_t **cycle_out);
int warts_cycle_getid(const scamper_file_t *sf, scamper_cycle_t *cycle,
			     uint32_t *id);
int warts_cycle_stop_write(const scamper_file_t *sf,
				  scamper_cycle_t *cycle);
int warts_icmpext_read(const uint8_t *buf, uint32_t *off, uint32_t len,
			      scamper_icmpext_t **exts);
void warts_icmpext_write(uint8_t *buf,uint32_t *off,const uint32_t len,
				const scamper_icmpext_t *exts);

int scamper_file_warts_read(scamper_file_t *sf,
			    const scamper_file_filter_t *filter,
			    uint16_t *type, void **data);

int scamper_file_warts_cyclestart_write(const scamper_file_t *sf,
					scamper_cycle_t *c);
int scamper_file_warts_cyclestop_write(const scamper_file_t *sf,
				       scamper_cycle_t *c);

int scamper_file_warts_init_append(scamper_file_t *file);
int scamper_file_warts_init_read(scamper_file_t *file);
int scamper_file_warts_init_write(scamper_file_t *file);

void scamper_file_warts_free_state(scamper_file_t *file);

#endif /* __SCAMPER_FILE_WARTS_H */
