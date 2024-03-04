/*
 * scamper_do_host.h
 *
 * $Id: scamper_host_do.h,v 1.7 2024/02/27 03:34:02 mjl Exp $
 *
 * Copyright (C) 2018-2020 Matthew Luckie
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

#ifndef __SCAMPER_DO_HOST_H
#define __SCAMPER_DO_HOST_H

typedef struct scamper_host_do scamper_host_do_t;

scamper_task_t *scamper_do_host_alloctask(void *data,
					  scamper_list_t *list,
					  scamper_cycle_t *cycle,
					  char *errbuf, size_t errlen);

void scamper_do_host_free(void *data);

/* code to use the host code to do a PTR record lookup */
typedef void (*scamper_host_do_ptr_cb_t)(void *param, const char *name);
scamper_host_do_t *scamper_do_host_do_ptr(scamper_addr_t *ip, void *param,
					  scamper_host_do_ptr_cb_t cb);

/* code to use the host code to do A record lookup */
typedef void (*scamper_host_do_a_cb_t)(void *param, scamper_addr_t **a, int c);
scamper_host_do_t *scamper_do_host_do_a(const char *name, void *param,
					scamper_host_do_a_cb_t cb);

void scamper_host_do_free(scamper_host_do_t *hostdo);

/* code to get or set the nameserver that scamper should use by default */
const scamper_addr_t *scamper_do_host_getns(void);
int scamper_do_host_setns(const char *nsip);

uint32_t scamper_do_host_userid(void *data);

void scamper_do_host_cleanup(void);
int scamper_do_host_init(void);

#endif /* __SCAMPER_DO_HOST_H */
