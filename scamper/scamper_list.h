/*
 * scamper_list.h
 *
 * $Id: scamper_list.h,v 1.12 2023/08/08 06:19:31 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2008 The University of Waikato
 * Copyright (C) 2023      Matthew Luckie
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

#ifndef __SCAMPER_LIST_H
#define __SCAMPER_LIST_H

/*
 * scamper_list:
 *
 * details regarding a list that was fed into scamper for probing.
 *
 * id:       some ID assigned to identify the list by a person
 * name:     the name assigned to the list
 * monitor:  the (optional) canonical name of the monitor
 * descr:    optional free-form text describing the list somehow.
 */
typedef struct scamper_list scamper_list_t;
uint32_t scamper_list_id_get(const scamper_list_t *list);
const char *scamper_list_name_get(const scamper_list_t *list);
const char *scamper_list_descr_get(const scamper_list_t *list);
const char *scamper_list_monitor_get(const scamper_list_t *list);

/*
 * scamper_cycle:
 *
 * details of the cycle that scamper is currently making over the list.
 *
 * list:       the list id of the cycle.
 * id:         the cycle id.
 * start_time: time at which cycle began, seconds since the epoch
 * stop_time:  time at which cycle ended, seconds since the epoch
 * hostname:   optional record of the hostname at the beginning of the cycle.
 */
typedef struct scamper_cycle scamper_cycle_t;
scamper_list_t *scamper_cycle_list_get(const scamper_cycle_t *cycle);
uint32_t scamper_cycle_id_get(const scamper_cycle_t *cycle);
time_t scamper_cycle_start_time_get(const scamper_cycle_t *cycle);
time_t scamper_cycle_stop_time_get(const scamper_cycle_t *cycle);
const char *scamper_cycle_hostname_get(const scamper_cycle_t *cycle);

/*
 * scamper_[list|cycle]_[use|free]
 *
 * in order to prevent list and cycle objects from being copied many times
 * for use by data objects, we use a reference counter in each structure
 * so that it is allocated just the once.
 */
scamper_list_t *scamper_list_use(scamper_list_t *list);
void scamper_list_free(scamper_list_t *list);
int scamper_list_cmp(const scamper_list_t *a, const scamper_list_t *b);

scamper_cycle_t *scamper_cycle_use(scamper_cycle_t *cycle);
void scamper_cycle_free(scamper_cycle_t *cycle);
int scamper_cycle_cmp(const scamper_cycle_t *a, const scamper_cycle_t *b);

#endif /* __SCAMPER_LIST_H */
