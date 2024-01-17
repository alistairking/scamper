/*
 * scamper_list.h
 *
 * $Id: scamper_list_int.h,v 1.2 2023/07/29 08:14:31 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2008 The University of Waikato
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

#ifndef __SCAMPER_LIST_INT_H
#define __SCAMPER_LIST_INT_H

/*
 * scamper_list:
 *
 * details regarding a list that was fed into scamper for probing.
 *
 * id:       some ID assigned to identify the list by a person
 * name:     the name assigned to the list
 * monitor:  the (optional) canonical name of the monitor
 * descr:    optional free-form text describing the list somehow.
 * refcnt:   a count of references to an instance of this struct
 */
struct scamper_list
{
  uint32_t  id;
  char     *name;
  char     *descr;
  char     *monitor;
  int       refcnt;
};

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
 * refcnt:     a count of references to an instance of this struct
 */
struct scamper_cycle
{
  scamper_list_t *list;
  uint32_t        id;
  uint32_t        start_time;
  uint32_t        stop_time;
  char           *hostname;
  int             refcnt;
};

scamper_list_t *scamper_list_alloc(const uint32_t id, const char *name,
				   const char *descr, const char *monitor);
scamper_cycle_t *scamper_cycle_alloc(scamper_list_t *list);

#endif /* __SCAMPER_LIST_INT_H */
