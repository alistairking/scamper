/*
 * scamper_source
 *
 * $Id: scamper_sources.h,v 1.23 2025/05/28 07:10:37 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2022      Matthew Luckie
 * Copyright (C) 2023      The Regents of the University of California
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

#ifndef __SCAMPER_SOURCE_H
#define __SCAMPER_SOURCE_H

typedef struct scamper_source scamper_source_t;

#define SCAMPER_SOURCE_TYPE_FILE    1
#define SCAMPER_SOURCE_TYPE_CMDLINE 2
#define SCAMPER_SOURCE_TYPE_CONTROL 3

#define SCAMPER_SOURCE_TYPE_MIN     1
#define SCAMPER_SOURCE_TYPE_MAX     3

/* a mapping between a task and the source that delivered it */
typedef struct scamper_sourcetask scamper_sourcetask_t;

typedef struct scamper_source_params
{
  /*
   *  name:     the name of the list being probed.
   *  descr:    a description of the addresses that are stored in this source
   *  monitor:  the name of the monitor.
   *  list_id:  the list id number assigned by a human.
   *  cycle_id: the initial cycle id to use.
   *  type:     type of the source (file, cmdline, control socket, ...)
   *  priority: the mix priority of this source compared to other sources.
   *  sof:      the output file to direct results to.
   */
  char              *name;
  char              *descr;
  char              *monitor;
  uint32_t           list_id;
  uint32_t           cycle_id;
  int                type;
  uint32_t           priority;
  scamper_outfile_t *sof;

  /*
   * these parameters are set by the scamper_source_*_alloc function
   */
  void              *data;
  int              (*take)(void *data);
  void             (*freedata)(void *data);
  int              (*isfinished)(void *data);
  char *           (*tostr)(void *data, char *str, size_t len);

} scamper_source_params_t;

/* functions for allocating, referencing, and dereferencing scamper sources */
scamper_source_t *scamper_source_alloc(const scamper_source_params_t *ssp);
scamper_source_t *scamper_source_use(scamper_source_t *source);
void scamper_source_free(scamper_source_t *source);
void scamper_source_abandon(scamper_source_t *source);

/* take a finished source and put it in a special place */
void scamper_source_finished(scamper_source_t *source);

/* functions for getting various source properties */
const char *scamper_source_getname(const scamper_source_t *source);
const char *scamper_source_getdescr(const scamper_source_t *source);
const char *scamper_source_getoutfile(const scamper_source_t *source);
uint32_t scamper_source_getlistid(const scamper_source_t *source);
uint32_t scamper_source_getcycleid(const scamper_source_t *source);
int scamper_source_gettype(const scamper_source_t *source);
uint32_t scamper_source_getpriority(const scamper_source_t *source);
void scamper_source_setpriority(scamper_source_t *source, uint32_t priority);

/* functions for getting string representations */
const char *scamper_source_type_tostr(const scamper_source_t *source);
char *scamper_source_tostr(const scamper_source_t *source, char *b, size_t l);

/* functions for dealing with source-type specific data */
void *scamper_source_getdata(const scamper_source_t *source);
void scamper_source_setdata(scamper_source_t *source, void *data);

/* functions for getting the number of commands/cycles currently buffered */
int scamper_source_getcommandcount(const scamper_source_t *source);
int scamper_source_getcyclecount(const scamper_source_t *source);
int scamper_source_gettaskcount(const scamper_source_t *source);

/* determine if the source has finished yet */
int scamper_source_isfinished(scamper_source_t *source);

/* functions for adding stuff to the source's command queue */
int scamper_source_command(scamper_source_t *source, const char *command);
int scamper_source_command2(scamper_source_t *source, const char *command,
			    uint32_t *id, char *errbuf, size_t errlen);
int scamper_source_halttask(scamper_source_t *source, uint32_t id);

/* function for adding a snapshot of a current task to source */
int scamper_source_add_dup(scamper_source_t *source,
			   scamper_task_t *task, uint32_t id);

/* function for advising source that an active task has completed */
void scamper_sourcetask_free(scamper_sourcetask_t *st);
scamper_source_t *scamper_sourcetask_getsource(scamper_sourcetask_t *st);
uint32_t scamper_sourcetask_getid(const scamper_sourcetask_t *st);

void scamper_source_task_unhold(struct scamper_task *task);

/* functions for managing a collection of sources */
int scamper_sources_add(scamper_source_t *source);
int scamper_sources_gettask(struct scamper_task **task);
scamper_source_t *scamper_sources_get(char *name);
int scamper_sources_isready(void);
int scamper_sources_isempty(void);
void scamper_sources_foreach(void *p, int (*func)(void *, scamper_source_t *));
void scamper_sources_empty(void);
int scamper_sources_init(void);
void scamper_sources_cleanup(void);

#endif /* __SCAMPER_SOURCE_H */
