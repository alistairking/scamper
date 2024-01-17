/*
 * libscamperctrl
 *
 * $Id: libscamperctrl.h,v 1.20 2023/08/08 06:19:31 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2021-2023 Matthew Luckie. All rights reserved.
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

#ifndef __LIBSCAMPERCTRL_H
#define __LIBSCAMPERCTRL_H

typedef struct scamper_ctrl scamper_ctrl_t;
typedef struct scamper_inst scamper_inst_t;
typedef struct scamper_task scamper_task_t;
typedef struct scamper_attp scamper_attp_t;

#define SCAMPER_CTRL_TYPE_DATA  1
#define SCAMPER_CTRL_TYPE_MORE  2
#define SCAMPER_CTRL_TYPE_ERR   3
#define SCAMPER_CTRL_TYPE_EOF   4
#define SCAMPER_CTRL_TYPE_FATAL 5

#define SCAMPER_INST_TYPE_UNIX   1
#define SCAMPER_INST_TYPE_INET   2
#define SCAMPER_INST_TYPE_REMOTE 3

typedef void (*scamper_ctrl_cb_t)(scamper_inst_t *inst, uint8_t type,
				  scamper_task_t *task,
				  const void *data, size_t len);
const char *scamper_ctrl_type_tostr(uint8_t type);

scamper_ctrl_t *scamper_ctrl_alloc(scamper_ctrl_cb_t cb);

#ifdef DMALLOC
scamper_ctrl_t *scamper_ctrl_alloc_dm(scamper_ctrl_cb_t cb,
				      const char *file, const int line);
#define scamper_ctrl_alloc(cb) scamper_ctrl_alloc_dm((cb), __FILE__, __LINE__)
#endif

int scamper_ctrl_wait(scamper_ctrl_t *ctrl, struct timeval *to);
void scamper_ctrl_free(scamper_ctrl_t *ctrl);
int scamper_ctrl_isdone(scamper_ctrl_t *ctrl);

void *scamper_ctrl_getparam(const scamper_ctrl_t *ctrl);
void scamper_ctrl_setparam(scamper_ctrl_t *ctrl, void *param);

const char *scamper_ctrl_strerror(const scamper_ctrl_t *ctrl);

scamper_inst_t *scamper_inst_unix(scamper_ctrl_t *ctrl,
				  const scamper_attp_t *attp,
				  const char *path);
scamper_inst_t *scamper_inst_inet(scamper_ctrl_t *ctrl,
				  const scamper_attp_t *attp,
				  const char *addr, uint16_t port);
scamper_inst_t *scamper_inst_remote(scamper_ctrl_t *ctrl, const char *path);
void scamper_inst_free(scamper_inst_t *inst);
scamper_task_t *scamper_inst_do(scamper_inst_t *inst, const char *cmd, void *p);
int scamper_inst_halt(scamper_inst_t *inst, scamper_task_t *task);
int scamper_inst_done(scamper_inst_t *inst);

void *scamper_inst_getparam(const scamper_inst_t *inst);
void scamper_inst_setparam(scamper_inst_t *inst, void *param);

const char *scamper_inst_getname(const scamper_inst_t *inst);
uint8_t scamper_inst_gettype(const scamper_inst_t *inst);
const char *scamper_inst_strerror(const scamper_inst_t *inst);

scamper_ctrl_t *scamper_inst_getctrl(const scamper_inst_t *inst);

void *scamper_task_getparam(scamper_task_t *task);
void scamper_task_setparam(scamper_task_t *task, void *p);
char *scamper_task_getcmd(scamper_task_t *task, char *buf, size_t len);
void scamper_task_free(scamper_task_t *task);
void scamper_task_use(scamper_task_t *task);

scamper_attp_t *scamper_attp_alloc(void);

#ifdef DMALLOC
scamper_attp_t *scamper_attp_alloc_dm(const char *file, const int line);
#define scamper_attp_alloc() scamper_attp_alloc_dm(__FILE__, __LINE__)
#endif

void scamper_attp_set_listid(scamper_attp_t *attp, uint32_t list_id);
int scamper_attp_set_listname(scamper_attp_t *attp, char *list_name);
int scamper_attp_set_listdescr(scamper_attp_t *attp, char *list_descr);
int scamper_attp_set_listmonitor(scamper_attp_t *attp, char *list_monitor);
void scamper_attp_set_cycleid(scamper_attp_t *attp, uint32_t cycle_id);
void scamper_attp_set_priority(scamper_attp_t *attp, uint32_t priority);
void scamper_attp_free(scamper_attp_t *attp);

#endif /* __LIBSCAMPERCTRL_H */
