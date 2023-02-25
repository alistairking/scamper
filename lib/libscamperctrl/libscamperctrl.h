/*
 * libscamperctrl
 *
 * $Id: libscamperctrl.h,v 1.9 2023/01/10 07:42:18 mjl Exp $
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

typedef struct scamper_ctrl scamper_ctrl_t;
typedef struct scamper_inst scamper_inst_t;
typedef struct scamper_task scamper_task_t;

#define SCAMPER_CTRL_TYPE_DATA  1
#define SCAMPER_CTRL_TYPE_MORE  2
#define SCAMPER_CTRL_TYPE_ERR   3
#define SCAMPER_CTRL_TYPE_EOF   4
#define SCAMPER_CTRL_TYPE_FATAL 5

typedef void (*scamper_ctrl_cb_t)(scamper_inst_t *inst, uint8_t type,
				  scamper_task_t *task,
				  const void *data, size_t len);
const char *scamper_ctrl_type_tostr(uint8_t type);

#ifdef DMALLOC
scamper_ctrl_t *scamper_ctrl_alloc_dm(scamper_ctrl_cb_t cb,
				      const char *file, const int line);
#define scamper_ctrl_alloc(cb) scamper_ctrl_alloc_dm((cb), __FILE__, __LINE__)
#else
scamper_ctrl_t *scamper_ctrl_alloc(scamper_ctrl_cb_t cb);
#endif

int scamper_ctrl_wait(scamper_ctrl_t *ctrl, struct timeval *to);
void scamper_ctrl_free(scamper_ctrl_t *ctrl);
int scamper_ctrl_isdone(scamper_ctrl_t *ctrl);

const char *scamper_ctrl_strerror(const scamper_ctrl_t *ctrl);

scamper_inst_t *scamper_inst_unix(scamper_ctrl_t *ctrl, const char *path);
scamper_inst_t *scamper_inst_inet(scamper_ctrl_t *ctrl,
				  const char *addr, uint16_t port);
scamper_inst_t *scamper_inst_remote(scamper_ctrl_t *ctrl, const char *path);
void scamper_inst_free(scamper_inst_t *inst);
scamper_task_t *scamper_inst_do(scamper_inst_t *inst, const char *cmd);
int scamper_inst_halt(scamper_inst_t *inst, scamper_task_t *task);
int scamper_inst_done(scamper_inst_t *inst);

void *scamper_inst_getparam(const scamper_inst_t *inst);
void scamper_inst_setparam(scamper_inst_t *inst, void *param);

void scamper_task_free(scamper_task_t *task);
void scamper_task_use(scamper_task_t *task);
