/*
 * scamper.h
 *
 * $Id: scamper.h,v 1.74.2.1 2024/05/02 21:46:06 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2015-2023 Matthew Luckie
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

#ifndef __SCAMPER_H
#define __SCAMPER_H

#define SCAMPER_OPTION_PPS_MIN       1
#define SCAMPER_OPTION_PPS_DEF       20
#define SCAMPER_OPTION_PPS_MAX       10000
int scamper_option_pps_get(void);
int scamper_option_pps_set(const int pps);

#define SCAMPER_OPTION_WINDOW_MIN    0
#define SCAMPER_OPTION_WINDOW_DEF    0
#define SCAMPER_OPTION_WINDOW_MAX    65535
int scamper_option_window_get(void);
int scamper_option_window_set(const int window);

#define SCAMPER_OPTION_COMMAND_DEF   "trace"
const char *scamper_option_command_get(void);
int scamper_option_command_set(const char *command);

const char *scamper_option_monitorname_get(void);
int scamper_option_monitorname_set(const char *monitorname);

const char *scamper_option_nameserver_get(void);

#define SCAMPER_OPTION_POLLFUNC_POLL   0
#define SCAMPER_OPTION_POLLFUNC_KQUEUE 1
#define SCAMPER_OPTION_POLLFUNC_EPOLL  2
#define SCAMPER_OPTION_POLLFUNC_SELECT 3
int scamper_option_pollfunc_get(void);

int scamper_option_planetlab(void);
int scamper_option_noinitndc(void);
int scamper_option_notls(void);
int scamper_option_rawtcp(void);
int scamper_option_icmp_rxerr(void);
int scamper_option_debugfileappend(void);
int scamper_option_daemon(void);

int scamper_option_ring(void);
unsigned int scamper_option_ring_blocks(void);
unsigned int scamper_option_ring_block_size(void);
int scamper_option_ring_locked(void);

void scamper_exitwhendone(int on);

#ifdef HAVE_SETEUID
uid_t scamper_getuid(void);
uid_t scamper_geteuid(void);
#endif

int scamper_pidfile(void);

uint16_t scamper_sport_default(void);
uint16_t scamper_pid_u16(void);

#define SCAMPER_VERSION "20240503"

#endif /* __SCAMPER_H */
