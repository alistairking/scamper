/*
 * scamper_udpprobe_cmd.h
 *
 * $Id: scamper_udpprobe_cmd.h,v 1.2 2024/02/12 20:35:36 mjl Exp $
 *
 * Copyright (C) 2023 The Regents of the University of California
 *
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

#ifndef __SCAMPER_UDPPROBE_CMD_H
#define __SCAMPER_UDPPROBE_CMD_H

void *scamper_do_udpprobe_alloc(char *str, char *errbuf, size_t errlen);
const char *scamper_do_udpprobe_usage(void);
int scamper_do_udpprobe_arg_validate(int argc, char *argv[], int *stop,
				     char *errbuf, size_t errlen);

#endif /*__SCAMPER_UDPPROBE_CMD_H */
