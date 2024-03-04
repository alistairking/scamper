/*
 * scamper_do_dealias.h
 *
 * $Id: scamper_dealias_do.h,v 1.7 2024/02/27 03:34:02 mjl Exp $
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Author: Matthew Luckie
 *
 * This code implements alias resolution techniques published by others
 * which require the network to be probed; the author of each technique
 * is detailed with its data structures.
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

#ifndef __SCAMPER_DO_DEALIAS_H
#define __SCAMPER_DO_DEALIAS_H

scamper_task_t *scamper_do_dealias_alloctask(void *data,
					     scamper_list_t *list,
					     scamper_cycle_t *cycle,
					     char *errbuf, size_t errlen);

void scamper_do_dealias_free(void *data);

uint32_t scamper_do_dealias_userid(void *data);

void scamper_do_dealias_cleanup(void);
int scamper_do_dealias_init(void);

#endif /* __SCAMPER_DO_DEALIAS_H */
