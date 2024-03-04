/*
 * scamper_sniff_do.h
 *
 * $Id: scamper_sniff_do.h,v 1.4 2024/02/27 03:34:02 mjl Exp $
 *
 * Copyright (C) 2011 University of Waikato
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

#ifndef __SCAMPER_DO_SNIFF_H
#define __SCAMPER_DO_SNIFF_H

void scamper_do_sniff_free(void *data);

scamper_task_t *scamper_do_sniff_alloctask(void *data,
					   scamper_list_t *list,
					   scamper_cycle_t *cycle,
					   char *errbuf, size_t errlen);

uint32_t scamper_do_sniff_userid(void *data);

void scamper_do_sniff_cleanup(void);
int scamper_do_sniff_init(void);

#endif /*__SCAMPER_DO_SNIFF_H */
