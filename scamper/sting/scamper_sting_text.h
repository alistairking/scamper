/*
 * scamper_sting_text.h
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Copyright (C) 2022      Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_sting_text.h,v 1.2 2022/02/13 08:48:15 mjl Exp $
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
#ifndef __SCAMPER_STING_TEXT_H
#define __SCAMPER_STING_TEXT_H

int scamper_file_text_sting_write(const scamper_file_t *sf,
				  const scamper_sting_t *sting, void *p);

#endif /* __SCAMPER_STING_TEXT_H */
