/*
 * scamper_file_text_tbit.h
 *
 * Copyright (C) 2009-2010 Ben Stasiewicz
 * Copyright (C) 2010 University of Waikato
 * Copyright (C) 2022 Matthew Luckie
 *
 * $Id: scamper_tbit_text.h,v 1.3 2024/09/23 10:34:27 mjl Exp $
 *
 * This file implements algorithms described in the tbit-1.0 source code,
 * as well as the papers:
 *
 *  "On Inferring TCP Behaviour"
 *      by Jitendra Padhye and Sally Floyd
 *  "Measuring the Evolution of Transport Protocols in the Internet" by
 *      by Alberto Medina, Mark Allman, and Sally Floyd.
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

#ifndef __SCAMPER_FILE_TEXT_TBIT_H
#define __SCAMPER_FILE_TEXT_TBIT_H

int scamper_file_text_tbit_write(const scamper_file_t *sf,
				 const scamper_tbit_t *tbit, void *p);

#endif
