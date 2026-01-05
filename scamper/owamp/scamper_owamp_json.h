/*
 * scamper_owamp_json.h
 *
 * $Id: scamper_owamp_json.h,v 1.1 2025/12/04 08:11:00 mjl Exp $
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

#ifndef __SCAMPER_OWAMP_JSON_H
#define __SCAMPER_OWAMP_JSON_H

int scamper_file_json_owamp_write(const scamper_file_t *sf,
				  const scamper_owamp_t *owamp, void *p);

#endif /* __SCAMPER_OWAMP_JSON_H */
