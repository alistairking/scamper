/*
 * scamper_config.h
 *
 * $Id: scamper_config.h,v 1.1 2025/04/27 00:49:24 mjl Exp $
 *
 * Copyright (C) 2025 Matthew Luckie
 *
 * Authors: Matthew Luckie
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

#ifndef __SCAMPER_CONFIG_H
#define __SCAMPER_CONFIG_H

typedef struct scamper_config
{
  uint8_t   dealias_enable;
  uint8_t   host_enable;
  uint8_t   http_enable;
  uint8_t   neighbourdisc_enable;
  uint8_t   ping_enable;
  uint8_t   sniff_enable;
  uint8_t   sting_enable;
  uint8_t   tbit_enable;
  uint8_t   trace_enable;
  uint8_t   tracelb_enable;
  uint8_t   udpprobe_enable;
} scamper_config_t;

int scamper_config_read(const char *filename);
void scamper_config_cleanup(void);
int scamper_config_init(const char *filename);

#endif /* __SCAMPER_CONFIG_H */
