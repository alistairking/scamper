/*
 * scamper_udpprobe_int.h
 *
 * $Id: scamper_udpprobe_int.h,v 1.2 2023/11/22 20:43:17 mjl Exp $
 *
 * Copyright (C) 2023 The Regents of the University of California
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

#ifndef __SCAMPER_UDPPROBE_INT_H
#define __SCAMPER_UDPPROBE_INT_H

scamper_udpprobe_t *scamper_udpprobe_alloc(void);
scamper_udpprobe_reply_t *scamper_udpprobe_reply_alloc(void);

#define SCAMPER_UDPPROBE_FLAG_EXITFIRST 0x01 /* return on first reply */

#define SCAMPER_UDPPROBE_FLAG_IS_EXITFIRST(up) ( \
  ((up)->flags & SCAMPER_UDPPROBE_FLAG_EXITFIRST))

#define SCAMPER_UDPPROBE_STOP_NONE     0
#define SCAMPER_UDPPROBE_STOP_DONE     1
#define SCAMPER_UDPPROBE_STOP_HALTED   2
#define SCAMPER_UDPPROBE_STOP_ERROR    3

struct scamper_udpprobe_reply
{
  uint8_t                   *data;
  uint16_t                   len;
  struct timeval             tv;
#ifdef BUILDING_LIBSCAMPERFILE
  int                        refcnt;
#endif
};

struct scamper_udpprobe
{
  scamper_list_t            *list;
  scamper_cycle_t           *cycle;
  uint32_t                   userid;

  scamper_addr_t            *src;
  scamper_addr_t            *dst;
  uint16_t                   sport;
  uint16_t                   dport;
  struct timeval             start;
  struct timeval             wait_timeout;

  uint8_t                    flags;
  uint8_t                    stop;

  uint8_t                   *data;
  uint16_t                   len;

  scamper_udpprobe_reply_t **replies;
  uint8_t                    replyc;
};

#endif /* __SCAMPER_UDPPROBE_INT_H */
