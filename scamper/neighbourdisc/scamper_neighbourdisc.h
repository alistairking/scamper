/*
 * scamper_neighbourdisc
 *
 * $Id: scamper_neighbourdisc.h,v 1.6 2023/05/16 06:54:59 mjl Exp $
 *
 * Copyright (C) 2009-2023 Matthew Luckie
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

#ifndef __SCAMPER_NEIGHBOURDISC_H
#define __SCAMPER_NEIGHBOURDISC_H

#define SCAMPER_NEIGHBOURDISC_METHOD_ARP     0x01
#define SCAMPER_NEIGHBOURDISC_METHOD_ND_NSOL 0x02

#define SCAMPER_NEIGHBOURDISC_FLAG_ALLATTEMPTS   0x01
#define SCAMPER_NEIGHBOURDISC_FLAG_FIRSTRESPONSE 0x02

typedef struct scamper_neighbourdisc scamper_neighbourdisc_t;
typedef struct scamper_neighbourdisc_probe scamper_neighbourdisc_probe_t;
typedef struct scamper_neighbourdisc_reply scamper_neighbourdisc_reply_t;

scamper_list_t *scamper_neighbourdisc_list_get(const scamper_neighbourdisc_t *nd);
scamper_cycle_t *scamper_neighbourdisc_cycle_get(const scamper_neighbourdisc_t *nd);
uint32_t scamper_neighbourdisc_userid_get(const scamper_neighbourdisc_t *nd);
const struct timeval *scamper_neighbourdisc_start_get(const scamper_neighbourdisc_t *nd);
const char *scamper_neighbourdisc_ifname_get(const scamper_neighbourdisc_t *nd);
uint8_t scamper_neighbourdisc_method_get(const scamper_neighbourdisc_t *nd);
uint8_t scamper_neighbourdisc_flags_get(const scamper_neighbourdisc_t *nd);
uint16_t scamper_neighbourdisc_wait_get(const scamper_neighbourdisc_t *nd);
uint16_t scamper_neighbourdisc_attempts_get(const scamper_neighbourdisc_t *nd);
uint16_t scamper_neighbourdisc_replyc_get(const scamper_neighbourdisc_t *nd);
scamper_addr_t *scamper_neighbourdisc_src_ip_get(const scamper_neighbourdisc_t *nd);
scamper_addr_t *scamper_neighbourdisc_src_mac_get(const scamper_neighbourdisc_t *nd);
scamper_addr_t *scamper_neighbourdisc_dst_ip_get(const scamper_neighbourdisc_t *nd);
scamper_addr_t *scamper_neighbourdisc_dst_mac_get(const scamper_neighbourdisc_t *nd);
const scamper_neighbourdisc_probe_t *scamper_neighbourdisc_probe_get(const scamper_neighbourdisc_t *nd, uint16_t i);
uint16_t scamper_neighbourdisc_probec_get(const scamper_neighbourdisc_t *nd);

const struct timeval *scamper_neighbourdisc_probe_tx_get(const scamper_neighbourdisc_probe_t *p);
const scamper_neighbourdisc_reply_t *scamper_neighbourdisc_probe_reply_get(const scamper_neighbourdisc_probe_t *p, uint16_t i);
uint16_t scamper_neighbourdisc_probe_replyc_get(const scamper_neighbourdisc_probe_t *p);

const struct timeval *scamper_neighbourdisc_reply_rx_get(const scamper_neighbourdisc_reply_t *r);
scamper_addr_t *scamper_neighbourdisc_reply_mac_get(const scamper_neighbourdisc_reply_t *r);

scamper_neighbourdisc_t *scamper_neighbourdisc_alloc(void);
void scamper_neighbourdisc_free(scamper_neighbourdisc_t *);

scamper_neighbourdisc_probe_t *scamper_neighbourdisc_probe_alloc(void);
void scamper_neighbourdisc_probe_free(scamper_neighbourdisc_probe_t *);
int scamper_neighbourdisc_probe_add(scamper_neighbourdisc_t *,
				    scamper_neighbourdisc_probe_t *);
int scamper_neighbourdisc_probes_alloc(scamper_neighbourdisc_t *, uint16_t);

int scamper_neighbourdisc_ifname_set(scamper_neighbourdisc_t *, char *);

scamper_neighbourdisc_reply_t *scamper_neighbourdisc_reply_alloc(void);
void scamper_neighbourdisc_reply_free(scamper_neighbourdisc_reply_t *);
int scamper_neighbourdisc_reply_add(scamper_neighbourdisc_probe_t *,
				    scamper_neighbourdisc_reply_t *);
int scamper_neighbourdisc_replies_alloc(scamper_neighbourdisc_probe_t *,
					uint16_t);

#endif /* __SCAMPER_NEIGHBOURDISC_H */
