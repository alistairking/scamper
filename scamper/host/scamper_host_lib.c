/*
 * scamper_host_lib.c
 *
 * $Id: scamper_host_lib.c,v 1.9 2024/04/20 00:15:02 mjl Exp $
 *
 * Copyright (C) 2023-2024 Matthew Luckie
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_host.h"
#include "scamper_host_int.h"

scamper_list_t *scamper_host_list_get(const scamper_host_t *host)
{
  return host->list;
}

scamper_cycle_t *scamper_host_cycle_get(const scamper_host_t *host)
{
  return host->cycle;
}

scamper_addr_t *scamper_host_src_get(const scamper_host_t *host)
{
  return host->src;
}

scamper_addr_t *scamper_host_dst_get(const scamper_host_t *host)
{
  return host->dst;
}

uint32_t scamper_host_userid_get(const scamper_host_t *host)
{
  return host->userid;
}

const struct timeval *scamper_host_start_get(const scamper_host_t *host)
{
  return &host->start;
}

uint16_t scamper_host_flags_get(const scamper_host_t *host)
{
  return host->flags;
}

const struct timeval *scamper_host_wait_timeout_get(const scamper_host_t *host)
{
  return &host->wait_timeout;
}

uint8_t scamper_host_stop_get(const scamper_host_t *host)
{
  return host->stop;
}

uint8_t scamper_host_retries_get(const scamper_host_t *host)
{
  return host->retries;
}

uint16_t scamper_host_qtype_get(const scamper_host_t *host)
{
  return host->qtype;
}

uint16_t scamper_host_qclass_get(const scamper_host_t *host)
{
  return host->qclass;
}

const char *scamper_host_qname_get(const scamper_host_t *host)
{
  return host->qname;
}

uint8_t scamper_host_qcount_get(const scamper_host_t *host)
{
  return host->qcount;
}

scamper_host_query_t *scamper_host_query_get(const scamper_host_t *host, uint8_t i)
{
  if(host->qcount <= i)
    return NULL;
  return host->queries[i];
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_host_query_t *scamper_host_query_use(scamper_host_query_t *q)
{
  q->refcnt++;
  return q;
}
#endif

const struct timeval *scamper_host_query_tx_get(const scamper_host_query_t *q)
{
  return &q->tx;
}

const struct timeval *scamper_host_query_rx_get(const scamper_host_query_t *q)
{
  return &q->rx;
}

uint8_t scamper_host_query_rcode_get(const scamper_host_query_t *q)
{
  return q->rcode;
}

uint8_t scamper_host_query_flags_get(const scamper_host_query_t *q)
{
  return q->flags;
}

uint16_t scamper_host_query_id_get(const scamper_host_query_t *q)
{
  return q->id;
}

uint16_t scamper_host_query_ancount_get(const scamper_host_query_t *q)
{
  return q->ancount;
}

uint16_t scamper_host_query_nscount_get(const scamper_host_query_t *q)
{
  return q->nscount;
}

uint16_t scamper_host_query_arcount_get(const scamper_host_query_t *q)
{
  return q->arcount;
}

scamper_host_rr_t *scamper_host_query_an_get(const scamper_host_query_t *q, uint16_t i)
{
  if(q->ancount <= i)
    return NULL;
  return q->an[i];
}

scamper_host_rr_t *scamper_host_query_ns_get(const scamper_host_query_t *q, uint16_t i)
{
  if(q->nscount <= i)
    return NULL;
  return q->ns[i];
}

scamper_host_rr_t *scamper_host_query_ar_get(const scamper_host_query_t *q, uint16_t i)
{
  if(q->arcount <= i)
    return NULL;
  return q->ar[i];
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_host_rr_t *scamper_host_rr_use(scamper_host_rr_t *rr)
{
  rr->refcnt++;
  return rr;
}
#endif

uint16_t scamper_host_rr_class_get(const scamper_host_rr_t *rr)
{
  return rr->class;
}

uint16_t scamper_host_rr_type_get(const scamper_host_rr_t *rr)
{
  return rr->type;
}

const char *scamper_host_rr_name_get(const scamper_host_rr_t *rr)
{
  return rr->name;
}

uint32_t scamper_host_rr_ttl_get(const scamper_host_rr_t *rr)
{
  return rr->ttl;
}

const void *scamper_host_rr_v_get(const scamper_host_rr_t *rr)
{
  return rr->un.v;
}

scamper_addr_t *scamper_host_rr_addr_get(const scamper_host_rr_t *rr)
{
  if(scamper_host_rr_data_type(rr->class, rr->type) !=
     SCAMPER_HOST_RR_DATA_TYPE_ADDR)
    return NULL;
  return rr->un.addr;
}

const char *scamper_host_rr_str_get(const scamper_host_rr_t *rr)
{
  if(scamper_host_rr_data_type(rr->class, rr->type) !=
     SCAMPER_HOST_RR_DATA_TYPE_STR)
    return NULL;
  return rr->un.str;
}

scamper_host_rr_soa_t *scamper_host_rr_soa_get(const scamper_host_rr_t *rr)
{
  if(scamper_host_rr_data_type(rr->class, rr->type) !=
     SCAMPER_HOST_RR_DATA_TYPE_SOA)
    return NULL;
  return rr->un.soa;
}

scamper_host_rr_mx_t *scamper_host_rr_mx_get(const scamper_host_rr_t *rr)
{
  if(scamper_host_rr_data_type(rr->class, rr->type) !=
     SCAMPER_HOST_RR_DATA_TYPE_MX)
    return NULL;
  return rr->un.mx;
}

scamper_host_rr_txt_t *scamper_host_rr_txt_get(const scamper_host_rr_t *rr)
{
  if(scamper_host_rr_data_type(rr->class, rr->type) !=
     SCAMPER_HOST_RR_DATA_TYPE_TXT)
    return NULL;
  return rr->un.txt;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_host_rr_mx_t *scamper_host_rr_mx_use(scamper_host_rr_mx_t *mx)
{
  mx->refcnt++;
  return mx;
}
#endif

uint16_t scamper_host_rr_mx_preference_get(const scamper_host_rr_mx_t *mx)
{
  return mx->preference;
}

const char *scamper_host_rr_mx_exchange_get(const scamper_host_rr_mx_t *mx)
{
  return mx->exchange;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_host_rr_soa_t *scamper_host_rr_soa_use(scamper_host_rr_soa_t *soa)
{
  soa->refcnt++;
  return soa;
}
#endif

const char *scamper_host_rr_soa_mname_get(const scamper_host_rr_soa_t *soa)
{
  return soa->mname;
}

const char *scamper_host_rr_soa_rname_get(const scamper_host_rr_soa_t *soa)
{
  return soa->rname;
}

uint32_t scamper_host_rr_soa_serial_get(const scamper_host_rr_soa_t *soa)
{
  return soa->serial;
}

uint32_t scamper_host_rr_soa_refresh_get(const scamper_host_rr_soa_t *soa)
{
  return soa->refresh;
}

uint32_t scamper_host_rr_soa_retry_get(const scamper_host_rr_soa_t *soa)
{
  return soa->retry;
}

uint32_t scamper_host_rr_soa_expire_get(const scamper_host_rr_soa_t *soa)
{
  return soa->expire;
}

uint32_t scamper_host_rr_soa_minimum_get(const scamper_host_rr_soa_t *soa)
{
  return soa->minimum;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_host_rr_txt_t *scamper_host_rr_txt_use(scamper_host_rr_txt_t *txt)
{
  txt->refcnt++;
  return txt;
}
#endif

uint16_t scamper_host_rr_txt_strc_get(const scamper_host_rr_txt_t *txt)
{
  return txt->strc;
}

const char *scamper_host_rr_txt_str_get(const scamper_host_rr_txt_t *txt, uint16_t i)
{
  if(txt != NULL && txt->strs != NULL && i < txt->strc)
    return txt->strs[i];
  return NULL;
}
