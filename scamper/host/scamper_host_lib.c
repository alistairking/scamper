/*
 * scamper_host_lib.c
 *
 * $Id: scamper_host_lib.c,v 1.13 2025/02/23 05:38:15 mjl Exp $
 *
 * Copyright (C) 2023-2025 Matthew Luckie
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

const char *scamper_host_ecs_get(const scamper_host_t *host)
{
  return host->ecs;
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

scamper_host_rr_t *scamper_host_query_ar_opt_get(const scamper_host_query_t *q)
{
  uint16_t i;
  for(i=0; i<q->arcount; i++)
    if(q->ar[i] != NULL && q->ar[i]->type == SCAMPER_HOST_TYPE_OPT)
      return q->ar[i];
  return NULL;
}

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

scamper_host_rr_opt_t *scamper_host_rr_opt_get(const scamper_host_rr_t *rr)
{
  if(scamper_host_rr_data_type(rr->class, rr->type) !=
     SCAMPER_HOST_RR_DATA_TYPE_OPT)
    return NULL;
  return rr->un.opt;
}

scamper_host_rr_svcb_t *scamper_host_rr_svcb_get(const scamper_host_rr_t *rr)
{
  if(scamper_host_rr_data_type(rr->class, rr->type) !=
     SCAMPER_HOST_RR_DATA_TYPE_SVCB)
    return NULL;
  return rr->un.svcb;
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

#ifdef BUILDING_LIBSCAMPERFILE
scamper_host_rr_opt_t *scamper_host_rr_opt_use(scamper_host_rr_opt_t *opt)
{
  opt->refcnt++;
  return opt;
}
#endif

uint16_t scamper_host_rr_opt_elemc_get(const scamper_host_rr_opt_t *opt)
{
  return opt->elemc;
}

scamper_host_rr_opt_elem_t *scamper_host_rr_opt_elem_get(const scamper_host_rr_opt_t *opt,
							 uint16_t i)
{
  if(opt != NULL && opt->elems != NULL && i < opt->elemc)
    return opt->elems[i];
  return NULL;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_host_rr_opt_elem_t *scamper_host_rr_opt_elem_use(scamper_host_rr_opt_elem_t *elem)
{
  elem->refcnt++;
  return elem;
}
#endif

uint16_t scamper_host_rr_opt_elem_code_get(const scamper_host_rr_opt_elem_t *elem)
{
  return elem->code;
}

/*
 * scamper_host_rr_opt_elem_code_tostr
 *
 * convert 16-bit OPT code to name.
 *
 * https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
 */
char *scamper_host_rr_opt_elem_code_tostr(uint16_t code, char *b, size_t l)
{
  switch(code)
    {
    case 1:  snprintf(b, l, "LLQ"); break;
    case 3:  snprintf(b, l, "NSID"); break;
    case 5:  snprintf(b, l, "DAU"); break;
    case 6:  snprintf(b, l, "DHU"); break;
    case 7:  snprintf(b, l, "N3U"); break;
    case 8:  snprintf(b, l, "edns-client-subnet"); break;
    case 9:  snprintf(b, l, "EDNS-EXPIRE"); break;
    case 10: snprintf(b, l, "COOKIE"); break;
    case 11: snprintf(b, l, "edns-tcp-keepalive"); break;
    case 12: snprintf(b, l, "Padding"); break;
    case 13: snprintf(b, l, "CHAIN"); break;
    case 14: snprintf(b, l, "edns-key-tag"); break;
    case 15: snprintf(b, l, "Extended DNS Error"); break;
    case 16: snprintf(b, l, "EDNS-Client-Tag"); break;
    case 17: snprintf(b, l, "EDNS-Server-Tag"); break;
    case 18: snprintf(b, l, "Report-Channel"); break;
    case 19: snprintf(b, l, "ZONEVERSION"); break;
    default: snprintf(b, l, "%u", code); break;
    }

  return b;
}

uint16_t scamper_host_rr_opt_elem_len_get(const scamper_host_rr_opt_elem_t *elem)
{
  return elem->len;
}

const uint8_t *scamper_host_rr_opt_elem_data_get(const scamper_host_rr_opt_elem_t *elem)
{
  return elem->data;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_host_rr_svcb_t *scamper_host_rr_svcb_use(scamper_host_rr_svcb_t *svcb)
{
  svcb->refcnt++;
  return svcb;
}
#endif

const char *scamper_host_rr_svcb_target_get(const scamper_host_rr_svcb_t *svcb)
{
  return svcb->target;
}

uint16_t scamper_host_rr_svcb_priority_get(const scamper_host_rr_svcb_t *svcb)
{
  return svcb->priority;
}

uint16_t scamper_host_rr_svcb_paramc_get(const scamper_host_rr_svcb_t *svcb)
{
  return svcb->paramc;
}

scamper_host_rr_svcb_param_t *
scamper_host_rr_svcb_param_get(const scamper_host_rr_svcb_t *svcb, uint16_t i)
{
  if(svcb != NULL && svcb->params != NULL && i < svcb->paramc)
    return svcb->params[i];
  return NULL;
}

#ifdef BUILDING_LIBSCAMPERFILE
scamper_host_rr_svcb_param_t *
scamper_host_rr_svcb_param_use(scamper_host_rr_svcb_param_t *param)
{
  param->refcnt++;
  return param;
}
#endif

uint16_t
scamper_host_rr_svcb_param_key_get(const scamper_host_rr_svcb_param_t *param)
{
  return param->key;
}

uint16_t
scamper_host_rr_svcb_param_len_get(const scamper_host_rr_svcb_param_t *param)
{
  return param->len;
}

const uint8_t *
scamper_host_rr_svcb_param_val_get(const scamper_host_rr_svcb_param_t *param)
{
  return param->val;
}

/*
 * scamper_host_rr_svcb_param_key_tostr
 *
 * convert 16-bit SVCB param key to name.
 *
 * https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml
 */
char *scamper_host_rr_svcb_param_key_tostr(uint16_t key, char *b, size_t l)
{
  switch(key)
    {
    case 0:  snprintf(b, l, "mandatory"); break;
    case 1:  snprintf(b, l, "alpn"); break;
    case 2:  snprintf(b, l, "no-default-alpn"); break;
    case 3:  snprintf(b, l, "port"); break;
    case 4:  snprintf(b, l, "ipv4hint"); break;
    case 5:  snprintf(b, l, "ech"); break;
    case 6:  snprintf(b, l, "ipv6hint"); break;
    case 7:  snprintf(b, l, "dohpath"); break;
    case 8:  snprintf(b, l, "ohttp"); break;
    case 9:  snprintf(b, l, "tls-supported-groups"); break;
    default: snprintf(b, l, "%u", key); break;
    }

  return b;
}
