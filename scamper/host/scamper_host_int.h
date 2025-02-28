/*
 * scamper_host_int.h
 *
 * $Id: scamper_host_int.h,v 1.11 2025/02/23 05:38:15 mjl Exp $
 *
 * Copyright (C) 2018-2025 Matthew Luckie
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

#ifndef __SCAMPER_HOST_INT_H
#define __SCAMPER_HOST_INT_H

scamper_host_t *scamper_host_alloc(void);
int scamper_host_queries_alloc(scamper_host_t *host, uint8_t n);
scamper_host_query_t *scamper_host_query_alloc(void);
int scamper_host_query_rr_alloc(scamper_host_query_t *q,
				uint16_t an_c, uint16_t ns_c, uint16_t ar_c);
scamper_host_rr_t *scamper_host_rr_alloc(const char *,
					 uint16_t, uint16_t, uint32_t);
scamper_host_rr_mx_t *scamper_host_rr_mx_alloc(uint16_t, const char *);
scamper_host_rr_soa_t *scamper_host_rr_soa_alloc(const char *, const char *);
scamper_host_rr_txt_t *scamper_host_rr_txt_alloc(uint16_t strc);
scamper_host_rr_opt_t *scamper_host_rr_opt_alloc(uint16_t optc);
scamper_host_rr_svcb_t *scamper_host_rr_svcb_alloc(uint16_t prio,
						   const char *target,
						   uint16_t paramc);

scamper_host_rr_opt_elem_t *
scamper_host_rr_opt_elem_alloc(uint16_t code,uint16_t len,const uint8_t *data);

scamper_host_rr_svcb_param_t *
scamper_host_rr_svcb_param_alloc(uint16_t key,uint16_t len,const uint8_t *val);

struct scamper_host_rr_svcb_param
{
  uint16_t                 key;
  uint16_t                 len;
  uint8_t                 *val;

#ifdef BUILDING_LIBSCAMPERFILE
  int                      refcnt;
#endif
};

struct scamper_host_rr_svcb
{
  char                          *target;
  uint16_t                       priority;
  scamper_host_rr_svcb_param_t **params;
  uint16_t                       paramc;

#ifdef BUILDING_LIBSCAMPERFILE
  int                            refcnt;
#endif
};

struct scamper_host_rr_opt_elem
{
  uint16_t                 code;
  uint16_t                 len;
  uint8_t                 *data;

#ifdef BUILDING_LIBSCAMPERFILE
  int                      refcnt;
#endif
};

struct scamper_host_rr_opt
{
  scamper_host_rr_opt_elem_t **elems;
  uint16_t                     elemc;

#ifdef BUILDING_LIBSCAMPERFILE
  int                          refcnt;
#endif
};

struct scamper_host_rr_mx
{
  uint16_t                 preference;
  char                    *exchange;

#ifdef BUILDING_LIBSCAMPERFILE
  int                      refcnt;
#endif
};

struct scamper_host_rr_txt
{
  char                   **strs;
  uint16_t                 strc;

#ifdef BUILDING_LIBSCAMPERFILE
  int                      refcnt;
#endif
};

struct scamper_host_rr_soa
{
  char                    *mname;
  char                    *rname;
  uint32_t                 serial;
  uint32_t                 refresh;
  uint32_t                 retry;
  uint32_t                 expire;
  uint32_t                 minimum;

#ifdef BUILDING_LIBSCAMPERFILE
  int                      refcnt;
#endif
};

struct scamper_host_rr
{
  uint16_t                 class;
  uint16_t                 type;
  char                    *name;
  uint32_t                 ttl;
  union
  {
    void                   *v;
    scamper_addr_t         *addr;
    char                   *str;
    scamper_host_rr_soa_t  *soa;
    scamper_host_rr_mx_t   *mx;
    scamper_host_rr_txt_t  *txt;
    scamper_host_rr_opt_t  *opt;
    scamper_host_rr_svcb_t *svcb;
  } un;

#ifdef BUILDING_LIBSCAMPERFILE
  int                      refcnt;
#endif
};

struct scamper_host_query
{
  struct timeval           tx;
  struct timeval           rx;
  uint8_t                  rcode;   /* rcode, from reply */
  uint8_t                  flags;   /* flags, from reply */
  uint16_t                 id;
  uint16_t                 ancount; /* answer count */
  uint16_t                 nscount; /* authority count */
  uint16_t                 arcount; /* additional count */
  scamper_host_rr_t      **an;
  scamper_host_rr_t      **ns;
  scamper_host_rr_t      **ar;

#ifdef BUILDING_LIBSCAMPERFILE
  int                      refcnt;
#endif
};

struct scamper_host
{
  scamper_list_t          *list;     /* list */
  scamper_cycle_t         *cycle;    /* cycle */
  scamper_addr_t          *src;      /* source IP address */
  scamper_addr_t          *dst;      /* DNS server to query */
  uint32_t                 userid;   /* user assigned id */
  struct timeval           start;    /* when started */
  uint16_t                 flags;    /* flags controlling */
  struct timeval           wait_timeout; /* how long to wait */
  uint8_t                  stop;     /* reason we stopped */
  uint8_t                  retries;  /* how many retries to make */
  uint16_t                 qtype;    /* query type */
  uint16_t                 qclass;   /* query class */
  char                    *qname;    /* query name */
  char                    *ecs;      /* edns-client-subnet */
  scamper_host_query_t   **queries;  /* queries sent */
  uint8_t                  qcount;   /* number of queries sent */
};

#endif /* __SCAMPER_HOST_INT_H */
