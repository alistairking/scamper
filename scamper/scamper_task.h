/*
 * scamper_task.h
 *
 * $Id: scamper_task.h,v 1.59 2025/05/28 07:18:59 mjl Exp $
 *
 * Copyright (C) 2005-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2013      The Regents of the University of California
 * Copyright (C) 2018-2023 Matthew Luckie
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

#ifndef __SCAMPER_TASK_H
#define __SCAMPER_TASK_H

struct scamper_addr;
struct scamper_queue;
struct scamper_task;
struct scamper_dl_rec;
struct scamper_icmp_resp;
struct scamper_udp_resp;
struct scamper_cyclemon;
struct scamper_file;
struct scamper_sourcetask;

#define SCAMPER_TASK_SIG_TYPE_TX_IP 1
#define SCAMPER_TASK_SIG_TYPE_TX_ND 2
#ifndef DISABLE_SCAMPER_SNIFF
#define SCAMPER_TASK_SIG_TYPE_SNIFF 3
#endif
#ifndef DISABLE_SCAMPER_HOST
#define SCAMPER_TASK_SIG_TYPE_HOST  4
#endif

typedef struct scamper_task scamper_task_t;
typedef struct scamper_task_anc scamper_task_anc_t;

typedef struct scamper_task_sig
{
  uint8_t sig_type;
  union
  {
    struct tx_ip
    {
      struct scamper_addr *dst;
      uint8_t              proto;
      union
      {
	struct tx_ip_icmp
	{
	  uint8_t  type;
	  uint16_t id;
	} icmp;
	struct tx_ip_udp
	{
	  uint16_t sport_x, sport_y;
	  uint16_t dport_x, dport_y;
	} udp;
	struct tx_ip_tcp
	{
	  uint16_t sport_x, sport_y;
	  uint16_t dport_x, dport_y;
	} tcp;
      } un;
    } ip;
    struct tx_nd
    {
      struct scamper_addr *ip;
    } nd;
#ifndef DISABLE_SCAMPER_SNIFF
    struct sniff
    {
      struct scamper_addr *src;
      uint16_t             icmpid;
    } sniff;
#endif
#ifndef DISABLE_SCAMPER_HOST
    struct host
    {
      struct scamper_addr *dst;
      char                *name;
      uint16_t             type;
    } host;
#endif
  } un;
} scamper_task_sig_t;

#define sig_tx_ip_dst         un.ip.dst
#define sig_tx_ip_proto       un.ip.proto
#define sig_tx_ip_icmp_id     un.ip.un.icmp.id
#define sig_tx_ip_icmp_type   un.ip.un.icmp.type
#define sig_tx_ip_udp_sport_x un.ip.un.udp.sport_x
#define sig_tx_ip_udp_sport_y un.ip.un.udp.sport_y
#define sig_tx_ip_udp_dport_x un.ip.un.udp.dport_x
#define sig_tx_ip_udp_dport_y un.ip.un.udp.dport_y
#define sig_tx_ip_tcp_sport_x un.ip.un.tcp.sport_x
#define sig_tx_ip_tcp_sport_y un.ip.un.tcp.sport_y
#define sig_tx_ip_tcp_dport_x un.ip.un.tcp.dport_x
#define sig_tx_ip_tcp_dport_y un.ip.un.tcp.dport_y
#define sig_tx_nd_ip          un.nd.ip
#ifndef DISABLE_SCAMPER_SNIFF
#define sig_sniff_src         un.sniff.src
#define sig_sniff_icmp_id     un.sniff.icmpid
#endif
#ifndef DISABLE_SCAMPER_HOST
#define sig_host_dst          un.host.dst
#define sig_host_name         un.host.name
#define sig_host_type         un.host.type
#endif

typedef struct scamper_task_funcs
{
  /* probe the destination */
  void (*probe)(struct scamper_task *task);

  /* settle sigs just before probing commences */
  void (*sigs)(struct scamper_task *task);

  /* handle some ICMP packet */
  void (*handle_icmp)(struct scamper_task *task,
		      struct scamper_icmp_resp *icmp);

  void (*handle_udp)(struct scamper_task *task,
		     struct scamper_udp_resp *udp);

  /* handle some information from the datalink */
  void (*handle_dl)(struct scamper_task *task, struct scamper_dl_rec *dl_rec);

  /* handle the task timing out on the wait queue */
  void (*handle_timeout)(struct scamper_task *task);

  void (*halt)(struct scamper_task *task);

  /* return a duplicate of the data currently stored with the task */
  void *(*data_dup)(void *data);

  /* function to call to free data */
  void (*data_free)(void *data);

  /* is the data marked as in-progress? */
  int (*data_inprog)(void *data);

  /* write the task's data object out */
  void (*write)(struct scamper_file *file, struct scamper_task *task);

  /* free the task's data and state */
  void (*task_free)(struct scamper_task *task);

} scamper_task_funcs_t;

scamper_task_t *scamper_task_alloc(void *data, scamper_task_funcs_t *funcs);
void scamper_task_free(scamper_task_t *task);

/* put a duplicate version of the task in the source's queue */
scamper_task_t *scamper_task_dup(scamper_task_t *task);

/* get various items of the task */
void *scamper_task_getdata(const scamper_task_t *task);
void *scamper_task_getstate(const scamper_task_t *task);
struct scamper_source *scamper_task_getsource(scamper_task_t *task);
struct scamper_sourcetask *scamper_task_getsourcetask(scamper_task_t *task);

/* set various items on the task */
void scamper_task_setdatanull(scamper_task_t *task);
void scamper_task_setstate(scamper_task_t *task, void *state);
void scamper_task_setsourcetask(scamper_task_t *task,
				struct scamper_sourcetask *st);
void scamper_task_setcyclemon(scamper_task_t *t, struct scamper_cyclemon *cm);

int scamper_task_is_inprog(scamper_task_t *task);

/* access the various functions registered with the task */
void scamper_task_write(scamper_task_t *task, struct scamper_file *file);
void scamper_task_probe(scamper_task_t *task);
void scamper_task_handletimeout(scamper_task_t *task);
void scamper_task_halt(scamper_task_t *task);

/* pass the datalink record to all appropriate tasks */
void scamper_task_handledl(struct scamper_dl_rec *dl);

/* pass the ICMP response to all appropriate tasks */
void scamper_task_handleicmp(struct scamper_icmp_resp *r);

/* pass the UDP response to all appropriate tasks */
void scamper_task_handleudp(struct scamper_udp_resp *r);

/* access the queue structre the task holds */
int scamper_task_queue_probe(scamper_task_t *task);
int scamper_task_queue_probe_head(scamper_task_t *task);
int scamper_task_queue_wait(scamper_task_t *task, int ms);
int scamper_task_queue_wait_tv(scamper_task_t *task, struct timeval *tv);
int scamper_task_queue_done(scamper_task_t *task, int ms);
int scamper_task_queue_isprobe(scamper_task_t *task);
int scamper_task_queue_isdone(scamper_task_t *task);

/* access the file descriptors the task holds */
#ifdef __SCAMPER_FD_H
scamper_fd_t *scamper_task_fd_icmp4(scamper_task_t *task, void *addr);
scamper_fd_t *scamper_task_fd_icmp6(scamper_task_t *task, void *addr);
scamper_fd_t *scamper_task_fd_udp4(scamper_task_t *task, void *a, uint16_t sp);
scamper_fd_t *scamper_task_fd_udp6(scamper_task_t *task, void *a, uint16_t sp);
scamper_fd_t *scamper_task_fd_tcp4(scamper_task_t *task, void *a, uint16_t sp);
scamper_fd_t *scamper_task_fd_tcp6(scamper_task_t *task, void *a, uint16_t sp);
scamper_fd_t *scamper_task_fd_dl(scamper_task_t *task, int ifindex);
scamper_fd_t *scamper_task_fd_ip4(scamper_task_t *task);
#endif

#if defined(__SCAMPER_FD_H) && !defined(_WIN32) /* no routing socket */
scamper_fd_t *scamper_task_fd_rtsock(scamper_task_t *task);
#endif

/* define and use the task's probe signatures */
scamper_task_sig_t *scamper_task_sig_alloc(uint8_t type);
void scamper_task_sig_free(scamper_task_sig_t *sig);
int scamper_task_sig_add(scamper_task_t *task, scamper_task_sig_t *sig);
void scamper_task_sig_prepare(scamper_task_t *task);
scamper_task_t *scamper_task_sig_block(scamper_task_t *task);
int scamper_task_sig_install(scamper_task_t *task);
void scamper_task_sig_expiry_run(const struct timeval *now);
scamper_task_t *scamper_task_find(scamper_task_sig_t *sig);
char *scamper_task_sig_tostr(scamper_task_sig_t *sig, char *buf, size_t len);
int scamper_task_sig_sport_used(struct scamper_addr *dst,
				uint8_t proto, uint16_t sport, uint16_t dport);
int scamper_task_sig_icmpid_used(struct scamper_addr *dst,
				 uint8_t type, uint16_t id);

/* manage ancillary data attached to the task */
scamper_task_anc_t *scamper_task_anc_add(scamper_task_t *task, void *data,
					 void (*freedata)(void *));
void scamper_task_anc_del(scamper_task_t *task, scamper_task_anc_t *anc);

/*
 * scamper_task_onhold
 *
 * given a task that another is blocked on, register the fact.
 * when either task is free'd, the other task will be placed back
 * into the source's command queue.
 *
 */
int scamper_task_onhold(scamper_task_t *blocker, scamper_task_t *blocked);

int scamper_task_init(void);
void scamper_task_cleanup(void);

#define SCAMPER_TASK_SIG_ICMP_ECHO(sig, id) do {			\
    assert((sig)->sig_tx_ip_dst != NULL);				\
    assert((sig)->sig_tx_ip_dst->type == SCAMPER_ADDR_TYPE_IPV4 ||	\
	   (sig)->sig_tx_ip_dst->type == SCAMPER_ADDR_TYPE_IPV6);	\
    if((sig)->sig_tx_ip_dst->type == SCAMPER_ADDR_TYPE_IPV4)		\
      {									\
	(sig)->sig_tx_ip_proto = IPPROTO_ICMP;				\
	(sig)->sig_tx_ip_icmp_type = ICMP_ECHO;				\
      }									\
    else								\
      {									\
	(sig)->sig_tx_ip_proto = IPPROTO_ICMPV6;			\
	(sig)->sig_tx_ip_icmp_type = ICMP6_ECHO_REQUEST;		\
      }									\
    (sig)->sig_tx_ip_icmp_id = (id);					\
  } while(0)

#define SCAMPER_TASK_SIG_ICMP_TIME(sig, id) do {			\
    assert((sig)->sig_tx_ip_dst != NULL);				\
    assert((sig)->sig_tx_ip_dst->type == SCAMPER_ADDR_TYPE_IPV4);	\
    (sig)->sig_tx_ip_proto = IPPROTO_ICMP;				\
    (sig)->sig_tx_ip_icmp_type = ICMP_TSTAMP;				\
    (sig)->sig_tx_ip_icmp_id = (id);					\
  } while(0)

#define SCAMPER_TASK_SIG_TCP(sig, sport, dport) do {			\
    (sig)->sig_tx_ip_proto = IPPROTO_TCP;				\
    (sig)->sig_tx_ip_tcp_sport_x = (sport);				\
    (sig)->sig_tx_ip_tcp_sport_y = (sport);				\
    (sig)->sig_tx_ip_tcp_dport_x = (dport);				\
    (sig)->sig_tx_ip_tcp_dport_y = (dport);				\
  } while(0)

#define SCAMPER_TASK_SIG_TCP_SPORT(sig, sport_x, sport_y, dport) do {	\
    assert((sport_x) <= (sport_y));					\
    (sig)->sig_tx_ip_proto = IPPROTO_TCP;				\
    (sig)->sig_tx_ip_tcp_sport_x = (sport_x);				\
    (sig)->sig_tx_ip_tcp_sport_y = (sport_y);				\
    (sig)->sig_tx_ip_tcp_dport_x = (dport);				\
    (sig)->sig_tx_ip_tcp_dport_y = (dport);				\
  } while(0)

#define SCAMPER_TASK_SIG_UDP(sig, sport, dport) do {			\
    (sig)->sig_tx_ip_proto = IPPROTO_UDP;				\
    (sig)->sig_tx_ip_udp_sport_x = (sport);				\
    (sig)->sig_tx_ip_udp_sport_y = (sport);				\
    (sig)->sig_tx_ip_udp_dport_x = (dport);				\
    (sig)->sig_tx_ip_udp_dport_y = (dport);				\
  } while(0)

#define SCAMPER_TASK_SIG_UDP_SPORT(sig, sport_x, sport_y, dport) do {	\
    assert((sport_x) <= (sport_y));					\
    (sig)->sig_tx_ip_proto = IPPROTO_UDP;				\
    (sig)->sig_tx_ip_udp_sport_x = (sport_x);				\
    (sig)->sig_tx_ip_udp_sport_y = (sport_y);				\
    (sig)->sig_tx_ip_udp_dport_x = (dport);				\
    (sig)->sig_tx_ip_udp_dport_y = (dport);				\
  } while(0)

#define SCAMPER_TASK_SIG_UDP_DPORT(sig, sport, dport_x, dport_y) do {	\
    assert((dport_x) <= (dport_y));					\
    (sig)->sig_tx_ip_proto = IPPROTO_UDP;				\
    (sig)->sig_tx_ip_udp_sport_x = (sport);				\
    (sig)->sig_tx_ip_udp_sport_y = (sport);				\
    (sig)->sig_tx_ip_udp_dport_x = (dport_x);				\
    (sig)->sig_tx_ip_udp_dport_y = (dport_y);				\
  } while(0)

#endif /* __SCAMPER_TASK_H */
