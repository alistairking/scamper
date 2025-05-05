/*
 * scamper_file_arts.c
 *
 * $Id: scamper_file_arts.c,v 1.82 2025/05/04 03:02:09 mjl Exp $
 *
 * code to read the legacy arts data file format into scamper_hop structures.
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2014      The Regents of the University of California
 * Copyright (C) 2022-2025 Matthew Luckie
 * Copyright (C) 2025      The Regents of the University of California
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_list_int.h"
#include "trace/scamper_trace.h"
#include "trace/scamper_trace_int.h"
#include "scamper_file.h"
#include "scamper_file_arts.h"

#include "mjl_splaytree.h"
#include "mjl_list.h"

#include "utils.h"

typedef struct arts_state
{
  int          ispipe;
  splaytree_t *list_tree;
  splaytree_t *cycle_tree;
} arts_state_t;

typedef struct arts_header
{
  uint8_t  ver;
  uint32_t id;
  uint32_t flags;
  uint32_t data_length;
  uint32_t creation;
} arts_header_t;

#define ARTS_MAGIC            0xdfb0
#define ARTS_IP_PATH          0x00003000
#define ARTS_IP_PATH_RTT      0x01

#define ARTS_ATTR_CREATION    2

#define ARTS_FORMAT_UNIXDATE  13

#define ARTS_STOP_NOHALT      0x00
#define ARTS_STOP_ICMPUNREACH 0x01
#define ARTS_STOP_LOOP        0x02
#define ARTS_STOP_GAPLIMIT    0x03

static int tree_to_slist(void *ptr, void *entry)
{
  if(slist_tail_push((slist_t *)ptr, entry) != NULL)
    return 0;
  return -1;
}

/*
 * arts_read_hdr:
 *
 * read the 20 byte header that is written out before each arts object
 * and parse it into ah
 */
static int arts_read_hdr(const scamper_file_t *sf, arts_header_t *ah)
{
  int      fd = scamper_file_getfd(sf);
  uint8_t  buf[20], *tmp = buf;
  uint32_t u32, i, attr_len;
  uint16_t u16;
  int      ret;
  size_t   rc;

  memset(ah, 0, sizeof(arts_header_t));

  /* read the arts header */
  if((ret = read_wrap(fd, buf, &rc, 20)) != 0)
    {
      /* have we hit the eof? */
      if(ret == -2 && rc == 0)
	{
	  return 0;
	}

      fprintf(stderr, "%s: read %d of 20 bytes\n", __func__, (int)rc);
      goto err;
    }

  /* read the magic section of the header */
  if((u16 = bytes_ntohs(buf)) != ARTS_MAGIC)
    {
      fprintf(stderr, "%s: expected magic 0x%02x got 0x%02x\n", __func__,
	      ARTS_MAGIC, u16);
      goto err;
    }

  /*
   * the arts id field is stored in the upper 28 bits of the 32 bit field.
   * the arts version field takes the lower 4.
   */
  u32  = bytes_ntohl(buf + 2);
  ah->id  = u32 >> 4;
  ah->ver = u32 & 0x0f;
  ah->flags = bytes_ntohl(buf + 6);
  ah->data_length = bytes_ntohl(buf + 16);

  /* figure out the length of the arts attributes */
  attr_len = bytes_ntohl(buf + 12);

  /* allocate a large enough buffer, if necessary */
  if(attr_len > sizeof(buf) && (tmp = malloc_zero(attr_len)) == NULL)
    goto err;

  /* read the arts attributes into a buffer */
  if(attr_len > 0 && read_wrap(fd, tmp, &rc, attr_len) != 0)
    {
      goto err;
    }

  /* parse the buffer for recognised arts attributes */
  for(i = 0; i < attr_len; i += u32)
    {
      /* make sure there is enough left for a complete attribute */
      if(attr_len - i < 8)
	{
	  goto err;
	}

      /* read the type / identifier field */
      u32 = bytes_ntohl(tmp + i);

      /* extract the identifier field */
      switch(u32 >> 8)
	{
	case ARTS_ATTR_CREATION:
	  /* make sure the type of this field is a unix date */
	  if((u32 & 0xff) != ARTS_FORMAT_UNIXDATE || attr_len - i < 12)
	    {
	      goto err;
	    }
	  ah->creation = bytes_ntohl(tmp + i + 8);
	  break;
	}

      /* read the length field */
      u32 = bytes_ntohl(tmp + i + 4);
      if(u32 < 8 || attr_len - i < u32)
	{
	  goto err;
	}
    }

  /* free the buffer allocated, if there was one */
  if(tmp != buf) free(tmp);

  return 1;

 err:
  if(tmp != NULL && tmp != buf) free(tmp);
  return -1;
}

static int probe_cmp(const scamper_trace_probe_t *a,
		     const scamper_trace_probe_t *b)
{
  if(a->ttl < b->ttl) return -1;
  if(a->ttl > b->ttl) return  1;
  if(a->id < b->id) return -1;
  if(a->id > b->id) return  1;
  return 0;
}

static scamper_trace_probe_t *probe_get(splaytree_t *probes,
					uint8_t ttl, uint8_t id)
{
  scamper_trace_probe_t fm, *probe;

  fm.ttl = ttl;
  fm.id  = id;
  if((probe = splaytree_find(probes, &fm)) == NULL)
    {
      if((probe = scamper_trace_probe_alloc()) == NULL)
	goto err;
      probe->ttl = ttl;
      probe->id = id;
      if(splaytree_insert(probes, probe) == NULL)
	goto err;
    }

  return probe;

 err:
  if(probe != NULL) scamper_trace_probe_free(probe);
  return NULL;
}

static scamper_trace_reply_t *arts_hop_reply(scamper_addr_t *addr, uint32_t rtt)
{
  scamper_trace_reply_t *hop;

  if((hop = scamper_trace_reply_alloc()) == NULL)
    return NULL;
  hop->addr = scamper_addr_use(addr);
  hop->rtt.tv_sec = rtt / 1000000;
  hop->rtt.tv_usec = rtt % 1000000;
  hop->reply_icmp_type = ICMP_ECHOREPLY;

  return hop;
}

static int arts_hop_read(const arts_header_t *ah, const uint8_t *buf,
			 scamper_trace_probe_t *probe,
			 scamper_trace_reply_t *hop)
{
  uint32_t u32;
  int i = 0;

  probe->ttl = buf[i++]; /* probe ttl */
  if(probe->ttl == 0)
    return -1;

  hop->reply_icmp_type = ICMP_TIMXCEED;
  hop->reply_icmp_code = ICMP_TIMXCEED_INTRANS;

  /* the IPv4 address of the hop that responded */
  if((hop->addr = scamper_addr_alloc_ipv4(buf+i)) == NULL)
    return -1;
  i += 4;

  /* arts 1 always stores RTT per hop; arts > 1 conditionally stores it */
  if(ah->ver == 1 || (ah->flags & ARTS_IP_PATH_RTT && ah->ver > 1))
    {
      /* RTT, stored in microseconds */
      u32 = bytes_ntohl(buf+i); i += 4;
      hop->rtt.tv_sec  = u32 / 1000000;
      hop->rtt.tv_usec = u32 % 1000000;

      /* num tries */
      probe->id = buf[i++];
    }

  return i;
}

static int arts_hops_read(const arts_header_t *ah, splaytree_t *probes,
			  const uint8_t *buf, uint8_t count, uint32_t *off)
{
  scamper_trace_probe_t fm, *probe = NULL;
  scamper_trace_reply_t *hop = NULL;
  uint32_t i = 0;
  int rc;

  if(count == 0)
    goto err;

  while(count-- > 0)
    {
      memset(&fm, 0, sizeof(fm));
      if((hop = scamper_trace_reply_alloc()) == NULL ||
	 (rc = arts_hop_read(ah, buf+i, &fm, hop)) <= 0 ||
	 (probe = probe_get(probes, fm.ttl, fm.id)) == NULL ||
	 scamper_trace_probe_reply_add(probe, hop) != 0)
	goto err;
      i += (uint32_t)rc;
    }

  *off += i;
  return 0;

 err:
  if(hop != NULL) scamper_trace_reply_free(hop);
  return -1;
}

static int arts_list_cmp(const scamper_list_t *a, const scamper_list_t *b)
{
  if(a->id < b->id) return -1;
  if(a->id > b->id) return  1;
  return 0;
}

static scamper_list_t *arts_list_get(arts_state_t *state, uint32_t id)
{
  scamper_list_t findme, *list;

  findme.id = id;
  if((list = splaytree_find(state->list_tree, &findme)) == NULL)
    {
      if((list = scamper_list_alloc(id, NULL, NULL, NULL)) == NULL)
	return NULL;

      if(splaytree_insert(state->list_tree, list) == NULL)
	{
	  scamper_list_free(list);
	  return NULL;
	}
    }

  return list;
}

static int arts_cycle_cmp(const scamper_cycle_t *a, const scamper_cycle_t *b)
{
  int i;
  if((i = arts_list_cmp(a->list, b->list)) != 0)
    return i;
  if(a->id < b->id) return -1;
  if(a->id > b->id) return  1;
  return 0;
}

static scamper_cycle_t *arts_cycle_get(arts_state_t *state,
				       scamper_list_t *list, uint32_t id)
{
  scamper_cycle_t findme, *cycle;

  findme.list = list;
  findme.id = id;
  if((cycle = splaytree_find(state->cycle_tree, &findme)) == NULL)
    {
      if((cycle = scamper_cycle_alloc(list)) == NULL)
	return NULL;
      cycle->id = id;

      if(splaytree_insert(state->cycle_tree, cycle) == NULL)
	{
	  scamper_cycle_free(cycle);
	  return NULL;
	}
    }

  return cycle;
}

static scamper_trace_t *arts_read_trace(const scamper_file_t *sf,
					const arts_header_t *ah)
{
  arts_state_t *state = scamper_file_getstate(sf);
  scamper_trace_t *trace = NULL;
  scamper_trace_probettl_t *pttl;
  scamper_trace_probe_t *probe = NULL;
  scamper_trace_reply_t *hop = NULL;
  splaytree_t *probe_tree = NULL;
  slist_t *probe_list = NULL;
  uint8_t *buf = NULL;
  uint32_t i, u32, rtt;
  uint8_t u8, hop_distance, halt_reason, halt_reason_data, reply_ttl = 0;
  uint8_t num_hop_recs, max_hop, destination_replied;
  size_t rc;
  int fd;

  if((buf = malloc_zero(ah->data_length)) == NULL)
    {
      fprintf(stderr, "%s: malloc %d for trace object failed\n", __func__,
	      ah->data_length);
      goto err;
    }

  fd = scamper_file_getfd(sf);
  if(read_wrap(fd, buf, &rc, ah->data_length) != 0)
    {
      fprintf(stderr, "%s: read %d expected %d\n", __func__, (int)rc,
	      ah->data_length);
      goto err;
    }

  if((trace = scamper_trace_alloc()) == NULL)
    {
      fprintf(stderr, "%s: scamper_trace_alloc failed\n", __func__);
      goto err;
    }

  trace->start.tv_sec = ah->creation;
  trace->type = SCAMPER_TRACE_TYPE_ICMP_ECHO;
  trace->probe_size = 20 + 8 + 12;

  i = 0;

  if((trace->src = scamper_addr_alloc_ipv4(buf+i)) == NULL)
    goto err;
  i += 4;

  if((trace->dst = scamper_addr_alloc_ipv4(buf+i)) == NULL)
    goto err;
  i += 4;

  if(ah->ver >= 3)
    {
      /* list id */
      u32 = bytes_ntohl(buf+i); i += 4;
      if((trace->list = arts_list_get(state, u32)) == NULL)
	goto err;
      scamper_list_use(trace->list);

      /* cycle id */
      u32 = bytes_ntohl(buf+i); i += 4;
      if((trace->cycle = arts_cycle_get(state, trace->list, u32)) == NULL)
	goto err;
      scamper_cycle_use(trace->cycle);
    }

  /*
   * read the RTT of the last hop.  arts prior to version 2 stores a
   * timeval struct in the file for recording RTT.
   */
  rtt = bytes_ntohl(buf + i); i += 4;
  if(ah->ver < 2)
    {
      rtt *= 1000000;
      u32  = bytes_ntohl(buf+i); i += 4;
      rtt += u32;
    }

  /*
   * the hop distance field tells us how many hops a packet takes to a
   * destination
   */
  hop_distance = buf[i++];

  /*
   * read the next 8 bit field.  the first bit says if the trace was
   * successful in probing to the end host, and the other 7 bits say
   * how many hops actually responded to a probe.
   */
  u8 = buf[i++];
  destination_replied = u8 >> 7;
  num_hop_recs = u8 & 0x7f;

  if(destination_replied != 0)
    trace->stop_reason = SCAMPER_TRACE_STOP_COMPLETED;

  /*
   * arts versions after 1 (and arts version 1 conditionally) store
   * data that tells us why the trace stopped
   */
  if(ah->ver > 1 || (destination_replied != 0 && ah->ver == 1))
    {
      halt_reason      = buf[i++];
      halt_reason_data = buf[i++];

      switch(halt_reason)
	{
	case ARTS_STOP_NOHALT:
	  trace->stop_reason = SCAMPER_TRACE_STOP_NONE;
	  break;

	case ARTS_STOP_ICMPUNREACH:
	  trace->stop_reason = SCAMPER_TRACE_STOP_UNREACH;
	  break;

	case ARTS_STOP_LOOP:
	  trace->stop_reason = SCAMPER_TRACE_STOP_LOOP;
	  break;

	case ARTS_STOP_GAPLIMIT:
	  trace->stop_reason = SCAMPER_TRACE_STOP_GAPLIMIT;
	  break;
	}

      trace->stop_data = halt_reason_data;
    }

  if(num_hop_recs == 0 && destination_replied == 0)
    goto done;

  if((probe_tree = splaytree_alloc((splaytree_cmp_t)probe_cmp)) == NULL)
    goto err;

  /*
   * arts >= 2 stores the TTL of reply packet from a destination so we
   * can estimate the number of hops on the reverse path
   */
  if(ah->ver >= 2)
    reply_ttl = buf[i++];

  if(num_hop_recs > 0 &&
     arts_hops_read(ah, probe_tree, buf+i, num_hop_recs, &i) != 0)
    {
      fprintf(stderr, "%s: arts_hops_read %d failed\n", __func__,
	      num_hop_recs);
      goto err;
    }

  if(destination_replied != 0)
    max_hop = hop_distance;
  else
    max_hop = 0;

  /*
   * make a pass through all ArtsIpPathEntry structures.  figure out
   * the largest probe ttl used.  if the trace stopped because an ICMP
   * unreachable was received, then associate the type/code with the last
   * structure read.
   */
  if((probe_list = slist_alloc()) == NULL)
    goto err;
  splaytree_inorder(probe_tree,
		    (splaytree_inorder_t)tree_to_slist, probe_list);
  splaytree_free(probe_tree, NULL); probe_tree = NULL;
  if((probe = slist_tail_item(probe_list)) != NULL)
    {
      assert(probe->replyc > 0);
      if(max_hop < probe->ttl)
	max_hop = probe->ttl;
      if(trace->stop_reason == SCAMPER_TRACE_STOP_UNREACH)
	{
	  hop = probe->replies[probe->replyc-1];
	  hop->reply_icmp_type = ICMP_UNREACH;
	  hop->reply_icmp_code = trace->stop_data;
	}
    }

  if(i != ah->data_length)
    goto err;
  free(buf); buf = NULL;

  if(max_hop == 0)
    goto done;

  if(scamper_trace_hops_alloc(trace, max_hop) == -1)
    goto err;
  trace->hop_count = max_hop;

  /*
   * now loop through the hops array stored in this procedure
   * and assemble the responses into trace->hops. order them based
   * on the probe's ttl then by attempt
   */
  while((probe = slist_head_item(probe_list)) != NULL)
    {
      if((pttl = trace->hops[probe->ttl-1]) == NULL)
	{
	  if((pttl = scamper_trace_probettl_alloc()) == NULL)
	    goto err;
	  trace->hops[probe->ttl-1] = pttl;
	}
      probe = slist_head_pop(probe_list);
      if(scamper_trace_probettl_probe_add(pttl, probe) != 0)
	{
	  scamper_trace_probe_free(probe);
	  goto err;
	}
    }
  
  if(destination_replied != 0 && hop_distance > 0)
    {
      if((pttl = trace->hops[hop_distance-1]) == NULL)
	{
	  if((pttl = scamper_trace_probettl_alloc()) == NULL)
	    goto err;
	  trace->hops[hop_distance-1] = pttl;
	}

      if(pttl->probec == 0 || pttl->probes[0]->id > 0)
	{
	  if((probe = scamper_trace_probe_alloc()) == NULL)
	    goto err;
	  probe->ttl = hop_distance - 1;
	  if(scamper_trace_probettl_probe_add(pttl, probe) != 0)
	    {
	      scamper_trace_probe_free(probe);
	      goto err;
	    }

	  /*
	   * move this probe to the start of the list for consistency
	   * with prior code
	   */
	  if(pttl->probec > 1)
	    {
	      memmove(&pttl->probes[1], &pttl->probes[0],
		      sizeof(scamper_trace_probe_t *) * (pttl->probec - 1));
	      pttl->probes[0] = probe;
	    }
	}

      /*
       * add reply to probe, and make sure it is the first reply for
       * consistency with prior code
       */
      if((hop = arts_hop_reply(trace->dst, rtt)) == NULL)
	goto err;
      if(ah->ver >= 2)
	{
	  hop->ttl = reply_ttl;
	  hop->flags |= SCAMPER_TRACE_REPLY_FLAG_REPLY_TTL;
	}
      if(scamper_trace_probe_reply_add(probe, hop) != 0)
	{
	  scamper_trace_reply_free(hop);
	  goto err;
	}
      if(probe->replyc > 1)
	{
	  memmove(&probe->replies[1], &probe->replies[0],
		  sizeof(scamper_trace_probe_t *) * (probe->replyc - 1));
	  probe->replies[0] = hop;
	}
    }

 done:
  if(probe_list != NULL)
    slist_free_cb(probe_list, (slist_free_t)scamper_trace_probe_free);
  if(buf != NULL) free(buf);
  return trace;

 err:
  if(probe_list != NULL)
    slist_free_cb(probe_list, (slist_free_t)scamper_trace_probe_free);
  if(trace != NULL) scamper_trace_free(trace);
  if(buf != NULL) free(buf);
  return NULL;
}

static int arts_skip(const scamper_file_t *sf, uint32_t bytes)
{
  arts_state_t *state = scamper_file_getstate(sf);
  int fd = scamper_file_getfd(sf);
  uint8_t buf[512];
  size_t len;

  if(state->ispipe == 0)
    {
      if(lseek(fd, bytes, SEEK_CUR) != -1)
	return 0;
      if(errno != ESPIPE)
	return -1;
      state->ispipe = 1;
    }

  while(bytes != 0)
    {
      len = (sizeof(buf) < bytes) ? sizeof(buf) : bytes;
      if(read_wrap(fd, buf, NULL, len) != 0)
	return -1;
      bytes -= (uint32_t)len;
    }

  return 0;
}

/*
 * scamper_file_arts_read
 *
 * legacy arts only recognises IPv4 traces
 */
int scamper_file_arts_read(scamper_file_t *sf,
			   const scamper_file_filter_t *filter,
			   uint16_t *type, void **data)
{
  arts_header_t ah;
  int           tmp;

  for(;;)
    {
      if((tmp = arts_read_hdr(sf, &ah)) == 0)
	{
	  /* EOF */
	  *data = NULL;
	  break;
	}
      else if(tmp == -1)
	{
	  /* partial record */
	  return -1;
	}

      if(ah.data_length == 0)
	return -1;

      if(ah.id == ARTS_IP_PATH &&
	 scamper_file_filter_isset(filter, SCAMPER_FILE_OBJ_TRACE))
	{
	  if((*data = arts_read_trace(sf, &ah)) == NULL)
	    return -1;
	  *type = SCAMPER_FILE_OBJ_TRACE;
	  return 0;
	}

      /* skip over */
      if(arts_skip(sf, ah.data_length) != 0)
	return -1;
    }

  return 0;
}

static void arts_state_free(arts_state_t *state)
{
  if(state == NULL)
    return;

  if(state->list_tree != NULL)
    splaytree_free(state->list_tree, (splaytree_free_t)scamper_list_free);
  if(state->cycle_tree != NULL)
    splaytree_free(state->cycle_tree, (splaytree_free_t)scamper_cycle_free);
  free(state);
  return;
}

int scamper_file_arts_init_read(scamper_file_t *sf)
{
  arts_state_t *s;
  if((s = (arts_state_t *)malloc_zero(sizeof(arts_state_t))) == NULL ||
     (s->list_tree=splaytree_alloc((splaytree_cmp_t)arts_list_cmp)) == NULL ||
     (s->cycle_tree=splaytree_alloc((splaytree_cmp_t)arts_cycle_cmp)) == NULL)
    {
      arts_state_free(s);
      return -1;
    }
  scamper_file_setstate(sf, s);
  return 0;
}

void scamper_file_arts_free_state(scamper_file_t *sf)
{
  arts_state_free(scamper_file_getstate(sf));
  return;
}
