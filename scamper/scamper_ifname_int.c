/*
 * scamper_ifname_int.c
 *
 * $Id: scamper_ifname_int.c,v 1.2 2024/05/02 03:09:55 mjl Exp $
 *
 * Copyright (C) 2024 The Regents of the University of California
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

#include "scamper_ifname.h"
#include "scamper_ifname_int.h"
#include "scamper_debug.h"

#include "mjl_list.h"
#include "mjl_splaytree.h"

#include "utils.h"

static splaytree_t *ifni_tree;
static dlist_t     *ifni_list;

typedef struct ifname_int
{
  unsigned int          ifindex;   /* the ifindex for the name */
  struct timeval        check;     /* when to recheck ifname (2 secs) */
  struct timeval        expire;    /* when to expire entry   (10 secs) */
  splaytree_node_t     *tree_node; /* tree node in ifni_tree */
  dlist_node_t         *list_node; /* list node in ifni_list */
  scamper_ifname_t     *ifn;       /* the actual ifn */
} ifname_int_t;

static int ifname_int_cmp(const ifname_int_t *a, const ifname_int_t *b)
{
  if(a->ifindex < b->ifindex) return -1;
  if(a->ifindex > b->ifindex) return  1;
  return 0;
}

static void ifname_int_free(ifname_int_t *ifni)
{
  if(ifni->ifn != NULL)
    scamper_ifname_free(ifni->ifn);
  if(ifni->tree_node != NULL)
    splaytree_remove_node(ifni_tree, ifni->tree_node);
  if(ifni->list_node != NULL)
    dlist_node_pop(ifni_list, ifni->list_node);
  free(ifni);
  return;
}

scamper_ifname_t *scamper_ifname_int_get(unsigned int ifindex,
					 const struct timeval *now)
{
  ifname_int_t *ifni = NULL, *ptr, fm;
  scamper_ifname_t *ifn = NULL;
  dlist_node_t *dn;
  char ifname[IFNAMSIZ];
  int push = 0;

  /*
   * do we have an entry that we've checked in the past couple of seconds?
   * if so, use it.
   */
  fm.ifindex = ifindex;
  if((ifni = splaytree_find(ifni_tree, &fm)) != NULL &&
     (now == NULL || timeval_cmp(now, &ifni->check) <= 0))
    return scamper_ifname_use(ifni->ifn);

  /* get the name for the corresponding interface */
  if(if_indextoname(ifindex, ifname) == NULL)
    return NULL;

  /* if the name is the same, then the expire time was reached.  update it */
  if(ifni != NULL && strcmp(ifname, ifni->ifn->ifname) == 0)
    {
      push = 1;
      goto done;
    }

  /* the name has changed for the ifindex, so remove our copy */
  if(ifni != NULL)
    ifname_int_free(ifni);

  /* new ifname */
  if((ifni = malloc_zero(sizeof(ifname_int_t))) == NULL ||
     (ifn = scamper_ifname_alloc(ifname)) == NULL)
    goto err;
  ifni->ifindex = ifindex;
  if((ifni->tree_node = splaytree_insert(ifni_tree, ifni)) == NULL ||
     (ifni->list_node = dlist_tail_push(ifni_list, ifni)) == NULL)
    goto err;
  ifni->ifn = ifn; ifn = NULL;

 done:
  if(push != 0)
    dlist_node_tail_push(ifni_list, ifni->list_node);
  if(now != NULL)
    timeval_cpy(&ifni->expire, now);
  else
    gettimeofday_wrap(&ifni->expire);
  timeval_cpy(&ifni->check, &ifni->expire);
  now = &ifni->expire;

  /* expire old entries */
  dn = dlist_head_node(ifni_list);
  while(dn != NULL)
    {
      ptr = dlist_node_item(dn);
      dn = dlist_node_next(dn);
      if(ptr != ifni && timeval_cmp(&ptr->expire, now) < 0)
	ifname_int_free(ptr);
    }

  /* update the re-check and expiry times */
  ifni->check.tv_sec += 2;
  ifni->expire.tv_sec += 10;
  return scamper_ifname_use(ifni->ifn);

 err:
  if(ifn != NULL) scamper_ifname_free(ifn);
  if(ifni != NULL) ifname_int_free(ifni);
  return NULL;
}

int scamper_ifname_int_init(void)
{
  if((ifni_tree = splaytree_alloc((splaytree_cmp_t)ifname_int_cmp)) == NULL ||
     (ifni_list = dlist_alloc()) == NULL)
    return -1;
  return 0;
}

void scamper_ifname_int_cleanup(void)
{
  ifname_int_t *ifni;

  if(ifni_list != NULL)
    {
      while((ifni = dlist_head_pop(ifni_list)) != NULL)
	{
	  ifni->list_node = NULL;
	  ifname_int_free(ifni);
	}
      dlist_free(ifni_list);
      ifni_list = NULL;
    }

  if(ifni_tree != NULL)
    {
      splaytree_free(ifni_tree, NULL);
      ifni_tree = NULL;
    }

  return;
}
