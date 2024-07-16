/*
 * linked list routines
 * by Matthew Luckie
 *
 * Copyright (C) 2004-2023 Matthew Luckie. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Matthew Luckie ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Matthew Luckie BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: mjl_list.h,v 1.44 2024/03/23 07:55:43 mjl Exp $
 *
 */

#ifndef __MJL_LIST_H
#define __MJL_LIST_H

typedef struct slist slist_t; /* single linked list */
typedef struct dlist dlist_t; /* double linked list */
typedef struct clist clist_t; /* circular doubly-linked list */

typedef struct slist_node slist_node_t;
typedef struct dlist_node dlist_node_t;
typedef struct clist_node clist_node_t;

typedef int (*slist_foreach_t)(void *item, void *param);
typedef int (*dlist_foreach_t)(void *item, void *param);
typedef int (*clist_foreach_t)(void *item, void *param);

typedef void (*slist_onremove_t)(void *item);
typedef void (*dlist_onremove_t)(void *item);
typedef void (*clist_onremove_t)(void *item);

typedef int (*slist_cmp_t)(const void *a, const void *b);
typedef int (*dlist_cmp_t)(const void *a, const void *b);

typedef void (*slist_free_t)(void *item);
typedef void (*dlist_free_t)(void *item);
typedef void (*clist_free_t)(void *item);

#ifndef DMALLOC
/* allocate an empty list */
slist_t *slist_alloc(void);

/* duplicate the list, applying the supplied function to each item */
slist_t *slist_dup(slist_t *list, const slist_foreach_t func, void *param);

/* push the item onto the head of the list */
slist_node_t *slist_head_push(slist_t *list, void *item);

/* push the item onto the tail of the list */
slist_node_t *slist_tail_push(slist_t *list, void *item);
#endif

#ifdef DMALLOC
slist_t *slist_alloc_dm(const char *file, const int line);
slist_t *slist_dup_dm(slist_t *oldlist,const slist_foreach_t func,void *param,
		      const char *file, const int line);
slist_node_t *slist_head_push_dm(slist_t *list, void *item,
				 const char *file, const int line);
slist_node_t *slist_tail_push_dm(slist_t *list, void *item,
				 const char *file, const int line);

#define slist_alloc() slist_alloc_dm(__FILE__, __LINE__)
#define slist_dup(old,func,param) slist_dup_dm((old), (func), (param), \
					    __FILE__, __LINE__)
#define slist_head_push(list, item) slist_head_push_dm((list), (item), \
						       __FILE__, __LINE__)
#define slist_tail_push(list, item) slist_tail_push_dm((list), (item), \
						       __FILE__, __LINE__)
#endif

/* set function to call when a node is removed from the list */
void slist_onremove(slist_t *list, slist_onremove_t onremove);

/* concatenate second list onto tail of first */
void slist_concat(slist_t *first, slist_t *second);

/* remove item at head of list, free node */
void *slist_head_pop(slist_t *list);

/* get item at head of list without removing from list */
void *slist_head_item(const slist_t *list);

/* get item at tail of list without removing from list */
void *slist_tail_item(const slist_t *list);

/* get the item associated with a node */
void *slist_node_item(const slist_node_t *node);

/* get the node at the head of the list */
slist_node_t *slist_head_node(const slist_t *list);

/* get the node at the tail of the list */
slist_node_t *slist_tail_node(const slist_t *list);

/* get the node after the provided node */
slist_node_t *slist_node_next(const slist_node_t *node);

/* iterate through the list, applying the function on each item */
int slist_foreach(slist_t *list, const slist_foreach_t func, void *param);

/* return how many items are on the list */
int slist_count(const slist_t *list);

/* sort the items on the list with the provided sorting function */
int slist_qsort(slist_t *list, slist_cmp_t func);

/* randomly shuffle the items on the list */
int slist_shuffle(slist_t *list);

/* lock the list, asserting that the list cannot be modified until unlocked */
void slist_lock(slist_t *list);

/* unlock the list */
void slist_unlock(slist_t *list);

/* return lock status of the list */
int slist_islocked(slist_t *list);

/* empty out the list but retain an empty list structure */
void slist_empty(slist_t *list);
void slist_empty_cb(slist_t *list, slist_free_t func);

/* free the list, including the list structure */
void slist_free(slist_t *list);
void slist_free_cb(slist_t *list, slist_free_t func);

#ifndef DMALLOC
/* allocate an empty list */
dlist_t *dlist_alloc(void);

/* duplicate the list, applying the supplied function to each item */
dlist_t *dlist_dup(dlist_t *list, const dlist_foreach_t func, void *param);

/* allocate a node */
dlist_node_t *dlist_node_alloc(void *item);

/* push the item onto the head of the list */
dlist_node_t *dlist_head_push(dlist_t *list, void *item);

/* push the item onto the tail of the list */
dlist_node_t *dlist_tail_push(dlist_t *list, void *item);
#else
dlist_t *dlist_alloc_dm(const char *file, const int line);
dlist_t *dlist_dup_dm(dlist_t *oldlist,const dlist_foreach_t func,void *param,
		      const char *file, const int line);
dlist_node_t *dlist_node_alloc_dm(void *item,const char *file,const int line);
dlist_node_t *dlist_head_push_dm(dlist_t *list, void *item,
				 const char *file, const int line);
dlist_node_t *dlist_tail_push_dm(dlist_t *list, void *item,
				 const char *file, const int line);
#define dlist_alloc() dlist_alloc_dm(__FILE__, __LINE__)
#define dlist_node_alloc(item) dlist_node_alloc_dm((item), __FILE__, __LINE__)
#define dlist_head_push(list,item) dlist_head_push_dm((list), (item), \
						      __FILE__, __LINE__)
#define dlist_tail_push(list,item) dlist_tail_push_dm((list), (item), \
						      __FILE__, __LINE__)
#endif

/* set function to call when a node is removed from the list */
void dlist_onremove(dlist_t *list, dlist_onremove_t onremove);

/* concatenate second list onto tail of first */
void dlist_concat(dlist_t *first, dlist_t *second);

/* remove item at head of list, free node */
void *dlist_head_pop(dlist_t *list);

/* remove item at tail of list, free node */
void *dlist_tail_pop(dlist_t *list);

/* get item at head of list without removing from list */
void *dlist_head_item(const dlist_t *list);

/* get item at tail of list without removing from list */
void *dlist_tail_item(const dlist_t *list);

/* remove item from list, free node */
void *dlist_node_pop(dlist_t *list, dlist_node_t *node);

/* get the item associated with a node */
void *dlist_node_item(const dlist_node_t *node);

/* get the node at the head of the list */
dlist_node_t *dlist_head_node(const dlist_t *list);

/* get the node at the tail of the list */
dlist_node_t *dlist_tail_node(const dlist_t *list);

/* get the node after the provided node */
dlist_node_t *dlist_node_next(const dlist_node_t *node);

/* get the node previous to the provided node */
dlist_node_t *dlist_node_prev(const dlist_node_t *node);

/* remove the node from the list, do not free node */
void dlist_node_eject(dlist_t *list, dlist_node_t *node);

/* put the node at the head of the list */
void dlist_node_head_push(dlist_t *list, dlist_node_t *node);

/* put the node at the tail of the list */
void dlist_node_tail_push(dlist_t *list, dlist_node_t *node);

/* iterate through the list, applying the function on each item */
int dlist_foreach(dlist_t *list, const dlist_foreach_t func, void *param);

/* return how many items are on the list */
int dlist_count(const dlist_t *list);

/* sort the items on the list with the provided sorting function */
int dlist_qsort(dlist_t *list, dlist_cmp_t func);

/* randomly shuffle the items on the list */
int dlist_shuffle(dlist_t *list);

/* lock the list, asserting that the list cannot be modified until unlocked */
void dlist_lock(dlist_t *list);

/* unlock the list */
void dlist_unlock(dlist_t *list);

/* return lock status of the list */
int dlist_islocked(dlist_t *list);

/* empty out the list but retain an empty list structure */
void dlist_empty(dlist_t *list);
void dlist_empty_cb(dlist_t *list, dlist_free_t func);

/* free the list, including the list structure */
void dlist_free(dlist_t *list);
void dlist_free_cb(dlist_t *list, dlist_free_t func);

#ifndef DMALLOC
/* allocate an empty list */
clist_t *clist_alloc(void);

/* push the item onto the tail of the list */
clist_node_t *clist_tail_push(clist_t *list, void *item);
#else
clist_t *clist_alloc_dm(const char *file, const int line);
clist_node_t *clist_tail_push_dm(clist_t *list, void *item,
				 const char *file, const int line);
#define clist_alloc() clist_alloc_dm(__FILE__, __LINE__)
#define clist_tail_push(list,item) clist_tail_push_dm((list), (item), \
						      __FILE__, __LINE__)
#endif

/* set function to call when a node is removed from the list */
void clist_onremove(clist_t *list, clist_onremove_t onremove);

/* get the node at the head of the list */
clist_node_t *clist_head_node(const clist_t *list);

/* push the item onto the head of the list */
clist_node_t *clist_head_push(clist_t *list, void *item);

/* remove item at head of list, free node */
void *clist_head_pop(clist_t *list);

/* remove item at tail of list, free node */
void *clist_tail_pop(clist_t *list);

/* get item at head of list without removing from list */
void *clist_head_item(const clist_t *list);

/* get item at tail of list without removing from list */
void *clist_tail_item(const clist_t *list);

/* remove item from list, free node */
void *clist_node_pop(clist_t *list, clist_node_t *node);

/* get the item associated with a node */
void *clist_node_item(const clist_node_t *node);

/* get the node after the provided node */
clist_node_t *clist_node_next(const clist_node_t *node);

/* move the head node to the left and return the new head node */
clist_node_t *clist_head_left(clist_t *node);

/* move the head node to the right and return the new head node */
clist_node_t *clist_head_right(clist_t *node);

/* iterate through the list, applying the function on each item */
int clist_foreach(clist_t *list, const clist_foreach_t func, void *param);

/* return how many items are on the list */
int clist_count(const clist_t *list);

/* lock the list, asserting that the list cannot be modified until unlocked */
void clist_lock(clist_t *list);

/* unlock the list */
void clist_unlock(clist_t *list);

/* return lock status of the list */
int clist_islocked(clist_t *list);

/* free the list, including the list structure */
void clist_free(clist_t *list);
void clist_free_cb(clist_t *list, clist_free_t func);

#endif
