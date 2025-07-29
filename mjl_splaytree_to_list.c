/*
 * mjl_splaytree_to_list: take each item out of a splaytree and put in list
 *
 * Copyright (C) 2025 Matthew Luckie. All rights reserved.
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
 * $Id: mjl_splaytree_to_list.c,v 1.1 2025/07/16 19:31:22 mjl Exp $
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#include "mjl_splaytree.h"
#include "mjl_list.h"
#include "mjl_splaytree_to_list.h"

static int slist_cb(slist_t *list, void *item)
{
  return slist_tail_push(list, item) != NULL ? 0 : -1;
}

static int dlist_cb(dlist_t *list, void *item)
{
  return dlist_tail_push(list, item) != NULL ? 0 : -1;
}

slist_t *splaytree_to_slist(splaytree_t *tree, slist_t *out)
{
  slist_t *tmp;
  if((tmp = slist_alloc()) == NULL ||
     splaytree_inorder(tree, (splaytree_inorder_t)slist_cb, tmp) != 0)
    goto err;
  if(out != NULL)
    {
      slist_concat(out, tmp);
      slist_free(tmp);
      return out;
    }
  return tmp;

 err:
  if(tmp != NULL) slist_free(tmp);
  return NULL;
}

dlist_t *splaytree_to_dlist(splaytree_t *tree, dlist_t *out)
{
  dlist_t *tmp;
  if((tmp = dlist_alloc()) == NULL ||
     splaytree_inorder(tree, (splaytree_inorder_t)dlist_cb, tmp) != 0)
    goto err;
  if(out != NULL)
    {
      dlist_concat(out, tmp);
      dlist_free(tmp);
      return out;
    }
  return tmp;

 err:
  if(tmp != NULL) dlist_free(tmp);
  return NULL;
}
