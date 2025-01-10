/*
 * splay tree routines
 * By Matthew Luckie
 * U of Waikato 0657.317b 1999
 *
 * Copyright (C) 1999-2024 Matthew Luckie. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef MJLSPLAYTREE_DEBUG
#undef NDEBUG
#endif

#include <stdlib.h>
#include <assert.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#include "mjl_splaytree.h"

/*
 * the splay tree algorithm needs a simple stack to do the work.
 * the implementations of these functions is found at the bottom of this
 * file.
 */
#ifndef SPLAYTREE_STACK_NODEC
#define SPLAYTREE_STACK_NODEC 512
#endif
typedef struct splaytree_stack splaytree_stack_t;
struct splaytree_stack
{
  splaytree_node_t  *nodes[SPLAYTREE_STACK_NODEC];
  splaytree_stack_t *next;
  int                i;
};

/*
 * splay tree node data structure
 * conveniently hidden from users of the splay tree.
 */
struct splaytree_node
{
  void              *item;
  splaytree_node_t  *left;
  splaytree_node_t  *right;
};

struct splaytree
{
  splaytree_node_t  *head;
  int                size;
  splaytree_cmp_t    cmp;
};

#ifdef HAVE_FUNC_ATTRIBUTE_NONNULL
static splaytree_node_t *stack_pop(splaytree_stack_t **stack)
  __attribute__ ((nonnull));
static int stack_push(splaytree_stack_t **stack, splaytree_node_t *node)
  __attribute__ ((nonnull));
#else
static splaytree_node_t *stack_pop(splaytree_stack_t **stack);
static int stack_push(splaytree_stack_t **stack, splaytree_node_t *node);
#endif
static void stack_free(splaytree_stack_t *stack);

#ifdef MJLSPLAYTREE_DEBUG
static void splaytree_assert2(const splaytree_t *tree,
			      const splaytree_node_t *node)
{
  int i;

  if(node != NULL)
    {
      if(node->left != NULL)
	{
	  i = tree->cmp(node->left->item, node->item);
	  assert(i < 0);
	  splaytree_assert2(tree, node->left);
	}

      if(node->right != NULL)
	{
	  i = tree->cmp(node->right->item, node->item);
	  assert(i > 0);
	  splaytree_assert2(tree, node->right);
	}
    }
  return;
}

static void splaytree_assert(const splaytree_t *tree)
{
  splaytree_assert2(tree, tree->head);
  return;
}
#else
#define splaytree_assert(tree)((void)0)
#endif

/*
 * splaytree_rotate
 *
 * perform the generic treenode-rotate algorithm.
 */
static void splaytree_rotate(splaytree_node_t *above, splaytree_node_t *below)
{
  splaytree_node_t *temp;

  /*
   * above and below must be valid treenode pointers.
   * above must point to the below node
   */
  assert(above != NULL);
  assert(below != NULL);
  assert(above->left == below || above->right == below);

  /*
   * check to see if the below node is to the left of the above or to
   * the right
   */
  if(above->left == below)
    {
      temp = below->right;
      below->right = above;
      above->left = temp;
    }
  else
    {
      temp = below->left;
      below->left = above;
      above->right = temp;
    }

  return;
}

/*
 * splaytree_splay2
 *
 * appropriately splay the treenodes passed in so that the child is moved
 * higher than the other nodes passed in
 */
static void splaytree_splay2(splaytree_node_t *child,
			     splaytree_node_t *parent,
			     splaytree_node_t *grandparent)
{
  /* pre-condition: grandparent points to parent, parent points to child */
  assert(child != NULL);
  assert(parent == NULL || (parent->left == child || parent->right == child));
  assert(grandparent == NULL ||
	 (grandparent->left == parent || grandparent->right == parent));

  /* case 0: access node is root */
  if(parent == NULL)
    {
      return;
    }

  /* case 1: parent is root */
  else if(grandparent == NULL)
    {
      splaytree_rotate(parent, child);
    }

  /*
   * case 2: zig zig - p is not the root and the child and the parent are both
   * left (right) children
   */
  else if((parent->left  == child && grandparent->left  == parent) ||
	  (parent->right == child && grandparent->right == parent))
    {
      splaytree_rotate(grandparent, parent);
      splaytree_rotate(parent, child);
    }

  /*
   * case 3: zig zag - p is not the root and the child is a left(right) child
   * and parent is a right(left) child
   */
  else if((parent->left  == child && grandparent->right == parent) ||
	  (parent->right == child && grandparent->left  == parent))
    {
      if(grandparent->left == parent)
	{
	  splaytree_rotate(parent, child);
	  grandparent->left = child;
	  splaytree_rotate(grandparent, child);
	}
      else
	{
	  splaytree_rotate(parent, child);
	  grandparent->right = child;
	  splaytree_rotate(grandparent, child);
	}
    }

  return;
}

/*
 * splaytree_splay
 *
 * coordinate the calls to splaytree_splay2.
 * the stack contains, in order, the path to the child so that the nodes can
 * be splayed.
 */
#ifdef HAVE_FUNC_ATTRIBUTE_NONNULL
static void splaytree_splay(splaytree_t *tree, splaytree_stack_t **stack)
  __attribute__ ((nonnull));
#endif

static void splaytree_splay(splaytree_t *tree, splaytree_stack_t **stack)
{
  splaytree_node_t *child, *parent, *grandparent, *keep;

  child       = stack_pop(stack);
  parent      = stack_pop(stack);
  grandparent = stack_pop(stack);

  /* there has to be at least one entry in the stack */
  assert(child != NULL);

  /* is there only one node in the tree */
  if(parent == NULL)
    {
      tree->head = child;
      return;
    }

  /* splay the node */
  splaytree_splay2(child, parent, grandparent);

  /* it was a simple swap at the root */
  if(grandparent == NULL)
    {
      tree->head = child;
      return;
    }

  /*
   * remember the grandparent so that we can figure out where to relink the
   * splayed child to
   */
  keep = grandparent;

  /* just loop and we will break out when we need to */
  for(;;)
    {
      /* get the parent nodes to the child */
      parent      = stack_pop(stack);
      grandparent = stack_pop(stack);

      /*
       * if the child node is now at the root, break out as the splay is
       * complete
       */
      if(parent == NULL)
	break;

      assert(parent->left == keep || parent->right == keep);

      /*
       * figure out where to relink the child to
       * (as the grandparent in keep is now down the tree)
       */
      if(parent->left == keep)
	parent->left = child;
      else
	parent->right = child;

      /* splay now */
      splaytree_splay2(child, parent, grandparent);

      if(grandparent == NULL)
	break;

      keep = grandparent;
    }

  /* return the new root of the tree */
  tree->head = child;
  return;
}

/*
 * splaytree_node_alloc
 *
 * creates/mallocs a node and initialises the contents of the node ready to
 * insert to the tree
 */
#ifndef DMALLOC
static splaytree_node_t *splaytree_node_alloc(const void *item)
#else
static splaytree_node_t *splaytree_node_alloc(const void *item,
					      const char *file, const int line)
#endif
{
  splaytree_node_t *node;
  size_t len = sizeof(splaytree_node_t);

#ifndef DMALLOC
  node = (splaytree_node_t *)malloc(len);
#else
  node = (splaytree_node_t *)dmalloc_malloc(file, line, len,
					    DMALLOC_FUNC_MALLOC, 0, 0);
#endif

  if(node != NULL)
    {
      node->left    = NULL;
      node->right   = NULL;
      node->item    = (void *)item;
    }

  return node;
}

/*
 * splaytree_insert2
 *
 * insert the item into the tree.
 * returns 0 if inserted, -1 on error.
 */
#ifndef DMALLOC
static int splaytree_insert2(splaytree_t *tree, const void *item,
			     splaytree_stack_t **stack)
#else
static int splaytree_insert2(splaytree_t *tree, const void *item,
			     splaytree_stack_t **stack,
			     const char *file, const int line)
#endif
{
  splaytree_node_t *tn, *node;
  int i;

  tn = tree->head;

  for(;;)
    {
      /* put the node into the insert path and try the next level */
      if(stack_push(stack, tn) != 0)
	return -1;

      /* see whether the data belongs to the left, right, or is a duplicate */
      i = tree->cmp(item, tn->item);
      if(i < 0)
	{
	  if(tn->left != NULL)
	    {
	      tn = tn->left;
	      continue;
	    }

	  /* insert the item into the tree here */
#ifndef DMALLOC
	  if((node = splaytree_node_alloc(item)) == NULL)
#else
	  if((node = splaytree_node_alloc(item, file, line)) == NULL)
#endif
	    return -1;

	  if(stack_push(stack, node) != 0)
	    {
	      free(node);
	      return -1;
	    }

	  tn->left = node;
	  break;
	}
      else if(i > 0)
	{
	  if(tn->right != NULL)
	    {
	      tn = tn->right;
	      continue;
	    }

#ifndef DMALLOC
	  if((node = splaytree_node_alloc(item)) == NULL)
#else
	  if((node = splaytree_node_alloc(item, file, line)) == NULL)
#endif
	    return -1;

	  if(stack_push(stack, node) != 0)
	    {
	      free(node);
	      return -1;
	    }

	  tn->right = node;
	  break;
	}
      else
	{
	  /* the data already exists in the tree: do not add it */
	  return -1;
	}
    }

  return 0;
}

/*
 * splaytree_insert
 *
 * insert a value into the splay tree, and return with the tree splayed on
 * that value.  return the node of the item.
 *
 */
#ifndef DMALLOC
splaytree_node_t *splaytree_insert(splaytree_t *tree, const void *item)
#else
splaytree_node_t *splaytree_insert_dm(splaytree_t *tree, const void *item,
				      const char *file, const int line)
#endif
{
  splaytree_stack_t *stack = NULL;

  assert(tree != NULL);

  splaytree_assert(tree);

  /*
   * if the tree actually has something in it, then we need to
   * find the place to insert the node and splay on that.
   */
  if(tree->head != NULL)
    {
      /*
       * try and insert the item.  can't insert it if an item matching this
       * one is already there
       */
#ifndef DMALLOC
      if(splaytree_insert2(tree, item, &stack) != 0)
#else
      if(splaytree_insert2(tree, item, &stack, file, line) != 0)
#endif
	goto err;

      splaytree_splay(tree, &stack);
    }
  else
    {
#ifndef DMALLOC
      if((tree->head = splaytree_node_alloc(item)) == NULL)
#else
      if((tree->head = splaytree_node_alloc(item, file, line)) == NULL)
#endif
	goto err;
    }

  tree->size++;

  splaytree_assert(tree);
  assert(stack == NULL);

  return tree->head;

 err:
  stack_free(stack);
  return NULL;
}

/*
 * splaytree_find2
 *
 * find the node with the data item matching.  returns the node, if found.
 */
static int splaytree_find2(splaytree_t *tree, const void *item,
			   splaytree_node_t **node, splaytree_stack_t **stack)
{
  splaytree_node_t *tn;
  int i;

  tn = tree->head;
  while(tn != NULL)
    {
      /*
       * try and push the node onto the stack.
       * if we don't then we can't splay the node to the top of the tree, so
       * we fail.
       */
      if(stack_push(stack, tn) != 0)
	return -1;

      /* determine the next node to visit */
      i = tree->cmp(item, tn->item);
      if(i < 0)
	tn = tn->left;
      else if(i > 0)
	tn = tn->right;
      else
	break;
    }

  *node = tn;
  return 0;
}

/*
 * splaytree_find
 *
 * finds an item in the tree, and then splays the tree on that value
 */
void *splaytree_find(splaytree_t *tree, const void *item)
{
  splaytree_stack_t *stack = NULL;
  splaytree_node_t *node;

  if(tree == NULL || tree->head == NULL)
    return NULL;

  splaytree_assert(tree);
  if(splaytree_find2(tree, item, &node, &stack) != 0 || node == NULL)
    {
      stack_free(stack);
      return NULL;
    }

  splaytree_splay(tree, &stack);
  splaytree_assert(tree);
  assert(stack == NULL);
  assert(tree->head == node);
  return node->item;
}

/*
 * splaytree_find_ro
 *
 * a read-only version of splaytree_find, which finds an item in the
 * tree, and returns it without splaying the tree.
 */
void *splaytree_find_ro(const splaytree_t *tree, const void *item)
{
  splaytree_node_t *tn;
  int i;

  if(tree == NULL)
    return NULL;
  splaytree_assert(tree);

  tn = tree->head;
  while(tn != NULL)
    {
      i = tree->cmp(item, tn->item);
      if(i < 0)
	tn = tn->left;
      else if(i > 0)
	tn = tn->right;
      else
	return tn->item;
    }

  return NULL;
}

/*
 * splaytree_remove
 *
 * remove the first item in the splaytree
 */
static int splaytree_remove(splaytree_t *tree)
{
  splaytree_stack_t *stack = NULL;
  splaytree_node_t *node;
  splaytree_node_t *l, *r;
  splaytree_node_t *temp;

  node = tree->head;
  l = node->left;
  r = node->right;

  /*
   * search for the right most node in the left tree
   * if there are no nodes on the left hand side of the tree, then we just
   * need to shift the head of the tree to whatever is there on the right
   * of it.
   */
  if(l != NULL)
    {
      if(stack_push(&stack, l) != 0)
	goto err;

      temp = l;
      while(temp->right != NULL)
	{
	  if(stack_push(&stack, temp->right) != 0)
	    goto err;
	  temp = temp->right;
	}

      /* bring this node to the top of the tree with a splay operation */
      splaytree_splay(tree, &stack);

      /*
       * as the right most node on the left branch has no nodes on the right
       * branch, we connect the right hand branch to it
       */
      tree->head->right = r;
    }
  else
    {
      tree->head = r;
    }

  tree->size--;
  free(node);
  assert(stack == NULL);

  return 0;

 err:
  stack_free(stack);
  return -1;
}

/*
 * splaytree_remove_item
 *
 * remove an item from the tree that matches the particular key
 */
int splaytree_remove_item(splaytree_t *tree, const void *item)
{
  splaytree_stack_t *stack = NULL;
  splaytree_node_t *node;

  /*
   * find the node that we are supposed to delete.
   * if we can't find it, then the remove operation has failed.
   */
  if(splaytree_find2(tree, item, &node, &stack) != 0 || node == NULL)
    {
      stack_free(stack);
      return -1;
    }

  /*
   * now that we've found it, splay the tree to bring the node we are to
   * delete to the top of the tree and then delete it.
   */
  splaytree_splay(tree, &stack);
  assert(stack == NULL);
  assert(tree->head == node);
  return splaytree_remove(tree);
}

/*
 * splaytree_remove_node
 *
 * remove a specific node from the splay tree
 */
int splaytree_remove_node(splaytree_t *tree, splaytree_node_t *node)
{
  splaytree_stack_t *stack = NULL;
  splaytree_node_t *found_node;

  /*
   * find the path to the node that we are supposed to delete.  the node
   * that we find has to match what was passed in
   */
  if(splaytree_find2(tree, node->item, &found_node, &stack) != 0 ||
     found_node != node)
    {
      stack_free(stack);
      return -1;
    }

  /*
   * now that we've found it, splay the tree to bring the node we are to
   * delete to the top of the tree and then delete it.
   */
  splaytree_splay(tree, &stack);
  assert(stack == NULL);
  assert(tree->head == node);
  return splaytree_remove(tree);
}

/*
 * splaytree_findclosest
 *
 * find a value in the tree as close to the specified one as possible
 */
void *splaytree_findclosest(splaytree_t *tree, const void *item,
			    splaytree_diff_t diff)
{
  splaytree_stack_t *stack = NULL;
  splaytree_node_t *ret;
  splaytree_node_t *first, *second;
  int               first_diff, second_diff;

  if(tree == NULL || tree->head == NULL)
    return NULL;

  if(splaytree_find2(tree, item, &ret, &stack) != 0)
    {
      stack_free(stack);
      return NULL;
    }

  /* wow, the value we are looking for is actually in the tree! */
  if(ret != NULL)
    {
      splaytree_splay(tree, &stack);
      assert(ret == tree->head);
      assert(stack == NULL);
      return tree->head->item;
    }

  /*
   * we need to get the last two items off the stack and figure out which
   * one of the two is the closest to the one we are looking for
   */
  first  = stack_pop(&stack);
  second = stack_pop(&stack);

  /* need at least one item in the stack if tree->head != NULL */
  assert(first != NULL);

  /* if there is only one item in the stack, splay? on it and return it */
  if(second == NULL)
    {
      if(stack_push(&stack, first) != 0)
	return NULL;
      splaytree_splay(tree, &stack);
      assert(stack == NULL);
      return tree->head->item;
    }

  /* work out which one is closer to the value we are looking for */
  first_diff  = abs(diff(first->item,  item));
  second_diff = abs(diff(second->item, item));

  /*
   * if the first item is closer than the second, put the first back on the
   * stack and the splay on that
   * else put them both back on and splay on that
   */
  if(stack_push(&stack, second) != 0 ||
     (second_diff > first_diff && stack_push(&stack, first) != 0))
    {
      stack_free(stack);
      return NULL;
    }

  splaytree_splay(tree, &stack);
  assert(stack == NULL);
  return tree->head->item;
}

/*
 * splaytree_depth2
 *
 * recursive function to return the depth of the splay tree.
 */
static int splaytree_depth2(const splaytree_node_t *tn)
{
  int left = 0;
  int right = 0;

  if(tn == NULL) return 0;

  if(tn->left != NULL)
    left = splaytree_depth2(tn->left) + 1;
  if(tn->right != NULL)
    right = splaytree_depth2(tn->right) + 1;

  return (left > right) ? left : right;
}

/*
 * splaytree_depth
 *
 * returns the longest path (the depth) of the splay tree
 */
int splaytree_depth(const splaytree_t *tree)
{
  if(tree == NULL) return -1;
  if(tree->head == NULL) return 0;
  return splaytree_depth2(tree->head) + 1;
}

/*
 * splaytree_free2
 *
 * iterative function used to free a splaytree's nodes.
 */
static void splaytree_free2(splaytree_t *tree, splaytree_free_t free_ptr)
{
  splaytree_stack_t *stack = NULL;
  splaytree_node_t *tn = tree->head, *tn2;

  while(tn != NULL)
    {
      if(tn->left != NULL)
	{
	  tn2 = tn->left; tn->left = NULL;
	  stack_push(&stack, tn);
	  tn = tn2;
	  continue;
	}

      if(tn->right != NULL)
	{
	  tn2 = tn->right; tn->right = NULL;
	  stack_push(&stack, tn);
	  tn = tn2;
	  continue;
	}

      if(free_ptr != NULL) free_ptr(tn->item);
      free(tn);

      tn = stack_pop(&stack);
    }

  return;
}

/*
 * splaytree_free
 *
 * dellocate the splaytree
 */
void splaytree_free(splaytree_t *tree, splaytree_free_t free_ptr)
{
  if(tree == NULL) return;
  splaytree_free2(tree, free_ptr);
  free(tree);
  return;
}

void splaytree_empty(splaytree_t *tree, splaytree_free_t free_ptr)
{
  if(tree == NULL) return;
  splaytree_free2(tree, free_ptr);
  tree->head = NULL;
  tree->size = 0;
  return;
}

void *splaytree_gethead(splaytree_t *tree)
{
  if(tree == NULL || tree->head == NULL)
    {
      return NULL;
    }

  return tree->head->item;
}

void *splaytree_pophead(splaytree_t *tree)
{
  void *item;
  if(tree->head == NULL)
    return NULL;

  item = tree->head->item;
  if(splaytree_remove(tree) != 0)
    return NULL;

  return item;
}

/*
 * splaytree_getrmlb
 *
 * return the right-most item on the left branch of the tree
 */
void *splaytree_getrmlb(splaytree_t *tree)
{
  splaytree_node_t *tn;

  if(tree == NULL || tree->head == NULL || tree->head->left == NULL)
    {
      return NULL;
    }

  tn = tree->head->left;
  while(tn->right != NULL)
    {
      tn = tn->right;
    }

  return tn->item;
}

/*
 * splaytree_getlmrb
 *
 * return the left-most item on the right branch of the tree
 */
void *splaytree_getlmrb(splaytree_t *tree)
{
  splaytree_node_t *tn;

  if(tree == NULL || tree->head == NULL || tree->head->right == NULL)
    {
      return NULL;
    }

  tn = tree->head->right;
  while(tn->left != NULL)
    {
      tn = tn->left;
    }

  return tn->item;
}

/*
 * splaytree_display2
 *
 * recursive function to print the contents of the splaytree, ascii-like.
 */
static void splaytree_display2(splaytree_node_t *tn, splaytree_display_t disp,
			       int pad)
{
  if(tn != NULL)
    {
      splaytree_display2(tn->left, disp, pad+1);
      disp(tn->item, pad);
      splaytree_display2(tn->right, disp, pad+1);
    }

  return;
}

/*
 * splaytree_display
 *
 * print the contents of the splaytree.
 */
void splaytree_display(splaytree_t *tree, splaytree_display_t disp)
{
  if(tree != NULL && disp != NULL)
    {
      splaytree_display2(tree->head, disp, 1);
    }
  return;
}

/*
 * splaytree_inorder
 *
 * call a user-provided function on all items in the splay tree in order
 */
void splaytree_inorder(splaytree_t *tree, splaytree_inorder_t func, void *in)
{
  splaytree_stack_t *stack = NULL;
  splaytree_node_t *tn;

  if(tree == NULL || func == NULL)
    return;

  tn = tree->head;

  for(;;)
    {
      if(tn != NULL)
	{
	  stack_push(&stack, tn);
	  tn = tn->left;
	}
      else if((tn = stack_pop(&stack)) != NULL)
	{
	  func(in, tn->item);
	  tn = tn->right;
	}
      else break;
    }

  return;
}

/*
 * splaytree_alloc
 *
 * allocate a splaytree
 */
#ifndef DMALLOC
splaytree_t *splaytree_alloc(splaytree_cmp_t cmp)
#else
splaytree_t *splaytree_alloc_dm(splaytree_cmp_t cmp,
				const char *file, const int line)
#endif
{
  splaytree_t *tree;
  size_t len = sizeof(splaytree_t);

#ifndef DMALLOC
  tree = (splaytree_t *)malloc(len);
#else
  tree = (splaytree_t *)dmalloc_malloc(file,line,len,DMALLOC_FUNC_MALLOC,0,0);
#endif

  if(tree == NULL)
    goto err;

  tree->head     = NULL;
  tree->size     = 0;
  tree->cmp      = cmp;
  return tree;

 err:
  if(tree != NULL)
    free(tree);
  return NULL;
}

/*
 * splaytree_count
 *
 * return the number of items in the splaytree.
 */
int splaytree_count(const splaytree_t *tree)
{
  if(tree == NULL) return -1;
  return tree->size;
}

static int stack_push(splaytree_stack_t **s, splaytree_node_t *node)
{
  splaytree_stack_t *p = *s;

  if(p == NULL || p->i == SPLAYTREE_STACK_NODEC)
    {
      if((p = malloc(sizeof(splaytree_stack_t))) == NULL)
	return -1;
      p->next = *s;
      p->i = 0;
      *s = p;
    }

  assert(p->i >= 0);
  assert(p->i < SPLAYTREE_STACK_NODEC);
  p->nodes[p->i++] = node;

  return 0;
}

static splaytree_node_t *stack_pop(splaytree_stack_t **s)
{
  splaytree_stack_t *p;
  splaytree_node_t *n;

  if(*s == NULL)
    return NULL;

  p = *s;
  assert(p->i > 0);
  assert(p->i <= SPLAYTREE_STACK_NODEC);
  n = p->nodes[--p->i];

  if(p->i == 0)
    {
      *s = p->next;
      free(p);
    }

  return n;
}

static void stack_free(splaytree_stack_t *stack)
{
  splaytree_stack_t *next;
  while(stack != NULL)
    {
      next = stack->next;
      free(stack);
      stack = next;
    }
  return;
}
