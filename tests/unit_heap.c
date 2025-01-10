/*
 * unit_heap : unit tests for the heap structure
 *
 * $Id: unit_heap.c,v 1.2 2024/12/29 18:38:15 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024 Matthew Luckie
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

#include "mjl_heap.h"

static const char *words[] = {
  "apple",
  "banana",
  "carrot",
  "dough",
  "eggplant",
  "fig",
  "grape",
  "icecream",
  "lemon",
  "melon",
  "nectarine",
  "octopus",
  "pineapple",
  "rhubarb",
};

static int orders[][14] = {
  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13},
  {13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
  {1, 3, 5, 7, 9, 11, 13, 0, 2, 4, 6, 8, 10, 12},
  {1, 6, 13, 8, 5, 9, 0, 12, 4, 10, 2, 11, 7, 3},
  {8, 6, 5, 10, 13, 7, 12, 2, 0, 4, 11, 3, 9, 1},
  {9, 7, 5, 12, 1, 0, 13, 2, 11, 10, 4, 3, 6, 8},
  {0, 5, 10, 9, 7, 1, 3, 11, 8, 6, 4, 12, 2, 13},
  {0, 6, 11, 9, 1, 3, 12, 13, 5, 10, 4, 2, 7, 8},
  {0, 4, 5, 8, 6, 2, 3, 9, 13, 1, 10, 11, 12, 7},
  {1, 5, 4, 6, 3, 9, 7, 11, 0, 13, 8, 10, 12, 2},
  {8, 11, 13, 0, 4, 2, 5, 10, 1, 12, 9, 3, 6, 7},
  {9, 11, 4, 8, 3, 13, 1, 10, 5, 12, 2, 6, 0, 7},
  {13, 12, 9, 4, 1, 3, 8, 10, 0, 2, 11, 6, 5, 7},
  {11, 2, 4, 13, 6, 8, 1, 5, 3, 0, 12, 7, 9, 10},
  {8, 1, 0, 7, 4, 10, 6, 13, 9, 11, 12, 3, 5, 2},
  {0, 4, 2, 1, 11, 7, 10, 5, 6, 12, 8, 9, 13, 3},
  {4, 6, 3, 7, 11, 2, 12, 9, 13, 8, 0, 5, 10, 1},
  {13, 6, 4, 10, 5, 9, 7, 3, 8, 12, 1, 0, 11, 2},
  {6, 5, 11, 12, 2, 8, 3, 10, 1, 4, 13, 7, 9, 0},
  {5, 2, 13, 8, 10, 12, 6, 4, 0, 9, 11, 3, 7, 1},
};

typedef struct inorder
{
  char *items[14];
  int   i;
} inorder_t;

static int cmp(const char *a, const char *b)
{
  return strcmp(b, a);
}

/*
 * test_1_it
 *
 * add and remove individual items, checking that
 * the structure remains intact
 */
static int test_1_it(int *insert)
{
  heap_t *heap;
  heap_node_t *nodes[14];
  inorder_t set;
  const char *word;
  char *str;
  int x;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

  /* initial import into tree */
  if((heap = heap_alloc((heap_cmp_t)cmp)) == NULL)
    return -1;

  for(x=0; x<14; x++)
    {
      word = words[insert[x]];
      if((nodes[insert[x]] = heap_insert(heap, (void *)word)) == NULL)
	return -1;
    }

  /* remove items in sorted order */
  memset(&set, 0, sizeof(set));
  while((str = heap_remove(heap)) != NULL)
    set.items[set.i++] = str;
  for(x=0; x<14; x++)
    {
      if(strcmp(set.items[x], words[x]) != 0)
	return -1;
    }

  /* we're done */
  heap_free(heap, NULL);

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(start_mem != stop_mem)
    {
      printf("memory leak\n");
      return -1;
    }
#endif

  return 0;
}

static int test_1(void)
{
  int i, j;
  for(i=0; i<20; i++)
    {
      for(j=0; j<20; j++)
	{
	  if(test_1_it(orders[i]) != 0)
	    return -1;
	}
    }
  return 0;
}

static int test_2_it(int *insert, int *order)
{
  heap_t *heap;
  heap_node_t *nodes[14], *node;
  const char *word;
  char *str;
  int x, y;
  int rc = -1;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

  /* initial import into tree */
  if((heap = heap_alloc((heap_cmp_t)cmp)) == NULL)
    return -1;

  for(x=0; x<14; x++)
    {
      word = words[insert[x]];
      if((nodes[insert[x]] = heap_insert(heap, (void *)word)) == NULL)
	goto done;
    }

  /* remove items, checking the correctness of the head item */
  for(x=0; x<14; x++)
    {
      node = nodes[order[x]];
      heap_delete(heap, node);
      if(heap_count(heap) != 14 - x - 1)
	goto done;
      nodes[order[x]] = NULL;

      str = heap_head_item(heap);
      for(y=0; y<14; y++)
	{
	  if(nodes[y] != NULL)
	    {
	      if(strcmp(words[y], str) != 0)
		goto done;
	      break;
	    }
	}
    }

  rc = 0;

 done:

  /* we're done */
  heap_free(heap, NULL);

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(rc != 0 && start_mem != stop_mem)
    {
      printf("memory leak\n");
      return rc;
    }
#endif

  return rc;
}

static int test_2(void)
{
  int i, j;
  for(i=0; i<20; i++)
    {
      for(j=0; j<20; j++)
	{
	  if(test_2_it(orders[i], orders[j]) != 0)
	    return -1;
	}
    }
  return 0;
}

int main(int argc, char *argv[])
{
  if(test_1() != 0 || test_2() != 0)
    return -1;
  printf("OK\n");
  return 0;
}
