/*
 * scamper_tracelb_text.c
 *
 * Copyright (C) 2008-2011 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
 * Copyright (C) 2022-2025 Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_tracelb_text.c,v 1.16 2025/07/29 01:30:14 mjl Exp $
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
#include "scamper_icmpext.h"
#include "scamper_tracelb.h"
#include "scamper_tracelb_int.h"
#include "scamper_file.h"
#include "scamper_tracelb_text.h"
#include "utils.h"

static void probeset_summary_tostr(scamper_tracelb_probeset_summary_t *sum,
				   char *buf, size_t len, size_t *off)
{
  char dst[64];
  int k;

  if(sum->nullc > 0 && sum->addrc == 0)
    {
      string_concatc(buf, len, off, '*');
      return;
    }

  scamper_addr_tostr(sum->addrs[0], dst, sizeof(dst));
  string_concat2(buf, len, off, "(", dst);
  for(k=1; k<sum->addrc; k++)
    {
      scamper_addr_tostr(sum->addrs[k], dst, sizeof(dst));
      string_concat2(buf, len, off, ", ", dst);
    }
  if(sum->nullc > 0)
    string_concat(buf, len, off, ", *)");
  else
    string_concatc(buf, len, off, ')');

  return;
}

static char *header_tostr(const scamper_tracelb_t *trace)
{
  char buf[192], addr[64];
  size_t off = 0;

  string_concat(buf, sizeof(buf), &off, "tracelb");
  if(trace->src != NULL)
    string_concat2(buf, sizeof(buf), &off, " from ",
		   scamper_addr_tostr(trace->src, addr, sizeof(addr)));
  if(trace->dst != NULL)
    string_concat2(buf, sizeof(buf), &off, " to ",
		   scamper_addr_tostr(trace->dst, addr, sizeof(addr)));
  if(trace->src != NULL || trace->dst != NULL)
    string_concatc(buf, sizeof(buf), &off, ',');
  string_concat_u16(buf, sizeof(buf), &off, " ", trace->nodec);
  string_concat_u16(buf, sizeof(buf), &off, " nodes, ", trace->linkc);
  string_concat_u32(buf, sizeof(buf), &off, " links, ", trace->probec);
  string_concat_u8(buf, sizeof(buf), &off, " probes, ", trace->confidence);
  string_concat(buf, sizeof(buf), &off, "%\n");

  return strdup(buf);
}

char *node_tostr(const scamper_tracelb_node_t *node)
{
  scamper_tracelb_probeset_summary_t *sum;
  scamper_tracelb_probeset_t *set;
  scamper_tracelb_link_t *link;
  char buf[2048], src[64], dst[54];
  size_t off = 0;
  int j;

  assert(node->linkc > 0);

  if(node->addr != NULL)
    scamper_addr_tostr(node->addr, src, sizeof(src));
  else {
    src[0] = '*'; src[1] = '\0';
  }

  if(node->linkc > 1)
    {
      for(j=0; j<node->linkc; j++)
	{
	  if(node->links[j]->to != NULL)
	    string_concat3(buf, sizeof(buf), &off, src, " -> ",
			   scamper_addr_tostr(node->links[j]->to->addr,
					      dst, sizeof(dst)));
	  else
	    string_concat2(buf, sizeof(buf), &off, src, " -> *");
	  string_concatc(buf, sizeof(buf), &off, '\n');
	}
    }
  else
    {
      link = node->links[0];
      if(link->hopc < 1)
	return NULL;

      string_concat2(buf, sizeof(buf), &off, src, " -> ");
      for(j=0; j<link->hopc-1; j++)
	{
	  set = link->sets[j];
	  if((sum = scamper_tracelb_probeset_summary_alloc(set)) == NULL)
	    return NULL;
	  probeset_summary_tostr(sum, buf, sizeof(buf), &off);
	  string_concat(buf, sizeof(buf), &off, " -> ");
	  scamper_tracelb_probeset_summary_free(sum); sum = NULL;
	}

      if(link->to != NULL)
	{
	  scamper_addr_tostr(link->to->addr, dst, sizeof(dst));
	  string_concat(buf, sizeof(buf), &off, dst);
	}
      else
	{
	  set = link->sets[link->hopc-1];
	  if((sum = scamper_tracelb_probeset_summary_alloc(set)) == NULL)
	    return NULL;
	  probeset_summary_tostr(sum, buf, sizeof(buf), &off);
	  scamper_tracelb_probeset_summary_free(sum); sum = NULL;
	}

      string_concatc(buf, sizeof(buf), &off, '\n');
    }

  return strdup(buf);
}

char *scamper_tracelb_totext(const scamper_tracelb_t *trace, size_t *len_out)
{
  char *header = NULL, **nodes = NULL, *str = NULL;
  int i, x, rc = -1, nodec = 0;
  size_t len, off = 0;

  for(i=0; i<trace->nodec; i++)
    {
      if(trace->nodes[i] == NULL || trace->nodes[i]->linkc == 0)
	continue;
      nodec++;
    }

  if((header = header_tostr(trace)) == NULL)
    goto done;
  len = strlen(header) + 1;

  if(nodec > 0)
    {
      if((nodes = malloc_zero(sizeof(char *) * nodec)) == NULL)
	goto done;
      x = 0;
      for(i=0; i<trace->nodec; i++)
	{
	  if(trace->nodes[i] == NULL || trace->nodes[i]->linkc == 0)
	    continue;
	  if((nodes[x] = node_tostr(trace->nodes[i])) == NULL)
	    goto done;
	  len += strlen(nodes[x]);
	  x++;
	}
    }

  if((str = malloc(len)) == NULL)
    goto done;

  string_concat(str, len, &off, header);
  if(nodes != NULL)
    {
      for(i=0; i<nodec; i++)
	string_concat(str, len, &off, nodes[i]);
    }

  assert(off > 0);
  assert(off+1 == len);

  str[off-1] = '\0';

  /* we succeeded */
  rc = 0;

 done:
  if(nodes != NULL)
    {
      for(i=0; i<nodec; i++)
	if(nodes[i] != NULL)
	  free(nodes[i]);
      free(nodes);
    }
  if(header != NULL) free(header);

  if(rc != 0)
    {
      if(str != NULL)
	free(str);
      return NULL;
    }

  if(len_out != NULL)
    *len_out = off;
  return str;
}

int scamper_file_text_tracelb_write(const scamper_file_t *sf,
				    const scamper_tracelb_t *trace, void *p)
{
  /* variables for writing to the file */
  size_t wc, len;
  off_t foff = 0;
  char *str = NULL;
  int fd, rc = -1;

  /*
   * get the current offset into the file, incase the write fails and a
   * truncation is required
   */
  fd = scamper_file_getfd(sf);
  if(fd != STDOUT_FILENO && (foff = lseek(fd, 0, SEEK_CUR)) == -1)
    goto cleanup;

  if((str = scamper_tracelb_totext(trace, &len)) == NULL)
    goto cleanup;
  str[len-1] = '\n';

  /*
   * try and write the string to disk.  if it fails, then truncate the
   * write and fail
   */
  if(write_wrap(fd, str, &wc, len) != 0)
    {
      if(fd != STDOUT_FILENO)
	{
	  if(ftruncate(fd, foff) != 0)
	    goto cleanup;
	}
      goto cleanup;
    }

  rc = 0;

 cleanup:
  if(str != NULL) free(str);
  return rc;
}
