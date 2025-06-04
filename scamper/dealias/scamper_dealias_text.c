/*
 * scamper_dealias_text.c
 *
 * Copyright (C) 2008-2010 The University of Waikato
 * Copyright (C) 2013-2025 Matthew Luckie
 * Author: Matthew Luckie
 *
 * $Id: scamper_dealias_text.c,v 1.8 2025/05/17 06:58:48 mjl Exp $
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
#include "scamper_file.h"
#include "scamper_dealias.h"
#include "scamper_dealias_int.h"
#include "scamper_dealias_text.h"
#include "utils.h"

#include "scamper_debug.h"

char *scamper_dealias_totext(const scamper_dealias_t *dealias, size_t *len_out)
{
  scamper_dealias_ally_t *ally;
  char *str, buf[256], x[64];
  size_t off = 0;

  if(SCAMPER_DEALIAS_METHOD_IS_ALLY(dealias))
    {
      ally = dealias->data;
      scamper_addr_tostr(ally->probedefs[0]->dst, x, sizeof(x));
      string_concat(buf, sizeof(buf), &off, x);
      string_concatc(buf, sizeof(buf), &off, ' ');

      scamper_addr_tostr(ally->probedefs[1]->dst, x, sizeof(x));
      string_concat(buf, sizeof(buf), &off, x);
      string_concatc(buf, sizeof(buf), &off, ' ');

      if(dealias->result == SCAMPER_DEALIAS_RESULT_ALIASES)
	string_concat(buf, sizeof(buf), &off, "aliases");
      else if(dealias->result == SCAMPER_DEALIAS_RESULT_NOTALIASES)
	string_concat(buf, sizeof(buf), &off, "not aliases");
      else if(dealias->result == SCAMPER_DEALIAS_RESULT_NONE)
	string_concat(buf, sizeof(buf), &off, "none");
      else
	string_concat_u8(buf, sizeof(buf), &off, NULL, dealias->result);

      string_concatc(buf, sizeof(buf), &off, '\n');
    }

  if(off > 0)
    str = memdup(buf, off);
  else
    str = strdup("");

  if(len_out != NULL)
    *len_out = off;
  return str;
}

int scamper_file_text_dealias_write(const scamper_file_t *sf,
				    const scamper_dealias_t *dealias, void *p)
{
  size_t wc, len;
  off_t off = 0;
  char *str = NULL;
  int fd, rc = -1;

  fd = scamper_file_getfd(sf);
  if(fd != STDOUT_FILENO && (off = lseek(fd, 0, SEEK_CUR)) == -1)
    goto cleanup;

  if((str = scamper_dealias_totext(dealias, &len)) == NULL)
    goto cleanup;

  /*
   * try and write the string to disk.  if it fails, then truncate the
   * write and fail
   */
  if(len > 0 && write_wrap(fd, str, &wc, len) != 0)
    {
      if(fd != STDOUT_FILENO)
	{
	  if(ftruncate(fd, off) != 0)
	    goto cleanup;
	}
      goto cleanup;
    }

  rc = 0;

 cleanup:
  if(str != NULL) free(str);
  return rc;
}
