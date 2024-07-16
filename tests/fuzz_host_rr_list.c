/*
 * fuzz_host_rr_list : fuzz RR parsing
 *
 * $Id: fuzz_host_rr_list.c,v 1.1 2024/04/20 00:15:02 mjl Exp $
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

#include "scamper_list.h"
#include "scamper_addr.h"
#include "scamper_host.h"
#include "scamper_host_int.h"

#include "utils.h"
#include "mjl_list.h"

/* function prototype of two normally static functions */
slist_t *host_rr_list(const uint8_t *buf, size_t off, size_t len);
int extract_name(char *name, size_t namelen,
		 const uint8_t *pbuf, size_t plen, size_t off);

static void check(const uint8_t *pktbuf, size_t len)
{
  slist_t *rr_list;
  char name[256];
  int i;

  if((i = extract_name(name, sizeof(name), pktbuf, len, 12)) > 0 &&
     (rr_list = host_rr_list(pktbuf, 12 + 4 + i, len)) != NULL)
    {
      slist_free_cb(rr_list, (slist_free_t)scamper_host_rr_free);
    }
  return;
}

static int input(const char *filename, uint8_t **out, size_t *len)
{
  uint8_t *buf = NULL;
  struct stat sb;
  size_t readc;
  int fd = -1;

  if((fd = open(filename, O_RDONLY)) == -1 ||
     fstat(fd, &sb) != 0)
    goto err;
  *len = sb.st_size;
  if((buf = malloc(*len)) == NULL ||
     read_wrap(fd, buf, &readc, *len) != 0 || readc != *len)
    goto err;

  close(fd);
  *out = buf;
  return 0;

 err:
  if(buf != NULL) free(buf);
  if(fd != -1) close(fd);
  return -1;
}

int main(int argc, char *argv[])
{
  uint8_t *buf = NULL;
  size_t len;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  int assert_mem = 1;
#endif

  if(argc < 2)
    {
      printf("missing input\n");
      return -1;
    }

  if(argc > 2)
    {
#ifdef DMALLOC
      if(strcmp(argv[2], "0") == 0)
	assert_mem = 0;
#else
      fprintf(stderr, "not compiled with dmalloc support\n");
      return -1;
#endif
    }

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

  if(input(argv[1], &buf, &len) != 0)
    return -1;

  check(buf, len);

  if(buf != NULL)
    free(buf);

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(assert_mem != 0)
    assert(start_mem == stop_mem);
#endif

  return 0;
}
