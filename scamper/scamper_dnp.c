/*
 * scamper_dnp.c
 *
 * $Id: scamper_dnp.c,v 1.5 2025/10/16 00:06:07 mjl Exp $
 *
 * Copyright (C) 2025 The Regents of the University of California
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

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_addr_int.h"
#include "scamper_dnp.h"
#include "scamper_priv.h"
#include "scamper_debug.h"

#include "mjl_prefixtree.h"
#include "utils.h"

#ifdef BUILDING_SCAMPER

static prefixtree_t *pfx4 = NULL;
static prefixtree_t *pfx6 = NULL;
static int           line = 0;

static int dnp_line(char *str, void *param)
{
  prefixtree_t **trees = (prefixtree_t **)param;
  struct sockaddr_storage sas;
  struct sockaddr *sa = (struct sockaddr *)&sas;
  struct in_addr *in4;
  struct in6_addr *in6;
  prefix4_t *pf4 = NULL;
  prefix6_t *pf6 = NULL;
  char *pf;
  long lo;

  line++;

  if(str[0] == '#' || str[0] == '\0')
    return 0;

  string_nullterm_char(str, '/', &pf);

  if(sockaddr_compose_str(sa, AF_UNSPEC, str, 0) != 0 ||
     (sa->sa_family != AF_INET && sa->sa_family != AF_INET6))
    {
      printerror_msg(__func__, "invalid network address on line %d", line);
      goto err;
    }

  if(pf != NULL)
    {
      if(string_isdigit(pf) == 0 || string_tolong(pf, &lo) != 0 || lo < 1)
	{
	  printerror_msg(__func__, "invalid prefix length on line %d", line);
	  goto err;
	}
      if(sa->sa_family == AF_INET)
	{
	  if(prefix4_isvalid(&((struct sockaddr_in *)sa)->sin_addr, lo) == 0)
	    {
	      printerror_msg(__func__, "invalid IPv4 prefix on line %d", line);
	      goto err;
	    }
	}
      else
	{
	  if(prefix6_isvalid(&((struct sockaddr_in6 *)sa)->sin6_addr, lo) == 0)
	    {
	      printerror_msg(__func__, "invalid IPv6 prefix on line %d", line);
	      goto err;
	    }
	}
    }
  else
    {
      if(sa->sa_family == AF_INET)
	lo = 32;
      else
	lo = 128;
    }

  if(sa->sa_family == AF_INET)
    {
      if(trees[0] == NULL && (trees[0] = prefixtree_alloc4()) == NULL)
	{
	  printerror(__func__, "could not alloc pfx4 tree");
	  goto err;
	}
      in4 = &((struct sockaddr_in *)sa)->sin_addr;

      /* duplicate of a prefix already in the tree */
      if(prefixtree_find_exact4(trees[0], in4, lo) != NULL)
	return 0;

      if((pf4 = prefix4_alloc(in4, lo, NULL)) == NULL ||
	 prefixtree_insert4(trees[0], pf4) == NULL)
	{
	  printerror(__func__, "could not add pfx4 on line %d to tree", line);
	  goto err;
	}
      prefix4_setptr(pf4, pf4);
      pf4 = NULL;
    }
  else
    {
      if(trees[1] == NULL && (trees[1] = prefixtree_alloc6()) == NULL)
	{
	  printerror(__func__, "could not alloc pfx6 tree");
	  goto err;
	}
      in6 = &((struct sockaddr_in6 *)sa)->sin6_addr;

      /* duplicate of a prefix already in the tree */
      if(prefixtree_find_exact6(trees[1], in6, lo) != NULL)
	return 0;

      if((pf6 = prefix6_alloc(in6, lo, NULL)) == NULL ||
	 prefixtree_insert6(trees[1], pf6) == NULL)
	{
	  printerror(__func__, "could not add pfx6 on line %d to tree", line);
	  goto err;
	}
      prefix6_setptr(pf6, pf6);
      pf6 = NULL;
    }

  return 0;

 err:
  if(pf4 != NULL) prefix4_free(pf4);
  if(pf6 != NULL) prefix6_free(pf6);
  return -1;
}

int scamper_dnp_reload(const char **files, size_t filec)
{
  prefixtree_t *trees[2];
  int fd = -1;
  size_t i;

  trees[0] = NULL;
  trees[1] = NULL;

  for(i=0; i<filec; i++)
    {
      line = 0;
      if((fd = scamper_priv_open(files[i], O_RDONLY, 0)) == -1 ||
	 fd_lines(fd, dnp_line, trees) != 0)
	goto err;
      close(fd);
    }

  prefixtree_free_cb(pfx4, (prefix_free_t)prefix4_free); pfx4 = trees[0];
  prefixtree_free_cb(pfx6, (prefix_free_t)prefix6_free); pfx6 = trees[1];

  return 0;

 err:
  if(fd != -1) close(fd);
  if(trees[0] != NULL)
    prefixtree_free_cb(trees[0], (prefix_free_t)prefix4_free);
  if(trees[1] != NULL)
    prefixtree_free_cb(trees[1], (prefix_free_t)prefix6_free);
  return -1;
}

int scamper_dnp_init(const char **files, size_t filec)
{
  prefixtree_t *trees[2];
  size_t i;

  trees[0] = NULL;
  trees[1] = NULL;

  for(i=0; i<filec; i++)
    {
      line = 0;
      if(file_lines(files[i], dnp_line, trees) != 0)
	{
	  printerror(__func__, "could not read do-not-probe file %s", files[i]);
	  goto err;
	}
    }

  pfx4 = trees[0];
  pfx6 = trees[1];

  return 0;

 err:
  if(trees[0] != NULL)
    prefixtree_free_cb(trees[0], (prefix_free_t)prefix4_free);
  if(trees[1] != NULL)
    prefixtree_free_cb(trees[1], (prefix_free_t)prefix6_free);
  return -1;
}

void scamper_dnp_cleanup(void)
{
  if(pfx4 != NULL)
    {
      prefixtree_free_cb(pfx4, (prefix_free_t)prefix4_free);
      pfx4 = NULL;
    }
  if(pfx6 != NULL)
    {
      prefixtree_free_cb(pfx6, (prefix_free_t)prefix6_free);
      pfx6 = NULL;
    }
  return;
}

int scamper_dnp_canprobe(scamper_addr_t *dst)
{
  if(SCAMPER_ADDR_TYPE_IS_IPV4(dst))
    {
      if(pfx4 == NULL ||
	 prefixtree_find_ip4(pfx4, dst->addr) == NULL)
	return 1;
      return 0;
    }
  else if(SCAMPER_ADDR_TYPE_IS_IPV6(dst))
    {
      if(pfx6 == NULL ||
	 prefixtree_find_ip6(pfx6, dst->addr) == NULL)
	return 1;
      return 0;
    }

  return 1;
}

#else /* BUILDING_SCAMPER */

int scamper_dnp_canprobe(scamper_addr_t *dst)
{
  return 1;
}

#endif
