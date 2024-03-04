/*
 * scamper_osinfo.c
 *
 * $Id: scamper_osinfo.c,v 1.10 2024/02/28 20:30:43 mjl Exp $
 *
 * Copyright (C) 2006 Matthew Luckie
 * Copyright (C) 2014 The Regents of the University of California
 * Copyright (C) 2023 Matthew Luckie
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

#include "scamper_debug.h"
#include "scamper_osinfo.h"
#include "mjl_list.h"
#include "utils.h"

static scamper_osinfo_t *osinfo = NULL;

int scamper_osinfo_is_sunos(void)
{
  return SCAMPER_OSINFO_IS_SUNOS(osinfo);
}

const scamper_osinfo_t *scamper_osinfo_get(void)
{
  return osinfo;
}

/*
 * scamper_osinfo_alloc
 *
 * do some basic parsing on the output from uname
 */
scamper_osinfo_t *scamper_osinfo_alloc(const char *sysname, char *release)
{
  scamper_osinfo_t *os = NULL;
  int               i;
  char             *str, *ptr;
  slist_t          *nos = NULL;
  size_t            size;

  /* allocate our wrapping struct */
  if((os = malloc_zero(sizeof(scamper_osinfo_t))) == NULL)
    {
      printerror(__func__, "could not malloc osinfo");
      goto err;
    }

  /* copy sysname in */
  if((os->os = strdup(sysname)) == NULL)
    {
      printerror(__func__, "could not strdup sysname");
      goto err;
    }

  /* parse the OS name */
  if(strcasecmp(os->os, "FreeBSD") == 0)
    os->os_id = SCAMPER_OSINFO_OS_FREEBSD;
  else if(strcasecmp(os->os, "OpenBSD") == 0)
    os->os_id = SCAMPER_OSINFO_OS_OPENBSD;
  else if(strcasecmp(os->os, "NetBSD") == 0)
    os->os_id = SCAMPER_OSINFO_OS_NETBSD;
  else if(strcasecmp(os->os, "SunOS") == 0)
    os->os_id = SCAMPER_OSINFO_OS_SUNOS;
  else if(strcasecmp(os->os, "Linux") == 0)
    os->os_id = SCAMPER_OSINFO_OS_LINUX;
  else if(strcasecmp(os->os, "Darwin") == 0)
    os->os_id = SCAMPER_OSINFO_OS_DARWIN;
  else if(strcasecmp(os->os, "Windows") == 0)
    os->os_id = SCAMPER_OSINFO_OS_WINDOWS;

  if(release != NULL)
    {
      /* parse the release integer string */
      if((nos = slist_alloc()) == NULL)
	{
	  printerror(__func__, "could not alloc nos");
	  goto err;
	}

      str = release;
      while(isdigit((int)*str))
	{
	  ptr = str; ptr++;
	  while(isdigit((int)*ptr) != 0)
	    ptr++;

	  if(slist_tail_push(nos, str) == NULL)
	    {
	      printerror(__func__, "could not push str");
	      goto err;
	    }

	  if(*ptr == '.')
	    {
	      *ptr = '\0';
	      str = ptr + 1;
	    }
	  else
	    {
	      *ptr = '\0';
	      break;
	    }
	}

      os->os_rel_dots = slist_count(nos);
      if(os->os_rel_dots != 0)
	{
	  size = os->os_rel_dots * sizeof(long);
	  if((os->os_rel = malloc_zero(size)) == NULL)
	    {
	      printerror(__func__, "could not malloc os_rel");
	      goto err;
	    }

	  i = 0;
	  while((str = slist_head_pop(nos)) != NULL)
	    {
	      if(string_tolong(str, &os->os_rel[i]) != 0)
		{
		  printerror(__func__, "could not tolong");
		  goto err;
		}
	      i++;
	    }
	}

      slist_free(nos);
    }

  return os;

 err:
  if(nos != NULL) slist_free(nos);
  if(os != NULL) scamper_osinfo_free(os);
  return NULL;
}

int scamper_osinfo_init(void)
{
#ifndef _WIN32 /* windows does not have uname */
  struct utsname utsname;

  /* call uname to get the information */
  if(uname(&utsname) < 0)
    {
      printerror(__func__, "could not uname");
      return -1;
    }

  if((osinfo = scamper_osinfo_alloc(utsname.sysname, utsname.release)) == NULL)
    return -1;
#else
  if((osinfo = scamper_osinfo_alloc("Windows", NULL)) == NULL)
    return -1;
#endif
  return 0;
}

void scamper_osinfo_free(scamper_osinfo_t *os)
{
  if(os->os != NULL) free(os->os);
  if(os->os_rel != NULL) free(os->os_rel);
  free(os);
  return;
}

void scamper_osinfo_cleanup(void)
{
  if(osinfo != NULL)
    {
      scamper_osinfo_free(osinfo);
      osinfo = NULL;
    }
  return;
}
