/*
 * scamper_outfiles: hold a collection of output targets together
 *
 * $Id: scamper_outfiles.c,v 1.64 2025/03/29 18:46:03 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012      The Regents of the University of California
 * Copyright (C) 2023      The Regents of the University of California
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
#include "scamper_file.h"
#include "scamper_priv.h"
#include "scamper_outfiles.h"
#include "utils.h"
#include "mjl_splaytree.h"

struct scamper_outfile
{
  char           *name;
  scamper_file_t *sf;
  int             refcnt;
};

static splaytree_t       *outfiles = NULL;
static scamper_outfile_t *outfile_def = NULL;

static int outfile_cmp(const scamper_outfile_t *a, const scamper_outfile_t *b)
{
  return strcasecmp(b->name, a->name);
}

static scamper_outfile_t *outfile_alloc(const char *name, scamper_file_t *sf)
{
  scamper_outfile_t *sof = NULL;

  if((sof = malloc_zero(sizeof(scamper_outfile_t))) == NULL)
    {
      printerror(__func__, "could not malloc sof");
      goto err;
    }

  sof->sf = sf;
  sof->refcnt = 1;

  if((sof->name = strdup(name)) == NULL)
    {
      printerror(__func__, "could not strdup");
      goto err;
    }

  if(splaytree_insert(outfiles, sof) == NULL)
    {
      printerror(__func__, "could not insert");
      goto err;
    }

  scamper_debug(__func__, "name %s fd %d", name, scamper_file_getfd(sf));
  return sof;

 err:
  if(sof != NULL)
    {
      if(sof->name != NULL) free(sof->name);
      free(sof);
    }
  return NULL;
}

static void outfile_free(scamper_outfile_t *sof)
{
  assert(sof != NULL);

  if(sof->name != NULL && sof->sf != NULL)
    scamper_debug(__func__, "name %s fd %d", sof->name,
		  scamper_file_getfd(sof->sf));

  if(sof->name != NULL)
    {
      splaytree_remove_item(outfiles, sof);
      free(sof->name);
    }

  if(sof->sf != NULL)
    {
      scamper_file_close(sof->sf);
    }

  free(sof);
  return;
}

int scamper_outfile_getrefcnt(const scamper_outfile_t *sof)
{
  return sof->refcnt;
}

scamper_file_t *scamper_outfile_getfile(scamper_outfile_t *sof)
{
  return sof->sf;
}

const char *scamper_outfile_getname(const scamper_outfile_t *sof)
{
  return sof->name;
}

scamper_outfile_t *scamper_outfile_use(scamper_outfile_t *sof)
{
  if(sof != NULL)
    {
      sof->refcnt++;
    }
  return sof;
}

void scamper_outfile_free(scamper_outfile_t *sof)
{
  assert(sof->refcnt > 0);

  if(--sof->refcnt == 0)
    outfile_free(sof);

  return;
}

scamper_outfile_t *scamper_outfiles_get(const char *name)
{
  const scamper_outfile_t findme = {(char *)name, NULL, 0};
  if(name == NULL)
    return outfile_def;
  return splaytree_find(outfiles, &findme);
}

static int outfile_opendef(const char *filename, const char *type)
{
  scamper_file_t *sf;
  int flags;
  char sf_mode;
  int fd;

  flags = O_WRONLY | O_TRUNC | O_CREAT;
  sf_mode = 'w';

#ifdef _WIN32 /* windows needs O_BINARY */
  flags |= O_BINARY;
#endif

  if(string_isdash(filename) != 0)
    {
      fd = STDOUT_FILENO;
    }
  else
    {
      if((fd = scamper_priv_open(filename, flags, MODE_644)) == -1)
	{
	  printerror(__func__, "could not open %s", filename);
	  return -1;
	}
    }

  if(fd == -1)
    {
      return -1;
    }

  if((sf = scamper_file_openfd(fd, filename, sf_mode, type)) == NULL)
    {
      close(fd);
      return -1;
    }

  if((outfile_def = outfile_alloc(filename, sf)) == NULL)
    {
      scamper_file_close(sf);
      return -1;
    }

  return 0;
}

scamper_outfile_t *scamper_outfile_opennull(const char *name,
					    const char *type)
{
  scamper_outfile_t *sof;
  scamper_file_t *sf;

  if((sf = scamper_file_opennull('w', type)) == NULL)
    {
      printerror(__func__, "could not opennull");
      return NULL;
    }

  if((sof = outfile_alloc(name, sf)) == NULL)
    {
      scamper_file_free(sf);
      return NULL;
    }

  return sof;
}

int scamper_outfiles_init(const char *def_filename, const char *def_type)
{
  if((outfiles = splaytree_alloc((splaytree_cmp_t)outfile_cmp)) == NULL)
    {
      printerror(__func__, "could not alloc outfiles tree");
      return -1;
    }

  if(outfile_opendef(def_filename, def_type) != 0)
    return -1;

  return 0;
}

void scamper_outfiles_cleanup()
{
  if(outfile_def != NULL)
    {
      if(--outfile_def->refcnt > 0)
	{
	  scamper_debug(__func__,
			"default outfile refcnt %d", outfile_def->refcnt);
	}

      outfile_free(outfile_def);
      outfile_def = NULL;
    }

  if(outfiles != NULL)
    {
      splaytree_free(outfiles, NULL);
      outfiles = NULL;
    }

  return;
}
