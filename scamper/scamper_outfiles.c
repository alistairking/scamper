/*
 * scamper_outfiles: hold a collection of output targets together
 *
 * $Id: scamper_outfiles.c,v 1.58 2023/08/26 21:25:08 mjl Exp $
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
#include "scamper_privsep.h"
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

int scamper_outfile_close(scamper_outfile_t *sof)
{
  if(sof->refcnt > 1)
    {
      scamper_debug(__func__,"not closing %s refcnt %d",sof->name,sof->refcnt);
      return -1;
    }

  outfile_free(sof);
  return 0;
}

scamper_outfile_t *scamper_outfiles_get(const char *name)
{
  const scamper_outfile_t findme = {(char *)name, NULL, 0};
  if(name == NULL)
    return outfile_def;
  return splaytree_find(outfiles, &findme);
}

/*
 * scamper_outfiles_swap
 *
 * swap the files around.  the name and refcnt parameters are unchanged.
 */
void scamper_outfiles_swap(scamper_outfile_t *a, scamper_outfile_t *b)
{
  scamper_file_t *sf;

  sf = b->sf;
  b->sf = a->sf;
  a->sf = sf;

  return;
}

scamper_outfile_t *scamper_outfile_open(const char *name, const char *file,
					const char *mo,char *err,size_t errlen)
{
  scamper_outfile_t *sof;
  scamper_file_t *sf;
  char *outfile_type = "warts";
  int flags;
  char sf_mode;
  int fd;

  /* already an outfile with this name */
  if(scamper_outfiles_get(name) != NULL)
    {
      snprintf(err, errlen, "already an outfile with name");
      return NULL;
    }

  if(string_endswith(file, ".gz") != 0)
    {
#ifdef HAVE_ZLIB
      outfile_type = "warts.gz";
#else
      snprintf(err, errlen, "not compiled with zlib");
      return NULL;
#endif
    }
  else if(string_endswith(file, ".bz2") != 0)
    {
#ifdef HAVE_LIBBZ2
      outfile_type = "warts.bz2";
#else
      snprintf(err, errlen, "not compiled with libbz2");
      return NULL;
#endif
    }
  else if(string_endswith(file, ".xz") != 0)
    {
#ifdef HAVE_LIBLZMA
      outfile_type = "warts.xz";
#else
      snprintf(err, errlen, "not compiled with liblzma");
      return NULL;
#endif
    }

  if(strcasecmp(mo, "append") == 0)
    {
      flags = O_RDWR | O_APPEND | O_CREAT;
      sf_mode = 'a';
    }
  else if(strcasecmp(mo, "truncate") == 0)
    {
      flags = O_WRONLY | O_TRUNC | O_CREAT;
      sf_mode = 'w';
    }
  else
    {
      snprintf(err, errlen, "unknown mode");
      return NULL;
    }

#ifdef _WIN32 /* windows needs O_BINARY */
  flags |= O_BINARY;
#endif

#ifdef DISABLE_PRIVSEP
  fd = open(file, flags, MODE_644);
#else
  fd = scamper_privsep_open_file(file, flags, MODE_644);
#endif

  /* make sure the fd is valid, otherwise bail */
  if(fd == -1)
    {
      snprintf(err, errlen, "could not open %s", file);
      return NULL;
    }

  if((sf = scamper_file_openfd(fd, file, sf_mode, outfile_type)) == NULL)
    {
      snprintf(err, errlen, "could not openfd for %s", file);
      close(fd);
      return NULL;
    }

  if((sof = outfile_alloc(name, sf)) == NULL)
    {
      snprintf(err, errlen, "could not outfile_alloc %s", name);
      scamper_file_close(sf);
      return NULL;
    }

  err[0] = '\0';
  return sof;
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
#ifdef DISABLE_PRIVSEP
      fd = open(filename, flags, MODE_644);
#else
      fd = scamper_privsep_open_file(filename, flags, MODE_644);
#endif

      if(fd == -1)
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

scamper_outfile_t *scamper_outfile_openfd(const char *name, int fd,
					  const char *type)
{
  scamper_outfile_t *sof = NULL;
  scamper_file_t *sf = NULL;

  if(fd == -1 || (sf = scamper_file_openfd(fd, NULL, 'w', type)) == NULL)
    return NULL;

  if((sof = outfile_alloc(name, sf)) == NULL)
    {
      scamper_file_free(sf);
      return NULL;
    }

  return sof;
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

void scamper_outfiles_foreach(void *p,
			      int (*func)(void *p, scamper_outfile_t *sof))
{
  splaytree_inorder(outfiles, (splaytree_inorder_t)func, p);
  return;
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
