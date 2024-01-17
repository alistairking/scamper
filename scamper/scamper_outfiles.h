/*
 * scamper_outfiles: hold a collection of output targets together
 *
 * $Id: scamper_outfiles.h,v 1.21 2023/06/15 23:03:58 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
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

#ifndef __SCAMPER_OUTFILES_H
#define __SCAMPER_OUTFILES_H

typedef struct scamper_outfile scamper_outfile_t;

#ifdef __SCAMPER_FILE_H
#ifdef HAVE_FUNC_ATTRIBUTE_NONNULL
scamper_file_t *scamper_outfile_getfile(scamper_outfile_t *sof)
  __attribute__((nonnull));
#else
scamper_file_t *scamper_outfile_getfile(scamper_outfile_t *sof);
#endif
#endif

#ifdef HAVE_FUNC_ATTRIBUTE_NONNULL
const char *scamper_outfile_getname(const scamper_outfile_t *sof)
  __attribute__((nonnull));
int scamper_outfile_getrefcnt(const scamper_outfile_t *sof)
  __attribute__((nonnull));
scamper_outfile_t *scamper_outfile_open(const char *alias, const char *file,
					const char *mo,char *err,size_t errlen)
  __attribute__((nonnull));
int scamper_outfile_close(scamper_outfile_t *sof) __attribute__((nonnull));
void scamper_outfile_free(scamper_outfile_t *sof) __attribute__((nonnull));
#else
const char *scamper_outfile_getname(const scamper_outfile_t *sof);
int scamper_outfile_getrefcnt(const scamper_outfile_t *sof);
scamper_outfile_t *scamper_outfile_open(const char *alias, const char *file,
					const char *mo,char *err,size_t errlen);
int scamper_outfile_close(scamper_outfile_t *sof);
void scamper_outfile_free(scamper_outfile_t *sof);
#endif

scamper_outfile_t *scamper_outfiles_get(const char *alias);
scamper_outfile_t *scamper_outfile_use(scamper_outfile_t *sof);
void scamper_outfiles_foreach(void *p,
			      int (*func)(void *p, scamper_outfile_t *sof));

#ifdef HAVE_FUNC_ATTRIBUTE_NONNULL
int scamper_outfiles_init(const char *def_filename, const char *def_type)
  __attribute__((nonnull));
scamper_outfile_t *scamper_outfile_openfd(const char *name, int fd,
					  const char *type)
  __attribute__((nonnull));
scamper_outfile_t *scamper_outfile_opennull(const char *name,
					    const char *type)
  __attribute__((nonnull));
void scamper_outfiles_swap(scamper_outfile_t *a, scamper_outfile_t *b)
  __attribute__((nonnull));
#else
int scamper_outfiles_init(const char *def_filename, const char *def_type);
scamper_outfile_t *scamper_outfile_openfd(const char *name, int fd,
					  const char *type);
scamper_outfile_t *scamper_outfile_opennull(const char *name,
					    const char *type);
void scamper_outfiles_swap(scamper_outfile_t *a, scamper_outfile_t *b);
#endif

void scamper_outfiles_cleanup(void);

#endif
