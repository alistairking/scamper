/*
 * scamper_debug.h
 *
 * $Id: scamper_debug.h,v 1.29 2025/10/13 00:52:32 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2009 The University of Waikato
 * Copyright (C) 2015-2022 Matthew Luckie
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

#ifndef __SCAMPER_DEBUG_H
#define __SCAMPER_DEBUG_H

typedef struct scamper_err
{
  int error;
  char errstr[256];
} scamper_err_t;

#define SCAMPER_ERR_INIT(err) do { \
  (err)->error = 0;		   \
  (err)->errstr[0] = '\0';	   \
  } while(0)

#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
void scamper_err_make(scamper_err_t *err, int error, const char *format, ...)
  __attribute__((format(printf, 3, 4)));
#else
void scamper_err_make(scamper_err_t *err, int error, const char *format, ...);
#endif

#ifdef HAVE_FUNC_ATTRIBUTE_NONNULL
char *scamper_err_render(const scamper_err_t *err, char *buf, size_t len)
  __attribute__((nonnull));
#else
char *scamper_err_render(const scamper_err_t *err, char *buf, size_t len);
#endif

int printerror_would(void);

#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
void printerror(const char *func, const char *format, ...)
  __attribute__((format(printf, 2, 3)));
void printerror_msg(const char *func, const char *format, ...)
  __attribute__((format(printf, 2, 3)));
#else
void printerror(const char *func, const char *format, ...);
void printerror_msg(const char *func, const char *format, ...);
#endif

#ifdef HAVE_OPENSSL
#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
void printerror_ssl(const char *func, const char *format, ...)
  __attribute__((format(printf, 2, 3)));
#else
void printerror_ssl(const char *func, const char *format, ...);
#endif
#endif

/* only define scamper_debug if scamper is being built in debugging mode */
#if defined(NDEBUG) && defined(WITHOUT_DEBUGFILE) && defined(BUILDING_SCAMPER)
#define scamper_debug(func, format, ...) ((void)0)
#else
#define HAVE_SCAMPER_DEBUG
int scamper_debug_would(void);
#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
void scamper_debug(const char *func, const char *format, ...)
  __attribute__((format(printf, 2, 3)));
#else
void scamper_debug(const char *func, const char *format, ...);
#endif
#endif

#ifndef WITHOUT_DEBUGFILE
int scamper_debug_open(const char *debugfile);
void scamper_debug_close(void);
#endif

void scamper_debug_daemon(void);

#endif /* scamper_debug.h */
