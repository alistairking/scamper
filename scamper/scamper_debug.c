/*
 * scamper_debug.c
 *
 * $Id: scamper_debug.c,v 1.52 2025/01/19 03:51:01 mjl Exp $
 *
 * routines to reduce the impact of debugging cruft in scamper's code.
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2010 The University of Waikato
 * Copyright (C) 2012-2025 Matthew Luckie
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
#include "scamper_debug.h"
#include "utils.h"

#ifndef WITHOUT_DEBUGFILE
static FILE *debugfile = NULL;
#endif

static int isdaemon = 0;

static void timestamp_str(char *buf, size_t len)
{
  struct timeval tv;
  size_t off = 0;
  char ts[16];
  gettimeofday_wrap(&tv);
  string_concat3(buf, len, &off, "[", timeval_tostr_hhmmssms(&tv, ts), "]");
  return;
}

/*
 * printerror
 *
 * format a nice and consistent error string using strerror and the
 * arguments supplied
 */
void printerror(const char *func, const char *format, ...)
{
  char     message[512];
  char     ts[16];
  va_list  ap;
  int      ecode = errno;

  if(isdaemon != 0)
    {
#ifndef WITHOUT_DEBUGFILE
      if(debugfile == NULL)
	return;
#else
      return;
#endif
    }

  va_start(ap, format);
  vsnprintf(message, sizeof(message), format, ap);
  va_end(ap);
  timestamp_str(ts, sizeof(ts));

  if(isdaemon == 0)
    {
      fprintf(stderr, "%s %s: %s: %s\n", ts, func, message, strerror(ecode));
      fflush(stderr);
    }

#ifndef WITHOUT_DEBUGFILE
  if(debugfile != NULL)
    {
      fprintf(debugfile, "%s %s: %s: %s\n", ts, func, message, strerror(ecode));
      fflush(debugfile);
    }
#endif

  return;
}

void printerror_msg(const char *func, const char *format, ...)
{
  char msg[512], ts[16];
  va_list ap;

  if(isdaemon != 0)
    {
#ifndef WITHOUT_DEBUGFILE
      if(debugfile == NULL)
	return;
#else
      return;
#endif
    }

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);
  timestamp_str(ts, sizeof(ts));

  if(isdaemon == 0)
    {
      fprintf(stderr, "%s %s: %s\n", ts, func, msg);
      fflush(stderr);
    }

#ifndef WITHOUT_DEBUGFILE
  if(debugfile != NULL)
    {
      fprintf(debugfile, "%s %s: %s\n", ts, func, msg);
      fflush(debugfile);
    }
#endif

  return;
}

#ifdef HAVE_OPENSSL
void printerror_ssl(const char *func, const char *format, ...)
{
  char msg[512], ts[16];
  char sslbuf[1024], buf[256];
  va_list ap;
  size_t off = 0;
  int ecode;

  if(isdaemon != 0)
    {
#ifndef WITHOUT_DEBUGFILE
      if(debugfile == NULL)
	return;
#else
      return;
#endif
    }

  va_start(ap, format);
  vsnprintf(msg, sizeof(msg), format, ap);
  va_end(ap);
  timestamp_str(ts, sizeof(ts));

  for(;;)
    {
      if((ecode = ERR_get_error()) == 0)
	break;
      ERR_error_string_n(ecode, buf, sizeof(buf));
      string_concat2(sslbuf, sizeof(sslbuf), &off, off > 0 ? " " : "", buf);
    }

  if(isdaemon == 0)
    {
      fprintf(stderr, "%s %s: %s: %s\n", ts, func, msg, sslbuf);
      fflush(stderr);
    }

#ifndef WITHOUT_DEBUGFILE
  if(debugfile != NULL)
    {
      fprintf(debugfile, "%s %s: %s: %s\n", ts, func, msg, sslbuf);
      fflush(debugfile);
    }
#endif

  return;
}
#endif

#ifdef HAVE_SCAMPER_DEBUG
/*
 * scamper_debug_would
 *
 * would scamper_debug emit something, if called now?
 */
int scamper_debug_would(void)
{
#ifndef NDEBUG
  if(isdaemon == 0)
    return 1;
#endif
#ifndef WITHOUT_DEBUGFILE
  if(debugfile != NULL)
    return 1;
#endif
  return 0; /* into the flood again */
}

void scamper_debug(const char *func, const char *format, ...)
{
  char     message[512];
  va_list  ap;
  char     ts[16];
  char     fs[64];

  assert(format != NULL);

  if(scamper_debug_would() == 0)
    return;

  va_start(ap, format);
  vsnprintf(message, sizeof(message), format, ap);
  va_end(ap);

  timestamp_str(ts, sizeof(ts));

  if(func != NULL) snprintf(fs, sizeof(fs), "%s: ", func);
  else             fs[0] = '\0';

#ifndef NDEBUG
  if(isdaemon == 0)
    {
      fprintf(stderr, "%s %s%s\n", ts, fs, message);
      fflush(stderr);
    }
#endif

#ifndef WITHOUT_DEBUGFILE
  if(debugfile != NULL)
    {
      fprintf(debugfile, "%s %s%s\n", ts, fs, message);
      fflush(debugfile);
    }
#endif

  return;
}
#endif

#ifndef WITHOUT_DEBUGFILE
int scamper_debug_open(const char *file)
{
  int flags, fd;

  if(scamper_option_debugfileappend() == 0)
    flags = O_WRONLY | O_CREAT | O_TRUNC;
  else
    flags = O_WRONLY | O_CREAT | O_APPEND;

  if((fd = open(file, flags, MODE_644)) == -1)
    {
      printerror(__func__, "could not open debugfile %s", file);
      return -1;
    }

  if((debugfile = fdopen(fd, "a")) == NULL)
    {
      printerror(__func__, "could not fdopen debugfile %s", file);
      return -1;
    }

  return 0;
}

void scamper_debug_close()
{
  if(debugfile != NULL)
    {
      fclose(debugfile);
      debugfile = NULL;
    }
  return;
}
#endif

void scamper_debug_daemon(void)
{
  isdaemon = 1;
  return;
}
