/*
 * scamper_source_file.c
 *
 * $Id: scamper_source_file.c,v 1.33 2024/06/10 03:28:08 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2014      The Regents of the University of California
 * Copyright (C) 2017-2023 Matthew Luckie
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
#include "scamper_outfiles.h"
#include "scamper_task.h"
#include "scamper_sources.h"
#include "scamper_linepoll.h"
#include "scamper_fds.h"
#include "scamper_privsep.h"
#include "scamper_source_file.h"

#include "utils.h"

typedef struct scamper_source_file
{
  /* back-pointer to the parent source */
  scamper_source_t   *source;

  /* parameters for the file */
  char               *filename;
  char               *command;
  size_t              command_len;
  int                 cycles;
  int                 autoreload;

  /* run-time state */
  int                 reload;
  time_t              mtime;
  scamper_fd_t       *fdn;
  int                 fd;
  scamper_linepoll_t *lp;

} scamper_source_file_t;

/*
 * ssf_free
 *
 * free up all resources related to an address-list-file.
 */
static void ssf_free(scamper_source_file_t *ssf)
{
  if(ssf->lp != NULL)
    scamper_linepoll_free(ssf->lp, 0);

  if(ssf->filename != NULL)
    free(ssf->filename);

  if(ssf->command != NULL)
    free(ssf->command);

  if(ssf->fdn != NULL)
    scamper_fd_free(ssf->fdn);
  else if(ssf->fd != -1)
    close(ssf->fd);

  free(ssf);
  return;
}

static int ssf_open(const char *filename)
{
  int fd = -1;

  /* get a file descriptor to the file */
#ifdef DISABLE_PRIVSEP
  fd = open(filename, O_RDONLY);
#else
  fd = scamper_privsep_open_file(filename, O_RDONLY, 0);
#endif

  if(fd == -1)
    printerror(__func__, "could not open %s", filename);

  return fd;
}

/*
 * ssf_read_line
 *
 * this callback receives a single line per call, which should contain an
 * address in string form.  it combines that address with the source's
 * default command and then passes the string to source_command for further
 * processing.  the line eventually ends up in the commands queue.
 */
static int ssf_read_line(void *param, uint8_t *buf, size_t len)
{
  scamper_source_file_t *ssf = (scamper_source_file_t *)param;
  scamper_source_t *source = ssf->source;
  char *str = (char *)buf;
  char cmd_buf[256], *cmd = NULL;
  size_t reqd_len;

  /* make sure the string contains only printable characters */
  if(string_isprint(str, len) == 0)
    {
      printerror(__func__, "%s contains unprintable characters", ssf->filename);
      goto err;
    }

  if(ssf->command != NULL)
    {
      /* null terminate at these characters */
      string_nullterm(str, " \r\t#", NULL);
      if(str[0] == '\0' || str[0] == '#')
	return 0;

      /* figure out if the cmd_buf above is large enough */
      len = strlen(str);
      if(sizeof(cmd_buf) >= (reqd_len = ssf->command_len + 1 + len + 1))
	{
	  cmd = cmd_buf;
	}
      else
	{
	  if((cmd = malloc_zero(reqd_len)) == NULL)
	    {
	      printerror(__func__, "could not malloc %d bytes", (int)reqd_len);
	      goto err;
	    }
	}

      /* build the command string */
      memcpy(cmd, ssf->command, ssf->command_len);
      cmd[ssf->command_len] = ' ';
      memcpy(cmd + ssf->command_len + 1, str, len+1);
    }
  else
    {
      string_nullterm(str, "\r\t#", NULL);
      if(str[0] == '\0' || str[0] == '#')
	return 0;
      cmd = str;
    }

  /* add the command to the source */
  if(scamper_source_command(source, cmd) != 0)
    {
      goto err;
    }

  if(cmd != cmd_buf && cmd != str) free(cmd);
  return 0;

 err:
  if(cmd != cmd_buf && cmd != str) free(cmd);
  return -1;
}

/*
 * ssf_read_stdin:
 *
 * simplified read path for when the input file is stdin
 */
#ifndef _WIN32 /* windows cannot treat stdin like a socket */
static void ssf_read_stdin(int fd, void *param)
{
  scamper_source_file_t *ssf = (scamper_source_file_t *)param;
  scamper_source_t *source = ssf->source;
  uint8_t buf[1024];
  ssize_t rc;

  assert(ssf->cycles != 0);

  if((rc = read(fd, buf, sizeof(buf))) > 0)
    {
      /* got data to read. parse the buffer for addresses, one per line. */
      scamper_linepoll_handle(ssf->lp, buf, (size_t)rc);

      /*
       * if probe queue for this source is sufficiently large, then
       * don't read any more for the time being
       */
      if(scamper_source_getcommandcount(source) >= scamper_option_pps_get())
	scamper_fd_read_pause(ssf->fdn);
    }
  else if(rc == 0)
    {
      /* got EOF; this is the last cycle over an input file */
      scamper_linepoll_flush(ssf->lp);
      ssf->cycles = 0;
      scamper_fd_read_pause(ssf->fdn);
      if(scamper_source_isfinished(source) != 0)
	scamper_source_finished(source);
    }
  else
    {
      assert(rc == -1);
      if(errno != EAGAIN && errno != EINTR)
	{
	  printerror(__func__, "read failed fd %d", fd);
	  goto err;
	}
    }

  return;

 err:
  /*
   * an error occurred.  the simplest way to cause the source to disappear
   * gracefully is to set the cycles parameter to zero, which will signal
   * to the sources code that there are no more commands to come
   */
  ssf->cycles = 0;
  return;
}
#endif

static void ssf_read_file(scamper_source_file_t *ssf)
{
  scamper_source_t *source = ssf->source;
  uint8_t buf[1024];
  ssize_t rc;
  time_t mtime;
  int reload = 0;
  int newfd;

  assert(ssf->cycles != 0);

  if((rc = read(ssf->fd, buf, sizeof(buf))) > 0)
    {
      /* got data to read. parse the buffer for addresses, one per line. */
      scamper_linepoll_handle(ssf->lp, buf, (size_t)rc);
    }
  else if(rc == 0 && ssf->cycles == 1)
    {
      /* got EOF; this is the last cycle over an input file */
      scamper_linepoll_flush(ssf->lp);
      ssf->cycles = 0;
      if(scamper_source_isfinished(source) != 0)
	scamper_source_finished(source);
    }
  else if(rc == 0)
    {
      scamper_linepoll_flush(ssf->lp);

      /* a cycle value of -1 means cycle indefinitely */
      if(ssf->cycles != -1)
	ssf->cycles--;

      /* decide if we should reload the file at this point */
      if(ssf->reload == 1)
	{
	  /* stat the file so we have an mtime value for later */
	  if(stat_mtime(ssf->filename, &mtime) == 0)
	    reload = 1;
	}
      else if(ssf->autoreload == 1)
	{
	  /*
	   * reload is conditional on being able to stat the file, and the
	   * mtime being different to whatever our record of the mtime is
	   */
	  if(stat_mtime(ssf->filename, &mtime) == 0 && ssf->mtime != mtime)
	    reload = 1;
	}

      /* we have to reload the file (if we can open it) */
      if(reload == 1 && (newfd = ssf_open(ssf->filename)) != -1)
	{
	  /* close the existing file */
	  close(ssf->fd);

	  /* update file details; ensure reload is reset to zero */
	  ssf->fd = newfd;
	  ssf->mtime = mtime;
	  ssf->reload = 0;
	}
      else
	{
	  /* rewind the current file position */
	  if(lseek(ssf->fd, 0, SEEK_SET) == -1)
	    {
	      goto err;
	    }
	}

      /* create a new cycle record, etc */
      if(scamper_source_cycle(source) != 0)
	{
	  goto err;
	}
    }
  else
    {
      assert(rc == -1);
      if(errno != EAGAIN && errno != EINTR)
	{
	  printerror(__func__, "read failed fd %d", ssf->fd);
	  goto err;
	}
    }

  return;

 err:
  /*
   * an error occurred.  the simplest way to cause the source to disappear
   * gracefully is to set the cycles parameter to zero, which will signal
   * to the sources code that there are no more commands to come
   */
  ssf->cycles = 0;
  return;
}

/*
 * ssf_tostr
 *
 * this function generates a printable representation of the source
 */
static char *ssf_tostr(void *data, char *str, size_t len)
{
  scamper_source_file_t *ssf = (scamper_source_file_t *)data;
  size_t off = 0;

  if(len < 1)
    return NULL;

  string_concat(str, len, &off, "type file ");

  if(ssf->fdn != NULL)
    string_concat(str, len, &off, "fd %d ", scamper_fd_fd_get(ssf->fdn));
  else
    string_concat(str, len, &off, "fd %d ", ssf->fd);

  if(ssf->filename != NULL)
    string_concat(str, len, &off, "file \"%s\" ", ssf->filename);

  if(ssf->command != NULL)
    string_concat(str, len, &off, "cmd \"%s\" ", ssf->command);

  string_concat(str, len, &off, "cycles %d", ssf->cycles);
  return str;
}

/*
 * ssf_take
 *
 * this function is used to quench the source from sending more commands
 */
static int ssf_take(void *data)
{
  scamper_source_file_t *ssf = (scamper_source_file_t *)data;

  if(scamper_source_getcyclecount(ssf->source) < 2 &&
     scamper_source_getcommandcount(ssf->source) < scamper_option_pps_get() &&
     ssf->cycles != 0)
    {
      if(ssf->fdn != NULL)
	scamper_fd_read_unpause(ssf->fdn);
      else if(ssf->fd != -1)
	ssf_read_file(ssf);
    }

  return 0;
}

static void ssf_freedata(void *data)
{
  ssf_free((scamper_source_file_t *)data);
  return;
}

/*
 * ssf_isfinished
 *
 * advise the caller if the source may be supplying more commands or not.
 * in the address-list-file case, more addresses will be supplied until
 * the cycles count reaches zero.
 */
static int ssf_isfinished(void *data)
{
  scamper_source_file_t *ssf = (scamper_source_file_t *)data;
  if(ssf->cycles != 0)
    return 0;
  return 1;
}

int scamper_source_file_getcycles(const scamper_source_t *source)
{
  scamper_source_file_t *ssf;
  if((ssf = (scamper_source_file_t *)scamper_source_getdata(source)) != NULL)
    return ssf->cycles;
  return -1;
}

int scamper_source_file_getautoreload(const scamper_source_t *source)
{
  scamper_source_file_t *ssf;
  if((ssf = (scamper_source_file_t *)scamper_source_getdata(source)) != NULL)
    return ssf->autoreload;
  return -1;
}

const char *scamper_source_file_getfilename(const scamper_source_t *source)
{
  scamper_source_file_t *ssf;
  if((ssf = (scamper_source_file_t *)scamper_source_getdata(source)) != NULL)
    return ssf->filename;
  return NULL;
}

int scamper_source_file_update(scamper_source_t *source,
			       const int *autoreload, const int *cycles)
{
  scamper_source_file_t *ssf;

  if(scamper_source_gettype(source) != SCAMPER_SOURCE_TYPE_FILE ||
     (ssf = (scamper_source_file_t *)scamper_source_getdata(source)) == NULL)
    {
      return -1;
    }

  if(autoreload != NULL)
    ssf->autoreload = *autoreload;

  if(cycles != NULL)
    ssf->cycles = *cycles;

  return 0;
}

scamper_source_t *scamper_source_file_alloc(scamper_source_params_t *ssp,
					    const char *filename,
					    const char *command,
					    int cycles, int autoreload)
{
  scamper_source_file_t *ssf = NULL;
  int fd = -1;

  /* sanity checks */
  if(ssp == NULL || filename == NULL)
    goto err;

  /* allocate the structure for keeping track of the address list file */
  if((ssf = malloc_zero(sizeof(scamper_source_file_t))) == NULL)
    goto err;
  ssf->fd = -1;
  if((ssf->filename = strdup(filename)) == NULL)
    goto err;
  ssf->cycles     = cycles;
  ssf->autoreload = autoreload;

  /* addresses are matched with a command to execute */
  if(command != NULL)
    {
      if((ssf->command = strdup(command)) == NULL)
	goto err;
      ssf->command_len = strlen(ssf->command);
    }

  /* if we're reading from stdin */
  if(string_isdash(filename) != 0)
    {
#ifndef _WIN32 /* windows cannot treat stdin like a socket */
      fd = STDIN_FILENO;
#ifdef O_NONBLOCK
      fcntl_set(fd, O_NONBLOCK);
#endif
      /* allocate a scamper_fd_t to monitor when new data is able to be read */
      if((ssf->fdn = scamper_fd_private(fd, ssf, ssf_read_stdin, NULL)) == NULL)
	goto err;
#else
      scamper_debug(__func__, "reading from stdin not supported on windows");
      goto err;
#endif
    }
  else
    {
      if((fd = ssf_open(filename)) == -1)
	goto err;
      ssf->fd = fd;
    }

  if((ssf->lp = scamper_linepoll_alloc(ssf_read_line, ssf)) == NULL)
    goto err;

  /*
   * data and callback functions that scamper_source_alloc needs to know about
   */
  ssp->data        = ssf;
  ssp->take        = ssf_take;
  ssp->freedata    = ssf_freedata;
  ssp->isfinished  = ssf_isfinished;
  ssp->tostr       = ssf_tostr;
  ssp->type        = SCAMPER_SOURCE_TYPE_FILE;

  /* allocate the parent source structure */
  if((ssf->source = scamper_source_alloc(ssp)) == NULL)
    {
      goto err;
    }

  return ssf->source;

 err:
  if(ssf != NULL)
    {
      assert(ssf->source == NULL);
      ssf_free(ssf);
    }
  return NULL;
}
