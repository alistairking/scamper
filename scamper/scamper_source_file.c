/*
 * scamper_source_file.c
 *
 * $Id: scamper_source_file.c,v 1.37 2025/03/29 18:46:03 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2014      The Regents of the University of California
 * Copyright (C) 2017-2024 Matthew Luckie
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
#include "scamper_priv.h"
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

  /* run-time state */
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

  if(ssf->fdn != NULL) /* reading from stdin */
    scamper_fd_free(ssf->fdn);
  else if(ssf->fd != -1) /* reading from file */
    close(ssf->fd);

  free(ssf);
  return;
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
      ssf->fd = -1; /* do not close */
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
   * an error occurred.  the simplest way to cause the source to
   * disappear gracefully is to set the fd to -1, which will signal to
   * the sources code that there are no more commands to come
   */
  ssf->fd = -1;
  return;
}
#endif

static void ssf_read_file(scamper_source_file_t *ssf)
{
  scamper_source_t *source = ssf->source;
  uint8_t buf[1024];
  ssize_t rc;

  if((rc = read(ssf->fd, buf, sizeof(buf))) > 0)
    {
      /* got data to read. parse the buffer for addresses, one per line. */
      scamper_linepoll_handle(ssf->lp, buf, (size_t)rc);
    }
  else if(rc == 0)
    {
      /* got EOF */
      scamper_linepoll_flush(ssf->lp);
      close(ssf->fd); ssf->fd = -1;
      if(scamper_source_isfinished(source) != 0)
	scamper_source_finished(source);
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
   * an error occurred.  the simplest way to cause the source to
   * disappear gracefully is to set the fd to -1, which will signal to
   * the sources code that there are no more commands to come
   */
  close(ssf->fd);
  ssf->fd = -1;
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

  string_concat(str, len, &off, "type file");

  if(ssf->fdn != NULL)
    string_concaf(str, len, &off, " fd %d", scamper_fd_fd_get(ssf->fdn));
  else
    string_concaf(str, len, &off, " fd %d", ssf->fd);

  if(ssf->filename != NULL)
    string_concat3(str, len, &off, " file \"", ssf->filename, "\"");

  if(ssf->command != NULL)
    string_concat3(str, len, &off, " cmd \"", ssf->command, "\"");

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

  if(ssf->fd == -1)
    return 0;

  if(scamper_source_getcommandcount(ssf->source) < scamper_option_pps_get())
    {
      if(ssf->fdn != NULL)
	scamper_fd_read_unpause(ssf->fdn);
      else
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
 * this is true so long as the file descriptor is not -1.
 */
static int ssf_isfinished(void *data)
{
  scamper_source_file_t *ssf = (scamper_source_file_t *)data;
  if(ssf->fd != -1)
    return 0;
  return 1;
}

const char *scamper_source_file_getfilename(const scamper_source_t *source)
{
  scamper_source_file_t *ssf;
  if((ssf = (scamper_source_file_t *)scamper_source_getdata(source)) != NULL)
    return ssf->filename;
  return NULL;
}

scamper_source_t *scamper_source_file_alloc(scamper_source_params_t *ssp,
					    const char *filename,
					    const char *command)
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
      /* get a file descriptor to the file */
      if((fd = scamper_priv_open(filename, O_RDONLY, 0)) == -1)
	{
	  printerror(__func__, "could not open %s", filename);
	  goto err;
	}
    }

  ssf->fd = fd;
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
