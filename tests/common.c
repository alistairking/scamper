/*
 * common.c: common functions that we might need for linking unit tests
 *
 * $Id: common.c,v 1.6 2024/04/20 00:15:02 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2023 Matthew Luckie
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
#include "scamper_addr.h"
#include "utils.h"
#include "common.h"

int check_addr(const scamper_addr_t *sa, const char *str)
{
  struct in_addr in;
  struct in6_addr in6;

  if(sa == NULL)
    return -1;

  if(inet_pton(AF_INET, str, &in) == 1)
    {
      if(scamper_addr_isipv4(sa) == 0)
	return -1;
      if(scamper_addr_raw_cmp(sa, &in) == 0)
	return 0;
    }
  else if(inet_pton(AF_INET6, str, &in6) == 1)
    {
      if(scamper_addr_isipv6(sa) == 0)
	return -1;
      if(scamper_addr_raw_cmp(sa, &in6) == 0)
	return 0;
    }

  return -1;
}

int dump_cmd(const char *cmd, const char *filename)
{
  size_t len, wc;
  uint8_t *buf = NULL;
  int rc = -1, fd = -1;
  int fd_flags = O_WRONLY | O_CREAT | O_TRUNC;

  if((fd = open(filename, fd_flags, MODE_644)) == -1)
    {
      fprintf(stderr, "%s: could not open %s: %s\n",
	      __func__, filename, strerror(errno));
      goto done;
    }

  len = strlen(cmd);
  if(write_wrap(fd, cmd, &wc, len) != 0 || wc != len)
    {
      fprintf(stderr, "%s: could not write %s: %s\n",
	      __func__, filename, strerror(errno));
      goto done;
    }

  rc = 0;

 done:
  if(fd != -1) close(fd);
  if(buf != NULL) free(buf);
  return rc;
}

int hex2buf(const char *str, uint8_t **buf_out, size_t *len_out)
{
  size_t len = strlen(str);
  size_t i, off = 0;
  uint8_t *buf = NULL;
  int rc = -1;

  if((len % 2) != 0 || len == 0 || (buf = malloc(len / 2)) == NULL)
    goto done;

  for(i=0; i<len; i+=2)
    {
      if(ishex(str[i]) == 0 || ishex(str[i+1]) == 0)
	goto done;
      buf[off++] = hex2byte(str[i], str[i+1]);
    }

  *buf_out = buf; buf = NULL;
  *len_out = off;
  rc = 0;

 done:
  if(buf != NULL) free(buf);
  return rc;
}

int dump_hex(const char *str, const char *filename)
{
  size_t len, wc;
  uint8_t *buf = NULL;
  int rc = -1, fd = -1;
  int fd_flags = O_WRONLY | O_CREAT | O_TRUNC;

#ifdef _WIN32 /* windows needs O_BINARY */
  fd_flags |= O_BINARY;
#endif

  if(hex2buf(str, &buf, &len) != 0)
    goto done;

  if((fd = open(filename, fd_flags, MODE_644)) == -1)
    {
      fprintf(stderr, "%s: could not open %s: %s\n",
	      __func__, filename, strerror(errno));
      goto done;
    }

  if(write_wrap(fd, buf, &wc, len) != 0 || wc != len)
    {
      fprintf(stderr, "%s: could not write %s: %s\n",
	      __func__, filename, strerror(errno));
      goto done;
    }

  rc = 0;

 done:
  if(fd != -1) close(fd);
  if(buf != NULL) free(buf);
  return rc;
}

int scamper_option_notls(void)
{
  return 0;
}

uint16_t scamper_sport_default(void)
{
  return 31337;
}

uint16_t scamper_pid_u16(void)
{
  return 31337;
}

void scamper_debug(const char *func, const char *format, ...)
{
#if 0
  char     message[512];
  va_list  ap;
  char     fs[64];

  va_start(ap, format);
  vsnprintf(message, sizeof(message), format, ap);
  va_end(ap);

  if(func != NULL) snprintf(fs, sizeof(fs), "%s: ", func);
  else             fs[0] = '\0';

  printf("%s%s\n", fs, message);
#endif
  return;
}

void printerror(const char *func, const char *format, ...)
{
  return;
}

void printerror_msg(const char *func, const char *format, ...)
{
  return;
}
