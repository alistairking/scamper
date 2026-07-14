/*
 * fuzz_icmpext_parse : fuzz scamper_icmpext_parse function
 *
 * $Id: fuzz_icmpext_parse.c,v 1.1 2026/07/12 02:16:23 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2026 Matthew Luckie
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

#include "scamper_icmpext.h"
#include "scamper_icmpext_int.h"
#include "utils.h"

int main(int argc, char *argv[])
{
  scamper_icmpexts_t *exts = NULL;
  struct stat sb;
  uint8_t *buf = NULL;
  size_t readc, len;
  int rc = -1;
  int fd = -1;

  if((fd = open(argv[1], O_RDONLY)) == -1)
    goto done;
  if(fstat(fd, &sb) != 0)
    goto done;
  len = sb.st_size;
  if((buf = malloc(len)) == NULL)
    goto done;
  if(read_wrap(fd, buf, &readc, len) != 0 || readc != len)
    goto done;

  scamper_icmpext_parse(&exts, buf, len);
  if(exts != NULL)
    scamper_icmpexts_free(exts);

  rc = 0;

 done:
  if(fd != -1) close(fd);
  if(buf != NULL) free(buf);
  return rc;
}
