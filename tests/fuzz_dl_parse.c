/*
 * fuzz_dl_parse : fuzz dl_parse functions
 *
 * $Id: fuzz_dl_parse.c,v 1.1 2024/07/02 00:50:12 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2023-2024 Matthew Luckie
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

#include "scamper_dl.h"
#include "utils.h"

/*
 * function prototype of a normally static function that is not in
 * scamper_dl.h
 */
#ifdef TEST_DL_PARSE_IP
int dl_parse_ip(scamper_dl_rec_t *dl, uint8_t *pktbuf, size_t pktlen);
#endif

#ifdef TEST_DL_PARSE_ARP
int dl_parse_arp(scamper_dl_rec_t *dl, uint8_t *pktbuf, size_t pktlen);
#endif

int main(int argc, char *argv[])
{
  struct stat sb;
  scamper_dl_rec_t dlr;
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

#ifdef TEST_DL_PARSE_IP
  dl_parse_ip(&dlr, buf, len);
#endif
#ifdef TEST_DL_PARSE_ARP
  dl_parse_arp(&dlr, buf, len);
#endif

  rc = 0;

 done:
  if(fd != -1) close(fd);
  if(buf != NULL) free(buf);
  return rc;
}
