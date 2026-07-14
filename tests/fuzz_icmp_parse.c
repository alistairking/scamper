/*
 * fuzz_icmp_parse : fuzz scamper_icmp[46]_parse functions
 *
 * $Id: fuzz_icmp_parse.c,v 1.1 2026/07/13 09:12:18 mjl Exp $
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

#include "scamper_addr.h"
#include "scamper_icmp_resp.h"
#include "utils.h"

/*
 * function prototype of normally static functions that are not in
 * scamper_icmp[46].h
 */
#ifdef TEST_ICMP4_PARSE
int scamper_icmp4_parse(scamper_icmp_resp_t *resp,
			uint8_t *pbuf, ssize_t pbuflen);
#endif

#ifdef TEST_ICMP6_PARSE
int scamper_icmp6_parse(scamper_icmp_resp_t *resp,
			uint8_t *pbuf, ssize_t pbuflen);
#endif

int main(int argc, char *argv[])
{
  struct stat sb;
  scamper_icmp_resp_t ir;
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

  memset(&ir, 0, sizeof(ir));

#ifdef TEST_ICMP4_PARSE
  scamper_icmp4_parse(&ir, buf, (ssize_t)len);
#endif
#ifdef TEST_ICMP6_PARSE
  scamper_icmp6_parse(&ir, buf, (ssize_t)len);
#endif

  scamper_icmp_resp_clean(&ir);

  rc = 0;

 done:
  if(fd != -1) close(fd);
  if(buf != NULL) free(buf);
  return rc;
}
