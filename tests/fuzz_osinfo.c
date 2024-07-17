/*
 * fuzz_osinfo : simple program to fuzz osinfo
 *
 * $Id: fuzz_osinfo.c,v 1.2 2024/03/04 19:36:41 mjl Exp $
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

#include "scamper_osinfo.h"
#include "utils.h"

static void check(const char *sysname, char *release)
{
  scamper_osinfo_t *osinfo;
  if((osinfo = scamper_osinfo_alloc(sysname, release)) != NULL)
    scamper_osinfo_free(osinfo);
  return;
}

static int test(char *in, void *param)
{
  static char *sysname = NULL;
  static char *release = NULL;
  static int   line = 0;

  line++;

  if(line == 1)
    {
      sysname = strdup(in);
      return 0;
    }
  else if(line == 2)
    {
      release = strdup(in);
      check(sysname, release);
      return 0;
    }

  return -1;
}

int main(int argc, char *argv[])
{
  if(argc < 2)
    {
      fprintf(stderr, "missing parameter\n");
      return -1;
    }

  if(file_lines(argv[1], test, NULL) != 0)
    {
      fprintf(stderr, "could not process %s\n", argv[1]);
      return -1;
    }

  return 0;
}
