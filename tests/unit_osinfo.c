/*
 * unit_osinfo : unit tests for osinfo module
 *
 * $Id: unit_osinfo.c,v 1.3 2023/08/07 21:02:30 mjl Exp $
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

typedef struct sc_test
{
  const char *sysname;
  const char *release;
  int (*func)(const scamper_osinfo_t *osinfo);
} sc_test_t;

static int test_linux_5_19_0(const scamper_osinfo_t *os)
{
  if(os == NULL ||
     os->os_id != SCAMPER_OSINFO_OS_LINUX || os->os_rel_dots != 3 ||
     os->os_rel[0] != 5 || os->os_rel[1] != 19 || os->os_rel[2] != 0)
    return -1;
  return 0;
}

static int test_freebsd_12_4(const scamper_osinfo_t *os)
{
  if(os == NULL ||
     os->os_id != SCAMPER_OSINFO_OS_FREEBSD || os->os_rel_dots != 2 ||
     os->os_rel[0] != 12 || os->os_rel[1] != 4)
    return -1;
  return 0;
}

static int test_freebsd_10_4(const scamper_osinfo_t *os)
{
  if(os == NULL ||
     os->os_id != SCAMPER_OSINFO_OS_FREEBSD || os->os_rel_dots != 2 ||
     os->os_rel[0] != 10 || os->os_rel[1] != 4)
    return -1;
  return 0;
}

static int test_darwin_21_6_0(const scamper_osinfo_t *os)
{
  if(os == NULL ||
     os->os_id != SCAMPER_OSINFO_OS_DARWIN || os->os_rel_dots != 3 ||
     os->os_rel[0] != 21 || os->os_rel[1] != 6 || os->os_rel[2] != 0)
    return -1;
  return 0;
}

static int test_linux_5_4_19(const scamper_osinfo_t *os)
{
  if(os == NULL ||
     os->os_id != SCAMPER_OSINFO_OS_LINUX || os->os_rel_dots != 3 ||
     os->os_rel[0] != 5 || os->os_rel[1] != 4 || os->os_rel[2] != 19)
    return -1;
  return 0;
}

static int test_linux_5_15_0(const scamper_osinfo_t *os)
{
  if(os == NULL ||
     os->os_id != SCAMPER_OSINFO_OS_LINUX || os->os_rel_dots != 3 ||
     os->os_rel[0] != 5 || os->os_rel[1] != 15 || os->os_rel[2] != 0)
    return -1;
  return 0;
}

static int test_linux_4_15_0(const scamper_osinfo_t *os)
{
  if(os == NULL ||
     os->os_id != SCAMPER_OSINFO_OS_LINUX || os->os_rel_dots != 3 ||
     os->os_rel[0] != 4 || os->os_rel[1] != 15 || os->os_rel[2] != 0)
    return -1;
  return 0;
}

static int test_linux_5_10_103(const scamper_osinfo_t *os)
{
  if(os == NULL ||
     os->os_id != SCAMPER_OSINFO_OS_LINUX || os->os_rel_dots != 3 ||
     os->os_rel[0] != 5 || os->os_rel[1] != 10 || os->os_rel[2] != 103)
    return -1;
  return 0;
}

static int test_linux_4_19_42(const scamper_osinfo_t *os)
{
  if(os == NULL ||
     os->os_id != SCAMPER_OSINFO_OS_LINUX || os->os_rel_dots != 3 ||
     os->os_rel[0] != 4 || os->os_rel[1] != 19 || os->os_rel[2] != 42)
    return -1;
  return 0;
}

static int test_linux_4__53(const scamper_osinfo_t *os)
{
  if(os == NULL ||
     os->os_id != SCAMPER_OSINFO_OS_LINUX || os->os_rel_dots != 1 ||
     os->os_rel[0] != 4)
    return -1;
  return 0;
}

static int test_linux____53(const scamper_osinfo_t *os)
{
  if(os == NULL ||
     os->os_id != SCAMPER_OSINFO_OS_LINUX || os->os_rel_dots != 0)
    return -1;
  return 0;
}

static int check(const char *sysname, const char *release,
		 int (*func)(const scamper_osinfo_t *osinfo))
{
  scamper_osinfo_t *osinfo;
  char *dup;
  int rc;

  if((dup = strdup(release)) == NULL)
    return -1;
  osinfo = scamper_osinfo_alloc(sysname, dup);
  free(dup);
  if((rc = func(osinfo)) != 0)
    printf("fail: %s %s\n", sysname, release);
  if(osinfo != NULL)
    scamper_osinfo_free(osinfo);

  return rc;
}

int main(int argc, char *argv[])
{
  sc_test_t tests[] = {
    {"Linux", "5.19.0-46-generic", test_linux_5_19_0},
    {"freebsd", "12.4-RELEASE", test_freebsd_12_4},
    {"freebsd", "10.4-RELEASE-p3", test_freebsd_10_4},
    {"Darwin", "21.6.0", test_darwin_21_6_0},
    {"Linux", "5.15.0-1033-raspi", test_linux_5_15_0},
    {"Linux", "5.4.19.bsk.2-amd64", test_linux_5_4_19},
    {"Linux", "4.15.0-36-generic", test_linux_4_15_0},
    {"Linux", "4.19.42-v7+", test_linux_4_19_42},
    {"Linux", "5.10.103-v7+", test_linux_5_10_103},
    {"Linux", "4..53", test_linux_4__53},
    {"Linux", "...53", test_linux____53},
  };
  size_t i, testc = sizeof(tests) / sizeof(sc_test_t);

  for(i=0; i<testc; i++)
    if(check(tests[i].sysname, tests[i].release, tests[i].func) != 0)
      break;
  if(i != testc)
    return -1;

  printf("OK\n");
  return 0;
}
