/*
 * unit_fds : unit tests for scamper_fd
 *
 * $Id: unit_fds.c,v 1.5 2024/03/04 19:36:41 mjl Exp $
 *
 *        Matthew Luckie
 *        mjl@luckie.org.nz
 *
 * Copyright (C) 2024 Matthew Luckie
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

#include "scamper_fds.h"
#include "scamper_dl.h"
#include "scamper_addr.h"
#include "utils.h"

static int fd_n = 4;
static int fd_fail = 0;

int scamper_dl_open(int ifindex)
{
  if(fd_fail != 0)
    return -1;
  return fd_n++;
}

void scamper_dl_read_cb(int fd, void *param)
{
  return;
}

scamper_dl_t *scamper_dl_state_alloc(scamper_fd_t *fdn)
{
  return malloc_zero(sizeof(int));
}

void scamper_dl_state_free(scamper_dl_t *dl)
{
  free(dl);
  return;
}

int scamper_icmp4_open(const void *src)
{
  if(fd_fail != 0)
    return -1;
  return fd_n++;
}

int scamper_icmp4_open_err(const void *src)
{
  if(fd_fail != 0)
    return -1;
  return fd_n++;
}

void scamper_icmp4_read_cb(int fd, void *param)
{
  return;
}

void scamper_icmp4_read_err_cb(int fd, void *param)
{
  return;
}

int scamper_icmp6_open(const void *src)
{
  if(fd_fail != 0)
    return -1;
  return fd_n++;
}

void scamper_icmp6_read_cb(int fd, void *param)
{
  return;
}

int scamper_ip4_openraw(void)
{
  if(fd_fail != 0)
    return -1;
  return fd_n++;
}

void scamper_rtsock_read_cb(int fd, void *param)
{
  return;
}

int scamper_rtsock_open(void)
{
  if(fd_fail != 0)
    return -1;
  return fd_n++;
}

int scamper_tcp4_open(const void *addr, int sport)
{
  if(fd_fail != 0)
    return -1;
  return fd_n++;
}

int scamper_tcp6_open(const void *addr, int sport)
{
  if(fd_fail != 0)
    return -1;
  return fd_n++;
}

int scamper_udp4_opendgram(const void *addr, int sport)
{
  if(fd_fail != 0)
    return -1;
  return fd_n++;
}

int scamper_udp4_openraw(const void *addr, int sport)
{
  if(fd_fail != 0)
    return -1;
  return fd_n++;
}

int scamper_udp6_open(const void *addr, int sport)
{
  if(fd_fail != 0)
    return -1;
  return fd_n++;
}

int scamper_udp6_open_err(const void *addr, int sport)
{
  if(fd_fail != 0)
    return -1;
  return fd_n++;
}

void scamper_udp6_read_cb(int fd, void *param)
{
  return;
}

void scamper_udp6_read_err_cb(int fd, void *param)
{
  return;
}

void scamper_udp4_read_cb(int fd, void *param)
{
  return;
}

int scamper_option_pollfunc_get(void)
{
  return 0; /* poll */
}

int scamper_task_sig_sport_used(struct scamper_addr *dst, uint8_t proto,
				uint16_t sport, uint16_t dport)
{
  return 0;
}

/*
 * test_0:
 *
 * test open functions for different socket types.  check that a
 * second open of the same socket returns the same fd handle.  check
 * that sport, addr, and ifindex functions work correctly.
 */
static int test_0(void)
{
  struct in6_addr in6;
  struct in_addr in4;
  scamper_fd_t *fds[10], *fdy[10];
  int i, j, x, fdx = 0, rc = -1;
  uint16_t sport;

  memset(fds, 0, sizeof(fds));
  memset(fdy, 0, sizeof(fdy));

  /* open a bunch of unique fds */
  if((fds[fdx++] = scamper_fd_udp4dg(NULL, 443)) == NULL ||   /* 0 */
     (fds[fdx++] = scamper_fd_tcp4(NULL, 80)) == NULL ||      /* 1 */
     (fds[fdx++] = scamper_fd_icmp4(NULL)) == NULL ||         /* 2 */
     (fds[fdx++] = scamper_fd_rtsock()) == NULL ||            /* 3 */
     (fds[fdx++] = scamper_fd_udp6(NULL, 443)) == NULL ||     /* 4 */
     (fds[fdx++] = scamper_fd_tcp6(NULL, 80)) == NULL ||      /* 5 */
     (fds[fdx++] = scamper_fd_icmp6(NULL)) == NULL ||         /* 6 */
     (fds[fdx++] = scamper_fd_dl(5)) == NULL ||               /* 7 */
     (fds[fdx++] = scamper_fd_udp4raw(NULL)) == NULL)         /* 8 */
    goto done;

  /* make sure each got their own file descriptor */
  for(i=0; i<fdx; i++)
    {
      for(j=0; j<i; j++)
	if(fds[i] == fds[j])
	  goto done;
    }

  /* scamper_fd_sport should only work on udp/tcp sockets */
  if(scamper_fd_sport(fds[0], &sport) != 0 || sport != 443 || /* udp4dg */
     scamper_fd_sport(fds[1], &sport) != 0 || sport != 80 ||  /* tcp4 */
     scamper_fd_sport(fds[4], &sport) != 0 || sport != 443 || /* udp6 */
     scamper_fd_sport(fds[5], &sport) != 0 || sport != 80 ||  /* tcp6 */
     scamper_fd_sport(fds[2], &sport) == 0 ||                 /* icmp4 */
     scamper_fd_sport(fds[3], &sport) == 0 ||                 /* rtsock */
     scamper_fd_sport(fds[6], &sport) == 0 ||                 /* icmp6 */
     scamper_fd_sport(fds[7], &sport) == 0 ||                 /* dl */
     scamper_fd_sport(fds[8], &sport) == 0)                   /* udp4raw */
    goto done;

  /*
   * scamper_fd_addr should only work on IP sockets, and should only
   * return 0 to signify it is not bound to any address
   */
  if(scamper_fd_addr(fds[0], &in4, sizeof(in4)) != 0 ||       /* udp4dg */
     scamper_fd_addr(fds[1], &in4, sizeof(in4)) != 0 ||       /* tcp4 */
     scamper_fd_addr(fds[2], &in4, sizeof(in4)) != 0 ||       /* icmp4 */
     scamper_fd_addr(fds[8], &in6, sizeof(in4)) != 0 ||       /* udp4raw */
     scamper_fd_addr(fds[4], &in6, sizeof(in6)) != 0 ||       /* udp6 */
     scamper_fd_addr(fds[5], &in6, sizeof(in6)) != 0 ||       /* tcp6 */
     scamper_fd_addr(fds[6], &in6, sizeof(in6)) != 0 ||       /* icmp6 */
     /* not IP sockets */
     scamper_fd_addr(fds[3], &in6, sizeof(in6)) != -1 ||      /* rtsock */
     scamper_fd_addr(fds[7], &in6, sizeof(in6)) != -1 ||      /* dl */
     /* IPv6 sockets but too small addr buffer */
     scamper_fd_addr(fds[4], &in4, sizeof(in4)) != -1 ||      /* udp6 */
     scamper_fd_addr(fds[5], &in4, sizeof(in4)) != -1 ||      /* tcp6 */
     scamper_fd_addr(fds[6], &in4, sizeof(in4)) != -1)        /* icmp6 */
    goto done;

  /* scamper_fd_ifindex should only work on DL sockets */
  for(i=0; i<9; i++)
    {
      x = scamper_fd_ifindex(fds[i], &j);
      if((i != 7 && x == 0) ||
	 (i == 7 && (x != 0 || j != 5)))
	goto done;
    }

  /* get a second copy of each of the sockets we opened earlier */
  if((fdy[0] = scamper_fd_udp4dg(NULL, 443)) == NULL ||       /* 0 */
     (fdy[1] = scamper_fd_tcp4(NULL, 80)) == NULL ||          /* 1 */
     (fdy[2] = scamper_fd_icmp4(NULL)) == NULL ||             /* 2 */
     (fdy[3] = scamper_fd_rtsock()) == NULL ||                /* 3 */
     (fdy[4] = scamper_fd_udp6(NULL, 443)) == NULL ||         /* 4 */
     (fdy[5] = scamper_fd_tcp6(NULL, 80)) == NULL ||          /* 5 */
     (fdy[6] = scamper_fd_icmp6(NULL)) == NULL ||             /* 6 */
     (fdy[7] = scamper_fd_dl(5)) == NULL ||                   /* 7 */
     (fdy[8] = scamper_fd_udp4raw(NULL)) == NULL)             /* 8 */
    goto done;
  for(i=0; i<10; i++)
    if(fds[i] != fdy[i])
      goto done;

  rc = 0;

 done:
  for(i=0; i<10; i++)
    {
      if(fds[i] != NULL) scamper_fd_free(fds[i]);
      if(fdy[i] != NULL) scamper_fd_free(fdy[i]);
    }
  return rc;
}

/*
 * test_1:
 *
 * check that everything works as intended when the underlying open function
 * returns -1.
 */
static int test_1(void)
{
  scamper_fd_t *fd = NULL;

  fd_fail = 1;
  if((fd = scamper_fd_udp4dg(NULL, 443)) != NULL ||
     (fd = scamper_fd_tcp4(NULL, 80)) != NULL ||
     (fd = scamper_fd_icmp4(NULL)) != NULL ||
     (fd = scamper_fd_rtsock()) != NULL ||
     (fd = scamper_fd_udp6(NULL, 443)) != NULL ||
     (fd = scamper_fd_tcp6(NULL, 80)) != NULL ||
     (fd = scamper_fd_icmp6(NULL)) != NULL ||
     (fd = scamper_fd_dl(5)) != NULL)
    goto err;

  return 0;

 err:
  if(fd != NULL) scamper_fd_free(fd);
  return -1;
}

static int check(int id, int (*func)(void))
{
  int rc;

#ifdef DMALLOC
  unsigned long start_mem, stop_mem;
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &start_mem, NULL, NULL, NULL, NULL);
#endif

  fd_fail = 0;
  fd_n = 4;

  scamper_fds_init();
  rc = func();
  scamper_fds_cleanup();

#ifdef DMALLOC
  dmalloc_get_stats(NULL, NULL, NULL, NULL, &stop_mem, NULL, NULL, NULL, NULL);
  if(start_mem != stop_mem && rc == 0)
    {
      printf("memory leak: %d\n", id);
      rc = -1;
    }
#endif

  return rc;
}

int main(int argc, char *argv[])
{
  static int (*const tests[])(void) = {
    test_0,
    test_1,
  };
  int i, testc = sizeof(tests) / sizeof(void *);

  for(i=0; i<testc; i++)
    if(check(i, tests[i]) != 0)
      return -1;

  printf("OK\n");
  return 0;
}
