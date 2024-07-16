/*
 * utils.c
 *
 * $Id: utils.c,v 1.241 2024/05/02 00:13:57 mjl Exp $
 *
 * Copyright (C) 2003-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2011      Matthew Luckie
 * Copyright (C) 2012-2015 The Regents of the University of California
 * Copyright (C) 2015-2024 Matthew Luckie
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
#include "utils.h"

#if defined(HAVE_STRUCT_SOCKADDR_SA_LEN)
int sockaddr_len(const struct sockaddr *sa)
{
  return sa->sa_len;
}
#else
int sockaddr_len(const struct sockaddr *sa)
{
  if(sa->sa_family == AF_INET)  return sizeof(struct sockaddr_in);
  if(sa->sa_family == AF_INET6) return sizeof(struct sockaddr_in6);

#ifdef AF_LINK
  if(sa->sa_family == AF_LINK)  return sizeof(struct sockaddr_dl);
#endif

#ifdef HAVE_SOCKADDR_UN
  if(sa->sa_family == AF_UNIX)  return sizeof(struct sockaddr_un);
#endif

  return -1;
}
#endif

int sockaddr_compose(struct sockaddr *sa, int af, const void *addr, int port)
{
  socklen_t len;
  struct sockaddr_in  *sin4;
  struct sockaddr_in6 *sin6;

  assert(port >= 0);
  assert(port <= 65535);

  if(af == AF_INET)
    {
      len = sizeof(struct sockaddr_in);
      memset(sa, 0, len);
      sin4 = (struct sockaddr_in *)sa;
      if(addr != NULL) memcpy(&sin4->sin_addr, addr, sizeof(struct in_addr));
      sin4->sin_port = htons(port);
    }
  else if(af == AF_INET6)
    {
      len = sizeof(struct sockaddr_in6);
      memset(sa, 0, len);
      sin6 = (struct sockaddr_in6 *)sa;
      if(addr != NULL) memcpy(&sin6->sin6_addr, addr, sizeof(struct in6_addr));
      sin6->sin6_port = htons(port);
    }
  else return -1;

#if defined(HAVE_STRUCT_SOCKADDR_SA_LEN)
  sa->sa_len    = len;
#endif

  sa->sa_family = af;

  return 0;
}

int sockaddr_compose_un(struct sockaddr *sa, const char *file)
{
#ifdef HAVE_SOCKADDR_UN
  struct sockaddr_un *sn = (struct sockaddr_un *)sa;

  if(strlen(file) + 1 > sizeof(sn->sun_path))
    return -1;
  memset(sn, 0, sizeof(struct sockaddr_un));
  sn->sun_family = AF_UNIX;
  snprintf(sn->sun_path, sizeof(sn->sun_path), "%s", file);

#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
  sn->sun_len    = sizeof(struct sockaddr_un);
#endif

  return 0;
#else
  errno = EINVAL;
  return -1;
#endif
}

int sockaddr_compose_str(struct sockaddr *sa, const char *addr, int port)
{
  struct addrinfo hints, *res, *res0;
  int rc = -1;
  void *va;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags    = AI_NUMERICHOST;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_family   = AF_UNSPEC;

  if(getaddrinfo(addr, NULL, &hints, &res0) != 0 || res0 == NULL)
    return rc;

  for(res = res0; res != NULL; res = res->ai_next)
    {
      if(res->ai_family == PF_INET)
	{
	  va = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
	  sockaddr_compose(sa, AF_INET, va, port);
	  rc = 0;
	  break;
	}
      else if(res->ai_family == PF_INET6)
	{
	  va = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
	  sockaddr_compose(sa, AF_INET6, va, port);
	  rc = 0;
	  break;
	}
    }

  freeaddrinfo(res0);
  return rc;
}

#if defined(AF_LINK) && !defined(_WIN32)
static char *link_tostr(const struct sockaddr_dl *sdl, char *buf, size_t len)
{
  static const char hex[] = "01234567890abcdef";
  size_t off = 0;
  uint8_t *u8, i;

  if((off = snprintf(buf, len, "t%d", sdl->sdl_type)) + 1 > len)
    {
      return NULL;
    }

  if(sdl->sdl_nlen == 0 && sdl->sdl_alen == 0)
    {
      return buf;
    }
  else
    {
      buf[off++] = '.';
    }

  /* check for enough remaining space */
  if((size_t)(sdl->sdl_nlen + 1 + (3 * sdl->sdl_alen)) > len-off)
    {
      return NULL;
    }

  if(sdl->sdl_nlen > 0)
    {
      memcpy(buf+off, sdl->sdl_data, sdl->sdl_nlen);
      off += sdl->sdl_nlen;
      if(sdl->sdl_alen > 0)
	{
	  buf[off++] = '.';
	}
      else
	{
	  buf[off] = '\0';
	  return buf;
	}
    }

  if(sdl->sdl_alen > 0)
    {
      u8 = (uint8_t *)LLADDR(sdl);
      for(i=0; i<sdl->sdl_alen; i++)
	{
	  buf[off++] = hex[u8[i] & 0xf];
	  buf[off++] = hex[(u8[i] >> 4) & 0xf];
	  buf[off++] = ':';
	}
      buf[off-1] = '\0';
    }

  return buf;
}
#endif

char *sockaddr_tostr(const struct sockaddr *sa, char *buf, size_t len)
{
  char addr[128];

  if(sa->sa_family == AF_INET)
    {
#ifndef _WIN32 /* windows did not have inet_ntop until 2008 */
      if(inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr,
		   addr, sizeof(addr)) == NULL)
	{
	  return NULL;
	}
#else
      if(getnameinfo(sa, sizeof(struct sockaddr_in), addr, sizeof(addr),
		     NULL, 0, NI_NUMERICHOST) != 0)
	{
	  return NULL;
	}
#endif

      snprintf(buf, len, "%s:%d", addr,
	       ntohs(((const struct sockaddr_in *)sa)->sin_port));
    }
  else if(sa->sa_family == AF_INET6)
    {
#ifndef _WIN32 /* windows did not have inet_ntop until 2008 */
      if(inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)sa)->sin6_addr,
		   addr, sizeof(addr)) == NULL)
	{
	  return NULL;
	}
#else
      if(getnameinfo(sa, sizeof(struct sockaddr_in6), addr, sizeof(addr),
		     NULL, 0, NI_NUMERICHOST) != 0)
	{
	  return NULL;
	}
#endif

      snprintf(buf, len, "%s.%d", addr,
	       ntohs(((const struct sockaddr_in6 *)sa)->sin6_port));
    }
#if defined(AF_LINK) && !defined(_WIN32)
  else if(sa->sa_family == AF_LINK)
    {
      return link_tostr((const struct sockaddr_dl *)sa, buf, len);
    }
#endif
#ifdef HAVE_SOCKADDR_UN
  else if(sa->sa_family == AF_UNIX)
    {
      snprintf(buf, len, "%s", ((const struct sockaddr_un *)sa)->sun_path);
    }
#endif
  else
    {
      return NULL;
    }

  return buf;
}

int addr4_cmp(const struct in_addr *a, const struct in_addr *b)
{
  if(a->s_addr < b->s_addr) return -1;
  if(a->s_addr > b->s_addr) return  1;
  return 0;
}

int addr4_human_cmp(const struct in_addr *a, const struct in_addr *b)
{
  uint32_t ua = ntohl(a->s_addr);
  uint32_t ub = ntohl(b->s_addr);
  if(ua < ub) return -1;
  if(ua > ub) return  1;
  return 0;
}

int addr6_cmp(const struct in6_addr *a, const struct in6_addr *b)
{
  return memcmp(a, b, sizeof(struct in6_addr));
}

int addr6_human_cmp(const struct in6_addr *a, const struct in6_addr *b)
{
  int i;

#ifndef _WIN32 /* windows does not have s6_addr32 for in6_addr */
  uint32_t ua, ub;
  for(i=0; i<4; i++)
    {
      ua = ntohl(a->s6_addr32[i]);
      ub = ntohl(b->s6_addr32[i]);
      if(ua < ub) return -1;
      if(ua > ub) return  1;
    }
#else
  uint16_t ua, ub;
  for(i=0; i<8; i++)
    {
      ua = ntohs(a->u.Word[i]);
      ub = ntohs(b->u.Word[i]);
      if(ua < ub) return -1;
      if(ua > ub) return  1;
    }
#endif

  return 0;
}

int addr6_add_netlen(struct in6_addr *in, int netlen)
{
  static const uint8_t add[] = {0x80,0x40,0x20,0x10,0x08,0x04,0x02,0x01};
  int j = (netlen-1) / 8;
  int k = (netlen-1) % 8;

  if(((int)in->s6_addr[j]) + add[k] <= 255)
    {
      in->s6_addr[j] += add[k];
      return 0;
    }

  in->s6_addr[j--] = 0;
  while(j >= 0)
    {
      if(in->s6_addr[j] < 255)
	break;
      in->s6_addr[j--] = 0;
    }

  if(j < 0)
    return -1;

  in->s6_addr[j]++;
  return 0;
}

void addr6_sub(struct in6_addr *out,
	       const struct in6_addr *y, const struct in6_addr *x)
{
  uint16_t x16, y16, z, c = 0;
  int i;

  assert(addr6_human_cmp(x, y) <= 0);

  for(i=15; i>=0; i--)
    {
      y16 = y->s6_addr[i];
      x16 = x->s6_addr[i] + c;
      if(y16 >= x16)
	{
	  out->s6_addr[i] = y16 - x16;
	  c = 0;
	}
      else
	{
	  z = 256 + y16 - x16;
	  out->s6_addr[i] = z;
	  c = 1;
	}
    }

  return;
}

void addr6_add(struct in6_addr *out, const struct in6_addr *x,
	       const struct in6_addr *y)
{
  uint16_t z, c = 0;
  int i;

  for(i=15; i>=0; i--)
    {
      z = x->s6_addr[i] + y->s6_addr[i] + c;
      if(z > 255)
	{
	  c = 1;
	  z = z & 0xff;
	}
      else c = 0;
      out->s6_addr[i] = z;
    }

  return;
}

/*
 * addr_cmp:
 * this function is used to provide a sorting order, not for advising the
 * numerical order of the addresses passed in.
 */
int addr_cmp(int af, const void *a, const void *b)
{
  if(af == AF_INET)  return addr4_cmp(a, b);
  if(af == AF_INET6) return addr6_cmp(a, b);
  return 0;
}

#ifndef _WIN32 /* windows did not have inet_ntop until 2008 */
const char *addr_tostr(int af, const void *addr, char *buf, size_t len)
{
  return inet_ntop(af, addr, buf, len);
}
#endif

#ifdef _WIN32 /* windows did not have inet_ntop until 2008 */
const char *addr_tostr(int af, const void *addr, char *buf, size_t len)
{
  struct sockaddr_storage sas;

  if(sockaddr_compose((struct sockaddr *)&sas, af, addr, 0) != 0)
    return NULL;

  if(getnameinfo((const struct sockaddr *)&sas, sizeof(sas), buf, len,
                 NULL, 0, NI_NUMERICHOST) != 0)
    {
      return NULL;
    }

  return buf;
}
#endif

/*
 * memdup
 *
 * duplicate some memory.
 */
#ifndef DMALLOC
void *memdup(const void *ptr, size_t len)
{
  void *d;
  assert(ptr != NULL);
  if((d = malloc(len)) != NULL)
    {
      memcpy(d, ptr, len);
    }
  return d;
}
#endif

/*
 * malloc_zero
 *
 * allocate some memory, zero it, and return a pointer to it.
 */
#if !defined(DMALLOC) && !defined(HAVE_CALLOC)
void *malloc_zero(size_t size)
{
  void *ptr;
  if((ptr = malloc(size)) != NULL)
    {
      memset(ptr, 0, size);
    }
  return ptr;
}
#endif

#ifdef DMALLOC
void *malloc_zero_dm(size_t size, const char *file, int line)
{
  void *ptr;
  if((ptr = dmalloc_malloc(file,line,size,DMALLOC_FUNC_MALLOC,0,0)) != NULL)
    {
      memset(ptr, 0, size);
    }
  return ptr;
}
#endif

#ifndef DMALLOC
int realloc_wrap(void **ptr, size_t len)
{
  void *tmp;

  if(len != 0)
    {
      if(*ptr != NULL)
	tmp = realloc(*ptr, len);
      else
	tmp = malloc(len);

      if(tmp != NULL)
	{
	  *ptr = tmp;
	  return 0;
	}
    }
  else
    {
      if(*ptr != NULL)
	{
	  free(*ptr);
	  *ptr = NULL;
	}
      return 0;
    }

  return -1;
}
#endif

#ifdef DMALLOC
int realloc_wrap_dm(void **ptr, size_t len, const char *file, int line)
{
  void *tmp;

  if(len != 0)
    {
      if(*ptr != NULL)
	tmp = dmalloc_realloc(file, line, *ptr, len, DMALLOC_FUNC_REALLOC, 0);
      else
	tmp = dmalloc_malloc(file, line, len, DMALLOC_FUNC_MALLOC, 0, 0);

      if(tmp != NULL)
	{
	  *ptr = tmp;
	  return 0;
	}
    }
  else
    {
      if(*ptr != NULL)
	{
	  dmalloc_free(file, line, *ptr, DMALLOC_FUNC_FREE);
	  *ptr = NULL;
	}
      return 0;
    }

  return -1;
}
#endif

int array_findpos(void **array, size_t nmemb, const void *item,
		  array_cmp_t cmp, size_t *pos)
{
  size_t l, r, k;
  int i;

  if(nmemb == 0)
    return -1;

  l = 0;
  r = nmemb-1;

  if(r == 0)
    {
      if(cmp(array[0], item) == 0)
	{
	  *pos = 0;
	  return 0;
	}
      return -1;
    }

  while(l <= r)
    {
      k = (l + r) / 2;
      i = cmp(array[k], item);
      if(i > 0)
	{
	  if(k == 0)
	    break;
	  r = k-1;
	}
      else if(i < 0)
	l = k+1;
      else
	{
	  *pos = k;
	  return 0;
	}
    }

  return -1;
}

void *array_find(void **array,size_t nmemb,const void *item,array_cmp_t cmp)
{
  size_t k;
  if(array_findpos(array, nmemb, item, cmp, &k) == 0)
    return array[k];
  return NULL;
}

/*
 * array_insert_0
 *
 * handy function that deals with inserting an element into an array
 * and then sorting the array, if necessary.  using mergesort because
 * the array is likely to have pre-existing order.
 */
static int array_insert_0(void **array, size_t *nmemb, void *item,
			    array_cmp_t cmp)
{
  assert(array != NULL);
  array[*nmemb] = item;
  *nmemb = *nmemb + 1;
  if(cmp != NULL)
    array_qsort(array, *nmemb, cmp);
  return 0;
}

#ifndef DMALLOC
int array_insert(void ***array, size_t *nmemb, void *item, array_cmp_t cmp)
{
  size_t len;
  assert(nmemb != NULL);
  len = ((*nmemb) + 1) * sizeof(void *);
  if(realloc_wrap((void **)array, len) != 0)
    return -1;
  return array_insert_0(*array, nmemb, item, cmp);
}

int array_insert_gb(void ***array, size_t *nmemb, size_t *mmemb, size_t growby,
		    void *item, array_cmp_t cmp)
{
  size_t len;

  assert(nmemb != NULL);
  if(*nmemb + 1 >= *mmemb)
    {
      assert(*mmemb + growby > *nmemb);
      len = (*mmemb + growby) * sizeof(void *);
      if(realloc_wrap((void **)array, len) != 0)
	return -1;
      *mmemb += growby;
    }

  return array_insert_0(*array, nmemb, item, cmp);
}
#endif

#ifdef DMALLOC
int array_insert_dm(void ***array, size_t *nmemb, void *item,
		    array_cmp_t cmp, const char *file, int line)
{
  size_t len;

  assert(nmemb != NULL);
  len = ((*nmemb) + 1) * sizeof(void *);
  if(realloc_wrap_dm((void **)array, len, file, line) != 0)
    return -1;

  return array_insert_0(*array, nmemb, item, cmp);
}

int array_insert_gb_dm(void ***array, size_t *nmemb, size_t *mmemb,
		       size_t growby, void *item, array_cmp_t cmp,
		       const char *file, int line)
{
  size_t len;

  assert(nmemb != NULL);
  if(*nmemb + 1 >= *mmemb)
    {
      assert(*mmemb + growby > *nmemb);
      len = (*mmemb + growby) * sizeof(void *);
      if(realloc_wrap_dm((void **)array, len, file, line) != 0)
	return -1;
      *mmemb += growby;
    }

  return array_insert_0(*array, nmemb, item, cmp);
}
#endif

void array_remove(void **array, size_t *nmemb, size_t p)
{
  assert(*nmemb > 0);
  assert(p < *nmemb);
  memmove(array+p, array+p+1, ((*nmemb)-p-1) * sizeof(void *));
  *nmemb = *nmemb - 1;
  return;
}

static void array_swap(void **a, size_t i, size_t j)
{
  void *item = a[i];
  a[i] = a[j];
  a[j] = item;
  return;
}

static void array_qsort_3(void **a, array_cmp_t cmp, size_t l, size_t r)
{
  size_t lt, gt, i;
  int rc;
  void *c;

  if(l >= r)
    return;

  lt = l;
  gt = r;
  i  = l;
  c  = a[l];

  while(i <= gt)
    {
      rc = a[i] != c ? cmp(a[i], c) : 0;
      if(rc < 0)
	array_swap(a, lt++, i++);
      else if(rc > 0)
	array_swap(a, i, gt--);
      else
	i++;
    }

  if(lt > 0)
    array_qsort_3(a, cmp, l, lt-1);
  array_qsort_3(a, cmp, gt+1, r);
  return;
}

void array_qsort(void **a, size_t n, array_cmp_t cmp)
{
  if(n > 1)
    array_qsort_3(a, cmp, 0, n-1);
  return;
}

void gettimeofday_wrap(struct timeval *tv)
{
#ifndef _WIN32 /* windows does not have gettimeofday */
  struct timezone tz;
  gettimeofday(tv, &tz);
#else
  FILETIME ft;
  uint64_t u64;
  GetSystemTimeAsFileTime(&ft);
  u64 = ft.dwHighDateTime;
  u64 <<= 32;
  u64 |= ft.dwLowDateTime;

  u64 /= 10;
  u64 -= 11644473600000000LL;
  tv->tv_sec = (long)(u64 / 1000000UL);
  tv->tv_usec = (long)(u64 % 1000000UL);
#endif
  return;
}

int timeval_cmp(const struct timeval *a, const struct timeval *b)
{
  if(a->tv_sec  < b->tv_sec)  return -1;
  if(a->tv_sec  > b->tv_sec)  return  1;

  if(a->tv_usec < b->tv_usec) return -1;
  if(a->tv_usec > b->tv_usec) return  1;

  return 0;
}

int timeval_cmp_lt(const struct timeval *tv, time_t s, suseconds_t us)
{
  if(tv->tv_sec < s || (tv->tv_sec == s && tv->tv_usec < us))
    return 1;
  return 0;
}

int timeval_cmp_gt(const struct timeval *tv, time_t s, suseconds_t us)
{
  if(tv->tv_sec > s || (tv->tv_sec == s && tv->tv_usec > us))
    return 1;
  return 0;
}

static void timeval_handlewrap(struct timeval *tv)
{
  if(tv->tv_usec >= 1000000)
    {
      tv->tv_sec++;
      tv->tv_usec -= 1000000;
    }
  else if(tv->tv_usec < 0)
    {
      tv->tv_sec--;
      tv->tv_usec += 1000000;
    }
  return;
}

void timeval_add_ms(struct timeval *out, const struct timeval *in, int msec)
{
  out->tv_sec  = in->tv_sec  + (msec / 1000);
  out->tv_usec = in->tv_usec + ((msec % 1000) * 1000);
  timeval_handlewrap(out);
  return;
}

void timeval_add_us(struct timeval *out, const struct timeval *in, int us)
{
  out->tv_sec  = in->tv_sec  + (us / 1000000);
  out->tv_usec = in->tv_usec + (us % 1000000);
  timeval_handlewrap(out);
  return;
}

void timeval_add_s(struct timeval *out, const struct timeval *in, int s)
{
  out->tv_sec  = in->tv_sec + s;
  out->tv_usec = in->tv_usec;
  return;
}

void timeval_sub_us(struct timeval *out, const struct timeval *in, int us)
{
  out->tv_sec  = in->tv_sec  - (us / 1000000);
  out->tv_usec = in->tv_usec - (us % 1000000);
  timeval_handlewrap(out);
  return;
}

void timeval_sub_tv(struct timeval *tv, const struct timeval *sub)
{
  assert(sub->tv_sec >= 0);
  assert(sub->tv_usec >= 0); assert(sub->tv_usec < 1000000);
  assert(timeval_cmp(tv, sub) >= 0);

  tv->tv_sec -= sub->tv_sec;
  if(tv->tv_usec < sub->tv_usec)
    {
      tv->tv_sec--;
      tv->tv_usec += (1000000 - sub->tv_usec);
    }
  else
    {
      tv->tv_usec -= sub->tv_usec;
    }

  return;
}

void timeval_add_tv(struct timeval *tv, const struct timeval *add)
{
  assert(add->tv_sec >= 0);
  assert(add->tv_usec >= 0);

  tv->tv_sec += add->tv_sec;
  tv->tv_usec += add->tv_usec;

  /* check for overflow */
  if(tv->tv_usec > 1000000)
    {
      tv->tv_sec++;
      tv->tv_usec -= 1000000;
    }

  return;
}

void timeval_add_tv3(struct timeval *out,
		     const struct timeval *in, const struct timeval *add)
{
  assert(in->tv_sec >= 0); assert(in->tv_usec >= 0);
  assert(add->tv_sec >= 0); assert(add->tv_usec >= 0);

  out->tv_sec = in->tv_sec + add->tv_sec;
  out->tv_usec = in->tv_usec + add->tv_usec;
  if(out->tv_usec > 1000000)
    {
      out->tv_sec++;
      out->tv_usec -= 1000000;
    }

  return;
}

void timeval_diff_tv(struct timeval *out,
		     const struct timeval *from, const struct timeval *to)
{
  out->tv_sec  = to->tv_sec  - from->tv_sec;
  out->tv_usec = to->tv_usec - from->tv_usec;

  if(out->tv_usec < 0)
    {
      out->tv_sec--;
      out->tv_usec += 1000000;
    }

  return;
}

/*
 * timeval_diff_ms
 * return the millisecond difference between the two timevals.
 */
int timeval_diff_ms(const struct timeval *from, const struct timeval *to)
{
  struct timeval tv;
  timeval_diff_tv(&tv, from, to);
  return ((int)tv.tv_sec * 1000) + ((int)tv.tv_usec / 1000);
}

/*
 * timeval_diff_us
 * return the microsecond difference between the two timevals.
 */
int timeval_diff_us(const struct timeval *from, const struct timeval *to)
{
  struct timeval tv;
  timeval_diff_tv(&tv, from, to);
  return ((int)tv.tv_sec * 1000000) + tv.tv_usec;
}

void timeval_cpy(struct timeval *dst, const struct timeval *src)
{
  memcpy(dst, src, sizeof(struct timeval));
  return;
}

int timeval_inrange_us(const struct timeval *a, const struct timeval *b, int c)
{
  struct timeval tv;
  int rc = timeval_cmp(a, b);
  if(rc < 0)
    {
      timeval_add_us(&tv, a, c);
      if(timeval_cmp(&tv, b) < 0)
	return 0;
    }
  else if(rc > 0)
    {
      timeval_add_us(&tv, b, c);
      if(timeval_cmp(&tv, a) < 0)
	return 0;
    }
  return 1;
}

char *timeval_tostr_us(const struct timeval *rtt, char *str, size_t len)
{
  uint32_t usec = (rtt->tv_sec * 1000000) + rtt->tv_usec;
  snprintf(str, len, "%d.%03d", usec / 1000, usec % 1000);
  return str;
}

int timeval_fromstr(struct timeval *out, const char *in, uint32_t unit)
{
  static const int rzm[] = {1, 10, 100, 1000, 10000, 100000};
  long long l, r = 0;
  uint64_t v;
  char *eptr;
  int x, rz = 0;

  assert(unit == 1 || unit == 10 || unit == 100 || unit == 1000 ||
	 unit == 10000 || unit == 100000 || unit == 1000000);

  if(string_tollong(in, &l, &eptr, 10) != 0 || l < 0)
    return -1;
  if(*eptr == '.')
    {
      x = 1;
      while(eptr[x++] == '0')
	rz++;
      if(string_tollong(eptr+1, &r, &eptr, 10) != 0 || r < 0)
	return -1;
    }

  if(eptr[0] == 's' && eptr[1] == '\0')
    unit = 1000000;
  else if(eptr[0] == 'u' && eptr[1] == 's' && eptr[2] == '\0')
    unit = 1;
  else if(eptr[0] == 'm' && eptr[1] == 's' && eptr[2] == '\0')
    unit = 1000;
  else if(eptr[0] != '\0')
    return -1;

  if(r > unit - 1)
    return -1;

  switch(unit)
    {
    case 1000000: rz += 0; break;
    case 100000:  rz += 1; break;
    case 10000:   rz += 2; break;
    case 1000:    rz += 3; break;
    case 100:     rz += 4; break;
    case 10:      rz += 5; break;
    default:
      if(unit == 1 && r == 0)
	break;
      return -1;
    }

  v = l * unit;
  if(r > 0)
    {
      if(r < 10 && rz < 6)
	v += (r * (100000 / rzm[rz]));
      else if(r < 100 && rz < 5)
	v += (r * (10000 / rzm[rz]));
      else if(r < 1000 && rz < 4)
	v += (r * (1000 / rzm[rz]));
      else if(r < 10000 && rz < 3)
	v += (r * (100 / rzm[rz]));
      else if(r < 100000 && rz < 2)
	v += (r * (10 / rzm[rz]));
      else if(r < 1000000 && rz < 1)
	v += r;
      else
	return -1;
    }

  out->tv_sec  = v / 1000000;
  out->tv_usec = v % 1000000;

  return 0;
}

int timeval_iszero(const struct timeval *tv)
{
  if(tv->tv_sec == 0 && tv->tv_usec == 0)
    return 1;
  return 0;
}

#ifdef HAVE_FCNTL
int fcntl_unset(int fd, int flags)
{
  int i;

  if((i = fcntl(fd, F_GETFL, 0)) == -1)
    {
      return -1;
    }

  if(fcntl(fd, F_SETFL, i & (~flags)) == -1)
    {
      return -1;
    }

  return 0;
}

int fcntl_set(int fd, int flags)
{
  int i;

  if((i = fcntl(fd, F_GETFL, 0)) == -1)
    {
      return -1;
    }

  if(fcntl(fd, F_SETFL, i | flags) == -1)
    {
      return -1;
    }

  return 0;
}
#endif

size_t json_esc_len(const char *in)
{
  size_t len = 0;

  assert(in != NULL);
  while(*in != '\0')
    {
      if(isprint((unsigned char)*in) == 0)
	break;

      if(*in == '"' || *in == '\\')
	len++;
      len++;
      in++;
    }

  len++;
  return len;
}

char *json_esc(const char *in, char *out, size_t len)
{
  size_t off = 0;

  if(len == 0)
    return NULL;

  assert(in != NULL);
  while(*in != '\0')
    {
      if(isprint((unsigned char)*in) == 0)
	break;

      if(*in == '"' || *in == '\\')
	{
	  if(len - off <= 2)
	    break;
	  out[off++] = '\\';
	  out[off++] = *in;
	}
      else
	{
	  if(len - off <= 1)
	    break;
	  out[off++] = *in;
	}

      in++;
    }
  out[off++] = '\0';
  return out;
}

int url_parse(const char *url, uint16_t *port,
	      char **scheme_out, char **host_out, char **file_out)
{
  const char *ptr, *host;
  char *endptr;
  long lo;
  size_t scheme_len, host_len, file_len;

  *scheme_out = NULL;
  *host_out = NULL;
  *file_out = NULL;
  *port = 0;

  if(strncasecmp(url, "http://", 7) == 0)
    {
      scheme_len = 5;
      host = url+7;
    }
  else if(strncasecmp(url, "https://", 8) == 0)
    {
      scheme_len = 6;
      host = url+8;
    }
  else goto err;

  /* find the hostname */
  ptr = host;
  while(*ptr != '\0')
    {
      if(*ptr == '/' || *ptr == ':') break;
      if(isalnum((int)*ptr) == 0 && *ptr != '-' && *ptr != '.')
	goto err;
      ptr++;
    }
  if(ptr == host)
    goto err;
  host_len = (ptr - host) + 1;

  /* extract the port */
  if(*ptr == ':')
    {
      ptr++;
      lo = strtol(ptr, &endptr, 10);
      if(lo < 1 || lo > 65535)
	goto err;
      ptr = endptr;
      *port = (uint16_t)lo;
    }

  /* extract the file */
  file_len = strlen(ptr) + 1;

  if((*scheme_out = malloc(scheme_len)) == NULL ||
     (*host_out = malloc(host_len)) == NULL ||
     (file_len > 1 && (*file_out = malloc(file_len)) == NULL))
    goto err;

  memcpy(*scheme_out, url, scheme_len-1); (*scheme_out)[scheme_len-1] = '\0';
  memcpy(*host_out, host, host_len-1); (*host_out)[host_len-1] = '\0';
  if(file_len > 1)
    {
      memcpy(*file_out, ptr, file_len-1);
      (*file_out)[file_len-1] = '\0';
    }

  return 0;

 err:
  if(*scheme_out != NULL) { free(*scheme_out); *scheme_out = NULL; }
  if(*host_out != NULL) { free(*host_out); *host_out = NULL; }
  if(*file_out != NULL) { free(*file_out); *file_out = NULL; }
  return -1;
}

int string_isprint(const char *str, size_t len)
{
  size_t i = 0;

  for(i=0; i<len; i++)
    {
      if(isprint((unsigned char)str[i]) != 0)
	{
	  continue;
	}
      else if(str[i] == '\0')
	{
	  break;
	}
      else return 0;
    }

  return 1;
}

char *string_toupper(char *buf, size_t len, const char *in)
{
  size_t off = 0;
  while(in[off] != '\0' && len - off > 1)
    {
      buf[off] = toupper((unsigned char)in[off]);
      off++;
    }
  buf[off] = '\0';
  return buf;
}

char *string_tolower(char *buf, size_t len, const char *in)
{
  size_t off = 0;
  while(in[off] != '\0' && len - off > 1)
    {
      buf[off] = tolower((unsigned char)in[off]);
      off++;
    }
  buf[off] = '\0';
  return buf;
}

int string_tolong(const char *str, long *l)
{
  char *endptr;

  errno = 0;
  *l = strtol(str, &endptr, 0);
  if(*l == 0)
    {
      if(errno == EINVAL || endptr == str)
	return -1;
    }
  else if(*l == LONG_MIN || *l == LONG_MAX)
    {
      if(errno == ERANGE)
	return -1;
    }

  return 0;
}

int string_tollong(const char *str, long long *l, char **endptr_out, int base)
{
  char *endptr;

  errno = 0;
  *l = strtoll(str, &endptr, base);
  if(*l == 0)
    {
      if(errno == EINVAL || endptr == str)
	return -1;
    }
  else if(*l == LLONG_MIN || *l == LLONG_MAX)
    {
      if(errno == ERANGE)
	return -1;
    }

  if(endptr_out != NULL)
    *endptr_out = endptr;
  return 0;
}

/*
 * string_isalnum
 *
 * scan the word to establish if it is made up entirely of
 * alphanumeric characters.
 */
int string_isalnum(const char *str)
{
  if(*str == '\0')
    return 0;
  while(isalnum((unsigned char)*str) != 0)
    str++;
  if(*str == '\0')
    return 1;
  return 0;
}

/*
 * string_isdigit
 *
 * scan the word to establish if it is made up entirely of digits,
 * with no + or - at the start.
 */
int string_isdigit(const char *str)
{
  if(*str == '\0')
    return 0;
  while(isdigit((unsigned char)*str) != 0)
    str++;
  if(*str == '\0')
    return 1;
  return 0;
}

/*
 * string_isalpha
 *
 * scan the string to establish if it is made up entirely of alphabetic
 * characters.
 */
int string_isalpha(const char *str)
{
  if(*str == '\0')
    return 0;
  while(isalpha((unsigned char)*str) != 0)
    str++;
  if(*str == '\0')
    return 1;
  return 0;
}

/*
 * string_isnumber
 *
 * scan the word to establish if it an integer.
 */
int string_isnumber(const char *str)
{
  int i = 1;

  if(str[0] != '-' && str[0] != '+' && isdigit((unsigned char)str[0]) == 0)
    {
      return 0;
    }

  while(str[i] != '\0')
    {
      if(isdigit((unsigned char)str[i]) != 0)
	{
	  i++;
	  continue;
	}

      return 0;
    }

  return 1;
}

/*
 * string_isfloat
 *
 * scan the word to establish if it is a float.
 */
int string_isfloat(const char *str)
{
  int seen_dp = 0;
  int i = 1;

  if(str[0] != '-' && str[0] != '+' && isdigit((unsigned char)str[0]) == 0)
    {
      if(str[0] == '.')
	{
	  seen_dp = 1;
	}
      else return 0;
    }

  while(str[i] != '\0')
    {
      if(isdigit((unsigned char)str[i]) != 0)
	{
	  i++;
	  continue;
	}
      else if(str[i] == '.')
	{
	  /* if the decimal point has already been seen */
	  if(seen_dp == 1)
	    {
	      return 0;
	    }

	  i++;
	  seen_dp = 1;
	  continue;
	}
      return 0;
    }

  return 1;
}

/*
 * string_nextword
 *
 * scan for the next word occurance in the string, after the current
 * word.  if there is no other word after this one, return NULL.
 */
char *string_nextword(char *buf)
{
  /* scan for a start of a word */
  while(*buf != '\0' && isspace((int)*buf) == 0)
    {
      buf++;
    }

  if(*buf == '\0')
    {
      return NULL;
    }
  *buf = '\0';
  buf++;

  /* now scan for the end of the word */
  while(*buf != '\0' && isspace((int)*buf) != 0)
    {
      buf++;
    }

  if(*buf == '\0')
    {
      return NULL;
    }

  return buf;
}

const char *string_findlc(const char *str, const char *find)
{
  const char *sp = str;
  int i;

  assert(*find != '\0');
  for(;;)
    {
      for(i=0; find[i] != '\0'; i++)
	if(tolower((int)sp[i]) != find[i])
	  break;
      if(find[i] == '\0')
	return sp;
      if(sp[i] == '\0')
	break;
      sp++;
    }

  return NULL;
}

/*
 * string_nullterm
 *
 * null terminate the string pointed to by buf at the first occurance of
 * a character in the delim string.
 *
 * if null termination occurs, this function returns a pointer to the first
 * byte of the buf (i.e. the buf parameter passed)
 */
char *string_nullterm(char *buf, const char *delim, char **next)
{
  const char *dtmp;
  char *tmp;

  if(delim == NULL || *delim == '\0' || (tmp = buf) == NULL)
    return NULL;

  while(*tmp != '\0')
    {
      dtmp = delim;

      while(*dtmp != '\0')
	{
	  if(*tmp != *dtmp)
	    {
	      dtmp++;
	      continue;
	    }

	  *tmp = '\0';
	  if(next != NULL)
	    {
	      tmp++;
	      *next = tmp;
	    }
	  return buf;
	}

      tmp++;
    }

  if(next != NULL)
    *next = NULL;
  return buf;
}

char *string_nullterm_char(char *buf, char delim, char **next)
{
  char *tmp;

  if((tmp = buf) == NULL)
    return NULL;

  while(*tmp != '\0')
    {
      if(*tmp == delim)
	{
	  *tmp = '\0';
	  if(next != NULL)
	    {
	      tmp++;
	      *next = tmp;
	    }
	  return buf;
	}

      tmp++;
    }

  if(next != NULL)
    *next = NULL;
  return buf;
}

char *string_lastof(char *str, const char *delim)
{
  char *lastof = NULL;
  const char *d;
  int i;

  for(i=0; str[i] != '\0'; i++)
    {
      for(d = delim; *d != '\0'; d++)
	{
	  if(str[i] == *d)
	    {
	      lastof = &str[i];
	      break;
	    }
	}
    }

  return lastof;
}

char *string_lastof_char(char *str, char delim)
{
  char *lastof = NULL;
  int i;

  for(i=0; str[i] != '\0'; i++)
    {
      if(str[i] == delim)
	{
	  lastof = &str[i];
	}
    }

  return lastof;
}

char *string_firstof_char(char *str, char delim)
{
  char *firstof = NULL;
  int i;

  for(i=0; str[i] != '\0'; i++)
    {
      if(str[i] == delim)
	{
	  firstof = &str[i];
	  break;
	}
    }

  return firstof;
}

char *string_concat(char *str, size_t len, size_t *off, const char *fs, ...)
{
  va_list ap;
  size_t left;
  int wc;

  if(len < *off)
    return NULL;

  if((left = len - *off) == 0)
    return str;

  va_start(ap, fs);
  wc = vsnprintf(str + *off, left, fs, ap);
  va_end(ap);

  if(wc < 0)
    return NULL;

  *off = *off + ((size_t)wc < left ? (size_t)wc : left);
  return str;
}

char *string_byte2hex(char *str, size_t len, size_t *off,
		      const uint8_t *b, size_t bl)
{
  size_t i;

  if(len < *off)
    return NULL;

  if((len - *off) == 0)
    return str;

  for(i=0; i<bl; i++)
    {
      if(len - *off <= 2)
	break;
      byte2hex(b[i], str+(*off));
      (*off) += 2;
    }

  str[*off] = '\0';
  return str;
}

/*
 * string_addrport
 *
 * given an input string, return the ip address / name in the first part
 * (if present) and the port number in the second.  do some basic sanity
 * checking as well.
 */
int string_addrport(const char *in, char **first, int *port)
{
  char *ptr, *dup = NULL, *first_tmp = NULL;
  long lo;

  if(string_isnumber(in))
    {
      if(string_tolong(in, &lo) == -1 || lo < 1 || lo > 65535)
	goto err;
      *first = NULL;
      *port  = lo;
      return 0;
    }

  if((dup = strdup(in)) == NULL)
    goto err;

  if(dup[0] == '[')
    {
      string_nullterm_char(dup, ']', &ptr);
      if(ptr == NULL || *ptr != ':' || (first_tmp = strdup(dup+1)) == NULL)
	goto err;
      ptr++;
    }
  else
    {
      string_nullterm_char(dup, ':', &ptr);
      if(ptr == NULL || (first_tmp = strdup(dup)) == NULL)
	goto err;
    }

  if(string_tolong(ptr, &lo) != 0 || lo < 1 || lo > 65535)
    goto err;

  *first = first_tmp;
  *port  = lo;
  free(dup);
  return 0;

 err:
  if(first_tmp != NULL) free(first_tmp);
  if(dup != NULL) free(dup);
  return -1;
}

#ifndef NDEBUG
int string_isdash(const char *str)
{
  if(str[0] == '-' && str[1] == '\0')
    return 1;
  return 0;
}
#endif

int string_endswith(const char *in, const char *ending)
{
  size_t in_len = strlen(in);
  size_t end_len = strlen(ending);
  if(end_len >= in_len ||
     strcasecmp(in + in_len - end_len, ending) != 0)
    return 0;
  return 1;
}

void mem_concat(void *dst,const void *src,size_t len,size_t *off,size_t size)
{
  assert(*off + len <= size);
  memcpy(((uint8_t *)dst) + *off, src, len);
  *off += len;
  return;
}

int ishex(char c)
{
  if((c >= '0' && c <= '9') ||
     (c >= 'a' && c <= 'f') ||
     (c >= 'A' && c <= 'F'))
    {
      return 1;
    }
  return 0;
}

/*
 * string_ishex
 *
 * scan the string to establish if it is made up entirely of hexadecimal
 * characters.  if it is, return the number of characters.
 */
int string_ishex(const char *str)
{
  int i;
  for(i=0; str[i] != '\0'; i++)
    if(ishex(str[i]) == 0)
      return 0;
  return i;
}

uint8_t hex2byte(char a, char b)
{
  uint8_t out;

  assert(ishex(a));
  assert(ishex(b));

  if(a <= '9')      out = (((int)a - (int)'0') << 4);
  else if(a <= 'F') out = (((int)a - (int)'A' + 10) << 4);
  else              out = (((int)a - (int)'a' + 10) << 4);

  if(b <= '9')      out |= ((int)b - (int)'0');
  else if(b <= 'F') out |= ((int)b - (int)'A' + 10);
  else              out |= ((int)b - (int)'a' + 10);

  return out;
}

void byte2hex(uint8_t byte, char *a)
{
  static const char hex[] = "0123456789abcdef";
  a[0] = hex[(byte >> 4)];
  a[1] = hex[byte & 0x0f];
  return;
}

uint16_t bytes_ntohs(const uint8_t *bytes)
{
  uint16_t u16;
  memcpy(&u16, bytes, 2);
  return ntohs(u16);
}

uint32_t bytes_ntohl(const uint8_t *bytes)
{
  uint32_t u32;
  memcpy(&u32, bytes, 4);
  return ntohl(u32);
}

void bytes_htons(uint8_t *bytes, uint16_t u16)
{
  uint16_t tmp = htons(u16);
  memcpy(bytes, &tmp, 2);
  return;
}

void bytes_htonl(uint8_t *bytes, uint32_t u32)
{
  uint32_t tmp = htonl(u32);
  memcpy(bytes, &tmp, 4);
  return;
}

int read_wrap(int fd, void *ptr, size_t *rc_out, size_t rt)
{
  uint8_t *buf;
  int      ret = 0;
  ssize_t  r;
  size_t   rc;

  assert(rt > 0);
  assert(ptr != NULL);

  buf = (uint8_t *)ptr;

  for(rc = 0; rc < rt; rc += r)
    {
      if((r = read(fd, buf+rc, rt-rc)) < 0)
	{
	  ret = -1;
	  break;
	}
      else if(r == 0)
	{
	  ret = -2;
	  break;
	}
    }

  if(rc_out != NULL)
    *rc_out = rc;

  return ret;
}

int write_wrap(int fd, const void *ptr, size_t *wc_out, size_t wt)
{
  int      ret = 0;
  ssize_t  w;
  size_t   wc;

  assert(wt > 0);
  assert(ptr != NULL);

  for(wc = 0; wc < wt; wc += w)
    {
      if((w = write(fd, ((const uint8_t *)ptr)+wc, wt-wc)) < 0)
	{
	  ret = -1;
	  break;
	}
    }

  if(wc_out != NULL)
    *wc_out = wc;

  return ret;
}

/*
 * fstat_mtime
 *
 * simple utility function that gets the mtime field from
 * a fstat call as a time_t.
 */
int fstat_mtime(int fd, time_t *mtime)
{
  struct stat sb;

  if(fstat(fd, &sb) != 0)
    {
      return -1;
    }

  *mtime = sb.st_mtime;
  return 0;
}

/*
 * stat_mtime
 *
 * simple utility function that gets the mtime field from
 * a stat call as a time_t.
 */
int stat_mtime(const char *filename, time_t *mtime)
{
  struct stat sb;

  if(stat(filename, &sb) != 0)
    {
      return -1;
    }

  *mtime = sb.st_mtime;
  return 0;
}

#if defined(HAVE_SYSCTL) && !defined(__linux__)
int sysctl_wrap(int *mib, u_int len, void **buf, size_t *size)
{
  if(sysctl(mib, len, NULL, size, NULL, 0) != 0)
    {
      return -1;
    }

  if(*size == 0)
    {
      *buf = NULL;
      return 0;
    }

  if((*buf = malloc(*size)) == NULL)
    {
      return -1;
    }

  if(sysctl(mib, len, *buf, size, NULL, 0) != 0)
    {
      free(*buf);
      return -1;
    }

  return 0;
}
#endif

void random_seed(void)
{
#if defined(_WIN32) || defined(HAVE_ARC4RANDOM) /* seed crypto-insecure prng */
  return;
#else
  struct timeval tv;
  gettimeofday_wrap(&tv);
  srandom(tv.tv_usec);
  return;
#endif
}

int random_u32(uint32_t *r)
{
#if defined(_WIN32) /* use rand_s on windows */
  unsigned int ui;
  if(rand_s(&ui) != 0)
    return -1;
  *r = ui;
#elif defined(HAVE_ARC4RANDOM)
  *r = arc4random();
#else
  *r = random();
#endif
  return 0;
}

int random_u16(uint16_t *r)
{
#ifdef _WIN32 /* use rand_s on windows */
  unsigned int ui;
  if(rand_s(&ui) != 0)
    return -1;
  *r = ui;
#elif defined(HAVE_ARC4RANDOM)
  *r = arc4random();
#else
  *r = random();
#endif
  return 0;
}

int random_u8(uint8_t *r)
{
#ifdef _WIN32 /* use rand_s on windows */
  unsigned int ui;
  if(rand_s(&ui) != 0)
    return -1;
  *r = ui;
#elif defined(HAVE_ARC4RANDOM)
  *r = arc4random();
#else
  *r = random();
#endif
  return 0;
}

/*
 * countbits32
 *
 * count the number of bits set in v.  first published by Peter Wegner in
 * CACM 3 (1960), 322.
 */
int countbits32(uint32_t v)
{
  int c;
  for(c=0; v != 0; c++)
    v &= v - 1;
  return c;
}

/* Fisher-Yates shuffle */
int shuffle16(uint16_t *array, size_t len)
{
  size_t x, n = len;
  uint32_t k;
  uint16_t tmp;

  while(n > 1)
    {
      n--;
      if(random_u32(&k) != 0)
	return -1;

      x = k % (n+1);

      tmp = array[x];
      array[x] = array[n];
      array[n] = tmp;
    }

  return 0;
}

/* Fisher-Yates shuffle */
int shuffle32(uint32_t *array, size_t len)
{
  size_t n = len;
  uint32_t k, tmp;

  while(n > 1)
    {
      n--;
      if(random_u32(&k) != 0)
	return -1;
      k %= n+1;

      tmp = array[k];
      array[k] = array[n];
      array[n] = tmp;
    }

  return 0;
}

int min_array(const int *array, size_t len)
{
  int x;
  size_t i;
  x = array[0];
  for(i=1; i<len; i++)
    if(x > array[i])
      x = array[i];
  return x;
}

uint16_t in_cksum(const void *buf, size_t len)
{
  uint16_t *w = (uint16_t *)buf;
  size_t l = len;
  int sum = 0;

  while(l > 1)
    {
      sum += *w++;
      l   -= 2;
    }

  if(l != 0)
    {
      sum += ((uint8_t *)w)[0];
    }

  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return ~sum;
}

/*
 * uudecode_4
 *
 * decode four ascii characters to form up to 3 binary bytes.
 */
static int uudecode_4(uint8_t *out, const char *in, size_t c)
{
  char a, b;

  if(c == 0)
    return -1;

  if(in[0] >= '!' && in[0] <= '`')
    a = in[0];
  else return -1;

  if(in[1] >= '!' && in[1] <= '`')
    b = in[1];
  else return -1;

  out[0] = (((a - 32) & 0x3f) << 2 & 0xfc) | (((b - 32) & 0x3f) >> 4 & 0x3);

  if(in[2] >= '!' && in[2] <= '`')
    a = in[2];
  else return -1;

  if(c > 1)
    out[1] = (((b - 32) & 0x3f) << 4 & 0xf0) | (((a - 32) & 0x3f) >> 2 & 0xf);

  if(in[3] >= '!' && in[3] <= '`')
    b = in[3];
  else return -1;

  if(c > 2)
    out[2] = (((a - 32) & 0x3f) << 6 & 0xc0) |  ((b - 32) & 0x3f);

  return 0;
}

/*
 * uudecode_line
 *
 * decode a uuencoded line into binary bytes.
 */
int uudecode_line(const char *in, size_t ilen, uint8_t *out, size_t *olen)
{
  size_t i, j, o;

  if(ilen == 0)
    goto err;

  /* EOF */
  if(in[0] == '`')
    {
      *olen = 0;
      return 0;
    }

  /* figure out the number of binary bytes that should be found */
  if(in[0] >= '!' && in[0] <= '`')
    o = in[0] - 32;
  else goto err;

  /* make sure we can uudecode to the buffer provided */
  if(o > *olen)
    goto err;

  i = 0;
  j = 1;

  for(;;)
    {
      /* there needs to be at least four characters remaining */
      if(ilen - j < 4)
	goto err;

      /* decode 4 characters into 3 bytes */
      if(uudecode_4(out+i, in+j, o-i) != 0)
	goto err;

      /* next block of 4 characters */
      j += 4;

      /* advance */
      if(o-i > 3)
	i += 3;
      else break;
    }

  *olen = o;
  return 0;

 err:
  return -1;
}

void *uudecode(const char *in, size_t len)
{
  uint8_t *out = NULL;
  size_t i, j, k, x;

  /* if the first character is a ` (EOF) there is nothing to decode */
  if(in[0] == '`')
    return NULL;

  i = 0;
  x = 0;

  /* first, figure out how much memory to allocate */
  for(;;)
    {
      /* make sure character is valid */
      if(in[i] < '!' || in[i] > '`')
	{
	  goto err;
	}

      /* check for EOF */
      if(in[i] == '`')
	break;

      /* number of uuencoded bytes on this line */
      j = in[i++] - 32;

      /* number of ascii bytes required */
      k = j + (j/3);
      if((k % 4) != 0)
	{
	  k /= 4;
	  k++;
	  k *= 4;
	}

      /* advance to the end of the line */
      if(len - i < k+1 || in[i+k] != '\n')
	{
	  goto err;
	}
      i += k + 1;
      x += j;
    }

  /* make sure the uuencoded data ends with a new line */
  if(len - i < 1 || in[i+1] != '\n')
    {
      goto err;
    }

  if((out = malloc(x)) == NULL)
    goto err;

  i = 0;
  j = 0;
  for(;;)
    {
      /* number of uuencoded bytes on this line */
      k = in[i++] - 32;
      for(;;)
	{
	  /* there needs to be at least four characters remaining */
	  if(len - i < 4)
	    goto err;

	  /* decode the next four */
	  if(uudecode_4(out+j, in+i, x-j) != 0)
	    goto err;

	  i += 4;

	  if(k > 3)
	    {
	      j += 3;
	      k -= 3;
	    }
	  else
	    {
	      j += k;
	      break;
	    }
	}

      /* advance to next line */
      if(in[i] != '\n')
	goto err;
      i++;

      if(j == x)
	break;
    }

  return out;

 err:
  if(out != NULL) free(out);
  return NULL;
}

static void uuencode_3(uint8_t *out, uint8_t a, uint8_t b, uint8_t c)
{
  uint8_t t;

  out[0] = (t =  ((a >> 2)                     & 0x3f)) != 0 ? t + 32 : '`';
  out[1] = (t = (((a << 4) | ((b >> 4) & 0xf)) & 0x3f)) != 0 ? t + 32 : '`';
  out[2] = (t = (((b << 2) | ((c >> 6) & 0x3)) & 0x3f)) != 0 ? t + 32 : '`';
  out[3] = (t =   (c                           & 0x3f)) != 0 ? t + 32 : '`';

  return;
}

size_t uuencode_len(size_t ilen, size_t *complete, size_t *leftover)
{
  size_t len;
  size_t complete_lines;
  size_t leftover_bytes;

  assert(ilen != 0);

  /*
   * figure out how many complete lines there are,
   * and then how many leftover bytes there are
   */
  complete_lines = ilen / 45;
  leftover_bytes = ilen % 45;

  /*
   * an input line of 45 characters is transformed into an 60 character
   * sequence, with the length encoded as a character at the start, and
   * a new-line character at the end of the line
   */
  len = (complete_lines * 62);

  /*
   * if there are leftover bytes, then each group of three characters
   * will take four output bytes.  if the number of leftover bytes is not
   * a multiple of three, then they are encoded in a 4 character sequence.
   * finally, there's a length character at the start and a new line at the
   * end.
   */
  if(leftover_bytes != 0)
    {
      len += ((leftover_bytes / 3) * 4);
      if((leftover_bytes % 3) > 0)
	{
	  len += 4;
	}
      len += 2;
    }

  /* allocate the end-of-data bytes */
  len += 2;

  if(complete != NULL) *complete = complete_lines;
  if(leftover != NULL) *leftover = leftover_bytes;

  return len;
}

/*
 * uuencode_bytes
 *
 * take an input buffer, and an offset into that buffer, and encode as
 * much of it as possible into the output buffer
 */
size_t uuencode_bytes(const uint8_t *in, size_t len, size_t *off,
		      uint8_t *out, size_t olen)
{
  static const uint8_t b[] = {
    2, 6,6,6, 10,10,10, 14,14,14, 18,18,18, 22,22,22, 26,26,26, 30,30,30,
    34,34,34, 38,38,38, 42,42,42, 46,46,46, 50,50,50, 54,54,54, 58,58,58,
    62,62,62};
  size_t ooff = 0, i, lc, bb;

  assert(*off < len);

  for(;;)
    {
      /* determine how many characters will be written out this time */
      if(len - *off >= 45)
	lc = 45;
      else
	lc = len - *off;

      /* determine how many bytes will be required */
      bb = b[lc];
      if(*off + lc == len)
	bb += 2;

      /* if not enough space, then stop now */
      if(olen - ooff < bb)
	break;

      /* write out the line */
      out[ooff++] = 32 + lc;
      for(i=0; i+3<=lc; i+=3)
	{
	  uuencode_3(out+ooff, in[*off], in[*off+1], in[*off+2]);
	  *off += 3;
	  ooff += 4;
	}
      if(i != lc)
	{
	  lc -= i;
      	  uuencode_3(out+ooff, in[*off], lc == 2 ? in[*off+1] : 0, 0);
	  *off += lc;
	  ooff += 4;
	}
      out[ooff++] = '\n';

      /* encode eof */
      if(*off == len)
	{
	  out[ooff++] = '`';
	  out[ooff++] = '\n';
	  break;
	}
    }

  return ooff;
}

int uuencode(const uint8_t *in, size_t ilen, uint8_t **out, size_t *olen)
{
  uint8_t *ptr;
  size_t len;
  size_t complete_lines;
  size_t leftover_bytes;
  size_t i, j;

  /* figure out how large the allocated buffer needs to be */
  len = uuencode_len(ilen, &complete_lines, &leftover_bytes);
  assert(len != 0);

  /* allocate memory to encode the data to */
  if((ptr = malloc(len)) == NULL)
    return -1;
  *out  = ptr;
  *olen = len;

  /* encode all complete lines */
  for(i=0; i<complete_lines; i++)
    {
      *ptr = (32 + 45); ptr++;
      for(j=0; j<15; j++)
	{
	  uuencode_3(ptr, in[0], in[1], in[2]);
	  in  += 3;
	  ptr += 4;
	}
      *ptr = '\n'; ptr++;
    }

  /* encode the last line */
  if(leftover_bytes != 0)
    {
      /* encode groups of 3 input bytes */
      *ptr = (32 + leftover_bytes); ptr++;
      for(j=0; j<leftover_bytes/3; j++)
	{
	  uuencode_3(ptr, in[0], in[1], in[2]);
	  in  += 3;
	  ptr += 4;
	}

      /* if there are one or two straggling bytes left, encode those */
      if((leftover_bytes % 3) > 0)
	{
	  uuencode_3(ptr, in[0], (leftover_bytes % 3) == 2 ? in[1] : 0, 0);
	  ptr += 4;
	}

      *ptr = '\n'; ptr++;
    }

  /* this line has no data -- uuencode EOF */
  *ptr = '`'; ptr++;
  *ptr = '\n';

  return 0;
}

uint16_t byteswap16(uint16_t word)
{
  return ((word >> 8) | (word << 8));
}

uint32_t byteswap32(uint32_t word)
{
  return ((word << 24) | (word >> 24) |
	  ((word & 0xff00) << 8) | ((word >> 8) & 0xff00));
}

#ifndef _WIN32 /* SOCKET vs int on windows */
int socket_sport(int fd, uint16_t *sport)
#else
int socket_sport(SOCKET fd, uint16_t *sport)
#endif
{
  struct sockaddr *sa;
  struct sockaddr_storage ss;
  socklen_t sl;

  sl = sizeof(struct sockaddr_storage);
  if(getsockname(fd, (struct sockaddr *)&ss, &sl) != 0)
    return -1;
  sa = (struct sockaddr *)&ss;
  if(sa->sa_family == AF_INET)
    *sport = ntohs(((struct sockaddr_in *)sa)->sin_port);
  else if(sa->sa_family == AF_INET6)
    *sport = ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
  else
    return -1;
  return 0;
}

char *strerror_wrap(char *errbuf, size_t errlen, const char *format, ...)
{
  char message[512];
  int ecode = errno;
  va_list ap;

  va_start(ap, format);
  vsnprintf(message, sizeof(message), format, ap);
  va_end(ap);
  snprintf(errbuf, errlen, "%s: %s", message, strerror(ecode));

  return errbuf;
}

int fd_lines(int fd, int (*func)(char *, void *), void *param)
{
  char *readbuf = NULL;
  size_t readbuf_len, readbuf_off;
  size_t start, end, off;
  int rc = -1;
  ssize_t ss;

  readbuf_len = 8192; readbuf_off = 0;
  if((readbuf = malloc(readbuf_len)) == NULL)
    goto done;

  while((ss = read(fd, readbuf+readbuf_off, readbuf_len-readbuf_off-1)) >= 0)
    {
      start = 0; off = 0;
      end = readbuf_off + ss;

      while(off <= end)
	{
	  if(off == end && ss != 0)
	    break;
	  if(readbuf[off] == '\n' || (off == end && start < off))
	    {
	      readbuf[off] = '\0';
	      if(func(readbuf+start, param) != 0)
		goto done;
	      start = ++off;
	    }
	  else
	    {
	      ++off;
	    }
	}

      if(ss == 0)
	{
	  rc = 0;
	  break;
	}
      else if(start == 0)
	{
	  readbuf_len += 8192;
	  readbuf_off = off;
	  if(realloc_wrap((void **)&readbuf, readbuf_len) != 0)
	    goto done;
	}
      else
	{
	  memmove(readbuf, readbuf+start, end - start);
	  readbuf_off = end - start;
	}
    }

 done:
  if(readbuf != NULL) free(readbuf);
  return rc;
}

/* process a text file, line by line */
int file_lines(const char *filename, int (*func)(char *, void *), void *param)
{
  int rc, fd = -1;
  if((fd = open(filename, O_RDONLY)) < 0)
    return -1;
  rc = fd_lines(fd, func, param);
  close(fd);
  return rc;
}

char *offt_tostr(char *buf, size_t len, off_t off, int lz, char c)
{
  char sp[16];

  assert(lz >= 0);

  if(sizeof(int) == sizeof(off_t))
    {
      if(lz == 0)
	snprintf(sp, sizeof(sp), "%%%c", c);
      else
	snprintf(sp, sizeof(sp), "%%0%d%c", lz, c);
    }
  else if(sizeof(long int) == sizeof(off_t))
    {
      if(lz == 0)
	snprintf(sp, sizeof(sp), "%%l%c", c);
      else
	snprintf(sp, sizeof(sp), "%%0%dl%c", lz, c);
    }
  else if(sizeof(long long int) == sizeof(off_t))
    {
      if(lz == 0)
	snprintf(sp, sizeof(sp), "%%ll%c", c);
      else
	snprintf(sp, sizeof(sp), "%%0%dll%c", lz, c);
    }
  else
    {
      return NULL;
    }

  snprintf(buf, len, sp, off);
  return buf;
}
