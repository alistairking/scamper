/*
 * utils.h
 *
 * $Id: utils.h,v 1.159 2024/04/28 00:47:41 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2014 The Regents of the University of California
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

#ifndef __UTILS_H
#define __UTILS_H

#if defined(HAVE_FUNC_ATTRIBUTE_PURE)
#define ATTRIBUTE_PURE __attribute__((pure))
#else
#define ATTRIBUTE_PURE
#endif

#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
#define ATTRIBUTE_NONNULL __attribute__((nonnull))
#else
#define ATTRIBUTE_NONNULL
#endif

#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL) && defined(HAVE_FUNC_ATTRIBUTE_PURE)
#define ATTRIBUTE_NONNULL_PURE __attribute__((nonnull, pure))
#else
#define ATTRIBUTE_NONNULL_PURE
#endif

#if defined(HAVE_FUNC_ATTRIBUTE_MALLOC)
#define ATTRIBUTE_MALLOC __attribute__((malloc))
#else
#define ATTRIBUTE_MALLOC
#endif

#if defined(HAVE_FUNC_ATTRIBUTE_CONST)
#define ATTRIBUTE_CONST __attribute__((const))
#else
#define ATTRIBUTE_CONST
#endif

/*
 * Functions for dealing with time and timestamps
 */
int timeval_cmp(const struct timeval *a, const struct timeval *b)
  ATTRIBUTE_NONNULL_PURE;
int timeval_cmp_lt(const struct timeval *tv, time_t s, suseconds_t us)
  ATTRIBUTE_NONNULL_PURE;
int timeval_cmp_gt(const struct timeval *tv, time_t s, suseconds_t us)
  ATTRIBUTE_NONNULL_PURE;

int timeval_inrange_us(const struct timeval *a, const struct timeval *b, int c)
  ATTRIBUTE_NONNULL_PURE;

int timeval_diff_ms(const struct timeval *from, const struct timeval *to)
  ATTRIBUTE_NONNULL_PURE;
int timeval_diff_us(const struct timeval *from, const struct timeval *to)
  ATTRIBUTE_NONNULL_PURE;
void timeval_diff_tv(struct timeval *out,
		     const struct timeval *from, const struct timeval *to)
  ATTRIBUTE_NONNULL;

void timeval_add_ms(struct timeval *out, const struct timeval *in, int ms)
  ATTRIBUTE_NONNULL;
void timeval_add_us(struct timeval *out, const struct timeval *in, int us)
  ATTRIBUTE_NONNULL;
void timeval_add_tv(struct timeval *tv, const struct timeval *add)
  ATTRIBUTE_NONNULL;
void timeval_add_tv3(struct timeval *out, const struct timeval *in,
		     const struct timeval *add)
  ATTRIBUTE_NONNULL;
void timeval_add_s(struct timeval *out, const struct timeval *in, int s)
  ATTRIBUTE_NONNULL;
void timeval_sub_tv(struct timeval *out, const struct timeval *sub)
  ATTRIBUTE_NONNULL;
void timeval_sub_us(struct timeval *out, const struct timeval *in, int us)
  ATTRIBUTE_NONNULL;
void timeval_cpy(struct timeval *dst, const struct timeval *src)
  ATTRIBUTE_NONNULL;
char *timeval_tostr_us(const struct timeval *rtt, char *str, size_t len)
  ATTRIBUTE_NONNULL;

int timeval_iszero(const struct timeval *tv) ATTRIBUTE_NONNULL;
int timeval_fromstr(struct timeval *out, const char *in, uint32_t unit)
  ATTRIBUTE_NONNULL;

void gettimeofday_wrap(struct timeval *tv) ATTRIBUTE_NONNULL;

int fstat_mtime(int fd, time_t *mtime) ATTRIBUTE_NONNULL;
int stat_mtime(const char *filename, time_t *mtime) ATTRIBUTE_NONNULL;

/*
 * Functions for dealing with memory allocation
 */
#ifndef DMALLOC
#ifdef HAVE_CALLOC
#define malloc_zero(size) calloc(1, (size))
#else
void *malloc_zero(size_t size) ATTRIBUTE_MALLOC;
#endif
#else
void *malloc_zero_dm(size_t size, const char *file, int line);
#define malloc_zero(size) malloc_zero_dm((size), __FILE__, __LINE__)
#endif

#ifndef DMALLOC
void *memdup(const void *ptr, size_t len);
int   realloc_wrap(void **ptr, size_t len);
#else
int   realloc_wrap_dm(void **ptr,size_t len, const char *file, int line);
#define realloc_wrap(ptr, len) realloc_wrap_dm((ptr),(len), __FILE__,__LINE__)
#define memdup(ptr, len) memcpy(malloc(len), ptr, len)
#endif

void mem_concat(void *dst,const void *src,size_t len,size_t *off,size_t size)
  ATTRIBUTE_NONNULL;

typedef int (*array_cmp_t)(const void *va, const void *vb);

#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
void *array_find(void **a, size_t nmemb, const void *item, array_cmp_t cmp)
  __attribute__ ((nonnull(3, 4)));
int array_findpos(void **a, size_t nmemb, const void *item,
		  array_cmp_t cmp, size_t *pos)
  __attribute__ ((nonnull(3, 4, 5)));
#else
void *array_find(void **a, size_t nmemb, const void *item, array_cmp_t cmp);
int array_findpos(void **a, size_t nmemb, const void *item,
		  array_cmp_t cmp, size_t *pos);
#endif

void array_remove(void **a, size_t *nmemb, size_t pos) ATTRIBUTE_NONNULL;
void array_qsort(void **a, size_t n, array_cmp_t cmp);

#ifndef DMALLOC
int array_insert(void ***a, size_t *nmemb, void *item, array_cmp_t cmp);
int array_insert_gb(void ***a, size_t *nmemb, size_t *mmemb, size_t growby,
		    void *item, array_cmp_t cmp);
#else
int array_insert_dm(void ***a, size_t *nmemb, void *item, array_cmp_t cmp,
		    const char *file, int line);
int array_insert_gb_dm(void ***a, size_t *nmemb, size_t *mmemb, size_t growby,
		       void *item, array_cmp_t cmp, const char *file, int line);
#define array_insert(a, nmemb, item, cmp) \
  array_insert_dm((a), (nmemb), (item), (cmp), __FILE__, __LINE__)
#define array_insert_gb(a, nmemb, mmemb, growby, item, cmp) \
  array_insert_gb_dm((a), (nmemb), (mmemb), (growby), (item), (cmp), \
		     __FILE__, __LINE__)
#endif

/*
 * Functions for dealing with raw IPv4/IPv6 addresses
 */
int addr4_cmp(const struct in_addr *a, const struct in_addr *b)
  ATTRIBUTE_NONNULL_PURE;
int addr4_human_cmp(const struct in_addr *a, const struct in_addr *b)
  ATTRIBUTE_NONNULL_PURE;
int addr6_cmp(const struct in6_addr *a, const struct in6_addr *b)
  ATTRIBUTE_NONNULL_PURE;
int addr6_human_cmp(const struct in6_addr *a, const struct in6_addr *b)
  ATTRIBUTE_NONNULL_PURE;
void addr6_add(struct in6_addr *out,
	       const struct in6_addr *x, const struct in6_addr *y)
  ATTRIBUTE_NONNULL;
int addr6_add_netlen(struct in6_addr *in, int netlen)
  ATTRIBUTE_NONNULL;
void addr6_sub(struct in6_addr *out,
	       const struct in6_addr *y, const struct in6_addr *x)
  ATTRIBUTE_NONNULL;
int addr_cmp(int af, const void *a, const void *b)
  ATTRIBUTE_NONNULL_PURE;
const char *addr_tostr(int af, const void *addr, char *buf, size_t len)
  ATTRIBUTE_NONNULL;

/*
 * Functions for dealing with sockaddr addresses
 */
int sockaddr_compose(struct sockaddr *sa, int af, const void *addr, int port);
int sockaddr_compose_un(struct sockaddr *sa, const char *name)
  ATTRIBUTE_NONNULL;
int sockaddr_compose_str(struct sockaddr *sa, const char *ip, int port)
  ATTRIBUTE_NONNULL;
int sockaddr_len(const struct sockaddr *sa)
  ATTRIBUTE_NONNULL_PURE;
char *sockaddr_tostr(const struct sockaddr *sa, char *buf, size_t len)
  ATTRIBUTE_NONNULL;

/*
 * Functions for dealing with fcntl flags on a file descriptor
 */
int fcntl_set(int fd, int flags);
int fcntl_unset(int fd, int flags);

/* get the source port that a socket is bound to */
#ifndef _WIN32 /* SOCKET vs int on windows */
int socket_sport(int fd, uint16_t *sport) ATTRIBUTE_NONNULL;
#else
int socket_sport(SOCKET fd, uint16_t *sport) ATTRIBUTE_NONNULL;
#endif

/* format a string with strerror appended */
#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
char *strerror_wrap(char *errbuf, size_t errlen, const char *format, ...)
  __attribute__((format(printf, 3, 4)));
#else
char *strerror_wrap(char *errbuf, size_t errlen, const char *format, ...);
#endif

/*
 * Functions for parsing strings
 */
char *string_nextword(char *str) ATTRIBUTE_NONNULL;
char *string_nullterm(char *str, const char *delim, char **next);
char *string_nullterm_char(char *str, char delim, char **next);
int   string_isprint(const char *str, size_t len) ATTRIBUTE_NONNULL_PURE;
int   string_isalpha(const char *str) ATTRIBUTE_NONNULL_PURE;
int   string_isnumber(const char *str) ATTRIBUTE_NONNULL_PURE;
int   string_isdigit(const char *str) ATTRIBUTE_NONNULL_PURE;
int   string_isalnum(const char *str) ATTRIBUTE_NONNULL_PURE;
int   string_isfloat(const char *str) ATTRIBUTE_NONNULL_PURE;
int   string_ishex(const char *str) ATTRIBUTE_NONNULL_PURE;
char *string_toupper(char *buf, size_t len, const char *in) ATTRIBUTE_NONNULL;
char *string_tolower(char *buf, size_t len, const char *in) ATTRIBUTE_NONNULL;
int   string_tolong(const char *str, long *l) ATTRIBUTE_NONNULL;
int   string_tollong(const char *str, long long *ll, char **endptr, int base);
char *string_lastof(char *str, const char *delim) ATTRIBUTE_NONNULL;
char *string_lastof_char(char *str, char delim) ATTRIBUTE_NONNULL;
char *string_firstof_char(char *str, char delim) ATTRIBUTE_NONNULL;
#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
char *string_concat(char *str, size_t len, size_t *off, const char *fs, ...)
  __attribute__((format(printf, 4, 5)));
#else
char *string_concat(char *str, size_t len, size_t *off, const char *fs, ...);
#endif
char *string_byte2hex(char *str, size_t len, size_t *off,
		      const uint8_t *b, size_t bl) ATTRIBUTE_NONNULL;

const char *string_findlc(const char *str, const char *find)
  ATTRIBUTE_NONNULL_PURE;
int   string_addrport(const char *in, char **addr, int *port)
  ATTRIBUTE_NONNULL;
int   string_endswith(const char *in, const char *ending)
  ATTRIBUTE_NONNULL_PURE;

#ifndef NDEBUG
int string_isdash(const char *str) ATTRIBUTE_NONNULL_PURE;
#else
#define string_isdash(str)((str)[0] == '-' && (str)[1] == '\0')
#endif

/* escape a string for json output */
char *json_esc(const char *in, char *out, size_t len) ATTRIBUTE_NONNULL;
size_t json_esc_len(const char *in) ATTRIBUTE_NONNULL;

/* parse a URL into its components */
int url_parse(const char *in, uint16_t *port, char **scheme,
	      char **host, char **file)
  ATTRIBUTE_NONNULL;

/* check the character to see if it is possibly hex */
int ishex(char c) ATTRIBUTE_CONST;
uint8_t hex2byte(char a, char b) ATTRIBUTE_CONST;
void byte2hex(uint8_t byte, char *a) ATTRIBUTE_NONNULL;

/* functions for extracting and inserting values from byte arrays */
uint16_t bytes_ntohs(const uint8_t *) ATTRIBUTE_NONNULL_PURE;
uint32_t bytes_ntohl(const uint8_t *) ATTRIBUTE_NONNULL_PURE;
void bytes_htons(uint8_t *, uint16_t) ATTRIBUTE_NONNULL;
void bytes_htonl(uint8_t *, uint32_t) ATTRIBUTE_NONNULL;

/*
 * Functions for doing I/O
 */
int read_wrap(int fd, void *ptr, size_t *rc, size_t rt);
int write_wrap(int fd, const void *ptr, size_t *wc, size_t wt);

/* function for dealing with sysctls */
#if defined(HAVE_SYSCTL) && !defined(__linux__)
int sysctl_wrap(int *mib, u_int len, void **buf, size_t *size)
  ATTRIBUTE_NONNULL;
#endif

/* function for formatting an off_t */
char *offt_tostr(char *buf, size_t len, off_t off, int lz, char m)
  ATTRIBUTE_NONNULL;

/* function for computing an Internet checksum */
uint16_t in_cksum(const void *buf, size_t len) ATTRIBUTE_NONNULL_PURE;

/* functions for dealing with random numbers */
void random_seed(void);

int random_u32(uint32_t *r) ATTRIBUTE_NONNULL;
int random_u16(uint16_t *r) ATTRIBUTE_NONNULL;
int random_u8(uint8_t *r) ATTRIBUTE_NONNULL;

/* fisher-yates shuffle */
int shuffle16(uint16_t *array, size_t len) ATTRIBUTE_NONNULL;
int shuffle32(uint32_t *array, size_t len) ATTRIBUTE_NONNULL;

/* count the number of bits set */
int countbits32(uint32_t v) ATTRIBUTE_CONST;

/* return the minimum integer in the array */
int min_array(const int *array, size_t len) ATTRIBUTE_NONNULL;

/*
 * Functions for uuencode and uudecode.
 */
size_t uuencode_len(size_t ilen, size_t *complete, size_t *leftover);
int uuencode(const uint8_t *in, size_t ilen, uint8_t **out, size_t *olen)
  ATTRIBUTE_NONNULL;
size_t uuencode_bytes(const uint8_t *in, size_t len, size_t *off,
		      uint8_t *out, size_t olen)
  ATTRIBUTE_NONNULL;
void *uudecode(const char *in, size_t len)
  ATTRIBUTE_NONNULL;
int uudecode_line(const char *in, size_t ilen, uint8_t *out, size_t *olen)
  ATTRIBUTE_NONNULL;

/* swap bytes in a 16 bit word */
uint16_t byteswap16(const uint16_t word) ATTRIBUTE_CONST;
uint32_t byteswap32(const uint32_t word) ATTRIBUTE_CONST;

/*
 * would adding y to x wrap if the result were stored in a uint16_t or
 * a uint32_t ?
 */
#define uint16_wouldwrap(x, y) ((UINT16_MAX - (x)) < (y))
#define uint32_wouldwrap(x, y) ((UINT32_MAX - (x)) < (y))

/* process a text file, line by line */
#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
int file_lines(const char *filename, int (*func)(char *, void *), void *param)
  __attribute__ ((nonnull(1, 2)));
int fd_lines(int fd, int (*func)(char *, void *), void *param)
  __attribute__ ((nonnull(2)));
#else
int file_lines(const char *filename, int (*func)(char *, void *), void *param);
int fd_lines(int fd, int (*func)(char *, void *), void *param);
#endif

#undef ATTRIBUTE_NONNULL
#undef ATTRIBUTE_PURE
#undef ATTRIBUTE_NONNULL_PURE
#undef ATTRIBUTE_MALLOC
#undef ATTRIBUTE_CONST

#endif /* __UTILS_H */
