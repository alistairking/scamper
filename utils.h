/*
 * utils.h
 *
 * $Id: utils.h,v 1.139 2023/05/03 19:23:19 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012-2014 The Regents of the University of California
 * Copyright (C) 2015-2023 Matthew Luckie
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

/*
 * Functions for dealing with time and timestamps
 */
#if defined(HAVE_FUNC_ATTRIBUTE_PURE) && defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
int timeval_cmp(const struct timeval *a, const struct timeval *b)
  __attribute__ ((pure, nonnull));
int timeval_inrange_us(const struct timeval *a,const struct timeval *b,int c)
  __attribute__ ((pure, nonnull));
#else
int timeval_cmp(const struct timeval *a, const struct timeval *b);
int timeval_inrange_us(const struct timeval *a,const struct timeval *b,int c);
#endif

#if defined(HAVE_FUNC_ATTRIBUTE_PURE)
int timeval_diff_ms(const struct timeval *a, const struct timeval *b)
  __attribute__ ((pure));
int timeval_diff_us(const struct timeval *a, const struct timeval *b)
  __attribute__ ((pure));
#else
int timeval_diff_ms(const struct timeval *a, const struct timeval *b);
int timeval_diff_us(const struct timeval *a, const struct timeval *b);
#endif

#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
void timeval_diff_tv(struct timeval *rtt,
		     const struct timeval *from, const struct timeval *to)
  __attribute__ ((nonnull));
void timeval_add_cs(struct timeval *out, const struct timeval *in, int cs)
  __attribute__ ((nonnull));
void timeval_add_ms(struct timeval *out, const struct timeval *in, int ms)
  __attribute__ ((nonnull));
void timeval_add_us(struct timeval *out, const struct timeval *in, int us)
  __attribute__ ((nonnull));
void timeval_add_tv(struct timeval *tv, const struct timeval *add)
  __attribute__ ((nonnull));
void timeval_add_tv3(struct timeval *out, const struct timeval *a,
		     const struct timeval *b)
  __attribute__ ((nonnull));
void timeval_add_s(struct timeval *out, const struct timeval *in, int s)
  __attribute__ ((nonnull));
void timeval_sub_us(struct timeval *out, const struct timeval *in, int us)
  __attribute__ ((nonnull));
void timeval_cpy(struct timeval *dst, const struct timeval *src)
  __attribute__ ((nonnull));
char *timeval_tostr_us(const struct timeval *rtt, char *str, size_t len)
  __attribute__ ((nonnull));
#else
void timeval_diff_tv(struct timeval *rtt,
		     const struct timeval *from, const struct timeval *to);
void timeval_add_cs(struct timeval *out, const struct timeval *in, int cs);
void timeval_add_ms(struct timeval *out, const struct timeval *in, int ms);
void timeval_add_us(struct timeval *out, const struct timeval *in, int us);
void timeval_add_tv(struct timeval *tv, const struct timeval *add);
void timeval_add_tv3(struct timeval *out, const struct timeval *a,
		     const struct timeval *b);
void timeval_add_s(struct timeval *out, const struct timeval *in, int s);
void timeval_sub_us(struct timeval *out, const struct timeval *in, int us);
void timeval_cpy(struct timeval *dst, const struct timeval *src);
char *timeval_tostr_us(const struct timeval *rtt, char *str, size_t len);
#endif

#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
void gettimeofday_wrap(struct timeval *tv) __attribute__ ((nonnull));
#else
void gettimeofday_wrap(struct timeval *tv);
#endif

#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
int fstat_mtime(int fd, time_t *mtime) __attribute__ ((nonnull));
int stat_mtime(const char *filename, time_t *mtime) __attribute__ ((nonnull));
#else
int fstat_mtime(int fd, time_t *mtime);
int stat_mtime(const char *filename, time_t *mtime);
#endif

/*
 * Functions for dealing with memory allocation
 */
#ifndef DMALLOC
#ifdef HAVE_CALLOC
#define malloc_zero(size) calloc(1, (size))
#else
void *malloc_zero(const size_t size);
#endif
#else
void *malloc_zero_dm(const size_t size, const char *file, const int line);
#define malloc_zero(size) malloc_zero_dm((size), __FILE__, __LINE__)
#endif

#ifndef DMALLOC
void *memdup(const void *ptr, const size_t len);
int   realloc_wrap(void **ptr, size_t len);
#else
int   realloc_wrap_dm(void **ptr,size_t len, const char *file,const int line);
#define realloc_wrap(ptr, len) realloc_wrap_dm((ptr),(len), __FILE__,__LINE__)
#define memdup(ptr, len) memcpy(malloc(len), ptr, len)
#endif

#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
void mem_concat(void *dst,const void *src,size_t len,size_t *off,size_t size)
  __attribute__ ((nonnull));
#else
void mem_concat(void *dst,const void *src,size_t len,size_t *off,size_t size);
#endif

typedef int (*array_cmp_t)(const void *va, const void *vb);

#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
void *array_find(void **a, size_t nmemb, const void *item, array_cmp_t cmp)
  __attribute__ ((nonnull(3, 4)));
int array_findpos(void **a, size_t nmemb, const void *item,
		  array_cmp_t cmp, size_t *pos)
  __attribute__ ((nonnull(3, 4, 5)));
void array_remove(void **, size_t *nmemb, size_t pos)
  __attribute__ ((nonnull));
#else
void *array_find(void **a, size_t nmemb, const void *item, array_cmp_t cmp);
int array_findpos(void **a, size_t nmemb, const void *item,
		  array_cmp_t cmp, size_t *pos);
void array_remove(void **, size_t *nmemb, size_t pos);
#endif

void array_qsort(void **a, size_t n, array_cmp_t cmp);

#ifndef DMALLOC
int array_insert(void ***a, size_t *nmemb, void *item, array_cmp_t cmp);
int array_insert_gb(void ***a, size_t *nmemb, size_t *mmemb, size_t growby,
		    void *item, array_cmp_t cmp);
#else
int array_insert_dm(void ***a, size_t *nmemb, void *item, array_cmp_t cmp,
		    const char *file, const int line);
int array_insert_gb_dm(void ***a, size_t *nmemb, size_t *mmemb, size_t growby,
		       void *item, array_cmp_t cmp,
		       const char *file, const int line);
#define array_insert(a, nmemb, item, cmp) \
  array_insert_dm((a), (nmemb), (item), (cmp), __FILE__, __LINE__)
#define array_insert_gb(a, nmemb, mmemb, growby, item, cmp) \
  array_insert_gb_dm((a), (nmemb), (mmemb), (growby), (item), (cmp), \
		     __FILE__, __LINE__)
#endif

/*
 * Functions for dealing with raw IPv4/IPv6 addresses
 */
int addr4_cmp(const struct in_addr *a, const struct in_addr *b);
int addr4_human_cmp(const struct in_addr *a, const struct in_addr *b);
int addr6_cmp(const struct in6_addr *a, const struct in6_addr *b);
int addr6_human_cmp(const struct in6_addr *a, const struct in6_addr *b);
void addr6_add(struct in6_addr *out,
	       const struct in6_addr *x, const struct in6_addr *y);
int addr6_add_netlen(struct in6_addr *in, int netlen);
void addr6_sub(struct in6_addr *out,
	       const struct in6_addr *y, const struct in6_addr *x);
int addr_cmp(const int af, const void *a, const void *b);
const char *addr_tostr(int af, const void *addr, char *buf, size_t len);

/*
 * Functions for dealing with sockaddr addresses
 */

int sockaddr_compose(struct sockaddr *sa,
		     const int af, const void *addr, const int port);
int sockaddr_compose_un(struct sockaddr *sa, const char *name);
int sockaddr_compose_str(struct sockaddr *sa, const char *ip, const int port);
int sockaddr_len(const struct sockaddr *sa);
char *sockaddr_tostr(const struct sockaddr *sa, char *buf, const size_t len);

/*
 * Functions for dealing with fcntl flags on a file descriptor
 */

int fcntl_set(const int fd, const int flags);
int fcntl_unset(const int fd, const int flags);

/*
 * Functions for parsing strings
 */
char *string_nextword(char *str);
char *string_nullterm(char *str, const char *delim, char **next);
char *string_nullterm_char(char *str, const char delim, char **next);
int   string_isprint(const char *str, const size_t len);
int   string_isalpha(const char *str);
int   string_isnumber(const char *str);
int   string_isdigit(const char *str);
int   string_isalnum(const char *str);
int   string_isfloat(const char *str);
char *string_toupper(char *buf, size_t len, const char *in);
char *string_tolower(char *buf, size_t len, const char *in);
int   string_tolong(const char *str, long *l);
int   string_tollong(const char *str, long long *ll);
char *string_lastof(char *str, const char *delim);
char *string_lastof_char(char *str, const char delim);
char *string_firstof_char(char *str, const char delim);
#ifdef HAVE_FUNC_ATTRIBUTE_FORMAT
char *string_concat(char *str, size_t len, size_t *off, const char *fs, ...)
  __attribute__((format(printf, 4, 5)));
#else
char *string_concat(char *str, size_t len, size_t *off, const char *fs, ...);
#endif
const char *string_findlc(const char *str, const char *find);
int   string_addrport(const char *in, char **addr, int *port);
int   string_endswith(const char *in, const char *ending);

#ifndef NDEBUG
int   string_isdash(const char *str);
#else
#define string_isdash(str)((str)[0] == '-' && (str)[1] == '\0') 
#endif

/* escape a string for json output */
#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
char *json_esc(const char *in, char *out, size_t len) __attribute__ ((nonnull));
#else
char *json_esc(const char *in, char *out, size_t len);
#endif

/* check the character to see if it is possibly hex */
#if defined(HAVE_FUNC_ATTRIBUTE_CONST)
int ishex(char c) __attribute__ ((const));
uint8_t hex2byte(char a, char b) __attribute__ ((const));
#else
int ishex(char c);
uint8_t hex2byte(char a, char b);
#endif

#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
void byte2hex(uint8_t byte, char *a) __attribute__ ((nonnull));
#else
void byte2hex(uint8_t byte, char *a);
#endif

/* functions for extracting and inserting values from byte arrays */
#if defined(HAVE_FUNC_ATTRIBUTE_PURE) && defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
uint16_t bytes_ntohs(const uint8_t *) __attribute__ ((pure, nonnull));
uint32_t bytes_ntohl(const uint8_t *) __attribute__ ((pure, nonnull));
#else
uint16_t bytes_ntohs(const uint8_t *);
uint32_t bytes_ntohl(const uint8_t *);
#endif

#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
void bytes_htons(uint8_t *, uint16_t) __attribute__ ((nonnull));
void bytes_htonl(uint8_t *, uint32_t) __attribute__ ((nonnull));
#else
void bytes_htons(uint8_t *, uint16_t);
void bytes_htonl(uint8_t *, uint32_t);
#endif

/*
 * Functions for doing I/O
 */

int read_wrap(const int fd, void *ptr, size_t *rc, const size_t rt);
int write_wrap(const int fd, const void *ptr, size_t *wc, const size_t wt);

#ifndef _WIN32
int mkdir_wrap(const char *path, mode_t mode);
#else
int mkdir_wrap(const char *path);
#endif

/* function for dealing with sysctls */
#if defined(HAVE_SYSCTL) && !defined(__linux__)
#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
int sysctl_wrap(int *mib, u_int len, void **buf, size_t *size)
  __attribute__ ((nonnull));
#else
#endif
int sysctl_wrap(int *mib, u_int len, void **buf, size_t *size);
#endif

/* function for formatting an off_t */
#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
char *offt_tostr(char *buf, size_t len, off_t off, int lz, char m)
  __attribute__ ((nonnull));
#else
char *offt_tostr(char *buf, size_t len, off_t off, int lz, char m);
#endif

/* function for computing an Internet checksum */
#if defined(HAVE_FUNC_ATTRIBUTE_PURE) && defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
uint16_t in_cksum(const void *buf, size_t len)
  __attribute__ ((pure, nonnull));  
#else
uint16_t in_cksum(const void *buf, size_t len);
#endif

/* functions for dealing with random numbers */
void random_seed(void);

#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
int random_u32(uint32_t *r) __attribute__ ((nonnull));
int random_u16(uint16_t *r) __attribute__ ((nonnull));
int random_u8(uint8_t *r) __attribute__ ((nonnull));
#else
int random_u32(uint32_t *r);
int random_u16(uint16_t *r);
int random_u8(uint8_t *r);
#endif

/* fisher-yates shuffle */
#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
int shuffle16(uint16_t *array, size_t len) __attribute__ ((nonnull));
int shuffle32(uint32_t *array, size_t len) __attribute__ ((nonnull));
#else
int shuffle16(uint16_t *array, size_t len);
int shuffle32(uint32_t *array, size_t len);
#endif

/* count the number of bits set */
#if defined(HAVE_FUNC_ATTRIBUTE_CONST)
int countbits32(uint32_t v) __attribute__ ((const));
#else
int countbits32(uint32_t v);
#endif

/* return the minimum integer in the array */
#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
int min_array(const int *array, size_t len) __attribute__ ((nonnull));
#else
int min_array(const int *array, size_t len);
#endif

/*
 * Functions for uuencode and uudecode.
 */
size_t uuencode_len(size_t ilen, size_t *complete, size_t *leftover);
#if defined(HAVE_FUNC_ATTRIBUTE_NONNULL)
int uuencode(const uint8_t *in, size_t ilen, uint8_t **out, size_t *olen)
  __attribute__ ((nonnull));
size_t uuencode_bytes(const uint8_t *in, size_t len, size_t *off,
		      uint8_t *out, size_t olen)
  __attribute__ ((nonnull));
void *uudecode(const char *in, size_t len)
  __attribute__ ((nonnull));
int uudecode_line(const char *in, size_t ilen, uint8_t *out, size_t *olen)
  __attribute__ ((nonnull));
#else
int uuencode(const uint8_t *in, size_t ilen, uint8_t **out, size_t *olen);
size_t uuencode_bytes(const uint8_t *in, size_t len, size_t *off,
		      uint8_t *out, size_t olen);
void *uudecode(const char *in, size_t len);
int uudecode_line(const char *in, size_t ilen, uint8_t *out, size_t *olen);
#endif

/* swap bytes in a 16 bit word */
#if defined(HAVE_FUNC_ATTRIBUTE_CONST)
uint16_t byteswap16(const uint16_t word) __attribute__ ((const));
uint32_t byteswap32(const uint32_t word) __attribute__ ((const));
#else
uint16_t byteswap16(const uint16_t word);
uint32_t byteswap32(const uint32_t word);
#endif

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

#endif /* __UTILS_H */
