# Process this file with autoconf to produce a configure script.

AC_INIT([scamper],[20230614b],[mjl@luckie.org.nz])

AC_CONFIG_SRCDIR([scamper/scamper.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([foreign])
AM_MAINTAINER_MODE([disable])

LT_INIT
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_LANG(C)

# Whether all the debugging output should be spewed out
AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug], [build with debugging symbols])])

if test "x$enable_debug" != "xyes"; then
  AC_DEFINE([NDEBUG],[1],[Define to 1 if we don't want to do any debugging])
fi

# No privilege separation
AC_ARG_ENABLE([privsep],
  [AS_HELP_STRING([--disable-privsep], [disable privilege separation])])

if test "x$enable_privsep" = xno; then
  AC_DEFINE([WITHOUT_PRIVSEP], [1], [Define to 1 if we don't want privilege separation])
fi

# privsep parameters
AC_ARG_WITH([privsep_user],
  [AS_HELP_STRING([--with-privsep-user=USER],[sets user name for privsep process])],
  [privsep_user=$withval],
  [privsep_user=nobody])
AC_ARG_WITH([privsep_dir],
  [AS_HELP_STRING([--with-privsep-dir=DIR],[sets chroot directory for privsep process])],
  [privsep_dir=$withval],
  [privsep_dir=/var/empty])
AC_ARG_WITH([privsep_dir_owner],
  [AS_HELP_STRING([--with-privsep-dir-owner=USER],[sets chroot directory owner])],
  [privsep_dir_owner=$withval],
  [privsep_dir_owner=root])
AC_ARG_WITH([privsep_dir_group],
  [AS_HELP_STRING([--with-privsep-dir-group=GROUP],[sets chroot directory group id])],
  [privsep_dir_group=$withval],
  [privsep_dir_group=wheel])
AC_SUBST(privsep_user)
AC_SUBST(privsep_dir)
AC_SUBST(privsep_dir_owner)
AC_SUBST(privsep_dir_group)
AC_DEFINE_UNQUOTED(PRIVSEP_USER,
  ["$privsep_user"],
  [user name for privsep process])
AC_DEFINE_UNQUOTED(PRIVSEP_DIR,
  ["$privsep_dir"],
  [chroot directory for privsep process])
AC_DEFINE_UNQUOTED(PRIVSEP_DIR_OWNER,
  ["$privsep_dir_owner"],
  [chroot directory owner])
AC_DEFINE_UNQUOTED(PRIVSEP_DIR_GROUP,
  ["$privsep_dir_group"],
  [chroot directory group id])

# Debug file support
AC_ARG_ENABLE([debug-file],
  [AS_HELP_STRING([--disable-debug-file],
    [remove support for generating a debug file])])

if test "x$enable_debug_file" = xno; then
  AC_DEFINE([WITHOUT_DEBUGFILE], [1], [Defined to 1 if we don't want to be able generate a debugfile])
fi

# dmalloc support
AC_ARG_WITH([dmalloc],
  [AS_HELP_STRING([--with-dmalloc],
     [enable support for dmalloc])])

if test "x$with_dmalloc" = xyes; then
	AC_CHECK_LIB([dmalloc],	[dmalloc_malloc],
		[
		CFLAGS="$CFLAGS -DDMALLOC"
		LDFLAGS="$LDFLAGS -ldmalloc"
		],
		[AC_MSG_FAILURE([dmalloc test failed (remove --with-dmalloc)])])
fi

# pcre support
AC_ARG_WITH([pcre],
  [AS_HELP_STRING([--with-pcre],
     [use pcre for regex engine])])

if test "x$with_pcre" = xyes; then
	AC_CHECK_LIB([pcre], [pcre_compile],
		[
		PCRE_CFLAGS="-DHAVE_PCRE"
		PCRE_LIBS="-lpcre"
		],
		[AC_MSG_FAILURE([pcre test failed (remove --with-pcre)])])
fi

# pcre2 support
AC_ARG_WITH([pcre2],
  [AS_HELP_STRING([--with-pcre2],
     [use pcre2 for regex engine])])

if test "x$with_pcre2" = xyes; then
	AC_CHECK_LIB([pcre2-8], [pcre2_compile_8],
		[
		PCRE_CFLAGS="-DHAVE_PCRE2"
		PCRE_LIBS="-lpcre2-8"
		],
		[AC_MSG_FAILURE([pcre2 test failed (remove --with-pcre2)])])
fi

AC_SUBST(PCRE_CFLAGS)
AC_SUBST(PCRE_LIBS)

# sc_hoiho utlity
AC_ARG_ENABLE([sc_hoiho],
  [AS_HELP_STRING([--enable-sc_hoiho],
     [enable support for sc_hoiho])],
     [enable_sc_hoiho=$enableval],
     [enable_sc_hoiho=no]
)
AM_CONDITIONAL([WITH_SC_HOIHO], [test x$enable_sc_hoiho = xyes])

# sc_uptime prober support
AC_ARG_ENABLE([sc_uptime],
  [AS_HELP_STRING([--enable-sc_uptime],
     [enable support for sc_uptime])],
     [enable_sc_uptime=$enableval],
     [enable_sc_uptime=no]
)
AM_CONDITIONAL([WITH_SC_UPTIME], [test x$enable_sc_uptime = xyes])

# build tests
AC_ARG_ENABLE([tests],
  [AS_HELP_STRING([--enable-tests],
     [build tests])],
     [enable_tests=$enableval],
     [enable_tests=no]
)
AM_CONDITIONAL([WITH_TESTS], [test x$enable_tests = xyes])

# Checks for libraries.
AC_CHECK_LIB([iphlpapi], [GetIpNetTable])
AC_CHECK_LIB([ws2_32], [WSAStartup])

# Checks for header files.
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(arpa/inet.h)
AC_CHECK_HEADERS(fcntl.h)
AC_CHECK_HEADERS(limits.h)
AC_CHECK_HEADERS(netdb.h)
AC_CHECK_HEADERS(net/if_dl.h)
AC_CHECK_HEADERS(net/if_types.h)
AC_CHECK_HEADERS(netinet/in.h)
AC_CHECK_HEADERS(poll.h)
AC_CHECK_HEADERS(stdint.h)
AC_CHECK_HEADERS(stdlib.h)
AC_CHECK_HEADERS(string.h)
AC_CHECK_HEADERS(sys/epoll.h)
AC_CHECK_HEADERS(sys/event.h)
AC_CHECK_HEADERS(sys/ioctl.h)
AC_CHECK_HEADERS(sys/param.h)
AC_CHECK_HEADERS(sys/socket.h)
AC_CHECK_HEADERS(sys/socketvar.h)
AC_CHECK_HEADERS(sys/time.h)
AC_CHECK_HEADERS(unistd.h)
AC_CHECK_HEADERS(ifaddrs.h)

# sys/sysctl.h requires other headers on at least OpenBSD
AC_CHECK_HEADERS([sys/sysctl.h], [], [],
[[
#if HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
]])

AC_CHECK_HEADERS([netinet/ip_fw.h netinet6/ip6_fw.h], [], [],
[[
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#include <net/if.h>
#include <netinet/ip_compat.h>
]])

AC_CHECK_HEADERS([netinet/tcp_var.h], [], [],
[[
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#include <sys/queue.h>
#include <netinet/tcp.h>
]])

AC_CHECK_HEADERS(net/pfvar.h, [], [],
[[
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
]])

AC_CHECK_HEADERS(linux/netlink.h, [], [],
[[
#include <sys/types.h>
#include <sys/socket.h>
]])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_STRUCT_TM
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_CHECK_FUNCS(arc4random)
AC_CHECK_FUNCS(arc4random_uniform)
AC_CHECK_FUNCS(atexit)
AC_CHECK_FUNCS(calloc)
AC_CHECK_FUNCS(daemon)
AC_CHECK_FUNCS(endpwent)
AC_CHECK_FUNCS(epoll_wait)
AC_CHECK_FUNCS(ftruncate)
AC_CHECK_FUNCS(getdtablesize)
AC_CHECK_FUNCS(gethostname)
AC_CHECK_FUNCS(getifaddrs)
AC_CHECK_FUNCS(getpagesize)
AC_CHECK_FUNCS(gettimeofday)
AC_CHECK_FUNCS(isatty)
AC_CHECK_FUNCS(kqueue)
AC_CHECK_FUNCS(memmove)
AC_CHECK_FUNCS(memset)
AC_CHECK_FUNCS(mkdir)
AC_CHECK_FUNCS(poll)
AC_CHECK_FUNCS(rmdir)
AC_CHECK_FUNCS(select)
AC_CHECK_FUNCS(socket)
AC_CHECK_FUNCS(snprintf)
AC_CHECK_FUNCS(setproctitle)
AC_CHECK_FUNCS(strcasecmp)
AC_CHECK_FUNCS(strcasestr)
AC_CHECK_FUNCS(strdup)
AC_CHECK_FUNCS(strerror)
AC_CHECK_FUNCS(strncasecmp)
AC_CHECK_FUNCS(strtol)
AC_CHECK_FUNCS(sysctl)
AC_CHECK_FUNCS(uname)

AC_CHECK_SIZEOF(long)

AC_CHECK_MEMBER([struct sockaddr.sa_len],
	[AC_DEFINE([HAVE_STRUCT_SOCKADDR_SA_LEN],[1],
	[Define if struct sockaddr has an sa_len member])],[:],
	[#include <sys/types.h>
	 #include <sys/socket.h>])

if test "x$ac_cv_header_net_pfvar_h" == xyes; then
   AC_CHECK_MEMBER([struct pfioc_trans_e.type],
	[AC_DEFINE([HAVE_STRUCT_PFIOC_TRANS_E_TYPE],[1],
	[Define if struct pfioc_trans_e has a type member])],[:],
	[#include <sys/types.h>
	 #include <sys/socket.h>
	 #include <netinet/in.h>
	 #include <net/if.h>
	 #include <net/pfvar.h>])
   AC_CHECK_MEMBER([struct pfioc_trans_e.rs_num],
	[AC_DEFINE([HAVE_STRUCT_PFIOC_TRANS_E_RS_NUM],[1],
	[Define if struct pfioc_trans_e has a rs_num member])],[:],
	[#include <sys/types.h>
	 #include <sys/socket.h>
	 #include <netinet/in.h>
	 #include <net/if.h>
	 #include <net/pfvar.h>])
   AC_CHECK_MEMBER([struct pf_rule.nat],
	[AC_DEFINE([HAVE_STRUCT_PF_RULE_NAT],[1],
	[Define if struct pf_rule has a nat member])],[:],
	[#include <sys/types.h>
	 #include <sys/socket.h>
	 #include <netinet/in.h>
	 #include <net/if.h>
	 #include <net/pfvar.h>])
   AC_CHECK_MEMBER([struct pf_rule.rdr],
	[AC_DEFINE([HAVE_STRUCT_PF_RULE_RDR],[1],
	[Define if struct pf_rule has a rdr member])],[:],
	[#include <sys/types.h>
	 #include <sys/socket.h>
	 #include <netinet/in.h>
	 #include <net/if.h>
	 #include <net/pfvar.h>]) 
fi

# Check for structs
AC_MSG_CHECKING([for struct nlmsghdr])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
	[[
		#include <sys/types.h>
		#include <sys/socket.h>
		#include <linux/netlink.h>
	]],
	[[
		struct nlmsghdr msg;
	]])],
	[
		AC_MSG_RESULT([yes])
		AC_DEFINE_UNQUOTED([HAVE_STRUCT_NLMSGHDR], 1,
		[Define to 1 if you have the `nlmsghdr' struct.])
	],
	[
		AC_MSG_RESULT([no])
	])

AC_MSG_CHECKING([for struct nlmsgerr])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
	[[
		#include <sys/types.h>
		#include <sys/socket.h>
		#include <linux/netlink.h>
	]],
	[[
		struct nlmsgerr msgerr;
	]])],
	[
		AC_MSG_RESULT([yes])
		AC_DEFINE_UNQUOTED([HAVE_STRUCT_NLMSGERR], 1,
		[Define to 1 if you have the `nlmsgerr' struct.])
	],
	[
		AC_MSG_RESULT([no])
	])

AC_MSG_CHECKING([for struct sockaddr_nl])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
	[[
		#include <sys/types.h>
		#include <sys/socket.h>
		#include <linux/netlink.h>
	]],
	[[
		struct sockaddr_nl snl;
	]])],
	[
		AC_MSG_RESULT([yes])
		AC_DEFINE_UNQUOTED([HAVE_STRUCT_SOCKADDR_NL], 1,
		[Define to 1 if you have the `sockaddr_nl' struct.])
	],
	[
		AC_MSG_RESULT([no])
	])

# These libraries have to be explicitly linked in OpenSolaris
AC_SEARCH_LIBS(getaddrinfo, socket, [], [], -lnsl)
AC_SEARCH_LIBS(inet_ntop, nsl, [], [], -lsocket)

# Some systems need -lm to use sqrt.
AC_SEARCH_LIBS(sqrt, m, [], [], [])

AX_CHECK_OPENSSL(
	[AC_DEFINE([HAVE_OPENSSL], [1], [Define to 1 if you have OpenSSL])]
	[CFLAGS="$CFLAGS $OPENSSL_INCLUDES"]
	[have_openssl=yes])

if test "x$have_openssl" = xyes; then
   save_LIBS="$LIBS"
   save_LDFLAGS="$LDFLAGS"
   LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"
   LIBS="$LIBS $OPENSSL_LIBS"
   AC_MSG_CHECKING([for X509_VERIFY_PARAM_set1_host])
   AC_LINK_IFELSE([
     AC_LANG_PROGRAM([
	[#include <openssl/bio.h>]
	[#include <openssl/ssl.h>]
	[#include <openssl/err.h>]
	[#include <openssl/x509v3.h>]],
	[
	 [X509_VERIFY_PARAM *p = X509_VERIFY_PARAM_new();]
	 [X509_VERIFY_PARAM_set_hostflags(p, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);]
	 [X509_VERIFY_PARAM_set1_host(p, "localhost", 0);]
	])
   ],
   [
	AC_MSG_RESULT([yes])
	AC_DEFINE_UNQUOTED([HAVE_X509_VERIFY_PARAM_SET1_HOST], 1,
		[Define to 1 if you have the X509_VERIFY_PARAM_set1_host function])
   ],
   [
	AC_MSG_RESULT([no])
   ])
   AC_MSG_CHECKING([for ASN1_STRING_get0_data])
   AC_LINK_IFELSE([
     AC_LANG_PROGRAM([
	[#include <openssl/bio.h>]
	[#include <openssl/ssl.h>]
	[#include <openssl/err.h>]
	[#include <openssl/x509v3.h>]],
	[
	 [ASN1_STRING_get0_data(NULL);]
	])
   ],
   [
	AC_MSG_RESULT([yes])
	AC_DEFINE_UNQUOTED([HAVE_ASN1_STRING_GET0_DATA], 1,
		[Define to 1 if you have the HAVE_ASN1_STRING_GET0_DATA function])
   ],
   [
	AC_MSG_RESULT([no])
   ])
   LDFLAGS="$save_LDFLAGS"
   LIBS="$save_LIBS"
fi

# zlib support
AC_ARG_WITH([zlib],
  [AS_HELP_STRING([--with-zlib],
    [support reading and writing gz streams @<:@default=check@:>@])],
  [],
  [with_zlib=check])
AS_IF([test "x$with_zlib" != xno],[
  save_LIBS="$LIBS"
  LIBS="$LIBS -lz"
  AC_MSG_CHECKING([for inflateInit2 in -lz])
  AC_LINK_IFELSE([AC_LANG_PROGRAM(
    [[
      #ifdef HAVE_STRING_H
      #include <string.h>
      #endif
      #include <zlib.h>
    ]],
    [[
      z_stream zs;
      memset(&zs, 0, sizeof(zs));
      inflateInit2(&zs, MAX_WBITS + 32);
    ]]
  )],
  [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_ZLIB], [1], [Define to 1 if you have zlib])
    ZLIB_LIBS="-lz"
  ],
  [
    if test "x$with_zlib" != xcheck; then
      AC_MSG_FAILURE([--with-zlib was given, but test for zlib failed])
    fi
    AC_MSG_RESULT([no])
  ])
  LIBS="$save_LIBS"
])
AC_SUBST(ZLIB_LIBS)

# bz2 support
AC_ARG_WITH([bz2],
  [AS_HELP_STRING([--with-bz2],
    [support reading and writing bz2 streams @<:@default=check@:>@])],
  [],
  [with_bz2=check])
AS_IF([test "x$with_bz2" != xno],[
  save_LIBS="$LIBS"
  LIBS="$LIBS -lbz2"
  AC_MSG_CHECKING([for BZ2_bzDecompressInit in -lbz2])
  AC_LINK_IFELSE([AC_LANG_PROGRAM(
    [[
      #ifdef HAVE_STRING_H
      #include <string.h>
      #endif
      #include <bzlib.h>
    ]],
    [[
      bz_stream zs;
      memset(&zs, 0, sizeof(zs));
      BZ2_bzDecompressInit(&zs, 0, 0);
    ]]
  )],
  [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_LIBBZ2], [1], [Define to 1 if you have libbz2])
    LIBBZ2_LIBS="-lbz2"
  ],
  [
    if test "x$with_bz2" != xcheck; then
      AC_MSG_FAILURE([--with-bz2 was given, but test for bz2 failed])
    fi
    AC_MSG_RESULT([no])
  ])
  LIBS="$save_LIBS"
])
AC_SUBST(LIBBZ2_LIBS)

# lzma (xz) support
AC_ARG_WITH([lzma],
  [AS_HELP_STRING([--with-lzma],
    [support reading and writing xz streams @<:@default=check@:>@])],
  [],
  [with_lzma=check])
AS_IF([test "x$with_lzma" != xno],[
  save_LIBS="$LIBS"
  LIBS="$LIBS -llzma"
  AC_MSG_CHECKING([for lzma_stream_decoder in -llzma])
  AC_LINK_IFELSE([AC_LANG_PROGRAM(
    [[
      #ifdef HAVE_STRING_H
      #include <string.h>
      #endif
      #include <lzma.h>
    ]],
    [[
      lzma_stream zs;
      memset(&zs, 0, sizeof(zs));
      lzma_stream_decoder(&zs, UINT64_MAX, 0);
    ]]
  )],
  [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_LIBLZMA], [1], [Define to 1 if you have liblzma])
    LIBLZMA_LIBS="-llzma"
  ],
  [
    if test "x$with_lzma" != xcheck; then
      AC_MSG_FAILURE([--with-lzma was given, but test for lzma failed])
    fi
    AC_MSG_RESULT([no])
  ])
  LIBS="$save_LIBS"
])
AC_SUBST(LIBLZMA_LIBS)

AX_GCC_BUILTIN(__builtin_clz)

# No thread support
AC_ARG_ENABLE([threads],
  [AS_HELP_STRING([--disable-threads], [disable use of threads])])

if test "x$enable_threads" != xno; then
  AX_PTHREAD(
	[AC_DEFINE([HAVE_PTHREAD], [1], [Define to 1 if you have pthread])])
fi

AX_GCC_FUNC_ATTRIBUTE(const)
AX_GCC_FUNC_ATTRIBUTE(format)
AX_GCC_FUNC_ATTRIBUTE(malloc)
AX_GCC_FUNC_ATTRIBUTE(nonnull)
AX_GCC_FUNC_ATTRIBUTE(pure)

AC_CONFIG_FILES([
	Makefile
	scamper/Makefile
	lib/Makefile
	lib/libscamperctrl/Makefile])

AM_COND_IF([WITH_TESTS],
   	[AC_CONFIG_FILES([
	tests/Makefile
	])])

AC_CONFIG_FILES([
	utils/Makefile
	utils/sc_ally/Makefile
	utils/sc_analysis_dump/Makefile
	utils/sc_attach/Makefile
	utils/sc_bdrmap/Makefile
	utils/sc_erosprober/Makefile])

AM_COND_IF([WITH_SC_HOIHO],
	[AC_CONFIG_FILES([
	utils/sc_hoiho/Makefile
	])])

AC_CONFIG_FILES([
	utils/sc_filterpolicy/Makefile
	utils/sc_ipiddump/Makefile
	utils/sc_pinger/Makefile
	utils/sc_prefixprober/Makefile
	utils/sc_prefixscan/Makefile
	utils/sc_radargun/Makefile
	utils/sc_remoted/Makefile
	utils/sc_speedtrap/Makefile
	utils/sc_tbitblind/Makefile
	utils/sc_tbitpmtud/Makefile
	utils/sc_tracediff/Makefile
	utils/sc_ttlexp/Makefile
])

AM_COND_IF([WITH_SC_UPTIME],
	[AC_CONFIG_FILES([
	utils/sc_uptime/Makefile
	])])

AC_CONFIG_FILES([
	utils/sc_warts2csv/Makefile
	utils/sc_warts2json/Makefile
	utils/sc_warts2pcap/Makefile
	utils/sc_warts2text/Makefile
	utils/sc_wartscat/Makefile
	utils/sc_wartsdump/Makefile
	utils/sc_wartsfilter/Makefile
	utils/sc_wartsfix/Makefile
])

AC_OUTPUT
