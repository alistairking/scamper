# $Id: Makefile.am,v 1.29 2024/05/01 07:46:20 mjl Exp $

AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

noinst_PROGRAMS = \
	fuzz_cmd_dealias \
	fuzz_cmd_host \
	fuzz_cmd_http \
	fuzz_cmd_ping \
	fuzz_cmd_sniff \
	fuzz_cmd_sting \
	fuzz_cmd_tbit \
	fuzz_cmd_trace \
	fuzz_cmd_tracelb \
	fuzz_cmd_udpprobe \
	unit_cmd_dealias \
	unit_cmd_host \
	unit_cmd_http \
	unit_cmd_ping \
	unit_cmd_sniff \
	unit_cmd_sting \
	unit_cmd_tbit \
	unit_cmd_trace \
	unit_cmd_udpprobe \
	unit_addr \
	fuzz_osinfo \
	unit_osinfo \
	fuzz_dl_parse_ip \
	unit_dl_parse_ip \
	fuzz_http_lib_chunked \
	fuzz_http_lib_hdrs \
	unit_http_lib \
	fuzz_host_rr_list \
	unit_host_rr_list \
	unit_options \
	unit_string \
	unit_timeval \
	unit_fds

noinst_LIBRARIES = libcmdtest.a libosinfotest.a

libcmdtest_a_CFLAGS = -DBUILDING_SCAMPER
libcmdtest_a_SOURCES = \
	../utils.c \
	../scamper/scamper_addr.c \
	../scamper/scamper_list.c \
	../scamper/scamper_options.c \
	../scamper/scamper_icmpext.c \
	../scamper/scamper_ifname.c \
	../mjl_splaytree.c \
	../mjl_list.c \
	common.c

libosinfotest_a_SOURCES = \
	../scamper/scamper_osinfo.c \
	../scamper/scamper_addr.c \
	../utils.c \
	../mjl_list.c \
	common.c

fuzz_cmd_dealias_CFLAGS = -DFUZZ_DEALIAS -I$(top_srcdir)/scamper/dealias
fuzz_cmd_dealias_SOURCES = fuzz_cmd.c \
	../scamper/dealias/scamper_dealias.c \
	../scamper/dealias/scamper_dealias_cmd.c
fuzz_cmd_dealias_LDADD = libcmdtest.a

fuzz_cmd_host_CFLAGS = -DFUZZ_HOST -I$(top_srcdir)/scamper/host
fuzz_cmd_host_SOURCES = fuzz_cmd.c \
	../scamper/host/scamper_host.c \
	../scamper/host/scamper_host_cmd.c
fuzz_cmd_host_LDADD = libcmdtest.a

fuzz_cmd_http_CFLAGS = -DFUZZ_HTTP -I$(top_srcdir)/scamper/http
fuzz_cmd_http_SOURCES = fuzz_cmd.c \
	../scamper/http/scamper_http.c \
	../scamper/http/scamper_http_cmd.c
fuzz_cmd_http_LDADD = libcmdtest.a

fuzz_cmd_ping_CFLAGS = -DFUZZ_PING -I$(top_srcdir)/scamper/ping
fuzz_cmd_ping_SOURCES = fuzz_cmd.c \
	../scamper/ping/scamper_ping.c \
	../scamper/ping/scamper_ping_cmd.c
fuzz_cmd_ping_LDADD = libcmdtest.a

fuzz_cmd_sniff_CFLAGS = -DFUZZ_SNIFF -I$(top_srcdir)/scamper/sniff
fuzz_cmd_sniff_SOURCES = fuzz_cmd.c \
	../scamper/sniff/scamper_sniff.c \
	../scamper/sniff/scamper_sniff_cmd.c
fuzz_cmd_sniff_LDADD = libcmdtest.a

fuzz_cmd_sting_CFLAGS = -DFUZZ_STING -I$(top_srcdir)/scamper/sting
fuzz_cmd_sting_SOURCES = fuzz_cmd.c \
	../scamper/sting/scamper_sting.c \
	../scamper/sting/scamper_sting_cmd.c
fuzz_cmd_sting_LDADD = libcmdtest.a

fuzz_cmd_tbit_CFLAGS = -DFUZZ_TBIT -I$(top_srcdir)/scamper/tbit
fuzz_cmd_tbit_SOURCES = fuzz_cmd.c \
	../scamper/tbit/scamper_tbit.c \
	../scamper/tbit/scamper_tbit_cmd.c
fuzz_cmd_tbit_LDADD = libcmdtest.a

fuzz_cmd_trace_CFLAGS = -DFUZZ_TRACE -I$(top_srcdir)/scamper/trace
fuzz_cmd_trace_SOURCES = fuzz_cmd.c \
	../scamper/trace/scamper_trace.c \
	../scamper/trace/scamper_trace_cmd.c
fuzz_cmd_trace_LDADD = libcmdtest.a

fuzz_cmd_tracelb_CFLAGS = -DFUZZ_TRACELB -I$(top_srcdir)/scamper/tracelb
fuzz_cmd_tracelb_SOURCES = fuzz_cmd.c \
	../scamper/tracelb/scamper_tracelb.c \
	../scamper/tracelb/scamper_tracelb_cmd.c
fuzz_cmd_tracelb_LDADD = libcmdtest.a

fuzz_cmd_udpprobe_CFLAGS = -DFUZZ_UDPPROBE -I$(top_srcdir)/scamper/udpprobe
fuzz_cmd_udpprobe_SOURCES = fuzz_cmd.c \
	../scamper/udpprobe/scamper_udpprobe.c \
	../scamper/udpprobe/scamper_udpprobe_cmd.c
fuzz_cmd_udpprobe_LDADD = libcmdtest.a

unit_cmd_dealias_CFLAGS = -I$(top_srcdir)/scamper/dealias
unit_cmd_dealias_SOURCES = unit_cmd_dealias.c \
	../scamper/dealias/scamper_dealias.c \
	../scamper/dealias/scamper_dealias_lib.c \
	../scamper/dealias/scamper_dealias_cmd.c
unit_cmd_dealias_LDADD = libcmdtest.a

unit_cmd_http_CFLAGS = -I$(top_srcdir)/scamper/http
unit_cmd_http_SOURCES = unit_cmd_http.c \
	../scamper/http/scamper_http.c \
	../scamper/http/scamper_http_lib.c \
	../scamper/http/scamper_http_cmd.c
unit_cmd_http_LDADD = libcmdtest.a

unit_cmd_host_CFLAGS = -I$(top_srcdir)/scamper/host
unit_cmd_host_SOURCES = unit_cmd_host.c \
	../scamper/host/scamper_host.c \
	../scamper/host/scamper_host_lib.c \
	../scamper/host/scamper_host_cmd.c
unit_cmd_host_LDADD = libcmdtest.a

unit_cmd_ping_CFLAGS = -I$(top_srcdir)/scamper/ping
unit_cmd_ping_SOURCES = unit_cmd_ping.c \
	../scamper/ping/scamper_ping.c \
	../scamper/ping/scamper_ping_lib.c \
	../scamper/ping/scamper_ping_cmd.c
unit_cmd_ping_LDADD = libcmdtest.a

unit_cmd_sniff_CFLAGS = -I$(top_srcdir)/scamper/sniff
unit_cmd_sniff_SOURCES = unit_cmd_sniff.c \
	../scamper/sniff/scamper_sniff.c \
	../scamper/sniff/scamper_sniff_lib.c \
	../scamper/sniff/scamper_sniff_cmd.c
unit_cmd_sniff_LDADD = libcmdtest.a

unit_cmd_sting_CFLAGS = -I$(top_srcdir)/scamper/sting
unit_cmd_sting_SOURCES = unit_cmd_sting.c \
	../scamper/sting/scamper_sting.c \
	../scamper/sting/scamper_sting_lib.c \
	../scamper/sting/scamper_sting_cmd.c
unit_cmd_sting_LDADD = libcmdtest.a

unit_cmd_tbit_CFLAGS = -I$(top_srcdir)/scamper/tbit
unit_cmd_tbit_SOURCES = unit_cmd_tbit.c \
	../scamper/tbit/scamper_tbit.c \
	../scamper/tbit/scamper_tbit_lib.c \
	../scamper/tbit/scamper_tbit_cmd.c
unit_cmd_tbit_LDADD = libcmdtest.a

unit_cmd_trace_CFLAGS = -I$(top_srcdir)/scamper/trace
unit_cmd_trace_SOURCES = unit_cmd_trace.c \
	../scamper/trace/scamper_trace.c \
	../scamper/trace/scamper_trace_lib.c \
	../scamper/trace/scamper_trace_cmd.c
unit_cmd_trace_LDADD = libcmdtest.a

unit_cmd_udpprobe_CFLAGS = -I$(top_srcdir)/scamper/udpprobe
unit_cmd_udpprobe_SOURCES = unit_cmd_udpprobe.c \
	../scamper/udpprobe/scamper_udpprobe.c \
	../scamper/udpprobe/scamper_udpprobe_lib.c \
	../scamper/udpprobe/scamper_udpprobe_cmd.c
unit_cmd_udpprobe_LDADD = libcmdtest.a

unit_addr_CFLAGS = -DBUILDING_SCAMPER
unit_addr_SOURCES = unit_addr.c \
	../scamper/scamper_addr.c \
	../utils.c \
	../mjl_splaytree.c

fuzz_osinfo_SOURCES = fuzz_osinfo.c
fuzz_osinfo_LDADD = libosinfotest.a

unit_osinfo_SOURCES = unit_osinfo.c
unit_osinfo_LDADD = libosinfotest.a

fuzz_dl_parse_ip_CFLAGS = -DTEST_DL_PARSE_IP
fuzz_dl_parse_ip_SOURCES = fuzz_dl_parse_ip.c \
	../scamper/scamper_dl.c \
	../utils.c

unit_dl_parse_ip_CFLAGS = -DTEST_DL_PARSE_IP
unit_dl_parse_ip_SOURCES = unit_dl_parse_ip.c \
	../scamper/scamper_dl.c \
	../scamper/scamper_addr.c \
	../utils.c \
	common.c

fuzz_http_lib_chunked_CFLAGS = -I$(top_srcdir)/scamper/http -DFUZZ_CHUNKED
fuzz_http_lib_chunked_SOURCES = fuzz_http_lib.c \
	../scamper/http/scamper_http.c \
	../scamper/http/scamper_http_lib.c
fuzz_http_lib_chunked_LDADD = libcmdtest.a

fuzz_http_lib_hdrs_CFLAGS = -I$(top_srcdir)/scamper/http -DFUZZ_HDRS
fuzz_http_lib_hdrs_SOURCES = fuzz_http_lib.c \
	../scamper/http/scamper_http.c \
	../scamper/http/scamper_http_lib.c
fuzz_http_lib_hdrs_LDADD = libcmdtest.a

unit_http_lib_CFLAGS = -I$(top_srcdir)/scamper/http
unit_http_lib_SOURCES = unit_http_lib.c \
	../scamper/http/scamper_http.c \
	../scamper/http/scamper_http_lib.c
unit_http_lib_LDADD = libcmdtest.a

fuzz_host_rr_list_CFLAGS = -I$(top_srcdir)/scamper/host -DTEST_HOST_RR_LIST
fuzz_host_rr_list_SOURCES = fuzz_host_rr_list.c \
	../scamper/host/scamper_host_do.c \
	../scamper/host/scamper_host.c \
	../scamper/scamper_addr.c \
	../scamper/scamper_list.c \
	../mjl_list.c \
	../utils.c \
	common.c

unit_host_rr_list_CFLAGS = -I$(top_srcdir)/scamper/host -DTEST_HOST_RR_LIST
unit_host_rr_list_SOURCES = unit_host_rr_list.c \
	../scamper/host/scamper_host_do.c \
	../scamper/host/scamper_host_lib.c \
	../scamper/host/scamper_host.c \
	../scamper/scamper_addr.c \
	../scamper/scamper_list.c \
	../mjl_list.c \
	../utils.c \
	common.c

unit_options_SOURCES = unit_options.c \
	../scamper/scamper_options.c \
	../utils.c

unit_string_SOURCES = unit_string.c \
	../utils.c

unit_timeval_SOURCES = unit_timeval.c \
	../utils.c

unit_fds_CFLAGS = -DTEST_FDS
unit_fds_SOURCES = unit_fds.c \
	../scamper/scamper_fds.c \
	../scamper/scamper_addr.c \
	../utils.c \
	../mjl_list.c \
	../mjl_splaytree.c \
	common.c

CLEANFILES = *~ *.core
