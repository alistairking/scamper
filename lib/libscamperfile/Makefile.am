# $Id: Makefile.am,v 1.6 2025/05/05 04:08:00 mjl Exp $

AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

lib_LTLIBRARIES = libscamperfile.la

libscamperfile_la_CFLAGS = -DBUILDING_LIBSCAMPERFILE

libscamperfile_la_LDFLAGS = -version-info 13:0:0 \
	-export-symbols-regex '^scamper_'

libscamperfile_la_LIBADD = @ZLIB_LIBS@ @LIBBZ2_LIBS@ @LIBLZMA_LIBS@ \
	@WINSOCK_LIBS@

libscamperfile_la_SOURCES = \
	$(top_srcdir)/mjl_splaytree.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/scamper/scamper_file.c \
	$(top_srcdir)/scamper/scamper_file_arts.c \
	$(top_srcdir)/scamper/scamper_file_warts.c \
	$(top_srcdir)/scamper/scamper_file_json.c \
	$(top_srcdir)/scamper/scamper_addr.c \
	$(top_srcdir)/scamper/scamper_list.c \
	$(top_srcdir)/scamper/scamper_icmpext.c \
	$(top_srcdir)/scamper/scamper_icmpext_lib.c \
	$(top_srcdir)/scamper/scamper_ifname.c \
	$(top_srcdir)/scamper/trace/scamper_trace.c \
	$(top_srcdir)/scamper/trace/scamper_trace_warts.c \
	$(top_srcdir)/scamper/trace/scamper_trace_text.c \
	$(top_srcdir)/scamper/trace/scamper_trace_json.c \
	$(top_srcdir)/scamper/trace/scamper_trace_lib.c \
	$(top_srcdir)/scamper/ping/scamper_ping.c \
	$(top_srcdir)/scamper/ping/scamper_ping_warts.c \
	$(top_srcdir)/scamper/ping/scamper_ping_text.c \
	$(top_srcdir)/scamper/ping/scamper_ping_json.c \
	$(top_srcdir)/scamper/ping/scamper_ping_lib.c \
	$(top_srcdir)/scamper/tracelb/scamper_tracelb.c \
	$(top_srcdir)/scamper/tracelb/scamper_tracelb_warts.c \
	$(top_srcdir)/scamper/tracelb/scamper_tracelb_text.c \
	$(top_srcdir)/scamper/tracelb/scamper_tracelb_json.c \
	$(top_srcdir)/scamper/tracelb/scamper_tracelb_lib.c \
	$(top_srcdir)/scamper/dealias/scamper_dealias.c \
	$(top_srcdir)/scamper/dealias/scamper_dealias_warts.c \
	$(top_srcdir)/scamper/dealias/scamper_dealias_text.c \
	$(top_srcdir)/scamper/dealias/scamper_dealias_json.c \
	$(top_srcdir)/scamper/dealias/scamper_dealias_lib.c \
	$(top_srcdir)/scamper/sting/scamper_sting.c \
	$(top_srcdir)/scamper/sting/scamper_sting_warts.c \
	$(top_srcdir)/scamper/sting/scamper_sting_text.c \
	$(top_srcdir)/scamper/sting/scamper_sting_lib.c \
	$(top_srcdir)/scamper/neighbourdisc/scamper_neighbourdisc.c \
	$(top_srcdir)/scamper/neighbourdisc/scamper_neighbourdisc_warts.c \
	$(top_srcdir)/scamper/neighbourdisc/scamper_neighbourdisc_lib.c \
	$(top_srcdir)/scamper/tbit/scamper_tbit.c \
	$(top_srcdir)/scamper/tbit/scamper_tbit_warts.c \
	$(top_srcdir)/scamper/tbit/scamper_tbit_text.c \
	$(top_srcdir)/scamper/tbit/scamper_tbit_json.c \
	$(top_srcdir)/scamper/tbit/scamper_tbit_lib.c \
	$(top_srcdir)/scamper/sniff/scamper_sniff.c \
	$(top_srcdir)/scamper/sniff/scamper_sniff_warts.c \
	$(top_srcdir)/scamper/sniff/scamper_sniff_lib.c \
	$(top_srcdir)/scamper/host/scamper_host.c \
	$(top_srcdir)/scamper/host/scamper_host_warts.c \
	$(top_srcdir)/scamper/host/scamper_host_json.c \
	$(top_srcdir)/scamper/host/scamper_host_lib.c \
	$(top_srcdir)/scamper/http/scamper_http.c \
	$(top_srcdir)/scamper/http/scamper_http_warts.c \
	$(top_srcdir)/scamper/http/scamper_http_lib.c \
	$(top_srcdir)/scamper/udpprobe/scamper_udpprobe.c \
	$(top_srcdir)/scamper/udpprobe/scamper_udpprobe_warts.c \
	$(top_srcdir)/scamper/udpprobe/scamper_udpprobe_json.c \
	$(top_srcdir)/scamper/udpprobe/scamper_udpprobe_lib.c

include_HEADERS = \
	$(top_srcdir)/scamper/scamper_file.h \
	$(top_srcdir)/scamper/scamper_addr.h \
	$(top_srcdir)/scamper/scamper_list.h \
	$(top_srcdir)/scamper/scamper_icmpext.h \
	$(top_srcdir)/scamper/trace/scamper_trace.h \
	$(top_srcdir)/scamper/ping/scamper_ping.h \
	$(top_srcdir)/scamper/tracelb/scamper_tracelb.h \
	$(top_srcdir)/scamper/dealias/scamper_dealias.h \
	$(top_srcdir)/scamper/sting/scamper_sting.h \
	$(top_srcdir)/scamper/neighbourdisc/scamper_neighbourdisc.h \
	$(top_srcdir)/scamper/tbit/scamper_tbit.h \
	$(top_srcdir)/scamper/sniff/scamper_sniff.h \
	$(top_srcdir)/scamper/host/scamper_host.h \
	$(top_srcdir)/scamper/http/scamper_http.h \
	$(top_srcdir)/scamper/udpprobe/scamper_udpprobe.h

man_MANS = \
	libscamperfile.3 \
	warts.5

CLEANFILES = *~
