# $Id: Makefile.am,v 1.76 2024/05/02 21:21:47 mjl Exp $

AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = scamper

lib_LTLIBRARIES = libscamperfile.la

libscamperfile_la_CFLAGS = -DBUILDING_LIBSCAMPERFILE

libscamperfile_la_LDFLAGS = -version-info 9:0:0 \
	-export-symbols-regex '^scamper_'

libscamperfile_la_LIBADD = @ZLIB_LIBS@ @LIBBZ2_LIBS@ @LIBLZMA_LIBS@ @WINSOCK_LIBS@

libscamperfile_la_SOURCES = \
	../mjl_splaytree.c \
	../utils.c \
	scamper_file.c \
	scamper_file_arts.c \
	scamper_file_warts.c \
	scamper_file_json.c \
	scamper_addr.c \
	scamper_list.c \
	scamper_icmpext.c \
	scamper_icmpext_lib.c \
	scamper_ifname.c \
	trace/scamper_trace.c \
	trace/scamper_trace_warts.c \
	trace/scamper_trace_text.c \
	trace/scamper_trace_json.c \
	trace/scamper_trace_lib.c \
	ping/scamper_ping.c \
	ping/scamper_ping_warts.c \
	ping/scamper_ping_text.c \
	ping/scamper_ping_json.c \
	ping/scamper_ping_lib.c \
	tracelb/scamper_tracelb.c \
	tracelb/scamper_tracelb_warts.c \
	tracelb/scamper_tracelb_text.c \
	tracelb/scamper_tracelb_json.c \
	tracelb/scamper_tracelb_lib.c \
	dealias/scamper_dealias.c \
	dealias/scamper_dealias_warts.c \
	dealias/scamper_dealias_text.c \
	dealias/scamper_dealias_json.c \
	dealias/scamper_dealias_lib.c \
	sting/scamper_sting.c \
	sting/scamper_sting_warts.c \
	sting/scamper_sting_text.c \
	sting/scamper_sting_lib.c \
	neighbourdisc/scamper_neighbourdisc.c \
	neighbourdisc/scamper_neighbourdisc_warts.c \
	neighbourdisc/scamper_neighbourdisc_lib.c \
	tbit/scamper_tbit.c \
	tbit/scamper_tbit_warts.c \
	tbit/scamper_tbit_text.c \
	tbit/scamper_tbit_json.c \
	tbit/scamper_tbit_lib.c \
	sniff/scamper_sniff.c \
	sniff/scamper_sniff_warts.c \
	sniff/scamper_sniff_lib.c \
	host/scamper_host.c \
	host/scamper_host_warts.c \
	host/scamper_host_json.c \
	host/scamper_host_lib.c \
	http/scamper_http.c \
	http/scamper_http_warts.c \
	http/scamper_http_lib.c \
	udpprobe/scamper_udpprobe.c \
	udpprobe/scamper_udpprobe_warts.c \
	udpprobe/scamper_udpprobe_json.c \
	udpprobe/scamper_udpprobe_lib.c

scamper_SOURCES = \
	../mjl_list.c \
	../mjl_heap.c \
	../mjl_splaytree.c \
	../mjl_patricia.c \
	../utils.c \
	scamper.c \
	scamper_osinfo.c \
	scamper_addr.c \
	scamper_list.c \
	scamper_debug.c \
	scamper_udp4.c \
	scamper_udp6.c \
	scamper_icmp4.c \
	scamper_icmp6.c \
	scamper_icmp_resp.c \
	scamper_icmpext.c \
	scamper_icmpext_int.c \
	scamper_ifname.c \
	scamper_ifname_int.c \
	scamper_tcp4.c \
	scamper_tcp6.c \
	scamper_ip6.c \
	scamper_ip4.c \
	scamper_if.c \
	scamper_rtsock.c \
	scamper_dl.c \
	scamper_addr2mac.c \
	scamper_fds.c \
	scamper_linepoll.c \
	scamper_writebuf.c \
	scamper_dlhdr.c \
	scamper_getsrc.c \
	scamper_control.c \
	scamper_firewall.c \
	scamper_outfiles.c \
	scamper_probe.c \
	scamper_task.c \
	scamper_queue.c \
	scamper_cyclemon.c \
	scamper_options.c \
	scamper_file.c \
	scamper_file_warts.c \
	scamper_file_json.c \
	scamper_sources.c \
	scamper_source_cmdline.c \
	scamper_source_control.c \
	scamper_source_file.c
if ENABLE_PRIVSEP
scamper_SOURCES += \
	scamper_privsep.c
endif
if HAVE_OPENSSL
scamper_SOURCES += \
	../utils_tls.c
endif
if ENABLE_SCAMPER_TRACE
scamper_SOURCES += \
	trace/scamper_trace.c \
	trace/scamper_trace_warts.c \
	trace/scamper_trace_text.c \
	trace/scamper_trace_json.c \
	trace/scamper_trace_cmd.c \
	trace/scamper_trace_do.c
endif
if ENABLE_SCAMPER_PING
scamper_SOURCES += \
	ping/scamper_ping.c \
	ping/scamper_ping_warts.c \
	ping/scamper_ping_text.c \
	ping/scamper_ping_json.c \
	ping/scamper_ping_cmd.c \
	ping/scamper_ping_do.c
endif
if ENABLE_SCAMPER_TRACELB
scamper_SOURCES += \
	tracelb/scamper_tracelb.c \
	tracelb/scamper_tracelb_warts.c \
	tracelb/scamper_tracelb_text.c \
	tracelb/scamper_tracelb_json.c \
	tracelb/scamper_tracelb_cmd.c \
	tracelb/scamper_tracelb_do.c
endif
if ENABLE_SCAMPER_DEALIAS
scamper_SOURCES += \
	dealias/scamper_dealias.c \
	dealias/scamper_dealias_warts.c \
	dealias/scamper_dealias_text.c \
	dealias/scamper_dealias_json.c \
	dealias/scamper_dealias_cmd.c \
	dealias/scamper_dealias_do.c
endif
scamper_SOURCES += \
	neighbourdisc/scamper_neighbourdisc.c \
	neighbourdisc/scamper_neighbourdisc_warts.c \
	neighbourdisc/scamper_neighbourdisc_cmd.c \
	neighbourdisc/scamper_neighbourdisc_do.c
if ENABLE_SCAMPER_TBIT
scamper_SOURCES += \
	tbit/scamper_tbit.c \
	tbit/scamper_tbit_warts.c \
	tbit/scamper_tbit_text.c \
	tbit/scamper_tbit_json.c \
	tbit/scamper_tbit_cmd.c \
	tbit/scamper_tbit_do.c
endif
if ENABLE_SCAMPER_STING
scamper_SOURCES += \
	sting/scamper_sting.c \
	sting/scamper_sting_warts.c \
	sting/scamper_sting_text.c \
	sting/scamper_sting_cmd.c \
	sting/scamper_sting_do.c
endif
if ENABLE_SCAMPER_SNIFF
scamper_SOURCES += \
	sniff/scamper_sniff.c \
	sniff/scamper_sniff_warts.c \
	sniff/scamper_sniff_cmd.c \
	sniff/scamper_sniff_do.c
endif
if ENABLE_SCAMPER_HOST
scamper_SOURCES += \
	host/scamper_host.c \
	host/scamper_host_warts.c \
	host/scamper_host_json.c \
	host/scamper_host_cmd.c \
	host/scamper_host_do.c
endif
if ENABLE_SCAMPER_HTTP
scamper_SOURCES += \
	http/scamper_http.c \
	http/scamper_http_warts.c \
	http/scamper_http_cmd.c \
	http/scamper_http_do.c
endif
if ENABLE_SCAMPER_UDPPROBE
scamper_SOURCES += \
	udpprobe/scamper_udpprobe.c \
	udpprobe/scamper_udpprobe_warts.c \
	udpprobe/scamper_udpprobe_json.c \
	udpprobe/scamper_udpprobe_cmd.c \
	udpprobe/scamper_udpprobe_do.c
endif

scamper_CFLAGS = $(AM_CFLAGS) -DBUILDING_SCAMPER

scamper_LDADD = @OPENSSL_LIBS@ @LIBNV_LIBS@ \
	@ZLIB_LIBS@ @LIBBZ2_LIBS@ @LIBLZMA_LIBS@ \
	@WINSOCK_LIBS@ @WINMM_LIBS@ @IPHLPAPI_LIBS@

scamper_LDFLAGS = @OPENSSL_LDFLAGS@

include_HEADERS = \
	scamper_file.h \
	scamper_addr.h \
	scamper_list.h \
	scamper_icmpext.h \
	trace/scamper_trace.h \
	ping/scamper_ping.h \
	tracelb/scamper_tracelb.h \
	dealias/scamper_dealias.h \
	sting/scamper_sting.h \
	neighbourdisc/scamper_neighbourdisc.h \
	tbit/scamper_tbit.h \
	sniff/scamper_sniff.h \
	host/scamper_host.h \
	http/scamper_http.h \
	udpprobe/scamper_udpprobe.h

man_MANS = \
	scamper.1 \
	libscamperfile.3 \
	warts.5

CLEANFILES = *~ *.core \
	trace/*~ ping/*~ tracelb/*~ dealias/*~ sting/*~ \
	neighbourdisc/*~ tbit/*~ sniff/*~ host/*~ http/*~ udpprobe/*~
