# $Id: Makefile.am,v 1.4 2023/06/05 00:21:20 mjl Exp $

AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

noinst_PROGRAMS = \
	fuzz_cmd_dealias \
	fuzz_cmd_host \
	fuzz_cmd_ping \
	fuzz_cmd_sniff \
	fuzz_cmd_sting \
	fuzz_cmd_tbit \
	fuzz_cmd_trace \
	fuzz_cmd_tracelb \
	unit_cmd_dealias \
	unit_cmd_ping \
	unit_cmd_trace

fuzz_cmd_SOURCES = \
	fuzz_cmd.c \
	../utils.c \
	../scamper/scamper_addr.c \
	../scamper/scamper_list.c \
	../scamper/scamper_options.c \
	../mjl_splaytree.c

fuzz_cmd_dealias_CFLAGS = -DFUZZ_DEALIAS -I$(top_srcdir)/scamper/dealias

fuzz_cmd_dealias_SOURCES = $(fuzz_cmd_SOURCES) \
	../scamper/dealias/scamper_dealias.c \
	../scamper/dealias/scamper_dealias_cmd.c \
	../mjl_list.c

fuzz_cmd_host_CFLAGS = -DFUZZ_HOST -I$(top_srcdir)/scamper/host

fuzz_cmd_host_SOURCES = $(fuzz_cmd_SOURCES) \
	../scamper/host/scamper_host.c \
	../scamper/host/scamper_host_cmd.c

fuzz_cmd_ping_CFLAGS = -DFUZZ_PING -I$(top_srcdir)/scamper/ping

fuzz_cmd_ping_SOURCES = $(fuzz_cmd_SOURCES) \
	../scamper/ping/scamper_ping.c \
	../scamper/ping/scamper_ping_cmd.c

fuzz_cmd_sniff_CFLAGS = -DFUZZ_SNIFF -I$(top_srcdir)/scamper/sniff

fuzz_cmd_sniff_SOURCES = $(fuzz_cmd_SOURCES) \
	../scamper/sniff/scamper_sniff.c \
	../scamper/sniff/scamper_sniff_cmd.c

fuzz_cmd_sting_CFLAGS = -DFUZZ_STING -I$(top_srcdir)/scamper/sting

fuzz_cmd_sting_SOURCES = $(fuzz_cmd_SOURCES) \
	../scamper/sting/scamper_sting.c \
	../scamper/sting/scamper_sting_cmd.c

fuzz_cmd_tbit_CFLAGS = -DFUZZ_TBIT -I$(top_srcdir)/scamper/tbit

fuzz_cmd_tbit_SOURCES = $(fuzz_cmd_SOURCES) \
	../scamper/tbit/scamper_tbit.c \
	../scamper/tbit/scamper_tbit_cmd.c

fuzz_cmd_trace_CFLAGS = -DFUZZ_TRACE -I$(top_srcdir)/scamper/trace

fuzz_cmd_trace_SOURCES = $(fuzz_cmd_SOURCES) \
	../scamper/trace/scamper_trace.c \
	../scamper/trace/scamper_trace_cmd.c \
	../scamper/scamper_icmpext.c \
	../mjl_list.c

fuzz_cmd_tracelb_CFLAGS = -DFUZZ_TRACELB -I$(top_srcdir)/scamper/tracelb

fuzz_cmd_tracelb_SOURCES = $(fuzz_cmd_SOURCES) \
	../scamper/tracelb/scamper_tracelb.c \
	../scamper/tracelb/scamper_tracelb_cmd.c \
	../scamper/scamper_icmpext.c

unit_cmd_SOURCES = \
	../utils.c \
	../scamper/scamper_addr.c \
	../scamper/scamper_list.c \
	../scamper/scamper_options.c \
	../mjl_splaytree.c

unit_cmd_dealias_CFLAGS = -I$(top_srcdir)/scamper/dealias

unit_cmd_dealias_SOURCES = $(unit_cmd_SOURCES) \
	unit_cmd_dealias.c \
	../scamper/dealias/scamper_dealias.c \
	../scamper/dealias/scamper_dealias_lib.c \
	../scamper/dealias/scamper_dealias_cmd.c \
	../mjl_list.c

unit_cmd_ping_CFLAGS = -I$(top_srcdir)/scamper/ping

unit_cmd_ping_SOURCES = $(unit_cmd_SOURCES) \
	unit_cmd_ping.c \
	../scamper/ping/scamper_ping.c \
	../scamper/ping/scamper_ping_lib.c \
	../scamper/ping/scamper_ping_cmd.c \
	../mjl_list.c

unit_cmd_trace_CFLAGS = -I$(top_srcdir)/scamper/trace

unit_cmd_trace_SOURCES = $(unit_cmd_SOURCES) \
	unit_cmd_trace.c \
	../scamper/trace/scamper_trace.c \
	../scamper/trace/scamper_trace_lib.c \
	../scamper/trace/scamper_trace_cmd.c \
	../scamper/scamper_icmpext.c \
	../mjl_list.c

CLEANFILES = *~ *.core
