# $Id: Makefile.am,v 1.19 2025/10/02 07:58:03 mjl Exp $

AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir)

lib_LTLIBRARIES = libscamperctrl.la

libscamperctrl_la_LDFLAGS = -version-info 5:0:1 \
	-export-symbols-regex '^scamper_(attp|ctrl|inst|task|mux|vp|vpset)_'

libscamperctrl_la_LIBADD = @WINSOCK_LIBS@

libscamperctrl_la_SOURCES = \
	libscamperctrl.c ../../mjl_splaytree.c ../../mjl_list.c

include_HEADERS = \
	libscamperctrl.h

man_MANS = \
	libscamperctrl.3

CLEANFILES = *~ *.core
