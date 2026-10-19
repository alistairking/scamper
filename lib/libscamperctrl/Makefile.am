# $Id: Makefile.am,v 1.25 2026/10/19 03:47:08 mjl Exp $

AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir)

lib_LTLIBRARIES = libscamperctrl.la

libscamperctrl_la_LDFLAGS = -version-info 9:1:5 \
	-export-symbols-regex '^scamper_(attp|ctrl|inst|task|mux|vp|vpset)_'

libscamperctrl_la_LIBADD = @WINSOCK_LIBS@

libscamperctrl_la_SOURCES = \
	libscamperctrl.c ../../mjl_splaytree.c ../../mjl_list.c

include_HEADERS = \
	libscamperctrl.h

man_MANS = \
	libscamperctrl.3

CLEANFILES = *~ *.core
