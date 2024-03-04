# $Id: Makefile.am,v 1.14 2024/02/29 01:33:13 mjl Exp $

AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir)

lib_LTLIBRARIES = libscamperctrl.la

libscamperctrl_la_LDFLAGS = -version-info 3:3:1 \
	-export-symbols-regex '^scamper_(attp|ctrl|inst|task)_'

libscamperctrl_la_LIBADD = @WINSOCK_LIBS@

libscamperctrl_la_SOURCES = \
	libscamperctrl.c ../../mjl_splaytree.c ../../mjl_list.c

include_HEADERS = \
	libscamperctrl.h

man_MANS = \
	libscamperctrl.3

CLEANFILES = *~ *.core
