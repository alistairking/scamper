# $Id: Makefile.am,v 1.4 2023/06/05 00:42:01 mjl Exp $

AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir)

lib_LTLIBRARIES = libscamperctrl.la

libscamperctrl_la_LDFLAGS = -version-info 2:0:0

libscamperctrl_la_SOURCES = \
	libscamperctrl.c

include_HEADERS = \
	libscamperctrl.h

man_MANS = \
	libscamperctrl.3

CLEANFILES = *~ *.core
