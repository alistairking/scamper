# $Id: Makefile.am,v 1.3 2023/01/03 01:50:51 mjl Exp $

AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir)

lib_LTLIBRARIES = libscamperctrl.la

libscamperctrl_la_LDFLAGS = -version-info 1:0:0

libscamperctrl_la_SOURCES = \
	libscamperctrl.c

include_HEADERS = \
	libscamperctrl.h

man_MANS = \
	libscamperctrl.3

CLEANFILES = *~ *.core
