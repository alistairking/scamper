AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_uptime

sc_uptime_SOURCES = \
	sc_uptime.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_heap.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/mjl_splaytree.c \
	$(top_srcdir)/mjl_prefixtree.c \
	$(top_srcdir)/scamper/scamper_linepoll.c \
	$(top_srcdir)/scamper/scamper_writebuf.c

sc_uptime_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la \
	-lsqlite3

man_MANS = sc_uptime.1

CLEANFILES = *~ *.core
