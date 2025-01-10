AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_erosprober

sc_erosprober_SOURCES = \
	sc_erosprober.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_heap.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/mjl_patricia.c \
	$(top_srcdir)/scamper/scamper_linepoll.c \
	$(top_srcdir)/scamper/scamper_writebuf.c

sc_erosprober_LDADD = $(top_srcdir)/lib/libscamperfile/libscamperfile.la

man_MANS = sc_erosprober.1

CLEANFILES = *~ *.core
