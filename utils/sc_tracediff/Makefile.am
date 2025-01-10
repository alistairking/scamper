AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_tracediff

sc_tracediff_SOURCES = \
	sc_tracediff.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_splaytree.c

sc_tracediff_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la

man_MANS = sc_tracediff.1

CLEANFILES = *~ *.core
