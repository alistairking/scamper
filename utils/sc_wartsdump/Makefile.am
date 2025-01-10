AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_wartsdump

sc_wartsdump_SOURCES = \
	sc_wartsdump.c \
	$(top_srcdir)/utils.c

sc_wartsdump_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la

man_MANS = sc_wartsdump.1

CLEANFILES = *~ *.core
