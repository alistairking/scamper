AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_analysis_dump

sc_analysis_dump_SOURCES = sc_analysis_dump.c ../../utils.c

sc_analysis_dump_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_analysis_dump.1

CLEANFILES = *~ *.core
