AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_wartsfilter

sc_wartsfilter_SOURCES = \
	sc_wartsfilter.c \
	../../mjl_list.c \
	../../mjl_prefixtree.c

sc_wartsfilter_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_wartsfilter.1

CLEANFILES = *~ *.core
