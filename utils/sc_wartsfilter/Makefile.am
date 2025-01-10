AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_wartsfilter

sc_wartsfilter_SOURCES = \
	sc_wartsfilter.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/mjl_prefixtree.c \
	$(top_srcdir)/utils.c

sc_wartsfilter_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la

man_MANS = sc_wartsfilter.1

CLEANFILES = *~ *.core
