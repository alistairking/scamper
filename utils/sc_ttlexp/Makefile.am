AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_ttlexp

sc_ttlexp_SOURCES = \
	sc_ttlexp.c \
	$(top_srcdir)/mjl_splaytree.c \
	$(top_srcdir)/mjl_prefixtree.c

sc_ttlexp_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la

man_MANS = sc_ttlexp.1

CLEANFILES = *~ *.core
