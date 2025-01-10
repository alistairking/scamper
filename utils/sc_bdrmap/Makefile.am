AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_bdrmap

sc_bdrmap_SOURCES = \
	sc_bdrmap.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_heap.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/mjl_splaytree.c \
	$(top_srcdir)/mjl_prefixtree.c

sc_bdrmap_LDADD = $(top_srcdir)/lib/libscamperfile/libscamperfile.la

man_MANS = sc_bdrmap.1

CLEANFILES = *~ *.core
