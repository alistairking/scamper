AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_tbitpmtud

sc_tbitpmtud_SOURCES = \
	sc_tbitpmtud.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_heap.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/mjl_prefixtree.c \
	$(top_srcdir)/mjl_splaytree.c

sc_tbitpmtud_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la

man_MANS = sc_tbitpmtud.1

CLEANFILES = *~ *.core
