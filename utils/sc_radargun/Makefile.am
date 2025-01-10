AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_radargun

sc_radargun_SOURCES = \
	sc_radargun.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_heap.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/mjl_splaytree.c

sc_radargun_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la

man_MANS = sc_radargun.1

CLEANFILES = *~ *.core
