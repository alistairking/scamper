AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_prefixscan

sc_prefixscan_SOURCES = \
	sc_prefixscan.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_heap.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/mjl_splaytree.c

sc_prefixscan_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la \
	$(top_srcdir)/lib/libscamperctrl/libscamperctrl.la

man_MANS = sc_prefixscan.1

CLEANFILES = *~ *.core
