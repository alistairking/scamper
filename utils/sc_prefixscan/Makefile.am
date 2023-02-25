AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_prefixscan

sc_prefixscan_SOURCES = \
	sc_prefixscan.c \
	../../utils.c \
	../../mjl_heap.c \
	../../mjl_list.c \
	../../mjl_splaytree.c

sc_prefixscan_LDADD = \
	../../scamper/libscamperfile.la \
	../../lib/libscamperctrl/libscamperctrl.la

man_MANS = sc_prefixscan.1

CLEANFILES = *~ *.core
