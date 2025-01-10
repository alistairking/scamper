AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_ally

sc_ally_SOURCES = \
	sc_ally.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_heap.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/mjl_splaytree.c

sc_ally_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la \
	$(top_srcdir)/lib/libscamperctrl/libscamperctrl.la

man_MANS = sc_ally.1

CLEANFILES = *~ *.core
