AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_prefixprober

sc_prefixprober_SOURCES = \
	sc_prefixprober.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/mjl_prefixtree.c

sc_prefixprober_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la \
	$(top_srcdir)/lib/libscamperctrl/libscamperctrl.la

man_MANS = sc_prefixprober.1

CLEANFILES = *~ *.core
