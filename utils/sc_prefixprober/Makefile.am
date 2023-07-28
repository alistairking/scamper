AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_prefixprober

sc_prefixprober_SOURCES = \
	sc_prefixprober.c \
	../../utils.c \
	../../mjl_list.c \
	../../mjl_prefixtree.c

sc_prefixprober_LDADD = \
	../../scamper/libscamperfile.la \
	../../lib/libscamperctrl/libscamperctrl.la

man_MANS = sc_prefixprober.1

CLEANFILES = *~ *.core
