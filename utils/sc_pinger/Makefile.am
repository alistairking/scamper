AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_pinger

sc_pinger_SOURCES = \
	sc_pinger.c \
	../../utils.c \
	../../mjl_list.c

sc_pinger_LDADD = \
	../../scamper/libscamperfile.la \
	../../lib/libscamperctrl/libscamperctrl.la

man_MANS = sc_pinger.1

CLEANFILES = *~ *.core
