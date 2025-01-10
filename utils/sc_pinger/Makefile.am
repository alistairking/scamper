AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/scamper \
	-I$(top_srcdir)/scamper/ping \
	-I$(top_srcdir)/scamper/dealias \
	-I$(top_srcdir)/lib/libscamperctrl

bin_PROGRAMS = sc_pinger

sc_pinger_SOURCES = \
	sc_pinger.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_list.c

sc_pinger_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la \
	$(top_srcdir)/lib/libscamperctrl/libscamperctrl.la

man_MANS = sc_pinger.1

CLEANFILES = *~ *.core
