AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_warts2json

sc_warts2json_SOURCES = \
	sc_warts2json.c \
	$(top_srcdir)/utils.c

sc_warts2json_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la

man_MANS = sc_warts2json.1

CLEANFILES = *~ *.core
