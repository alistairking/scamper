AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_pinger

sc_pinger_SOURCES = \
	sc_pinger.c \
	../../scamper/scamper_linepoll.c \
	../../scamper/scamper_writebuf.c \
	../../utils.c \
	../../mjl_list.c \
	../../mjl_splaytree.c

sc_pinger_LDADD = ../../scamper/libscamperfile.la

man_MANS = sc_pinger.1

CLEANFILES = *~ *.core
