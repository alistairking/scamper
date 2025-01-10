AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_warts2text

sc_warts2text_SOURCES = \
	sc_warts2text.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_splaytree.c

sc_warts2text_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la

man_MANS = sc_warts2text.1

CLEANFILES = *~ *.core
