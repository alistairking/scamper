AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = \
	-I$(top_srcdir)

bin_PROGRAMS = sc_rxifd

sc_rxifd_SOURCES = \
	sc_rxifd.c \
	$(top_srcdir)/utils.c

man_MANS = sc_rxifd.1

CLEANFILES = *~ *.core
