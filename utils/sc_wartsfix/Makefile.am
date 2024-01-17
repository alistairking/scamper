AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_wartsfix

sc_wartsfix_SOURCES = sc_wartsfix.c ../../utils.c

sc_wartsfix_LDADD = @WINSOCK_LIBS@

man_MANS = sc_wartsfix.1

CLEANFILES = *~ *.core
