AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_attach

sc_attach_SOURCES = \
	sc_attach.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/scamper/scamper_writebuf.c \
	$(top_srcdir)/scamper/scamper_linepoll.c

sc_attach_LDADD = @WINSOCK_LIBS@

man_MANS = sc_attach.1

CLEANFILES = *~ *.core
