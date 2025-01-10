AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_remoted

sc_remoted_SOURCES = \
	sc_remoted.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_heap.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/mjl_splaytree.c \
	$(top_srcdir)/scamper/scamper_linepoll.c \
	$(top_srcdir)/scamper/scamper_writebuf.c
if HAVE_OPENSSL
sc_remoted_SOURCES += \
	$(top_srcdir)/utils_tls.c
endif

sc_remoted_LDADD = @OPENSSL_LIBS@
sc_remoted_LDFLAGS = @OPENSSL_LDFLAGS@

man_MANS = sc_remoted.1

CLEANFILES = *~ *.core
