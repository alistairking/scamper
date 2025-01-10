AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/scamper \
	-I$(top_srcdir)/scamper/ping \
	-I$(top_srcdir)/scamper/dealias

bin_PROGRAMS = sc_minrtt

sc_minrtt_SOURCES = \
	sc_minrtt.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/mjl_splaytree.c \
	$(top_srcdir)/mjl_threadpool.c \
	$(top_srcdir)/mjl_heap.c

sc_minrtt_CFLAGS = @PTHREAD_CFLAGS@ @PCRE_CFLAGS@
sc_minrtt_LDFLAGS = @PTHREAD_CFLAGS@ @PCRE_CFLAGS@
sc_minrtt_LDADD = @PTHREAD_LIBS@ @PCRE_LIBS@ \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la \
	-lsqlite3

man_MANS = sc_minrtt.1

CLEANFILES = *~ *.core
