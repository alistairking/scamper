AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/scamper \
	-I$(top_srcdir)/scamper/ping \
	-I$(top_srcdir)/scamper/dealias

bin_PROGRAMS = sc_minrtt

sc_minrtt_SOURCES = \
	sc_minrtt.c \
	../../utils.c \
	../../mjl_list.c \
	../../mjl_splaytree.c \
	../../mjl_threadpool.c

sc_minrtt_CFLAGS = @PTHREAD_CFLAGS@ @PCRE_CFLAGS@
sc_minrtt_LDFLAGS = @PTHREAD_CFLAGS@ @PCRE_CFLAGS@
sc_minrtt_LDADD = @PTHREAD_LIBS@ @PCRE_LIBS@ ../../scamper/libscamperfile.la -lsqlite3

man_MANS = sc_minrtt.1

CLEANFILES = *~ *.core
