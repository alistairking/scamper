AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_speedtrap

sc_speedtrap_SOURCES = \
	sc_speedtrap.c \
	$(top_srcdir)/utils.c \
	$(top_srcdir)/mjl_heap.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/mjl_splaytree.c \
	$(top_srcdir)/mjl_threadpool.c

sc_speedtrap_CFLAGS = @PTHREAD_CFLAGS@
sc_speedtrap_LDFLAGS = @PTHREAD_CFLAGS@
sc_speedtrap_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la \
	$(top_srcdir)/lib/libscamperctrl/libscamperctrl.la \
	@PTHREAD_LIBS@

man_MANS = sc_speedtrap.1

CLEANFILES = *~ *.core
