AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = \
	-I$(top_srcdir)

bin_PROGRAMS = sc_rxifd

sc_rxifd_SOURCES = \
	sc_rxifd.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/utils.c

if HAVE_OSSL_QUIC_SERVER_METHOD
sc_rxifd_SOURCES += \
	$(top_srcdir)/mjl_huffman.c \
	$(top_srcdir)/utils_tls.c
sc_rxifd_LDADD = @OPENSSL_LIBS@
sc_rxifd_LDFLAGS = @OPENSSL_LDFLAGS@
endif

man_MANS = sc_rxifd.1

CLEANFILES = *~ *.core
