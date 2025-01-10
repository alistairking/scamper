AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/scamper

bin_PROGRAMS = sc_warts2pcap

sc_warts2pcap_SOURCES = \
	sc_warts2pcap.c \
	$(top_srcdir)/mjl_list.c \
	$(top_srcdir)/utils.c

sc_warts2pcap_LDADD = \
	$(top_srcdir)/lib/libscamperfile/libscamperfile.la

man_MANS = sc_warts2pcap.1

CLEANFILES = *~ *.core
