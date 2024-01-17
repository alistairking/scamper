BUILT_SOURCES = scamper.c

scamper.c:	scamper.pyx \
		clibscamperctrl.pxd \
		cscamper_addr.pxd \
		cscamper_dealias.pxd \
		cscamper_file.pxd \
		cscamper_host.pxd \
		cscamper_http.pxd \
		cscamper_icmpext.pxd \
		cscamper_list.pxd \
		cscamper_neighbourdisc.pxd \
		cscamper_ping.pxd \
		cscamper_sniff.pxd \
		cscamper_sting.pxd \
		cscamper_tbit.pxd \
		cscamper_trace.pxd \
		cscamper_tracelb.pxd \
		cscamper_udpprobe.pxd
		$(CYTHON) -3 -o scamper.c scamper.pyx

scamperdir = $(PYTHON_SITE_PKG)
scamper_LTLIBRARIES = scamper.la

scamper_la_SOURCES = scamper.c

scamper_la_CFLAGS = \
	$(PYTHON_CPPFLAGS) \
	-I$(top_srcdir)/lib/libscamperctrl \
	-I$(top_srcdir)/scamper \
	-I$(top_srcdir)/scamper/dealias \
	-I$(top_srcdir)/scamper/host \
	-I$(top_srcdir)/scamper/http \
	-I$(top_srcdir)/scamper/neighbourdisc \
	-I$(top_srcdir)/scamper/ping \
	-I$(top_srcdir)/scamper/sniff \
	-I$(top_srcdir)/scamper/sting \
	-I$(top_srcdir)/scamper/tbit \
	-I$(top_srcdir)/scamper/trace \
	-I$(top_srcdir)/scamper/tracelb \
	-I$(top_srcdir)/scamper/tbit \
	-I$(top_srcdir)/scamper/udpprobe

scamper_la_LDFLAGS = \
	-module \
	-avoid-version

scamper_la_LIBADD = \
	../../scamper/libscamperfile.la \
	../libscamperctrl/libscamperctrl.la

CLEANFILES = *~ \
	scamper.c
