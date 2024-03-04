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
	-avoid-version \
	$(PYTHON_LIBS)

scamper_la_LIBADD = \
	../../scamper/libscamperfile.la \
	../libscamperctrl/libscamperctrl.la

CLEANFILES = *~
