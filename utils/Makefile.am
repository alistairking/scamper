SUBDIRS = \
	sc_ally \
	sc_analysis_dump \
	sc_attach \
	sc_bdrmap \
	sc_erosprober \
	sc_filterpolicy

if ENABLE_SC_HOIHO
SUBDIRS+= sc_hoiho
endif

SUBDIRS+= \
	sc_ipiddump

if ENABLE_SC_MINRTT
SUBDIRS+= sc_minrtt
endif

SUBDIRS+= \
	sc_pinger \
	sc_prefixprober \
	sc_prefixscan \
	sc_radargun \
	sc_remoted \
	sc_speedtrap \
	sc_tbitblind \
	sc_tbitpmtud \
	sc_tracediff \
	sc_ttlexp

if ENABLE_SC_UPTIME
SUBDIRS+= sc_uptime
endif

SUBDIRS+= \
	sc_warts2csv \
	sc_warts2json \
	sc_warts2pcap \
	sc_warts2text \
	sc_wartscat \
	sc_wartsdump \
	sc_wartsfilter \
	sc_wartsfix

CLEANFILES = *~ *.core
