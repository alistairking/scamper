#!/usr/bin/env perl
#
# $Id: build-man-pdfs.pl,v 1.22 2023/04/10 07:45:38 mjl Exp $

use strict;
use warnings;

sub cmd($)
{
    my ($cmd) = @_;
    print "$cmd\n";
    system("$cmd");
}

my @mans = ("scamper/scamper.1",
	    "scamper/libscamperfile.3",
	    "scamper/warts.5",
	    "lib/libscamperctrl/libscamperctrl.3",
	    "utils/sc_ally/sc_ally.1",
	    "utils/sc_analysis_dump/sc_analysis_dump.1",
	    "utils/sc_attach/sc_attach.1",
	    "utils/sc_bdrmap/sc_bdrmap.1",
	    "utils/sc_erosprober/sc_erosprober.1",
	    "utils/sc_filterpolicy/sc_filterpolicy.1",
	    "utils/sc_hoiho/sc_hoiho.1",
	    "utils/sc_ipiddump/sc_ipiddump.1",
	    "utils/sc_pinger/sc_pinger.1",
	    "utils/sc_prefixprober/sc_prefixprober.1",
	    "utils/sc_prefixscan/sc_prefixscan.1",
	    "utils/sc_remoted/sc_remoted.1",
	    "utils/sc_radargun/sc_radargun.1",
	    "utils/sc_speedtrap/sc_speedtrap.1",
	    "utils/sc_ttlexp/sc_ttlexp.1",
	    "utils/sc_tbitblind/sc_tbitblind.1",
	    "utils/sc_tbitpmtud/sc_tbitpmtud.1",
	    "utils/sc_tracediff/sc_tracediff.1",
	    "utils/sc_uptime/sc_uptime.1",
	    "utils/sc_warts2csv/sc_warts2csv.1",
	    "utils/sc_warts2json/sc_warts2json.1",
	    "utils/sc_warts2pcap/sc_warts2pcap.1",
	    "utils/sc_warts2text/sc_warts2text.1",
	    "utils/sc_wartscat/sc_wartscat.1",
	    "utils/sc_wartsdump/sc_wartsdump.1",
	    "utils/sc_wartsfilter/sc_wartsfilter.1",
	    "utils/sc_wartsfix/sc_wartsfix.1",
    );

cmd("mkdir -p man");

foreach my $man (@mans)
{
    if($man =~ /^.+\/(.+)$/)
    {
	my $name = $1;

	my @manstat = stat("$man");
	if(scalar(@manstat) == 0)
	{
	    print STDERR "could not stat $man\n";
	    exit -1;
	}
	my @pdfstat = stat("man/$name.pdf");
	if(scalar(@pdfstat) == 0 || $manstat[9] > $pdfstat[9])
	{
	    cmd("groff -T ps -man $man | ps2pdf - >man/$name.pdf");
	    cmd("touch -r $man man/$name.pdf");
	}
    }
}
