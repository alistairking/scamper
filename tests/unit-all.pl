#!/usr/bin/env perl

use strict;
use warnings;

my $rc = 0;

my @tests = (
    "unit_addr",
    "unit_cmd_dealias",
    "unit_cmd_host",
    "unit_cmd_http",
    "unit_cmd_ping",
    "unit_cmd_sniff",
    "unit_cmd_sting",
    "unit_cmd_tbit",
    "unit_cmd_trace",
    "unit_cmd_udpprobe",
    "unit_dl_parse_ip",
    "unit_fds",
    "unit_host_rr_list",
    "unit_http_lib",
    "unit_options",
    "unit_osinfo",
    "unit_string",
    "unit_timeval",
    );
foreach my $test (@tests)
{
    my $cmd = "./$test";
    my @out;
    open(CMD, "$cmd |") or die "could not run $test";
    while(<CMD>)
    {
	chomp;
	push @out, $_;
    }
    close CMD;

    if(scalar(@out) == 0)
    {
	$rc = -1;
	printf "%-20s %s\n", $test, "no output";
    }
    else
    {
	$rc = -1 if(scalar(@out) != 1 || $out[0] ne "OK");
	foreach my $out (@out)
	{
	    printf "%-20s %s\n", $test, $out;
	}
    }
}

exit $rc;
