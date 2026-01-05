#!/usr/bin/env perl

use strict;
use warnings;
use Getopt::Long;

sub usage
{
    print STDERR "usage: fuzz-tmux.pl [--all] \$dir \@fuzzers\n";
    return;
}

my $all = '';
my $rc = GetOptions("all" => \$all);
if(!$rc || scalar(@ARGV) < 1)
{
    usage();
    exit -1;
}
my ($dir, @fuzzers) = @ARGV;

if(!-d $dir)
{
    usage();
    print STDERR "$dir does not exist\n";
    exit -1;
}

if(-r "/proc/sys/kernel/core_pattern")
{
    my $line;
    open(CORE_PAT, "/proc/sys/kernel/core_pattern")
	or die "could not read core pattern\n";
    while(<CORE_PAT>)
    {
	chomp;
	$line = $_;
	last;
    }
    close CORE_PAT;

    if(!defined($line))
    {
	print STDERR "could not read core pattern\n";
	exit -1;
    }
    if($line ne "core")
    {
	print STDERR "unexpected core pattern $line\n";
	exit -1;
    }
}

my %fuzzers;
$fuzzers{"cmd_dealias"}  = [0, "cmd_dealias"];
$fuzzers{"cmd_host"}     = [0, "cmd_host"];
$fuzzers{"cmd_http"}     = [0, "cmd_http"];
$fuzzers{"cmd_owamp"}    = [0, "cmd_owamp"];
$fuzzers{"cmd_ping"}     = [0, "cmd_ping"];
$fuzzers{"cmd_sniff"}    = [0, "cmd_sniff"];
$fuzzers{"cmd_tbit"}     = [0, "cmd_tbit"];
$fuzzers{"cmd_trace"}    = [0, "cmd_trace"];
$fuzzers{"cmd_tracelb"}  = [0, "cmd_tracelb"];
$fuzzers{"cmd_udpprobe"} = [0, "cmd_udpprobe"];
$fuzzers{"dl_parse_arp"} = [0, "dl_parse_arp"];
$fuzzers{"dl_parse_ip"}  = [0, "dl_parse_ip"];
$fuzzers{"host_rr_list"} = [0, "host_rr_list"];
$fuzzers{"warts"}        = [0, "warts"];
$fuzzers{"warts2json"}   = [0, "warts"];
$fuzzers{"warts2text"}   = [0, "warts"];

if($all)
{
    foreach my $fuzzer (keys %fuzzers)
    {
	$fuzzers{$fuzzer}->[0] = 1;
    }
}
elsif(scalar(@fuzzers) > 0)
{
    foreach my $fuzzer (@fuzzers)
    {
	if($fuzzer =~ /^re:(.+)$/)
	{
	    my $c = 0;
	    my $re = $1;
	    foreach my $f (keys %fuzzers)
	    {
		if($f =~ /$re/)
		{
		    $fuzzers{$f}->[0] = 1;
		    $c++;
		}
	    }
	    if($c == 0)
	    {
		usage();
		print STDERR "$fuzzer did not match any fuzzers\n";
		exit -1;
	    }
	}
	else
	{
	    if(!defined($fuzzers{$fuzzer}))
	    {
		usage();
		print STDERR "$fuzzer not valid\n";
		exit -1;
	    }
	    $fuzzers{$fuzzer}->[0] = 1;
	}
    }
}
else
{
    usage();
    exit -1;
}

sub prepare($)
{
    my ($type) = @_;
    my $cmd;
    my $rc;

    $cmd = "mkdir -p $dir/$type/input";
    if(system($cmd) != 0)
    {
	print STDERR "could not $cmd\n";
	return -1;
    }

    $cmd = "./unit_" . $fuzzers{$type}->[1] . " dump $dir/$type/input";
    if(system($cmd) != 0)
    {
	print STDERR "could not $cmd\n";
	return -1;
    }

    $cmd = "afl-cmin" .
	" -i $dir/$type/input" .
	" -o $dir/$type/testcases -- ./fuzz_$type @@";
    if(system($cmd) != 0)
    {
	print STDERR "could not $cmd\n";
	return -1;
    }

    return 0;
}

foreach my $fuzzer (sort keys %fuzzers)
{
    next if($fuzzers{$fuzzer}->[0] == 0);
    if(prepare($fuzzer) != 0)
    {
	exit -1;
    }
}

my $win = 0;
foreach my $type (sort keys %fuzzers)
{
    next if($fuzzers{$type}->[0] == 0);
    my $cmd;

    if($win == 0)
    {
	$cmd = "tmux new-session -d -s fuzz-scamper";
	if(system($cmd) != 0)
	{
	    print STDERR "could not $cmd\n";
	    exit -1;
	}
	$cmd = "tmux rename-window -t fuzz-scamper:$win 'fuzz_$type'";
	if(system($cmd) != 0)
	{
	    print STDERR "could not $cmd\n";
	    exit -1;
	}
    }
    else
    {
	$cmd = "tmux new-window -t fuzz-scamper:$win -n 'fuzz_$type'";
	if(system($cmd) != 0)
	{
	    print STDERR "could not $cmd\n";
	    exit -1;
	}
    }

    $cmd = "tmux send-keys -t fuzz-scamper:$win \"" .
	"AFL_TMPDIR=$dir/$type AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 afl-fuzz " .
	"-i $dir/$type/testcases -o $dir/$type/findings -- " .
	"./fuzz_$type @@\" C-m";
    if(system($cmd) != 0)
    {
	print STDERR "could not $cmd\n";
	exit -1;
    }

    $win++;
}

exit 0;
