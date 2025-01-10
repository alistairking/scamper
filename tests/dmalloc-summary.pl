#!/usr/bin/env perl

use strict;
use warnings;
use Data::Dumper;

if(scalar(@ARGV) < 2)
{
    print STDERR "usage: dmalloc-summary.pl \$cmd \@files\n";
    exit -1;
}

if(!defined($ENV{'DMALLOC_OPTIONS'}))
{
    print STDERR "DMALLOC_OPTIONS environment variable not set\n";
    exit -1;
}

my $logfile;
if($ENV{'DMALLOC_OPTIONS'} =~ /log=([^,]+)/)
{
    $logfile = $1;
}
else
{
    print STDERR "did not find log= statement in DMALLOC_OPTIONS\n";
    exit -1;
}

my ($cmd, @files) = @ARGV;

my @cmd = split(/{}/, $cmd);
if(scalar(@cmd) == 1 && $cmd =~ /^(.+)\{\}$/)
{
    @cmd = ($1, "");
}
elsif(scalar(@cmd) != 2)
{
    print STDERR "expected single {} in $cmd\n";
    exit -1;
}

my %data;

foreach my $file (@files)
{
    $cmd = $cmd[0];
    $cmd .= "$file";
    $cmd .= $cmd[1] if($cmd[1] ne "");
    $cmd .= " 2>/dev/null";

    system($cmd);

    my $empty = 0;
    my %sig;
    open(LOGFILE, $logfile) or die "could not read dmalloc log $logfile";
    while(<LOGFILE>)
    {
	chomp;
	if(/^\d+:\s+\d+:\s+not freed: .+ from '(.+)'$/)
	{
	    $sig{$1}++;
	}
	elsif(/memory table is empty/)
	{
	    $empty = 1;
	}
    }
    close LOGFILE;

    my @sig = sort(keys %sig);
    my $sig;
    if(scalar(@sig) > 0)
    {
	$sig = join("\n", @sig);
    }
    elsif($empty == 0)
    {
	$sig = "error";
    }

    if(defined($sig))
    {
	push @{$data{$sig}}, $file;
    }
}

foreach my $sig (keys %data)
{
    print "$sig\n";
    foreach my $file (@{$data{$sig}})
    {
	print "  $file\n";
    }
    print "\n";
}
