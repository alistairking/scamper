#!/usr/bin/env perl
#
# process source code looking for #ifdef-related bugs.
#
# $Id: check-ifdef.pl,v 1.8 2024/11/30 06:50:38 mjl Exp $

use strict;
use warnings;

my %defs;

# we use these in scamper at some point, assuming they exist.
# initialise to zero, set to 1 if ever observed in an #ifdef, so that
# we can find stale ifdefs in this file.
$defs{$_} = 0 foreach (
    "AF_LINK", "AF_UNIX",
    "ARPHRD_IEEE1394", "ARPHRD_SIT", "ARPHRD_VOID",
    "DLT_APPLE_IP_OVER_IEEE1394",
    "BIOCSETFNR", "DIOCGETSTATUSNV", "SIOCGSTAMP",
    "ICMP6_FILTER", "ICMP_FILTER",
    "IPV6_DONTFRAG", "IPV6_HOPLIMIT",
    "IPV6_PKTINFO", "IPV6_RECVERR", "IPV6_RECVHOPLIMIT",
    "IPV6_RECVPKTINFO", "IPV6_RECVTCLASS", "IPV6_TCLASS", "IPV6_V6ONLY",
    "IP_PKTINFO", "IP_RECVERR", "IP_RECVOPTS", "IP_RECVPKTINFO", "IP_RECVIF",
    "MJLHEAP_DEBUG", "MJLLIST_DEBUG", "MJLSPLAYTREE_DEBUG",
    "O_NONBLOCK", "PCRE_STUDY_JIT_COMPILE", "RTF_LLINFO",
    "SIGCHLD", "SIGPIPE",
    "SOURCES_DEBUG",
    "SO_TIMESTAMP",
    "SSL_CTRL_SET_TLSEXT_HOSTNAME",
    "_MSC_VER",
    "IOV_MAX", "_SC_IOV_MAX", "_SC_NPROCESSORS_ONLN",
    "s6_addr32",
    "BUILDING_SCAMPER", "BUILDING_LIBSCAMPERFILE",
    "DMALLOC",
    "HAVE_CONFIG_H", "HAVE_PCRE2", "HAVE_WINGETOPT_H",
    "_IPFW2_H", "_IP_FW_H",
    "__linux__", "__sun__", "__ANDROID__", "__APPLE__", "_WIN32",
    "__FreeBSD__", "__NetBSD__", "__OpenBSD__", "__DragonFly__",
    "__NetBSD_Version__",
    "COMMON_CHECK_ADDR",
    "FUZZ_CHUNKED", "FUZZ_DEALIAS", "FUZZ_HDRS", "FUZZ_HOST",
    "FUZZ_HTTP", "FUZZ_NEIGHBOURDISC", "FUZZ_PING", "FUZZ_SNIFF",
    "FUZZ_STING", "FUZZ_TBIT", "FUZZ_TRACE", "FUZZ_TRACELB",
    "FUZZ_UDPPROBE", "TEST_DL_PARSE_ARP", "TEST_DL_PARSE_IP",
    "TEST_HOST_RR_LIST", "TEST_DL_FILTER_COMPILE",
    );

my %hdrdefs;
my %hdrpaths;

sub hdrname($)
{
    my ($in) = @_;
    return $1 if($in =~ /([a-z\d_]+\.h$)/);
    return $in;
}

sub process_file($$$);
sub process_file($$$)
{
    my ($cfile, $file, $state) = @_;

    my $hfile = 0;
    $hfile = 1 if($file =~ /\.h$/);

    my @lines;
    open(FILE, $file) or die "could not open $file";
    while(<FILE>)
    {
	chomp;
	push @lines, $_;
    }
    close FILE;
    foreach my $line (@lines)
    {
	if($line =~ /^\s*#define\s+([A-Z\d_]+)/)
	{
	    my $def = $1;
	    if(defined($state->{$def}) && $state->{$def} == 0)
	    {
		print "out of order includes in $cfile: $def\n"
	    }
	    $state->{$def} = 1;
	}
        elsif($file =~ /config\.h$/ && $line =~ /^\/\* #undef ([A-Z\d_]+)/)
	{
	    $state->{$1} = 1;
	}
	elsif($line =~ /^\s*#\s*include\s+\"(.+?)\"/)
	{
	    next if($hfile != 0);
	    my $hdrname = hdrname($1);
	    process_file($cfile, $hdrpaths{$hdrname}, $state);
	}
	else
	{
	    # assemble a list of defs to check
	    my @check;
	    if($line =~ /^\s*#ifdef\s+(.+?) / || $line =~ /^\s*#ifdef\s+(.+)$/)
	    {
		push @check, $1;
	    }
	    else
	    {
		foreach my $bit (split(/\s+/, $line))
		{
		    push @check, $1 if($bit =~ /defined\((.+?)\)/);
		}
	    }

	    # check the defs
	    foreach my $def (@check)
	    {
		if(defined($defs{$def}))
		{
		    $defs{$def} = 1;
		    next;
		}
		next if(defined($state->{$def}));
		if(defined($hdrdefs{$def}))
		{
		    if($hfile == 0)
		    {
			print "$file $def not in state\n";
		    }
		    else
		    {
			$state->{$def} = 0;
		    }
		}
		else
		{
		    print "$def $file\n";
		}
	    }
	}
    }
}

# get other #defines in header files.
open(FILES, "find . -name \"*.h\" -print |") or die "could not find";
while(<FILES>)
{
    chomp;
    my $file = $_;
    my $hdrname = hdrname($file);
    if(defined($hdrpaths{$hdrname}))
    {
	print STDERR "two headers named $hdrname\n";
	exit -1;
    }
    $hdrpaths{$hdrname} = $file;

    open(HEADER, $file) or die "could not open $file";
    while(<HEADER>)
    {
	if(/^\s*#define ([A-Z\d_]+)/ ||
	   ($hdrname eq "config.h" && /^\/\* #undef ([A-Z\d_]+)/))
	{
	    my $def = $1;
	    next if($def =~ /^_/ && $hdrname eq "config.h");
	    if(defined($hdrdefs{$def}) && $hdrname ne $hdrdefs{$def})
	    {
		print STDERR "$def in $hdrdefs{$def} and $hdrname\n";
		exit -1;
	    }
	    $hdrdefs{$def} = $hdrname;
	}
    }
    close HEADER;
}
close FILES;

if(!defined($hdrpaths{"config.h"}))
{
    print STDERR "error: config.h missing\n";
    exit -1;
}

open(FILES, "find . -name \"*.c\" -print |") or die "could not find";
while(<FILES>)
{
    chomp;
    my $file = $_;
    next if($file =~ /\/python\/scamper\.c$/);

    my %state;
    process_file($file, $file, \%state);
}

# print out defs that are stale.
foreach my $def (keys %defs)
{
    print "$def unused\n" if($defs{$def} == 0);
}

exit 0;
