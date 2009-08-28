#!/usr/bin/perl -w
#
# Author: Miika Komu miika@iki.fi
# Licence: GNU/GPL
# 
# Usage:   hashlinediff file1 file2
# Purpose: makes a hash of the lines in the given files and prints
#          the differences

use strict;
use English;

my ($file1, $file2) = @ARGV;
my (%hash1, %hash2) = ((), ());

die("usage: $0 file1 file2\n") if ($#ARGV != 1);

%hash1 = readhash($file1);
%hash2 = readhash($file2);

foreach my $key (sort((keys(%hash1), keys(%hash2)))) {
    if (!$hash1{$key}) {
	print("+$key\n");
    } elsif (!$hash2{$key}) {
	print("-$key\n");
    }
}

sub readhash {
    my ($file) = @ARG;
    my ($fd, $line);
    my %hash = ();
    open($fd, $file) || die("failed to open file $file\n");
    while (defined($line = <$fd>)) {
	chomp $line;
	$hash{$line} = 0 if (!$hash{$line});
	$hash{$line} += 1;
    }
    close($fd);
    return %hash;
}
