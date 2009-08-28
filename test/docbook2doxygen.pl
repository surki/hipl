#!/usr/bin/perl -w

# Reads stdin and converts docbook comments to doxygen format

# I converted the entire source code tree like this:
# for i in */*.c; do cp $i /tmp/g1; test/docbook2doxygen.pl </tmp/g1 >/tmp/g2; mv /tmp/g2 $i; done
# -miika


use English;
use strict;

while (defined(my $line = <>)) {
    $line =~ s/\s+\*\s+\@(\S+)\:\s+/\ \*\ \@param\ $1\ /;
    $line =~ s/\s+\*\s+Returns\:\s+/\ \*\ \@return\ /;
    $line =~ s/\/\*\s+XX\ TODO\:/\/\*\!\ \\todo/;
    $line =~ s/\/\*\s+TODO\:/\/\*\!\ \\todo/;
#    $line =~ s///;
#    $line =~ s///;
#    $line =~ s///;
    print "$line";
}
