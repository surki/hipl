#! /usr/bin/perl
# $USAGI: lorder.pl,v 1.1 2001/01/26 04:07:36 yoshfuji Exp $
# ==========================================================================
# Copyright (C) 2001 USAGI/WIDE Project.
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the project nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
# ==========================================================================
# --------------------------------------------------------------
# a perl implementation of lorder.
#
# this is quick hacked version;
# so it may not work well on some platforms.
# --------------------------------------------------------------

@file = @ARGV;

if (@file == 0) {
	print STDERR ("$0 Copyright (C)2001 USAGI/WIDE Project,  All Rights Reserved.\n");
	print STDERR ("usage: lorder file ...\n");
	exit(1);
} elsif (@file == 1) {
	print "$file $file\n";
}
foreach $file (@file){
	print "$file $file\n";
	@nm = `nm -go $file`;
	foreach (@nm){
		chomp;
		if (!/^([^ ]*):.*?\s([TUD]) ([^ ]*)/) {
			next;
		}
		($file, $type, $symbol) = ($1, $2, $3);
		if ($type =~ /[TD]/){
			push (@{$sym{$symbol}}, $file);
		} else {
			push (@{$ref{$symbol}}, $file);
		}
		#print "$file, $type, $symbol\n";
	}
}

for $symbol (keys %ref) {
	foreach $file (@{$ref{$symbol}}) {
		foreach $deffile (@{$sym{$symbol}}) {
			print "$file $deffile\n";
		}
	}
}

exit(0);
