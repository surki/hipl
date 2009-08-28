#!/usr/bin/perl -w

use strict;
use CGI qw/:standard/;
use FileHandle;

$| = 1;
my ($src_v6, $dst_v6, $src_hit, $dst_hit);

$ENV{'PATH'} = "";

print header(), start_html("HIP checksum calculator");
print h1("HIP checksum calculator (for IPv6 I1 packet)"), hr();

$src_v6 = param('si');
$dst_v6 = param('di');
$src_hit = param('sh');
$dst_hit = param('dh');

$^W = 0;
print STDERR "$0: src_v6='$src_v6' dst_v6='$dst_v6' src_hit='$src_hit' dst_hit='$dst_hit'\n";
$^W = 1;

#if (!defined($src_v6) || !defined($dst_v6) ||
#    !defined($src_hit) || !defined($dst_hit)) {
if (!$src_v6 || !$dst_v6 ||
    !$src_hit || !$dst_hit) {
  print b("Error: missing parameter(s)"), p();
} else {
$src_v6 =~ s/^\s*//;
$src_v6 =~ s/\s*$//;
$dst_v6 =~ s/^\s*//;
$dst_v6 =~ s/\s*$//;
$src_hit =~ s/^\s*//;
$src_hit =~ s/\s*$//;
$dst_hit =~ s/^\s*//;
$dst_hit =~ s/\s*$//;

  print "source IPv6=$src_v6", br();
  print "destination IPv6=$dst_v6", br();
  print "source HIT=$src_hit", br();
  print "destination HIT=$dst_hit", br();
  print br();
  print "<pre>\n";
  system("./csumcalc", $src_v6, $dst_v6, $src_hit, $dst_hit);
  print "</pre>\n";
}

print start_form(),
  "source IPv6:", textfield(-name => 'si', -size => 46, -maxlength => 46), p(),
  "destination IPv6:", textfield(-name => 'di', -size => 46, -maxlength => 46), p(),
  "source HIT:", textfield(-name => 'sh', -size => 46, -maxlength => 46), p(),
  "destination HIT:", textfield(-name => 'dh', -size => 46, -maxlength => 46), p(),
  submit(-name => 'recalculate', -value => 'Recalculate'),
  end_form();

print end_html();
