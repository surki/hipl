#!/usr/bin/perl
##########################################################
# 
# Executed by hipd after address changes
#
# It expects parameters in the environment variables: 
# HIPD_IPS with space-separated list of ip addreses
# HIPD_HIT with Host Identitity Tag 
# HIPD_START with 0 or 1 
# for example,
# HIPD_IPS='192.168.187.1 2001:db8:140:220:215:60ff:fe9f:60c4'
# HIPD_HIT='2001:1e:574e:2505:264a:b360:d8cc:1d75'
# HIPD_START='1'
#
###########################################################
# Oleg Ponomarev, Helsinki Institute for Information Technology
###########################################################
use strict;

my $CONFIG_PATH = "/etc/hip/nsupdate.conf";

##########################################################
# default values, please change in /etc/hip/nsupdate.conf 
our $DEBUG = 0;
our $LOG_FACILITY = 'local6';
our $HIT_TO_IP_ZONE = 'hit-to-ip.infrahip.net.';
our $HIT_TO_IP_SERVER = '';
our $HIT_TO_IP_KEY_NAME = '';
our $HIT_TO_IP_KEY_SECRET = '';
our $HIT_TO_IP_TTL = 1;

our $REVERSE_ZONE = '1.0.0.1.0.0.2.ip6.arpa.';
our $REVERSE_SERVER = 'ptr-soa-hit.infrahip.net.'; # SOA for 1.0.0.1.0.0.2.ip6.arpa. is dns1.icann.org. now
our $REVERSE_KEY_NAME = '';
our $REVERSE_KEY_SECRET = '';
our $REVERSE_TTL = 86400;
our $REVERSE_HOSTNAME = '';
##########################################################

# Read configuration
do $CONFIG_PATH;

use Net::DNS;
use Net::IP qw/ip_is_ipv6 ip_is_ipv4/;
use Sys::Syslog;
use Sys::Hostname;

openlog('nsupdate.pl', 'ndelay,pid', $LOG_FACILITY);

my $env_HIT = $ENV{HIPD_HIT}; log_debug("HIPD_HIT=${env_HIT}");
my $env_IPS = $ENV{HIPD_IPS}; log_debug("HIPD_IPS=${env_IPS}");
my $env_START = $ENV{HIPD_START}; log_debug("HIPD_START=${env_START}"); 

my($HIT, $REV_HIT, $REV_HIT_WITHOUT_ORCHID);

parse_hit();

# globally used resolver
my $RES_DEFAULT = Net::DNS::Resolver->new();

if ($env_IPS) {update_hit_to_ip($env_IPS, $env_START);}

if ($env_START) {
	if ($REVERSE_HOSTNAME) { 
		update_reverse($REVERSE_HOSTNAME);
	} else {
		my $fqdn = fqdn(); 
		if ($fqdn =~ /\./) {
			update_reverse($fqdn);	
		} else {
			log_error("No dots in FQDN ($fqdn), will not update reverse");
		}
	}
}

exit 0;

####################################################################################################
sub parse_hit
{
	unless ($env_HIT) {log_and_die("HIPD_HIT environment variable is empty");}
	$HIT = $env_HIT;
	my $hit_ip = new Net::IP($HIT) or log_and_die("$HIT does not look like IP address");
	my $r = $hit_ip->reverse_ip();
	$r =~ /^(.+)\.ip6\.arpa\.$/ or log_and_die("reverse $HIT ($r) does not look like reverse IPv6 address");
	$REV_HIT = $1;
	unless ($REV_HIT =~ /(.+)\.1\.0\.0\.1\.0\.0\.2$/) {log_and_die("$REV_HIT does not end with ORCHID prefix");}
	$REV_HIT_WITHOUT_ORCHID = $1;
}

####################################################################################################
sub update_hit_to_ip
{
	my @new_ips = split(/\s/,$_[0]);
	my $compare_first = $_[1];

	normalize_ips(\@new_ips);

	my $hit_to_ip_domain = ${REV_HIT} . "." . ${HIT_TO_IP_ZONE};

	my $res = Net::DNS::Resolver->new();

	if ($HIT_TO_IP_SERVER) {$res->nameservers(resolve_nameservers($HIT_TO_IP_SERVER));}

	if ($compare_first) {
		my @current_ips = query_addresses($hit_to_ip_domain, $res);
		normalize_ips(\@current_ips);
		my $current_ips_str = join(',',sort @current_ips);
		my $new_ips_str = join(',',sort @new_ips);

		log_debug("compared current: ${current_ips_str} and desired: ${new_ips_str}");

		if ($current_ips_str eq $new_ips_str) {
			log_debug("No hit-to-ip update needed");
			return;
		}
	}

	my $update = prepare_hit_to_ip_update($hit_to_ip_domain, \@new_ips);

	sign_update($update, $HIT_TO_IP_KEY_NAME, $HIT_TO_IP_KEY_SECRET);

	unless ($HIT_TO_IP_SERVER) {
		$res->nameservers(query_addresses(query_soa($HIT_TO_IP_ZONE), $RES_DEFAULT));
	}

	send_update_from_hit($update, $HIT, $res);
}

####################################################################################################
sub prepare_hit_to_ip_update
{
	my $domain = $_[0];
	my $ips_ref = $_[1];

	my $update = Net::DNS::Update->new($HIT_TO_IP_ZONE);

	$update->push(update => rr_del($domain));

	foreach my $ip (@$ips_ref) {
        	if (ip_is_ipv6($ip)) {
			$update->push(update => rr_add("$domain ${HIT_TO_IP_TTL} AAAA $ip"));
		} elsif (ip_is_ipv4($ip)) {			
			$update->push(update => rr_add("$domain ${HIT_TO_IP_TTL} A $ip"));
		} else {
			log_error("Don't know how to add $ip");
		}
        }

	return $update;
}

####################################################################################################
sub update_reverse
{
	my $hostname = $_[0];

	log_debug("Desired reverse: $hostname");

	my $reverse_domain = ${REV_HIT_WITHOUT_ORCHID} . "." . ${REVERSE_ZONE};

	my $res = Net::DNS::Resolver->new();

	if ($REVERSE_SERVER) {$res->nameservers(resolve_nameservers($REVERSE_SERVER));}

	my @ptrs = query_ptrs($reverse_domain, $res);
	
	log_debug("Found reverse: " . join(',',@ptrs));

# Check if it already contains desired PTR 
	if (grep {$_ eq $hostname} @ptrs) {log_debug("No reverse update needed");return;}

	my $update = prepare_reverse_update($reverse_domain, $hostname);

	sign_update($update, $REVERSE_KEY_NAME, $REVERSE_KEY_SECRET);

	unless ($REVERSE_SERVER) {$res->nameservers(query_addresses(query_soa($REVERSE_ZONE), $RES_DEFAULT));}

	send_update_from_hit($update, $HIT, $res);
}

####################################################################################################
sub prepare_reverse_update
{
	my $domain = $_[0];
	my $hostname = $_[1];

	my $update = Net::DNS::Update->new($REVERSE_ZONE);

	unless ($hostname =~ /\.$/) {$hostname .= ".";}

	$update->push(update => rr_del($domain));
	$update->push(update => rr_add("$domain ${REVERSE_TTL} PTR $hostname"));

	return $update;
}

####################################################################################################
sub resolve_nameservers
{
	my $server = $_[0];

	if (ip_is_ipv6($server)) {
		return ($server);
	} elsif (ip_is_ipv4($server)) {		
		return ($server);
	}

	# we can't put symbolic name to Resolver->nameservers because it would not use AAAA then
	my @server_ips = query_addresses($server, $RES_DEFAULT);
	log_debug("nameservers set to " . join(',', @server_ips));

	return @server_ips;
}

####################################################################################################
sub query_soa
{
	my $zone = $_[0];

	log_debug("query_soa($zone)");

	my $query = ${RES_DEFAULT}->query($zone, "SOA");

	if ($query) {
		foreach my $rr ($query->answer) {
        		next unless ($rr->type eq "SOA");
			if ($rr->mname =~ /icann\.org/) {log_error("Will not send update to $rr->mname");return;}
			log_debug("query_soa found " . $rr->mname);
			return $rr->mname;
        	}
		log_error("SOA for $zone not found in the answer: " . $query->print());
	} else {
		log_error("SOA for $zone not found: " . ${RES_DEFAULT}->errorstring);
	}
}

####################################################################################################
sub query_addresses
{
	my $host = $_[0];
	my $res = $_[1];
	
	log_debug("query_addresses($host):");

	my @addresses;

	my $query = $res->query($host, "AAAA");
	if ($query) {
		foreach my $rr ($query->answer) {
        		next unless ($rr->type eq "AAAA");
			push @addresses, $rr->address();
			log_debug("query_addresses found AAAA " . $rr->address());
        	}
	}

	$query = $res->query($host, "A");
	if ($query) {
		foreach my $rr ($query->answer) {
        		next unless ($rr->type eq "A");
			push @addresses, $rr->address();
			log_debug("query_addresses found A " . $rr->address());
        	}
	} 

	return @addresses;
}

####################################################################################################
sub query_ptrs
{
	my $domain = $_[0];
	my $res = $_[1];

	log_debug("query_ptrs($domain)");

	my $query = $res->query($domain , "PTR");

	my @ptrs;

	if ($query) {
		foreach my $rr ($query->answer) {
        		next unless ($rr->type eq "PTR");
			log_debug("query_ptrs found " . $rr->ptrdname());
			push @ptrs, $rr->ptrdname();
        	}
	}

	return @ptrs;
}

####################################################################################################
sub sign_update
{
	my $update = $_[0];
	my $key_name = $_[1];
	my $key_secret = $_[2];
	
	if ($key_name) {
		unless ($key_secret) {log_and_and('KEY_NAME is defined, but KEY_SECRET is empty');}
		log_debug("Signing using $key_name");
		$update->sign_tsig($key_name, $key_secret) or log_error("sign_tsig failed");
	}
}

####################################################################################################
sub send_update_from_hit
{
	my $update = $_[0];
	my $hit = $_[1];
	my $res = $_[2];

	log_debug("Using $hit as local address");
	$res->srcaddr($hit);

	my $reply = $res->send($update);

        if ($reply) {
            if ($reply->header->rcode eq 'NOERROR') {
                log_debug("Update succeeded");
            } else {
                log_error('Update failed: ' . $reply->header->rcode);
            }
        } else {
            log_error('Update failed: ' . $res->errorstring);
        }
}

####################################################################################################
sub log_debug
{
	my $message = $_[0];
	if ($DEBUG) {print $message, "\n";}
	syslog('debug', $message);
}

sub log_error
{
	my $message = $_[0];
	if ($DEBUG) {print $message, "\n";}
	syslog('err', $message);
}

sub log_and_die
{
	my $message = $_[0];
	log_error($message);
	die $message;
}

####################################################################################################
sub fqdn {
  my $sys_hostname = hostname(); # may be short
  my @hostent = gethostbyname($sys_hostname);
  return $hostent[0] || $sys_hostname;
}


####################################################################################################
sub normalize_ips {
	my $ips_ref = $_[0];

	foreach my $ip (@$ips_ref) {
		$ip = new Net::IP($ip)->ip();
	}
	
	return $ips_ref;
}
