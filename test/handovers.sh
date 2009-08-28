#!/bin/bash
##########################################################################
#
# Script to test that all the handovers are working
# Author: Samu Varjonen 09/2008
#
# This script needs you to define a mapping to /etc/hosts
# and into the /etc/hip/hosts to map the hit to either IPv4
# or IPv6 address. Use IPv4 mapping with the tests that need
# to start with IPv4 address and vice versa.
#
# Tests run by this script that start of with IPv4 address:
# Hard IPv4 to IPv4
# Soft IPv4 to IPv4
# Soft IPv4 to IPv6
# Hard IPv4 to IPv6
#
# Tests run by this script that start of with IPv6 address:
# Hard IPv6 to IPv6
# Soft IPv6 to IPv6
# Soft IPv6 to IPv4
# Hard IPv6 to IPv4
#
# These tests are run with one interface by using different IP masks
# and by using the tools offered by the iputils package.
#
# NOTE: RUN AS SUDO to get everything working without having to ask 
#       passwords all the time. BECAUSE this is run as sudo READ this
#       script to know what it does before using it.
#
# NOTE: Remember this peer is the MN/Initiator node. Also Remember
#       to check that the other CN/Responder has its hipd running 
#       and that it has both IPv4 and IPv6 addresses. Also this
#       node/MN/Initiator has to have hipd running.
#
# NOTE: All the interfamily tests are run with "locator on" option of 
#       hipconf configuration tool.
#
# NOTE: Remember to change the variables below to mirror your network
#       Also remember that to this script to work the IPv4 primary and 
#       secondary addresses have to be added with different masks.
#       Otherwise when you delete the primary address the secondary 
#       one will also disappear. 
#
# NOTE: If initialization of the tunnel hangs your mappings in /etc/hosts
#       or in /etc/hip/hosts might be incorrect.
#
# NOTE: Removing the primary IPv4 address from the interface will
#       also remove the default route and when you add default route
#       to the interface you may have to wait a long time before you can 
#       send anything. For some reason after manually adding default route
#       the networking becomes unresponsive.
#
# NOTE: Also wireless interfaces might intervene and take control so 
#       shut them down
#
# NOTE: Modifies /proc/sys/net/ipv6/conf/all/accept_ra
#       In some cases you have to stop listening routing advertisements
#       This may have to be done on the peer side also
#
# NOTE: Reset interface turns locators off by default.
#       For some reason soft4to4 did not work 29.9.2008.
#       Better luck with the new code some day.
#       Remember to turn locators off on the CN side also on inner tests.
#
##########################################################################

#VARIABLES THAT HAVE TO BE MODIFIED 
#ACCORDING TO YOUR INFRASTRUCTURE

# if you have more addresses with scope:global they might interfere so 
# remove them or at least know that they might and probably will interfere
# This means that you may have to modify this scripts reset interface to remove
# the extra addresses after it has brought up the interface

##test network peer is sutherland
#PEER_HIT="2001:11:8ed8:59b:95ff:c8b:8aba:9c24"
#PEER_IPV4="193.167.187.2"
#PEER_IPV6="3::2"

#OUR_PRIMARY_ADDR_V4="193.167.187.93"
#OUR_PRIMARY_MASK_V4="/25"
#OUR_SECONDARY_ADDR_V4="193.167.187.94"
#OUR_SECONDARY_MASK_V4="/32"

#OUR_PRIMARY_ADDR_V6="3::3"
#OUR_SECONDARY_ADDR_V6="3::15"
#OUR_MASK_V6="/64"

##home network peer is atlantis
PEER_HIT="2001:13:91ea:bcda:af5d:7ec1:27fb:a207"
PEER_IPV4="192.168.1.13"
PEER_IPV6="3::2"

OUR_PRIMARY_ADDR_V4="192.168.1.12"
OUR_PRIMARY_MASK_V4="/24"
OUR_SECONDARY_ADDR_V4="192.168.1.22"
OUR_SECONDARY_MASK_V4="/32"

OUR_PRIMARY_ADDR_V6="3::3"
OUR_SECONDARY_ADDR_V6="3::15"
OUR_MASK_V6="/64"

TARGET_DEVICE="eth0"

TEMPORARY_FILE_PING="/tmp/pong"

#END MOD VARIABLES

#START INTERNAL VARIABLES

#these variables contain FAILED/SUCCESS/No_result
STAT_S44="No_result"
STAT_H44="No_result"
STAT_S66="No_result"
STAT_H66="No_result"
STAT_S46="No_result"
STAT_H46="No_result"
STAT_S64="No_result"
STAT_H64="No_result"

#before the handover FAILED/SUCCESS/No_result
BSTAT_S44="No_result"
BSTAT_H44="No_result"
BSTAT_S66="No_result"
BSTAT_H66="No_result"
BSTAT_S46="No_result"
BSTAT_H46="No_result"
BSTAT_S64="No_result"
BSTAT_H64="No_result"

#just for the enter in the start
tmp=""
pinglinecount=""

ROOT_UID=0 

#END INTERNAL VARIABLES

##########################################################################

#UTILITY FUNCTIONS

function dotline {
    echo " ::::::::::::::::::::::::::::::::::::::::::::::::::::::::: "
}

function eqline {
    echo " ========================================================= "
}

function usage {
  printf "Usage:\n\n"
  printf "\tTests starting with IPv4 address\n"
  printf "\t %s all4|h44|s44|h46|s46\n\n" $0
  printf "\tTests starting with IPv6 address\n"
  printf "\t %s all6|h66|s66|h64|s64\n" $0
  printf "\t %s all\n\n" $0
  printf "\t %s inner\n" $0
  printf "\t %s inter\n\n" $0
  printf "\tall    : Run all handovers\n\n"
  printf "\tinner  : Run all innerfamily handovers\n"
  printf "\tinter  : Run all interfamily handovers\n\n"
  printf "\tall4   : Run all handovers from IPv4\n"
  printf "\th44    : Run hard handover from IPv4 to IPv4\n"
  printf "\ts44    : Run soft handover from IPv4 to IPv4\n"
  printf "\th46    : Run hard handover from IPv4 to IPv6\n"
  printf "\ts46    : Run soft handover from IPv4 to IPv6\n\n"
  printf "\tall6   : Run all handovers from IPv6\n"
  printf "\th66    : Run hard handover from IPv6 to IPv6\n"
  printf "\ts66    : Run soft handover from IPv6 to IPv6\n"
  printf "\th64    : Run hard handover from IPv6 to IPv4\n"
  printf "\ts64    : Run soft handover from IPv6 to IPv4\n\n"
  exit 0
}


function print_statistics {
    #raflip 1
    dotline
    echo "Test results!!!!!!!"
    dotline
    case $1 in 
	"all") 
	    printf "\nTest results for all the tests:\n\n"
	    printf "Starting from IPv4 address -->\n"
	    printf "\tSoft handover from IPv4 to IPv4: before %s after %s\n" $BSTAT_S44 $STAT_S44
	    printf "\tHard handover from IPv4 to IPv4: before %s after %s\n" $BSTAT_H44 $STAT_H44
	    printf "\tSoft handover from IPv4 to IPv6: before %s after %s\n" $BSTAT_S46 $STAT_S46
	    printf "\tHard handover from IPv4 to IPv6: before %s after %s\n" $BSTAT_H46 $STAT_H46
	    printf "\nStarting from IPv6 address -->\n"
	    printf "\tSoft handover from IPv6 to IPv6: before %s after %s\n" $BSTAT_S66 $STAT_S66
	    printf "\tHard handover from IPv6 to IPv6: before %s after %s\n" $BSTAT_H66 $STAT_H66
	    printf "\tSoft handover from IPv6 to IPv4: before %s after %s\n" $BSTAT_S64 $STAT_S64
	    printf "\tHard handover from IPv6 to IPv4: before %s after %s\n" $BSTAT_H64 $STAT_H64
	    ;; 	
	"all4")    
	    printf "Starting from IPv4 address -->\n"
	    printf "\tSoft handover from IPv4 to IPv4: before %s after %s\n" $BSTAT_S44 $STAT_S44
	    printf "\tHard handover from IPv4 to IPv4: before %s after %s\n" $BSTAT_H44 $STAT_H44
	    printf "\tSoft handover from IPv4 to IPv6: before %s after %s\n" $BSTAT_S46 $STAT_S46
	    printf "\tHard handover from IPv4 to IPv6: before %s after %s\n" $BSTAT_H46 $STAT_H46
	    ;;
	"all6")    
	    printf "\nStarting from IPv6 address -->\n"
	    printf "\tSoft handover from IPv6 to IPv6: before %s after %s\n" $BSTAT_S66 $STAT_S66
	    printf "\tHard handover from IPv6 to IPv6: before %s after %s\n" $BSTAT_H66 $STAT_H66
	    printf "\tSoft handover from IPv6 to IPv4: before %s after %s\n" $BSTAT_S64 $STAT_S64
	    printf "\tHard handover from IPv6 to IPv4: before %s after %s\n" $BSTAT_H64 $STAT_H64
	    ;;
	"inner")  
	    printf "\tSoft handover from IPv4 to IPv4: before %s after %s\n" $BSTAT_S44 $STAT_S44
	    printf "\tHard handover from IPv4 to IPv4: before %s after %s\n" $BSTAT_H44 $STAT_H44
	    printf "\tSoft handover from IPv6 to IPv6: before %s after %s\n" $BSTAT_S66 $STAT_S66
	    printf "\tHard handover from IPv6 to IPv6: before %s after %s\n" $BSTAT_H66 $STAT_H66
	    ;;
	"inter")  
	    printf "\tSoft handover from IPv4 to IPv6: before %s after %s\n" $BSTAT_S46 $STAT_S46
	    printf "\tHard handover from IPv4 to IPv6: before %s after %s\n" $BSTAT_H46 $STAT_H46
	    printf "\tSoft handover from IPv6 to IPv4: before %s after %s\n" $BSTAT_S64 $STAT_S64
	    printf "\tHard handover from IPv6 to IPv4: before %s after %s\n" $BSTAT_H64 $STAT_H64
	    ;;
	"h44")      
	    printf "\tHard handover from IPv4 to IPv4: before %s after %s\n" $BSTAT_H44 $STAT_H44
	    ;;
	"h66")      
	    printf "\tHard handover from IPv6 to IPv6: before %s after %s\n" $BSTAT_H66 $STAT_H66
	    ;;
	"s44")      
	    printf "\tSoft handover from IPv4 to IPv6: before %s after %s\n" $BSTAT_S44 $STAT_S44
	    ;;
	"s66")      
	    printf "\tSoft handover from IPv6 to IPv6: before %s after %s\n" $BSTAT_S66 $STAT_S66
	    ;;
	"h46")      
	    printf "\tHard handover from IPv4 to IPv6: before %s after %s\n" $BSTAT_H46 $STAT_H46
	    ;;
	"h64")      
	    printf "\tHard handover from IPv6 to IPv4: before %s after %s\n" $BSTAT_H64 $STAT_H64
	    ;;
	"s46")     
	    printf "\tSoft handover from IPv4 to IPv6: before %s after %s\n" $BSTAT_S46 $STAT_S46
	    ;;
	"s64")     
	    printf "\tSoft handover from IPv6 to IPv4: before %s after %s\n" $BSTAT_S64 $STAT_S64
	    ;;
	*) echo "ERROR unknown test type"; usage ; exit 0;;
    esac
    exit 0
}

function check_root {
    if [ "$UID" -eq "$ROOT_UID" ] ; then
	echo "You are root, so be carefull and"
	echo -n "read the comments for usage [ENTER to continue]:"
	read tmp
	printf "\n"
    else
	echo ""
	echo "This scripts needs to be run as sudo/root"
	echo "and be sure to read the comments from the script"
	echo "to know what this script works."
	echo ""
	exit 0 
    fi

}

function pong {
    printf "Trying to send ping to %s\n" $PEER_HIT 
    ping6 -c 1 $PEER_HIT > $TEMPORARY_FILE_PING 
    pinglinecount=$(grep '1 packets transmitted, 1 received' $TEMPORARY_FILE_PING)
    if [ "$pinglinecount" = "" ]
    then 
	case $1 in 
	    "STAT_S44") STAT_S44="FAILED" ; echo FAILED ;;
	    "STAT_H44") STAT_H44="FAILED" ; echo FAILED ;;
	    "STAT_H66") STAT_H66="FAILED" ; echo FAILED ;;
	    "STAT_S66") STAT_S66="FAILED" ; echo FAILED ;;
	    "STAT_H46") STAT_H46="FAILED" ; echo FAILED ;;
	    "STAT_H64") STAT_H64="FAILED" ; echo FAILED ;;
	    "STAT_S46") STAT_S46="FAILED" ; echo FAILED ;;
	    "STAT_S64") STAT_S64="FAILED" ; echo FAILED ;;
	    "BSTAT_S44") BSTAT_S44="FAILED" ; echo FAILED ;;
	    "BSTAT_H44") BSTAT_H44="FAILED" ; echo FAILED ;;
	    "BSTAT_H66") BSTAT_H66="FAILED" ; echo FAILED ;;
	    "BSTAT_S66") BSTAT_S66="FAILED" ; echo FAILED ;;
	    "BSTAT_H46") BSTAT_H46="FAILED" ; echo FAILED ;;
	    "BSTAT_H64") BSTAT_H64="FAILED" ; echo FAILED ;;
	    "BSTAT_S46") BSTAT_S46="FAILED" ; echo FAILED ;;
	    "BSTAT_S64") BSTAT_S64="FAILED" ; echo FAILED ;;
	esac
    else
	case $1 in 
	    "STAT_S44") STAT_S44="SUCCESS" ; echo SUCCESS ;;
	    "STAT_H44") STAT_H44="SUCCESS" ; echo SUCCESS  ;;
	    "STAT_H66") STAT_H66="SUCCESS" ; echo SUCCESS  ;;
	    "STAT_S66") STAT_S66="SUCCESS" ; echo SUCCESS  ;;
	    "STAT_H46") STAT_H46="SUCCESS" ; echo SUCCESS  ;;
	    "STAT_H64") STAT_H64="SUCCESS" ; echo SUCCESS  ;;
	    "STAT_S46") STAT_S46="SUCCESS" ; echo SUCCESS  ;;
	    "STAT_S64") STAT_S64="SUCCESS" ; echo SUCCESS  ;;
	    "BSTAT_S44") BSTAT_S44="SUCCESS" ; echo SUCCESS  ;;
	    "BSTAT_H44") BSTAT_H44="SUCCESS" ; echo SUCCESS  ;;
	    "BSTAT_H66") BSTAT_H66="SUCCESS" ; echo SUCCESS  ;;
	    "BSTAT_S66") BSTAT_S66="SUCCESS" ; echo SUCCESS  ;;
	    "BSTAT_H46") BSTAT_H46="SUCCESS" ; echo SUCCESS  ;;
	    "BSTAT_H64") BSTAT_H64="SUCCESS" ; echo SUCCESS  ;;
	    "BSTAT_S46") BSTAT_S46="SUCCESS" ; echo SUCCESS  ;;
	    "BSTAT_S64") BSTAT_S64="SUCCESS" ; echo SUCCESS  ;;
	esac
    fi
}

function init_maps {
    if [ $1 -eq 4 ] ; then
	printf "Adding %s to %s mapping\n" $PEER_HIT $PEER_IPV4
	sudo hipconf add map $PEER_HIT $PEER_IPV4
    else
	printf "Adding %s to %s mapping\n" $PEER_HIT $PEER_IPV6
	sudo hipconf add map $PEER_HIT $PEER_IPV6
    fi
}

function init_bex {
    printf "Initializing BEX/tunnel to %s\n" $PEER_HIT
    eqline
    ping6 -c 1 -W 25 $PEER_HIT 
    eqline
    printf "Tunnel should be open\n"
}

function reset_hipd {
    printf "Resetting hipd...\n"
    kill_hipd
    printf "Starting hipd\n"
    sudo hipd -b
    sleep 5
    printf "Resetting hadb\n"
    sudo hipconf rst all > /dev/null
    sleep 5
    #turn locators off by default because some of the 
    #tests did not work locators on (soft4to4 for example)
    # -Samu 29.9.2008
    sudo hipconf locator off
    sleep 10
    printf "Done hipd is running with PID "
    pidof hipd
}

function kill_hipd {
    sudo killall hipd
    sleep 5
    printf "Killed hipd\n"
}

function reset_interface {
    eqline
    eqline
    printf "Resetting the interface\n"
    sudo ifconfig $TARGET_DEVICE down
    sleep 1
    #raflip 0
    sudo ifconfig $TARGET_DEVICE up
    #sudo ip addr add $OUR_PRIMARY_ADDR_V4$OUR_PRIMARY_MASK_V4 dev $TARGET_DEVICE
    sleep 10
}

function deladdr {
    printf "Deleting address %s from %s\n" $1 $TARGET_DEVICE
    sudo ip addr del $1$2 dev $TARGET_DEVICE
    sleep 1
    eqline
    ip addr show $TARGET_DEVICE
    eqline
}

function addaddr {
    printf "Adding address %s to %s\n" $1 $TARGET_DEVICE
    sudo ip addr add $1$2 dev $TARGET_DEVICE
    sleep 1
    eqline
    ip addr show $TARGET_DEVICE
    eqline
}

function addroute {
    printf "Adding default route\n"
    sudo route add default dev $TARGET_DEVICE
    #Sleep quite long otherwise networking architecture does not answer
    #Figure out what results into the unresponsiveness
    sleep 40
}

function locators {
    sudo hipconf locator on
    sleep 10
}

function raflip {
    printf "Echo IPv6 routing advertisements to %s on all devices\n" $1
    if [ -e /proc/sys/net/ipv6/conf/all/accept_ra ] ; then
	for f in /proc/sys/net/ipv6/conf/*/accept_ra
	do
	    echo $1 > $f
	done
    fi
}

#END UTILITY FUNCTIONS

##########################################################################

#TEST FUNCTIONS

#Do ALL tests at one go
function alltests {
    echo "Running all tests"
    dotline
    all4tests
    all6tests
}

#Run all innerfamily tests
function innertests {
    echo "Running all innerfamily tests"
    dotline
    hard4to4
    dotline
    soft4to4
    dotline
    hard6to6
    dotline
    soft6to6
    dotline
}

#Run all interfamily tests
function intertests {
    echo "Running all interfamily tests"
    dotline
    hard4to6
    dotline
    soft4to6
    dotline
    hard6to4
    dotline
    soft6to4
    dotline
}

#Do all tests that start from IPv4 address
function all4tests {
    echo "Running all tests from IPv4"
    dotline
    hard4to4
    dotline
    soft4to4
    dotline
    hard4to6
    dotline
    soft4to6
    dotline
}

# Do all tests that start from IPv6 address 
function all6tests {
    echo "Running all tests from IPv6"
    dotline
    hard6to6
    dotline
    soft6to6
    dotline
    hard6to4
    dotline
    soft6to4
    dotline
}
#TESTS STARTING FROM IPv4

# Hard IPv4 to IPv4
#
# In this test we start from the IPv4 address remove the IPv4 address wait
# for a while and add another IPv4 address.
function hard4to4 {
    printf "Running test hard4to4...\n"
    reset_interface
    reset_hipd
    init_maps 4
    init_bex
    pong BSTAT_H44
    #start handover
    deladdr $OUR_PRIMARY_ADDR_V4 $OUR_PRIMARY_MASK_V4
    addaddr $OUR_SECONDARY_ADDR_V4 $OUR_SECONDARY_MASK_V4
    addroute
    #stop handover
    pong STAT_H44
    reset_interface
}

# Soft IPv4 to IPv4
#
# In this test we start from the IPv4 address and add another IPv4 address 
# to the same interface with different prefix mask. After we wait a while
# we remove the original/first IPv4 address.
function soft4to4 {
    printf "Running test soft4to4...\n"
    reset_interface
    reset_hipd
    init_maps 4
    init_bex
    pong BSTAT_S44
    #start handover
    addaddr $OUR_SECONDARY_ADDR_V4 $OUR_SECONDARY_MASK_V4
    deladdr $OUR_PRIMARY_ADDR_V4 $OUR_PRIMARY_MASK_V4
    addroute
    #stop handover
    pong STAT_S44
    reset_interface
}

# Soft IPv4 to IPv6
#
# In this test we start from the IPv4 address and add a IPv6 address and
# then we wait for a while and remove the IPv4 address.
function soft4to6 {
    printf "Running test soft4to6...\n"
    reset_interface
    reset_hipd
    locators
    init_maps 4
    init_bex
    pong BSTAT_S46
    #start handover
    addaddr $OUR_PRIMARY_ADDR_V6 $OUR_MASK_V6
    deladdr $OUR_PRIMARY_ADDR_V4 $OUR_PRIMARY_MASK_V4
    addroute
    #stop handover
    pong STAT_S46
    reset_interface
}

# Hard IPv4 to IPv6
#
# This test starts with IPv4 address that is removed and after a while
# we add IPv6 address to the interface.
function hard4to6 {
    printf "Running test hard4to6...\n"
    reset_interface
    reset_hipd
    locators
    init_maps 4
    init_bex
    pong BSTAT_H46
    #start handover
    deladdr $OUR_PRIMARY_ADDR_V4 $OUR_PRIMARY_MASK_V4
    addaddr $OUR_PRIMARY_ADDR_V6 $OUR_MASK_V6
    addroute
    #stop handover
    pong STAT_H46
    reset_interface
}

#TESTS STARTING FROM IPv6

# Hard IPv6 to IPv6
#
# We start with IPv6 address that is removed and after a while another
# IPv6 address is added to the interface.
function hard6to6 {
    printf "Running test hard6to6...\n"
    reset_interface
    deladdr $OUR_PRIMARY_ADDR_V4 $OUR_PRIMARY_MASK_V4 
    addaddr $OUR_PRIMARY_ADDR_V6 $OUR_MASK_V6
    #addroute
    reset_hipd
    sleep 15
    init_maps 6
    init_bex
    pong BSTAT_H66
    #start handover
    deladdr $OUR_PRIMARY_ADDR_V6 $OUR_MASK_V6
    addaddr $OUR_SECONDARY_ADDR_V6 $OUR_MASK_V6
    addroute
    #stop handover
    pong STAT_H66
    reset_interface
}

# Soft IPv6 to IPv6
#
# In this test we start from IPv6 address and add another IPv6 address to
# the same interface and after a while we remove the original/first IPv6 
# address.
function soft6to6 {
    printf "Running test soft6to6...\n"
    reset_interface
    deladdr $OUR_PRIMARY_ADDR_V4 $OUR_PRIMARY_MASK_V4
    addaddr $OUR_PRIMARY_ADDR_V6 $OUR_MASK_V6
    addroute
    reset_hipd
    sleep 15
    init_maps 6
    init_bex
    pong BSTAT_S66
    #start handover
    addaddr $OUR_SECONDARY_ADDR_V6 $OUR_MASK_V6
    deladdr $OUR_PRIMARY_ADDR_V6 $OUR_MASK_V6
    addroute
    #stop handover
    pong STAT_S66
    reset_interface
}

# Soft IPv6 to IPv4
#
# This test starts from IPv6 address. IPv4 address is added to the same
# interface and then the IPv6 address is removed.
function soft6to4 {
    printf "Running test soft6to4...\n"
    reset_interface
    deladdr $OUR_PRIMARY_ADDR_V4 $OUR_PRIMARY_MASK_V4
    addaddr $OUR_PRIMARY_ADDR_V6 $OUR_MASK_V6
    addroute
    reset_hipd
    locators
    init_maps 6
    init_bex
    pong BSTAT_S64
    #start handover
    addaddr $OUR_PRIMARY_ADDR_V4 $OUR_PRIMARY_MASK_V4
    deladdr $OUR_PRIMARY_ADDR_V6 $OUR_MASK_V6
    addroute
    #stop handover
    pong STAT_S64
    reset_interface
}

# Hard IPv6 to IPv4
#
# We start with IPv6 address that is removed and an IPv4 address is 
# added to the interface.
function hard6to4 {
    printf "Running test hard6to4...\n"
    reset_interface
    deladdr $OUR_PRIMARY_ADDR_V4 $OUR_PRIMARY_MASK_V4
    addaddr $OUR_PRIMARY_ADDR_V6 $OUR_MASK_V6
    addroute
    reset_hipd
    locators
    init_maps 6
    init_bex
    pong BSTAT_H64
    #start handover
    deladdr $OUR_PRIMARY_ADDR_V6 $OUR_MASK_V6
    addaddr $OUR_PRIMARY_ADDR_V4 $OUR_PRIMARY_MASK_V4
    addroute
    #stop handover
    pong STAT_H64
    reset_interface
}

#END TEST FUNCTIONS

##########################################################################

#MAIN

if [ $# -ne 1 ] ; then 
    usage
    exit 0
fi
check_root

args=`getopt abc:d $*`
set $args

for i
do
  case $i in 
      "all")    alltests   ;;
      "all4")   all4tests  ;;
      "all6")   all6tests  ;;
      "inner")  innertests ;;
      "inter")  intertests ;;
      "h44")    hard4to4   ;;
      "h66")    hard6to6   ;;
      "s44")    soft4to4   ;;
      "s66")    soft6to6   ;;
      "h46")    hard4to6   ;;
      "h64")    hard6to4   ;;
      "s46")    soft4to6   ;;
      "s64")    soft6to4   ;;
      *) echo "ERROR unknown test type"; usage ; exit 0;;
  esac
  kill_hipd
  print_statistics $i
done

#END MAIN

##########################################################################
