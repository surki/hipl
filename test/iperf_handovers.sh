#!/bin/bash

#################################################################################################
#
# Script that measures throughput over mobility events
# Author Samu Varjonen 09/2008
#
# READ AND UNDERSTAND THIS SCRIPT BEFORE USING IT
#
# See also handovers.sh for basic handover tests
#
# NOTE: No error checking !!!!!
#       Be sure hipd is running and that all the needed addresses are present
#       also remember to run iperf (-V) -s on the peer
#
# NOTE: Some additional sleeps added to tweak this script to work in my environment
#
#################################################################################################

## VARIABLES

# START configuration 
# Variables that have to be changed to fit network configuration

# start home network

PEER_HIT="2001:13:91ea:bcda:af5d:7ec1:27fb:a207"
PEER_ADDRV4="192.168.1.13"
PEER_ADDRV6="3::2"

OUR_ADDRV4="192.168.1.12"
OUR_SECONDARY_ADDRV4="192.168.1.24"
OUR_ADDRV6="3::1"
OUR_SECONDARY_ADDRV6="3::10"

# end home network
 
# start test network

#PEER_HIT="2001:11:8ed8:59b:95ff:c8b:8aba:9c24"
#PEER_ADDRV6="2001:708:140:220:215:60ff:fe9f:6048"
#PEER_ADDRV4="193.167.187.2"

#OUR_ADDRV6="2001:708:140:200:21c:25ff:fe12:c6e4"
#OUR_SECONDARY_ADDRV6="2001:708:140:200:21c:25ff:fe12:c6e5"
#OUR_ADDRV4="193.167.187.93"
#OUR_SECONDARY_ADDRV4="193.167.187.94"

# end test network

# masks 
OUR_MASK4="/24"
OUR_MASK4_SECONDARY="/32"
OUR_MASK6="/64"

# target device
DEV=eth0

# END configuration

# iperf options
IPERF_OPTIONS6="-f m -V -c"
IPERF_OPTIONS4="-f m -c"
IPERF_INTERVAL=30

# test options
TEST_COUNT=20
TMP_FILE="/tmp/iperf_tmp"

# count variables
total_throughput=0; total_throughputsec=0
total_throughput2=0; total_throughputsec2=0
mean=0; meansec=0
varians=0; varianssec=0

#tmp vars to count mean, varians
transorder=0
max=0
timing=0
tmp1=0; tmp2=0
ctmp1=0; ctmp2=0

pidofvarians=""

## UTILITY FUNCTIONS

function isnum {
    if [ $1 -eq $1 2> /dev/null ]; then
	return 0
    else
	return -1
    fi 
}

function init_maps {
    if [ $1 -eq 4 ] ; then
	#printf "Adding %s to %s mapping\n" $PEER_HIT $PEER_ADDRV4
	sudo hipconf add map $PEER_HIT $PEER_ADDRV4
    else
	#printf "Adding %s to %s mapping\n" $PEER_HIT $PEER_ADDRV6
	sudo hipconf add map $PEER_HIT $PEER_ADDRV6
    fi
}

function check_transform {
    transorder=9
    if [ "$1" = "aes" ] ; then
	transorder=123
    fi
    if [ "$1" = "3des" ] ; then 
	transorder=213
    fi
    if [ "$1" = "null" ] ; then 
	# no use just filling in the void
	transorder=0
    fi
    if [ $transorder == 9 ] ; then
	echo "Unknown transformation"
	exit 0
    fi
}

function usage {
    echo ""
    echo "Usage: "
    echo $0" si44 | si66 | sif46 | sif64 or "
    echo $0" hi44 | hi66 | hif46 | hif64 | hi64 | hi46 | b4 | b6 | hb4 | hb6 <interval> aes|3des(|null)"
    echo ""
    echo "si44 aes|des              = Soft innerfamily handover from IPv4 to IPv4"
    echo "si66 aes|des              = Soft innerfamily handover from IPv6 to IPv6"
    echo "hi44 <interval> aes|3des  = Hard innerfamily handover from IPv4 to IPv4"
    echo "hi66 <interval> aes|3des  = Hard innerfamily handover from IPv6 to IPv6"
    echo "sif46 aes|3des            = Soft interfamily handover from IPv4 to IPv6"
    echo "sif64 aes|3des            = Soft interfamily handover from IPv6 to IPv4"
    echo "hif46 <interval> aes|3des = Hard interfamily handover from IPV4 to IPv6"
    echo "hif64 <interval> aes|3des = Hard interfamily handover from IPV6 to IPv4"
    echo "b4 <interval> null        = IPv4 base line test"
    echo "b6 <interval> null        = IPv6 base line test"
    echo "hb4 <interval> aes|3des   = HIP IPv4 base line test"
    echo "hb6 <interval> aes|3des   = HIP IPv6 base line test"
    echo ""
    echo "Interval is a the time that this node is without address (in seconds)"
    echo "Interval is added also in the base tests to see the maximum throughput"
    echo "when transmitting the same time as other hard handovers have chance to send"
    echo "In base4 and base6 tests the transform is not used but must be present"
    echo ""
}

function add_current_v6 {
    sudo ip addr add $OUR_ADDRV6$OUR_MASK6 dev $DEV
    sleep $1
}

function del_current_v6 {
    sudo ip addr del $OUR_ADDRV6$OUR_MASK6 dev $DEV
    sleep $1
}

function add_secondary_v6 {
    sudo ip addr add $OUR_SECONDARY_ADDRV6$OUR_MASK6 dev $DEV
    sleep $1
}

function del_secondary_v6 {
    sudo ip addr del $OUR_SECONDARY_ADDRV6$OUR_MASK6 dev $DEV
    sleep $1
}
 
function add_current_v4 {
    sudo ip addr add $OUR_ADDRV4$OUR_MASK4 dev $DEV
    sleep $1
}

function del_current_v4 {
    sudo ip addr del $OUR_ADDRV4$OUR_MASK4 dev $DEV
    sleep $1
}

function add_secondary_v4 {
    sudo ip addr add $OUR_SECONDARY_ADDRV4$OUR_MASK4_SECONDARY dev $DEV
    sleep $1
}

function del_secondary_v4 {
    sudo ip addr del $OUR_SECONDARY_ADDRV4$OUR_MASK4_SECONDARY dev $DEV
    sleep $1
}

function reset_networking {
    sudo ifconfig $DEV down
    sleep 5
    sudo ifconfig $DEV up
    sleep 20
}

function droute {
    sudo route add default dev $DEV
}

function reset_hip {
    sleep 45
    sudo hipconf rst all
    sleep 10
    if [ $transorder -eq 0 ] ; then
	echo "Skipped transformation order setting"
    else
	printf "Setting transorder to %s\n" $transorder
	sudo hipconf transform order $transorder
    fi
    sleep 15
}

function pround {
    printf "Round %d interval %d ::::::::::::::::::::::::::::::::::::::::::::::::\n" $1 $2
}

function add_results {
    #echo "Waiting for the Iperf to finish"
    pidofiperf=$(pidof iperf)
    while [ "$pidofiperf" != "" ]
    do
	pidofiperf=$(pidof iperf)
    done

    ## strip the results from the file    

    # get the throughput Mbytes/GBytes 
    # With 10/100 switches Mbytes With 10/100/1000 switches GBytes
    ctmp1=`grep 'MBytes' $TMP_FILE | awk '$6 == "MBytes" {print $5} $7 == "MBytes" {print $6}'`
    # get the throughput per sec
    ctmp2=`grep 'MBytes' $TMP_FILE | awk '$8 == "Mbits/sec" {print $7} $9 == "Mbits/sec" {print $8}'`
    echo $ctmp1 $ctmp2 $timing

    total_throughput=$(echo "scale=5; ($total_throughput+$ctmp1)" | bc -l)
    total_throughputsec=$(echo "scale=5; ($total_throughputsec+$ctmp2)" | bc -l)
    total_throughput2=$(echo "scale=5; ($total_throughput2 + ($ctmp1 * $ctmp1))" | bc -l)
    total_throughputsec2=$(echo "scale=5; ($total_throughputsec2 + ($ctmp2 * $ctmp2))" | bc -l)
}

function calculate_results {
    printf "\n"
    # count the results	
    tmp1=$total_throughput
    tmp2=$total_throughput2
    mean=$(echo "scale=5; ($tmp1 / $TEST_COUNT)" | bc -l)
    varians=$(echo "scale=5; (($tmp2 - ($tmp1 * $mean)) / ($TEST_COUNT - 1))" | bc -l)
    varians=$(echo "scale=5; sqrt($varians)" | bc -l)
    
    ## Print the result for MBytes
    echo Mean $mean MBytes Variance $varians MBytes Interval $timing
    total_throughput=0
    total_throughput2=0
    
    tmp1=$total_throughputsec
    tmp2=$total_throughputsec2
    meansec=$(echo "scale=5; ($tmp1 / $TEST_COUNT)" | bc -l)
    varianssec=$(echo "scale=5; (($tmp2 - ($tmp1 * $meansec)) / ($TEST_COUNT - 1))" | bc -l)
    varianssec=$(echo "scale=5; sqrt($varianssec)" | bc -l)
	
    ## Print the result for MBits/sec
    echo Mean $meansec MBits/sec Variance $varianssec MBits/sec Interval $timing
    total_throughputsec=0
    total_throughputsec2=0
}

## TEST FUNCTIONS

function si44 {
    echo "Testing 4to4 soft innerfamily handovers" $TEST_COUNT \
	 "tests max gap is" $max "and test duration" $IPERF_INTERVAL \
	 "Transform order" $transorder
    timing=$IPERF_INTERVAL
    let max=$max+1
    for (( j=1 ; j<=max ; j++ ))
    do
	for ((  i=1 ;  i<=$TEST_COUNT ;  i++  ))
	do 
	    pround $i $j
	    reset_networking
	    reset_hip
	    init_maps 4
	    iperf $IPERF_OPTIONS6 $PEER_HIT -t $timing > $TMP_FILE &
	    sleep 5
	    add_secondary_v4 $j
	    del_current_v4 0
	    droute
	    add_results $j
	done
	calculate_results
	printf "\n"
    done 
    reset_networking
    exit 0
}

function si66 {
    echo "Testing 6to6 soft innerfamily handovers" $TEST_COUNT \
	 "tests max gap is" $max "and test duration" $IPERF_INTERVAL \
	 "Transform order" $transorder
    timing=$IPERF_INTERVAL
    let max=$max+1
    for (( j=1 ; j<=max ; j++ ))
    do
	for ((  i=1 ;  i<=$TEST_COUNT ;  i++  ))
	do 
	    pround $i $j
	    reset_networking
	    add_current_v6 0
	    del_current_v4 0	    
	    droute       
	    sleep 60 # tweaked to higher sleep
	    reset_hip
	    sleep 5
	    init_maps 6
	    sleep 5
	    iperf $IPERF_OPTIONS6 $PEER_HIT -t $timing > $TMP_FILE &
	    sleep 5
	    add_secondary_v6 $j
	    del_current_v6 0
	    droute
	    add_results $j
	done
	calculate_results
	printf "\n"
    done 
    reset_networking
    exit 0
}

function hi44 {
    echo "Testing 4to4 hard innerfamily handovers" $TEST_COUNT \
	 "tests max gap is" $max "and test duration" $IPERF_INTERVAL \
	 "Transform order" $transorder
    timing=$IPERF_INTERVAL
    let max=$max+1
    for (( j=1 ; j<=max ; j++ ))
    do
	for ((  i=1 ;  i<=$TEST_COUNT ;  i++  ))
	do 
	    pround $i $j
	    reset_networking
	    reset_hip
	    init_maps 4
	    iperf $IPERF_OPTIONS6 $PEER_HIT -t $timing > $TMP_FILE &
	    sleep 5
	    del_current_v4 $j
	    add_secondary_v4 0
	    droute
	    add_results $j
	done
	calculate_results
	printf "\n"
    done
    reset_networking
    exit 0
}

function hi66 { 
    echo "Testing 6to6 hard innerfamily handovers" $TEST_COUNT \
	 "tests max gap is" $max "and test duration" $IPERF_INTERVAL \
	 "Transform order" $transorder
    timing=$IPERF_INTERVAL
    let max=$max+1
    for (( j=1 ; j<=max ; j++ ))
    do
	for ((  i=1 ;  i<=$TEST_COUNT ;  i++  ))
	do 
	    pround $i $j
	    reset_networking
	    add_current_v6 0
	    del_current_v4 0
	    droute
	    sleep 30
	    reset_hip
	    init_maps 6
	    iperf $IPERF_OPTIONS6 $PEER_HIT -t $timing > $TMP_FILE &
	    sleep 5
	    del_current_v6 $j
	    add_secondary_v6 0
	    droute
 	    add_results $j
	done
	calculate_results
	printf "\n"
    done
    reset_networking
    exit 0
}

function sif46 {
    echo "Testing 4to6 soft interfamily handovers" $TEST_COUNT \
	 "tests max gap is" $max "and test duration" $IPERF_INTERVAL \
	 "Transform order" $transorder
    timing=$IPERF_INTERVAL
    let max=$max+1
    for (( j=1 ; j<=max ; j++ ))
    do
	for ((  i=1 ;  i<=$TEST_COUNT ;  i++  ))
	do 
	    pround $i $j
	    reset_networking
	    reset_hip
	    sleep 10
	    sudo hipconf locator on
	    sleep 15
	    init_maps 4
	    sleep 35
	    iperf $IPERF_OPTIONS6 $PEER_HIT -t $timing > $TMP_FILE &
	    sleep 5
	    add_current_v6 $j
	    del_current_v4 0
	    droute
	    add_results $j
	done
	calculate_results
	printf "\n"
    done
    reset_networking
    exit 0
}

function sif64 {
    echo "Testing 6to4 soft interfamily handovers" $TEST_COUNT \
	 "tests max gap is" $max "and test duration" $IPERF_INTERVAL \
	 "Transform order" $transorder
    timing=$IPERF_INTERVAL
    let max=$max+1
    for (( j=1 ; j<=max ; j++ ))
    do
	for ((  i=1 ;  i<=$TEST_COUNT ;  i++  ))
	do 
	    pround $i $j
	    reset_networking
	    add_current_v6 0
	    del_current_v4 0
	    droute
	    sleep 30
	    reset_hip
	    sleep 10
	    sudo hipconf locator on
	    sleep 5
	    init_maps 6
	    sleep 35
	    iperf $IPERF_OPTIONS6 $PEER_HIT -t $timing > $TMP_FILE &
	    sleep 5
	    add_current_v4 $j
	    del_current_v6 0
	    droute
	    add_results $j
	done
	calculate_results
	printf "\n"
    done
    reset_networking
    exit 0
}
 
function hif46 { 
    echo "Testing 4to6 hard interfamily handovers" $TEST_COUNT \
	 "tests max gap is" $max "and test duration" $IPERF_INTERVAL \
	 "Transform order" $transorder
    timing=$IPERF_INTERVAL
    let max=$max+1
    for (( j=1 ; j<=max ; j++ ))
    do
	for ((  i=1 ;  i<=$TEST_COUNT ;  i++  ))
	do 
	    pround $i $j
	    reset_networking
	    reset_hip
	    sudo hipconf locator on
	    sleep 5
	    init_maps 4
	    iperf $IPERF_OPTIONS6 $PEER_HIT -t $timing > $TMP_FILE &
	    sleep 5
	    del_current_v4 $j
	    add_current_v6 0
	    droute
	    add_results $j
	done
	calculate_results
	printf "\n"
    done
    reset_networking
    exit 0
}

function hif64 {
    echo "Testing 6to4 hard interfamily handovers" $TEST_COUNT \
	 "tests max gap is" $max "and test duration" $IPERF_INTERVAL \
	 "Transform order" $transorder
    timing=$IPERF_INTERVAL
    let max=$max+1
    for (( j=1 ; j<=max ; j++ ))
    do
	for ((  i=1 ;  i<=$TEST_COUNT ;  i++  ))
	do 
	    pround $i $j
	    reset_networking
	    add_current_v6 0
	    del_current_v4 0
	    droute
	    sleep 50
	    reset_hip
	    sudo hipconf locator on
	    sleep 5
	    init_maps 6
	    iperf $IPERF_OPTIONS6 $PEER_HIT -t $timing > $TMP_FILE &
	    sleep 5
	    del_current_v6 $j
	    add_current_v4 0
	    droute
	    add_results $j
	done
	calculate_results
	printf "\n"
    done
    reset_networking
    exit 0
}

function base4 {
    echo "Testing v4 base line without handovers" $TEST_COUNT \
	 "tests max gap is" $max "and test duration" $IPERF_INTERVAL \
	 "Transform order" $transorder
    reset_networking
    timing=$IPERF_INTERVAL
    let max=$max+1
    for (( j=1 ; j<=max ; j++ ))
    do
	for ((  i=1 ;  i<=$TEST_COUNT ;  i++  ))
	do 
	    pround $i $j
	    iperf $IPERF_OPTIONS4 $PEER_ADDRV4 -t $timing > $TMP_FILE &
	    echo moi
	    sleep 1
	    add_results $j
	done
	calculate_results
	let timing=$IPERF_INTERVAL-$j
    done
    exit 0
}

function base6 {
    echo "Testing v6 base line without handovers" $TEST_COUNT \
	 "tests max gap is" $max "and test duration" $IPERF_INTERVAL \
	 "Transform order" $transorder
    reset_networking
    add_current_v6 20
    timing=$IPERF_INTERVAL
    let max=$max+1
    for (( j=1 ; j<=max ; j++ ))
    do
	for ((  i=1 ;  i<=$TEST_COUNT ;  i++  ))
	do 
	    pround $i $j
	    iperf $IPERF_OPTIONS6 $PEER_ADDRV6 -t $timing > $TMP_FILE &
	    sleep 1
	    add_results $j
	done
	calculate_results
	let timing=$IPERF_INTERVAL-$j
    done
    reset_networking
    exit 0
}

function hbase4 {
    echo "Testing HIP v4 base line without handovers" $TEST_COUNT \
	 "tests max gap is" $max "and test duration" $IPERF_INTERVAL \
	 "Transform order" $transorder
    reset_networking
    timing=$IPERF_INTERVAL
    let max=$max+1
    for (( j=1 ; j<=max ; j++ ))
    do
	for ((  i=1 ;  i<=$TEST_COUNT ;  i++  ))
	do 
	    pround $i $j
	    reset_hip
	    init_maps 4
	    iperf $IPERF_OPTIONS6 $PEER_HIT -t $timing > $TMP_FILE &
	    sleep 1
	    add_results $j
	done
	calculate_results
	printf "\n"
	let timing=$IPERF_INTERVAL-$j
    done
    reset_networking
    exit 0
}

function hbase6 {
    echo "Testing HIP v6 base line without handovers" $TEST_COUNT \
	 "tests max gap is" $max "and test duration" $IPERF_INTERVAL \
	 "Transform order" $transorder
    reset_networking
    add_current_v6 20
    timing=$IPERF_INTERVAL
    let max=$max+1
    for (( j=1 ; j<=max ; j++ ))
    do
	for ((  i=1 ;  i<=$TEST_COUNT ;  i++  ))
	do 
	    pround $i $j
	    reset_hip
	    init_maps 6    
	    iperf $IPERF_OPTIONS6 $PEER_HIT -t $timing > $TMP_FILE &
	    sleep 1
	    add_results $j
	done
	calculate_results
	printf "\n"
	let timing=$IPERF_INTERVAL-$j
    done
    reset_networking
    exit 0
}
## MAIN

if [ $# -eq 2 ] ; then
    check_transform $2
    case $1 in
	"si44")  si44  ;;
	"si66")  si66  ;;
	"sif46") sif46 ;;
	"sif64") sif64 ;;
	*) echo "ERROR: Unknown test type"  
	    exit 0 ;;
    esac
elif [ $# -eq 3 ] ; then
    check_transform $3
    max=$2
    isnum $2
    returnval=$?
    if [ $returnval -eq 0 ] ; then
        case $1 in
	    "hi44")  hi44     ;;
	    "hi66")  hi66     ;;
	    "hif46") hif46    ;;
	    "hif64") hif64    ;;
	    "hb4") hbase4 ;;
	    "hb6") hbase6 ;;
	    "b4")  base4  ;;
	    "b6")  base6  ;;
	    *) echo "ERROR: Unknown test type"  
		exit 0 ;;
	esac 
    else
	usage
	exit 0
    fi
else
    usage
    exit 0
fi


