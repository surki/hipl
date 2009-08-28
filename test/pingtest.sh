#!/bin/sh

PATH="$PATH:$PWD../tools:$PWD:$PWD/tools"
IFACE=dummy0
PREFIX="inet6 2001:1"
SRC_HITS=`ip addr show $IFACE|grep "$PREFIX"|cut -d" " -f6|cut -d"/" -f1|tr '\n' ' '`
DST_IP=$1; shift
DST_HITS=$@
ROUND=1

echo "Usage: $0 <DST_IP> <DST_HIT1> [DST_HIT2] [..DST_HIT_N]"
echo ""
echo "src HITs: $SRC_HITS"
echo ""
echo "dst HITs: $DST_HITS"
echo ""
echo "dst IP: $DST_IP"
echo ""

hipconf rst all
sleep 3

for DST_HIT in $DST_HITS
  do
  hipconf add map $DST_HIT $DST_IP
  sleep 5
  for SRC_HIT in $SRC_HITS
    do
    echo "--- Round $ROUND ---"
    ping6 -c 1 -I $SRC_HIT $DST_HIT
    ping6 -c 4 -I $SRC_HIT $DST_HIT
    ROUND=`echo $ROUND + 1|bc`
  done
done
