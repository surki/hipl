#!/bin/sh

# REMEMBER TO STOP VMWARE

#HIPL_DIR=$1
PORT=12345
MP3="/home/mkousa/m/George Clinton & the Parliament Funkadelic (P-Funk All Stars) - Play That Funky Music White Boy.mp3"
AVI="/home/mkousa/julmahuvi3.avi"
PEER_IP0=fe80::204:76ff:fe4c:5176
PEER_IP1=fe80::200:86ff:fe57:7dd
PEER_MAC0=00:04:76:4c:51:76
PEER_MAC1=00:00:86:57:07:dd

if [ "$HIPL_DIR" = "" ]
then
#    echo "usage: $0 HIPL_DIR"
    echo "Environment variable HIPL_DIR is not set"
    exit 1
fi

#for dir in /proc/sys/net/ipv6/conf/*;do
# echo 0 > $dir/router_solicitation_delay
# echo 1 > $dir/router_solicitation_interval
# echo 1 > $dir/router_solicitations
#done

killall ifd
#sleep 2

#killall hipd
#sleep 2
rmmod hipmod
#sleep 2

#modprobe hipmod
$HIPL_DIR/tools/hipconf add hi default
set -e

#sleep 2

#cd $HIPL_DIR
#hipd/hipd&
#sleep 2

echo "Starting server"

#nc6 -n -vv -l -p $PORT --sndbuf-size=1000 < $MP3
nc6 -n -vv -l -p $PORT < $MP3
#$HIPL_DIR/test/demo/stdinserver tcp $PORT < $AVI 
#nc6 -n -vv -l -p $PORT < $AVI 
