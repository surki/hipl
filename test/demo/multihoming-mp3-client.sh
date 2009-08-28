#!/bin/sh

# XX TODO: mpg123 BUFFER SIZE
# REMEMBER TO STOP VMWARE

HIPL_DIR=$1
PEER_HIT=776b:60eb:acf0:1ee2:93ee:23f5:8396:c9c9
PEER_IP=fe80::204:76ff:fe4c:53d7
PEER_PORT=12345

if [ "$HIPL_DIR" = "" ]
then
  echo "usage: $0 HIPL_DIR"
  exit 1
fi

killall hipd
sleep 2
rmmod hipmod
sleep 2

killall ifd
sleep 2

set -e

if mii-tool eth0 | grep "link ok"
then
 ifconfig eth0 up
 ifconfig eth1 down
else
 ifconfig eth1 up
 ifconfig eth0 down
fi

insmod hipmod
sleep 2

cd $HIPL_DIR
hipd/hipd &
sleep 2
hipd/hipconf add map $PEER_HIT $PEER_IP
sleep 2

#echo "Press enter to start client"
#read

#nc6 -n -vv $PEER_HIT $PEER_PORT | mpg123 -q -b 16 -

nc6 -n -vv $PEER_HIT $PEER_PORT | mplayer -nocache -

#nc6 --disable-nagle -n -vv $PEER_HIT $PEER_PORT | mplayer -nocache -
#$HIPL_DIR/test/demo/stdinclient $PEER_HIT tcp $PEER_PORT | mplayer -nocache -
