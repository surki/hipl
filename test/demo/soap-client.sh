#!/bin/sh

HIPL_DIR=/home/mkomu/projects/hipl--main--2.6
FC_DIR=/home/mkomu/projects/fuegocore--demo--2.0/code/sh/message

if [ "$1" == "" ]
then
     echo "$0 port"
     exit
fi

umount /etc/hip
rmmod hipmod
sleep 1

ip link set eth0 up
sleep 1

ip addr add 3ffe::10/64 dev eth0
sleep 1

set -e

modprobe hipmod
sleep 1

read -p "*** Insert USB stick and press enter ***"
mount -t vfat /dev/sda1 /etc/hip
sleep 1

echo "Starting SOAP client"

cd $FC_DIR
./hip-demo-client oops $1
umount /etc/hip

