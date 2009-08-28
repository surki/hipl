#!/bin/sh

FC_DIR=/home/mkomu/projects/fuegocore--demo--2.0/code/sh/message
HIPL_DIR=/home/mkousa/hipl

rmmod hipmod
sleep 1

ifconfig eth0 up
sleep 1
pump -i eth0
sleep 1
ifconfig eth1 up
sleep 1

ip addr add 3ffe::32/64 dev eth0
ip addr add 3ffe::33/64 dev eth1
sleep 1

ifconfig eth1 down
sleep 1

modprobe hipmod
sleep 1

$HIPL_DIR/tools/hipconf add hi default
sleep 1

$HIPL_DIR/tools/hipconf rvs 7e69:d6c6:5725:3e4c:9728:0966:403e:6114 
3ffe::36
sleep 1
echo foo | nc6 --idle-timeout 5 -w 5 
7e69:d6c6:5725:3e4c:9728:0966:403e:6114 12345

cat /proc/net/hip/sdb_state

echo "Starting SOAP server"

cd $FC_DIR
./hip-demo-server
