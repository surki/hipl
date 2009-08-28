#!/bin/sh -xv

ifconfig eth0 down
read -p "Change interface and press enter"
ifconfig eth1 up
ip addr add 3ffe::47/64 dev eth1
