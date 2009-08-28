#!/bin/sh

rm -f ~/.hipagent/database
rm -f ~/.mozilla/firefox/*.default/history.dat
rm -f ~/.mozilla/firefox/*.default/cert8.db

sudo killall hipagent
sudo killall hipd
sudo killall firefox-bin
sleep 5

set -e

sudo cp resolv.conf /etc/resolv.conf

ping -c 2 webmail1
ping -c 2 webmail2
ping -c 2 webmail3
ping -c 2 webmail4

sudo hipd -b

sleep 5

hipagent &

sleep 3

hipconf run opp firefox&
