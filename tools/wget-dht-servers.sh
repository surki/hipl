#!/bin/sh

wget -q -O - http://opendht.org/servers.txt | grep -v UTC | awk -F '[\t\:]' '{print $3, "\t", $5}'

