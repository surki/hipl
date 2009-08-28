#!/bin/sh

export PATH=$PATH:~mkomu/projects/hipl--spam--2.6/tools

PEER_NAME=panu
PEER_HIT=4014:ecbc:a9a:e3eb:32e7:51c1:c323:9ab5
PEER_IP=3ffe::3
SPAM_FILE=/usr/share/doc/spamassassin/examples/sample-spam.txt
SLEEP=70 # should be R1 regen period + 10

die() {
    echo $1
    exit 1
}

grep $PEER_HIT /etc/hosts || die "Peer HIT ($PEER_HIT) must be in /etc/hosts"


#for REPEAT in `seq 1 1`
#  do
#  echo "-- Round $REPEAT --"
#    mailx -s "Round $REPEAT started" root@${PEER_NAME} <<EOF
#Now.
#EOF
#  for K in `seq 10 28`
#    do
#    echo "-- Cookie should be now $K --"
#    Note: upon R1 recreation, the mapping persists (a bug)
    hipconf del map $PEER_HIT $PEER_IP
#    ip xfrm policy flush
    hipconf add map $PEER_HIT $PEER_IP
#    sleep 2
#    ping6 -c 1 ${PEER_HIT}
    mailx  -s "BUY VIAGRA" root@${PEER_NAME} < ${SPAM_FILE}
#    sleep $SLEEP
#  done
#  # XX TODO: PROMPT TO KILL THE RESPONDER HIPD
#done