#!/bin/sh

export PATH=$PATH:..

mkdir logs

for ALGO in dsa rsa
do
  for BITS in `seq 256 256 4096`
  do
    LOGFILE="logs/keygentest-${ALGO}-${BITS}"
    rm -f $LOGFILE
    echo "--- algo=${ALGO} bits=${BITS} --"
    for REPEAT in `seq 1 30`
    do
      keygentest $ALGO $BITS 2>&1|grep "created"|tee -a $LOGFILE
    done
  done
done
