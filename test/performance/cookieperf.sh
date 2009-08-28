#!/bin/sh

export PATH=$PATH:..

mkdir logs

for K in `seq 1 30`
do
  LOGFILE="logs/cookieperf-${K}"
  rm -f $LOGFILE
  echo "--- cookie k=${K} --"
  for REPEAT in `seq 1 30`
    do
    cookietest $K 2>&1|grep "puzzle solved"|tee -a $LOGFILE
  done
done