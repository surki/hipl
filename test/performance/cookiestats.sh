#!/bin/sh

export PATH=$PATH:.

LOG=logs/cookieperf-final

rm -f $LOG

for K in `seq 1 30`
do
  echo -n "$K" >>$LOG
  stats.pl 95 type '.*(puzzle)\s+solved\s+in\s+(\S+)\s*' <logs/cookieperf-${K} | tail -1 | tee -a $LOG
done
