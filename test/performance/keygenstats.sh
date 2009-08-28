#!/bin/sh

export PATH=$PATH:.

LOG=logs/keygentest-final-${ALGO}

for ALGO in dsa rsa
do
  rm -f $LOG
  echo "--- $ALGO ---"
  for BITS in `seq 256 256 4096`
  do
    echo -n "$BITS" >> logs/keygentest-final-${ALGO}
    stats.pl 95 type '.*(\S+) key created in (\S+) secs' <logs/keygentest-${ALGO}-${BITS} | tail -1 | tee -a $LOG
  done
done

