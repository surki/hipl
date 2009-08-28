#!/bin/sh

getsize() {
    du $1|perl -n -e '/^(\S+)\s+/; print $1'
}

# draw figures of daemon op measurement times

mkdir fig 2>/dev/null

set -e

seq 10 30|while read op 
  do
    
    grep type=$op initiator_times.txt | \
      cut -d" " -f10 >fig/gnuplotdata-initiator
    grep type=$op responder_times.txt | \
      cut -d" " -f10 >fig/gnuplotdata-responder

   # empty files, skip
   if test `getsize fig/gnuplotdata-initiator` -eq 0 -a \
      `getsize fig/gnuplotdata-responder` -eq 0
   then
     continue
   fi

   PLOT_INIT="'fig/gnuplotdata-initiator' title 'initiator' with \
             linespoints"
   PLOT_RESP="'fig/gnuplotdata-responder' title 'responder' with \
              linespoints"

   if test `getsize fig/gnuplotdata-initiator` -eq 0
   then
	PLOT_INIT=""
   fi

   if test `getsize fig/gnuplotdata-responder|cut -f1 -d" "` -eq 0
   then
	PLOT_RESP=""
   fi

   if test -z "$PLOT_INIT" -a -n "$PLOT_RESP"
   then
        PLOT_ARGS="$PLOT_RESP"
   elif test -n "$PLOT_INIT" -a -z "$PLOT_RESP"
   then
        PLOT_ARGS="$PLOT_INIT"
   else
        PLOT_ARGS="$PLOT_INIT, $PLOT_RESP"
   fi

cat <<EOF>fig/gnuplotcode
set terminal fig color
set ylabel 'time in seconds'
set xlabel 'test number'
set output 'fig/tc9-op$op.fig'
plot $PLOT_ARGS
EOF
    gnuplot fig/gnuplotcode

done
