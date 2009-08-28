#!/bin/bash
# useful for debugging: -xv

BASE_DIR=~/dev/measurements
HIPL_DIR=~/dev/hipl--esp--2.6
#LEVEL_1_DIRS=no_mb router corp_fw pc_fw
#LEVEL_2_DIRS=rtt-no_load rtt-with_load tcp udp

# needed by the script - don't change these variables
STATS_DIR=$HIPL_DIR/test/performance
EXT_BASE_DIR=$BASE_DIR/networking
OUTPUT_DIR=output
STAGING_DIR=staging
RESULTS_DIR=results


if [ ! -e $BASE_DIR ]
then
  echo $BASE_DIR "not found"
  exit 1
fi

if [ ! -e $EXT_BASE_DIR ]
then
  echo $EXT_BASE_DIR "not found"
  exit 1
fi

for device in $EXT_BASE_DIR/*
do
  for run in $device/*
  do
    for type in $run/*
    do

      # check for raw data
      if [ -e $type/$OUTPUT_DIR ]
      then
      
        # create non-existing staging and results dirs
        if [ ! -e $type/$STAGING_DIR ]
        then
          mkdir $type/$STAGING_DIR
        fi

        if [ ! -e $type/$RESULTS_DIR ]
        then
          mkdir $type/$RESULTS_DIR
        fi

        # do post-processing
        for file in $type/$OUTPUT_DIR/*
        do
            
            file_name=`basename $file` 

            if [ $type == $run/rtt-no_load -o $type == $run/rtt-with_load ]
            then
              # RTT output post-processing
              #echo "rtt" $file_name
              grep 'from' $type/$OUTPUT_DIR/$file_name | tr '=' ' ' | awk '{printf("%.3f ms\n", $10)}' | tee $type/$STAGING_DIR/$file_name | $STATS_DIR/stats.pl 95 value '(\S+)\s+(ms)' | awk '{if ($1 == "ms") {printf("avg\tstd_dev\n"); printf("%.3f\t%.3f\n", $2, $3)}}' | tee $type/$RESULTS_DIR/$file_name
              # symlink newest results to plot_data dir
              #ln -sf $RESULTS_DIR/$FILE $PLOT_DATA_DIR/$FILE

            elif [ $type == $run/tcp ]
            then
              # TCP output post-processing
              #echo "tcp" $file_name
              grep 'sec' $type/$OUTPUT_DIR/$file_name | awk '{printf("%.3f Mbits/sec\n", $7)}' | tee $type/$STAGING_DIR/$file_name | $STATS_DIR/stats.pl 95 value '(\S+)\s+(Mbits/sec)' | awk '{if ($1 == "Mbits/sec") {printf("avg\tstd_dev\n"); printf("%.3f\t%.3f\n", $2, $3)}}' | tee $type/$RESULTS_DIR/$file_name
              # symlink newest results to plot_data dir
              #ln -sf $RESULTS_DIR/$FILE $PLOT_DATA_DIR/$FILE

            elif [ $type == $run/udp ]
            then
              # UDP output post-processing
              #echo "udp" $file_name
              grep '%' $type/$OUTPUT_DIR/$file_name | awk '{printf("%.3f Mbits/sec\n", $7)}' | tee $type/$STAGING_DIR/$file_name | $STATS_DIR/stats.pl 95 value '(\S+)\s+(Mbits/sec)' | awk '{if ($1 == "Mbits/sec") {printf("avg\tstd_dev\n"); printf("%.3f\t%.3f\n", $2, $3)}}' | tee $type/$RESULTS_DIR/$file_name
              # symlink newest results to plot_data dir
              #ln -sf $RESULTS_DIR/$FILE $PLOT_DATA_DIR/$FILE
            else
              echo "unknown" $file_name
              echo "ERROR: unknown measurement type!"
              exit 1
            fi

          done
        fi
    done
  done
done



#if [ $DO_PLOT -eq "1" ]
#then
#  read -p "Plot histograms: [ENTER]"
#  TMP_DIR=`pwd`
#  cd $BASE_DIR
#  gnuplot $STATS_DIR/plot-no_midfw
#  gnuplot $STATS_DIR/plot-with_pcfw
#  cd $TMP_DIR
#fi

