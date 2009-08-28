#!/bin/sh
# useful for debugging: -xv

HIPL_DIR=~/dev/hipl--esp--2.6
BASE_DIR=~/dev/measurements
DEVICE_TYPE=endhost-256_3072

# needed by the script - don't change these variables
EXT_BASE_DIR=$BASE_DIR/auth_performance
TEST_DIR=$HIPL_DIR/test
OUTPUT_DIR=$EXT_BASE_DIR/output

if [ ! -e $BASE_DIR ]
then
  mkdir $BASE_DIR
fi

if [ ! -e $EXT_BASE_DIR ]
then
  mkdir $EXT_BASE_DIR
fi

if [ ! -e $OUTPUT_DIR ]
then
  mkdir $OUTPUT_DIR
fi


$TEST_DIR/auth_performance | tee $OUTPUT_DIR/$DEVICE_TYPE
