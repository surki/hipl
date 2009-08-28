#!/bin/bash
# useful for debugging: -xv

DST_IPv4=192.168.1.201
DST_IPv6=0
DST_HIT=0
ROUTE_TOv4=192.168.1.202
ROUTE_TOv6=0

MEASUREMENT_COUNT=20
HIPFW_OPTS=

BASE_DIR=~/dev/measurements
HIPL_DIR=~/dev/hipl--esp--2.6

# needed by the script - don't change these variables
HIPD_DIR=$HIPL_DIR/hipd
HIPFW_DIR=$HIPL_DIR/firewall
EXT_BASE_DIR=$BASE_DIR/networking
OUTPUT_DIR=output

DEVICE_TYPE=0
ADDR_FAMILY=0
RUN_HIPD=0
RUN_HIPFW=0
RUN_USERIPSEC=0
RUN_ESPEXT=0
WITH_MID=0
WITH_HIPFW=0
WITH_WANEM=0
WANEM_TYPE=0
MEASURE_RTT=0
MEASURE_TPUT=0
BANDWIDTH=100M
PACKET_LENGTH=1370
VERIFY_PATH=0
TCP_LENGTH=

FILE=

# get the command line options
if [ $# -eq 0 ]
then
  echo "Usage: `basename $0` options: -a <family> -t <type> [-deirvw] [-m|c|M <value>] [-p <type> [-b <value>]]"
  echo
  echo "  -a <family>  = address family (4 - IPv4, 6 - IPv6)"
  echo "  -t <type>    = device type (1 - client, 2 - middlebox, 3 - server)"
  echo "  -d           = start hipd (only client/server)"
  echo "  -i           = start hipfw with userspace ipsec (no conntrack)"
  echo "  -e           = start hipfw with ESP extension (no conntrack)"
  echo "  -r <value>   = measure RTT (1 - plain, 2 - with load)"
  echo "  -p <value>   = measure throughput (1 - TCP, 2 - UDP)"
  echo "  -b <value>   = bandwith to be used for UDP measurements (include K or M)"
  echo "  -l <value>   = maximum packet length"
  echo "  -m <value>   = tests are run with a router (0 - hipfw off, 1 - hipfw on)"
  echo "  -c <value>   = tests are run with a corporate FW (0 - hipfw off, 1 - hipfw on)"
  echo "  -M <value>   = tests are run with middlebox-PC (0 - hipfw off, 1 - hipfw on)"
  echo "  -w <value>   = tests are run with WANem on the route (0 - off, 1 - passive, 2 - reorder, 3 - drop)"
  echo "  -v           = verify path"
  echo
  exit 0
fi

while getopts "a:b:c:deit:l:m:M:p:r:vw:" CMD_OPT
do
  case $CMD_OPT in
    a) ADDR_FAMILY=$OPTARG;;
    b) BANDWIDTH=$OPTARG;;
    c) WITH_MID=2
       WITH_HIPFW=$OPTARG;;
    d) RUN_HIPD=1;;
    e) RUN_HIPD=1
       RUN_HIPFW=1
       RUN_USERIPSEC=1
       RUN_ESPEXT=1;;
    i) RUN_HIPD=1
       RUN_HIPFW=1
       RUN_USERIPSEC=1;;
    t) DEVICE_TYPE=$OPTARG;;
    l) PACKET_LENGTH=$OPTARG;;
    m) WITH_MID=1
       WITH_HIPFW=$OPTARG;;
    M) WITH_MID=3
       WITH_HIPFW=$OPTARG;;
    p) MEASURE_TPUT=$OPTARG;;
    r) MEASURE_RTT=$OPTARG;;
    v) VERIFY_PATH=1;;
    w) WITH_WANEM=1
       WANEM_TYPE=$OPTARG;;
    *) echo "Unknown option specified."
       exit 1;;
  esac
done
shift $((OPTIND - 1))

if [ $PACKET_LENGTH -ne "1370" ]
then
  TCP_LENGTH="-M "$PACKET_LENGTH
fi


# create the directories for client, if they don't exist yet
if [ $DEVICE_TYPE -eq "1" ]
then

  if [ ! -e $BASE_DIR ]
  then
    mkdir $BASE_DIR
  fi

  if [ ! -e $EXT_BASE_DIR ]
  then
    mkdir $EXT_BASE_DIR
  fi

  if [ $WITH_MID -eq "1" ]
  then
    EXT_BASE_DIR=$EXT_BASE_DIR/router
  elif [ $WITH_MID -eq "2" ]
  then
    EXT_BASE_DIR=$EXT_BASE_DIR/corp_fw
  elif [ $WITH_MID -eq "3" ]
  then
    EXT_BASE_DIR=$EXT_BASE_DIR/pc_fw
  else
    EXT_BASE_DIR=$EXT_BASE_DIR/no_mb
  fi

  if [ ! -e $EXT_BASE_DIR ]
  then
    mkdir $EXT_BASE_DIR
  fi

  if [ $MEASURE_RTT -eq "1" ] 
  then
    EXT_BASE_DIR=$EXT_BASE_DIR/rtt-no_load
  fi
  
  if [ $MEASURE_RTT -eq "2" ] 
  then
    EXT_BASE_DIR=$EXT_BASE_DIR/rtt-with_load
  fi

  if [ $MEASURE_TPUT -eq "1" ] 
  then
    EXT_BASE_DIR=$EXT_BASE_DIR/tcp
  fi

  if [ $MEASURE_TPUT -eq "2" ] 
  then
    EXT_BASE_DIR=$EXT_BASE_DIR/udp
  fi

  if [ ! -e $EXT_BASE_DIR ]
  then
    mkdir $EXT_BASE_DIR
  fi

  OUTPUT_DIR=$EXT_BASE_DIR/$OUTPUT_DIR
  
  if [ $MEASURE_RTT -ne "0" -o $MEASURE_TPUT -ne "0" ]
  then
    if [ ! -e  $OUTPUT_DIR ]
    then
      mkdir $OUTPUT_DIR
    fi
  fi
fi

# set the output file name for the client
if [ $DEVICE_TYPE -eq "1" ]
then

  if [ $RUN_HIPD -eq "1" ]
  then
    if [ $RUN_USERIPSEC -eq "1" ]
    then
      if [ $RUN_ESPEXT -eq "1" ]
      then
        FILE=$FILE"esp_ext-"
      else
        FILE=$FILE"useripsec-"
      fi
    else
      FILE=$FILE"kernelipsec-"
    fi
  else
    FILE=$FILE"plain-"
  fi

  if [ $WITH_HIPFW -eq "1" ]
  then
    FILE=$FILE"actice_mb-"
  else
    FILE=$FILE"passive_mb-"
  fi

  if [ $WITH_WANEM -eq "0" ]
  then
    FILE=$FILE"no_wanem"
  elif [ $WITH_REORDER -eq "1" ]
  then
    FILE=$FILE"passive_wanem"
  elif [ $WITH_REORDER -eq "2" ]
  then
    FILE=$FILE"wanem_reorder"
  else
    FILE=$FILE"wanem-drop"
  fi
fi

# set hipfw parameters
if [ $RUN_USERIPSEC -eq "1" ]
then
  if [ $DEVICE_TYPE -eq "1" -o $DEVICE_TYPE -eq "3" ]
  then
    HIPFW_OPTS=Fi
  else
    echo "WARNING: Trying to set userspace IPsec a middlebox or unspecified device."
  fi
fi

if [ $RUN_ESPEXT -eq "1" ]
then
  if [ $DEVICE_TYPE -eq "1" -o $DEVICE_TYPE -eq "3" ]
  then
    HIPFW_OPTS=Fe
  elif [ $DEVICE_TYPE -eq "2" ]
  then
    HIPFW_OPTS=
  else 
    echo "ERROR: Unknown device type."
    exit 1
  fi
fi


# TODO check mandatory options


# disable redirection announcement and accept on all devices
if [ -e /proc/sys/net/ipv4/conf/all/accept_redirects ]
then
  for f in /proc/sys/net/ipv4/conf/*/accept_redirects
  do
    echo "0" > $f
  done
else
  echo "ERROR: proc-file not found."
  exit 1
fi

if [ -e /proc/sys/net/ipv4/conf/all/secure_redirects ]
then
  for f in /proc/sys/net/ipv4/conf/*/secure_redirects
  do
    echo "0" > $f
  done
else
  echo "ERROR: proc-file not found."
  exit 1
fi

if [ -e /proc/sys/net/ipv4/conf/all/send_redirects ]
then
  for f in /proc/sys/net/ipv4/conf/*/send_redirects
  do
    echo "0" > $f
  done
else
  echo "ERROR: proc-file not found."
  exit 1
fi

# TODO do the same for IPv6
echo "0" > /proc/sys/net/ipv6/conf/all/accept_redirects


# configure forwarding on middleboxes only
if [ $DEVICE_TYPE -eq "2" ]
then
  # enable forwarding
  echo "1" >/proc/sys/net/ipv4/conf/all/forwarding
  echo "1" >/proc/sys/net/ipv6/conf/all/forwarding
fi

# set up routes on all devices where the next hop is specified
if [ "$ROUTE_TOv4" != "0" -o "$ROUTE_TOv6" != "0" ]
then
  if [ $ADDR_FAMILY -eq "4" ]
  then
    route add -host $DST_IPv4 netmask 0.0.0.0 gw $ROUTE_TOv4
  elif [ $ADDR_FAMILY -eq "6" ]
  then
    echo "TODO route6 add"
    exit 1
  else
    echo "ERROR: Unknown address family or none specified."
    exit 1
  fi
fi


# start HIPL apps
if [ $RUN_HIPD -eq "1" -o $RUN_HIPFW -eq "1" ]
then

  read -p "Start HIPL apps: [ENTER]"

  if [ $RUN_HIPD -eq "1" ]
  then
    if [ $DEVICE_TYPE -eq "1" -o $DEVICE_TYPE -eq "3" ]
    then
      $HIPD_DIR/hipd -kb
      ps -A | grep hipd
    else
      echo "WARNING: hipd specified on middlebox - currently not supported."
    fi
  fi

  if [ $RUN_HIPFW -eq "1" ]
  then
    if [ $RUN_HIPD -eq "1" ]
    then
      echo "Waiting a bit for hipd to start up..."
      sleep 2
    fi
    $HIPFW_DIR/hipfw -kb$HIPFW_OPTS
    ps -A | grep hipfw
  fi
fi


# only check correctness of the routes on the end-hosts
if [ $VERIFY_PATH -eq "1" ]
then
  if [ $DEVICE_TYPE -eq "1" -o $DEVICE_TYPE -eq "3" ]
  then 

    read -p "Verify path: [ENTER]"

    if [ $RUN_HIPD -eq "1" ]
    then
      traceroute6 $DST_HIT
    elif [ $ADDR_FAMILY -eq "4" ]
    then
      traceroute $DST_IPv4
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      traceroute6 $DST_IPv6
    else
      echo "ERROR: Neither HIT nor correct address family specified."
      exit 1
    fi
  else
    echo "WARNING: Trying to use path verification on a middlebox or unspecified device."
  fi
fi


# measure RTTs only on the client
if [ $MEASURE_RTT -ne "0" -a $DEVICE_TYPE -eq "1" ]
then
  read -p "Measure RTT: [ENTER]"

  if [ $RUN_HIPD -eq "1" ]
  then
    ping6 -c $MEASUREMENT_COUNT $DST_HIT | tee $OUTPUT_DIR/$FILE
  elif [ $ADDR_FAMILY -eq "4" ]
  then
    ping -c $MEASUREMENT_COUNT $DST_IPv4 | tee $OUTPUT_DIR/$FILE
  elif [ $ADDR_FAMILY -eq "6" ]
  then
    ping6 -c $MEASUREMENT_COUNT $DST_IPv6 | tee $OUTPUT_DIR/$FILE
  else
    echo "ERROR: Neither HIT nor correct address family specified."
    exit 1
  fi
fi


# measure TCP throughput
if [ $MEASURE_TPUT -eq "1" -o $MEASURE_TPUT -eq "3" ]
then
  read -p "Measure TCP throughput (start server first!): [ENTER]"

  # client side
  if [ $DEVICE_TYPE -eq "1" ]
  then

    # remove old measurement
    if [ -e $OUTPUT_DIR/$FILE ]
    then
      rm $OUTPUT_DIR/$FILE
    fi
    
    i=0

    if [ $RUN_HIPD -eq "1" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf -V --client $DST_HIT $TCP_LENGTH | tee --append $OUTPUT_DIR/$FILE
        i=`expr $i + 1`
        # for some reason iperf needs this to reset the timer
        # for throughput calc
        sleep 2
      done
    elif [ $ADDR_FAMILY -eq "4" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf --client $DST_IPv4 $TCP_LENGTH | tee --append $OUTPUT_DIR/$FILE
        i=`expr $i + 1`
        sleep 2
      done
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf -V --client $DST_IPv6 $TCP_LENGTH | tee --append $OUTPUT_DIR/$FILE
        i=`expr $i + 1`
        sleep 2
      done
    else
      echo "ERROR: Neither HIT nor correct address family specified."
      exit 1
    fi

  # server side
  elif [ $DEVICE_TYPE -eq "3" ]
  then
    if [ $RUN_HIPD -eq "1" ]
    then
      iperf -V --server $TCP_LENGTH
    elif [ $ADDR_FAMILY -eq "4" ]
    then
      iperf --server $TCP_LENGTH
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      iperf -V --server $TCP_LENGTH
    else
      echo "ERROR: Neither HIT nor correct address family specified."
      exit 1
    fi
  else
    echo "WARNING: Trying to run throughput measurements on a middlebox or unspecified device."
  fi
fi


#measure UDP throughput
if [ $MEASURE_TPUT -eq "2" -o $MEASURE_TPUT -eq "3" ]
then
  read -p "Measure UDP throughput (start server first!): [ENTER]"

  # client side
  if [ $DEVICE_TYPE -eq "1" ]
  then
    
    # remove old measurement
    if [ -e $OUTPUT_DIR/$FILE ]
    then
      rm $OUTPUT_DIR/$FILE
    fi

    i=0

    if [ $RUN_HIPD -eq "1" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf -V --client $DST_HIT --udp --len $PACKET_LENGTH --bandwidth $BANDWIDTH | tee --append $OUTPUT_DIR/$FILE
        i=`expr $i + 1`
        sleep 2
      done 
    elif [ $ADDR_FAMILY -eq "4" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf --client $DST_IPv4 --udp --len $PACKET_LENGTH --bandwidth $BANDWIDTH | tee --append $OUTPUT_DIR/$FILE
        i=`expr $i + 1`
        sleep 2
      done
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      while [ $i -lt $MEASUREMENT_COUNT ]
      do
        iperf -V --client $DST_IPv6 --udp --len $PACKET_LENGTH --bandwidth $BANDWIDTH | tee --append $OUTPUT_DIR/$FILE
        i=`expr $i + 1`
        sleep 2
      done
    else
      echo "ERROR: Neither HIT nor correct address family specified."
      exit 1
    fi

  # server side
  elif [ $DEVICE_TYPE -eq "3" ]
  then
    if [ $RUN_HIPD -eq "1" ]
    then
      iperf -V --server --udp --len $PACKET_LENGTH
    elif [ $ADDR_FAMILY -eq "4" ]
    then
      iperf --server --udp --len $PACKET_LENGTH
    elif [ $ADDR_FAMILY -eq "6" ]
    then
      iperf -V --server --udp --len $PACKET_LENGTH
    else
      echo "ERROR: Neither HIT nor correct address family specified."
      exit 1
    fi
  fi
fi


if [ $RUN_HIPD -eq "1" -o $RUN_HIPFW -eq "1" ]
then
  read -p "Clean up: [ENTER]"

  if [ $RUN_HIPFW -eq "1" ]
  then
    killall hipfw
  fi

  if [ $RUN_HIPD -eq "1" ]
  then
    killall hipd
  fi
fi

exit 0

