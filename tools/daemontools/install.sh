#! /bin/sh

cd admin/daemontools-0.76/ || {
 echo cannot cd; exit 1
}

./package/compile

sudo ./package/install
