#! /bin/sh

rm -rf admin
tar -xzf daemontools-0.76.tar.gz
patch -N -p0 -s < Diff.patch
(
cd admin/daemontools-0.76/
./package/compile
)
