#! /bin/sh
rm -rf djbdns-1.05
tar -xzf djbdns-1.05.tar.gz
patch -N -p0 < Diff.patch
(
cd djbdns-1.05
make
)
