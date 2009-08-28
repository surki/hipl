#!/bin/sh

TMPDIR=/tmp/subst-gpl
FROM='http:\/\/www\.gnu\.org\/licenses\/gpl\.txt'
TO='http:\/\/www\.gnu\.org\/licenses\/gpl2\.txt'
DIR=..
TMPFILE=temp

rm -rf $TMPDIR

set -e

mkdir $TMPDIR

for FILE in `find $DIR -name '*\.[c|h]'` 
do
  sed "s/$FROM/$TO/i" $FILE >$TMPDIR/$TMPFILE
  cp $TMPDIR/$TMPFILE $FILE
done
