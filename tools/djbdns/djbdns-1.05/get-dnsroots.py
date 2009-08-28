#! /usr/bin/env python

import sys
import getopt
import os
import urllib2
import re

def usage(utyp, *msg):
    sys.stderr.write('Usage: %s\n' % os.path.split(sys.argv[0])[1])
    if msg:
        sys.stderr.write('Error: %s\n' % `msg`)
    sys.exit(1)

class Global:
    re_a1 = re.compile(r'^[A-Z]\.ROOT-SERVERS\.NET\.\s+\d+\s+A\s+([0-9\.]+)\s*$',re.I)
    def __init__(gp):
        return
    def doit(gp,args):
	url1 = 'http://www.internic.net/zones/named.root'
	u1 = urllib2.urlopen(url1)
	a = u1.readlines()
	a = [gp.re_a1.match(i) for i in a]
	a = ['%s\n' % (r1.group(1),) for r1 in a if r1]
	sys.stdout.writelines(a)
        return

def main(argv):
    gp = Global()
    try:
        opts, args = getopt.getopt(argv[1:],
                                   'hf:c:',
                                   ['help',
                                    'file=',
                                    'count=',
                                    ])
    except getopt.error, msg:
        usage(1, msg)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage(0)
        elif opt in ('-f', '--file'):
            gp.tarfilename = arg
        elif opt in ('-c', '--count'):
            gp.fetchcount = int(arg)

    gp.doit(args)
        
if __name__ == '__main__':
    main(sys.argv)
