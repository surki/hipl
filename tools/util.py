#! /usr/bin/env python

import sys
import getopt
import os
import re
import time
import string
import signal
import struct
import traceback

pjoin = os.path.join

__wantdown = None
__wantalarm = None

dev_null = file('/dev/null','w')

class Random:
    rfile = file('/dev/urandom','rb')
    def __init__(self):
        return
    def random(self,range=None):
        d = self.rfile.read(4)
        rval = struct.unpack('I',d)[0]
        return float(rval) / (1l << 32)

rand = Random().random

def tstamp(when=None):
    if when == None:
        when = time.time()
    t = map(int,('%.6f' % when).split('.'))
    t2 = time.localtime(t[0])
    return '%04d-%02d-%02d-%02d.%02d.%02d.%06d' % (t2[:6] + (t[1],))

def sighandler(signum, frame):
    global __wantdown
    global __wantalarm
    if signum == signal.SIGTERM:
        __wantdown = 1
    if signum == signal.SIGINT:
        __wantdown = 1
    if signum == signal.SIGALRM:
        __wantalarm = 1

def init_wantdown():
    signal.signal(signal.SIGTERM, sighandler)

def init_wantdown_int():
    signal.signal(signal.SIGINT, sighandler)

def init_wantalarm():
    signal.signal(signal.SIGALRM, sighandler)

def wantdown():
    global __wantdown
    r = __wantdown
    __wantdown = None
    return r

def wantalarm():
    global __wantalarm
    r = __wantalarm
    __wantalarm = None
    return r

class Global:
    pass

def usage(utyp, *msg):
    sys.stderr.write('Usage: ????\n')
    if msg:
        sys.stderr.write('Error: %s\n' % `msg`)
    sys.exit(1)

tmult = (
    (re.compile('^(?P<tval>-?\d+(\.\d*))(s|)$',re.I), float, 1),
    (re.compile('^(?P<tval>-?\d+)(s|)$',re.I), int, 1),
    (re.compile('^(?P<tval>-?\d+(\.\d*))m$',re.I), float, 60),
    (re.compile('^(?P<tval>-?\d+)m$',re.I), int, 60),
    (re.compile('^(?P<tval>-?\d+(\.\d*))h$',re.I), float, 60*60),
    (re.compile('^(?P<tval>-?\d+)h$',re.I), int, 60*60),
    (re.compile('^(?P<tval>-?\d+(\.\d*))d$',re.I), float, 60*60*24),
    (re.compile('^(?P<tval>-?\d+)d$',re.I), int, 60*60*24),
    )

class TimeSpecError(Exception):
    pass

def timespec(s,default=None):
    for tre,fun,tmul in tmult:
        r1 = tre.match(s)
        if r1:
            return fun(r1.group('tval')) * tmul
    if not default:
        raise TimeSpecError('Invalid timespec: %s' % s)

def verbosetime(x):
    if x < 1.0:
        return '%.3fs' % x
    if x < 60:
        return '%ds' % x
    x = int(x)
    if x < 60*60:
        m,s = divmod(x,60)
        return '%dm%02ds' % (m,s)
    if x < 24*60*60:
        h,s = divmod(x,60*60)
        m,s = divmod(s,60)
        return '%dh%02dm%02ds' % (h,m,s)
    d,s = divmod(x,24*60*60)
    h,s = divmod(s,60*60)
    m,s = divmod(s,60)
    return '%dd%02dh%02dm%02ds' % (d,h,m,s)

def catchall(fout,fun,args=(),kwargs={}):
    try:
        r = apply(fun,args,kwargs)
        ok = 1
    except Exception,e:
        einfo = sys.exc_info()
        fout.write('Error: %s\n%s\n' % (e,einfo))
        traceback.print_tb(einfo[2],None,fout)
        r = None
        fout.flush()
        ok = 0
    return (ok,r)

re_xml_test1 = re.compile(r'((?P<a1>>)(?P<b1>.))|((?P<a2>.)(?P<b2><))')
def rf1_test(r):
    d = r.groupdict('')
    return '%s%s\n%s%s' % (d.get('a1',''),d.get('a2',''),d.get('b1',''),d.get('b2',''))

def main(argv):

    gp = Global()

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   'hf:c:',['help',
                                            'todir=',
                                            'older=',
                                            'move',
                                            ])
    except getopt.error, msg:
        usage(1, msg)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage(0)

    fmtd = {int:   '%10d       ',
            long:  '%10d       ',
            float: '%17.6f',}

    for a in args:
        ts = timespec(a)
        sys.stdout.write('%-20s : %s seconds\n' % (a,fmtd[type(ts)] % ts))

    init_wantdown()
    init_wantalarm()

    while 1:
        time.sleep(10)
        if wantdown():
            sys.stdout.write('Wantdown\n')
        if wantalarm():
            sys.stdout.write('Wantalarm\n')
        
if __name__ == '__main__':
    main(sys.argv)
