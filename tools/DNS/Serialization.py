#! /usr/bin/env python

import sys
import getopt
import os
import binascii
import socket

import struct

from Lib import Mpacker
from Lib import Munpacker
from Lib import DnsResult

def usage(utyp, *msg):
    sys.stderr.write('Usage: %s\n' % os.path.split(sys.argv[0])[1])
    if msg:
        sys.stderr.write('Error: %s\n' % `msg`)
    sys.exit(1)

randfd = file('/dev/urandom','rb')

class Serialize:

    fld_lists = ('additional', 'nslist', 'answers', 'questions')
    fld_zero = ('aa', 'qr', 'tc', 'rd', 'opcode', 'ra', 'z', 'rcode')

    @classmethod
    def rand16(klass):
        r = randfd.read(2)
        return struct.unpack('!H',r)[0]
    def __init__(self,d):
        self.d = d
        self.normalize()
        return

    def normalize(self):
        d = self.d
        for k in self.fld_lists:
            if not d.has_key(k):
                d[k] = []
        for k in self.fld_zero:
            if not d.has_key(k):
                d[k] = 0
        if not d.has_key('id'):
            d['id'] = self.rand16()
        d['qdcount'] = len(d['questions'])
        d['ancount'] = len(d['answers'])
        d['nscount'] = len(d['nslist'])
        d['arcount'] = len(d['additional'])
        return

    def put_A(self,p,rr):
        p.addRRheader(rr[0],rr[1],rr[2],rr[3])
        p.addaddr(rr[4])
        p.endRR()
        return

    def put_NS(self,p,rr):
        p.addRRheader(rr[0],rr[1],rr[2],rr[3])
        p.addname(rr[4])
        p.endRR()
        return

    def put_CNAME(self,p,rr):
        p.addRRheader(rr[0],rr[1],rr[2],rr[3])
        p.addname(rr[4])
        p.endRR()
        return

    def put_SOA(self,p,rr):
        p.addRRheader(rr[0],rr[1],rr[2],rr[3])
        p.addname(rr[4])
        p.addname(rr[5])
        p.add32bit(rr[6])
        p.add32bit(rr[7])
        p.add32bit(rr[8])
        p.add32bit(rr[9])
        p.add32bit(rr[10])
        p.endRR()
        return

    def put_WKS(self,p,rr):
        p.addRRheader(rr[0],rr[1],rr[2],rr[3])
        p.addaddr(rr[4])
        p.addbyte(chr(rr[5]))
        p.addbytes(rr[6])
        p.endRR()
        return

    def put_PTR(self,p,rr):
        p.addRRheader(rr[0],rr[1],rr[2],rr[3])
        p.addname(rr[4])
        p.endRR()
        return

    def put_HINFO(self,p,rr):
        p.addRRheader(rr[0],rr[1],rr[2],rr[3])
        p.addstring(rr[4])
        p.addstring(rr[5])
        p.endRR()
        return

    def put_MX(self,p,rr):
        p.addRRheader(rr[0],rr[1],rr[2],rr[3])
        p.add16bit(rr[4])
        p.addname(rr[5])
        p.endRR()
        return

    def put_TXT(self,p,rr):
        p.addRRheader(rr[0],rr[1],rr[2],rr[3])
        lst = rr[4:]
        for l in lst:
            p.addstring(l)
        p.endRR()
        return

    def put_AAAA(self,p,rr):
        p.addRRheader(rr[0],rr[1],rr[2],rr[3])
        p.addbytes(socket.inet_pton(socket.AF_INET6,rr[4]))
        p.endRR()
        return

    def put_generic(self,p,rr):
        p.addRRheader(rr[0],rr[1],rr[2],rr[3])
        p.addbytes(rr[4])
        p.endRR()
        return

    def put_HI(self,p,rr):
        p.addRRheader(rr[0],rr[1],rr[2],rr[3])
        p.addbyte(rr[4])
        p.addbyte(rr[5])
        p.add16bit(rr[6])
        p.addbytes(rr[7])
        p.addbytes(rr[8])
        p.addbytes(rr[9])
        p.endRR()
        return

    RR_dispatch = {
        1: put_A,
        2: put_NS,
        5: put_CNAME,
        6: put_SOA,
        11: put_WKS,
        12: put_PTR,
        13: put_HINFO,
        15: put_MX,
        16: put_TXT,
        28: put_AAAA,
        55: put_HI,
        }

    def put_RR(self,p,rr):
        qtype = rr[1]
        put_fun = self.RR_dispatch.get(qtype)
        if put_fun:
            put_fun(self,p,rr)
        else:
            self.put_generic(p,rr)
        return

    def get_packet(self):
        d = self.d
        p1 = Mpacker()

        a = []
        for fld in ('id','qr','opcode','aa','tc','rd','ra','z','rcode',
                    'qdcount','ancount','nscount','arcount',):
            a.append(d[fld])
        apply(p1.addHeader,a)
        for q in d['questions']:
            p1.addname(q[0])
            p1.add16bit(q[1])
            p1.add16bit(q[2])
        for rr in d['answers']:
            self.put_RR(p1,rr)
        for rr in d['nslist']:
            self.put_RR(p1,rr)
        for rr in d['additional']:
            self.put_RR(p1,rr)

        return p1.getbuf()

class DeSerialize:
    def __init__(self,data):
        self.data = data
        return

    def get_dict(self):
        u = Munpacker(self.data)
        
        hdr0 = list(u.getHeader())
        # id, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount = u.getHeader()

        hdr = {}

        hdr['id'] = hdr0.pop(0)
        hdr['qr'] = hdr0.pop(0)
        hdr['opcode'] = hdr0.pop(0)
        hdr['aa'] = hdr0.pop(0)
        hdr['tc'] = hdr0.pop(0)
        hdr['rd'] = hdr0.pop(0)
        hdr['ra'] = hdr0.pop(0)
        hdr['z'] = hdr0.pop(0)
        hdr['rcode'] = hdr0.pop(0)
        hdr['qdcount'] = hdr0.pop(0)
        hdr['ancount'] = hdr0.pop(0)
        hdr['nscount'] = hdr0.pop(0)
        hdr['arcount'] = hdr0.pop(0)

        qd = []
        for i in xrange(hdr['qdcount']):
            qd.append(list(u.getQuestion()))

        hdr['questions'] = qd

        hdr['answers'] = self.get_rrlist(u,hdr['ancount'])
        hdr['nslist'] = self.get_rrlist(u,hdr['nscount'])
        hdr['additional'] = self.get_rrlist(u,hdr['arcount'])

        return hdr
    
    def pprint(self,fout):
        d = self.get_dict()
        for fld in ('id','qr','opcode','aa','tc','rd','ra','z','rcode',
                    'qdcount','ancount','nscount','arcount',):
            fout.write('%-8s %5d\n' % (fld,d[fld]))
        for fld in ('questions','answers','nslist','additional',):
            fout.write('%s\n' % (fld,))
            a0 = d[fld]
            for a in a0:
                fout.write(' %s\n' % (' '.join([str(i) for i in a]),))
        return

    def get_rrlist(self,u,n):
        a = []
        for i in xrange(n):
            a.append(self.get_rr(u))
        return a

    def get_A(self,u):
        r = u.getAdata()
        return (r,)

    def get_NS(self,u):
        r = u.getname()
        return (r,)

    def get_CNAME(self,u):
        r = u.getname()
        return (r,)

    def get_SOA(self,u):
        r = []
        r.append(u.getname())
        r.append(u.getname())
        r.append(u.get32bit())
        r.append(u.get32bit())
        r.append(u.get32bit())
        r.append(u.get32bit())
        r.append(u.get32bit())
        return tuple(r)

    def get_WKS(self,u):
        r = []
        r.append(u.getaddr())
        r.append(u.getbyte())
        r.append(u.getbytes(u.rdend - u.offset))
        return tuple(r)

    def get_PTR(self,u):
        r = u.getname()
        return (r,)

    def get_HINFO(self,u):
        r = []
        r.append(u.getstring())
        r.append(u.getstring())
        return tuple(r)

    def get_MX(self,u):
        r = []
        r.append(u.get16bit())
        r.append(u.getname())
        return tuple(r)

    def get_TXT(self,u):
        r = []
        while u.offset < u.rdend:
            r.append(u.getstring())
        return tuple(r)

    def get_AAAA(self,u):
        b = u.getbytes(16)
        r = socket.inet_ntop(socket.AF_INET6,b)
        return (r,)

    def get_HI(self,u):
        r = []
        r.append(u.getbyte())
        r.append(u.getbyte())
        r.append(u.get16bit())
        r.append(u.getbytes(ord(r[0])))
        r.append(u.getbytes(r[2]))
        r.append(u.getbytes(u.rdend - u.offset))
        return tuple(r)

    RR_dispatch = {
        1: get_A,
        2: get_NS,
        5: get_CNAME,
        6: get_SOA,
        11: get_WKS,
        12: get_PTR,
        13: get_HINFO,
        15: get_MX,
        16: get_TXT,
        28: get_AAAA,
        55: get_HI,
        }
    
    def get_rr(self,u):
        rrhdr = list(u.getRRheader())
        rdlength = rrhdr.pop()
        
        df = self.RR_dispatch.get(rrhdr[1])
        if df:
            a = df(self,u)
            rrhdr.extend(a)
        else:
            rrhdr.append(u.getbytes(rdlength))
        return rrhdr

class Global:
    def __init__(self):
        return
    def doit(self,args):
        return

def main(argv):
    self = Global()
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
            self.tarfilename = arg

    self.doit(args)
        
if __name__ == '__main__':
    main(sys.argv)
