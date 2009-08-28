#! /usr/bin/env python

import sys
import getopt
import os
import myasn
import binascii
import re
import sha
import struct

def usage(utyp, *msg):
    sys.stderr.write('Usage: %s\n' % os.path.split(sys.argv[0])[1])
    if msg:
        sys.stderr.write('Error: %s\n' % `msg`)
    sys.exit(1)

def i2b(i,minbytes=0):
    '''Convert integer to big-endian binary format, optionally padding
    up to minbytes length'''
    s = '%x' % (i,)
    if len(s) % 2:
        s = '0%s' % (s,)
    b = binascii.a2b_hex(s)
    if len(b) < minbytes:
        b = ('\x00' * (minbytes-len(b))) + b
    return b

def fillto(b,l):
    '''Pad big-endian binary to l bytes'''
    if len(b) < l:
        b = ('\x00' * (l-len(b))) + b
    return b
    
def rvs2b(rvslist):
    '''Convert hostname list to DNS encoded binary format.'''
    a = []
    for dn in rvslist:
        aa = [i.lower() for i in dn.split('.') if i]
        aa = ['%c%s' % (len(i),i) for i in aa]
        aa.append('\x00')
        a.append(''.join(aa))
    return ''.join(a)

def levelstr(n):
    return '>'*(n+1)

class Global:
    re_start = re.compile(r'^-+BEGIN.*$')
    re_end = re.compile(r'^-+END.*$')
    def __init__(gp):
        gp.v = 0
        return

    def write_rsa_data(gp,fout,rsa_n,rsa_e,hostname,rvslist):
        rsa_e_bytes = i2b(rsa_e)
        rsa_n_bytes = i2b(rsa_n)

        rsa_e_len = len(rsa_e_bytes)

        rsa_e_len_bytes = i2b(rsa_e_len)
        if rsa_e_len > 255:
            rsa_e_len_bytes = ('\x00\x00\x00%s' % (rsa_e_len_bytes,))[-3:]

        rsa_data = '%s%s%s' % (rsa_e_len_bytes,rsa_e_bytes,rsa_n_bytes)

        rsa_data_b64 = binascii.b2a_base64(rsa_data).strip()
        sys.stdout.write('  %s\n' % (binascii.b2a_hex(rsa_data),))
        sys.stdout.write('  %s\n' % (rsa_data_b64,))
        
        # The following is based on RFC4843
        # Begin bit twiddling magic
        o1 = binascii.a2b_hex('F0EFF02FBFF43D0FE7930C3C6E6174EA')
        o2 = rsa_data
        sh1 = sha.new(o1)
        sh1.update(o2)

        d1 = sh1.hexdigest()
        i1 = int(d1,16)

        middle_100 = (i1 >> 30) & 0xfffffffffffffffffffffffff

        hit = (0x20010010 << 96) | middle_100

        hit_h = '%032x' % (hit,)
        # End bit twiddling magic

        if rvslist:
            fout.write('HIPBIND %s IN HIP ( 2 %s %s %s )\n' % (hostname,hit_h,rsa_data_b64,' '.join(rvslist)))
        else:
            fout.write('HIPBIND %s IN HIP ( 2 %s %s )\n' % (hostname,hit_h,rsa_data_b64))

        aa = []
        aa.append(struct.pack('>BBH',16,2,len(rsa_data)))
        aa.append(binascii.a2b_hex(hit_h))
        aa.append(rsa_data)
        if rvslist:
            aa.append(rvs2b(rvslist))
        aa = ''.join(aa)
        aa3 = ''.join(['\\%03o' % (ord(x),) for x in aa])

        fout.write('DJBDNS :%s:55:%s\n' % (hostname,aa3,))
        fout.write('9BIND %s IN TYPE55 \\# %d ( %s )\n' % (hostname,len(aa),binascii.b2a_hex(aa)))
        
    def write_dsa_data(gp,fout,dsa_q,dsa_p,dsa_g,dsa_y,hostname,rvslist):
        dsa_q_bytes = i2b(dsa_q,20)
        dsa_p_bytes = i2b(dsa_p)
        dsa_g_bytes = i2b(dsa_g)
        dsa_y_bytes = i2b(dsa_y)

        l = len(dsa_p_bytes)
        if len(dsa_g_bytes) > l:
            l = len(dsa_g_bytes)
        if len(dsa_y_bytes) > l:
            l = len(dsa_y_bytes)
        l2 = ((l+7)/8)*8
        dsa_p_bytes = fillto(dsa_p_bytes,l2)
        dsa_g_bytes = fillto(dsa_g_bytes,l2)
        dsa_y_bytes = fillto(dsa_y_bytes,l2)

        t = (l2-64)/8
        t_bytes = i2b(t,1)

        dsa_data = '%s%s%s%s%s' % (t_bytes,dsa_q_bytes,dsa_p_bytes,dsa_g_bytes,dsa_y_bytes)

        dsa_data_b64 = binascii.b2a_base64(dsa_data).strip()
        
        # The following is based on RFC4843
        o1 = binascii.a2b_hex('F0EFF02FBFF43D0FE7930C3C6E6174EA')
        o2 = dsa_data
        sh1 = sha.new(o1)
        sh1.update(o2)

        d1 = sh1.hexdigest()
        i1 = int(d1,16)

        middle_100 = (i1 >> 30) & 0xfffffffffffffffffffffffff

        hit = (0x20010010 << 96) | middle_100

        hit_h = '%032x' % (hit,)
        # End bit twiddling magic

        if rvslist:
            fout.write('HIPBIND %s IN HIP ( 1 %s %s %s )\n' % (hostname,hit_h,dsa_data_b64,' '.join(rvslist)))
        else:
            fout.write('HIPBIND %s IN HIP ( 1 %s %s )\n' % (hostname,hit_h,dsa_data_b64))

        aa = []
        aa.append(struct.pack('>BBH',16,1,len(dsa_data)))
        aa.append(binascii.a2b_hex(hit_h))
        aa.append(dsa_data)
        if rvslist:
            aa.append(rvs2b(rvslist))
        aa = ''.join(aa)
        aa3 = ''.join(['\\%03o' % (ord(x),) for x in aa])

        fout.write('DJBDNS :%s:55:%s\n' % (hostname,aa3,))
        fout.write('9BIND %s IN TYPE55 \\# %d ( %s )\n' % (hostname,len(aa),binascii.b2a_hex(aa)))
        
    def parse2(gp,fout,level,as1,hostname,rvslist=()):
        a = []
        x = as1.decode_next()


        id = x[0][0].getvalue()

        if id[1] == '1.2.840.113549.1.1.1': # RSA key
            as2 = myasn.ASN(x[1].getvalue())
            x2 = as2.decode_next()
            rsa_n = x2[0].getvalue()
            rsa_e = x2[1].getvalue()
            fout.write('RSA_N 0x%x\n' % (rsa_n,))
            fout.write('RSA_E 0x%x\n' % (rsa_e,))
            gp.write_rsa_data(sys.stdout,rsa_n,rsa_e,hostname,rvslist)
            
        elif id[1] == '1.2.840.10040.4.1': # DSA key
            dsa_p = x[0][1][0].getvalue()
            dsa_q = x[0][1][1].getvalue()
            dsa_g = x[0][1][2].getvalue()
            as2 = myasn.ASN(x[1].getvalue())
            x2 = as2.decode_next()
            dsa_y = x2.getvalue()
            fout.write('DSA_P 0x%x\n' % (dsa_p,))
            fout.write('DSA_Q 0x%x\n' % (dsa_q,))
            fout.write('DSA_G 0x%x\n' % (dsa_g,))
            fout.write('DSA_Y 0x%x\n' % (dsa_y,))
            gp.write_dsa_data(sys.stdout,dsa_q,dsa_p,dsa_g,dsa_y,hostname,rvslist)
        else:
            pass
        return a
        
    def read_base64_file(gp,f):
        a = []
        st = 0
        while 1:
            l = f.readline()
            if not l:
                break
            if st == 0:
                if gp.re_start.match(l):
                    st = 1
            elif st == 1:
                if gp.re_end.match(l):
                    st = 2
                    break
                else:
                    a.append(l.strip())
        d0 = binascii.a2b_base64(''.join(a))
        if 0: file('kk0.bin','wb').write(d0)
        return d0

    def doit(gp,args):
        d0 = gp.read_base64_file(sys.stdin)
        fout = sys.stdout
        sys.stdout.write('%s\n' % (binascii.b2a_hex(d0),))

        as1 = myasn.ASN(d0)
        hostname = args.pop(0)
        gp.parse2(sys.stdout,0,as1,hostname,args)
        
        return

def main(argv):
    gp = Global()
    try:
        opts, args = getopt.getopt(argv[1:],
                                   'hvc:',
                                   ['help',
                                    'verbose',
                                    'count=',
                                    ])
    except getopt.error, msg:
        usage(1, msg)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage(0)
        elif opt in ('-v', '--verbose'):
            gp.v = gp.v + 1
        elif opt in ('-c', '--count'):
            gp.fetchcount = int(arg)

    gp.doit(args)
        
if __name__ == '__main__':
    main(sys.argv)
