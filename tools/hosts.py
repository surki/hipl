#! /usr/bin/env python

import sys
import getopt
import os
import pyip6
import binascii
import time

def usage(utyp, *msg):
    sys.stderr.write('Usage: %s\n' % os.path.split(sys.argv[0])[1])
    if msg:
        sys.stderr.write('Error: %s\n' % `msg`)
    sys.exit(1)

class Hosts:
    def __init__(self,filename,resolv_conf=None):
        self.hostsfile = filename
        self.modified = None
        self.rcmodified = None
        if not resolv_conf:
            resolv_conf = '/etc/resolv.conf'
        self.resolv_conf = resolv_conf
        self.a = {}
        self.aaaa = {}
        self.aaaa_hit = {}
        self.recheck()
        return

    def recheck(self):
        st0 = os.stat(self.resolv_conf)
        if (self.rcmodified == None or
            st0.st_mtime > self.rcmodified):
            self.rcreread()
            self.rcmodified = st0.st_mtime
            self.modified = None
        st1 = os.stat(self.hostsfile)
        if (self.modified == None or
            st1.st_mtime > self.modified):
            self.reread()
            self.modified = st1.st_mtime
        return

    def sani(self,n):
        n = n.lower()
        a = n.split('.')
        while a and a[-1] == '':
            a.pop()
        return '.'.join(a)

    def sani_aaaa(self,a):
        a = pyip6.inet_pton(a)
        a2 = list(binascii.b2a_hex(a))
        a2.reverse()
        a2.extend(['ip6','arpa'])
        #print a2
        return '.'.join(a2)

    def rcreread(self):
        self.suffixes = ()
        f = file(self.resolv_conf)
        d = {}
        while 1:
            l = f.readline()
            if not l:
                break
            l = l.strip()
            if not l or l.startswith('#'):
                continue
            aa = l.split()
            kw = aa.pop(0)

            if kw == 'search':
                self.suffixes = tuple([i.lower() for i in aa])
        return

    def str_is_ipv6(self, addr_str):
        if addr_str.find(':') == -1:
            return False
        else:
            return True

    def str_is_hit(self, addr_str):
        if addr_str.startswith('2001:001') or addr_str.startswith('2001:1'):
            return True
        else:
            return False

    def str_is_lsi(self, addr_str):
        if addr_str.startswith('1.'):
            return True
        else:
            return False

    def ptr4_str_to_addr_str(self, ptr_str):
        in4 = ''
        octet = ''
        for i in range(len(ptr_str)):
            if ptr_str[i] == '.':
                in4 = octet + '.' + in4
                octet = ''
            else:
                octet += ptr_str[i]
        in4 = octet + '.' + in4[0:len(in4)-1]
        return in4

    def ptr6_str_to_addr_str(self, ptr_str):
        in6 = ''
        for i in range(len(ptr_str)):
            if (((i + 1) % 8) == 0):
                in6 += ':'
            if ptr_str[i] != '.':
                in6 += ptr_str[i]
        return in6

    def addr6_str_to_ptr_str(self, addr):
        # Note: address string must be in the full notation
        ptr = ''
        addr = addr[::-1]
        for c in addr:
            if c != ':':
                ptr += c + '.'
        ptr += 'ip6.arpa'
        return ptr

    def ptr_str_to_addr_str(self, ptr_str):
        # IPv4:
        # - 102.2.168.192.in-addr.arpa
        # - 4.3.2.1.in-addr.arpa
        # IPv6:
        # - 9.0...f.3.ip6.arpa
        if not ptr_str:
            return None
        strlen = len(ptr_str)
        end = ptr_str.find('.i')
        if end == -1:
            return None
        ps = ptr_str[0:end]
        if ptr_str.find('.ip6') == -1:
            return self.ptr4_str_to_addr_str(ps)
        else:
            return self.ptr6_str_to_addr_str(ps[::-1])

    def reread(self):
        f = file(self.hostsfile)
        d = {}
        aaaa_hit = {}
        aaaa = {}
	a = {}
        while 1:
            l = f.readline()
            if not l:
                break
            l = l.strip()
            if not l or l.startswith('#'):
                continue
            aa = l.split()
            addr = aa.pop(0)
            for n in aa:
                n = self.sani(n)
                a2 = n.split('.')
                if len(a2) <= 1:
                    for s in self.suffixes:
                        d['%s.%s' % (n,s)] = addr
                d[n] = addr
                if self.str_is_hit(addr):
                    aaaa_hit[n] = (addr, 0)
                elif self.str_is_ipv6(addr):
                    aaaa[n] = (addr, 0)
                else:
                    a[n] = (addr, 0)
	self.a = a
        self.aaaa = aaaa
        self.aaaa_hit = aaaa_hit
        return

    def getaddr_from_list(self, addr_str, list):
        for name in list:
           if self.str_is_ipv6(list[name][0]):
               # remove trailing zeroes from IPv6 address
               a = pyip6.inet_pton(list[name][0])
               cmp_addr = pyip6.inet_ntop(a)
           else:
               cmp_addr = list[name][0]
           if self.sani(addr_str) == cmp_addr:
                return name
        return None

    def getaddr(self, addr):
        if addr is None:
            return None
        if self.str_is_ipv6(addr):
            # remove trailing zeroes from IPv6 address
            a = pyip6.inet_pton(addr)
            addr_str = pyip6.inet_ntop(a)
            if self.str_is_hit(addr):
                return self.getaddr_from_list(addr_str, self.aaaa_hit)
            else:
                return self.getaddr_from_list(addr_str, self.aaaa)
        else:
            return self.getaddr_from_list(addr, self.a)

    def geta(self,n):
        return self.getrecord(n, self.a)

    def getaaaa(self,n):
        return self.getrecord(n, self.aaaa)

    def getaaaa_hit(self,n):
        return self.getrecord(n, self.aaaa_hit)

    def getrecord(self, n, src):
        a = src.get(self.sani(n))
        if a is None:
           return None
        if a[1] == 0:
            ttl = 122
        else:
            ttl = a[1] - int(time.time())
            if ttl < 1:
                del src[self.sani(n)]
                return None
        return (a[0], ttl)

    # Overload hosts file as cache for hostname->HIT/LSI
    def cache_name(self, hostname, addr, ttl):
        valid_to = int(time.time()) + ttl
        if self.str_is_hit(addr):
            self.aaaa_hit[hostname] = (addr, valid_to)
        elif self.str_is_ipv6(addr):
            self.aaaa[hostname] = (addr, valid_to)
        else:
            self.a[hostname] = (addr, valid_to)

class Global:
    def __init__(gp):
        return
    def doit(gp,args):
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
