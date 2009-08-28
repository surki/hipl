#! /usr/bin/env python

import sys
import getopt
import os
import binascii

def usage(utyp, *msg):
    sys.stderr.write('Usage: %s\n' % os.path.split(sys.argv[0])[1])
    if msg:
        sys.stderr.write('Error: %s\n' % `msg`)
    sys.exit(1)

class Item:
    def __init__(self,type0,value0,extra=None):
        self._type = type0
        self._value = value0
        if extra:
            for k in extra:
                setattr(self,k,extra[k])
        return

    def add_extra(self,x):
        self.extra = x
        return

    def __str__(self):
        if self._type == 2:
            return 'Item(int,0x%x)' % (self._value,)
        elif self._type == 3:
            return 'Item(bitstring,len=%d)' % (len(self._value),)
        elif self._type == 4:
            return 'Item(octetstring,len=%d)' % (len(self._value),)
        elif self._type == 5:
            return 'Item(null)'
        if self._type == 6:
            return 'Item(objid,%s)' % (self._value,)
        if self._type == 16:
            return 'Item(sequence,len=%d)' % (len(self._value),)
        else:
            return 'Item(t=%d)' % (self._type,)

        return

    def __repr__(self):
        return self.__str__()

    def __getitem__(self,k):
        return self._value[k]

    def getvalue(self):
        return self._value

class ASN:
    def __init__(self,data):
        self.data = data
        self.p = 0
        return
    def get_byte(self):
        if self.p == len(self.data):
            return None
        x = self.data[self.p]
        self.p = self.p + 1
        return x
    def get_bytes(self,n):
        x = self.data[self.p:self.p+n]
        self.p = self.p + n
        return x
    def parse_oid(self,d0):
        a = []
        d = [ord(i) for i in list(d0)]
        x = d.pop(0)
        o1,o2 = divmod(x,40)
        a.append(o1)
        a.append(o2)
        while 1:
            if not d:
                break
            x = 0
            while 1:
                c = d.pop(0)
                x = x*128 + (c&0x7f)
                if not (c & 0x80):
                    break
            a.append(x)
        a = '.'.join(['%d' % i for i in a])
        return (binascii.b2a_hex(d0),a)
    def parse_sequence(self):
        a = []
        while 1:
            x = self.decode_next()
            if not x:
                break
            a.append(x)
        return a
    def decode_next(self):
        x1 = self.get_byte()
        if x1 == None:
            return None
        x1 = ord(x1)
        t = x1 & 0x3f
        assert t != 0x3f

        t2 = t & 0x1f
        c = (t & 0x20) != 0
        
        x2 = ord(self.get_byte())
        if x2 & 0x80:
            nx2 = x2 & 0x7f
            l = self.get_bytes(nx2)
            l = int(binascii.b2a_hex(l),16)
        else:
            l = x2 & 0x7f

        i0 = None

        d = self.get_bytes(l)
        if t2 == 2:                     # INTEGER
            d = int(binascii.b2a_hex(d),16)
            i0 = Item(t2,d)
        elif t2 == 3:                   # BIT STRING
            d = (d[1:],d[0])
            i0 = Item(t2,d[0],{'ignore_bits':ord(d[1]),})
        elif t2 == 4:                   # OCTET STRING
            i0 = Item(t2,d)
            pass
        elif t2 == 5:                   # NULL
            i0 = Item(t2,None)
            pass
        elif t2 == 6:                   # OBJECT INDENTIFIER
            d = self.parse_oid(d)
            i0 = Item(t2,d,{'raw':binascii.a2b_hex(d[0]),})
        elif t2 == 16:                  # SEQUENCE
            as2 = ASN(d)
            i2a = as2.parse_sequence()
            i0 = Item(t2,i2a,{'raw_value': d,})
            pass
        elif t2 == 17:                  # SET
            i0 = Item(t2,d)
            pass
        if not i0:
            i0 = Item(t2,None)
        i0.add_extra((t2,c,l,d))
        return i0

    def x_INTEGER(self,ed,val):
        if ed:
            return
        else:
            return

    if 0: tags = {
        2: x_INTEGER,
        3: x_BIT_STRING,
        4: x_OCTET_STRING,
        5: x_NULL,
        6: x_OBJECT_IDENTIFIER,
        16: x_SEQUENCE,
        17: x_SET,
        # 19: x_PrintableString,
        # 20: x_T61String,
        # 22: x_IA5String,
        # 23: x_UTCTime,
        }


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
