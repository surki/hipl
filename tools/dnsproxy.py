#! /usr/bin/env python

# HIP name look-up daemon for /etc/hip/hosts and DNS and Bamboo servers
#
# Usage: Basic usage without any command line options.
#        See getopt() for the options.
#
# Working test cases with hipdnsproxy
# - Interoperates with libc and dnsmasq
# - Resolvconf(on/off) + dnsmasq (on/off)
#    - initial look up (check HIP and non-hip look up)
#      - check that ctrl+c restores /etc/resolv.conf
#    - change access network (check HIP and non-hip look up)
#      - check that ctrl+c restores /etc/resolv.conf
# - Watch out for cached entries! Restart dnmasq and hipdnsproxy after
#   each test.
# - Test name resolution with following methods:
#   - Non-HIP records
#   - Hostname to HIT resolution
#     - HITs and LSIs from /etc/hip/hosts
#     - On-the-fly generated LSI; HIT either from from DNS, DHT or hosts
#     - HI records from DNS
#     - HITs from Bamboo via hipd
#   - PTR records: maps HITs to hostnames from /etc/hip/hosts
#
# Actions to resolv.conf files and dnsproxy hooking:
# - Dnsmasq=on, revolvconf=on: only hooks dnsmasq
# - Dnsmasq=off, revolvconf=on: rewrites /etc/resolvconf/run/resolv.conf
# - Dnsmasq=on, revolvconf=off: hooks dnsmasq and rewrites /etc/resolv.conf
# - Dnsmasq=off, revolvconf=off: rewrites /etc/resolv.conf
#
# TBD:
# - rewrite the code to more object oriented
# - the use of alternative (multiple) dns servers
# - implement TTLs for cache
#   - applicable to HITs, LSIs and IP addresses
#   - host files: forever (purged when the file is changed)
#   - dns records: follow DNS TTL
# - bind to ::1, not 127.0.0.1 (setsockopt blah blah)
# - remove hardcoded addresses from ifconfig commands

import sys
import getopt
import os
import stat
import time
import util
import socket
import traceback
import DNS
import binascii
import hosts
import re
import signal
import syslog
import fileinput
import subprocess
import select
import copy
import errno

Serialize = DNS.Serialize
DeSerialize = DNS.DeSerialize
Popen = subprocess.Popen

def usage(utyp, *msg):
    sys.stderr.write('Usage: %s\n' % os.path.split(sys.argv[0])[1])
    if msg:
        sys.stderr.write('Error: %s\n' % `msg`)
    sys.exit(1)

path = os.environ.get('PATH',None)
if path is not None:
    path = path.split(':')
else:
    path = []

# Done: forking affects this. Fixed in forkme
myid = '%d-%d' % (time.time(),os.getpid())

class ResolvConfError(Exception):
    pass

class Logger:
    def __init__(self):
        self.wrfun = sys.stdout.write
        self.flfun = sys.stdout.flush
        return
    def wrsyslog(self,s):
        syslog.syslog(s)
        return
    def setsyslog(self):
        syslog.openlog('dnsproxy',syslog.LOG_PID)
        self.wrfun = self.wrsyslog
        self.flfun = None
        return
    def flush(self):
        return
    def write(self,s):
        self.wrfun(s)
        if self.flfun: self.flfun()
        return

class ResolvConf:
    re_nameserver = re.compile(r'nameserver\s+(\S+)$')

    def guess_resolvconf(self):
        if self.use_dnsmasq_hook and self.use_resolvconf:
            return self.dnsmasq_resolv
        elif self.use_resolvconf:
            return self.resolvconf_run
        else:
            return '/etc/resolv.conf'

    def __init__(self, gp, filetowatch = None):
        self.fout = gp.fout
        self.dnsmasq_initd_script = '/etc/init.d/dnsmasq'
        if os.path.exists('/etc/redhat-release'):
            self.distro = 'redhat'
            self.rh_before = '# See how we were called.'
            self.rh_inject = '. /etc/sysconfig/dnsmasq # Added by hipdnsproxy'
        elif os.path.exists('/etc/debian_version'):
            self.distro = 'debian'
        else:
            self.distro = 'unknown'

        if self.distro == 'redhat':
            self.dnsmasq_defaults = '/etc/sysconfig/dnsmasq'
            if not os.path.exists(self.dnsmasq_defaults):
                open(self.dnsmasq_defaults, 'w').close()
        else:
            self.dnsmasq_defaults = '/etc/default/dnsmasq'

        self.dnsmasq_defaults_backup = self.dnsmasq_defaults + '.backup.hipdnsproxy'

        if (os.path.isdir('/etc/resolvconf/.') and
            os.path.exists('/sbin/resolvconf') and
            os.path.exists('/etc/resolvconf/run/resolv.conf')):
            self.use_resolvconf = True
        else:
            self.use_resolvconf = False
        self.use_dnsmasq_hook = False

        self.dnsmasq_resolv = '/var/run/dnsmasq/resolv.conf'
        self.resolvconf_run = '/etc/resolvconf/run/resolv.conf'
        if self.use_resolvconf:
            self.resolvconf_towrite = '/etc/resolvconf/run/resolv.conf'
        else:
            self.resolvconf_towrite = '/etc/resolv.conf'

        self.dnsmasq_restart = self.dnsmasq_initd_script + ' restart >/dev/null'
        if filetowatch is None:
            self.filetowatch = self.guess_resolvconf()
        self.resolvconf_orig = self.filetowatch
        self.old_rc_mtime = os.stat(self.filetowatch).st_mtime
        self.resolvconf_bkname = '%s-%s' % (self.resolvconf_towrite,myid)
        self.overwrite_resolv_conf = gp.overwrite_resolv_conf
        return

    def reread_old_rc(self):
        d = {}
        self.resolvconfd = d
        f = open(self.filetowatch)
        for l in f.xreadlines():
            l = l.strip()
            if not d.has_key('nameserver'):
                r1 = self.re_nameserver.match(l)
                if r1:
                    d['nameserver'] = r1.group(1)
        return d

    def set_dnsmasq_hook(self, gp):
        self.alt_port = gp.bind_alt_port
        self.use_dnsmasq_hook = True
        self.fout.write('Dnsmasq-resolvconf installation detected\n')
        if self.distro == 'redhat':
            self.dnsmasq_hook = 'OPTIONS+="--no-hosts --no-resolv --cache-size=0 --server=%s#%s"\n' % (gp.bind_ip, self.alt_port,)
        else:
            self.dnsmasq_hook = 'DNSMASQ_OPTS="--no-hosts --no-resolv --cache-size=0 --server=%s#%s"\n' % (gp.bind_ip, self.alt_port,)
        return

    def old_has_changed(self):
        old_rc_mtime = os.stat(self.filetowatch).st_mtime
        if old_rc_mtime != self.old_rc_mtime:
            self.reread_old_rc()
            self.old_rc_mtime = old_rc_mtime
            return True
        else:
            return False

    def save_resolvconf_dnsmasq(self):
        if self.use_dnsmasq_hook:
            if os.path.exists(self.dnsmasq_defaults):
                f = open(self.dnsmasq_defaults, 'r')
                l = f.readline()
                f.close()
                if l.find('server=127') != -1 and l[:l.find('server=')] == self.dnsmasq_hook[:self.dnsmasq_hook.find('server=')]:
                    self.fout.write('Dnsmasq configuration file seems to be written by dnsproxy. Zeroing.\n')
                    f = open(self.dnsmasq_defaults, 'w')
                    f.write('')
                    f.close()
                os.rename(self.dnsmasq_defaults, 
                          self.dnsmasq_defaults_backup)
            dmd = open(self.dnsmasq_defaults, 'w')
            dmd.write(self.dnsmasq_hook)
            dmd.close()
            if self.distro == 'redhat':
                for line in fileinput.input(self.dnsmasq_initd_script, inplace=1):
                    if line.find(self.rh_before) == 0:
                        print self.rh_inject
                    print line,
            os.system(self.dnsmasq_restart)
            self.fout.write('Hooked with dnsmasq\n')
            # Restarting of dnsproxy changes also resolv conf. Reset timer
            # to make sure that we don't load dnsproxy's IP address (bug 909)
            self.old_rc_mtime = os.stat(self.filetowatch).st_mtime
        if (not (self.use_dnsmasq_hook and self.use_resolvconf) and self.overwrite_resolv_conf):
            os.link(self.resolvconf_towrite,self.resolvconf_bkname)
        return

    def restore_resolvconf_dnsmasq(self):
        if self.use_dnsmasq_hook:
            self.fout.write('Removing dnsmasq hooks\n')
            if os.path.exists(self.dnsmasq_defaults_backup):
              os.rename(self.dnsmasq_defaults_backup,
                        self.dnsmasq_defaults)
            if self.distro == 'redhat':
                for line in fileinput.input(self.dnsmasq_initd_script, inplace=1):
                    if line.find(self.rh_inject) == -1:
                        print line,
            os.system(self.dnsmasq_restart)
        if (not (self.use_dnsmasq_hook and self.use_resolvconf) and self.overwrite_resolv_conf):
            os.rename(self.resolvconf_bkname, self.resolvconf_towrite)
            self.fout.write('resolv.conf restored\n')
        return

    def write(self,params):
        keys = params.keys()
        keys.sort()
        tmp = '%s.tmp-%s' % (self.resolvconf_towrite,myid)
        tf = open(tmp,'w')
        tf.write('# This is written by dnsproxy.py\n')
        for k in keys:
            v = params.get(k)
            if type(v) == type(''):
                v = (v,)
            for v2 in v:
                tf.write('%-10s %s\n' % (k,v2))
        tf.close()
        os.rename(tmp,self.resolvconf_towrite)
        self.old_rc_mtime = os.stat(self.filetowatch).st_mtime

    def overwrite_resolvconf(self):
        tmp = '%s.tmp-%s' % (self.resolvconf_towrite,myid)
        f1 = open(self.resolvconf_towrite,'r')
        f2 = open(tmp,'w')
        while 1:
            d = f1.read(16384)
            if not d:
                break
            f2.write(d)
        f1.close()
        f2.close()
        os.rename(tmp,self.resolvconf_towrite)
        self.fout.write('Rewrote resolv.conf\n')

    def start(self):
        self.save_resolvconf_dnsmasq()
        if (not (self.use_dnsmasq_hook and self.use_resolvconf) and self.overwrite_resolv_conf):
            self.overwrite_resolvconf()

    def restart(self):
        if (not (self.use_dnsmasq_hook and self.use_resolvconf) and self.overwrite_resolv_conf):
            self.overwrite_resolvconf()
            #if os.path.exists(self.resolvconf_bkname):
            #    os.remove(self.resolvconf_bkname)
        self.old_rc_mtime = os.stat(self.filetowatch).st_mtime

    def stop(self):
        self.restore_resolvconf_dnsmasq()
        os.system("ifconfig lo:53 down")
        # Sometimes hipconf processes get stuck, particularly when
        # hipd is busy or unresponsive. This is a workaround.
        os.system('killall --quiet hipconf 2>/dev/null')

class Global:
    default_hiphosts = "/etc/hip/hosts"
    default_hosts = "/etc/hosts"
    re_nameserver = re.compile(r'nameserver\s+(\S+)$')
    def __init__(gp):
        gp.vlevel = 0
        gp.resolv_conf = '/etc/resolv.conf'
        gp.hostsnames = []
        gp.server_ip = None
        gp.server_port = None
        gp.bind_ip = None
        gp.bind_port = None
        gp.bind_alt_port = None
        gp.use_alt_port = False
        gp.disable_lsi = False
        gp.fork = False
        gp.pidfile = '/var/run/hipdnsproxy.pid'
        gp.kill = False
        gp.overwrite_resolv_conf = True
        gp.logger = Logger()
        gp.fout = gp.logger
        gp.app_timeout = 1
        gp.dns_timeout = 2
        gp.hosts_ttl = 122
        gp.sent_queue = []
        gp.sent_queue_d = {}            # Keyed by ('server_ip',server_port,query_id) tuple
        # required for ifconfig and hipconf in Fedora
        # (rpm and "make install" targets)
        os.environ['PATH'] += ':/sbin:/usr/sbin:/usr/local/sbin'
        return

    def add_query(gp,server_ip,server_port,query_id,query):
        """Add a pending DNS query"""
        k = (server_ip,server_port,query_id)
        v = (k,time.time(),query)
        gp.sent_queue.append(v)
        gp.sent_queue_d[k] = v

    def find_query(gp,server_ip,server_port,query_id):
        """Find a pending DNS query"""
        k = (server_ip,server_port,query_id)
        query = gp.sent_queue_d.get(k)
        if query:
            i = gp.sent_queue.index(query)
            gp.sent_queue.pop(i)
            del gp.sent_queue_d[k]
            return query[2]
        return None

    def clean_queries(gp):
        """Clean old unanswered queries"""
        texp = time.time()-30
        q = gp.sent_queue
        while q:
            if q[0][1] < texp:
                k = q[0][0]
                q.pop(0)
                del gp.sent_queue_d[k]
            else:
                break
        return

    def read_resolv_conf(gp, cfile=None):
        d = {}
        if cfile is None:
            cfile = gp.resolv_conf
        f = open(cfile)
        for l in f.xreadlines():
            l = l.strip()
            if not d.has_key('nameserver'):
                r1 = gp.re_nameserver.match(l)
                if r1:
                    d['nameserver'] = r1.group(1)
        gp.resolvconfd = d
        if gp.server_ip is None:
            s_ip = gp.resolvconfd.get('nameserver')
            if s_ip:
                gp.server_ip = s_ip
            else:
                gp.server_ip = None
        return d

    def parameter_defaults(gp):
        env = os.environ
        if gp.server_ip is None:
            gp.server_ip = env.get('SERVER',None)
        if gp.server_port is None:
            server_port = env.get('SERVERPORT',None)
            if server_port is not None:
                gp.server_port = int(server_port)
        if gp.server_port is None:
            gp.server_port = 53
        if gp.bind_ip is None:
            gp.bind_ip = env.get('IP',None)
        if gp.bind_ip is None:
            gp.bind_ip = '127.0.0.53'
        if gp.bind_port is None:
            bind_port = env.get('PORT',None)
            if bind_port is not None:
                gp.bind_port = int(bind_port)
        if gp.bind_port is None:
            gp.bind_port = 53
        if gp.bind_alt_port is None:
            gp.bind_alt_port = 5000

    def hosts_recheck(gp):
        for h in gp.hosts:
            h.recheck()
        return

#    def getname(gp,hn):
#        for h in gp.hosts:
#            r = h.getname(hn)
#            if r:
#                return r
#        return None

    def getaddr(gp,ahn):
        for h in gp.hosts:
            r = h.getaddr(ahn)
            if r:
                return r
        return None

    def getaaaa(gp,ahn):
        for h in gp.hosts:
            r = h.getaaaa(ahn)
            if r:
                return r
        return None

    def getaaaa_hit(gp,ahn):
        for h in gp.hosts:
            r = h.getaaaa_hit(ahn)
            if r:
                return r
        return None

    def str_is_lsi(gp, id):
        for h in gp.hosts:
            return h.str_is_lsi(id);
        return None

    def str_is_hit(gp, id):
        for h in gp.hosts:
            return h.str_is_hit(id);
        return None

    def cache_name(gp, name, addr, ttl):
        for h in gp.hosts:
            h.cache_name(name, addr, ttl)

    def geta(gp,ahn):
        for h in gp.hosts:
            r = h.geta(ahn)
            if r:
                return r
        return None

    def ptr_str_to_addr_str(gp, ptr_str):
        for h in gp.hosts:
            return h.ptr_str_to_addr_str(ptr_str)

    def addr6_str_to_ptr_str(gp, addr_str):
        for h in gp.hosts:
            return h.addr6_str_to_ptr_str(addr_str)

    def forkme(gp):
        pid = os.fork()
        if pid:
            return False
        else:
            # we are the child
            global myid
            myid = '%d-%d' % (time.time(),os.getpid())
            gp.logger.setsyslog()
            return True

    def killold(gp):
        try:
            f = open(gp.pidfile, 'r')
        except IOError, e:
            if e[0] == errno.ENOENT:
                return
            else:
                gp.fout.write('Error opening pid file: %s\n' % e)
                sys.exit(1)
        try:
            os.kill(int(f.readline().rstrip()), signal.SIGTERM)
        except OSError, e:
            if e[0] == errno.ESRCH:
                f.close()
                return
            else:
                gp.fout.write('Error terminating old process: %s\n' % e)
                sys.exit(1)
        time.sleep(3)
        f.close()

    def recovery(gp):
        try:
            f = open(gp.pidfile, 'r')
        except IOError, e:
            if e[0] == errno.ENOENT:
                return
            else:
                gp.fout.write('Error opening pid file: %s\n' % e)
                sys.exit(1)
        f.readline()
        bk_path = '%s-%s' % (gp.rc1.resolvconf_towrite, f.readline().rstrip())
        if os.path.exists(bk_path):
            gp.fout.write('resolv.conf backup found. Restoring.\n')
            tmp = gp.rc1.resolvconf_bkname
            gp.rc1.resolvconf_bkname = bk_path
            gp.rc1.restore_resolvconf_dnsmasq()
            gp.rc1.resolvconf_bkname = tmp
        f.close()

    def savepid(gp):
        try:
            f = open(gp.pidfile, 'w')
        except IOError, e:
            gp.fout.write('Error opening pid file for writing: %s' % e)
            sys.exit(1)
        f.write('%d\n' % (os.getpid(),))
        f.write('%s\n' % myid)
        f.close()

    def dht_lookup(gp, nam):
        #gp.fout.write("DHT look up\n")
        cmd = "hipconf dht get " + nam + " 2>&1"
        #gp.fout.write("Command: %s\n" % (cmd))
        p = Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout
        result = p.readline()
        # xx fixme: we should query cache for PTR records
        while result:
            start = result.find("2001:001")
            end = result.find('\n')
            if start != -1 and end != -1:
                return result[start:end]
            result = p.readline()
        return None

    # Add local HITs to hosts files (bug id 737).
    # xx fixme: should we really write the local hits
    #           to a file rather than just adding them
    #           to the cache?
    def write_local_hits_to_hosts(gp):
        localhit = []
        cmd = "ifconfig dummy0 2>&1"
        p = Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout
        result = p.readline()
        while result:
            start = result.find("2001:1")
            end = result.find("/28")
            if start != -1 and end != -1:
                hit = result[start:end]
                if not gp.getaddr(hit):
                    localhit.append(hit)
            result = p.readline()
        p.close()
        f = open(gp.default_hiphosts, 'a')
        for i in range(len(localhit)):
            f.write(localhit[i] + "\tlocalhit" + str(i+1) + '\n')
        f.close()

    def map_hit_to_lsi(gp, hit):
        cmd = "hipconf hit-to-lsi " + hit + " 2>&1"
        #gp.fout.write("cmd - %s\n" % (cmd,))
        p = Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout
        result = p.readline()
        while result:
            start = result.find("1.")
            end = result.find("\n")
            if start != -1 and end != -1:
                return result[start:end]
            result = p.readline()
        return None

    def lsi_to_hit(gp, lsi):
        cmd = "hipconf lsi-to-hit " + lsi + " 2>&1"
        p = Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout
        result = p.readline()
        while result:
            start = result.find("2001:")
            end = result.find("\n")
            if start != -1 and end != -1:
                return result[start:end]
            result = p.readline()
        return None

    def add_hit_ip_map(gp, hit, ip):
        cmd = "hipconf add map " + hit + " " + ip + \
            " >/dev/null 2>&1"
        gp.fout.write('Associating HIT %s with IP %s\n' % (hit, ip))
        os.system(cmd)

    def dns_r2s(gp,r):
        a = []
        attrs = dir(r)
        attrs.sort()
        a.append('%s\n' % (attrs,))
        for k in attrs:
            a.append('  %-10s %s\n' % (k,getattr(r,k)))
        return ''.join(a).strip()

    def hip_is_reverse_hit_query(gp, name):
        # Check if the query is a reverse query to a HIT:
        # 8.e.b.8.b.3.c.9.1.a.0.c.e.e.2.c.c.e.d.0.9.c.9.a.e.1.0.0.1.0.0.2.hit-to-ip.infrahip.net
        if (len(name) > 64 and name.find('.1.0.0.1.0.0.2.') == 49):
            return True
        else:
            return False

    def hip_cache_lookup(gp, g1):
        lr = None
        qname = g1['questions'][0][0]
        qtype = g1['questions'][0][1]

        # convert 1.2....1.0.0.1.0.0.2.ip6.arpa to a HIT and
        # map host name to address from cache
        if qtype == 12:
            lr_ptr = None
            addr_str = gp.ptr_str_to_addr_str(qname)
            if not gp.disable_lsi and addr_str is not None and gp.str_is_lsi(addr_str):
                    addr_str = gp.lsi_to_hit(addr_str)
            lr_ptr = gp.getaddr(addr_str)
            lr_aaaa_hit = None
        else:
            lr_a =  gp.geta(qname)
            lr_aaaa = gp.getaaaa(qname)
            lr_aaaa_hit = gp.getaaaa_hit(qname)

        if lr_aaaa_hit is not None:
            if lr_a is not None:
                gp.add_hit_ip_map(lr_aaaa_hit[0], lr_a[0])
            if lr_aaaa is not None:
                gp.add_hit_ip_map(lr_aaaa_hit[0], lr_aaaa[0])
            if qtype == 28:               # 28: AAAA
                lr = lr_aaaa_hit
            elif qtype == 1 and not gp.disable_lsi: # 1: A
                lsi = gp.map_hit_to_lsi(lr_aaaa_hit[0])
                if lsi is not None:
                    lr = (lsi, lr_aaaa_hit[1])
        elif qtype == 28:
            lr = lr_aaaa
        elif qtype == 1:
            lr = lr_a
        elif qtype == 12 and lr_ptr is not None:  # 12: PTR
            lr = (lr_ptr, gp.hosts_ttl)

        if lr is not None:
            g1['answers'].append([qname, qtype, 1, lr[1], lr[0]])
            g1['ancount'] = len(g1['answers'])
            g1['qr'] = 1
            return True

        return False

    def hip_lookup(gp, g1):
        qname = g1['questions'][0][0]
        qtype = g1['questions'][0][1]

        dns_hit_found = False
        for a1 in g1['answers']:
            if a1[1] == 55:
                dns_hit_found = True
                break

        dhthit = None
        if not dns_hit_found:
            dhthit = gp.dht_lookup(qname)
            if dhthit is not None:
                gp.fout.write('DHT match: %s %s\n' % (qname, dhthit))
                g1['answers'].append([qname, 55, 1, gp.hosts_ttl ,dhthit])

        lsi = None
        hit_found = dns_hit_found or dhthit is not None
        if hit_found:
            hit_ans = []
            lsi_ans = []

            for a1 in g1['answers']:
                if a1[1] != 55:
                    continue

                if dhthit is not None: # already an AAAA record
                    hit = dhthit
                    a1[1] = 28
                    hit_ans.append(a1)
                else:
                    hit = socket.inet_ntop(socket.AF_INET6, a1[7])
                    hit_ans.append([qname, 28, 1, a1[3], hit])

                if qtype == 1 and not gp.disable_lsi:
                    lsi = gp.map_hit_to_lsi(hit)
                    if lsi is not None:
                        lsi_ans.append([qname, 1, 1, gp.hosts_ttl, lsi])

                gp.cache_name(qname, hit, a1[3])

        if qtype == 28 and hit_found:
            g1['answers'] = hit_ans
        elif lsi is not None:
            g1['answers'] = lsi_ans
        else:
            g1['answers'] = []
        g1['ancount'] = len(g1['answers'])

    def doit(gp,args):
        connected = False
        fout = gp.fout

        fout.write('Dns proxy for HIP started\n')

        gp.parameter_defaults()

        # Default virtual interface and address for dnsproxy to
        # avoid problems with other dns forwarders (e.g. dnsmasq)
        os.system("ifconfig lo:53 %s" % (gp.bind_ip,))
        #os.system("ifconfig lo:53 inet6 add ::53/128")

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((gp.bind_ip, gp.bind_port))
        except:
            fout.write('Port %d occupied, falling back to port %d\n' %
                       (gp.bind_port, gp.bind_alt_port))
            s.bind((gp.bind_ip, gp.bind_alt_port))
            gp.use_alt_port = True

        s.settimeout(gp.app_timeout)

        rc1 = gp.rc1
        if gp.use_alt_port and os.path.exists(rc1.dnsmasq_defaults):
            rc1.set_dnsmasq_hook(gp)

        if rc1.use_dnsmasq_hook and rc1.use_resolvconf:
            conf_file = rc1.guess_resolvconf()
        else:
            conf_file = None

        if conf_file is not None:
            fout.write("Using conf file %s\n" % conf_file)

        gp.read_resolv_conf(conf_file)
        if gp.server_ip is not None:
            fout.write("DNS server is %s\n" % gp.server_ip)

        gp.hosts = []
        if gp.hostsnames:
            for hn in gp.hostsnames:
                gp.hosts.append(hosts.Hosts(hn))
        else:
            if os.path.exists(gp.default_hiphosts):
                gp.hosts.append(hosts.Hosts(gp.default_hiphosts))

        if os.path.exists(gp.default_hosts):
            gp.hosts.append(hosts.Hosts(gp.default_hosts))

        gp.write_local_hits_to_hosts()

        util.init_wantdown()
        util.init_wantdown_int()        # Keyboard interrupts

        args0 = {'server': gp.bind_ip,
                }
        rc1.start()

        if (not (rc1.use_dnsmasq_hook and rc1.use_resolvconf) and gp.overwrite_resolv_conf):
            rc1.write({'nameserver': gp.bind_ip})

        if gp.server_ip is not None:
            if gp.server_ip.find(':') == -1:
                server_family = socket.AF_INET
            else:
                server_family = socket.AF_INET6
            s2 = socket.socket(server_family, socket.SOCK_DGRAM)
            s2.settimeout(gp.dns_timeout)
            try:
                s2.connect((gp.server_ip,gp.server_port))
                connected = True
            except:
                connected = False

        query_id = 1

        while not util.wantdown():
            try:
                gp.hosts_recheck()
                if rc1.old_has_changed():
                    connected = False
                    gp.server_ip = rc1.resolvconfd.get('nameserver')
                    if gp.server_ip is not None:
                        if gp.server_ip.find(':') == -1:
                            server_family = socket.AF_INET
                        else:
                            server_family = socket.AF_INET6
                        s2 = socket.socket(server_family, socket.SOCK_DGRAM)
                        s2.settimeout(gp.dns_timeout)
                        try:
                            s2.connect((gp.server_ip,gp.server_port))
                            connected = True
                            fout.write("DNS server is %s\n" % gp.server_ip)
                        except:
                            connected = False

                    rc1.restart()
                    if (not (rc1.use_dnsmasq_hook and rc1.use_resolvconf) and gp.overwrite_resolv_conf):
                        rc1.write({'nameserver': gp.bind_ip})

                if connected:
                    rlist,wlist,xlist = select.select([s,s2],[],[],5.0)
                else:
                    rlist,wlist,xlist = select.select([s],[],[],5.0)
                gp.clean_queries()
                if s in rlist:          # Incoming DNS request
                    buf,from_a = s.recvfrom(2048)

                    #fout.write('Up %s\n' % (util.tstamp(),))
                    #fout.write('%s %s\n' % (from_a,repr(buf)))
                    #fout.flush()

                    d1 = DeSerialize(buf)
                    g1 = d1.get_dict()
                    qtype = g1['questions'][0][1]
                    gp.fout.write('Query type %d for %s\n' % (qtype, g1['questions'][0][0]))

                    sent_answer = False

                    if qtype in (1,28,12):
                        if gp.hip_cache_lookup(g1):
                            try:
                                #fout.write("sending %d answer\n" % qtype)
                                dnsbuf = Serialize(g1).get_packet()
                                s.sendto(dnsbuf,from_a)
                                sent_answer = True
                            except Exception,e:
                                tbstr = traceback.format_exc()
                                fout.write('Exception: %s %s\n' % (e,tbstr,))

                    if connected and not sent_answer:
                        if gp.vlevel >= 2: fout.write('No HIP-related records found\n')
                        query = (g1,from_a[0],from_a[1],qtype)
                        query_id = (query_id % 65535)+1 # XXX Should randomize for security, fix this later
                        g2 = copy.copy(g1)
                        g2['id'] = query_id
                        if ((qtype == 28 or (qtype == 1 and not gp.disable_lsi)) and
                            not gp.hip_is_reverse_hit_query(g1['questions'][0][0])):

                            g2['questions'][0][1] = 55
                        if (qtype == 12 and not gp.disable_lsi):
                            qname = g1['questions'][0][0]
                            addr_str = gp.ptr_str_to_addr_str(qname)
                            if addr_str is not None and gp.str_is_lsi(addr_str):
                                query = (g1,from_a[0],from_a[1],qname)
                                hit_str = gp.lsi_to_hit(addr_str)
                                if hit_str is not None:
                                    g2['questions'][0][0] = gp.addr6_str_to_ptr_str(hit_str)

                        dnsbuf = Serialize(g2).get_packet()
                        s2.sendto(dnsbuf,(gp.server_ip,gp.server_port))

                        gp.add_query(gp.server_ip,gp.server_port,query_id,query)

                if connected and s2 in rlist:   # Incoming DNS reply
                    buf,from_a = s2.recvfrom(2048)
                    fout.write('Packet from DNS server %d bytes from %s\n' % (len(buf),from_a))
                    d1 = DeSerialize(buf)
                    g1 = d1.get_dict()
                    if gp.vlevel >= 2:
                        fout.write('%s %s\n' % (r.header,r.questions,))
                        fout.write('%s\n' % (g1,))

                    query_id_o = g1['id']
                    query_o = gp.find_query(from_a[0],from_a[1],query_id_o)
                    if query_o:
                        qname = g1['questions'][0][0]
                        qtype = g1['questions'][0][1]
                        send_reply = True
                        query_again = False
                        hit_found = False
                        #fout.write('Found original query %s\n' % (query_o,))
                        g1_o = query_o[0]
                        g1['id'] = g1_o['id'] # Replace with the original query id
                        if qtype == 55 and query_o[3] in (1, 28):
                            g1['questions'][0][1] = query_o[3] # Restore qtype
                            gp.hip_lookup(g1)
                            if g1['ancount'] > 0:
                                hit_found = True
                            query_again = True
                            send_reply = False

                        elif qtype in (1, 28):
                            hit = gp.getaaaa_hit(qname)
                            ip6 = gp.getaaaa(qname)
                            ip4 = gp.geta(qname)
                            for id in g1['answers']:
                                if id[1] in (1, 28):
                                    gp.cache_name(qname, id[4], id[3])
                            if hit is not None:
                                for id in g1['answers']:
                                    if id[1] == 1 or (id[1] == 28 and not gp.str_is_hit(id[4])):
                                        gp.add_hit_ip_map(hit[0], id[4])
                                # Reply with HIT/LSI once it's been mapped to an IP
                                if ip6 is None and ip4 is None:
                                    if g1_o['ancount'] == 0: # No LSI available. Return IPv4
                                        tmp = g1['answers']
                                        g1 = g1_o
                                        g1['answers'] = tmp
                                        g1['ancount'] = len(g1['answers'])
                                    else:
                                        g1 = g1_o
                                else:
                                    send_reply = False

                        elif qtype == 12 and isinstance(query_o[3], str):
                            g1['questions'][0][0] = query_o[3]
                            for ans in g1['answers']:
                                ans[0] = query_o[3]

                        if query_again:
                            if hit_found:
                                qtypes = [28, 1]
                                g2 = copy.deepcopy(g1)
                            else:
                                qtypes = [query_o[3]]
                                g2 = copy.copy(g1)
                            g2['qr'] = 0
                            g2['answers'] = []
                            g2['ancount'] = 0
                            g2['nslist'] = []
                            g2['nscount'] = 0
                            g2['additional'] = []
                            g2['arcount'] = 0
                            for qtype in qtypes:
                                query = (g1, query_o[1], query_o[2], qtype)
                                query_id = (query_id % 65535)+1
                                g2['id'] = query_id
                                g2['questions'][0][1] = qtype
                                dnsbuf = Serialize(g2).get_packet()
                                s2.sendto(dnsbuf, (gp.server_ip, gp.server_port))
                                gp.add_query(gp.server_ip,gp.server_port,query_id,query)
                            g1['questions'][0][1] = query_o[3]

                        if send_reply:
                            dnsbuf = Serialize(g1).get_packet()
                            s.sendto(dnsbuf,(query_o[1],query_o[2]))
            except Exception,e:
                if e[0] == errno.EINTR:
                    pass
                else:
                    tbstr = traceback.format_exc()
                    fout.write('Exception: %s\n%s\n' % (os.errno,tbstr,))

        fout.write('Wants down\n')
        rc1.stop()
        return

def main(argv):
    gp = Global()
    try:
        opts, args = getopt.getopt(argv[1:],
                                   'bkhLf:c:H:s:p:l:i:P:',
                                   ['background',
                                    'kill',
                                    'help',
                                    'disable-lsi',
                                    'file=',
                                    'count=',
                                    'hosts=',
                                    'server=',
                                    'serverport=',
                                    'ip=',
                                    'port=',
                                    'pidfile='
                                    'resolv-conf=',
                                    'dns-timeout=',
                                    'leave-resolv-conf',
                                    ])
    except getopt.error, msg:
        usage(1, msg)

    for opt, arg in opts:
        if opt in ('-k', '--kill'):
            gp.kill = True
        elif opt in ('-b', '--background'):
            gp.fork = True
        elif opt in ('-L', '--disable-lsi'):
            gp.disable_lsi = True
        elif opt in ('-f', '--file'):
            gp.tarfilename = arg
        elif opt in ('-c', '--count'):
            gp.fetchcount = int(arg)
        elif opt in ('-H', '--hosts'):
            gp.hostsnames.append(arg)
        elif opt in ('--resolv-conf',):
            gp.resolv_conf = arg
        elif opt in ('-s', '--server'):
            gp.server_ip = arg
        elif opt in ('-p', '--serverport'):
            gp.server_port = int(arg)
        elif opt in ('-i', '--ip'):
            gp.bind_ip = arg
        elif opt in ('-l', '--port'):
            gp.bind_port = int(arg)
        elif opt in ('--dns-timeout',):
            gp.dns_timeout = float(arg)
        elif opt in ('-P', '--pidfile'):
            gp.pidfile = arg
        elif opt in ('--leave-resolv-conf'):
            gp.overwrite_resolv_conf = False

    child = False;
    if (gp.fork):
        child = gp.forkme()

    if child or not gp.fork:
        gp.rc1 = ResolvConf(gp)
        if gp.kill:
            gp.killold()
            if gp.overwrite_resolv_conf:
                gp.recovery()
        gp.savepid()
        gp.doit(args)

if __name__ == '__main__':
    main(sys.argv)
