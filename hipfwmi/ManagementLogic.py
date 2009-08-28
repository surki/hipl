#!/usr/bin/env python

import os
import sys
import syslog

from Rules import Rule


revision = '$Id'

from ConfigurationInterface import ConfigurationInterfaceServer


def _list_rules(fwrulefile):
    """Read and parse rules from a rulefile.

    The rulefile is created if it does not yet exist.

    @param fwrulefile: read the rules from this file
    @type  fwrulefile: str
    @return: list of rules
    @rtype:  [Rule()]
    """
    try:
        f = open(fwrulefile, 'r')
    except IOError, e:
        # retry if it did not exist
        if e.errno == 2:
            f = open(fwrulefile, 'w+')
    l = [Rule(s)
         for s in f.readlines()
         if s.strip()]
    #syslog.syslog(str(l))
    f.close()
    return l

def _write_rules(rules, fwrulefile):
    """Write list of rules into the rulefile.

    The old rulefile is replaced atomically with the new one.

    The file is created if necessary.

    @param rules: rules to write
    @type  rules: [Rule()]
    @param fwrulefile: name of the rulefile
    @type  fwrulefile: str
    """
    f = open(fwrulefile+'.new', 'w')
    for rule in rules:
        f.write(rule.to_text() + '\n')
        syslog.syslog('Wrote rule: %s' % str(rule))
    f.close()
    os.rename(fwrulefile+'.new', fwrulefile)
    syslog.syslog('Replaced the rulefile %s with a new one.' % repr(fwrulefile))

def _upload_key(keydir, keyname, key):
    """Upload a new key to the keystore for use with src_hi.

    If there already is a key with the same name, it is overridden.

    @param keydir: directory of the keystore
    @type  keydir: str
    @param keyname: filename for the key, must contain "_rsa_" or "_dsa_"
    @type  keyname: str
    @param key: contents of the keyfile
    @type  key: str
    """
    if '_rsa_' not in keyname and '_dsa_' not in keyname:
        raise ValueError("Key name must include the type of the key")
    assert key

    f = open(os.path.join(keydir, keyname), 'w')
    f.write(key)
    f.close()

def _list_keys(keydir):
    """List the names of the stored keys.

    @param keydir: directory of the keystore
    @type  keydir: str
    @return: filenames of the stored keys
    @rtype: [str]
    """
    return os.listdir(keydir)

def _delete_key(keydir, keyname):
    """Delete the specified key from keystore if it exists.

    @param keydir: directory of the keystore
    @type  keydir: str
    @param keyname: filename of the key
    @type  keyname: str
    """
    try:
        os.unlink(os.path.join(keydir, keyname))
    except OSError:
        pass


class ManagementLogic(object):
    """Logic for operating on the firewall.
    """
    
    def __init__(self, listeniface, listenport, fwrulefile, keydir):
        """Set up the logic.

        This is expected to be run with root privileges. Stuff like
        opening listening sockets is done here.

        @param listeniface: the ip address to listen on for incoming connections
        @type  listeniface: str
        @param listenport: tcp port number to listen on
        @type  listenport: int
        @param fwrulefile: name of the hip firewall's rulefile
        @type  fwrulefile: str
        @param keydir: directory where src_hi-keys are stored
        @type  keydir: str
        """
        # Run as root
        self.fwrulefile = fwrulefile
        self.keydir = keydir
        self.server = ConfigurationInterfaceServer(
            self, listeniface, listenport)

    def run(self):
        """ManagementLogic's main loop.

        This is expected to run with user privileges.

        Note: the user needs to have enough privileges to create a new
        rulefile in the directory containing fwrulefile and to replace
        the old file with the new one.
        """
        # Run as user
        print 'testmessage'
        sys.stdout.flush()
        self.server.run()

    def enable_debugging(self):
        """Enable more verbose logging."""
        self.server.enable_debugging()

    def reload_firewall(self):
        """Send a request of reloading the firewall rules."""
        print 'reloadfw'
	sys.stdout.flush()
	syslog.syslog("requested firewall reload")
	
    def list_rules(self):
        """List current firewall rules.

        If the rulefile does not exist, it is created.

        @return: list of rules
        @rtype:  [Rule()]
        """
        try:
            return _list_rules(self.fwrulefile)
        except StandardError, e:
            syslog.syslog("list_rules() failed: %s" % e)
            return []

    def write_rules(self, rulelist):
        """Write the list of rules to the rulefile.

        @return: True if succeeded.
        @rtype:  bool
        """
        try:
            _write_rules(rulelist, self.fwrulefile)
            syslog.syslog("wrote %d rules" % len(rulelist))
	    self.reload_firewall()
            return True
        except StandardError, e:
            #import traceback
            #traceback.print_exc(file=open('/tmp/trackback', 'a'))
            syslog.syslog("write_rules() failed: %s" %e)
            return False

    def append_rules(self, rulelist, rules):
        """Append rules to the rulelist.

        Merge the two lists. The new list will not be saved until
        explicitly written.

        @param rulelist: list of rules to operate on
        @type  rulelist: [Rule()]
        @param rules: new rules to append
        @type  rules: [Rule()]
        """
        for rule in rules:
            if rule not in rulelist:
                rulelist.append(rule)

    def upload_key(self, keyname, key):
        """Upload a new key to the keystore for use with src_hi.

        See _upload_key().

        @param keyname: filename for the key, must contain "_rsa_" or "_dsa_"
        @type  keyname: str
        @param key: contents of the keyfile
        @type  key: str
        """
        _upload_key(self.keydir, keyname, key)
        
    def list_keys(self):
        """List the names of the stored keys.

        See _list_keys().

        @return: filenames of the stored keys
        @rtype: [str]
        """
        return _list_keys(self.keydir)

    def delete_key(self, keyname):
        """Delete the specified key from keystore if it exists.

        See _delete_key().

        @param keyname: filename of the key
        @type  keyname: str
        """
        _delete_key(self.keydir, keyname)
