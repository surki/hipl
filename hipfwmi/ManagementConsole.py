#!/usr/bin/env python

import sys
import os
import cgi

import Rules
from ConfigurationInterface import ConfigurationInterfaceClient, ConnectionError


class ManagementConsole(object):
    """CGI-script for providing the user interface to the services
    provided by the ManagementLogic via ConfigurationInterface.
    """

    def __init__(self):
        self.servers = {}
        self.sent_headers = False

        # read list of available firewall hosts
        for host in self.get_hosts():
            self.wanna_configure(host)

    def get_hosts(self):
        """List the available firewall hosts.

        @return: list of hostnames
        @rtype:  [str]
        """
        hosts = []
        for host in open('hipmi.fwlist', 'r').readlines():
            host = cgi.escape(host.strip())
            if not host: continue
            hosts.append(host)
        return hosts

    def wanna_configure(self, host):
        """Indicate that we want to use the configuration interface.

        This function must be called before sending configuration requests.

        @param host: firewall host that we want to configure
        @type  host: str
        """
        if self.servers.has_key(host):
            return
        self.servers[host] = ConfigurationInterfaceClient(host)

    def print_headers(self, headers={}, nocache=True):
        """Write the headers to stdout

        Content-type defaults to text/html if it is not explicitly
        specified.

        No-cache-directives are on by default if nocache is true.

        Do nothing if the headers have already been sent.

        @param headers: headers to be sent
        @type  headers: dict of str:str-pairs
        @param nocache: indicate that the page should not be cacheable
        @type  nocache: bool
        """
        if self.sent_headers:
            return
        if not headers.has_key('Content-Type'):
            headers['Content-Type'] = 'text/html'
        if nocache:
            if not headers.has_key('Cache-Control'):
                headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
            if not headers.has_key('Pragma'):
                headers['Pragma'] = 'no-cache'

        sys.stdout.write('\r\n'.join(
                ['%s: %s' % t for t in headers.items()]
                ) + '\r\n\r\n')
        sys.stdout.flush()
        self.sent_headers = True

    def process_request(self):
        """Process the CGI request"""
        self.form = cgi.FieldStorage()

        # select function which to call based on form input
        do = 'default'
        if self.form.has_key('do'):
            do = self.form['do'].value

        # call the selected function
        if self.__class__.__dict__.has_key('do_'+do):
            try:
                self.__class__.__dict__['do_'+do](self)
            except ConnectionError, e:
                # Catch failed connections.
                self.do_default(error=e)
        else:
            self.do_default()

    def do_default(self, error=None, msg=None):
        """Default page.

        @param error: optional error message
        @type  error: str
        """
        self.print_headers()
        print '''<html><body><h1>HIP firewall management interface</h1>
        '''
        if msg:
            print '<p><b>%s</b></p>' % cgi.escape(str(msg))

        if error:
            print '<p><b color="red">%s</b><p>' % cgi.escape(str(error))

        print '''
        <h2>Choose firewall to manage</h2>

        <form action="ManagementConsole.cgi" method="GET">
        <input type="hidden" name="do" value="show_rules">
        <p>
        <select name="host">
        '''

        hosts = self.servers.keys()
        hosts.sort()
        for host in hosts:
            print '''<option value="%s">%s</option>''' % \
                  (host, host)

        print """</select>
        <input type="submit" value="Select">
        </p>
        </form>

        <h2>My Organization's Customized Forms</h2>

        <ul>
        <li><a href="ManagementConsole.cgi?do=org_new_host">Granting access to a new host</a>
        </ul>

        </body></html>"""

    def do_show_rules(self):
        """Page for listing and manipulating the rules."""
        self.print_headers()

        errmsg = ''
        
        if self.form.has_key('host'):
            host = self.form['host'].value
        else:
            return self.do_default("No host specified for show_rules!")
        if not self.servers.has_key(host):
            return self.do_default("Invalid firewall host: %s!" % host)
        client = self.servers[host]

        if self.form.has_key('empty_rules'):
            client.empty_rules()

        if self.form.has_key('delrule'):
            client.remove_rules([Rules.Rule(self.form['delrule'].value)])

        if self.form.has_key('add_rule'):
            hook = None
            target = None
            cond = ''
            ok = True
            
            if self.form.has_key('rulehook'):
                hook = self.form['rulehook'].value
            if hook not in ('INPUT', 'OUTPUT', 'FORWARD'):
                errmsg = '<p><b color="red">Invalid hook %s, failed to add!</b></p>' \
                         % cgi.escape(str(hook))
                ok = False

            if self.form.has_key('ruletarget'):
                target = self.form['ruletarget'].value
            if target not in ('ACCEPT', 'DROP'):
                errmsg = '<p><b color="red">Invalid target %s, failed to add!</b></p>' \
                         % cgi.escape(str(target))
                ok = False

            #if self.form.has_key('rulecond'):
            #    cond = self.form['rulecond'].value
            #    if '\n' in cond or '\r' in cond:
            #        errmsg = '<p><b color="red">Invalid rule, failed to add!</b></p>'
            #        ok = False

            rulecond = []

            if self.form.has_key('src_hi'):
                rulecond.append('--hi')
                if self.form.has_key('src_hi_not'): rulecond.append('!')
                rulecond.append(self.form['src_hi'].value)
            if self.form.has_key('src_hit'):
                rulecond.append('-src_hit')
                if self.form.has_key('src_hit_not'): rulecond.append('!')
                rulecond.append(self.form['src_hit'].value)
            if self.form.has_key('dst_hit'):
                rulecond.append('-dst_hit')
                if self.form.has_key('dst_hit_not'): rulecond.append('!')
                rulecond.append(self.form['dst_hit'].value)
            if self.form.has_key('in_iface'):
                rulecond.append('-i')
                if self.form.has_key('in_iface_not'): rulecond.append('!')
                rulecond.append(self.form['in_iface'].value)
            if self.form.has_key('out_iface'):
                rulecond.append('-o')
                if self.form.has_key('out_iface_not'): rulecond.append('!')
                rulecond.append(self.form['out_iface'].value)
            if self.form.has_key('pkt_type'):
                rulecond.append('-type')
                if self.form.has_key('pkt_type_not'): rulecond.append('!')
                rulecond.append(self.form['pkt_type'].value)
            if self.form.has_key('state'):
                rulecond.append('-state')
                if self.form.has_key('state_not'): rulecond.append('!')
                rulecond.append(self.form['state'].value)
                if self.form.has_key('vrfy_responder'):
                    rulecond.append('--verify_responder')
                if self.form.has_key('acpt_mobile'):
                    rulecond.append('--accept_mobile')

            cond = ' '.join(rulecond)

            if ok:
                try:
                    rule = Rules.Rule('%s %s %s' % (hook, cond, target))
                except StandardError:
                    errmsg = '<p><b color="red">Invalid rule, failed to add!</b></p>'
                else:
                    client.add_rules([rule])
                

        client.list_rules()
        client.list_keys()
        client.commit()
        client.process_replies()

        def visualize_rule(rule):
            """Create a html table-row presentation about a single rule."""
            return ('<tr><td>%s</td><td>%s</td><td>%s</td>'
                    '<td><button type="submit" name="delrule" value="%s">'
                    'Remove</button></td>'
                    '</tr>'
                    ) % (cgi.escape(rule.hook),
                         cgi.escape(rule.target),
                         cgi.escape(rule.conditions_to_text(True)),
                         cgi.escape(rule.to_text()),
                         )
        
        print """<html><head><title>Firewall host: %(server)s</title></head>
        <body>
        <h1>Firewall host: %(server)s</h1>

        <p>Choose <a href="ManagementConsole.cgi">another host</a>.</p>

        <h2>Current HIP firewall rules</h2>

        %(errmsg)s

        <form action="ManagementConsole.cgi" method="POST">

        <input type="hidden" name="do" value="show_rules">
        <input type="hidden" name="host" value="%(server)s">

        <table border="1">
        <thead>
        <tr>
        <td><b>Hook</b></td> <td><b>Action</b></td> <td><b>Conditions</b></td>
        <td></td>
        </tr>
        </thead>
        <tbody>
        %(rules)s
        </tbody>
        </table>

        <p>
        <input type="submit" name="refresh" value="Refresh list">
        </p>

        <hr>

        <p>
        New rule:<br>
        On <select name="rulehook">
          <option value="INPUT">INPUT</option>
          <option value="OUTPUT">OUTPUT</option>
          <option forward="FORWARD">FORWARD</option>
        </select>
        do <select name="ruletarget">
          <option value="ACCEPT">ACCEPT</option>
          <option value="DROP">DROP</option>
        </select><br>
        If conditions match:
        <!-- TODO: separate this field into parts -->
        <!-- TODOING: <input type="text" size="50" maxsize="200" name="rulecond"> -->
        <table border="0" cellpadding="4">
        <tbody>

        <tr>
        <td align="right">Source HIT:</td>
        <td><input type="text" size="40" name="src_hit"></td>
        <td><input type="checkbox" name="src_hit_not" value="1">Reverse condition</td>
        </tr>
        
        <tr>
        <td align="right">Destination HIT:</td>
        <td><input type="text" size="40" name="dst_hit"></td>
        <td><input type="checkbox" name="dst_hit_not" value="1">Reverse condition</td>
        </tr>
        
        <tr>
        <td align="right">Source Host Identity:</td>
        <td>
        <select name="src_hi">
          <option value="">Any</option>
          %(hi_options)s
        </select>
        </td>
        <td><input type="checkbox" name="src_hi_not" value="1">Reverse condition</td>
        </tr>

        <tr>
        <td align="right">Incoming interface:</td>
        <td><input type="text" size="10" name="in_iface"></td>
        <td><input type="checkbox" name="in_iface_not" value="1">Reverse condition</td>
        </tr>
        
        <tr>
        <td align="right">Outgoing interface:</td>
        <td><input type="text" size="10" name="out_iface"></td>
        <td><input type="checkbox" name="out_iface_not" value="1">Reverse condition</td>
        </tr>
        
        <tr>
        <td align="right">Packet type:</td>
        <td>
        <select name="pkt_type">
          <option value="">Any</option>
          <option value="I1" value="I1">I1</option>
          <option value="R1" value="R1">R1</option>
          <option value="I2" value="I2">I2</option>
          <option value="R2" value="R2">R2</option>
          <option value="CER" value="CER">CER</option>
          <option value="UPDATE" value="UPDATE">UPDATE</option>
          <option value="NOTIFY" value="NOTIFY">NOTIFY</option>
          <option value="CLOSE" value="CLOSE">CLOSE</option>
          <option value="CLOSE_ACK" value="CLOSE_ACK">CLOSE_ACK</option>
        </select>
        </td>
        <td><input type="checkbox" name="pkt_type_not" value="1">Reverse condition</td>
        </tr>

        <tr>
        <td align="right">HIP Association's state:</td>
        <td>
        <select name="state">
        <option value="">Any</option>
        <option value="NEW">NEW</option>
        <option value="ESTABLISHED">ESTABLISHED</option>
        </select>
        <input type="checkbox" name="vrfy_responder" value="1">Verify responder
        <input type="checkbox" name="acpt_mobile" value="1">Accept mobile
        </td>
        <td><input type="checkbox" name="state_not" value="1">Reverse condition</td>
        </tr>
        
        </tbody>
        </table>
        <br>
        <input type="submit" name="add_rule" value="Add new rule">
        </p>

        <hr>

        <p>
        <input type="submit" name="empty_rules" value="Flush rules">
        </p>

        </form>

        <hr>

        <p>
        <a href="ManagementConsole.cgi?host=%(server)s&do=keystore">
        Manage stored keys
        </a>
        </p>

        </body></html>
        """ % {
            'server': host,
            'rules': '\n'.join([visualize_rule(rule)
                                for rule in client.rules]),
            'hi_options': '\n'.join([('<option name="%s">%s</option>\n' %
                                      (s, s)) for s in client.keys]),
            'errmsg': errmsg,
            }

    def do_keystore(self):
        """Page for listing and manipulating the keys stored on the firewall hosts."""
        self.print_headers()

        errmsg = ''
        msg = ''

        if self.form.has_key('host'):
            host = self.form['host'].value
        else:
            return self.do_default("No host specified for keystore!")
        if not self.servers.has_key(host):
            return self.do_default("Invalid firewall host: %s!" % host)
        client = self.servers[host]

        if self.form.has_key('upload_key'):
            keyname = None
            key = None
            ok = True

            if self.form.has_key('keyname'):
                keyname = self.form['keyname'].value.strip()
            if not keyname:
                errmsg = '<p><b color="red">Missing key name!</b></p>'
                ok = False

            if self.form.has_key('key'):
                key = self.form['key'].value
            if not key:
                errmsg = '<p><b color="red">Missing key!</b></p>'
                ok = False

            if ok:
                client.upload_key(keyname, key)
                msg = '<p><b>Key uploaded.</b></p>'

        if self.form.has_key('delkeyname'):
            keyname = self.form['delkeyname'].value
            client.delete_key(keyname)

        client.list_keys()
        client.commit()
        client.process_replies()

        def visualize_key(keyname):
            keytype = "unknown"
            if '_rsa_' in keyname:
                keytype = "RSA"
            elif '_dsa_' in keyname:
                keytype = "DSA"
            return ('<tr><td>%s</td> <td>%s</td> <td>'
                    '<button type="submit" name="delkeyname" value="%s">'
                    'Delete</button></td></tr>'
                    ) % (keyname, keytype, keyname)

        print '''<html><head><title>Firewall keystore: %(server)s</title></head>
        <body>
        <h1>Firewall keystore: %(server)s</h1>

        <p>Back to
        <a href="ManagementConsole.cgi?do=show_rules&host=%(server)s">
        rule list.</a>
        </p>

        <h2>Currently stored keys</h2>

        %(msg)s
        %(errmsg)s

        <form action="ManagementConsole.cgi" method="POST">

        <input type="hidden" name="do" value="keystore">
        <input type="hidden" name="host" value="%(server)s">

        <table border="1">
        <thead>
        <tr>
        <td><b>Key filename</b></td> <td><b>Type</b></td> <td></td>
        </tr>
        </thead>
        <tbody>
        %(keys)s
        </tbody>
        </table>

        <p>
        <input type="submit" name="refresh" value="Refresh list">
        </p>

        <hr>

        <p>
        <b>Upload new key:</b><br>
        Filename: <input type="text" name="keyname" size="50" maxsize="100">
        <input type="file" name="key">
        <input type="submit" name="upload_key" value="Send"><br>
        <i>Note: the key must be in PEM format and it's filename must have
        <tt>_rsa_</tt> or <tt>_dsa_</tt> in it to denote it's type.</i>
        </p>

        </body></html>
        ''' % {
            'server': host,
            'keys': '\n'.join([visualize_key(keyname)
                                for keyname in client.keys]),
            'msg': msg,
            'errmsg': errmsg,
            }

    def do_org_new_host_apply(self):
        """Logic part: Sample of an organization-customized page for adding a new host to the network."""

        msg = ''
        errmsg = ''

        ok = True
	src_hit = None
        name = None
        keytype = None
        key = None
        roadwarrior = False
	if self.form.has_key('src_hit'):
	    src_hit = self.form['src_hit'].value.strip()
	if not src_hit:
	    errmsg = '<p><b color="red">Missing hit!</b></p>'
	    ok = False
        #if self.form.has_key('name'):
        #    name = self.form['name'].value.strip().replace(' ', '_')
        #if not name:
        #    errmsg = '<p><b color="red">Missing hostname!</b></p>'
        #    ok = False
        #if self.form.has_key('keytype'):
        #    keytype = self.form['keytype'].value.strip()
        #if not keytype or keytype not in ('dsa', 'rsa'):
        #    errmsg = '<p><b color="red">Invalid keytype!</b></p>'
        #    ok = False
        #if self.form.has_key('key'):
        #    key = self.form['key'].value.lstrip()
        #if not key:
        #    errmsg = '<p><b color="red">Missing key!</b></p>'
        #    ok = False

        #if self.form.has_key('roadwarrior'):
        #    roadwarrior = True

        if ok:
            #keyname = '%s_%s_key.pub' % (name, keytype)

            in_rule  = Rules.Rule('INPUT -src_hit %s ACCEPT' % src_hit)
            fwd_rule = Rules.Rule('FORWARD -src_hit %s ACCEPT' % src_hit)
            webserver_rule = Rules.Rule('INPUT -src_hit %s -dst_hit 4078:4163:62c8:897:f60e:7d69:bd6a:4e0e ACCEPT'
				        % src_hit)

            hosts = self.get_hosts()
            for host in hosts:
                self.wanna_configure(host)
		#self.servers[host].upload_key(keyname, key)
                #msg = msg + 'key to %s; ' % host
                if 'gateway' in host:
                    self.servers[host].prepend_rules([webserver_rule, fwd_rule])
                else:
                    self.servers[host].prepend_rules([in_rule])
                msg = msg + 'rules to %s; ' % host

                self.servers[host].commit()
                msg = msg + 'commit %s;' % host

            for host in hosts:
                self.servers[host].process_replies()
                msg = msg + 'replies %s;' % host

            msg = "Access granted for a new host."

            return self.do_default(errmsg, msg)
        return self.do_org_new_host(errmsg, msg)

    def do_org_new_host(self, errmsg='', msg=''):
        """Form part: Sample of an organization-customized page for adding a new host to the network."""

        self.print_headers()

        print '''<html><head>
        <title>Organization-customized sample form: add a new host</title>
        </head>

        <body>
        <h1>Add access to network for a new HIP host</h1>

        %(msg)s
        %(errmsg)s

        <form action="ManagementConsole.cgi" method="POST">

        <input type="hidden" name="do" value="org_new_host_apply">

        <table border="0" spacing="5">
        <tbody>

        <tr>
        <td align="right"><b>New HIT:</b></td>
        <td align="left"><input type="text" name="src_hit" size="50"></td>
        </tr>
<!--
        <tr>
        <td align="right"><b>Host identity:</b></td>
        <td align="left"><input type="file" name="key"></td>
        </tr>

        <tr>
        <td align="right"><b>Key type:</b></td>
        <td align="left"><select name="keytype">
          <option value="rsa">RSA</option>
          <option value="dsa">DSA</option>
        </select></td>
        </tr>

        <tr><td colspan="2"><hr></tr>

        <tr>
        <td><b>Roadwarrior access:</b></td>
        <td><input type="checkbox" name="roadwarrior" value="Allow"></td>
        </tr>

        <tr><td colspan="2"><hr></tr>
-->
        <tr>
        <td></td>
        <td align="left">
        <input type="submit" name="submit" value="Grant host access">
        </td>
        </tr>

        </tbody>
        </table>

        </form>

        </body>
        </html>
        ''' % {
            'msg': msg,
            'errmsg': errmsg,
            }


if __name__ == '__main__':
    console = ManagementConsole()

    # test if running as a CGI-script
    if os.environ.get('GATEWAY_INTERFACE', '').startswith('CGI/'):
        console.process_request()
    else:
        print "Running from console."

        # TODO: add interface for testing

        console.wanna_configure('::1')
        client = console.servers['::1']
        client.echo('qwerty')
        client.commit()
        client.process_replies()

