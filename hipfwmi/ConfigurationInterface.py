#!/usr/bin/env python

import cgi
import errno
import select
import socket
import syslog
# TODO: when python2.4 is an acceptable dependency, migrate to the
# built-in set-type
from sets import Set
from xml.parsers import expat

from Rules import Rule


revision = '$Id: ConfigurationInterface.py 28 2006-02-01 08:50:43Z jmtapio $'


"""Classes for the interface between ManagementConsole and ManagementLogic.
"""

LISTENINTERFACE=''
PORT=11235


def ignore_eagain(e):
    """Ignore socket.error caused by EAGAIN.

    If the error was not EAGAIN, socket.error is raised again.

    @param e: parameters for socket.error
    @type  e: 2-tuple
    """
    if e[0] != errno.EAGAIN:
        raise socket.error(e)


class ClientConnection(object):
    """Single client connection object.

    This class is owned by the server for keeping track of a single
    connection to a client.

    A connection has three phases/states here:

     1. "read": the client is sending the query.
     2. "turn": the client's request has been received and processing it can
        start. This state exists in order to allow for cleaning up the parser.
     3. "write": we are responding to the query.
     4. "done": the replies have been sent and we are done.
     5. "closed": the connection can be or has been killed.
    """
    def __init__(self, connection, address, mgmtlogic):
        """
        @param connection: connection to the client
        @type  connection: socket object
        @param address: client address
        @type  address: AF_INET6 address tuple
        @param mgmtlogic: reference to Management Logic
        @type  mgmtlogic: ManagementLogic()
        """
        # Connection stuff
        self.con = connection
        self.addr = address
        self.state = 'read'
        self.outbuffer = ''
        self.debug = False
        self.addrlabel = '(%s:%d)' % address[:2]
        self.logic = mgmtlogic
        self.fd = self.con.fileno()
        
        # XML stuff
        self.parser = expat.ParserCreate()
        self.parser.StartElementHandler  = self.handle_start_element
        self.parser.EndElementHandler    = self.handle_end_element
        self.parser.CharacterDataHandler = self.handle_char_data

        # XML state
        self.elementstack = []
        self.echostack = []
        self.keystack = []
        self.keyname = None
        self.want_list_rules = False
        self.want_list_keys  = False
        self.addables = []       # list of rules to add
        self.prependables = []	 # list of rules to prepend
        self.removables = []     # list of rules to remove
        self.empty_rules = False # true if rules should be flushed

    def tick(self):
        """If something needs to be done, do it.

        This function is not expected to block (at least not for a
        long time).
        """
        if self.state == 'read':
            try:
                buf = self.con.recv(1024)
            except socket.error, e:
                ignore_eagain(e)
            else:
                if buf:
                    self.parser.Parse(buf)
                else:  # connection was closed
                    self.close()
        if self.state == 'turn':
            try:
                self.parser.Parse('', True)
            except StandardError, e:
                syslog.syslog(self.addrlabel + ' failed parsing request: ' + e)
                import traceback
                traceback.print_exc(file=open('/tmp/tracback', 'w'))
            self.state = 'write'
            self.process_requests()
        if self.state == 'write':
            if not self.outbuffer:
                self.close()
            else:  # Send stuff from the buffer
                try:
                    i = self.con.send(self.outbuffer[:1400])
                except socket.error, e:
                    if e[0] == errno.EPIPE:
                        syslog.syslog(self.addrlabel + ' broken pipe')
                        self.close()
                    ignore_eagain(e)
                else:
                    self.outbuffer = self.outbuffer[i:]

    def write(self, data):
        """Add data to the output buffer.

        Data will be sent as fast as possible during the ticks.

        @param data: data to send to the client
        @type  data: unicode
        """
        self.outbuffer = self.outbuffer + unicode(data)

    def fileno(self):
        """Get the file descriptor from the connection.

        @return: connections file descriptor
        @rtype:  int
        """
        return self.fd
        #return self.con.fileno()

    def close(self):
        """Close the client connection."""
        self.con.close()
        self.state = 'closed'
        syslog.syslog(self.addrlabel + ': connection closed')

    def enable_debugging(self):
        """Enable more verbose logging."""
        self.debug = True

    # XML handlers
    def handle_start_element(self, name, attrs):
        """XML: Handle start element.

        Push the element into the stack and mark proper internal state
        so that we can process the forthcoming text with proper
        context.

        Relevant elements: X{list_rules}, X{list_keys}, X{rule},
        X{src_hit}, X{src_hi}, X{dst_hit}, X{pkt_type}, X{in_iface},
        X{out_iface}, X{state}, X{empty_rules}, X{upload_key} and
        X{delete_key}.
        """
        self.elementstack.append(name)
        if self.debug:
            syslog.syslog(self.addrlabel + ' start element %s %s' %
                          (name, str(attrs)))

        if name == 'list_rules':
            self.want_list_rules = True
        elif name == 'list_keys':
            self.want_list_keys = True
        elif name == 'rule':
            self.current_rule = Rule()
            self.current_rule.hook = attrs['hook']
            self.current_rule.target = attrs['target']
        elif name == 'src_hit':
            self.current_rule.src_hit = (attrs['not']=='1', attrs['hit'])
        elif name == 'src_hi':
            self.current_rule.src_hi = (attrs['not']=='1', attrs['hi'])
        elif name == 'dst_hit':
            self.current_rule.dst_hit = (attrs['not']=='1', attrs['hit'])
        elif name == 'pkt_type':
            self.current_rule.pkt_type = (attrs['not']=='1', attrs['type'])
        elif name == 'in_iface':
            self.current_rule.in_iface = (attrs['not']=='1', attrs['iface'])
        elif name == 'out_iface':
            self.current_rule.out_iface = (attrs['not']=='1', attrs['iface'])
        elif name == 'state':
            self.current_rule.state = (attrs['not']=='1', attrs['state'],
                                       attrs['vrfy_resp']=='1',
                                       attrs['acpt_mobile']=='1')
        elif name == 'empty_rules':
            self.empty_rules = True
        elif name == 'upload_key':
            self.keyname = attrs['name']
        elif name == 'delete_key':
            self.logic.delete_key(attrs['name'])

    def handle_end_element(self, name):
        """XML: Handle end element.

        Pop one element off the element stack and check if it matched
        the one we are closing. If not, we wreak havoc.

        Relevant elements: X{rule}, X{add_rules}, X{prepend_rules},
        X{remove_rules} and X{upload_key}.
        """
        if self.debug:
            syslog.syslog(self.addrlabel + ' end element %s' % name)
        try:
            topelement = self.elementstack.pop()
        except:
            # too many closing elements
            # TODO: error handling
            self.close()
        else:
            if topelement != name:
                # trying to close wrong element
                # TODO: error handling
                syslog.syslog(self.addrlabel +
                              ' Invalid query, expected </%s>, got </%s>' \
                              % (topelement, name))
                self.close()

        if name == 'rule':
            self.current_rule.complete = True
            if 'add_rules' in self.elementstack:
                self.addables.append(self.current_rule)
            elif 'prepend_rules' in self.elementstack:
                self.prependables.append(self.current_rule)
            elif 'remove_rules' in self.elementstack:
                self.removables.append(self.current_rule)
            else:
                syslog.syslog(self.addrlabel + ' rule in unknown context: %s'
                              % '.'.join(self.elementstack))

        if name == 'upload_key':
            key = ''.join(self.keystack).lstrip()
            self.keystack = []
            if type(key) == type(u''):
                key = key.encode('utf-8')
            self.logic.upload_key(self.keyname, key)

        if not self.elementstack:  # last query-element done
            if self.debug:
                syslog.syslog(self.addrlabel + ' query done, start replying')
            self.state = 'turn'

    def handle_char_data(self, data):
        """XML: Handle char data according to self.xmlstate.

        Relevant elements: X{echo} and X{upload_key}.
        """
        if self.elementstack:
            context = self.elementstack[-1]
            if context == 'echo':
                self.echostack.append(data)
            if context == 'upload_key':
                self.keystack.append(data)

    # Reply stuff
    def process_requests(self):
        """Process the requests received in this connection.

        This function is called when the entire XML request has been received.

        Relevant elements: X{results}, X{echo}, X{emptied_rules},
        X{removed_rules}, X{added_rules}, X{prepended_rules},
        X{list_rules}, X{list_keys} and X{key}.
        """
        syslog.syslog(self.addrlabel + ' replying')
        self.write('<?xml version="1.0"?>\n')
        self.write('<results protoversion="0.1">\n')

        # Echo requests
        if self.echostack:
            if self.debug:
                syslog.syslog(self.addrlabel + ' replying to echo request')
            self.write('<echo>%s</echo>\n' \
                       % cgi.escape(''.join(self.echostack)))
        if self.want_list_rules or self.addables \
               or self.prependables or self.removables:
            rulelist = self.logic.list_rules()
        else:
            rulelist = None

        if self.want_list_keys:
            keylist = self.logic.list_keys()
        else:
            keylist = None

        wanna_write_rules = False
        if self.empty_rules:
            rulelist = []
            wanna_write_rules = True
            self.write('<emptied_rules/>\n')
        if self.removables:
            wanna_write_rules = True
            for rule in self.removables:
                if rule in rulelist:
                    rulelist.remove(rule)
            self.write('<removed_rules count="%d"/>\n' % len(self.removables))
        if self.addables or self.prependables:
            x = len(rulelist)
            rulelist.extend(self.addables)
            wanna_write_rules = True
            if self.addables:
                self.write('<added_rules count="%d"/>\n' % len(self.addables))
                self.addables = []
            x = len(rulelist)
            if self.prependables:
                while self.prependables:
                    rulelist.insert(0, self.prependables.pop())
                self.write('<prepended_rules count="%d"/>\n' \
                           % (len(rulelist) - x))

        if wanna_write_rules:
            self.logic.write_rules(rulelist)
                
        if self.want_list_rules:
            if self.debug:
                syslog.syslog(self.addrlabel + ' replying to list_rules request')
            self.write('<list_rules>\n%s</list_rules>\n' % ''.join(
                [(rule.to_xml()+'\n') for rule in self.logic.list_rules()]))

        if self.want_list_keys:
            if self.debug:
                syslog.syslog(self.addrlabel + ' replying to list_keys request')
            self.write('<list_keys>\n%s</list_keys>\n' % ''.join(
                [('<key name="%s"/>\n' % key) for key in self.logic.list_keys()]))

        self.write('</results>\n')


class ConfigurationInterfaceServer(object):
    """Server implementation of the ConfigurationInterface.

    ConfigurationInterface is used between ManagementConsole (client)
    and ManagementLogic(server).

    The server is implemented asynchronously and it handles all
    connections within the same process.
    """

    def __init__(self, managementlogic, listeniface, listenport):
        """
        @param managementlogic: a reference to the management logic,
                                used for callbacks
        @type  managementlogic: ManagementLogic()
        """
        self.logic = managementlogic
        self.connections = Set()
        self.fdmap = {}
        self.debug = False
        self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setblocking(False)
        self.socket.bind((listeniface, listenport))
        self.socket.listen(5)
        syslog.syslog('Listening to interface %s, port %d.' % (
            repr(listeniface), listenport))

    def try_accept(self):
        """Try to accept a new TCP connection.

        Since the socket is in non-blocking mode, this often fails. If
        accepting the connection succeeds, it is added to the table of
        open connections. Errors are ignored.
        """
        try:
            connection, address = self.socket.accept()
        except socket.error, e:
            ignore_eagain(e)
            return
        connection.setblocking(False)
        if not self.is_client_authorized(address):
            syslog.syslog('Connection denied from unauthorized endpoint %s:%d.'
                          % address[:2])
            try:
                con.close()
            except: pass
            return
        con = ClientConnection(connection, address, self.logic)
        fd = con.fileno()
        self.connections.add(con)
        self.fdmap[fd] = con
        if self.debug:
            con.enable_debugging()
            syslog.syslog('New connection on fd=%d.' % fd)
        syslog.syslog('Accepted connection from %s:%d.' % address[:2])

    def is_client_authorized(self, address):
        """Check if the client is authorized to connect.

        @param address: Client's address
        @type  address: IPv6 address tuple
        @return: true if the client is authorized
        @rtype: bool
        """
        hit = address[0]
        allowed_hits = [line.strip()
                        for line in open('hits.allowed', 'r').readlines()
                        if line.strip()]
        return hit in allowed_hits

    def tick(self):
        """If there is something to do, do it.

        This function should be called from the mainloop when poll()
        indicates that something could be done. This function is not
        expected to block (at least not for a long time).

        This handles generic stuff like cleaning up closed
        connections. The ticks for each connections are handled
        separately.
        """
        if self.debug:
            syslog.syslog('tick')

        dellist = []
        for con in self.connections:
            if con.state == 'closed':
                # the connection was closed so remove it from the
                # table of open connections
                fd = con.fileno()
                dellist.append(con)
                del self.fdmap[fd]
                #self.poller.unregister(fd)

        for con in dellist:
            self.connections.discard(con)

        if self.debug:
            syslog.syslog('tock')

    def enable_debugging(self):
        """Enable more verbose log messages."""
        self.debug = True
        for con in self.connections:
            con.enable_debugging()

    def close(self):
        """Do cleanup."""
        # TODO
        if self.debug:
            syslog.syslog('Closing the listening socket.')

    def run(self):
        """Keep processing until killed.

        Listens to open sockets with poll() and calls tick().

        TODO: add some graceful handling of signals to facilitate a
        clean kill.
        """
        living = True
        syslog.syslog('Processing...')
        while living:
            try:
                poller = select.poll()
            except StandardError, e:
                syslog.syslog('poll() failed: %s' % e)
                break

            # Monitor the pipe to FirewallController
            try:
                poller.register(1, select.POLLHUP | select.POLLERR)
            except StandardError, e:
                syslog.syslog('failed to register stdout for poll(): %s' % e)
                break

            # Monitor the socket for new connections
            try:
                poller.register(self.socket.fileno(), select.POLLIN)
            except StandardError, e:
                syslog.syslog(
                    'failed to register listening socket for poll(): %s' % e)
                break

            for con in self.connections:
                if con.state == 'read':
                    poller.register(con.fileno(),
                                    select.POLLIN |
                                    select.POLLERR |
                                    select.POLLHUP)
                elif con.state == 'write':
                    poller.register(con.fileno(),
                                    select.POLLOUT |
                                    select.POLLERR |
                                    select.POLLHUP)

            items = poller.poll(60*1000)
            if self.debug and not items:
                syslog.syslog('Poll: timeout')                
            for x in items:
                if self.debug:
                    syslog.syslog('Poll: fd=%d, event=0x%x' % x)
                fd = x[0]
                if self.fdmap.has_key(fd):
                    try:
                        self.fdmap[fd].tick()
                    except StandardError, e:
                        syslog.syslog('Error ticking fd=%d: %s' % (fd, e))
                elif fd == 1:  # pipe to FirewallController
                    syslog.syslog('Lost pipe to FirewallController.')
                    self.close()
                    living = False
                    break
                elif fd == self.socket.fileno():
                    self.try_accept()

            try:
                self.tick()
            except StandardError, e:
                syslog.syslog('Error with main tick(): %s' % e)
        syslog.syslog('Closing down ManagementLogic.')


class ConnectionError(IOError):
    """I/O failed on the connection."""
    pass


class ConfigurationInterfaceClient(object):
    """Client implementation of the ConfigurationInterface.

    ConfigurationInterface is used between ManagementConsole (client)
    and ManagementLogic(server).

    The client is implemented synchronously since there does not seem
    to be urgent reason to make it non-blocking.
    """
    def __init__(self, serverhost, port=PORT):
        """
        @param serverhost: hostname of the server
        @type  serverhost: str
        @param port: TCP port of the server
        @type  port: int
        """
        self.serverhost = serverhost
        self.serverport = port
        self.connected = False

        # XML stuff
        self.parser = expat.ParserCreate()
        self.parser.StartElementHandler  = self.handle_start_element
        self.parser.EndElementHandler    = self.handle_end_element
        self.parser.CharacterDataHandler = self.handle_char_data

        # XML state
        self.elementstack = []
        self.replydone = False

        # Reply stuff
        self.rules = [] 	# Filled if list_rules is used.
        self.keys = []          # Filled if list_keys is used.

    def connect(self):
        """Actually open the connection to the server.

        Relevant elements: X{query}.
        """
        assert not self.connected
        
        # Connect
        try:
            self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            # omitting flowid and scope
            self.socket.connect((self.serverhost, self.serverport))
        except:
            raise ConnectionError("Failed to connect to server %s, port %d." \
                                  % (repr(self.serverhost), self.serverport))

        # Send the headers
        self.socket.send('<?xml version="1.0"?>\n')
        self.socket.send('<query protoversion="0.1">\n')

        self.connected = True

    def send(self, data):
        """Send data to the server

        This function wraps self.socket.send(). The purpose for this
        function is to defer connecting to the server until there is
        actually something to send. If we are lucky, sometimes it
        might not be necessary to go through with the connection at
        all.
        """
        if not self.connected:
            self.connect()
        self.socket.send(data)

    def close(self):
        """Close the connection."""
        self.socket.close()

    def commit(self):
        """Flush and end the queries.

        Relevant elements: X{query}.
        """
        self.send('</query>\n')

    def process_replies(self):
        """Read and process the replies sent by the server."""
        while True:
            buf = self.socket.recv(1024)
            if buf:
                self.parser.Parse(buf, False)
            else:
                self.parser.Parse('', True)
                break
        
    def echo(self, data):
        """Send data to the server and ask that it sends it back.

        This request is for testing.

        Relevant elements: X{echo}.

        @param data: test data
        @type  data: unicode
        """
        self.send('<echo>%s</echo>\n' % cgi.escape(unicode(data)))

    def cb_echo(self, data):
        """Callback for echo requests."""
        print 'echo reply: %s' % repr(data)

    def list_rules(self):
        """Ask the server to list rules.

        Relevant elements: X{list_rules}.
        """
        self.send('<list_rules/>\n')

    def cb_list_rules(self, rules):
        import pprint
        print 'got list_rules():'
        pprint.pprint(rules)
        self.rules = rules

    def _send_rules(self, rules):
        """Send the rules to the server.

        This operation needs happen within some other request (such
        as add_rules() or remove_rules() as the rules are not
        meaningful by themselves.

        @param rules: rules to send
        @type  rules: [Rule()]
        """
        for rule in rules:
            self.send(rule.to_xml() + '\n')

    def empty_rules(self):
        """Ask the server to clear the rules.

        Relevant elements: X{empty_rules}.
        """
        self.send('<empty_rules/>\n')

    def add_rules(self, rules):
        """Ask the server to add the rules.

        Relevant elements: X{add_rules}.

        @param rules: rules to add
        @type  rules: [Rule()]
        """
        self.send('<add_rules>\n')
        self._send_rules(rules)
        self.send('</add_rules>\n')

    def prepend_rules(self, rules):
        """Ask the server to prepend the rules.

        Relevant elements: X{prepend_rules}.

        @param rules: rules to prepend
        @type  rules: [Rule()]
        """
        self.send('<prepend_rules>\n')
        self._send_rules(rules)
        self.send('</prepend_rules>\n')

    def remove_rules(self, rules):
        """Ask the server to remove some rules.

        Relevant elements: X{remove_rules}.

        @param rules: rules to remove
        @type  rules: [Rule()]
        """
        self.send('<remove_rules>\n')
        self._send_rules(rules)
        self.send('</remove_rules>\n')

    def upload_key(self, keyname, key):
        """Upload a key for use with --hi.

        Key name should include either "_rsa_" or "_dsa_" depending on which
        type of a key it is.

        Overrides any previously uploaded keys with the same name.

        Relevant elements: X{upload_key}.

        @param keyname: filename for the key
        @type  keyname: str
        @param key: contents of the key (pem)
        @type  key: str
        """
        self.send('<upload_key name="%s">\n' % keyname)
        self.send(key)
        self.send('</upload_key>')

    def list_keys(self):
        """List the names of the keys stored on the firewall.

        Relevant elements: X{list_keys}.

        @return: key names
        @rtype:  [str]
        """
        self.send('<list_keys/>\n')

    def delete_key(self, keyname):
        """Delete a specific key from the keystore on the firewall.

        Relevant elements: X{delete_key}.

        @param keyname: key name
        @type  keyname: str
        """
        self.send('<delete_key name="%s"/>\n' % keyname)

    # XML handlers
    def handle_start_element(self, name, attrs):
        """XML: Handle start element.

        Push the element into the stack and mark proper internal state
        so that we can process the forthcoming text with proper
        context.

        Relevant elements: X{rule}, X{src_hit}, X{src_hi}, X{dst_hit},
        X{pkt_type}, X{in_iface}, X{out_iface}, X{state},
        X{key} and X{list_keys}.
        """
        self.elementstack.append(name)

        if name == 'rule':
            self.current_rule = Rule()
            if 'list_rules' in self.elementstack:
                self.rules.append(self.current_rule)
            self.current_rule.hook = attrs['hook']
            self.current_rule.target = attrs['target']
        elif name == 'src_hit':
            self.current_rule.src_hit = (attrs['not'] == '1', attrs['hit'])
        elif name == 'src_hi':
            self.current_rule.src_hi = (attrs['not'] == '1', attrs['hi'])
        elif name == 'dst_hit':
            self.current_rule.dst_hit = (attrs['not'] == '1', attrs['hit'])
        elif name == 'pkt_type':
            self.current_rule.pkt_type = (attrs['not'] == '1', attrs['type'])
        elif name == 'in_iface':
            self.current_rule.in_iface = (attrs['not'] == '1', attrs['iface'])
        elif name == 'out_iface':
            self.current_rule.out_iface = (attrs['not'] == '1', attrs['iface'])
        elif name == 'state':
            self.current_rule.state = (attrs['not'] == '1', attrs['state'],
                                       attrs['vrfy_resp'] == '1',
                                       attrs['acpt_mobile'] == '1')
        elif name == 'key':
            if 'list_keys' in self.elementstack:
                self.keys.append(attrs['name'])

    def handle_end_element(self, name):
        """XML: Handle end element.

        Pop one element off the element stack and check if it matched
        the one we are closing. If not, we wreak havoc.

        Relevant elements: X{rule}.
        """
        try:
            topelement = self.elementstack.pop()

        except:
            # too many closing elements
            # TODO: error handling
            self.close()
        else:
            if topelement != name:
                # trying to close wrong element
                # TODO: error handling
                self.close()
        if not self.elementstack:  # last result-element done
            # TODO
            pass

        if name == 'rule':
            self.current_rule.complete = True

    def handle_char_data(self, data):
        """XML: Handle char data according to self.xmlstate.

        Relevant elements: X{echo}.
        """
        if self.elementstack:
            context = self.elementstack[-1]
            if context == 'echo':
                self.cb_echo(data)
