#!/usr/bin/env python

"""Code to manage and contain the rules for the HIP firewall.

NOTE: the pieces of code for parsing the rules from XML are within the
XML parsers in ConfigurationInterface.
"""

revision = "$Id: Rules.py 31 2006-02-01 08:52:34Z jmtapio $"


class Rule(object):
    """Single HIP-firewall rule"""

    def __init__(self, rulestring=''):
        """
        @param rulestring: a single firewall rule as text
        @type  rulestring: str
        """
        # Reset the variables and tuples to default values.
        self.hook = None
        self.target = None
                       #  !      hit
        self.src_hit   = (False, None)
                       #  !      hi (filename)
        self.src_hi    = (False, None)
                       #  !      hit
        self.dst_hit   = (False, None)
                       #  !      pkt_type
        self.pkt_type  = (False, None)
                       #  !      interface
        self.in_iface  = (False, None)
                       #  !      interface
        self.out_iface = (False, None)
                       #  !      state, vrfy_resp, acpt_mobile
        self.state     = (False, None,  False,     False)

        # This flag is used to mark when the rule has been fully
        # constructed. Parsing has not been completed if this is
        # False. (This applies to the XML parsers aswell.
        self.complete = False

        self._parse(rulestring)

    def __eq__(self, other):
        """Compare equality."""
        try:
            return (isinstance(other, Rule) and
                    (self.to_text() == other.to_text()))
        except AttributeError:
            return False

    def __ne__(self, other):
        """Compare non-equality."""
        return not self.__eq__(other)

    def __str__(self):
        """Make a string representation.

        The produced output is not parseable and should mainly be used
        for debugging.
        """
        return '<Rule: %s>' % self.to_text()

    def to_xml(self):
        """Generate xml from the rule.

        The produced output can be sent as is within the XML-replies.

        Relevant elements: X{rule}, X{src_hit}, X{src_hi}, X{dst_hit},
        X{pkt_type}, X{in_iface}, X{out_iface} and X{state}.
        """
        if not self.complete:
            return '<rule></rule>'
        l = []
        l.append('<rule hook="%s" target="%s">' % (self.hook, self.target))
        if self.src_hit[1]:
            l.append('<src_hit not="%d" hit="%s"/>' % (int(self.src_hit[0]),
                                                       self.src_hit[1]))
        if self.src_hi[1]:
            l.append('<src_hi not="%d" hi="%s"/>' % (int(self.src_hi[0]),
                                                       self.src_hi[1]))
        if self.dst_hit[1]:
            l.append('<dst_hit not="%d" hit="%s"/>' % (int(self.dst_hit[0]),
                                                       self.dst_hit[1]))
        if self.pkt_type[1]:
            l.append('<pkt_type not="%d" type="%s"/>' % (int(self.pkt_type[0]),
                                                       self.pkt_type[1]))
        if self.in_iface[1]:
            l.append('<in_iface not="%d" iface="%s"/>'
                     % (int(self.in_iface[0]), self.in_iface[1]))
        if self.out_iface[1]:
            l.append('<out_iface not="%d" iface="%s"/>'
                     % (int(self.out_iface[0]), self.out_iface[1]))
        if self.state[1]:
            l.append('<state not="%d" state="%s" vrfy_resp="%d" acpt_mobile="%d"/>'
                     % (int(self.state[0]), self.state[1],
                        int(self.state[2]), int(self.state[3]))
                     )
        l.append('</rule>')
        return ''.join(l)

    def to_text(self):
        """Generate the rule text.

        The produced output should be valid for passing to the HIP
        firewall.
        """
        assert self.hook
        assert self.target
        return ' '.join([s for s in
                         (self.hook,
                         self.conditions_to_text(),
                         self.target)
                         if s]
                        )

    def conditions_to_text(self, resolve=False):
        """Generate the rule text for only the conditions.

        @param resolve: if true, hit reverse-resolving is attempted
        @type  resolve: bool
        """
        if not self.complete: return ''
        l = []

        if resolve:
            hit_resolve = self.resolve_hit
        else:
            hit_resolve = lambda x: x

        if self.src_hit[1]:
            l.append('-src_hit')
            if self.src_hit[0]:
                l.append('!')
            l.append(hit_resolve(self.src_hit[1]))

        if self.src_hi[1]:
            l.append('--hi')
            if self.src_hi[0]:
                l.append('!')
            l.append(self.src_hi[1])

        if self.dst_hit[1]:
            l.append('-dst_hit')
            if self.dst_hit[0]:
                l.append('!')
            l.append(hit_resolve(self.dst_hit[1]))

        if self.pkt_type[1]:
            l.append('-type')
            if self.pkt_type[0]:
                l.append('!')
            l.append(self.pkt_type[1])

        if self.in_iface[1]:
            l.append('-i')
            if self.in_iface[0]:
                l.append('!')
            l.append(self.in_iface[1])

        if self.out_iface[1]:
            l.append('-o')
            if self.out_iface[0]:
                l.append('!')
            l.append(self.out_iface[1])

        if self.state[1]:
            l.append('-state')
            if self.state[0]:
                l.append('!')
            l.append(self.state[1])
            if self.state[2]:
                l.append('--verify_responder')
            if self.state[3]:
                l.append('--accept_mobile')

        return ' '.join(l)

    def _parse(self, s):
        """Parse the string into components

        This function parses the rule in HIP firewall native syntax.

        The code for parsing the rules in XML format is in
        ConfigurationInterface.
        """
        parts = s.split()
        if not parts:  # empty rule
            return

        # hook
        try:
            hook = parts.pop(0)  # take the first token
        except IndexError:
            raise ValueError("Rule missing hook.")
        if hook in ('INPUT', 'OUTPUT', 'FORWARD'):
            self.hook = hook
        else:
            raise ValueError("Invalid hook: %s." % hook)

        # target
        try:
            target = parts.pop()  # take the last token
        except IndexError:
            raise ValueError("Rule missing target.")
        if target in ('ACCEPT', 'DROP'):
            self.target = target
        else:
            raise ValueError("Invalid target: %s." % target)

        # conditions
        while parts:
            param = parts.pop(0)
            reversed = False  # !-flag

            if param == '-src_hit':
                try:
                    next = parts.pop(0)
                    if next == '!':
                        reversed = True
                        next = parts.pop(0)
                    self._assert_is_hit(next)
                    self.src_hit = (reversed, next)
                except IndexError:
                    raise ValueError("Missing hit for -src_hit.")
            elif param == '--hi':
                try:
                    next = parts.pop(0)
                    if next == '!':
                        reversed = True
                        next = parts.pop(0)
                    self.src_hi = (reversed, next)
                except IndexError:
                    raise ValueError("Missing key name for --hi.")
            elif param == '-dst_hit':
                try:
                    next = parts.pop(0)
                    if next == '!':
                        reversed = True
                        next = parts.pop(0)
                    self._assert_is_hit(next)
                    self.dst_hit = (reversed, next)
                except IndexError:
                    raise ValueError("Missing hit for -dst_hit.")
            elif param == '-type':
                try:
                    next = parts.pop(0)
                    if next == '!':
                        reversed = True
                        next = parts.pop(0)
                    if next in ('I1', 'R1', 'I2', 'R2', 'CER', 'UPDATE',
                                'NOTIFY', 'CLOSE', 'CLOSE_ACK'):
                        self.pkt_type = (reversed, next)
                    else:
                        raise ValueError("Invalid packet type: %s." % next)
                except IndexError:
                    raise ValueError("Missing packet type for -type.")
            elif param == '-i':
                try:
                    next = parts.pop(0)
                    if next == '!':
                        reversed = True
                        next = parts.pop(0)
                    self.in_iface = (reversed, next)
                except IndexError:
                    raise ValueError("Missing interface for -i.")
            elif param == '-o':
                try:
                    next = parts.pop(0)
                    if next == '!':
                        reversed = True
                        next = parts.pop(0)
                    self.out_iface = (reversed, next)
                except IndexError:
                    raise ValueError("Missing interface for -o.")
            elif param == '-state':
                verify_responder = False
                accept_mobile = False
                
                try:
                    next = parts.pop(0)
                    if next == '!':
                        reversed = True
                        next = parts.pop(0)
                except IndexError:
                    raise ValueError("Missing state for -state.")
                state = next
                if state not in ('NEW', 'ESTABLISHED'):
                    raise ValueError("Invalid state: %s." % state)
                while parts:
                    if parts[0] == '--verify_responder':
                        verify_responder = True
                    elif parts[0] == '--accept_mobile':
                        accept_mobile = True
                    else:
                        break
                    parts.pop(0)
                self.state = (reversed, state, verify_responder, accept_mobile)

            else:
                raise ValueError('Invalid switch: %s' % param)
        self.complete = True

    def resolve_hit(self, hit):
        """Try to resolve hit into a name.

        If can't resolve, return hit as is.

        @param hit: hit to resolve
        @type  hit: str
        @return: hostname or hit
        @rtype:  str
        """
        try:
            l = [line.split()
                 for line in open('/etc/hip/hosts').readlines()
                 if line.strip() and not line.strip().startswith('#')]
            for line in l:
                if len(line) >= 2 and (line[0] == hit):
                    return line[1]
        except: pass
        return hit

    def _assert_is_hit(self, hit):
        """Test if the string looks like a valid hit.

        Raise ValueError if not.

        @param hit: hit representation
        @type  hit: str
        """
        # TODO: improvement needed
        if hit:
            for c in hit.lower():
                if c not in '0123456789abcdef:':
                    raise ValueError("Invalid char %s in hit." % repr(c))
            return True
        raise ValueError("Expected a hit, got %s." % repr(hit))

