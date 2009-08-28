#!/usr/bin/env python
import sys
import os
import unittest

import ManagementLogic
import Rules

class LogicTest(unittest.TestCase):
    def test_basics(self):
        logic = ManagementLogic.ManagementLogic(
            '::1', 17420, '/dev/null', '/var/lib/hipfw/keys')

    def test_list_rules(self):
        # TODO: make the RuntimeWarning go away
        fwrulefile = os.tempnam(None, 'tmprulefile')
        f = open(fwrulefile, 'w')
        f.write('INPUT -i eth0 ACCEPT\n')
        f.write('FORWARD -o lo DROP\n')
        f.write('\n')
        f.write('OUTPUT -state NEW --verify_responder -type ! CLOSE ACCEPT\n')
        f.close()
        results = ManagementLogic._list_rules(fwrulefile)
        assert len(results) == 3
        assert results[0].to_text() == 'INPUT -i eth0 ACCEPT'
        assert results[1].to_xml() == \
               ''.join(('<rule hook="FORWARD" target="DROP">',
                        '<out_iface not="0" iface="lo"/>',
                        '</rule>'))
        os.unlink(fwrulefile)

        newrule = Rules.Rule('INPUT -i eth0 ACCEPT')
        assert newrule in results
        newrule = Rules.Rule('OUTPUT -o lo ACCEPT')
        assert newrule not in results

    def test_add_rules(self):
        fwrulefile = os.tempnam(None, 'tmprulefile')
        rule1 = Rules.Rule('FORWARD -o eth1 -i eth0 ACCEPT')
        rule2 = Rules.Rule('OUTPUT ACCEPT')
        ManagementLogic._write_rules([rule1, rule2], fwrulefile)
        lines = open(fwrulefile).readlines()
        self.assertEqual(lines[0], 'FORWARD -i eth0 -o eth1 ACCEPT\n')
        self.assertEqual(lines[1], 'OUTPUT ACCEPT\n')
        rule3 = Rules.Rule('FORWARD -i eth1 -o eth0 ACCEPT')
        rules = ManagementLogic._list_rules(fwrulefile)
        rules.append(rule3)
        ManagementLogic._write_rules(rules, fwrulefile)
        lines = open(fwrulefile).readlines()
        self.assertEqual(lines[0], 'FORWARD -i eth0 -o eth1 ACCEPT\n')
        self.assertEqual(lines[1], 'OUTPUT ACCEPT\n')
        self.assertEqual(lines[2], 'FORWARD -i eth1 -o eth0 ACCEPT\n')

    def test_keystore(self):
        keystore = '/var/lib/hipfw/keys'
        list1 = ManagementLogic._list_keys(keystore)
        ManagementLogic._upload_key(keystore, 'test_key_rsa_foo1', 'foo1')
        ManagementLogic._upload_key(keystore, 'test_key_dsa_foo2', 'foo2')
        list2 = ManagementLogic._list_keys(keystore)
        self.assert_('test_key_rsa_foo1' in list2)
        self.assert_('test_key_dsa_foo2' in list2)
        self.assert_(len(list1) <= len(list2))
        ManagementLogic._delete_key(keystore, 'test_key_foo_foo3')
        try:
            ManagementLogic._upload_key(keystore, 'test_key_foo_foo3', 'foo3')
            self.assert_(0, '_upload_key() without _rsa_ or _dsa_ in name should have caused ValueError')
        except ValueError:
            pass
        ManagementLogic._delete_key(keystore, 'test_key_rsa_foo1')
        self.assert_('test_key_rsa_foo1' not in
                     ManagementLogic._list_keys(keystore))
        ManagementLogic._delete_key(keystore, 'test_key_dsa_foo2')
        

def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(LogicTest))
    return suite

if __name__ == '__main__':
    unittest.main()
