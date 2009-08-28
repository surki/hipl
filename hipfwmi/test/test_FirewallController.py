#!/usr/bin/env python
import sys
import unittest

from FirewallController import FirewallController


class ControllerTest(unittest.TestCase):
    def testbasics(self):
        controller = FirewallController()
        

def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ControllerTest))
    return suite

if __name__ == '__main__':
    unittest.main()
