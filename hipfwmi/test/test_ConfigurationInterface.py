#!/usr/bin/env python
import sys
import unittest

import ConfigurationInterface

class CfgIfaceTest(unittest.TestCase):
    def testbasics(self):
        pass


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(CfgIfaceTest))
    return suite

if __name__ == '__main__':
    unittest.main()
