#!/usr/bin/env python
import sys
import unittest

import ManagementConsole


class ConsoleTest(unittest.TestCase):
    def testbasics(self):
        console = ManagementConsole.ManagementConsole()


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ConsoleTest))
    return suite

if __name__ == '__main__':
    unittest.main()
