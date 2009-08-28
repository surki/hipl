#!/usr/bin/env python

# This module has been mimicked from python2.4's bsddb's tests

import sys
sys.path.append('.')

import unittest


def suite():
    test_modules = [
        'test_FirewallController',
        'test_ManagementLogic',
        'test_ManagementConsole',
        'test_ConfigurationInterface',
        ]
    alltests = unittest.TestSuite()
    for name in test_modules:
        module = __import__(name)
        alltests.addTest(module.test_suite())
    return alltests


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
    
