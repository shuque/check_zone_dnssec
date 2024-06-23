#!/usr/bin/env python3

"""
A very basic functional test.
"""

import unittest
import json

from reslib.prefs import Prefs
from reslib.lookup import initialize_dnssec
from check_zone_dnssec import ZoneChecker, process_arguments

def get_checker_status(checker):
    """Get status of Checker class"""
    return json.loads(checker.return_status())

class TestZoneChecker(unittest.TestCase):

    """Test Class"""

    def setUp(self):
        Prefs.DNSSEC = True
        initialize_dnssec()

    def test_example_com(self):
        """Test for example.com zone"""

        config = process_arguments(("example.com", "example.com", "SOA"))
        checker = ZoneChecker(config.zone, config.recname, config.rectype,
                              config=config)
        checker.check_nameservers()
        status = get_checker_status(checker)
        self.assertTrue(status['success'], 'Incorrect test')


if __name__ == '__main__':
    unittest.main()
