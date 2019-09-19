from __future__ import absolute_import

from twisted.trial import unittest

from ....ipv8.REST import json_util as json


class TestJson(unittest.TestCase):

    def test_ensure_serialization(self):
        """
        Tests json.ensure_serializable() produces the result compatible with json.dumps().
        """
        test_dict = {
            'key1': 'value1',
            b'binary_key': b'binary_value',
            'list1': [1, ['2', '3'], {'k1': 'v1', b'k2': b'v2'}],
            'dict': {'k1': 'v1', b'k2': b'v2', 'list': [1, 2, 3]}
        }

        json.dumps(json.ensure_serializable(test_dict))
