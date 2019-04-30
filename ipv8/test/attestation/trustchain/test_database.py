from __future__ import absolute_import

import unittest

from six.moves import xrange

from ....attestation.trustchain.block import TrustChainBlock
from ....attestation.trustchain.database import TrustChainDB
from ....keyvault.crypto import default_eccrypto
from ....test.attestation.trustchain.test_block import TestBlock


class TestTrustChainDB(unittest.TestCase):

    def setUp(self):
        self.db = TrustChainDB(u":memory:", 'temp_trustchain')

    def test_connected_users(self):
        """
        Test returning connected users for a given public key works.
        """
        user_key = default_eccrypto.generate_key(u"curve25519")
        public_key = user_key.pub().key_to_bin()

        # No users initially
        self.assertEqual(len(self.db.get_users()), 0)
        self.assertEqual(len(self.db.get_connected_users(public_key)), 0)

        # Add 10 random blocks, implying 10 unique peers
        random_blocks = []
        for i in range(0, 10):
            block = TestBlock()
            random_blocks.append(block)
            self.db.add_block(block)

        self.assertEqual(len(self.db.get_users()), 10)
        self.assertEqual(len(self.db.get_connected_users(public_key)), 0)

        # Create 5 link block implying 5 connected peers to the current user
        for i in xrange(0, 5):
            block = TrustChainBlock.create(b'test', {b'id': i}, self.db, public_key, link=random_blocks[i])
            self.db.add_block(block)

        self.assertEqual(len(self.db.get_users()), 11)
        self.assertEqual(len(self.db.get_connected_users(public_key)), 5)
