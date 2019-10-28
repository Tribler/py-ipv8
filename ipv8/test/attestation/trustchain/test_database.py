import unittest

from ....attestation.trustchain.block import TrustChainBlock
from ....attestation.trustchain.database import TrustChainDB
from ....keyvault.crypto import default_eccrypto
from ....test.attestation.trustchain.test_block import TestBlock


class TestTrustChainDB(unittest.TestCase):

    def setUp(self):
        self.key = default_eccrypto.generate_key(u"curve25519")
        self.public_key = self.key.pub().key_to_bin()
        self.db = TrustChainDB(u":memory:", 'temp_trustchain', my_pk=self.public_key)

    def test_connected_users(self):
        """
        Test returning connected users for a given public key works.
        """
        self.assertEqual(len(self.db.get_users()), 0)
        self.assertEqual(len(self.db.get_connected_users(self.public_key)), 0)

        # Add 10 random blocks, implying 10 unique peers
        random_blocks = []
        for i in range(0, 10):
            block = TestBlock()
            random_blocks.append(block)
            self.db.add_block(block)

        self.assertEqual(len(self.db.get_users()), 10)
        self.assertEqual(len(self.db.get_connected_users(self.public_key)), 0)

        # Create 5 link block implying 5 connected peers to the current user
        for i in range(0, 5):
            block = TrustChainBlock.create(b'test', {b'id': i}, self.db, self.public_key, link=random_blocks[i])
            self.db.add_block(block)

        self.assertEqual(len(self.db.get_users()), 11)
        self.assertEqual(len(self.db.get_connected_users(self.public_key)), 5)

    def test_crawl(self):
        """
        Test whether the crawl method returns the right blocks
        """
        block1 = TestBlock(key=self.key)
        block2 = TestBlock(previous=block1, key=self.key)
        self.db.add_block(block1)
        self.db.add_block(block2)

        # Clear the block cache
        self.db.my_blocks_cache.blocks = {}
        self.db.my_blocks_cache.linked_blocks = {}

        self.assertEqual(len(self.db.crawl(self.public_key, 0, 10)), 2)

        # Add some linked blocks
        key2 = default_eccrypto.generate_key(u"curve25519")
        linked_block1 = TestBlock(key=key2, linked=block1)
        self.db.add_block(linked_block1)

        # We should get this newly added block now
        self.assertEqual(len(self.db.crawl(self.public_key, 0, 10)), 3)
