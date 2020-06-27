from ...base import TestBase
from ....attestation.trustchain.block import TrustChainBlock
from ....attestation.trustchain.database import TrustChainDB
from ....keyvault.crypto import default_eccrypto
from ....test.attestation.trustchain.test_block import TestBlock


class TestTrustChainMemoryDB(TestBase):

    def setUp(self):
        super(TestTrustChainMemoryDB, self).setUp()
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


class TestTrustChainDB(TestBase):
    """
    This class contains tests with a database persisted to disk. The database is written to a temporary directory and
    is cleaned up after the tests finished.
    """

    def setUp(self):
        super(TestTrustChainDB, self).setUp()
        self.key = default_eccrypto.generate_key(u"curve25519")
        self.db_dir = self.temporary_directory()
        self.db = TrustChainDB(self.db_dir, 'temp_trustchain')

    def test_upgrade_wipe_db(self):
        """
        Test whether upgrading the database from version 1 to 6 removes all blocks
        """
        self.db.execute("UPDATE OPTION set value='1' WHERE key='database_version'")
        block1 = TestBlock(key=self.key)
        self.db.add_block(block1)
        self.assertTrue(self.db.get_all_blocks())
        self.db.close()

        # Load the database again
        db = TrustChainDB(self.db_dir, 'temp_trustchain')
        self.assertFalse(db.get_all_blocks())
        db.close()

    def test_upgrade_blob_text(self):
        """
        Test whether upgrading the database from version 7 to 8 does not result in an error.
        We specifically test for the situation where a public key got inserted as TEXT type (in Python 2) and another
        public key as BLOB type (in Python 3). This would bypass the IntegrityViolation error.
        """
        self.db.execute("UPDATE OPTION set value='7' WHERE key='database_version'")

        # Insert two blocks with the same public key and sequence number, bypassing the integrity violation.
        self.db.execute("INSERT INTO blocks VALUES('test', 'a1d2bid2i42', '1', 3, 'test', 3, '', '', 12345, 0, '');")
        self.db.execute("INSERT INTO blocks VALUES('test', 'a1d2bid2i42', X'31', 3, 'test', 3, '', '', 12345, 0, '');")

        self.assertTrue(self.db.get_all_blocks())
        self.db.close()

        # Load the database again
        db = TrustChainDB(self.db_dir, 'temp_trustchain')
        db.close()
