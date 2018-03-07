import logging
import random
import unittest

from hashlib import sha256

from ipv8.attestation.trustchain.block import TrustChainBlock, GENESIS_HASH, GENESIS_SEQ, EMPTY_SIG, ValidationResult
from ipv8.keyvault.crypto import ECCrypto
from ipv8.messaging.deprecated.encoding import encode


class TestBlock(TrustChainBlock):
    """
    Test Block that simulates a block used in TrustChain.
    Also used in other test files for TrustChain.
    """

    def __init__(self, transaction=None, previous=None, key=None, double_sign=False):
        crypto = ECCrypto()
        other = crypto.generate_key(u"curve25519").pub().key_to_bin()

        transaction = transaction or {'id': 42}

        if previous:
            self.key = previous.key
            TrustChainBlock.__init__(self, (encode(transaction), previous.public_key, previous.sequence_number + 1,
                                            other, 0, previous.hash, 0, 0))
        else:
            if key:
                self.key = key
            else:
                self.key = crypto.generate_key(u"curve25519")

            TrustChainBlock.__init__(self, (
                encode(transaction), self.key.pub().key_to_bin(), random.randint(50, 100), other, 0,
                sha256(str(random.randint(0, 100000))).digest(), 0, 0))
        self.sign(self.key, double_sign=double_sign)


class MockDatabase(object):
    """
    This mocked database is only used during the tests.
    """

    def __init__(self):
        super(MockDatabase, self).__init__()
        self.data = dict()

    def add_block(self, block):
        if self.data.get(block.public_key) is None:
            self.data[block.public_key] = []
        self.data[block.public_key].append(block)
        self.data[block.public_key].sort(key=lambda b: b.sequence_number)

    def get(self, pk, seq):
        if self.data.get(pk) is None:
            return None
        item = [i for i in self.data[pk] if i.sequence_number == seq]
        return item[0] if item else None

    def get_linked(self, blk):
        if self.data.get(blk.link_public_key) is None:
            return None
        item = [i for i in self.data[blk.link_public_key] if
                i.sequence_number == blk.link_sequence_number or i.link_sequence_number == blk.sequence_number]
        return item[0] if item else None

    def get_latest(self, pk):
        return self.data[pk][-1] if self.data.get(pk) else None

    def get_block_after(self, blk):
        if self.data.get(blk.public_key) is None:
            return None
        item = [i for i in self.data[blk.public_key] if i.sequence_number > blk.sequence_number]
        return item[0] if item else None

    def get_block_before(self, blk):
        if self.data.get(blk.public_key) is None:
            return None
        item = [i for i in self.data[blk.public_key] if i.sequence_number < blk.sequence_number]
        return item[-1] if item else None


class TestTrustChainBlock(unittest.TestCase):
    """
    This class contains tests for a TrustChain block.
    """

    def test_hash(self):
        """
        Test the empty hash of a block
        """
        block = TrustChainBlock()
        self.assertEqual(block.hash, '\x1f\x1bp\x90\xe3>\x83\xf6\xcd\xafd\xd9\xee\xfb"&|<ZLsyB:Z\r'
                                     '<\xc5\xb0\x97\xa3\xaf')

    def test_sign(self):
        """
        Test signing a block and whether the signature is valid
        """
        crypto = ECCrypto()
        block = TestBlock()
        self.assertTrue(crypto.is_valid_signature(block.key, block.pack(signature=False), block.signature))

    def test_create_genesis(self):
        """
        Test creating a genesis block
        """
        key = ECCrypto().generate_key(u"curve25519")
        db = MockDatabase()
        block = TrustChainBlock.create({'id': 42}, db, key.pub().key_to_bin(), link=None)
        self.assertEqual(block.previous_hash, GENESIS_HASH)
        self.assertEqual(block.sequence_number, GENESIS_SEQ)
        self.assertEqual(block.public_key, key.pub().key_to_bin())
        self.assertEqual(block.signature, EMPTY_SIG)

    def test_create_next(self):
        """
        Test creating a block that points towards a previous block
        """
        db = MockDatabase()
        prev = TestBlock()
        prev.sequence_number = GENESIS_SEQ
        db.add_block(prev)
        block = TrustChainBlock.create({'id': 42}, db, prev.public_key, link=None)
        self.assertEqual(block.previous_hash, prev.hash)
        self.assertEqual(block.sequence_number, 2)
        self.assertEqual(block.public_key, prev.public_key)

    def test_create_link_genesis(self):
        """
        Test creating a linked half block
        """
        key = ECCrypto().generate_key(u"curve25519")
        db = MockDatabase()
        link = TestBlock()
        db.add_block(link)
        block = TrustChainBlock.create({'id': 42}, db, key.pub().key_to_bin(), link=link)
        self.assertEqual(block.previous_hash, GENESIS_HASH)
        self.assertEqual(block.sequence_number, GENESIS_SEQ)
        self.assertEqual(block.public_key, key.pub().key_to_bin())
        self.assertEqual(block.link_public_key, link.public_key)
        self.assertEqual(block.link_sequence_number, link.sequence_number)

    def test_create_link_next(self):
        """
        Test creating a linked half that points back towards a previous block
        """
        db = MockDatabase()
        prev = TestBlock()
        prev.sequence_number = GENESIS_SEQ
        db.add_block(prev)
        link = TestBlock()
        db.add_block(link)
        block = TrustChainBlock.create({'id': 42}, db, prev.public_key, link=link)
        self.assertEqual(block.previous_hash, prev.hash)
        self.assertEqual(block.sequence_number, 2)
        self.assertEqual(block.public_key, prev.public_key)
        self.assertEqual(block.link_public_key, link.public_key)
        self.assertEqual(block.link_sequence_number, link.sequence_number)

    def test_double_spending(self):
        """
        Test double spending
        """
        key = ECCrypto().generate_key(u"curve25519")
        db = MockDatabase()

        # Adding 4 test blocks
        block0 = TestBlock(key=key, double_sign=True)
        block0.sequence_number = GENESIS_SEQ
        db.add_block(block0)

        block1 = TestBlock(previous=block0, double_sign=True)
        db.add_block(block1)

        block2 = TestBlock(previous=block1, double_sign=True)
        db.add_block(block2)

        block3 = TestBlock(previous=block2, double_sign=True)
        db.add_block(block3)

        # Double signed block; Previous block is same as for block3
        new_block = TestBlock(previous=block2, double_sign=True)

        # Validation should detect double spend and recover the private key of the signer.
        validation = new_block.validate(db)
        self.assertEqual(validation[0], ValidationResult.double_spend)
        self.assertIn("Double sign fraud", validation[1])

        # Check equality of the private keys
        recovered_private_key = validation[2][1]
        original_signing_secret_key = key.key.signer.sk[:32]
        self.assertEqual(original_signing_secret_key, recovered_private_key, "Recovered private key did not match.")

