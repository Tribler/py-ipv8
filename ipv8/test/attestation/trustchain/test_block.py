import random
import unittest

from hashlib import sha256

from ....attestation.trustchain.block import TrustChainBlock, GENESIS_HASH, GENESIS_SEQ, EMPTY_SIG, ValidationResult
from ....keyvault.crypto import ECCrypto
from ....messaging.deprecated.encoding import encode


class TestBlock(TrustChainBlock):
    """
    Test Block that simulates a block used in TrustChain.
    Also used in other test files for TrustChain.
    """

    def __init__(self, transaction=None, previous=None, key=None):
        crypto = ECCrypto()
        other = crypto.generate_key(u"curve25519").pub().key_to_bin()

        transaction = transaction or {'id': 42}

        if previous:
            self.key = previous.key
            TrustChainBlock.__init__(self, (encode(transaction), previous.public_key, previous.sequence_number + 1,
                                            other, 0, previous.hash, 0, 0, 0))
        else:
            if key:
                self.key = key
            else:
                self.key = crypto.generate_key(u"curve25519")

            TrustChainBlock.__init__(self, (
                encode(transaction), self.key.pub().key_to_bin(), random.randint(50, 100), other, 0,
                sha256(str(random.randint(0, 100000))).digest(), 0, 0, 0))
        self.sign(self.key)

        self.transaction_validation_result = (ValidationResult.valid, [])

    def validate_transaction(self, database):
        return self.transaction_validation_result


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
        block.timestamp = 0  # To make the hash the same between runs
        self.assertEqual(block.hash, '\x12s\xdd\xd9\xb0`^(b\xaby\xaf\xf8\x12\x10L\xfd\x91\x94\xa0i\xcc\xb2'
                                     ' \xa9\\\xe0\x8b6\t$7')

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

    def test_validation_level_no_blocks_genesis(self):
        """
        Test the validation level for no previous and no next block, if this is the genesis block.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 1
        block.update_validation_level(None, None, result)

        self.assertEqual(result.state, ValidationResult.partial_next)

    def test_validation_level_no_blocks(self):
        """
        Test the validation level for no previous and no next block.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 2
        block.update_validation_level(None, None, result)

        self.assertEqual(result.state, ValidationResult.no_info)

    def test_validation_level_next_block_no_gap_genesis(self):
        """
        Test the validation level for next block without gap, if this is the genesis block.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 1
        next_block = TestBlock()
        next_block.sequence_number = 2
        block.update_validation_level(None, next_block, result)

        self.assertEqual(result.state, ValidationResult.valid)

    def test_validation_level_next_block_no_gap(self):
        """
        Test the validation level for next block without gap.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 2
        next_block = TestBlock()
        next_block.sequence_number = 3
        block.update_validation_level(None, next_block, result)

        self.assertEqual(result.state, ValidationResult.partial_previous)

    def test_validation_level_next_block_gap_genesis(self):
        """
        Test the validation level for next block with gap, if this is the genesis block.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 1
        next_block = TestBlock()
        next_block.sequence_number = 3
        block.update_validation_level(None, next_block, result)

        self.assertEqual(result.state, ValidationResult.partial_next)

    def test_validation_level_next_block_gap(self):
        """
        Test the validation level for next block with gap.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 2
        next_block = TestBlock()
        next_block.sequence_number = 4
        block.update_validation_level(None, next_block, result)

        self.assertEqual(result.state, ValidationResult.partial)

    def test_validation_level_prev_block_no_gap(self):
        """
        Test the validation level for previous block without gap.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 3
        prev_block = TestBlock()
        prev_block.sequence_number = 2
        block.update_validation_level(prev_block, None, result)

        self.assertEqual(result.state, ValidationResult.partial_next)

    def test_validation_level_prev_block_gap(self):
        """
        Test the validation level for previous block with gap.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 4
        prev_block = TestBlock()
        prev_block.sequence_number = 2
        block.update_validation_level(prev_block, None, result)

        self.assertEqual(result.state, ValidationResult.partial)

    def test_validation_level_both_block_gap(self):
        """
        Test the validation level for both previous and next block with gap.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 3
        prev_block = TestBlock()
        prev_block.sequence_number = 1
        next_block = TestBlock()
        next_block.sequence_number = 5
        block.update_validation_level(prev_block, next_block, result)

        self.assertEqual(result.state, ValidationResult.partial)

    def test_validation_level_both_block_next_gap(self):
        """
        Test the validation level for both previous and only next block with gap.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 2
        prev_block = TestBlock()
        prev_block.sequence_number = 1
        next_block = TestBlock()
        next_block.sequence_number = 4
        block.update_validation_level(prev_block, next_block, result)

        self.assertEqual(result.state, ValidationResult.partial_next)

    def test_validation_level_both_block_prev_gap(self):
        """
        Test the validation level for both next and only previous block with gap.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 3
        prev_block = TestBlock()
        prev_block.sequence_number = 1
        next_block = TestBlock()
        next_block.sequence_number = 4
        block.update_validation_level(prev_block, next_block, result)

        self.assertEqual(result.state, ValidationResult.partial_previous)

    def test_invariant_tx_errors(self):
        """
        Test if transaction errors get added to the validation result.
        """
        result = ValidationResult()
        errors = ["a", "b"]
        block = TestBlock()
        block.transaction_validation_result = (ValidationResult.invalid, errors)
        block.update_block_invariant(None, result)

        self.assertEqual(errors, result.errors)
        self.assertEqual(ValidationResult.invalid, result.state)

    def test_invariant_negative_sq(self):
        """
        Test if negative sequence number blocks are not valid.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = -1
        block.update_block_invariant(None, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_invariant_link_negative_sq(self):
        """
        Test if negative sequence number linked blocks are not valid.
        """
        result = ValidationResult()
        block = TestBlock()
        block.link_sequence_number = -1
        block.update_block_invariant(None, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_invariant_link_null_pointer(self):
        """
        Test if 0 sequence number linked blocks are valid.
        """
        result = ValidationResult()
        block = TestBlock()
        block.link_sequence_number = 0
        block.update_block_invariant(None, result)

        self.assertEqual(ValidationResult.valid, result.state)

    def test_invariant_invalid_key(self):
        """
        Test if illegal key blocks are not valid.
        """
        result = ValidationResult()
        block = TestBlock()
        block.public_key = "definitelynotakey"
        block.update_block_invariant(None, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_invariant_invalid_link_key(self):
        """
        Test if illegal key linked-block blocks are not valid.
        """
        result = ValidationResult()
        block = TestBlock()
        block.link_public_key = "definitelynotakey"
        block.update_block_invariant(None, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_invariant_linked_own_key(self):
        """
        Test if self-signed blocks are not valid.
        """
        result = ValidationResult()
        block = TestBlock()
        block.link_public_key = block.public_key
        block.update_block_invariant(None, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_invariant_genesis_sq(self):
        """
        Test if genesis sq blocks with non-genesis hash are not valid.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = GENESIS_SEQ
        block.previous_hash = "abcdefg"
        block.update_block_invariant(None, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_invariant_genesis_hash(self):
        """
        Test if genesis hash blocks with non-zero sequence number are not valid.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 2
        block.previous_hash = GENESIS_HASH
        block.update_block_invariant(None, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_block_consistency_link_key(self):
        """
        Test for error on linked keys mismatch.
        """
        result = ValidationResult()
        block1 = TestBlock()
        block1.link_public_key = "1234"
        block2 = TestBlock()
        block2.link_public_key = "5678"
        block1.update_block_consistency(block2, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_block_consistency_link_sq(self):
        """
        Test for error on link sequence number mismatch.
        """
        result = ValidationResult()
        block1 = TestBlock()
        block1.link_sequence_number = 0
        block2 = TestBlock()
        block2.link_sequence_number = 1
        block1.update_block_consistency(block2, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_block_consistency_previous_hash(self):
        """
        Test for error on previous hash mismatch.
        """
        result = ValidationResult()
        block1 = TestBlock()
        block1.previous_hash = "1234"
        block2 = TestBlock()
        block2.previous_hash = "5678"
        block1.update_block_consistency(block2, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_block_consistency_signature(self):
        """
        Test for error on signature mismatch.
        """
        result = ValidationResult()
        block1 = TestBlock()
        block1.signature = "1234"
        block2 = TestBlock()
        block2.signature = "5678"
        block1.update_block_consistency(block2, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_block_consistency_hash(self):
        """
        Test for error on hash mismatch.
        """
        result = ValidationResult()
        block1 = TestBlock()
        block1.pack = lambda: "1234"
        block2 = TestBlock()
        block2.pack = lambda: "5678"
        block1.update_block_consistency(block2, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_link_consistency_key(self):
        """
        Test for error on key mismatch.
        """
        result = ValidationResult()
        block = TestBlock()
        block.link_public_key = "1234"
        link = TestBlock()
        link.public_key = "5678"
        block.update_linked_consistency(None, link, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_link_consistency_key_theirs(self):
        """
        Test for error on key mismatch on linked block.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 1
        block.link_sequence_number = 0
        link = TestBlock()
        link.sequence_number = 4
        link.link_sequence_number = 1
        block.link_public_key = link.public_key
        block.update_linked_consistency(None, link, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_link_consistency_key_ours(self):
        """
        Test for error on key mismatch on this block.
        """
        result = ValidationResult()
        block = TestBlock()
        block.link_public_key = "1234"
        link = TestBlock()
        link.public_key = "5678"
        link.link_public_key = block.public_key
        block.update_linked_consistency(None, link, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_link_consistency_sq_invalid(self):
        """
        Test for error on sequence number mismatch.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 1
        block.link_sequence_number = 1
        link = TestBlock()
        link.sequence_number = 4
        link.link_sequence_number = 4
        block.link_public_key = link.public_key
        link.link_public_key = block.public_key
        block.update_linked_consistency(None, link, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_link_consistency_sq_valid_ours(self):
        """
        Test for success on sequence number match through this block.
        """
        block = TestBlock()
        block.sequence_number = 1
        block.link_sequence_number = 4

        class FakeDB(object):

            def get_linked(self, _):
                return block

        result = ValidationResult()
        link = TestBlock()
        link.sequence_number = 4
        link.link_sequence_number = 0
        block.link_public_key = link.public_key
        link.link_public_key = block.public_key
        block.update_linked_consistency(FakeDB(), link, result)

        self.assertEqual(ValidationResult.valid, result.state)

    def test_link_consistency_sq_valid_theirs(self):
        """
        Test for success on sequence number match through the linked block.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 1
        block.link_sequence_number = 0
        link = TestBlock()
        link.sequence_number = 4
        link.link_sequence_number = 1
        block.link_public_key = link.public_key
        link.link_public_key = block.public_key
        block.update_linked_consistency(None, link, result)

        self.assertEqual(ValidationResult.valid, result.state)

    def test_link_consistency_double_countersign(self):
        """
        Test for error on double countersign fraud.
        """
        class FakeDB(object):

            def get_linked(self, _):
                return TestBlock(transaction={"a": "b"})

        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 1
        block.link_sequence_number = 4
        link = TestBlock()
        link.sequence_number = 4
        link.link_sequence_number = 0
        block.link_public_key = link.public_key
        link.link_public_key = block.public_key
        block.update_linked_consistency(FakeDB(), link, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_chain_consistency_no_blocks(self):
        """
        Check if a chaining is valid without previous or next blocks.
        """
        result = ValidationResult()
        block = TestBlock()
        block.update_chain_consistency(None, None, result)

        self.assertEqual(ValidationResult.valid, result.state)

    def test_chain_consistency_previous_block(self):
        """
        Check if a chaining is valid if the previous block connects to our block.
        """
        result = ValidationResult()
        prev_block = TestBlock()
        prev_block.sequence_number = 3
        block = TestBlock()
        block.public_key = prev_block.public_key
        block.sequence_number = 4
        block.previous_hash = prev_block.hash
        block.update_chain_consistency(prev_block, None, result)

        self.assertEqual(ValidationResult.valid, result.state)

    def test_chain_consistency_key_previous_block(self):
        """
        Check if a chaining is invalid on public key mismatch.
        """
        result = ValidationResult()
        prev_block = TestBlock()
        prev_block.sequence_number = 3
        block = TestBlock()
        block.sequence_number = 4
        block.previous_hash = prev_block.hash
        block.update_chain_consistency(prev_block, None, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_chain_consistency_sq_previous_block(self):
        """
        Check if a chaining is invalid on sequence number in the future.
        """
        result = ValidationResult()
        prev_block = TestBlock()
        prev_block.sequence_number = 5
        block = TestBlock()
        block.public_key = prev_block.public_key
        block.sequence_number = 4
        block.previous_hash = prev_block.hash
        block.update_chain_consistency(prev_block, None, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_chain_consistency_hash_previous_block(self):
        """
        Check if a chaining is invalid on hash mismatch.
        """
        result = ValidationResult()
        prev_block = TestBlock()
        prev_block.sequence_number = 3
        block = TestBlock()
        block.public_key = prev_block.public_key
        block.sequence_number = 4
        block.previous_hash = "definitelynotthathash"
        block.update_chain_consistency(prev_block, None, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_chain_consistency_hash_previous_block_gap(self):
        """
        Check if a chaining is valid on hash mismatch with non-previous block.
        """
        result = ValidationResult()
        prev_block = TestBlock()
        prev_block.sequence_number = 2
        block = TestBlock()
        block.public_key = prev_block.public_key
        block.sequence_number = 4
        block.previous_hash = "definitelynotthathash"
        block.update_chain_consistency(prev_block, None, result)

        self.assertEqual(ValidationResult.valid, result.state)

    def test_chain_consistency_next_block(self):
        """
        Check if a chaining is valid if the next block connects to our block.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 3
        next_block = TestBlock()
        next_block.public_key = block.public_key
        next_block.sequence_number = 4
        next_block.previous_hash = block.hash
        block.update_chain_consistency(None, next_block, result)

        self.assertEqual(ValidationResult.valid, result.state)

    def test_chain_consistency_key_next_block(self):
        """
        Check if a chaining is invalid on public key mismatch.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 3
        next_block = TestBlock()
        next_block.sequence_number = 4
        next_block.previous_hash = block.hash
        block.update_chain_consistency(None, next_block, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_chain_consistency_sq_next_block(self):
        """
        Check if a chaining is invalid on next sequence number in the past.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 5
        next_block = TestBlock()
        next_block.public_key = block.public_key
        next_block.sequence_number = 4
        next_block.previous_hash = block.hash
        block.update_chain_consistency(None, next_block, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_chain_consistency_hash_next_block(self):
        """
        Check if a chaining is invalid on hash mismatch.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 3
        next_block = TestBlock()
        next_block.public_key = block.public_key
        next_block.sequence_number = 4
        next_block.previous_hash = "definitelynotthathash"
        block.update_chain_consistency(None, next_block, result)

        self.assertEqual(ValidationResult.invalid, result.state)

    def test_chain_consistency_hash_next_block_gap(self):
        """
        Check if a chaining is valid on hash mismatch with non-next block.
        """
        result = ValidationResult()
        block = TestBlock()
        block.sequence_number = 2
        next_block = TestBlock()
        next_block.public_key = block.public_key
        next_block.sequence_number = 4
        next_block.previous_hash = "definitelynotthathash"
        block.update_chain_consistency(None, next_block, result)

        self.assertEqual(ValidationResult.valid, result.state)
