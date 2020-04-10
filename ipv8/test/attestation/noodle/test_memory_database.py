import asynctest
from collections import namedtuple
from random import random

from ....attestation.noodle.memory_database import NoodleMemoryDatabase
from ipv8.attestation.trustchain.block import EMPTY_PK
from ipv8.test.attestation.noodle.test_block import TestBlock


class TestMemDB(asynctest.TestCase):

    def setUp(self):
        self.session_id = "".join([chr(i) for i in range(64)])
        self.db = NoodleMemoryDatabase('test', 'test')
        self.db2 = NoodleMemoryDatabase('test2', 'test')

    def test_add_spend(self, previous=None):
        transaction = {"value": random(), "from_peer": 1, "to_peer": 2, "total_spend": 2}
        block = TestBlock(transaction=transaction, block_type=b'spend', previous=previous)
        from_id = self.db.key_to_id(block.public_key)
        to_id = self.db.key_to_id(block.link_public_key)

        self.db.add_block(block)
        self.assertEqual(transaction["total_spend"],
                         self.db.work_graph[from_id][to_id]["total_spend"])
        self.assertTrue('spend_num' in
                        self.db.work_graph[from_id][to_id])

        return block

    def test_add_mint(self):
        transaction = {"value": random(), "from_peer": 0, "to_peer": 2, "total_spend": 3}
        Linked = namedtuple('Linked', ['public_key', 'sequence_number'])
        linked = Linked(EMPTY_PK, 0)
        block = TestBlock(transaction=transaction, block_type=b'claim', linked=linked)
        from_id = self.db.key_to_id(block.public_key)
        to_id = self.db.key_to_id(block.link_public_key)

        self.db.add_block(block)
        self.assertEqual(transaction["total_spend"],
                         self.db.work_graph[to_id][from_id]["total_spend"])
        self.assertTrue(self.db.work_graph[to_id][from_id]['verified'])
        return block

    def test_add_claim(self, linked=None):
        transaction = {"value": random(), "from_peer": 0, "to_peer": 2, "total_spend": 1}
        if linked:
            transaction["total_spend"] = linked.transaction["total_spend"]
        key = linked.link_key if linked else None
        block = TestBlock(transaction=transaction, block_type=b'claim', linked=linked, key=key)
        if linked:
            self.assertEqual(block.link_public_key, linked.public_key)
            self.assertEqual(block.public_key, linked.link_public_key)
        self.db.add_block(block)
        from_id = self.db.key_to_id(block.public_key)
        to_id = self.db.key_to_id(block.link_public_key)

        if linked:
            self.assertTrue('spend_num' in self.db.work_graph[to_id][from_id])
        self.assertEqual(transaction["total_spend"],
                         self.db.work_graph[to_id][from_id]["total_spend"])
        self.assertEqual(transaction["total_spend"],
                         self.db.work_graph[to_id][from_id]["total_spend"])
        if linked:
            self.assertTrue(self.db.get_balance(to_id) >= 0)
        else:
            self.assertTrue(self.db.work_graph[to_id][from_id]['verified'])
        return block

    def test_full_chain(self):
        blk1 = self.test_add_mint()
        val = self.db.get_balance(blk1.public_key)
        blk2 = self.test_add_spend(previous=blk1)
        self.assertEqual(blk1.public_key, blk2.public_key)
        blk3 = self.test_add_claim(linked=blk2)
        from_id = self.db.key_to_id(blk3.public_key)
        to_id = self.db.key_to_id(blk3.link_public_key)

        self.assertTrue(self.db.work_graph[to_id][from_id]['verified'])
        return blk1, blk2, blk3

    def test_invert_insert(self):
        mint, spend, claim = self.test_full_chain()

        self.db2.add_block(claim)
        pid_claim = self.db2.key_to_id(claim.public_key)
        lid_claim = self.db2.key_to_id(claim.link_public_key)
        self.assertEqual(self.db2.get_balance(pid_claim), 2)
        self.assertGreater(self.db2.get_balance(pid_claim, False), 0)
        self.assertLess(self.db2.get_balance(lid_claim), 0)

        self.db2.add_block(spend)
        self.db2.add_block(mint)

        self.assertTrue(self.db2.get_last_pairwise_block(spend.public_key, spend.link_public_key))
        blk1, blk2 = self.db2.get_last_pairwise_block(spend.public_key, spend.link_public_key)
        self.assertEqual(blk1.public_key, blk2.link_public_key)

        self.assertGreater(self.db2.get_balance(pid_claim), 0)
        self.assertGreater(self.db2.get_balance(lid_claim), 0)

        # Test chain dumps
        self.db3 = NoodleMemoryDatabase('q1', 'a1')
        status = self.db2.get_peer_status(claim.link_public_key)

        self.db3.dump_peer_status(lid_claim, status)
        self.assertEqual(self.db2.get_balance(pid_claim), self.db3.get_balance(pid_claim))