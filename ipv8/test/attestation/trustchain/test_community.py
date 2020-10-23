from asyncio import sleep

from ...attestation.trustchain.test_block import TestBlock
from ...base import TestBase
from ...mocking.ipv8 import MockIPv8
from ....attestation.trustchain.block import TrustChainBlock
from ....attestation.trustchain.caches import CrawlRequestCache
from ....attestation.trustchain.community import TrustChainCommunity, UNKNOWN_SEQ
from ....attestation.trustchain.listener import BlockListener
from ....database import database_blob
from ....keyvault.crypto import default_eccrypto


class DummyBlock(TrustChainBlock):
    """
    This dummy block is used to verify the conversion to a specific block class during the tests.
    Other than that, it has no purpose.
    """
    pass


class TestBlockListener(BlockListener):
    """
    This block listener simply signs all blocks it receives.
    """
    BLOCK_CLASS = DummyBlock

    def should_sign(self, block):
        return True

    def received_block(self, block):
        pass


class TestTrustChainCommunity(TestBase):

    def setUp(self):
        super(TestTrustChainCommunity, self).setUp()
        self.initialize(TrustChainCommunity, 2)

        for node in self.nodes:
            node.overlay.add_listener(TestBlockListener(), [b'test'])

    def create_node(self):
        return MockIPv8(u"curve25519", TrustChainCommunity, working_directory=u":memory:")

    def persistence(self, i):
        return self.overlay(i).persistence

    async def test_sign_half_block(self):
        """
        Check if a block signed by one party is stored in the databases of both parties.
        """
        self.overlay(1).should_sign = lambda x: False

        self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test', transaction={})

        await self.deliver_messages()

        for node_nr in [0, 1]:
            self.assertIsNotNone(self.persistence(node_nr).get(self.key_bin(0), 1))
            self.assertEqual(self.persistence(node_nr).get(self.key_bin(0), 1).link_sequence_number, UNKNOWN_SEQ)

    async def test_sign_full_block(self):
        """
        Check if a double signed transaction is stored in the databases of both parties.
        """
        block, link_block = await self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1),
                                                             block_type=b'test', transaction={})
        self.assertIsInstance(block, DummyBlock)
        self.assertIsInstance(link_block, DummyBlock)

        for node_nr in [0, 1]:
            self.assertIsNotNone(self.persistence(node_nr).get(self.key_bin(1), 1))
            self.assertEqual(self.persistence(node_nr).get(self.key_bin(1), 1).link_sequence_number, 1)

    async def test_get_linked(self):
        """
        Check if a both halves of a fully signed block link to each other.
        """
        self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test', transaction={})

        await self.deliver_messages()

        for node_nr in [0, 1]:
            my_block = self.persistence(node_nr).get(self.key_bin(0), 1)
            his_block = self.persistence(node_nr).get(self.key_bin(1), 1)
            self.assertEqual(self.persistence(node_nr).get_linked(my_block), his_block)
            self.assertEqual(self.persistence(node_nr).get_linked(his_block), my_block)

    async def test_crawl(self):
        """
        Check if a block can be crawled.

         1. Node 0 makes a half block, but doesn't/can't share it with Node 1.
         2. Node 1 send a crawl request to Node 0
         3. Node 0 sends his half block back
        """
        self.overlay(1).should_sign = lambda x: False
        self.endpoint(0).close()

        self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test', transaction={})

        await self.deliver_messages()

        self.assertIsNone(self.persistence(1).get(self.key_bin(0), 1))

        self.endpoint(0).open()
        self.overlay(1).send_crawl_request(self.my_peer(0), self.key_bin(0), 1, 1)

        await self.deliver_messages()

        self.assertIsNotNone(self.persistence(1).get(self.key_bin(0), 1))
        self.assertEqual(self.persistence(1).get(self.key_bin(0), 1).link_sequence_number, UNKNOWN_SEQ)

    async def test_crawl_default(self):
        """
        Check if the default crawl strategy produces blocks.
        """
        self.overlay(1).should_sign = lambda x: False
        self.endpoint(0).close()

        self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test', transaction={})

        await self.deliver_messages()

        self.assertIsNone(self.persistence(1).get(self.key_bin(0), 1))

        self.endpoint(0).open()
        self.overlay(1).send_crawl_request(self.my_peer(0), self.key_bin(0), 1, 1)

        await self.deliver_messages()

        self.assertIsNotNone(self.persistence(1).get(self.key_bin(0), 1))
        self.assertEqual(self.persistence(1).get(self.key_bin(0), 1).link_sequence_number, UNKNOWN_SEQ)

    async def test_crawl_no_blocks(self):
        """
        Check if blocks don't magically appear.
        """
        CrawlRequestCache.CRAWL_TIMEOUT = 0.1
        response = await self.overlay(1).send_crawl_request(self.my_peer(0), self.key_bin(0), 1, 1)
        self.assertFalse(response)

    async def test_crawl_negative_index(self):
        """
        Check if a block can be crawled by negative range.
        """
        self.overlay(1).should_sign = lambda x: False
        self.endpoint(0).close()

        self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test', transaction={})

        await self.deliver_messages()
        self.assertIsNone(self.persistence(1).get(self.key_bin(0), 1))
        self.endpoint(0).open()

        self.overlay(1).send_crawl_request(self.my_peer(0), self.key_bin(0), -1, -1)

        await self.deliver_messages()

        self.assertIsNotNone(self.persistence(1).get(self.key_bin(0), 1))
        self.assertEqual(self.persistence(1).get(self.key_bin(0), 1).link_sequence_number, UNKNOWN_SEQ)

    async def test_crawl_lowest_unknown(self):
        """
        Test crawling the lowest unknown block of a specific peer.
        """
        for _ in [0, 1, 2]:
            await self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test',
                                             transaction={})

        self.persistence(1).execute(u"DELETE FROM blocks WHERE sequence_number = 2 AND public_key = ?",
                                    (database_blob(self.key_bin(0)), ))
        self.assertIsNone(self.persistence(1).get(self.key_bin(0), 2))

        await self.overlay(1).crawl_lowest_unknown(self.my_peer(0))
        await self.deliver_messages()

        self.assertIsNotNone(self.persistence(1).get(self.key_bin(0), 2))

    async def test_crawl_pair(self):
        """
        Test crawling a block pair.
        """
        await self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test', transaction={})

        self.add_node_to_experiment(self.create_node())

        await self.overlay(2).send_crawl_request(self.my_peer(0), self.key_bin(0), 1, 1)

        # Check whether we have both blocks now
        self.assertEqual(self.persistence(2).get(self.key_bin(0), 1).link_sequence_number, UNKNOWN_SEQ)
        self.assertEqual(self.persistence(2).get(self.key_bin(1), 1).link_sequence_number, 1)

    async def test_parallel_blocks(self):
        """
        Check if blocks created in parallel will properly be stored in the database.
        """
        self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test', transaction={})
        self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test', transaction={})

        await self.deliver_messages()

        # Blocks are signed FIFO, meaning that if Node 1 gets Node 0's 0@block#2 first it will sign it as 1@block#1
        # Ergo normally:
        #  0@block#1 <-> 1@block#1
        #  0@block#2 <-> 1@block#2
        # But if 0@block#2 is received first:
        #  0@block#2 <-> 1@block#1
        #  0@block#1 <-> 1@block#2
        first = self.persistence(1).get(self.key_bin(1), 1).link_sequence_number
        second = 2 if first == 1 else 1

        for node_nr in [0, 1]:
            # His first block -> my first block
            self.assertIsNotNone(self.persistence(node_nr).get(self.key_bin(1), 1))
            self.assertEqual(self.persistence(node_nr).get(self.key_bin(1), 1).link_sequence_number, first)
            # His second block -> my second block
            self.assertIsNotNone(self.persistence(node_nr).get(self.key_bin(1), 2))
            self.assertEqual(self.persistence(node_nr).get(self.key_bin(1), 2).link_sequence_number, second)

    async def test_retrieve_missing_block(self):
        """
        Check if missing blocks are retrieved through a crawl request.
        """
        self.endpoint(0).close()
        signed1 = self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test',
                                             transaction={})

        await self.deliver_messages()

        self.endpoint(0).open()
        signed2 = self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test',
                                             transaction={})

        await signed1
        await signed2

        for node_nr in [0, 1]:
            # His first block -> my first block
            self.assertIsNotNone(self.persistence(node_nr).get(self.key_bin(1), 1))
            self.assertEqual(self.persistence(node_nr).get(self.key_bin(1), 1).link_sequence_number, 1)
            # His second block -> my second block
            self.assertIsNotNone(self.persistence(node_nr).get(self.key_bin(1), 2))
            self.assertEqual(self.persistence(node_nr).get(self.key_bin(1), 2).link_sequence_number, 2)

    async def test_send_block_pair(self):
        """
        Test sending and receiving a pair of blocks from one to another peer.
        """
        block1 = TestBlock()
        block2 = TestBlock()
        self.overlay(0).send_block_pair(block1, block2, self.address(1))

        await self.deliver_messages()

        self.assertTrue(self.persistence(1).get_latest(block1.public_key))
        self.assertTrue(self.persistence(1).get_latest(block2.public_key))

    async def test_broadcast_half_block(self):
        """
        Test broadcasting a half block
        """
        # Let node 3 discover node 2.
        node3 = self.create_node()
        self.nodes.append(node3)
        self.network(1).add_verified_peer(node3.my_peer)
        self.nodes[1].discovery.take_step()

        # TTL=1 (should not be relayed)
        block = TestBlock()
        self.overlay(0).send_block(block, ttl=1)
        await self.deliver_messages()
        self.assertIn(block.block_id, self.overlay(0).relayed_broadcasts)
        self.assertNotIn(block.block_id, self.overlay(1).relayed_broadcasts)
        self.assertNotIn(block.block_id, node3.overlay.relayed_broadcasts)

        # TTL=2 (should be relayed)
        block = TestBlock()
        self.overlay(0).send_block(block, ttl=2)
        await self.deliver_messages()
        self.assertIn(block.block_id, self.overlay(0).relayed_broadcasts)
        self.assertIn(block.block_id, self.overlay(1).relayed_broadcasts)
        self.assertNotIn(block.block_id, node3.overlay.relayed_broadcasts)

        # TTL=3 (should be relayed twice)
        block = TestBlock()
        self.overlay(0).send_block(block, ttl=3)
        await self.deliver_messages()
        self.assertIn(block.block_id, self.overlay(0).relayed_broadcasts)
        self.assertIn(block.block_id, self.overlay(1).relayed_broadcasts)
        self.assertIn(block.block_id, node3.overlay.relayed_broadcasts)

    async def test_broadcast_half_block_pair(self):
        """
        Test broadcasting a half block pair
        """
        # Let node 3 discover node 2.
        node3 = self.create_node()
        self.nodes.append(node3)
        self.network(1).add_verified_peer(node3.my_peer)
        self.nodes[1].discovery.take_step()

        # TTL=1 (should not be relayed)
        block1 = TestBlock()
        block2 = TestBlock()
        self.overlay(0).send_block_pair(block1, block2, ttl=1)
        await self.deliver_messages()
        self.assertIn(block1.block_id, self.overlay(0).relayed_broadcasts)
        self.assertNotIn(block1.block_id, self.overlay(1).relayed_broadcasts)
        self.assertNotIn(block1.block_id, node3.overlay.relayed_broadcasts)

        # TTL=2 (should be relayed)
        block1 = TestBlock()
        block2 = TestBlock()
        self.overlay(0).send_block_pair(block1, block2, ttl=2)
        await self.deliver_messages()
        self.assertIn(block1.block_id, self.overlay(0).relayed_broadcasts)
        self.assertIn(block1.block_id, self.overlay(1).relayed_broadcasts)
        self.assertNotIn(block1.block_id, node3.overlay.relayed_broadcasts)

        # TTL=3 (should be relayed twice)
        block1 = TestBlock()
        block2 = TestBlock()
        self.overlay(0).send_block_pair(block1, block2, ttl=3)
        await self.deliver_messages()
        self.assertIn(block1.block_id, self.overlay(0).relayed_broadcasts)
        self.assertIn(block1.block_id, self.overlay(1).relayed_broadcasts)
        self.assertIn(block1.block_id, node3.overlay.relayed_broadcasts)

    async def test_intro_response_crawl(self):
        """
        Test whether we crawl a node when receiving an introduction response
        """
        self.endpoint(0).close()

        self.overlay(0).create_source_block(block_type=b'test', transaction={})
        await self.deliver_messages()

        self.endpoint(0).open()

        # Crawl each other
        await self.introduce_nodes()

        # We should have received the block now
        self.assertIsNotNone(self.persistence(1).get_latest(self.key_bin(0)))

        # Check whether we do not crawl this node again in a short time
        self.endpoint(0).close()
        self.overlay(0).create_source_block(block_type=b'test', transaction={})
        self.endpoint(0).open()

        await self.introduce_nodes()

        # We should not have crawled this second block
        self.assertEqual(self.persistence(1).get_latest(self.key_bin(0)).sequence_number, 1)

    async def test_empty_crawl(self):
        """
        Test a crawl request to a peer without any blocks
        """
        response = await self.overlay(1).send_crawl_request(self.my_peer(0), self.key_bin(0), 1, 1)
        self.assertListEqual([], response)

    async def test_invalid_block(self):
        """
        See if we can recover from database corruption.
        """
        # Create an invalid block
        invalid_block = TestBlock(key=self.private_key(0))
        invalid_block.signature = b'a' * 64
        invalid_block.hash = invalid_block.calculate_hash()
        self.persistence(0).add_block(invalid_block)

        # We will attempt to add a new block to our chain.
        # We should see that we have database corruption and clean up our chain.
        # Afterward we continue the signing as usual
        await self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test', transaction={})

        await self.deliver_messages()

        # Both nodes should have this newly signed block added correctly to their database
        self.assertIsNotNone(self.persistence(0).get(self.key_bin(0), 1))
        self.assertIsNotNone(self.persistence(1).get(self.key_bin(0), 1))

    async def test_half_block_self_signed(self):
        """
        Test creating and disseminating a half block, signed by yourself
        """
        await self.overlay(0).self_sign_block(block_type=b'test', transaction={})

        await self.deliver_messages()

        # The other node should now have the self-signed block
        self.assertIsNotNone(self.persistence(0).get(self.key_bin(0), 1))
        self.assertIsNotNone(self.persistence(1).get(self.key_bin(0), 1))

    async def test_half_block_link_block(self):
        """
        Test creating and disseminating a link block
        """
        # Create an initial source block with no counterpary
        await self.overlay(0).create_source_block(b'test', {})
        await self.deliver_messages()

        # Check the dissemination of the no counterparty source block
        self.assertIsNotNone(self.persistence(0).get(self.key_bin(0), 1))
        block = self.persistence(1).get(self.key_bin(0), 1)
        self.assertIsNotNone(block)

        # Create a Link Block
        link_block, _ = await self.overlay(1).create_link(block, b'link', additional_info={b'a': 1, b'b': 2})
        self.assertEqual(link_block.type, b'link')
        await self.deliver_messages()

        # Check the dissemination of the link block
        block_node_0 = self.persistence(0).get(self.key_bin(1), 1)
        block_node_1 = self.persistence(1).get(self.key_bin(1), 1)

        self.assertIsNotNone(block_node_0)
        self.assertIsNotNone(block_node_1)

        self.assertEqual(block_node_0.transaction, {b'a': 1, b'b': 2})
        self.assertEqual(block_node_1.transaction, {b'a': 1, b'b': 2})

    async def test_link_block_multiple(self):
        """
        Test whether we can create multiple link blocks for the same source block
        """
        source_block, _ = await self.overlay(0).create_source_block(b'test', {})
        await self.deliver_messages()

        block = self.persistence(1).get(self.key_bin(0), 1)

        self.overlay(1).create_link(block, b'link', additional_info={b'a': 1, b'b': 2})
        self.overlay(1).create_link(block, b'link', additional_info={b'a': 2, b'b': 3})
        await self.deliver_messages()

        self.assertEqual(len(self.persistence(0).get_all_linked(source_block)), 2)

    def test_db_remove(self):
        """
        Test pruning of the database when it grows too large
        """
        self.overlay(0).settings.max_db_blocks = 5

        for _ in range(10):
            test_block = TestBlock()
            self.persistence(0).add_block(test_block)

        self.overlay(0).do_db_cleanup()
        self.assertEqual(self.persistence(0).get_number_of_known_blocks(), 5)

    def test_database_cleanup(self):
        """
        Test whether we are cleaning up the database correctly when there are too many blocks
        """
        for _ in range(5):
            self.persistence(0).add_block(TestBlock())

        self.assertEqual(self.persistence(0).get_number_of_known_blocks(), 5)
        self.overlay(0).settings.max_db_blocks = 3
        self.overlay(0).do_db_cleanup()
        self.assertEqual(self.persistence(0).get_number_of_known_blocks(), 3)

    async def test_double_spend(self):
        """
        Test that a double spend is correctly detected and stored
        """
        for node in self.nodes:
            node.overlay.settings.block_types_bc_disabled.add(b'test')

        block1, block2 = await self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test',
                                                          transaction={})
        await self.deliver_messages()
        self.persistence(0).remove_block(block1)
        self.persistence(0).remove_block(block2)

        # Double spend
        self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test', transaction={})
        await self.deliver_messages()
        self.assertTrue(self.persistence(1).did_double_spend(self.key_bin(0)))

    async def test_chain_crawl_with_gaps(self):
        """
        Test crawling a whole chain with gaps from a specific user.
        """
        created_blocks = []
        for _ in range(0, 5):
            blocks = await self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test',
                                                      transaction={})
            created_blocks.append(blocks)

        await self.deliver_messages()

        self.assertEqual(self.persistence(1).get_number_of_known_blocks(), 10)

        # Let node 1 remove some of the blocks
        self.persistence(1).remove_block(created_blocks[0][1])
        self.persistence(1).remove_block(created_blocks[2][1])
        self.persistence(1).remove_block(created_blocks[4][1])

        # Let node 1 crawl the chain of node 0
        self.overlay(1).settings.crawler = True
        await self.introduce_nodes()
        await sleep(0.2)  # Let blocks propagate

        self.assertEqual(self.persistence(1).get_number_of_known_blocks(), 10)

    async def test_chain_crawl(self):
        """
        Test crawl the whole chain of a specific peer
        """
        self.endpoint(0).close()
        key = default_eccrypto.generate_key(u'very-low').pub().key_to_bin()
        for _ in range(4):
            self.overlay(0).sign_block(self.peer(1), public_key=key, block_type=b'test', transaction={})
        self.endpoint(0).open()

        self.overlay(1).settings.crawler = True
        await self.introduce_nodes()
        await sleep(0.2)  # Let blocks propagate

        test_blocks = self.persistence(1).get_latest_blocks(self.key_bin(0), block_types=[b'test'])
        self.assertEqual(len(test_blocks), 4)

    async def test_chain_crawl_unknown_length(self):
        """
        Test crawling a chain with unknown length
        """
        def create_blocks(num):
            self.endpoint(0).close()
            key = default_eccrypto.generate_key(u'curve25519').pub().key_to_bin()
            for _ in range(num):
                self.overlay(0).sign_block(self.peer(1), public_key=key, block_type=b'test', transaction={})
            self.endpoint(0).open()

        create_blocks(4)

        await self.overlay(1).crawl_chain(self.overlay(0).my_peer)

        self.assertEqual(self.persistence(1).get_number_of_known_blocks(), 4)

        # Now peer 0 create another block, we should be able to get that one too
        create_blocks(3)

        await self.overlay(1).crawl_chain(self.overlay(0).my_peer)

        self.assertEqual(self.persistence(1).get_number_of_known_blocks(), 7)

    async def test_crawl_linked_block(self):
        """
        Test whether we get correct linked blocks when crawling the chain of a specific peer
        """
        await self.overlay(1).sign_block(self.peer(0), public_key=self.key_bin(0), block_type=b'test', transaction={})

        # Now, a third peer crawl the chain of peer 0. We should both get the linked block and the originating block.
        self.add_node_to_experiment(self.create_node())
        await self.overlay(2).send_crawl_request(self.my_peer(0), self.key_bin(0), 1, 1)

        # Peer 2 should have 2 blocks now
        self.assertEqual(self.persistence(2).get_number_of_known_blocks(), 2)

    async def test_process_block_unrelated_block(self):
        """
        Test whether we can invoke process_block directly with a block not made by node 0 or node 1
        """
        block1 = TestBlock()
        try:
            result = await self.overlay(1).process_half_block(block1, self.my_peer(0))
        except RuntimeError:
            pass
            # The block is not valid - ignore the error
        self.assertIsNone(result)

    async def test_process_block(self):
        """
        Test whether we can invoke process_block directly with a block made between node 0 and 1
        """
        self.endpoint(0).close()
        self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test', transaction={})
        block = self.persistence(0).get_latest(self.key_bin(0))
        self.endpoint(0).open()

        blocks = await self.overlay(1).process_half_block(block, self.my_peer(0))
        self.assertTrue(blocks)

    async def test_process_block_crawl(self):
        """
        Test whether we can invoke process_block directly while node 1 has to crawl the chain of node 0
        """
        self.endpoint(0).close()
        key = default_eccrypto.generate_key(u'very-low').pub().key_to_bin()
        self.overlay(0).sign_block(self.peer(1), public_key=key, block_type=b'test', transaction={})
        self.overlay(0).sign_block(self.peer(1), public_key=self.key_bin(1), block_type=b'test', transaction={})
        block = self.persistence(0).get_latest(self.key_bin(0))
        self.endpoint(0).open()

        blocks = await self.overlay(1).process_half_block(block, self.my_peer(0))
        self.assertTrue(blocks)
