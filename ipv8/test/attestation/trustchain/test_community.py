from __future__ import absolute_import

from twisted.internet.defer import inlineCallbacks

from ....attestation.trustchain.block import TrustChainBlock
from ....attestation.trustchain.caches import CrawlRequestCache
from ....attestation.trustchain.community import TrustChainCommunity, UNKNOWN_SEQ
from ....attestation.trustchain.listener import BlockListener
from ...attestation.trustchain.test_block import TestBlock
from ....keyvault.crypto import ECCrypto
from ....messaging.deprecated.encoding import decode
from ...base import TestBase
from ...mocking.ipv8 import MockIPv8
from ....util import grange


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
            node.overlay.add_listener(TestBlockListener(), ['test'])

    def create_node(self):
        return MockIPv8(u"curve25519", TrustChainCommunity, working_directory=u":memory:")

    @inlineCallbacks
    def test_sign_half_block(self):
        """
        Check if a block signed by one party is stored in the databases of both parties.
        """
        self.nodes[1].overlay.should_sign = lambda x: False

        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         block_type='test', transaction={})

        yield self.deliver_messages()

        for node_nr in [0, 1]:
            self.assertIsNotNone(self.nodes[node_nr].overlay.persistence.get(my_pubkey, 1))
            self.assertEqual(self.nodes[node_nr].overlay.persistence.get(my_pubkey, 1).link_sequence_number, UNKNOWN_SEQ)

    @inlineCallbacks
    def test_sign_full_block(self):
        """
        Check if a double signed transaction is stored in the databases of both parties.
        """
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        block, link_block = yield self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0],
                                                                   public_key=his_pubkey, block_type='test',
                                                                   transaction={})
        self.assertIsInstance(block, DummyBlock)
        self.assertIsInstance(link_block, DummyBlock)

        for node_nr in [0, 1]:
            self.assertIsNotNone(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 1))
            self.assertEqual(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 1).link_sequence_number, 1)

    @inlineCallbacks
    def test_get_linked(self):
        """
        Check if a both halves of a fully signed block link to each other.
        """
        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         block_type='test', transaction={})

        yield self.deliver_messages()

        for node_nr in [0, 1]:
            my_block = self.nodes[node_nr].overlay.persistence.get(my_pubkey, 1)
            his_block = self.nodes[node_nr].overlay.persistence.get(his_pubkey, 1)
            self.assertEqual(self.nodes[node_nr].overlay.persistence.get_linked(my_block), his_block)
            self.assertEqual(self.nodes[node_nr].overlay.persistence.get_linked(his_block), my_block)

    @inlineCallbacks
    def test_crawl(self):
        """
        Check if a block can be crawled.

         1. Node 0 makes a half block, but doesn't/can't share it with Node 1.
         2. Node 1 send a crawl request to Node 0
         3. Node 0 sends his half block back
        """
        self.nodes[1].overlay.should_sign = lambda x: False
        self.nodes[0].endpoint.close()

        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         block_type='test', transaction={})

        yield self.deliver_messages()

        self.assertIsNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))

        self.nodes[0].endpoint.open()
        self.nodes[1].overlay.send_crawl_request(self.nodes[0].my_peer, my_pubkey, 1, 1)

        yield self.deliver_messages()

        self.assertIsNotNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))
        self.assertEqual(self.nodes[1].overlay.persistence.get(my_pubkey, 1).link_sequence_number, UNKNOWN_SEQ)

    @inlineCallbacks
    def test_crawl_default(self):
        """
        Check if the default crawl strategy produces blocks.
        """
        self.nodes[1].overlay.should_sign = lambda x: False
        self.nodes[0].endpoint.close()

        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         block_type='test', transaction={})

        yield self.deliver_messages()

        self.assertIsNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))

        self.nodes[0].endpoint.open()
        self.nodes[1].overlay.send_crawl_request(self.nodes[0].my_peer, my_pubkey, 1, 1)

        yield self.deliver_messages()

        self.assertIsNotNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))
        self.assertEqual(self.nodes[1].overlay.persistence.get(my_pubkey, 1).link_sequence_number, UNKNOWN_SEQ)

    @inlineCallbacks
    def test_crawl_no_blocks(self):
        """
        Check if blocks don't magically appear.
        """
        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        CrawlRequestCache.CRAWL_TIMEOUT = 0.1
        response = yield self.nodes[1].overlay.send_crawl_request(self.nodes[0].my_peer, my_pubkey, 1, 1)
        self.assertFalse(response)

    @inlineCallbacks
    def test_crawl_negative_index(self):
        """
        Check if a block can be crawled by negative range.
        """
        self.nodes[1].overlay.should_sign = lambda x: False
        self.nodes[0].endpoint.close()

        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         block_type='test', transaction={})

        yield self.deliver_messages()
        self.assertIsNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))
        self.nodes[0].endpoint.open()

        self.nodes[1].overlay.send_crawl_request(self.nodes[0].my_peer, my_pubkey, -1, -1)

        yield self.deliver_messages()

        self.assertIsNotNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))
        self.assertEqual(self.nodes[1].overlay.persistence.get(my_pubkey, 1).link_sequence_number, UNKNOWN_SEQ)

    @inlineCallbacks
    def test_crawl_lowest_unknown(self):
        """
        Test crawling the lowest unknown block of a specific peer.
        """
        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        for _ in [0, 1, 2]:
            yield self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                                   block_type=b'test', transaction={})

        self.nodes[1].overlay.persistence.execute(u"DELETE FROM blocks WHERE sequence_number = 2", tuple())
        self.assertIsNone(self.nodes[1].overlay.persistence.get(my_pubkey, 2))

        yield self.nodes[1].overlay.crawl_lowest_unknown(self.nodes[0].my_peer)
        yield self.deliver_messages()

        self.assertIsNotNone(self.nodes[1].overlay.persistence.get(my_pubkey, 2))

    @inlineCallbacks
    def test_crawl_pair(self):
        """
        Test crawling a block pair.
        """
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        yield self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                               block_type='test', transaction={})

        self.add_node_to_experiment(self.create_node())

        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        yield self.nodes[2].overlay.send_crawl_request(self.nodes[0].my_peer, my_pubkey, 1, 1)

        # Check whether we have both blocks now
        self.assertEqual(self.nodes[2].overlay.persistence.get(my_pubkey, 1).link_sequence_number, UNKNOWN_SEQ)
        self.assertEqual(self.nodes[2].overlay.persistence.get(his_pubkey, 1).link_sequence_number, 1)

    @inlineCallbacks
    def test_parallel_blocks(self):
        """
        Check if blocks created in parallel will properly be stored in the database.
        """
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         block_type='test', transaction={})
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         block_type='test', transaction={})

        yield self.deliver_messages()

        # Blocks are signed FIFO, meaning that if Node 1 gets Node 0's 0@block#2 first it will sign it as 1@block#1
        # Ergo normally:
        #  0@block#1 <-> 1@block#1
        #  0@block#2 <-> 1@block#2
        # But if 0@block#2 is received first:
        #  0@block#2 <-> 1@block#1
        #  0@block#1 <-> 1@block#2
        first = self.nodes[1].overlay.persistence.get(his_pubkey, 1).link_sequence_number
        second = 2 if first == 1 else 1

        for node_nr in [0, 1]:
            # His first block -> my first block
            self.assertIsNotNone(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 1))
            self.assertEqual(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 1).link_sequence_number, first)
            # His second block -> my second block
            self.assertIsNotNone(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 2))
            self.assertEqual(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 2).link_sequence_number, second)

    @inlineCallbacks
    def test_retrieve_missing_block(self):
        """
        Check if missing blocks are retrieved through a crawl request.
        """
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].endpoint.close()
        signed1 = self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                                   block_type='test', transaction={})

        yield self.deliver_messages()

        self.nodes[0].endpoint.open()
        signed2 = self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                                   block_type='test', transaction={})

        yield signed1
        yield signed2

        for node_nr in [0, 1]:
            # His first block -> my first block
            self.assertIsNotNone(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 1))
            self.assertEqual(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 1).link_sequence_number, 1)
            # His second block -> my second block
            self.assertIsNotNone(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 2))
            self.assertEqual(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 2).link_sequence_number, 2)

    @inlineCallbacks
    def test_send_block_pair(self):
        """
        Test sending and receiving a pair of blocks from one to another peer.
        """
        block1 = TestBlock()
        block2 = TestBlock()
        self.nodes[0].overlay.send_block_pair(block1, block2, self.nodes[0].network.verified_peers[0].address)

        yield self.deliver_messages()

        self.assertTrue(self.nodes[1].overlay.persistence.get_latest(block1.public_key))
        self.assertTrue(self.nodes[1].overlay.persistence.get_latest(block2.public_key))

    @inlineCallbacks
    def test_broadcast_half_block(self):
        """
        Test broadcasting a half block
        """
        # Let node 3 discover node 2.
        node3 = self.create_node()
        self.nodes.append(node3)
        self.nodes[1].network.add_verified_peer(node3.my_peer)
        self.nodes[1].discovery.take_step()

        # TTL=1 (should not be relayed)
        block = TestBlock()
        self.nodes[0].overlay.send_block(block, ttl=1)
        yield self.deliver_messages()
        self.assertIn(block.block_id, self.nodes[0].overlay.relayed_broadcasts)
        self.assertNotIn(block.block_id, self.nodes[1].overlay.relayed_broadcasts)
        self.assertNotIn(block.block_id, node3.overlay.relayed_broadcasts)

        # TTL=2 (should be relayed)
        block = TestBlock()
        self.nodes[0].overlay.send_block(block, ttl=2)
        yield self.deliver_messages()
        self.assertIn(block.block_id, self.nodes[0].overlay.relayed_broadcasts)
        self.assertIn(block.block_id, self.nodes[1].overlay.relayed_broadcasts)
        self.assertNotIn(block.block_id, node3.overlay.relayed_broadcasts)

    @inlineCallbacks
    def test_broadcast_half_block_pair(self):
        """
        Test broadcasting a half block pair
        """
        # Let node 3 discover node 2.
        node3 = self.create_node()
        self.nodes.append(node3)
        self.nodes[1].network.add_verified_peer(node3.my_peer)
        self.nodes[1].discovery.take_step()

        # TTL=1 (should not be relayed)
        block1 = TestBlock()
        block2 = TestBlock()
        self.nodes[0].overlay.send_block_pair(block1, block2, ttl=1)
        yield self.deliver_messages()
        self.assertIn(block1.block_id, self.nodes[0].overlay.relayed_broadcasts)
        self.assertNotIn(block1.block_id, self.nodes[1].overlay.relayed_broadcasts)
        self.assertNotIn(block1.block_id, node3.overlay.relayed_broadcasts)

        # TTL=2 (should be relayed)
        block1 = TestBlock()
        block2 = TestBlock()
        self.nodes[0].overlay.send_block_pair(block1, block2, ttl=2)
        yield self.deliver_messages()
        self.assertIn(block1.block_id, self.nodes[0].overlay.relayed_broadcasts)
        self.assertIn(block1.block_id, self.nodes[1].overlay.relayed_broadcasts)
        self.assertNotIn(block1.block_id, node3.overlay.relayed_broadcasts)

    @inlineCallbacks
    def test_intro_response_crawl(self):
        """
        Test whether we crawl a node when receiving an introduction response
        """
        self.nodes[0].endpoint.close()

        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        self.nodes[0].overlay.create_source_block(block_type=b'test', transaction={})
        yield self.deliver_messages()

        self.nodes[0].endpoint.open()

        # Crawl each other
        yield self.introduce_nodes()

        # We should have received the block now
        self.assertIsNotNone(self.nodes[1].overlay.persistence.get_latest(my_pubkey))

        # Check whether we do not crawl this node again in a short time
        self.nodes[0].endpoint.close()
        self.nodes[0].overlay.create_source_block(block_type=b'test', transaction={})
        self.nodes[0].endpoint.open()

        yield self.introduce_nodes()

        # We should not have crawled this second block
        self.assertEqual(self.nodes[1].overlay.persistence.get_latest(my_pubkey).sequence_number, 1)

    @inlineCallbacks
    def test_empty_crawl(self):
        """
        Test a crawl request to a peer without any blocks
        """
        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        yield self.nodes[1].overlay.send_crawl_request(self.nodes[0].my_peer, my_pubkey, 1, 1)

    @inlineCallbacks
    def test_invalid_block(self):
        """
        See if we can recover from database corruption.
        """
        # Create an invalid block
        invalid_block = TestBlock(key=self.nodes[0].overlay.my_peer.key)
        invalid_block.signature = 'a' * 64
        self.nodes[0].overlay.persistence.add_block(invalid_block)

        # We will attempt to add a new block to our chain.
        # We should see that we have database corruption and clean up our chain.
        # Afterward we continue the signing as usual
        my_pubkey = self.nodes[0].overlay.my_peer.public_key.key_to_bin()
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        yield self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                               block_type='test', transaction={})

        yield self.deliver_messages()

        # Both nodes should have this newly signed block added correctly to their database
        self.assertIsNotNone(self.nodes[0].overlay.persistence.get(my_pubkey, 1))
        self.assertIsNotNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))

    @inlineCallbacks
    def test_half_block_self_signed(self):
        """
        Test creating and disseminating a half block, signed by yourself
        """
        my_pubkey = self.nodes[0].overlay.my_peer.public_key.key_to_bin()
        yield self.nodes[0].overlay.self_sign_block(block_type='test', transaction={})

        yield self.deliver_messages()

        # The other node should now have the self-signed block
        self.assertIsNotNone(self.nodes[0].overlay.persistence.get(my_pubkey, 1))
        self.assertIsNotNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))

    @inlineCallbacks
    def test_half_block_link_block(self):
        """
        Test creating and disseminating a link block
        """
        source_peer_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        counter_peer_pubkey = self.nodes[1].my_peer.public_key.key_to_bin()

        # Create an initial source block with no counterpary
        yield self.nodes[0].overlay.create_source_block('test', {})
        yield self.deliver_messages()

        # Check the dissemination of the no counterparty source block
        self.assertIsNotNone(self.nodes[0].overlay.persistence.get(source_peer_pubkey, 1))
        block = self.nodes[1].overlay.persistence.get(source_peer_pubkey, 1)
        self.assertIsNotNone(block)

        # Create a Link Block
        yield self.nodes[1].overlay.create_link(block, block_type='link', additional_info={'a': 1, 'b': 2})
        yield self.deliver_messages()

        # Check the dissemination of the link block
        block_node_0 = self.nodes[0].overlay.persistence.get(counter_peer_pubkey, 1)
        block_node_1 = self.nodes[1].overlay.persistence.get(counter_peer_pubkey, 1)

        self.assertIsNotNone(block_node_0)
        self.assertIsNotNone(block_node_1)

        self.assertEqual(decode(block_node_0.transaction)[1], {'a': 1, 'b': 2})
        self.assertEqual(decode(block_node_1.transaction)[1], {'a': 1, 'b': 2})

    def test_db_remove(self):
        """
        Test pruning of the database when it grows too large
        """
        self.nodes[0].overlay.settings.max_db_blocks = 5

        for _ in grange(10):
            test_block = TestBlock()
            self.nodes[0].overlay.persistence.add_block(test_block)

        self.nodes[0].overlay.do_db_cleanup()
        self.assertEqual(self.nodes[0].overlay.persistence.get_number_of_known_blocks(), 5)

    def test_database_cleanup(self):
        """
        Test whether we are cleaning up the database correctly when there are too many blocks
        """
        for _ in range(5):
            self.nodes[0].overlay.persistence.add_block(TestBlock())

        self.assertEqual(self.nodes[0].overlay.persistence.get_number_of_known_blocks(), 5)
        self.nodes[0].overlay.settings.max_db_blocks = 3
        self.nodes[0].overlay.do_db_cleanup()
        self.assertEqual(self.nodes[0].overlay.persistence.get_number_of_known_blocks(), 3)

    @inlineCallbacks
    def test_double_spend(self):
        """
        Test that a double spend is correctly detected and stored
        """
        my_pubkey = self.nodes[0].overlay.my_peer.public_key.key_to_bin()
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        block1, block2 = yield self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0],
                                                                public_key=his_pubkey, block_type=b'test',
                                                                transaction={})
        yield self.deliver_messages()
        self.nodes[0].overlay.persistence.remove_block(block1)
        self.nodes[0].overlay.persistence.remove_block(block2)

        # Double spend
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0],
                                         public_key=his_pubkey, block_type=b'test', transaction={})
        yield self.deliver_messages()
        self.assertTrue(self.nodes[1].overlay.persistence.did_double_spend(my_pubkey))

    @inlineCallbacks
    def test_chain_crawl_with_gaps(self):
        """
        Test crawling a whole chain with gaps from a specific user.
        """
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        created_blocks = []
        for _ in range(0, 5):
            blocks = yield self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0],
                                                            public_key=his_pubkey, block_type=b'test', transaction={})
            created_blocks.append(blocks)

        yield self.deliver_messages()

        self.assertEqual(self.nodes[1].overlay.persistence.get_number_of_known_blocks(), 10)

        # Let node 1 remove some of the blocks
        self.nodes[1].overlay.persistence.remove_block(created_blocks[0][1])
        self.nodes[1].overlay.persistence.remove_block(created_blocks[2][1])
        self.nodes[1].overlay.persistence.remove_block(created_blocks[4][1])

        # Let node 1 crawl the chain of node 0
        self.nodes[1].overlay.settings.crawler = True
        yield self.introduce_nodes()
        yield self.sleep(0.2)  # Let blocks propagate

        self.assertEqual(self.nodes[1].overlay.persistence.get_number_of_known_blocks(), 10)

    @inlineCallbacks
    def test_chain_crawl(self):
        """
        Test crawl the whole chain of a specific peer
        """
        self.nodes[0].endpoint.close()
        key = ECCrypto().generate_key(u'very-low').pub().key_to_bin()
        for _ in range(4):
            self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=key,
                                             block_type=b'test', transaction={})
        self.nodes[0].endpoint.open()

        self.nodes[1].overlay.settings.crawler = True
        yield self.introduce_nodes()
        yield self.sleep(0.2)  # Let blocks propagate

        self.assertEqual(self.nodes[1].overlay.persistence.get_number_of_known_blocks(), 4)
