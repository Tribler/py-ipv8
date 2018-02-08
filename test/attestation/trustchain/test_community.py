from ipv8.attestation.trustchain.community import TrustChainCommunity, UNKNOWN_SEQ
from test.attestation.trustchain.test_block import TestBlock
from test.base import TestBase
from test.mocking.ipv8 import MockIPv8
from test.util import twisted_wrapper


class TestTrustChainCommunity(TestBase):

    def setUp(self):
        super(TestTrustChainCommunity, self).setUp()
        self.initialize(TrustChainCommunity, 2)

    def create_node(self):
        return MockIPv8(u"curve25519", TrustChainCommunity, working_directory=u":memory:")

    @twisted_wrapper
    def test_sign_half_block(self):
        """
        Check if a block signed by one party is stored in the databases of both parties.
        """
        self.nodes[1].overlay.should_sign = lambda x: False

        yield self.introduce_nodes()

        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         transaction={})

        yield self.deliver_messages()

        for node_nr in [0, 1]:
            self.assertIsNotNone(self.nodes[node_nr].overlay.persistence.get(my_pubkey, 1))
            self.assertEqual(self.nodes[node_nr].overlay.persistence.get(my_pubkey, 1).link_sequence_number, UNKNOWN_SEQ)

    @twisted_wrapper
    def test_sign_full_block(self):
        """
        Check if a double signed transaction is stored in the databases of both parties.
        """
        yield self.introduce_nodes()

        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        yield self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                               transaction={})

        for node_nr in [0, 1]:
            self.assertIsNotNone(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 1))
            self.assertEqual(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 1).link_sequence_number, 1)

    @twisted_wrapper
    def test_get_linked(self):
        """
        Check if a both halves of a fully signed block link to each other.
        """
        yield self.introduce_nodes()

        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         transaction={})

        yield self.deliver_messages()

        for node_nr in [0, 1]:
            my_block = self.nodes[node_nr].overlay.persistence.get(my_pubkey, 1)
            his_block = self.nodes[node_nr].overlay.persistence.get(his_pubkey, 1)
            self.assertEqual(self.nodes[node_nr].overlay.persistence.get_linked(my_block), his_block)
            self.assertEqual(self.nodes[node_nr].overlay.persistence.get_linked(his_block), my_block)

    @twisted_wrapper
    def test_crawl(self):
        """
        Check if a block can be crawled.

         1. Node 0 makes a half block, but doesn't/can't share it with Node 1.
         2. Node 1 send a crawl request to Node 0
         3. Node 0 sends his half block back
        """
        self.nodes[1].overlay.should_sign = lambda x: False

        yield self.introduce_nodes()

        self.nodes[0].endpoint.close()

        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         transaction={})

        yield self.deliver_messages()

        self.assertIsNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))

        self.nodes[0].endpoint.open()
        self.nodes[1].overlay.send_crawl_request(self.nodes[0].my_peer, my_pubkey, 1)

        yield self.deliver_messages()

        self.assertIsNotNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))
        self.assertEqual(self.nodes[1].overlay.persistence.get(my_pubkey, 1).link_sequence_number, UNKNOWN_SEQ)

    @twisted_wrapper
    def test_crawl_default(self):
        """
        Check if the default crawl strategy produces blocks.
        """
        self.nodes[1].overlay.should_sign = lambda x: False

        yield self.introduce_nodes()

        self.nodes[0].endpoint.close()

        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         transaction={})

        yield self.deliver_messages()

        self.assertIsNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))

        self.nodes[0].endpoint.open()
        self.nodes[1].overlay.send_crawl_request(self.nodes[0].my_peer, my_pubkey)

        yield self.deliver_messages()

        self.assertIsNotNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))
        self.assertEqual(self.nodes[1].overlay.persistence.get(my_pubkey, 1).link_sequence_number, UNKNOWN_SEQ)

    @twisted_wrapper
    def test_crawl_no_blocks(self):
        """
        Check if blocks don't magically appear.
        """
        yield self.introduce_nodes()

        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        self.nodes[1].overlay.send_crawl_request(self.nodes[0].my_peer, my_pubkey, 1)

        yield self.deliver_messages()

        self.assertIsNone(self.nodes[1].overlay.persistence.get(my_pubkey, 0))

    @twisted_wrapper
    def test_crawl_negative_index(self):
        """
        Check if a block can be crawled by negative range.
        """
        self.nodes[1].overlay.should_sign = lambda x: False
        yield self.introduce_nodes()
        self.nodes[0].endpoint.close()

        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()
        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         transaction={})

        yield self.deliver_messages()
        self.assertIsNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))
        self.nodes[0].endpoint.open()

        self.nodes[1].overlay.send_crawl_request(self.nodes[0].my_peer, my_pubkey, -1)

        yield self.deliver_messages()

        self.assertIsNotNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))
        self.assertEqual(self.nodes[1].overlay.persistence.get(my_pubkey, 1).link_sequence_number, UNKNOWN_SEQ)

    @twisted_wrapper
    def test_parallel_blocks(self):
        """
        Check if blocks created in parallel will properly be stored in the database.
        """
        yield self.introduce_nodes()

        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         transaction={})
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         transaction={})

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

    @twisted_wrapper
    def test_retrieve_missing_block(self):
        """
        Check if missing blocks are retrieved through a crawl request.
        """
        yield self.introduce_nodes()

        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].endpoint.close()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         transaction={})

        yield self.deliver_messages()

        self.nodes[0].endpoint.open()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         transaction={})

        yield self.sleep()

        for node_nr in [0, 1]:
            # His first block -> my first block
            self.assertIsNotNone(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 1))
            self.assertEqual(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 1).link_sequence_number, 1)
            # His second block -> my second block
            self.assertIsNotNone(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 2))
            self.assertEqual(self.nodes[node_nr].overlay.persistence.get(his_pubkey, 2).link_sequence_number, 2)

    @twisted_wrapper
    def test_send_block_pair(self):
        """
        Test sending and receiving a pair of blocks from one to another peer.
        """
        yield self.introduce_nodes()

        block1 = TestBlock()
        block2 = TestBlock()
        self.nodes[0].overlay.send_block_pair(block1, block2, self.nodes[0].network.verified_peers[0].address)

        yield self.deliver_messages()

        self.assertTrue(self.nodes[1].overlay.persistence.get_latest(block1.public_key))
        self.assertTrue(self.nodes[1].overlay.persistence.get_latest(block2.public_key))

    @twisted_wrapper
    def test_broadcast_half_block(self):
        """
        Test broadcasting a half block
        """
        yield self.introduce_nodes()

        # Let node 3 discover node 2.
        node3 = self.create_node()
        self.nodes.append(node3)
        self.nodes[1].network.add_verified_peer(node3.my_peer)
        self.nodes[1].discovery.take_step()

        block = TestBlock()
        self.nodes[0].overlay.send_block(block)

        yield self.deliver_messages()

        self.assertTrue(node3.overlay.relayed_broadcasts)

    @twisted_wrapper
    def test_broadcast_half_block_pair(self):
        """
        Test broadcasting a half block pair
        """
        yield self.introduce_nodes()

        # Let node 3 discover node 2.
        node3 = self.create_node()
        self.nodes.append(node3)
        self.nodes[1].network.add_verified_peer(node3.my_peer)
        self.nodes[1].discovery.take_step()

        block1 = TestBlock()
        block2 = TestBlock()
        self.nodes[0].overlay.send_block_pair(block1, block2)

        yield self.deliver_messages()

        for node_nr in [0, 1]:
            self.assertIsNotNone(self.nodes[node_nr].overlay.persistence.get_latest(block1.public_key))
            self.assertIsNotNone(self.nodes[node_nr].overlay.persistence.get_latest(block2.public_key))
