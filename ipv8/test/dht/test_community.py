from __future__ import absolute_import

import time

from twisted.internet.defer import Deferred, inlineCallbacks, succeed

from ..base import TestBase
from ..mocking.ipv8 import MockIPv8
from ...dht.community import DHTCommunity
from ...dht.provider import DHTCommunityProvider
from ...dht.routing import NODE_LIMIT_QUERIES, Node, distance
from ...messaging.anonymization.tunnel import IntroductionPoint


class TestDHTCommunity(TestBase):
    def setUp(self):
        super(TestDHTCommunity, self).setUp()
        self.initialize(DHTCommunity, 2)

        self.key = b'\x00' * 20
        self.value = b'test'
        self.value_in_store = self.nodes[0].overlay.serialize_value(self.value, sign=False)
        self.signed_in_store = self.nodes[0].overlay.serialize_value(self.value, sign=True)
        self.is_called = False

        now = time.time()
        for node1 in self.nodes:
            node1.overlay.cancel_pending_task('store_my_peer')
            for node2 in self.nodes:
                if node1 == node2:
                    continue
                dht_node1 = Node(node1.my_peer.key, node1.my_peer.address)
                dht_node2 = Node(node2.my_peer.key, node2.my_peer.address)
                node1.overlay.tokens[dht_node2] = (now, node2.overlay.generate_token(dht_node1))

    def create_node(self, *args, **kwargs):
        return MockIPv8(u"curve25519", DHTCommunity)

    @inlineCallbacks
    def test_routing_table(self):
        yield self.introduce_nodes()
        yield self.deliver_messages()

        node0_id = self.nodes[0].overlay.my_node_id
        node1_id = self.nodes[1].overlay.my_node_id

        node0_bucket = self.nodes[0].overlay.routing_table.get_bucket(node1_id)
        node1_bucket = self.nodes[1].overlay.routing_table.get_bucket(node0_id)

        self.assertTrue(node0_bucket and node0_bucket.prefix_id == u'')
        self.assertTrue(node1_bucket and node1_bucket.prefix_id == u'')

        self.assertTrue(node1_bucket.get(node0_id))
        self.assertTrue(node0_bucket.get(node1_id))

    @inlineCallbacks
    def test_ping_pong(self):
        yield self.introduce_nodes()
        node = yield self.nodes[0].overlay.ping(Node(self.nodes[1].my_peer.key,
                                                     self.nodes[1].my_peer.address))
        self.assertEqual(node, self.nodes[1].my_peer)

    @inlineCallbacks
    def test_ping_pong_fail(self):
        yield self.introduce_nodes()
        yield self.nodes[1].unload()
        d = self.nodes[0].overlay.ping(Node(self.nodes[1].my_peer.key,
                                            self.nodes[1].my_peer.address))
        yield self.deliver_messages()
        self.assertFailure(d, RuntimeError)

    @inlineCallbacks
    def test_store_value(self):
        yield self.introduce_nodes()
        node = yield self.nodes[0].overlay.store_value(self.key, self.value)
        self.assertIn(self.nodes[1].my_peer, node)
        self.assertEqual(self.nodes[1].overlay.storage.get(self.key), [self.value_in_store])

    @inlineCallbacks
    def test_store_value_fail(self):
        yield self.introduce_nodes()
        self.nodes[1].unload()
        d = self.nodes[0].overlay.store_value(self.key, self.value)
        yield self.deliver_messages()
        self.assertFailure(d, RuntimeError)

    @inlineCallbacks
    def test_find_nodes(self):
        yield self.introduce_nodes()
        nodes = yield self.nodes[0].overlay.find_nodes(self.key)
        self.assertSetEqual(set(nodes), set([Node(n.my_peer.key.pub().key_to_bin(), n.my_peer.address)
                                             for n in self.nodes[1:]]))

    @inlineCallbacks
    def test_find_values(self):
        yield self.introduce_nodes()
        self.nodes[1].overlay.storage.put(self.key, self.value_in_store)
        values = yield self.nodes[0].overlay.find_values(self.key)
        self.assertIn((self.value, None), values)

    @inlineCallbacks
    def test_find_values_signed(self):
        yield self.introduce_nodes()
        self.nodes[1].overlay.storage.put(self.key, self.signed_in_store)
        values = yield self.nodes[0].overlay.find_values(self.key)
        self.assertIn((self.value, self.nodes[0].my_peer.public_key.key_to_bin()), values)

    @inlineCallbacks
    def test_caching(self):
        # Add a third node
        node = MockIPv8(u"curve25519", DHTCommunity)
        self.add_node_to_experiment(node)

        # Sort nodes based on distance to target
        self.nodes.sort(key=lambda n: distance(n.overlay.my_node_id, self.key), reverse=True)

        self.nodes[0].overlay.on_node_discovered(self.nodes[1].my_peer.key, self.nodes[1].my_peer.address)
        self.nodes[1].overlay.on_node_discovered(self.nodes[2].my_peer.key, self.nodes[2].my_peer.address)

        self.nodes[2].overlay.storage.put(self.key, self.value_in_store)
        self.nodes[0].overlay.find_values(self.key)
        yield self.deliver_messages()
        self.assertEqual(self.nodes[1].overlay.storage.get(self.key), [self.value_in_store])

    @inlineCallbacks
    def test_refresh(self):
        yield self.introduce_nodes()
        yield self.deliver_messages()

        bucket = self.nodes[0].overlay.routing_table.get_bucket(self.nodes[1].overlay.my_node_id)
        bucket.last_changed = 0

        self.nodes[0].overlay.find_values = lambda *args: setattr(self, 'is_called', True) or succeed([])
        self.nodes[0].overlay.value_maintenance()
        self.assertNotEqual(bucket.last_changed, 0)
        self.assertTrue(self.is_called)

        self.is_called = False
        prev_ts = bucket.last_changed
        self.nodes[0].overlay.value_maintenance()
        self.assertEqual(bucket.last_changed, prev_ts)
        self.assertFalse(self.is_called)

    @inlineCallbacks
    def test_token(self):
        dht_node = Node(self.nodes[1].my_peer.key, self.nodes[1].my_peer.address)

        # Since the setup should have already have generated tokens, a direct store should work.
        yield self.introduce_nodes()
        self.nodes[0].overlay.store_on_nodes(self.key, [self.value_in_store], [dht_node])
        yield self.deliver_messages()
        self.assertEqual(self.nodes[1].overlay.storage.get(self.key), [self.value_in_store])

        # Without tokens..
        for node in self.nodes:
            node.overlay.tokens.clear()
        self.nodes[1].overlay.storage.items.clear()
        yield self.introduce_nodes()
        d = self.nodes[0].overlay.store_on_nodes(self.key, [self.value_in_store], [dht_node])
        self.assertFailure(d, RuntimeError)
        self.assertEqual(self.nodes[1].overlay.storage.get(self.key), [])

        # With a bad token..
        self.nodes[0].overlay.tokens[dht_node] = (0, b'faketoken')
        yield self.introduce_nodes()
        d = self.nodes[0].overlay.store_on_nodes(self.key, [self.value_in_store], [dht_node])
        yield self.deliver_messages()
        self.assertFailure(d, RuntimeError)
        self.assertEqual(self.nodes[1].overlay.storage.get(self.key), [])

    @inlineCallbacks
    def test_provider(self):
        """
        Test the DHT provider (used to fetch peers in the hidden services)
        """
        self.add_node_to_experiment(self.create_node())
        test_deferred = Deferred()

        yield self.introduce_nodes()
        dht_provider_1 = DHTCommunityProvider(self.nodes[0].overlay, 1337)
        dht_provider_2 = DHTCommunityProvider(self.nodes[1].overlay, 1338)
        dht_provider_3 = DHTCommunityProvider(self.nodes[2].overlay, 1338)
        dht_provider_1.announce(b'a' * 20, IntroductionPoint(self.nodes[0].overlay.my_peer, '\x01' * 20))
        dht_provider_2.announce(b'a' * 20, IntroductionPoint(self.nodes[1].overlay.my_peer, '\x02' * 20))

        yield self.deliver_messages(.5)

        def on_peers(peers):
            self.assertEqual(len(peers[1]), 2)
            test_deferred.callback(None)

        dht_provider_3.lookup(b'a' * 20, on_peers)

        yield test_deferred

    @inlineCallbacks
    def test_provider_invalid_data(self):
        """
        Test the DHT provider when invalid data arrives
        """
        self.nodes[0].overlay.find_values = lambda _: succeed([('invalid_data', None)])
        dht_provider = DHTCommunityProvider(self.nodes[0].overlay, 1337)

        test_deferred = Deferred()

        def on_peers(peers):
            self.assertEqual(len(peers[1]), 0)
            test_deferred.callback(None)

        dht_provider.lookup(b'a' * 20, on_peers)
        yield test_deferred

    @inlineCallbacks
    def test_rate_limit(self):
        yield self.introduce_nodes()
        yield self.deliver_messages(.5)

        node0 = Node(self.nodes[0].my_peer.key, self.nodes[0].my_peer.address)
        node1 = Node(self.nodes[1].my_peer.key, self.nodes[1].my_peer.address)

        # Send pings from node0 to node1 until blocked
        num_queries = len(self.nodes[1].overlay.routing_table.get(node0.id).last_queries)
        for _ in range(NODE_LIMIT_QUERIES - num_queries):
            yield self.nodes[0].overlay.ping(node1)

        # Node1 must have blocked node0
        self.assertTrue(self.nodes[1].overlay.routing_table.get(node0.id).blocked)
        # Additional pings should get dropped (i.e. timeout)
        d = self.nodes[0].overlay.ping(node1)
        self.assertFailure(d, RuntimeError)


class TestDHTCommunityXL(TestBase):

    def setUp(self):
        super(TestDHTCommunityXL, self).setUp()
        self.initialize(DHTCommunity, 15)
        for node in self.nodes:
            node.overlay.cancel_pending_task('store_peer')
            node.overlay.ping = lambda _: succeed(None)

    def create_node(self, *args, **kwargs):
        return MockIPv8(u"curve25519", DHTCommunity)

    def get_closest_nodes(self, node_id, max_nodes=8):
        return sorted(self.nodes, key=lambda n: distance(n.overlay.my_node_id, node_id))[:max_nodes]

    @inlineCallbacks
    def test_full_protocol(self):
        # Fill routing tables
        yield self.introduce_nodes()
        yield self.deliver_messages(.5)

        # Store key value pair
        kv_pair = (b'\x00' * 20, b'test1')
        yield self.nodes[0].overlay.store_value(*kv_pair)

        # Check if the closest nodes have now stored the key
        for node in self.get_closest_nodes(kv_pair[0]):
            self.assertTrue(node.overlay.storage.get(kv_pair[0]), kv_pair[1])

        # Store another value under the same key
        yield self.nodes[1].overlay.store_value(b'\x00' * 20, b'test2', sign=True)

        # Check if we get both values
        values = yield self.nodes[-1].overlay.find_values(b'\x00' * 20)
        self.assertIn((b'test1', None), values)
        self.assertIn((b'test2', self.nodes[1].my_peer.public_key.key_to_bin()), values)
