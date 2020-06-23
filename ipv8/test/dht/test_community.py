import time
from asyncio import TimeoutError, ensure_future, wait_for

from ..base import TestBase
from ..mocking.ipv8 import MockIPv8
from ...dht import DHTError
from ...dht.community import DHTCommunity
from ...dht.provider import DHTCommunityProvider
from ...dht.routing import NODE_LIMIT_QUERIES, Node, RoutingTable, distance
from ...messaging.anonymization.tunnel import IntroductionPoint
from ...util import succeed


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
        for node in self.nodes:
            node.overlay.cancel_pending_task('store_my_peer')
            node.overlay.token_maintenance()
        for node1 in self.nodes:
            for node2 in self.nodes:
                if node1 == node2:
                    continue
                dht_node1 = Node(node1.my_peer.key, node1.my_peer.address)
                dht_node2 = Node(node2.my_peer.key, node2.my_peer.address)
                node1.overlay.tokens[dht_node2] = (now, node2.overlay.generate_token(dht_node1))

    def create_node(self, *args, **kwargs):
        return MockIPv8(u"curve25519", DHTCommunity)

    async def test_routing_table(self):
        await self.introduce_nodes()
        await self.deliver_messages()

        node0_id = self.nodes[0].overlay.my_node_id
        node1_id = self.nodes[1].overlay.my_node_id

        node0_bucket = self.nodes[0].overlay.routing_table.get_bucket(node1_id)
        node1_bucket = self.nodes[1].overlay.routing_table.get_bucket(node0_id)

        self.assertTrue(node0_bucket and node0_bucket.prefix_id == u'')
        self.assertTrue(node1_bucket and node1_bucket.prefix_id == u'')

        self.assertTrue(node1_bucket.get(node0_id))
        self.assertTrue(node0_bucket.get(node1_id))

    async def test_ping_pong(self):
        await self.introduce_nodes()
        node = await self.nodes[0].overlay.ping(Node(self.nodes[1].my_peer.key,
                                                     self.nodes[1].my_peer.address))
        self.assertEqual(node, self.nodes[1].my_peer)

    async def test_ping_pong_fail(self):
        await self.introduce_nodes()
        await self.nodes[1].unload()
        with self.assertRaises(TimeoutError):
            await wait_for(self.nodes[0].overlay.ping(Node(self.nodes[1].my_peer.key,
                                                           self.nodes[1].my_peer.address)), 0.1)

    async def test_store_value(self):
        await self.introduce_nodes()
        node = await self.nodes[0].overlay.store_value(self.key, self.value)
        self.assertIn(self.nodes[1].my_peer, node)
        self.assertEqual(self.nodes[1].overlay.storage.get(self.key), [self.value_in_store])

    async def test_store_value_fail(self):
        await self.introduce_nodes()
        self.nodes[0].overlay.routing_table = RoutingTable(self.nodes[0].overlay.my_node_id)
        with self.assertRaises(DHTError):
            await self.nodes[0].overlay.store_value(self.key, self.value)

    async def test_find_nodes(self):
        await self.introduce_nodes()
        nodes = await self.nodes[0].overlay.find_nodes(self.key)
        self.assertSetEqual(set(nodes), set([Node(n.my_peer.key.pub().key_to_bin(), n.my_peer.address)
                                             for n in self.nodes[1:]]))

    async def test_find_values(self):
        await self.introduce_nodes()
        self.nodes[1].overlay.storage.put(self.key, self.value_in_store)
        values = await self.nodes[0].overlay.find_values(self.key)
        self.assertIn((self.value, None), values)

    async def test_find_values_signed(self):
        await self.introduce_nodes()
        self.nodes[1].overlay.storage.put(self.key, self.signed_in_store)
        values = await self.nodes[0].overlay.find_values(self.key)
        self.assertIn((self.value, self.nodes[0].my_peer.public_key.key_to_bin()), values)

    async def test_caching(self):
        # Add a third node
        node = MockIPv8(u"curve25519", DHTCommunity)
        node.overlay.token_maintenance()
        self.add_node_to_experiment(node)

        # Sort nodes based on distance to target
        self.nodes.sort(key=lambda n: distance(n.overlay.my_node_id, self.key), reverse=True)

        self.nodes[0].overlay.on_node_discovered(self.nodes[1].my_peer.key, self.nodes[1].my_peer.address)
        self.nodes[1].overlay.on_node_discovered(self.nodes[2].my_peer.key, self.nodes[2].my_peer.address)

        self.nodes[2].overlay.storage.put(self.key, self.value_in_store)
        await self.nodes[0].overlay.find_values(self.key)
        await self.deliver_messages(.2)
        self.assertEqual(self.nodes[1].overlay.storage.get(self.key), [self.value_in_store])

    async def test_refresh(self):
        await self.introduce_nodes()
        await self.deliver_messages()

        bucket = self.nodes[0].overlay.routing_table.get_bucket(self.nodes[1].overlay.my_node_id)
        bucket.last_changed = 0

        self.nodes[0].overlay.find_values = lambda *args: setattr(self, 'is_called', True) or succeed([])
        await self.nodes[0].overlay.node_maintenance()
        self.assertNotEqual(bucket.last_changed, 0)
        self.assertTrue(self.is_called)

        self.is_called = False
        prev_ts = bucket.last_changed
        await self.nodes[0].overlay.node_maintenance()
        self.assertEqual(bucket.last_changed, prev_ts)
        self.assertFalse(self.is_called)

    async def test_token(self):
        dht_node = Node(self.nodes[1].my_peer.key, self.nodes[1].my_peer.address)

        # Since the setup should have already have generated tokens, a direct store should work.
        await self.introduce_nodes()
        await self.nodes[0].overlay.store_on_nodes(self.key, [self.value_in_store], [dht_node])
        await self.deliver_messages()
        self.assertEqual(self.nodes[1].overlay.storage.get(self.key), [self.value_in_store])

        # Without tokens..
        for node in self.nodes:
            node.overlay.tokens.clear()
        self.nodes[1].overlay.storage.items.clear()
        await self.introduce_nodes()
        with self.assertRaises(DHTError):
            await self.nodes[0].overlay.store_on_nodes(self.key, [self.value_in_store], [dht_node])
        self.assertEqual(self.nodes[1].overlay.storage.get(self.key), [])

        # With a bad token..
        self.nodes[0].overlay.tokens[dht_node] = (0, b'faketoken')
        await self.introduce_nodes()
        with self.assertRaises(DHTError):
            await self.nodes[0].overlay.store_on_nodes(self.key, [self.value_in_store], [dht_node])
        self.assertEqual(self.nodes[1].overlay.storage.get(self.key), [])

    async def test_provider(self):
        """
        Test the DHT provider (used to fetch peers in the hidden services)
        """
        self.add_node_to_experiment(self.create_node())

        await self.introduce_nodes()
        dht_provider_1 = DHTCommunityProvider(self.nodes[0].overlay, 1337)
        dht_provider_2 = DHTCommunityProvider(self.nodes[1].overlay, 1338)
        dht_provider_3 = DHTCommunityProvider(self.nodes[2].overlay, 1338)
        await dht_provider_1.announce(b'a' * 20, IntroductionPoint(self.nodes[0].overlay.my_peer, '\x01' * 20))
        await dht_provider_2.announce(b'a' * 20, IntroductionPoint(self.nodes[1].overlay.my_peer, '\x02' * 20))

        await self.deliver_messages(.5)

        peers = await dht_provider_3.lookup(b'a' * 20)
        self.assertEqual(len(peers[1]), 2)

    async def test_provider_invalid_data(self):
        """
        Test the DHT provider when invalid data arrives
        """
        self.nodes[0].overlay.find_values = lambda _: succeed([('invalid_data', None)])
        dht_provider = DHTCommunityProvider(self.nodes[0].overlay, 1337)
        peers = await dht_provider.lookup(b'a' * 20)
        self.assertEqual(len(peers[1]), 0)

    async def test_rate_limit(self):
        await self.introduce_nodes()
        await self.deliver_messages(.5)

        node0 = Node(self.nodes[0].my_peer.key, self.nodes[0].my_peer.address)
        node1 = Node(self.nodes[1].my_peer.key, self.nodes[1].my_peer.address)

        # Send pings from node0 to node1 until blocked
        num_queries = len(self.nodes[1].overlay.routing_table.get(node0.id).last_queries)
        for _ in range(NODE_LIMIT_QUERIES - num_queries):
            await self.nodes[0].overlay.ping(node1)

        # Node1 must have blocked node0
        self.assertTrue(self.nodes[1].overlay.routing_table.get(node0.id).blocked)
        # Additional pings should get dropped (i.e. timeout)
        with self.assertRaises(TimeoutError):
            await wait_for(self.nodes[0].overlay.ping(node1), 0.1)

    async def test_unload_while_contacting_node(self):
        await self.introduce_nodes()
        overlay = self.nodes[0].overlay
        ensure_future(overlay.find_nodes(self.key))
        await overlay.unload()
        self.assertTrue(overlay.request_cache._shutdown)
        self.assertTrue(overlay._shutdown)


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

    async def test_full_protocol(self):
        # Fill routing tables
        await self.introduce_nodes()
        await self.deliver_messages(.5)

        # Store key value pair
        kv_pair = (b'\x00' * 20, b'test1')
        await self.nodes[0].overlay.store_value(*kv_pair)

        # Check if the closest nodes have now stored the key
        for node in self.get_closest_nodes(kv_pair[0]):
            self.assertTrue(node.overlay.storage.get(kv_pair[0]), kv_pair[1])

        # Store another value under the same key
        await self.nodes[1].overlay.store_value(b'\x00' * 20, b'test2', sign=True)

        # Check if we get both values
        values = await self.nodes[-1].overlay.find_values(b'\x00' * 20)
        self.assertIn((b'test1', None), values)
        self.assertIn((b'test2', self.nodes[1].my_peer.public_key.key_to_bin()), values)
