import time
from asyncio import TimeoutError, ensure_future, wait_for
from typing import Iterable

from ...dht import DHTError
from ...dht.community import DHTCommunity
from ...dht.routing import NODE_LIMIT_QUERIES, Node, RoutingTable, distance
from ...util import succeed
from ..mocking.ipv8 import MockIPv8
from .base import TestDHTBase


class TestDHTCommunity(TestDHTBase[DHTCommunity]):
    """
    Tests for the DHT Community.
    """

    def setUp(self) -> None:
        """
        Setup with two nodes.
        """
        super().setUp()
        self.initialize(DHTCommunity, 2)

        self.key = b'\x00' * 20
        self.value = b'test'
        self.value_in_store = self.overlay(0).serialize_value(self.value, sign=False)
        self.signed_in_store = self.overlay(0).serialize_value(self.value, sign=True)
        self.is_called = False

        for node in self.nodes:
            node.overlay.cancel_pending_task('store_my_peer')
            node.overlay.token_maintenance()

    def create_node(self, *args, **kwargs) -> MockIPv8:  # noqa: ANN002
        """
        Create a new node that runs the DHTCommunity with a curve25519 key.
        """
        return MockIPv8("curve25519", DHTCommunity)

    async def test_routing_table(self) -> None:
        """
        Test if the routing table is properly updated.
        """
        await self.introduce_nodes()
        await self.deliver_messages()

        node0_id = self.my_node_id(0)
        node1_id = self.my_node_id(1)

        node0_bucket = self.routing_table(0).get_bucket(node1_id)
        node1_bucket = self.routing_table(1).get_bucket(node0_id)

        self.assertTrue(node0_bucket and node0_bucket.prefix_id == '')
        self.assertTrue(node1_bucket and node1_bucket.prefix_id == '')

        self.assertTrue(node1_bucket.get(node0_id))
        self.assertTrue(node0_bucket.get(node1_id))

    async def test_ping_pong(self) -> None:
        """
        Tests if pings are properly propagated.
        """
        await self.introduce_nodes()
        node = await self.overlay(0).ping(Node(self.private_key(1), self.address(1)))
        self.assertEqual(node, self.my_peer(1))

    async def test_ping_pong_fail(self) -> None:
        """
        Test if pings can timeout.
        """
        await self.introduce_nodes()
        await self.nodes[1].stop()
        with self.assertRaises(TimeoutError):
            await wait_for(self.overlay(0).ping(Node(self.private_key(1), self.address(1))), 0.1)

    async def test_store_value(self) -> None:
        """
        Test if values are properly stored.
        """
        await self.introduce_nodes()
        node = await self.overlay(0).store_value(self.key, self.value)
        self.assertIn(self.my_peer(1), node)
        self.assertEqual(self.storage(1).get(self.key), [self.value_in_store])

    async def test_store_value_fail(self) -> None:
        """
        Test if values are not stored irresponsibly.
        """
        await self.introduce_nodes()
        self.overlay(0).routing_tables[self.address(0).__class__] = RoutingTable(self.my_node_id(0))
        with self.assertRaises(DHTError):
            await self.overlay(0).store_value(self.key, self.value)

    async def test_find_nodes(self) -> None:
        """
        Test if nodes can be found.
        """
        await self.introduce_nodes()
        nodes = await self.overlay(0).find_nodes(self.key)
        self.assertSetEqual(set(nodes), {Node(n.my_peer.key.pub().key_to_bin(), n.my_peer.address)
                                         for n in self.nodes[1:]})

    async def test_find_values(self) -> None:
        """
        Test if values can be found.
        """
        await self.introduce_nodes()
        self.storage(1).put(self.key, self.value_in_store)
        values = await self.overlay(0).find_values(self.key)
        self.assertIn((self.value, None), values)

    async def test_find_values_signed(self) -> None:
        """
        Test if signed values can be found.
        """
        await self.introduce_nodes()
        self.storage(1).put(self.key, self.signed_in_store)
        values = await self.overlay(0).find_values(self.key)
        self.assertIn((self.value, self.key_bin(0)), values)

    async def test_caching(self) -> None:
        """
        Test if values are cached.
        """
        # Add a third node
        node = MockIPv8("curve25519", DHTCommunity)
        node.overlay.token_maintenance()
        self.add_node_to_experiment(node)

        # Sort nodes based on distance to target
        self.nodes.sort(key=lambda n: distance(n.overlay.get_my_node_id(n.overlay.my_peer), self.key), reverse=True)

        self.overlay(0).on_node_discovered(self.key_bin(1), self.address(1))
        self.overlay(1).on_node_discovered(self.key_bin(2), self.address(2))

        self.storage(2).put(self.key, self.value_in_store)
        await self.overlay(0).find_values(self.key)
        await self.deliver_messages(.2)
        self.assertEqual(self.storage(1).get(self.key), [self.value_in_store])

    async def test_refresh(self) -> None:
        """
        Test if refreshing works.
        """
        await self.introduce_nodes()
        await self.deliver_messages()

        bucket = self.routing_table(0).get_bucket(self.my_node_id(1))
        bucket.last_changed = 0

        self.overlay(0).find_values = lambda *args: setattr(self, 'is_called', True) or succeed([])
        await self.overlay(0).node_maintenance()
        self.assertNotEqual(bucket.last_changed, 0)
        self.assertTrue(self.is_called)

        self.is_called = False
        prev_ts = bucket.last_changed
        await self.overlay(0).node_maintenance()
        self.assertEqual(bucket.last_changed, prev_ts)
        self.assertFalse(self.is_called)

    async def test_token(self) -> None:
        """
        Test if tokens work.
        """
        dht_node = Node(self.private_key(1), self.address(1))

        # Without tokens
        await self.introduce_nodes()
        with self.assertRaises(DHTError):
            await self.overlay(0).store_on_nodes(self.key, [self.value_in_store], [dht_node])
        self.assertEqual(self.storage(1).get(self.key), [])

        # With tokens
        for node1 in self.nodes:
            for node2 in self.nodes:
                if node1 == node2:
                    continue
                dht_node1 = Node(node1.my_peer.key, node1.my_peer.address)
                dht_node2 = Node(node2.my_peer.key, node2.my_peer.address)
                node1.overlay.tokens[dht_node2.id] = (time.time(), node2.overlay.generate_token(dht_node1))
        await self.introduce_nodes()
        await self.deliver_messages()
        await self.overlay(0).store_on_nodes(self.key, [self.value_in_store], [dht_node])
        self.assertEqual(self.storage(1).get(self.key), [self.value_in_store])

        # With a bad token..
        for node in self.nodes:
            node.overlay.tokens.clear()
        self.storage(1).items.clear()
        self.overlay(0).tokens[dht_node.id] = (0, b'faketoken')
        await self.introduce_nodes()
        with self.assertRaises(DHTError):
            await self.overlay(0).store_on_nodes(self.key, [self.value_in_store], [dht_node])
        self.assertEqual(self.storage(1).get(self.key), [])

    async def test_rate_limit(self) -> None:
        """
        Test that the rate limit is respected.
        """
        await self.introduce_nodes()
        await self.deliver_messages(.5)

        node0 = Node(self.private_key(0), self.address(0))
        node1 = Node(self.private_key(1), self.address(1))

        # Send pings from node0 to node1 until blocked
        num_queries = len(self.routing_table(1).get(node0.id).last_queries)
        for _ in range(NODE_LIMIT_QUERIES - num_queries):
            await self.overlay(0).ping(node1)

        # Node1 must have blocked node0
        self.assertTrue(self.routing_table(1).get(node0.id).blocked)
        # Additional pings should get dropped (i.e. timeout)
        with self.assertRaises(TimeoutError):
            await wait_for(self.overlay(0).ping(node1), 0.1)

    async def test_unload_while_contacting_node(self) -> None:
        """
        Test unloading nodes while contacting them.
        """
        await self.introduce_nodes()
        find_task = ensure_future(self.overlay(0).find_nodes(self.key))
        await self.overlay(0).unload()
        await find_task
        self.assertTrue(self.overlay(0).request_cache._shutdown)  # noqa: SLF001
        self.assertTrue(self.overlay(0)._shutdown)  # noqa: SLF001


class TestDHTCommunityXL(TestDHTBase[DHTCommunity]):
    """
    Fat tests for the DHT Community.
    """

    def setUp(self) -> None:
        """
        Set up 15 nodes that run the DHT Community.
        """
        super().setUp()
        self.initialize(DHTCommunity, 15)
        for node in self.nodes:
            node.overlay.cancel_pending_task('store_peer')
            node.overlay.ping = lambda _: succeed(None)

    def create_node(self, *args, **kwargs) -> MockIPv8:  # noqa: ANN002
        """
        Create a new node that runs the DHTCommunity with a curve25519 key.
        """
        return MockIPv8("curve25519", DHTCommunity)

    def get_closest_nodes(self, node_id: bytes, max_nodes: int = 8) -> Iterable[MockIPv8]:
        """
        Get the nodes closest to a given node id.
        """
        return sorted(self.nodes,
                      key=lambda n: distance(n.overlay.get_my_node_id(n.overlay.my_peer), node_id))[:max_nodes]

    async def test_full_protocol(self) -> None:
        """
        Check if the full DHT protocol works.
        """
        # Fill routing tables
        await self.introduce_nodes()
        await self.deliver_messages(.5)

        # Store key value pair
        kv_pair = (b'\x00' * 20, b'test1')
        await self.overlay(0).store_value(*kv_pair)

        # Check if the closest nodes have now stored the key
        for node in self.get_closest_nodes(kv_pair[0]):
            self.assertTrue(node.overlay.get_storage(node.overlay.my_peer).get(kv_pair[0]), kv_pair[1])

        # Store another value under the same key
        await self.overlay(1).store_value(b'\x00' * 20, b'test2', sign=True)

        # Check if we get both values
        values = await self.nodes[-1].overlay.find_values(b'\x00' * 20)
        self.assertIn((b'test1', None), values)
        self.assertIn((b'test2', self.key_bin(1)), values)
