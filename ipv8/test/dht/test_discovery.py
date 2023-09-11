from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from ...dht import DHTError
from ...dht.discovery import DHTDiscoveryCommunity
from ...dht.provider import DHTCommunityProvider
from ...dht.routing import Node, RoutingTable
from ...messaging.anonymization.tunnel import IntroductionPoint
from ...util import succeed
from ..mocking.ipv8 import MockIPv8
from .base import TestDHTBase

if TYPE_CHECKING:
    from ...types import Address


class TestDHTDiscoveryCommunity(TestDHTBase[DHTDiscoveryCommunity]):
    """
    Tests related to the DHTDiscoveryCommunity behaviors.
    """

    def setUp(self) -> None:
        """
        Create two discovery communities, without token maintenance.
        """
        super().setUp()
        self.initialize(DHTDiscoveryCommunity, 2)
        self.pinged = None
        self.puncture_to = None

        for node in self.nodes:
            node.overlay.cancel_pending_task('store_peer')
            node.overlay.token_maintenance()

    def create_node(self, *args: Any, **kwargs) -> MockIPv8:  # noqa: ANN401
        """
        We only allow curve 25519 (libnacl) keys.
        """
        return MockIPv8("curve25519", DHTDiscoveryCommunity)

    async def test_provider(self) -> None:
        """
        Test the DHT provider (used to fetch peers in the hidden services).
        """
        self.add_node_to_experiment(self.create_node())

        await self.introduce_nodes()
        dht_provider_1 = DHTCommunityProvider(self.overlay(0), 1337)
        dht_provider_2 = DHTCommunityProvider(self.overlay(1), 1338)
        dht_provider_3 = DHTCommunityProvider(self.overlay(2), 1338)
        await dht_provider_1.announce(b'a' * 20, IntroductionPoint(self.my_peer(0), b'\x01' * 20))
        await dht_provider_2.announce(b'a' * 20, IntroductionPoint(self.my_peer(1), b'\x02' * 20))

        await self.deliver_messages(.5)

        peers = await dht_provider_3.lookup(b'a' * 20)
        self.assertEqual(len(peers[1]), 2)

    async def test_provider_invalid_data(self) -> None:
        """
        Test the DHT provider when invalid data arrives.
        """
        self.overlay(0).find_values = lambda _: succeed([('invalid_data', None)])
        dht_provider = DHTCommunityProvider(self.overlay(0), 1337)
        peers = await dht_provider.lookup(b'a' * 20)
        self.assertEqual(len(peers[1]), 0)

    async def test_store_peer(self) -> None:
        """
        Check if peers properly make themselves part of the DHT.
        """
        await self.introduce_nodes()
        await self.overlay(0).store_peer()
        self.assertIn(self.mid(0), self.overlay(1).store)
        self.assertIn(self.mid(0), self.overlay(0).store_for_me)

    async def test_store_peer_fail(self) -> None:
        """
        Check if the routing table does not update if our node id is already present.
        """
        await self.introduce_nodes()
        self.overlay(0).routing_tables[self.address(0).__class__] = RoutingTable(self.my_node_id(0))
        self.assertFalse(await self.overlay(0).store_peer())

    async def test_connect_peer(self) -> None:
        """
        Test if connecting to a peer based on a public key works.
        """
        # Add a third node
        node = MockIPv8("curve25519", DHTDiscoveryCommunity)
        self.add_node_to_experiment(node)
        await self.introduce_nodes()

        # Node1 is storing the peer of node0
        self.overlay(1).store[self.mid(0)].append(self.dht_node(0))
        self.overlay(0).store_for_me[self.mid(0)].append(self.dht_node(1))

        org_func = self.overlay(1).create_puncture_request

        def create_puncture_request(lan_walker: Address, wan_walker: Address, identifier: int,
                                    prefix: bytes | None = None, new_style: bool = False) -> bytes:
            self.puncture_to = wan_walker
            return org_func(lan_walker, wan_walker, identifier, prefix, new_style)
        self.overlay(1).create_puncture_request = create_puncture_request

        await self.deliver_messages()
        nodes = await self.overlay(2).connect_peer(self.mid(0))
        self.assertEqual(self.puncture_to, self.address(2))
        self.assertIn(self.key_bin(0), [n.public_key.key_to_bin() for n in nodes])

    async def test_connect_peer_fail(self) -> None:
        """
        Check if a mid that is not in the routing table raises a DHTError on lookup.
        """
        await self.introduce_nodes()
        self.overlay(0).routing_tables[self.address(0).__class__] = RoutingTable(self.my_node_id(0))
        with self.assertRaises(DHTError):
            await self.overlay(0).connect_peer(self.mid(1))

    async def test_ping_pong(self) -> None:
        """
        Check if pinging between two particular nodes works.
        """
        now = time.time() - 1

        node0 = Node(self.private_key(0), self.address(0))
        node0.last_response = now
        node0.last_queries.append(now)

        node1 = Node(self.private_key(1), self.address(1))
        node1.last_response = now
        node1.last_queries.append(now)

        key = node1.mid
        self.overlay(0).store[key].append(node1)
        self.overlay(1).store_for_me[key].append(node0)

        await self.overlay(1).ping(node0)
        self.assertNotEqual(node0.last_response, now)
        self.assertNotEqual(node1.last_query, now)

    def test_ping_all(self) -> None:
        """
        Check if pinging all nodes - when necessary - works.
        """
        self.overlay(0).ping = lambda n: setattr(self, 'pinged', n) or succeed(None)

        node1 = Node(self.private_key(1), self.address(1))
        node1.last_ping_sent = time.time()
        node1.last_queries.append(time.time())

        self.overlay(0).store[node1.mid].append(node1)
        self.overlay(0).ping_all()
        self.assertIn(node1, self.overlay(0).store[node1.mid])

        node1.last_queries[-1] -= 100
        self.overlay(0).ping_all()
        self.assertNotIn(node1, self.overlay(0).store[node1.mid])
        self.assertEqual(self.pinged, None)

        self.overlay(0).store_for_me[node1.mid].append(node1)
        self.overlay(0).ping_all()
        self.assertIn(node1.mid, self.overlay(0).store_for_me)

        node1.last_ping_sent -= 30
        self.overlay(0).ping_all()
        self.assertEqual(self.pinged, node1)
        self.assertIn(node1, self.overlay(0).store_for_me[node1.mid])

        self.pinged = None
        node1.failed = 3
        self.overlay(0).ping_all()
        self.assertEqual(self.pinged, None)
        self.assertNotIn(node1, self.overlay(0).store_for_me[node1.mid])
