from ...peerdiscovery.discovery import EdgeWalk
from ..base import TestBase
from ..mocking.community import MockCommunity


class TestEdgeWalk(TestBase):
    """
    Tests related to the edge walker.
    """

    def setUp(self) -> None:
        """
        Set up three nodes that are not managed by TestBase.
        """
        super().setUp()

        node_count = 3
        self.overlays = [MockCommunity() for _ in range(node_count)]
        self.strategies = [EdgeWalk(self.overlays[i], neighborhood_size=1) for i in range(node_count)]

        # Prevent LAN IPs from ending up in Network
        for overlay in self.overlays:
            overlay.address_is_lan = lambda _: False

    async def tearDown(self) -> None:
        """
        We made our own unmanaged overlays: tear them down.
        """
        for overlay in self.overlays:
            await overlay.unload()
        return await super().tearDown()

    async def test_take_step(self) -> None:
        """
        Check if we will walk to a random other node.

        Unit test network layout:
          NODE0 <-> NODE1 <-> NODE2
        """
        self.overlays[0].network.add_verified_peer(self.overlays[1].my_peer)
        self.overlays[0].network.discover_services(self.overlays[1].my_peer, [self.overlays[1].community_id, ])
        self.overlays[1].network.add_verified_peer(self.overlays[2].my_peer)
        self.overlays[1].network.discover_services(self.overlays[2].my_peer, [self.overlays[2].community_id, ])
        # We expect NODE1 to introduce NODE0 to NODE2
        self.strategies[0].take_step()  # First it's added in the neighborhood
        self.strategies[0].take_step()  # Second it introduces its neighbor

        await self.deliver_messages()

        self.strategies[0].take_step()  # Find out the neighbor has been introduced and walk to it
        await self.deliver_messages()

        self.assertEqual(len(self.overlays[0].network.verified_peers), 2)

    async def test_take_step_into(self) -> None:
        """
        Check if we will walk to an introduced node.
        """
        self.strategies[0].edge_timeout = 0.0  # Finish the edge immediately
        self.overlays[0].network.add_verified_peer(self.overlays[1].my_peer)
        self.overlays[0].network.discover_services(self.overlays[1].my_peer, [self.overlays[1].community_id, ])

        # We expect NODE0 will add NODE1 to its neighborhood and start constructing an edge from it.
        # Don't allow that right now.
        self.strategies[0].take_step()

        await self.deliver_messages()

        # Now we give NODE2 to NODE1, which it can forward to NODE0 to make an edge
        self.overlays[1].network.add_verified_peer(self.overlays[2].my_peer)
        self.overlays[1].network.discover_services(self.overlays[2].my_peer, [self.overlays[2].community_id, ])

        # In order:
        # 1. Add root (NODE1) and query for nodes
        # 2. Detect intro (NODE2) from root and query for nodes
        # 3. Detect no more intros from NODE2 and finish edge
        for _ in range(3):
            self.strategies[0].take_step()  # Attempt intro
            await self.deliver_messages()
            self.strategies[0].take_step()  # Complete intro
            await self.deliver_messages()

        self.assertEqual(len(self.overlays[0].network.verified_peers), 2)
        self.assertEqual(len(self.strategies[0].complete_edges), 1)

    async def test_fail_step_into(self) -> None:
        """
        Check if we drop an unreachable introduced node.
        """
        self.strategies[0].edge_timeout = 0.0  # Finish the edge immediately
        self.overlays[0].network.add_verified_peer(self.overlays[1].my_peer)
        self.overlays[2].endpoint.close()

        # We expect NODE0 will add NODE1 to its neighborhood and start constructing an edge from it.
        # Don't allow that right now.
        self.strategies[0].take_step()

        await self.deliver_messages()

        # Now we give NODE2 to NODE1, which it can forward to NODE0 to make an edge
        self.overlays[1].network.add_verified_peer(self.overlays[2].my_peer)
        self.overlays[1].network.discover_services(self.overlays[2].my_peer, [self.overlays[2].community_id, ])

        # In order:
        # 1. Add root (NODE1) and query for nodes
        # 2. Detect intro (NODE2) from root and query for nodes
        # 3. Fail to walk to NODE2 -> edge is only root, so no complete edge
        for _ in range(3):
            self.strategies[0].take_step()
            await self.deliver_messages()

        self.assertEqual(len(self.overlays[0].network.verified_peers), 1)
        self.assertEqual(len(self.strategies[0].complete_edges), 0)

    async def test_complete_edge(self) -> None:
        """
        Check if we can complete an edge.
        """
        self.strategies[0].edge_length = 2  # Finish with one other node
        self.strategies[0].edge_timeout = 1.0  # Finish the edge, but allow the network to walk
        self.overlays[0].network.add_verified_peer(self.overlays[1].my_peer)
        self.overlays[0].network.discover_services(self.overlays[1].my_peer, [self.overlays[1].community_id, ])

        # We expect NODE0 will add NODE1 to its neighborhood and start constructing an edge from it.
        # Don't allow that right now.
        self.strategies[0].take_step()

        await self.deliver_messages()

        # Now we give NODE2 to NODE1, which it can forward to NODE0 to make an edge
        self.overlays[1].network.add_verified_peer(self.overlays[2].my_peer)
        self.overlays[1].network.discover_services(self.overlays[2].my_peer, [self.overlays[2].community_id, ])

        # In order:
        # 1. Add root (NODE1) and query for nodes
        # 2. Detect intro (NODE2) from root and query for nodes
        # 3. Detect no more intros from NODE2 and finish edge
        for _ in range(3):
            self.strategies[0].take_step()
            await self.deliver_messages()

        self.assertEqual(len(self.overlays[0].network.verified_peers), 2)
        self.assertEqual(len(self.strategies[0].complete_edges), 1)
