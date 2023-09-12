from typing import cast

from ...peerdiscovery.discovery import RandomWalk
from ..base import TestBase
from ..mocking.community import MockCommunity
from ..mocking.endpoint import AutoMockEndpoint


class TestRandomWalk(TestBase):
    """
    Tests related to the random walker.
    """

    def setUp(self) -> None:
        """
        Set up three nodes that are not managed by TestBase.
        """
        super().setUp()

        node_count = 3
        self.overlays = [MockCommunity() for _ in range(node_count)]
        self.strategies = [RandomWalk(self.overlays[i], reset_chance=0) for i in range(node_count)]

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
        self.strategies[0].take_step()
        await self.deliver_messages()
        self.strategies[0].take_step()
        await self.deliver_messages()

        self.assertEqual(len(self.overlays[0].network.verified_peers), 2)

    async def test_take_step_into(self) -> None:
        """
        Check if we will walk to an introduced node.

        Unit test network layout:
          NODE0 <-> (NODE1) <-> NODE2
          NODE0 -> NODE2
        """
        self.overlays[0].network.add_verified_peer(self.overlays[1].my_peer)
        self.overlays[0].network.discover_address(self.overlays[1].my_peer,
                                                  cast(AutoMockEndpoint, self.overlays[2].endpoint).wan_address,
                                                  MockCommunity.community_id)
        self.overlays[0].network.discover_services(self.overlays[1].my_peer, [self.overlays[1].community_id, ])
        # We expect NODE0 to visit NODE2
        self.strategies[0].take_step()
        await self.deliver_messages()
        self.strategies[0].take_step()
        await self.deliver_messages()

        self.assertEqual(len(self.overlays[0].network.verified_peers), 2)

    async def test_fail_step_into(self) -> None:
        """
        Check if we drop an unreachable introduced node.

        Unit test network layout:
          NODE0 <-> (NODE1) <-> NODE2
          NODE0 -> NODE2
        """
        self.overlays[0].network.add_verified_peer(self.overlays[1].my_peer)
        self.overlays[0].network.discover_address(self.overlays[1].my_peer,
                                                  cast(AutoMockEndpoint, self.overlays[2].endpoint).wan_address,
                                                  MockCommunity.community_id)
        self.overlays[0].network.discover_services(self.overlays[1].my_peer, [self.overlays[1].community_id, ])
        # Fail immediately when unreachable
        self.strategies[0].node_timeout = 0.0

        # NODE0 attempts to reach NODE2
        self.overlays[2].endpoint.close()
        self.strategies[0].take_step()
        # At this point the unreachable node should not have been removed yet
        self.assertEqual(len(self.overlays[0].network.get_walkable_addresses()), 1)

        await self.deliver_messages()

        # We expect NODE0 to clean unreachable NODE2
        self.strategies[0].take_step()

        self.assertEqual(len(self.overlays[0].network.get_walkable_addresses()), 0)
        self.assertEqual(len(self.overlays[0].network.verified_peers), 1)

    async def test_retry_step_into(self) -> None:
        """
        Check if we don't drop an introduced node immediately.

        Unit test network layout:
          NODE0 <-> (NODE1) <-> NODE2
          NODE0 -> NODE2
        """
        self.overlays[0].network.add_verified_peer(self.overlays[1].my_peer)
        self.overlays[0].network.discover_address(self.overlays[1].my_peer,
                                                  cast(AutoMockEndpoint, self.overlays[2].endpoint).wan_address,
                                                  MockCommunity.community_id)
        self.overlays[0].network.discover_services(self.overlays[1].my_peer, [self.overlays[1].community_id, ])
        self.strategies[0].node_timeout = 100000.0

        # NODE0 attempts to reach NODE2
        self.overlays[2].endpoint.close()
        self.strategies[0].take_step()

        await self.deliver_messages()

        # NODE2 is still within its timeout and should not have been cleaned yet
        self.strategies[0].take_step()

        self.assertEqual(len(self.overlays[0].network.get_walkable_addresses()), 1)
        self.assertEqual(len(self.overlays[0].network.verified_peers), 1)
