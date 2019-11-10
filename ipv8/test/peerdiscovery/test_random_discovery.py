from ..base import TestBase
from ..mocking.community import MockCommunity
from ...community import _DEFAULT_ADDRESSES
from ...peerdiscovery.discovery import RandomWalk


class TestRandomWalk(TestBase):

    def setUp(self):
        super(TestRandomWalk, self).setUp()
        while _DEFAULT_ADDRESSES:
            _DEFAULT_ADDRESSES.pop()

        node_count = 3
        self.overlays = [MockCommunity() for _ in range(node_count)]
        self.strategies = [RandomWalk(self.overlays[i], reset_chance=0) for i in range(node_count)]

    async def tearDown(self):
        for overlay in self.overlays:
            await overlay.unload()
        return await super(TestRandomWalk, self).tearDown()

    async def test_take_step(self):
        """
        Check if we will walk to a random other node.

        Unit test network layout:
          NODE0 <-> NODE1 <-> NODE2
        """
        self.overlays[0].network.add_verified_peer(self.overlays[1].my_peer)
        self.overlays[0].network.discover_services(self.overlays[1].my_peer, [self.overlays[1].master_peer.mid, ])
        self.overlays[1].network.add_verified_peer(self.overlays[2].my_peer)
        self.overlays[1].network.discover_services(self.overlays[2].my_peer, [self.overlays[2].master_peer.mid, ])
        # We expect NODE1 to introduce NODE0 to NODE2
        self.strategies[0].take_step()
        await self.deliver_messages()
        self.strategies[0].take_step()
        await self.deliver_messages()

        self.assertEqual(len(self.overlays[0].network.verified_peers), 2)

    async def test_take_step_into(self):
        """
        Check if we will walk to an introduced node.

        Unit test network layout:
          NODE0 <-> (NODE1) <-> NODE2
          NODE0 -> NODE2
        """
        self.overlays[0].network.add_verified_peer(self.overlays[1].my_peer)
        self.overlays[0].network.discover_address(self.overlays[1].my_peer, self.overlays[2].endpoint.wan_address,
                                                  MockCommunity.master_peer.mid)
        self.overlays[0].network.discover_services(self.overlays[1].my_peer, [self.overlays[1].master_peer.mid, ])
        # We expect NODE0 to visit NODE2
        self.strategies[0].take_step()
        await self.deliver_messages()
        self.strategies[0].take_step()
        await self.deliver_messages()

        self.assertEqual(len(self.overlays[0].network.verified_peers), 2)

    async def test_fail_step_into(self):
        """
        Check if we drop an unreachable introduced node.

        Unit test network layout:
          NODE0 <-> (NODE1) <-> NODE2
          NODE0 -> NODE2
        """
        self.overlays[0].network.add_verified_peer(self.overlays[1].my_peer)
        self.overlays[0].network.discover_address(self.overlays[1].my_peer, self.overlays[2].endpoint.wan_address,
                                                  MockCommunity.master_peer.mid)
        self.overlays[0].network.discover_services(self.overlays[1].my_peer, [self.overlays[1].master_peer.mid, ])
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

    async def test_retry_step_into(self):
        """
        Check if we don't drop an introduced node immediately.

        Unit test network layout:
          NODE0 <-> (NODE1) <-> NODE2
          NODE0 -> NODE2
        """
        self.overlays[0].network.add_verified_peer(self.overlays[1].my_peer)
        self.overlays[0].network.discover_address(self.overlays[1].my_peer, self.overlays[2].endpoint.wan_address,
                                                  MockCommunity.master_peer.mid)
        self.overlays[0].network.discover_services(self.overlays[1].my_peer, [self.overlays[1].master_peer.mid, ])
        self.strategies[0].node_timeout = 100000.0

        # NODE0 attempts to reach NODE2
        self.overlays[2].endpoint.close()
        self.strategies[0].take_step()

        await self.deliver_messages()

        # NODE2 is still within its timeout and should not have been cleaned yet
        self.strategies[0].take_step()

        self.assertEqual(len(self.overlays[0].network.get_walkable_addresses()), 1)
        self.assertEqual(len(self.overlays[0].network.verified_peers), 1)
