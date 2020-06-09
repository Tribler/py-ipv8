import time

from ..base import TestBase
from ..mocking.community import MockCommunity
from ..mocking.endpoint import MockEndpointListener
from ...community import _DEFAULT_ADDRESSES
from ...peerdiscovery.churn import RandomChurn


class TestChurn(TestBase):

    def setUp(self):
        super(TestChurn, self).setUp()
        while _DEFAULT_ADDRESSES:
            _DEFAULT_ADDRESSES.pop()

        node_count = 2
        self.overlays = [MockCommunity() for _ in range(node_count)]
        self.strategies = [RandomChurn(self.overlays[i], ping_interval=0.0) for i in range(node_count)]

    async def tearDown(self):
        for overlay in self.overlays:
            await overlay.unload()
        return await super(TestChurn, self).tearDown()

    async def test_keep_reachable(self):
        """
        Check if we don't remove reachable nodes.
        """
        peer = self.overlays[1].my_peer
        fake_last_response = time.time() - 30
        peer.last_response = fake_last_response
        self.overlays[0].network.add_verified_peer(peer)

        # Node inactive! We should ping it!
        self.strategies[0].take_step()

        await self.deliver_messages()

        # Node should have responded by now and not be removed.
        self.assertNotEqual(peer.last_response, fake_last_response)
        self.strategies[0].take_step()

        self.assertEqual(len(self.overlays[0].network.verified_peers), 1)

    async def test_remove_unreachable(self):
        """
        Check if we remove unreachable nodes.
        """
        peer = self.overlays[1].my_peer
        fake_last_response = time.time() - 30
        peer.last_response = fake_last_response
        self.overlays[0].network.add_verified_peer(peer)
        self.overlays[1].endpoint.close()

        # Node inactive! We should ping it!
        self.strategies[0].take_step()

        await self.deliver_messages()

        # Node should not have responded.
        self.assertEqual(peer.last_response, fake_last_response)
        # Nothing will happen the next 30 seconds, so we forward the clock a bit.
        peer.last_response = 1
        # Now the node should be removed.
        self.strategies[0].take_step()

        self.assertEqual(len(self.overlays[0].network.verified_peers), 0)

    async def test_no_nodes(self):
        """
        Nothing should happen if we have no nodes to check.
        """
        self.strategies[0].sample_size = 0  # Don't check anything
        peer = self.overlays[1].my_peer
        peer.last_response = 1  # 50 years ago
        self.overlays[0].network.add_verified_peer(peer)

        self.strategies[0].take_step()

        await self.deliver_messages()

        self.assertEqual(len(self.overlays[0].network.verified_peers), 1)

    async def test_ping_timeout(self):
        """
        Don't overload inactive nodes with pings, send it once within some timeout.
        """
        peer = self.overlays[1].my_peer
        peer.last_response = time.time() - 30
        self.overlays[0].network.add_verified_peer(peer)
        self.strategies[0].ping_interval = 10000.0
        # Hook up listener
        sniffer = MockEndpointListener(self.overlays[1].endpoint)

        # Node inactive! We should ping it!
        self.strategies[0].take_step()
        # Only once though
        self.strategies[0].take_step()

        await self.deliver_messages()

        self.assertEqual(len(sniffer.received_packets), 1)

    async def test_ping_timeout_resend(self):
        """
        Don't overload inactive nodes with pings, send it again after some timeout.
        """
        peer = self.overlays[1].my_peer
        peer.last_response = time.time() - 30
        self.overlays[0].network.add_verified_peer(peer)
        self.strategies[0].ping_interval = -1.0
        # Hook up listener
        sniffer = MockEndpointListener(self.overlays[1].endpoint)

        # Node inactive! We should ping it!
        self.strategies[0].take_step()
        # Timeout has passed, send it again.
        self.strategies[0].take_step()

        await self.deliver_messages()

        self.assertEqual(len(sniffer.received_packets), 2)
