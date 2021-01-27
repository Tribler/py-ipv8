from ...base import TestBase
from ...mocking.community import MockCommunity
from ...mocking.endpoint import AutoMockEndpoint, MockEndpointListener
from ....bootstrapping.dispersy.bootstrapper import DispersyBootstrapper


class TestDispersyBootstrapper(TestBase):

    def setUp(self):
        super().setUp()

        self.bootstrap_node = AutoMockEndpoint()
        self.bs_ep_listener = MockEndpointListener(self.bootstrap_node)
        self.bootstrap_node.open()

        self.bootstrapper = DispersyBootstrapper([self.bootstrap_node.wan_address], [], 60.0)
        self.overlay = MockCommunity()

    async def test_initialize(self):
        """
        Check if the special bootstrap addresses are added to the overlay's blacklist upon initialization.

        We don't test network DNS resolution here, which would contact the Internet.
        """
        result = self.bootstrapper.initialize(self.overlay)

        self.assertIn(self.bootstrap_node.wan_address, self.overlay.network.blacklist)
        self.assertTrue(result)

    async def test_get_addresses(self):
        """
        Check if the bootstrapper contacts the registered bootstrap nodes and doesn't return manual addresses.
        """
        addresses = await self.bootstrapper.get_addresses(self.overlay, 60.0)
        await self.deliver_messages()

        # There should be no manually walkable addresses.
        self.assertListEqual([], addresses)

        # However, the bootstrap node should have been contacted using the IPv8 protocol.
        self.assertEqual(1, len(self.bs_ep_listener.received_packets))

    async def test_get_addresses_timeout(self):
        """
        Check if a second call within the timeout gets dropped.
        """
        await self.bootstrapper.get_addresses(self.overlay, 60.0)
        await self.deliver_messages()

        await self.bootstrapper.get_addresses(self.overlay, 60.0)
        await self.deliver_messages()

        self.assertEqual(1, len(self.bs_ep_listener.received_packets))

    async def test_get_addresses_blacklist(self):
        """
        Check if the get_addresses ensures bootstrap nodes are in the blacklist.
        """
        self.overlay.network.blacklist.clear()

        await self.bootstrapper.get_addresses(self.overlay, 60.0)
        await self.deliver_messages()

        self.assertIn(self.bootstrap_node.wan_address, self.overlay.network.blacklist)

    async def test_keep_alive(self):
        """
        Check if the keep_alive tries to walk to a bootstrap node to keepe the connection alive.
        """
        self.bootstrapper.keep_alive(self.overlay)
        await self.deliver_messages()

        self.assertEqual(1, len(self.bs_ep_listener.received_packets))

    async def test_keep_alive_blacklist(self):
        """
        Check if the keep_alive adds walked nodes into the blacklist.
        """
        self.overlay.network.blacklist.clear()

        self.bootstrapper.keep_alive(self.overlay)
        await self.deliver_messages()

        self.assertIn(self.bootstrap_node.wan_address, self.overlay.network.blacklist)

    async def test_blacklist(self):
        """
        Check if the blacklist returns the added nodes in the blacklist.
        """
        self.assertListEqual([self.bootstrap_node.wan_address], self.bootstrapper.blacklist())
