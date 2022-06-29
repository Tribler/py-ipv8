import os
import unittest

from pyipv8.ipv8.community import Community, DEFAULT_MAX_PEERS
from pyipv8.ipv8.requestcache import NumberCache, RequestCache
from pyipv8.ipv8.test.base import TestBase
from pyipv8.ipv8.test.mocking.ipv8 import MockIPv8


class MyCache(NumberCache):

    def __init__(self, request_cache, overlay):
        super().__init__(request_cache, "", 0)
        self.overlay = overlay

    def on_timeout(self):
        self.overlay.timed_out = True


class MyCommunity(Community):
    community_id = os.urandom(20)

    def __init__(self, my_peer, endpoint, network, max_peers=DEFAULT_MAX_PEERS, anonymize=False, some_constant=None):
        super().__init__(my_peer, endpoint, network, max_peers, anonymize)
        self.request_cache = RequestCache()

        self._some_constant = 42 if some_constant is None else some_constant
        self.last_peer = None
        self.timed_out = False

    async def unload(self):
        await self.request_cache.shutdown()
        await super().unload()

    def some_constant(self):
        return self._some_constant

    def introduction_request_callback(self, peer, dist, payload):
        self.last_peer = peer

    def add_cache(self):
        self.request_cache.add(MyCache(self.request_cache, self))


class MyTests(TestBase):

    def setUp(self):
        super().setUp()
        # Insert your setUp logic here

    async def tearDown(self):
        await super().tearDown()
        # Insert your tearDown logic here

    def create_node(self, *args, **kwargs):
        return MockIPv8("curve25519", self.overlay_class, *args, **kwargs)

    def patch_overlays(self, i):
        if i == 1:
            pass  # We'll run the general exception handler for Peer 1
        else:
            super().patch_overlays(i)

    async def test_call(self):
        """
        Create a MyCommunity and check the output of some_constant().
        """
        # Create 1 MyCommunity
        self.initialize(MyCommunity, 1)

        # Nodes are 0-indexed
        value = self.overlay(0).some_constant()

        self.assertEqual(42, value)

    async def test_call2(self):
        """
        Create a MyCommunity with a custom some_constant.
        """
        self.initialize(MyCommunity, 1, some_constant=7)

        value = self.overlay(0).some_constant()

        self.assertEqual(7, value)

    async def test_intro_called(self):
        """
        Check if we got a request from another MyCommunity.
        """
        self.initialize(MyCommunity, 2)

        # We have the overlay of Peer 0 send a message to Peer 1.
        self.overlay(0).send_introduction_request(self.peer(1))
        # Our test is running in the asyncio main thread!
        # Let's yield to allow messages to be passed.
        await self.deliver_messages()

        # Peer 1 should have received the message from Peer 0.
        self.assertEqual(self.peer(0), self.overlay(1).last_peer)

    async def test_intro_called2(self):
        """
        Check if we got a request from another MyCommunity.
        """
        self.initialize(MyCommunity, 2)

        await self.introduce_nodes()

        self.assertEqual(self.peer(0), self.overlay(1).last_peer)
        self.assertEqual(self.peer(1), self.overlay(0).last_peer)

    async def test_passthrough(self):
        """
        Check if a cache time out is properly handled.
        """
        self.initialize(MyCommunity, 1)

        with self.overlay(0).request_cache.passthrough():
            self.overlay(0).add_cache()
        await self.deliver_messages()

        self.assertTrue(self.overlay(0).timed_out)

    async def test_passthrough2(self):
        """
        Check if a cache time out is properly handled.
        """
        self.initialize(MyCommunity, 1)

        with self.overlay(0).request_cache.passthrough(MyCache):
            self.overlay(0).add_cache()
        await self.deliver_messages()

        self.assertTrue(self.overlay(0).timed_out)


if __name__ == '__main__':
    unittest.main()
