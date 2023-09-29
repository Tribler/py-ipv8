from __future__ import annotations

import os
import unittest
from typing import TYPE_CHECKING, Any

from ipv8.community import Community, CommunitySettings
from ipv8.requestcache import NumberCache, RequestCache
from ipv8.test.base import TestBase
from ipv8.test.mocking.ipv8 import MockIPv8

if TYPE_CHECKING:
    from ipv8.messaging.payload import IntroductionRequestPayload
    from ipv8.messaging.payload_headers import GlobalTimeDistributionPayload
    from ipv8.types import Peer


class MyCache(NumberCache):

    def __init__(self, request_cache: RequestCache, overlay: MyCommunity) -> None:
        super().__init__(request_cache, "", 0)
        self.overlay = overlay

    def on_timeout(self) -> None:
        self.overlay.timed_out = True


class MyCommunitySettings(CommunitySettings):
    some_constant: int | None = None


class MyCommunity(Community):
    community_id = os.urandom(20)
    settings_class = MyCommunitySettings

    def __init__(self, settings: MyCommunitySettings) -> None:
        super().__init__(settings)
        self.request_cache = RequestCache()

        self._some_constant = 42 if settings.some_constant is None else settings.some_constant
        self.last_peer = None
        self.timed_out = False

    async def unload(self) -> None:
        await self.request_cache.shutdown()
        await super().unload()

    def some_constant(self) -> int:
        return self._some_constant

    def introduction_request_callback(self, peer: Peer,
                                      dist: GlobalTimeDistributionPayload,
                                      payload: IntroductionRequestPayload) -> None:
        self.last_peer = peer

    def add_cache(self) -> None:
        self.request_cache.add(MyCache(self.request_cache, self))


class MyTests(TestBase[MyCommunity]):

    def setUp(self) -> None:
        super().setUp()
        # Insert your setUp logic here

    async def tearDown(self) -> None:
        await super().tearDown()
        # Insert your tearDown logic here

    def create_node(self, *args: Any, **kwargs) -> MockIPv8:
        return MockIPv8("curve25519", self.overlay_class, *args, **kwargs)

    def patch_overlays(self, i: int) -> None:
        if i == 1:
            pass  # We'll run the general exception handler for Peer 1
        else:
            super().patch_overlays(i)

    async def test_call(self) -> None:
        """
        Create a MyCommunity and check the output of some_constant().
        """
        # Create 1 MyCommunity
        self.initialize(MyCommunity, 1)

        # Nodes are 0-indexed
        value = self.overlay(0).some_constant()

        self.assertEqual(42, value)

    async def test_call2(self) -> None:
        """
        Create a MyCommunity with a custom some_constant.
        """
        self.initialize(MyCommunity, 1, MyCommunitySettings(some_constant=7))

        value = self.overlay(0).some_constant()

        self.assertEqual(7, value)

    async def test_intro_called(self) -> None:
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

    async def test_intro_called2(self) -> None:
        """
        Check if we got a request from another MyCommunity.
        """
        self.initialize(MyCommunity, 2)

        await self.introduce_nodes()

        self.assertEqual(self.peer(0), self.overlay(1).last_peer)
        self.assertEqual(self.peer(1), self.overlay(0).last_peer)

    async def test_passthrough(self) -> None:
        """
        Check if a cache time out is properly handled.
        """
        self.initialize(MyCommunity, 1)

        with self.overlay(0).request_cache.passthrough():
            self.overlay(0).add_cache()
        await self.deliver_messages()

        self.assertTrue(self.overlay(0).timed_out)

    async def test_passthrough2(self) -> None:
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
