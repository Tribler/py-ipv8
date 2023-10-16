import os
import unittest
from functools import reduce
from typing import cast

from ...bootstrapping.dispersy.bootstrapper import DispersyBootstrapper
from ...messaging.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from ...peerdiscovery.payload import DiscoveryIntroductionRequestPayload
from ..base import TestBase
from ..mocking.community import MockCommunity
from ..mocking.endpoint import AutoMockEndpoint


@unittest.skipIf(AutoMockEndpoint.IPV6_ADDRESSES, "IPv6 not supported")
class TestDiscoveryCommunity(TestBase):
    """
    Tests related to the DiscoveryCommunity.
    """

    def setUp(self) -> None:
        """
        Create two discovery communities that are not managed by TestBase.
        """
        super().setUp()
        self.tracker = MockCommunity()

        node_count = 2
        self.overlays = [MockCommunity() for _ in range(node_count)]
        for overlay in self.overlays:
            overlay.network.blacklist.append(self.tracker.my_estimated_wan)
            bootstrapper = DispersyBootstrapper([self.tracker.my_estimated_wan], [], bootstrap_timeout=0.0)
            overlay.bootstrappers = [bootstrapper]

    async def tearDown(self) -> None:
        """
        We made our own unmanaged overlays: tear them down.
        """
        await self.tracker.unload()
        for overlay in self.overlays:
            await overlay.unload()
        return await super().tearDown()

    async def test_deprecated_introduction(self) -> None:
        """
        Check if we can handle the deprecated Discovery introduction request as a normal one.
        """
        global_time = self.overlays[0].claim_global_time()
        payload = DiscoveryIntroductionRequestPayload(b"a" * 20,
                                                      cast(AutoMockEndpoint, self.overlays[1].endpoint).wan_address,
                                                      self.overlays[0].my_estimated_lan,
                                                      self.overlays[0].my_estimated_wan,
                                                      True,
                                                      "unknown",
                                                      global_time,
                                                      b'')
        auth = BinMemberAuthenticationPayload(self.overlays[0].my_peer.public_key.key_to_bin())
        dist = GlobalTimeDistributionPayload(global_time)

        packet = self.overlays[0]._ez_pack(self.overlays[0]._prefix, 246, [auth, dist, payload])  # noqa: SLF001
        self.overlays[1].on_old_introduction_request(cast(AutoMockEndpoint, self.overlays[0].endpoint).wan_address,
                                                     packet)

        await self.deliver_messages()

        self.assertEqual(1, len(self.overlays[1].network.verified_peers))

    async def test_bootstrap(self) -> None:
        """
        Check if we can bootstrap our peerdiscovery.
        """
        # Both other overlays contact the tracker
        self.overlays[0].bootstrap()
        self.overlays[1].bootstrap()
        await self.deliver_messages()

        self.assertEqual(len(self.tracker.network.verified_peers), 2)

        # Now that the tracker knows both others, they should be introduced to each other
        self.overlays[0].bootstrap()
        self.overlays[1].bootstrap()
        await self.deliver_messages()

        for overlay in self.overlays:
            intros = overlay.network.get_introductions_from(self.tracker.my_peer)
            # Over time we get more than one option per network interface.
            # Usually deliver_messages will not deliver more than 1 option, but we could get more.
            self.assertGreaterEqual(len(intros), 1)
            self.assertNotIn(overlay.my_peer.mid, intros)
            self.assertNotIn(self.tracker.my_peer.mid, intros)

    async def test_cross_peer(self) -> None:
        """
        If we have different peers under our control, don't claim to be the other identity.
        """
        custom_community_id = os.urandom(20)

        class OtherMockCommunity(MockCommunity):
            community_id = custom_community_id
        custom_overlay = OtherMockCommunity()
        custom_overlay.my_peer.address = self.overlays[0].my_peer.address
        self.overlays.append(custom_overlay)
        self.overlays[0].network.register_service_provider(custom_community_id, custom_overlay)

        self.overlays[0].walk_to(self.overlays[1].my_peer.address)
        await self.deliver_messages()

        discovered = reduce(lambda a, b: a | b, self.overlays[1].network.services_per_peer.values(), set())

        self.assertEqual(len(self.overlays[1].network.services_per_peer), 2)
        self.assertSetEqual(discovered, {MockCommunity.community_id, custom_community_id})
