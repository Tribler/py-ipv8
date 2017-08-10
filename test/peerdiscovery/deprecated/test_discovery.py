from ipv8.peerdiscovery.deprecated.discovery import _DEFAULT_ADDRESSES
from test.base import TestBase
from test.mocking.community import MockCommunity
from test.util import twisted_test


class TestDiscoveryCommunity(TestBase):

    def setUp(self):
        while _DEFAULT_ADDRESSES:
            _DEFAULT_ADDRESSES.pop()
        self.tracker = MockCommunity()
        _DEFAULT_ADDRESSES.append(self.tracker.endpoint.wan_address)

        node_count = 2
        self.overlays = [MockCommunity() for _ in range(node_count)]

    def tearDown(self):
        self.tracker.unload()
        for overlay in self.overlays:
            overlay.unload()

    @twisted_test
    def test_bootstrap(self):
        """
        Check if we can bootstrap our peerdiscovery.
        """
        # Both other overlays contact the tracker
        self.overlays[0].bootstrap()
        self.overlays[1].bootstrap()
        yield self.deliver_messages()

        self.assertEqual(len(self.tracker.network.verified_peers), 2)

        # Now that the tracker knows both others, they should be introduced to each other
        self.overlays[0].bootstrap()
        self.overlays[1].bootstrap()
        yield self.deliver_messages()

        self.assertEqual(len(self.overlays[0].network.verified_peers), 1)
        self.assertEqual(len(self.overlays[1].network.verified_peers), 1)
