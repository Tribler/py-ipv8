from ..REST.rest_base import RESTTestBase
from ..mocking.community import MockCommunity
from ..mocking.endpoint import MockEndpoint, MockEndpointListener
from ...community import _DEFAULT_ADDRESSES
from ...messaging.anonymization.community import TunnelCommunity


class MockSettings:

    def __init__(self):
        self.peer_flags = {0}


class MockTunnelCommunity(TunnelCommunity, MockCommunity):  # pylint: disable=R0901

    def __init__(self):  # pylint: disable=W0231
        # We don't actually initialize the TunnelCommunity, we just want it as a base class (pylint doesn't approve).
        MockCommunity.__init__(self)
        self.settings = MockSettings()
        self.circuits = {}
        self.relay_from_to = {}
        self.exit_sockets = {}


class TestOverlaysEndpoint(RESTTestBase):

    FAKE_BOOTSTRAP_ADDRESS = ("127.0.0.1", 0)

    async def setUp(self):  # pylint: disable=W0236
        super().setUp()

        self.fake_endpoint = MockEndpoint(("0.0.0.0", 0), TestOverlaysEndpoint.FAKE_BOOTSTRAP_ADDRESS)
        self.fake_endpoint.open()
        self.fake_endpoint_listener = MockEndpointListener(self.fake_endpoint)
        self.fake_endpoint.add_listener(self.fake_endpoint_listener)

        await self.initialize([], 1)
        self.ipv8 = self.node(0)
        self.ipv8.overlay = MockTunnelCommunity()
        self.ipv8.overlay.network = self.ipv8.network
        self.ipv8.overlays.append(self.ipv8.overlay)

    async def tearDown(self):
        if TestOverlaysEndpoint.FAKE_BOOTSTRAP_ADDRESS in _DEFAULT_ADDRESSES:
            _DEFAULT_ADDRESSES.remove(TestOverlaysEndpoint.FAKE_BOOTSTRAP_ADDRESS)
        await super().tearDown()

    async def test_no_ip(self):
        """
        Test if requests that do not specify an IP are rejected.
        """
        response = await self.make_request(self.ipv8, "isolation", "POST", json={"port": 5, "exitnode": 1},
                                           expected_status=400)

        self.assertFalse(response["success"])

    async def test_no_port(self):
        """
        Test if requests that do not specify a port are rejected.
        """
        response = await self.make_request(self.ipv8, "isolation", "POST", json={"ip": "127.0.0.1", "exitnode": 1},
                                           expected_status=400)

        self.assertFalse(response["success"])

    async def test_no_choice(self):
        """
        Test if requests that do not specify a to add either an exit node or a bootstrap server.
        """
        response = await self.make_request(self.ipv8, "isolation", "POST", json={"ip": "127.0.0.1", "port": 5},
                                           expected_status=400)

        self.assertFalse(response["success"])

    async def test_add_bootstrap(self):
        """
        Check if bootstrap nodes are correctly added.

        A successfully added bootstrap node is walked to.
        """
        ip, port = TestOverlaysEndpoint.FAKE_BOOTSTRAP_ADDRESS

        response = await self.make_request(self.ipv8, "isolation", "POST",
                                           json={"ip": ip, "port": port, "bootstrapnode": 1})

        self.assertTrue(response["success"])
        self.assertIn(TestOverlaysEndpoint.FAKE_BOOTSTRAP_ADDRESS, _DEFAULT_ADDRESSES)
        self.assertIn(TestOverlaysEndpoint.FAKE_BOOTSTRAP_ADDRESS, self.ipv8.network.blacklist)
        self.assertLessEqual(1, len(self.fake_endpoint_listener.received_packets))

    async def test_add_bootstrap_no_overlays(self):
        """
        Check if bootstrap nodes are correctly added, without loaded overlays.

        A successfully added bootstrap node is walked to.
        """
        self.ipv8.overlays.clear()
        self.ipv8.overlay = None
        ip, port = TestOverlaysEndpoint.FAKE_BOOTSTRAP_ADDRESS

        response = await self.make_request(self.ipv8, "isolation", "POST",
                                           json={"ip": ip, "port": port, "bootstrapnode": 1})

        self.assertTrue(response["success"])
        self.assertIn(TestOverlaysEndpoint.FAKE_BOOTSTRAP_ADDRESS, _DEFAULT_ADDRESSES)
        self.assertIn(TestOverlaysEndpoint.FAKE_BOOTSTRAP_ADDRESS, self.ipv8.network.blacklist)
        self.assertLessEqual(0, len(self.fake_endpoint_listener.received_packets))

    async def test_add_exit(self):
        """
        Check if exit nodes are correctly added.

        A successfully added exit node is walked to.
        """
        ip, port = TestOverlaysEndpoint.FAKE_BOOTSTRAP_ADDRESS

        response = await self.make_request(self.ipv8, "isolation", "POST",
                                           json={"ip": ip, "port": port, "exitnode": 1})

        self.assertTrue(response["success"])
        self.assertLessEqual(1, len(self.fake_endpoint_listener.received_packets))
