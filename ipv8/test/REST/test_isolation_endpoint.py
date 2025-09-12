from __future__ import annotations

import unittest
from asyncio import sleep
from typing import TYPE_CHECKING, cast

from ...bootstrapping.dispersy.bootstrapper import DispersyBootstrapper
from ...configuration import DISPERSY_BOOTSTRAPPER
from ...messaging.anonymization.community import TunnelCommunity, TunnelSettings
from ...REST.isolation_endpoint import IsolationEndpoint
from ..base import TestBase
from ..mocking.community import MockCommunity
from ..mocking.endpoint import AutoMockEndpoint, MockEndpoint, MockEndpointListener
from .rest_base import MockRequest, response_to_json

if TYPE_CHECKING:
    from ...messaging.interfaces.udp.endpoint import Address


class MockSettings:
    """
    Mock tunnel settings.
    """

    def __init__(self) -> None:
        """
        Set the peer flags to 0.
        """
        self.peer_flags = {0}


class MockTunnelCommunity(TunnelCommunity, MockCommunity):
    """
    Fake TunnelCommunity just for circuit management.
    """

    def __init__(self, settings: TunnelSettings) -> None:
        """
        We don't actually initialize the TunnelCommunity, we just want it as a base class.
        """
        MockCommunity.__init__(self)
        self.settings = MockSettings()
        self.circuits = {}
        self.relay_from_to = {}
        self.exit_sockets = {}

        bootstrapper = DispersyBootstrapper(DISPERSY_BOOTSTRAPPER["init"]["ip_addresses"], [])
        self.bootstrappers = [bootstrapper]


class TestIsolationEndpoint(TestBase[MockTunnelCommunity]):
    """
    Tests for REST requests to the isolation endpoint.
    """

    FAKE_BOOTSTRAP_ADDRESS = ("127.0.0.1", 0)

    async def setUp(self) -> None:
        """
        Set up with a fake tunnel community.
        """
        super().setUp()

        self.fake_endpoint = MockEndpoint(("0.0.0.0", 0), TestIsolationEndpoint.FAKE_BOOTSTRAP_ADDRESS)
        self.fake_endpoint.open()
        self.fake_endpoint_listener = MockEndpointListener(self.fake_endpoint)
        self.fake_endpoint.add_listener(self.fake_endpoint_listener)

        self.initialize(MockTunnelCommunity, 1, TunnelSettings(endpoint=self.fake_endpoint))

        self.rest_ep = IsolationEndpoint()
        self.rest_ep.session = self.node(0)
        self.node(0).overlays.append(self.overlay(0))

    def bootstrap_addresses(self) -> list[Address]:
        """
        Get the bootstrapper ip addresses.
        """
        return cast("MockTunnelCommunity", self.node(0).overlay).bootstrappers[0].ip_addresses

    async def test_no_ip(self) -> None:
        """
        Test if requests that do not specify an IP are rejected.
        """
        raw_response = await self.rest_ep.handle_post(MockRequest("isolation", "POST", {"port": 5, "exitnode": 1}))
        response = await response_to_json(raw_response)

        self.assertEqual(400, raw_response.status)
        self.assertFalse(response["success"])

    async def test_no_port(self) -> None:
        """
        Test if requests that do not specify a port are rejected.
        """
        raw_response = await self.rest_ep.handle_post(MockRequest("isolation", "POST", {"ip": "127.0.0.1",
                                                                                        "exitnode": 1}))
        response = await response_to_json(raw_response)

        self.assertEqual(400, raw_response.status)
        self.assertFalse(response["success"])

    async def test_no_choice(self) -> None:
        """
        Test if requests that do not specify adding either an exit node or a bootstrap server are rejected.
        """
        raw_response = await self.rest_ep.handle_post(MockRequest("isolation", "POST", {"ip": "127.0.0.1", "port": 5}))
        response = await response_to_json(raw_response)

        self.assertEqual(400, raw_response.status)
        self.assertFalse(response["success"])

    @unittest.skipIf(AutoMockEndpoint.IPV6_ADDRESSES, "IPv6 not supported")
    async def test_add_bootstrap(self) -> None:
        """
        Check if bootstrap nodes are correctly added.

        A successfully added bootstrap node is walked to.
        """
        ip, port = TestIsolationEndpoint.FAKE_BOOTSTRAP_ADDRESS

        response = await response_to_json(await self.rest_ep.handle_post(
            MockRequest("isolation", "POST", {"ip": ip, "port": port, "bootstrapnode": 1})
        ))
        await sleep(0)  # We only expect one async event, this is ~10x faster than deliver_messages()

        self.assertTrue(response["success"])
        self.assertIn(TestIsolationEndpoint.FAKE_BOOTSTRAP_ADDRESS, self.bootstrap_addresses())
        self.assertIn(TestIsolationEndpoint.FAKE_BOOTSTRAP_ADDRESS, self.node(0).network.blacklist)
        self.assertLessEqual(1, len(self.fake_endpoint_listener.received_packets))

    @unittest.skipIf(AutoMockEndpoint.IPV6_ADDRESSES, "IPv6 not supported")
    async def test_add_exit(self) -> None:
        """
        Check if exit nodes are correctly added.

        A successfully added exit node is walked to.
        """
        ip, port = TestIsolationEndpoint.FAKE_BOOTSTRAP_ADDRESS

        response = await response_to_json(await self.rest_ep.handle_post(
            MockRequest("isolation", "POST", {"ip": ip, "port": port, "exitnode": 1})
        ))
        await sleep(0)  # We only expect one async event, this is ~10x faster than deliver_messages()

        self.assertTrue(response["success"])
        self.assertLessEqual(1, len(self.fake_endpoint_listener.received_packets))
