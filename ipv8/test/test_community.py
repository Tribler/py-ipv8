from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from ..bootstrapping.dispersy.bootstrapper import DispersyBootstrapper
from ..community import Community, CommunitySettings
from ..peer import Peer
from ..peerdiscovery.network import Network
from .base import TestBase
from .mocking.endpoint import AutoMockEndpoint, MockEndpointListener
from .mocking.ipv8 import MockIPv8

if TYPE_CHECKING:
    from ..types import Address


class OldCommunity(Community):
    """
    Old-style community that does not support new-style introduction requests.
    """

    community_id = b'\x00' * 20

    def create_introduction_request(self, socket_address: Address, extra_bytes: bytes = b'',
                                    new_style: bool = False, prefix: bytes | None = None) -> bytes:
        """
        Make sure all sent introduction requests are flagged as old style.
        """
        return super().create_introduction_request(socket_address)

    def create_introduction_response(self, lan_socket_address: Address, socket_address: Address,  # noqa: PLR0913
                                     identifier: int, introduction: Peer | None = None, extra_bytes: bytes = b'',
                                     prefix: bytes | None = None, new_style: bool = False) -> bytes:
        """
        Make sure all sent introduction responses are flagged as old style.
        """
        return super().create_introduction_response(lan_socket_address, socket_address, identifier, introduction)

    def create_puncture(self, lan_walker: Address, wan_walker: Address, identifier: int,
                        new_style: bool = False) -> bytes:
        """
        Make sure all sent punctures are flagged as old style.
        """
        return super().create_puncture(lan_walker, wan_walker, identifier)

    def create_puncture_request(self, lan_walker: Address, wan_walker: Address, identifier: int,
                                prefix: bytes | None = None, new_style: bool = False) -> bytes:
        """
        Make sure all sent puncture requests are flagged as old style.
        """
        return super().create_puncture_request(lan_walker, wan_walker, identifier)


class NewCommunity(Community):
    """
    A new-style supporting community.
    """

    community_id = b'\x00' * 20


class TestCommunityCompatibility(TestBase):
    """
    Tests for interoperability between old-style and new-style IPv8 Communities.
    """

    def setUp(self) -> None:
        """
        Create two nodes that have a new-style and old-style community.
        """
        super().setUp()
        self.production_overlay_classes.append(OldCommunity)
        self.production_overlay_classes.append(NewCommunity)
        self.make_nodes()

    def make_nodes(self) -> None:
        """
        Create the actual two nodes.
        """
        self.nodes = [MockIPv8("low", NewCommunity), MockIPv8("low", NewCommunity), MockIPv8("low", OldCommunity)]
        self.endpoint_listeners = [MockEndpointListener(self.endpoint(i)) for i in range(len(self.nodes))]
        self.new_peer1 = 0
        self.new_peer2 = 1
        self.old_peer = 2

    def endpoint_listener(self, i: int) -> MockEndpointListener:
        """
        Shortcut to the endpoint listener of node i.
        """
        return self.endpoint_listeners[i]

    def received_message_ids(self, i: int) -> list[int]:
        """
        List the message ids received by node i.
        """
        return [packet[1][22] for packet in self.endpoint_listener(i).received_packets]

    async def walk_from_to(self, from_i: int, to_i: int) -> None:
        """
        Send an introduction request from one node id to another node id.
        """
        self.overlay(from_i).walk_to(self.address(to_i))
        await self.deliver_messages()

    @unittest.skipIf(AutoMockEndpoint.IPV6_ADDRESSES, "IPv6 not supported")
    async def test_introduce_old(self) -> None:
        """
        Check that no new-style messages are going to the old-style peer.
        """
        await self.walk_from_to(self.new_peer1, self.new_peer2)
        await self.walk_from_to(self.old_peer, self.new_peer1)

        received_messages_old_peer = self.received_message_ids(self.old_peer)

        self.assertNotIn(231, received_messages_old_peer)
        self.assertNotIn(232, received_messages_old_peer)
        self.assertNotIn(233, received_messages_old_peer)
        self.assertNotIn(234, received_messages_old_peer)


class NoIDCommunity(Community):
    """
    Faulty community that has no id specified.
    """


class StrangeIDCommunity(Community):
    """
    Faulty community that has a wrong community id type.
    """

    community_id = '\x00' * 20  # This is not ``bytes`` but ``str``: error!


class TestCommunityInit(TestBase):
    """
    Tests for initializing new Communities.

    - A test for a Community with a valid id is omitted as this is already covered by other tests.
    """

    async def test_init_no_id(self) -> None:
        """
        Check that attempting to create a Community without an id raises an error.
        """
        settings = CommunitySettings(my_peer=Peer(b'LibNaCLPK:' + b'0' * 32), endpoint=AutoMockEndpoint(),
                                     network=Network())
        self.assertRaises(RuntimeError, NoIDCommunity, settings)

    async def test_init_strange_id(self) -> None:
        """
        Check that attempting to create a Community with an id that is not ```bytes`` raises an error.
        """
        settings = CommunitySettings(my_peer=Peer(b'LibNaCLPK:' + b'0' * 32), endpoint=AutoMockEndpoint(),
                                     network=Network())
        self.assertRaises(RuntimeError, StrangeIDCommunity, settings)


class TestCommunityBootstrapping(TestBase):
    """
    Tests for the Community to Bootstrapper interface.

    Note: don't put tests for the Bootstrapper implementations here.
    """

    async def test_empty_bootstrap(self) -> None:
        """
        Check if unloading a Community after waiting for bootstrapping results exits cleanly.
        """
        settings = CommunitySettings(my_peer=Peer(b'LibNaCLPK:' + b'0' * 32), endpoint=AutoMockEndpoint(),
                                     network=Network())
        community = NewCommunity(settings)
        community.bootstrappers = [DispersyBootstrapper([], [])]

        # Initialize bootstrapper and get the bootstrapping task
        community.bootstrap()
        tasks = community.get_tasks()
        bootstrap_task = tasks[1]
        # Unload the Community after the bootstrapping task has completed.
        await bootstrap_task
        await community.unload()

        self.assertEqual(2, len(tasks),
                         msg="Precondition failed. Only the bootstrap/LAN discovery tasks should be running!")
        self.assertFalse(bootstrap_task.cancelled())

    async def test_cancel_bootstrap(self) -> None:
        """
        Check if unloading a Community while waiting for bootstrapping results exits cleanly.
        """
        settings = CommunitySettings(my_peer=Peer(b'LibNaCLPK:' + b'0' * 32), endpoint=AutoMockEndpoint(),
                                     network=Network())
        community = NewCommunity(settings)
        community.bootstrappers = [DispersyBootstrapper([], [])]

        # Initialize bootstrapper and get the bootstrapping task
        community.bootstrap()
        tasks = community.get_tasks()
        bootstrap_task = tasks[1]
        # Cancel the bootstrapping task before it can complete.
        await community.unload()

        self.assertEqual(2, len(tasks),
                         msg="Precondition failed. Only the bootstrap/LAN discovery tasks should be running!")
        self.assertTrue(bootstrap_task.cancelled())
