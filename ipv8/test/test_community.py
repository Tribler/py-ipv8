from .base import TestBase
from .mocking.endpoint import AutoMockEndpoint, MockEndpointListener
from .mocking.ipv8 import MockIPv8
from ..bootstrapping.dispersy.bootstrapper import DispersyBootstrapper
from ..community import Community
from ..peer import Peer
from ..peerdiscovery.network import Network


class OldCommunity(Community):
    community_id = b'\x00' * 20

    def create_introduction_request(self, socket_address, extra_bytes=b'', new_style=False):
        return super().create_introduction_request(socket_address)

    def create_introduction_response(self, lan_socket_address, socket_address, identifier,
                                     introduction=None, extra_bytes=b'', prefix=None, new_style=False):
        return super().create_introduction_response(lan_socket_address, socket_address, identifier, introduction)

    def create_puncture(self, lan_walker, wan_walker, identifier, new_style=False):
        return super().create_puncture(lan_walker, wan_walker, identifier)

    def create_puncture_request(self, lan_walker, wan_walker, identifier, prefix=None, new_style=False):
        return super().create_puncture_request(lan_walker, wan_walker, identifier)


class NewCommunity(Community):
    community_id = b'\x00' * 20


class TestCommunityCompatibility(TestBase):
    """
    Tests for interoperability between old-style and new-style IPv8 Communities.
    """

    def setUp(self):
        super().setUp()
        self.production_overlay_classes.append(OldCommunity)
        self.production_overlay_classes.append(NewCommunity)
        self.make_nodes()

    def make_nodes(self):
        self.nodes = [MockIPv8(u"low", NewCommunity), MockIPv8(u"low", NewCommunity), MockIPv8(u"low", OldCommunity)]
        self.endpoint_listeners = [MockEndpointListener(self.endpoint(i)) for i in range(len(self.nodes))]
        self.new_peer1 = 0
        self.new_peer2 = 1
        self.old_peer = 2

    def endpoint_listener(self, i):
        return self.endpoint_listeners[i]

    def received_message_ids(self, i):
        return [packet[1][22] for packet in self.endpoint_listener(i).received_packets]

    async def walk_from_to(self, from_i, to_i):
        self.overlay(from_i).walk_to(self.address(to_i))
        await self.deliver_messages()

    async def test_introduce_old(self):
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
    pass


class StrangeIDCommunity(Community):
    community_id = '\x00' * 20  # This is not ``bytes`` but ``str``: error!


class TestCommunityInit(TestBase):
    """
    Tests for initializing new Communities.

    - A test for a Community with a valid id is omitted as this is already covered by other tests.
    """

    async def test_init_no_id(self):
        """
        Check that attempting to create a Community without an id raises an error.
        """
        self.assertRaises(RuntimeError, NoIDCommunity, Peer(b'LibNaCLPK:' + b'0' * 32), AutoMockEndpoint(), Network())

    async def test_init_strange_id(self):
        """
        Check that attempting to create a Community with an id that is not ```bytes`` raises an error.
        """
        self.assertRaises(RuntimeError, StrangeIDCommunity, Peer(b'LibNaCLPK:' + b'0' * 32), AutoMockEndpoint(),
                          Network())


class TestCommunityBootstrapping(TestBase):
    """
    Tests for the Community to Bootstrapper interface.

    Note: don't put tests for the Bootstrapper implementations here.
    """

    async def test_empty_bootstrap(self):
        """
        Check if unloading a Community after waiting for bootstrapping results exits cleanly.
        """
        community = NewCommunity(Peer(b'LibNaCLPK:' + b'0' * 32), AutoMockEndpoint(), Network())
        community.bootstrappers = [DispersyBootstrapper([], [])]

        # Initialize bootstrapper and get the bootstrapping task
        community.bootstrap()
        tasks = community.get_tasks()
        # Unload the Community after the bootstrapping task has completed.
        await tasks[0]
        await community.unload()

        self.assertEqual(1, len(tasks), msg="Precondition failed. Only the bootstrap task should be running!")
        self.assertFalse(tasks[0].cancelled())

    async def test_cancel_bootstrap(self):
        """
        Check if unloading a Community while waiting for bootstrapping results exits cleanly.
        """
        community = NewCommunity(Peer(b'LibNaCLPK:' + b'0' * 32), AutoMockEndpoint(), Network())
        community.bootstrappers = [DispersyBootstrapper([], [])]

        # Initialize bootstrapper and get the bootstrapping task
        community.bootstrap()
        tasks = community.get_tasks()
        # Cancel the bootstrapping task before it can complete.
        await community.unload()

        self.assertEqual(1, len(tasks), msg="Precondition failed. Only the bootstrap task should be running!")
        self.assertTrue(tasks[0].cancelled())
