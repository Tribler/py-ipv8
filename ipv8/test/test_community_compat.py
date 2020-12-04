from .base import TestBase
from .mocking.endpoint import MockEndpointListener
from .mocking.ipv8 import MockIPv8
from ..community import Community


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
