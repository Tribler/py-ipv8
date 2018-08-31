from twisted.internet import reactor
from twisted.internet.task import deferLater

from ...gossip.community import GossipOverlay, GossipRule, IGossipOverlayListener
from ...peer import Peer
from ...test.base import TestBase
from ...test.mocking.ipv8 import MockIPv8
from ...test.util import twisted_wrapper


class MockGossipOverlayListener(IGossipOverlayListener):

    def __init__(self, node):
        """
        Initialize a Mock Gossip Listener

        :param node: a node which must have a Gossip Overlay
        """
        self.node = node

    def on_gossip(self, public_key, message):
        self.node.overlay.store(public_key, message)


class TestGossipOverlay(TestBase):

    def create_node(self, *args, **kwargs):
        return MockIPv8(u"curve25519", self.overlay_class, *args, **kwargs)

    def setUp(self):
        super(TestGossipOverlay, self).setUp()
        self.initialize(GossipOverlay, 3)

        overlay_prefix = self.nodes[0].overlay.prefix

        # Introduce the neighbors for the Gossip service
        for node in self.nodes:
            for other in self.nodes:
                if not other == node:
                    private_peer = other.my_peer
                    public_peer = Peer(private_peer.public_key, private_peer.address)
                    node.network.add_verified_peer(public_peer)
                    node.network.discover_services(public_peer, [overlay_prefix])

    def remove_neighborhood(self, peer):
        """
        Removes the neighborhood of a peer

        :param peer: the peer whose neighborhood should be removed
        :return: None
        """
        for node in self.nodes:
            if not peer == node:
                private_peer = node.my_peer
                public_peer = Peer(private_peer.public_key, private_peer.address)
                peer.network.remove_peer(public_peer)

    @twisted_wrapper(2)
    def test_gossip_rule_vote_success(self):
        """
        Test the voting scheme for changing the GossipRule for a particular peer

        :return: None
        """
        target_public_key = self.nodes[0].overlay.my_peer.public_key.key_to_bin()

        self.nodes[1].overlay.set_rule(target_public_key, GossipRule.SUPPRESS)
        self.nodes[2].overlay.set_rule(target_public_key, GossipRule.SUPPRESS)

        yield deferLater(reactor, 1, lambda: None)

        yield self.deliver_messages()

        self.assertEqual(self.nodes[0].overlay.get_rule(target_public_key), GossipRule.SUPPRESS,
                         "The rule was not changed")

    @twisted_wrapper(2)
    def test_message_persistence_on_DEFAULT(self):
        """
        Test the persistence of a message stored in a peers' DB, upon receiving a DEFAULT rule message from a
        non-neighboring peer

        :return: None
        """
        # Remove the neighborhood of the first peer
        self.remove_neighborhood(self.nodes[0])

        first_node_pk = self.nodes[0].my_peer.key.pub().key_to_bin()

        message_contents = "asd"
        payload = self.nodes[0].my_peer.key.signature(message_contents) + message_contents

        # Store the message in the first peer's DB
        self.nodes[0].overlay.store(first_node_pk, message_contents)

        # Send the same message from the second peer
        self.assertTrue(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "The message could not be "
                                                                                            "stored in the first "
                                                                                            "node's DB.")

        self.nodes[1].overlay.send_to_neighbors(GossipRule.DEFAULT, first_node_pk, payload)

        yield deferLater(reactor, 1, lambda: None)

        yield self.deliver_messages()

        # Check that it was removed
        self.assertTrue(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "The message was deleted "
                                                                                            "from the first node's DB.")

    @twisted_wrapper(2)
    def test_message_removal_on_DEFAULT(self):
        """
        Test the removal of a message stored in a peers' DB, upon receiving a DEFAULT rule message from a
        non-neighboring peer

        :return: None
        """
        # Remove the neighborhood of the first peer
        self.remove_neighborhood(self.nodes[0])

        first_node_pk = self.nodes[0].my_peer.key.pub().key_to_bin()

        message_contents = "asd"
        payload = self.nodes[0].my_peer.key.signature(message_contents) + message_contents

        # Add the listener to the first peer
        self.nodes[0].overlay.add_listener(MockGossipOverlayListener(self.nodes[0]))

        # Send the same message from the second peer
        self.assertFalse(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "The message should not "
                                                                                             "be stored in the first "
                                                                                             "node's DB.")

        self.nodes[1].overlay.send_to_neighbors(GossipRule.DEFAULT, first_node_pk, payload)

        yield deferLater(reactor, 1, lambda: None)

        yield self.deliver_messages()

        # Check that it was removed
        self.assertFalse(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "The message could not be "
                                                                                             "deleted from the first "
                                                                                             "node's DB.")
