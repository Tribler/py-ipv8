from __future__ import absolute_import

from twisted.internet.defer import inlineCallbacks

from ...gossip.community import GossipOverlay, GossipRule, IGossipOverlayListener
from ...peer import Peer
from ...test.base import TestBase
from ...test.mocking.ipv8 import MockIPv8


class MockGossipOverlayListener(IGossipOverlayListener):

    def __init__(self, node):
        """
        Initialize a Mock Gossip Listener

        :param node: a node which must have a Gossip Overlay
        """
        self.node = node

    def on_gossip(self, public_key, message):
        """
        Store the message in the message_db
        """
        self.node.overlay.store(public_key, message)


class MockGossipOverlayListenerAppending(MockGossipOverlayListener):
    APPENDED_LITERAL = b"_APPENDED_LITERAL"

    def on_gossip(self, public_key, message):
        """
        Store the message in the message_db with an additional appended literal
        """
        self.node.overlay.store(public_key, message + MockGossipOverlayListenerAppending.APPENDED_LITERAL)


class MockGossipOverlayListenerDeleting(MockGossipOverlayListener):

    def on_gossip(self, public_key, message):
        """
        Try to clear the message_db of the public_key which was received
        """
        del self.node.overlay.message_db[public_key]


class TestGossipOverlay(TestBase):

    def create_node(self, *args, **kwargs):
        node = MockIPv8(u"curve25519", self.overlay_class, *args, **kwargs)
        node.overlay.cancel_pending_task('update_key')

        return node

    def setUp(self):
        super(TestGossipOverlay, self).setUp()
        self.initialize(GossipOverlay, 2)

        overlay_prefix = self.nodes[0].overlay.prefix

        # Introduce the neighbors for the Gossip service
        for node in self.nodes:
            self.introduce_to_Gossip_Overlays(node, overlay_prefix)

    def tgo_add_node_to_experiment(self, node, prefix):
        super(TestGossipOverlay, self).add_node_to_experiment(node)
        self.introduce_to_Gossip_Overlays(node, prefix, True)

    def introduce_to_Gossip_Overlays(self, node, overlay_prefix, reverse_add=False):
        """
        Introduce peers to each other's GossipOverlay

        :param node: the node in focus which is being added to the other peer's GossipOverlay
        :param overlay_prefix: the service identifier for the GossipOverlay
        :param reverse_add: when a new node is introduced after initialization, it should be added to the other peer's
                            GossipOverlay as well
        :return: None
        """
        node_public_peer = None

        if reverse_add:
            node_public_peer = Peer(node.my_peer.public_key, node.my_peer.address)

        for other in self.nodes:
            if not other == node:
                private_peer = other.my_peer
                public_peer = Peer(private_peer.public_key, private_peer.address)
                node.network.add_verified_peer(public_peer)
                node.network.discover_services(public_peer, [overlay_prefix])

                if reverse_add:
                    other.network.add_verified_peer(node_public_peer)
                    other.network.discover_services(node_public_peer, [overlay_prefix])

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

    def force_take_step(self, peer_idx, count=1):
        """
        Force a peer to take a number of steps

        :param peer_idx: the peer index in self.nodes
        :param count: the number of steps to be made by the peer
        :return:
        """
        for _ in range(count):
            self.nodes[peer_idx].overlay.take_step()

    @staticmethod
    def generate_signed_payload(signer_peer, true_data=b""):
        """
        Generate a signed payload for a given data for a given peer

        :param signer_peer: the peer which signs the payload
        :param true_data: the true data which is supposed to be signed and passed as part of the payload
        :return: the signed payload
        """
        return signer_peer.my_peer.key.signature(true_data) + true_data

    @inlineCallbacks
    def test_time_change_neighbor(self):
        """
        Test the fact that the clock changes (locally) in neighboring peers when a local peer receives a message
        from them

        :return: None
        """
        first_node_pk = self.nodes[0].my_peer.key.pub().key_to_bin()
        second_node_pk = self.nodes[1].my_peer.key.pub().key_to_bin()

        message_contents = b"asd"

        # Store the message in the second peer's DB and set the local rule for the first peer
        self.nodes[1].overlay.store(first_node_pk, self.generate_signed_payload(self.nodes[0], message_contents))
        self.nodes[1].overlay.set_rule(first_node_pk, GossipRule.SPREAD)

        self.assertEqual(0, self.nodes[0].overlay.network.get_verified_by_public_key_bin(second_node_pk)
                         .get_lamport_timestamp(), "Timestamp should be 0.")

        initial_time = self.nodes[0].overlay.network.get_verified_by_public_key_bin(second_node_pk).last_response

        # Send the message
        self.force_take_step(1)
        yield self.deliver_messages()

        self.assertEqual(0, self.nodes[0].overlay.network.get_verified_by_public_key_bin(second_node_pk)
                         .get_lamport_timestamp(), "Timestamp should be 0.")
        self.assertNotEqual(initial_time, self.nodes[0].overlay.network
                            .get_verified_by_public_key_bin(second_node_pk).last_response, "Last response time did not"
                                                                                           "change")

    @inlineCallbacks
    def test_message_rule_SUPPRESS_success(self):
        """
        Test the voting scheme for changing the GossipRule for a particular peer to SUPPRESS peer on success

        :return: None
        """
        self.tgo_add_node_to_experiment(self.create_node(), self.nodes[0].overlay.prefix)
        target_public_key = self.nodes[0].overlay.my_peer.public_key.key_to_bin()

        self.nodes[1].overlay.set_rule(target_public_key, GossipRule.SUPPRESS)
        self.nodes[2].overlay.set_rule(target_public_key, GossipRule.SUPPRESS)

        self.force_take_step(1, 2)
        self.force_take_step(2, 2)

        yield self.deliver_messages()

        self.assertEqual(self.nodes[0].overlay.get_rule(target_public_key), GossipRule.SUPPRESS,
                         "The rule was not changed")

    @inlineCallbacks
    def test_message_rule_SUPPRESS_fail(self):
        """
        Test the voting scheme for changing the GossipRule for a particular peer to SUPPRESS on failure

        :return: None
        """
        self.tgo_add_node_to_experiment(self.create_node(), self.nodes[0].overlay.prefix)
        target_public_key = self.nodes[0].overlay.my_peer.public_key.key_to_bin()

        self.nodes[1].overlay.set_rule(target_public_key, GossipRule.SUPPRESS)
        # The third peer will avoid voting for SUPPRESSION
        self.nodes[2].overlay.set_rule(target_public_key, GossipRule.DEFAULT)

        # Run multiple steps to increase the chances of failure (which should still be 0)
        self.force_take_step(1, 5)
        self.force_take_step(2, 5)

        yield self.deliver_messages()

        self.assertIsNotNone(self.nodes[0].overlay.rule_change_db.get(target_public_key, None), "The ballot could "
                                                                                                "not be added")

        self.nodes[0].overlay._reset_vote(target_public_key)

        self.assertRaises(KeyError, lambda: self.nodes[0].overlay.rule_change_db[target_public_key])

    @inlineCallbacks
    def test_message_rule_SUPPRESS_non_neighbor(self):
        """
        Test the voting scheme for changing the GossipRule for a particular peer to SUPPRESS when non-neighbor. This
        should fail.

        :return: None
        """
        self.tgo_add_node_to_experiment(self.create_node(), self.nodes[0].overlay.prefix)
        target_public_key = self.nodes[0].overlay.my_peer.public_key.key_to_bin()

        # Remove the neighborhood so the votes will be ignored
        self.remove_neighborhood(self.nodes[0])

        self.assertEqual(self.nodes[0].overlay.get_rule(target_public_key), GossipRule.DEFAULT,
                         "The rule should initially be DEFAULT.")

        self.nodes[1].overlay.set_rule(target_public_key, GossipRule.SUPPRESS)
        self.nodes[2].overlay.set_rule(target_public_key, GossipRule.SUPPRESS)

        self.force_take_step(1, 2)
        self.force_take_step(2, 2)

        yield self.deliver_messages()

        self.assertEqual(self.nodes[0].overlay.get_rule(target_public_key), GossipRule.DEFAULT, "The rule was changed.")

    @inlineCallbacks
    def test_peer_rule_DEFAULT_persistence(self):
        """
        Test the persistence of a message stored in a peers' DB, upon receiving an (already) stored message from a
        DEFAULT rule peer which isn't a neighbor

        :return: None
        """
        # Remove the neighborhood of the first peer
        self.remove_neighborhood(self.nodes[0])

        first_node_pk = self.nodes[0].my_peer.key.pub().key_to_bin()

        message_contents = b"asd"

        # Store the message in the second peer's DB and set the local rule for the first peer
        self.nodes[1].overlay.store(first_node_pk, self.generate_signed_payload(self.nodes[0], message_contents))
        self.nodes[1].overlay.set_rule(first_node_pk, GossipRule.SPREAD)

        # Store the message in the first peer's DB
        self.nodes[0].overlay.store(first_node_pk, message_contents)

        # Send the same message from the second peer
        self.assertTrue(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "The message could not be "
                                                                                            "stored in the first "
                                                                                            "node's DB.")

        self.force_take_step(1)
        yield self.deliver_messages()

        # Check that it was removed
        self.assertTrue(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "The message was deleted "
                                                                                            "from the first node's DB.")

    @inlineCallbacks
    def test_peer_rule_DEFAULT_removal(self):
        """
        Test the removal of a message stored in a peers' DB, upon receiving a message from a DEFAULT rule peer
        which isn't a neighbor

        :return: None
        """
        # Remove the neighborhood of the first peer
        self.remove_neighborhood(self.nodes[0])

        first_node_pk = self.nodes[0].my_peer.key.pub().key_to_bin()

        message_contents = b"asd"

        # Store the message in the second peer's DB and set the local rule for the first peer
        self.nodes[1].overlay.store(first_node_pk, self.generate_signed_payload(self.nodes[0], message_contents))
        self.nodes[1].overlay.set_rule(first_node_pk, GossipRule.SPREAD)

        # Add the listener to the first peer
        self.nodes[0].overlay.add_listener(MockGossipOverlayListener(self.nodes[0]))

        # Send the same message from the second peer
        self.assertFalse(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "The message should not "
                                                                                             "be stored in the first "
                                                                                             "node's DB.")

        self.force_take_step(1)
        yield self.deliver_messages()

        # Check that it was removed
        self.assertFalse(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "The message could not be "
                                                                                             "deleted from the first "
                                                                                             "node's DB.")

    @inlineCallbacks
    def test_peer_rule_DEFAULT_neighbor(self):
        """
        Test the case where a neighboring DEFAULT rule peer (as set in the other peer) sends a SPREAD message to the
        other peer.

        :return: None
        """
        first_node_pk = self.nodes[0].my_peer.key.pub().key_to_bin()

        message_contents = b"asd"

        # Store the message in the second peer's DB and set the local rule for the first peer
        self.nodes[1].overlay.store(first_node_pk, self.generate_signed_payload(self.nodes[0], message_contents))
        self.nodes[1].overlay.set_rule(first_node_pk, GossipRule.SPREAD)

        # Add the listener to the first peer
        self.nodes[0].overlay.add_listener(MockGossipOverlayListenerAppending(self.nodes[0]))

        # Assert no messages are stored in the first peer prior to the message transmission
        self.assertFalse(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "No message should be "
                                                                                             "stored in the DB.")
        self.assertFalse(self.nodes[0].overlay.has_message(
            first_node_pk, message_contents + MockGossipOverlayListenerAppending.APPENDED_LITERAL), "No message should "
                                                                                                    "be stored in the "
                                                                                                    "DB.")

        self.force_take_step(1)
        yield self.deliver_messages()

        self.assertTrue(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "The message should be "
                                                                                            "stored in the DB.")
        self.assertTrue(self.nodes[0].overlay.has_message(
            first_node_pk, message_contents + MockGossipOverlayListenerAppending.APPENDED_LITERAL), "The message "
                                                                                                    "should be stored "
                                                                                                    "in the DB.")

    @inlineCallbacks
    def test_message_rule_SPREAD_neighbor(self):
        """
        Test the SPREAD Gossip Rule, when received from a neighboring peer

        :return: None
        """
        first_node_pk = self.nodes[0].my_peer.key.pub().key_to_bin()

        message_contents = b"asd"

        # Store the message in the second peer's DB and set the local rule for the first peer
        self.nodes[1].overlay.store(first_node_pk, self.generate_signed_payload(self.nodes[0], message_contents))
        self.nodes[1].overlay.set_rule(first_node_pk, GossipRule.SPREAD)

        # Add a listener to the first peer
        self.nodes[0].overlay.add_listener(MockGossipOverlayListenerAppending(self.nodes[0]))

        # Assert no messages are stored in the first peer prior to the message transmission
        self.assertFalse(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "No message should be "
                                                                                             "stored in the DB.")
        self.assertFalse(self.nodes[0].overlay.has_message(
            first_node_pk, message_contents + MockGossipOverlayListenerAppending.APPENDED_LITERAL), "No message should "
                                                                                                    "be stored in the "
                                                                                                    "DB.")

        self.force_take_step(1)
        yield self.deliver_messages()

        self.assertTrue(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "The message should be "
                                                                                            "stored in the DB.")
        self.assertTrue(self.nodes[0].overlay.has_message(
            first_node_pk, message_contents + MockGossipOverlayListenerAppending.APPENDED_LITERAL), "The message "
                                                                                                    "should be stored "
                                                                                                    "in the DB.")

    @inlineCallbacks
    def test_message_rule_SPREAD_non_neighbor(self):
        """
        Test the SPREAD Gossip Rule, when received from a non-neighboring peer whose rule is set to COLLECT (generally
        speaking, set to something different than DEFAULT)

        :return: None
        """
        # Remove the neighborhood of the first peer
        self.remove_neighborhood(self.nodes[0])
        first_node_pk = self.nodes[0].my_peer.key.pub().key_to_bin()
        second_node_pk = self.nodes[1].my_peer.key.pub().key_to_bin()

        message_contents = b"asd"

        # Store the message in the second peer's DB and set the local rule for the first peer
        self.nodes[1].overlay.store(first_node_pk, self.generate_signed_payload(self.nodes[0], message_contents))
        self.nodes[1].overlay.set_rule(first_node_pk, GossipRule.SPREAD)

        # Add a listener to the first peer and adjust rule for first peer
        self.nodes[0].overlay.add_listener(MockGossipOverlayListenerAppending(self.nodes[0]))
        self.nodes[0].overlay.set_rule(second_node_pk, GossipRule.COLLECT)

        # Assert no messages are stored in the first peer prior to the message transmission
        self.assertFalse(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "No message should be "
                                                                                             "stored in the DB.")
        self.assertFalse(self.nodes[0].overlay.has_message(
            first_node_pk, message_contents + MockGossipOverlayListenerAppending.APPENDED_LITERAL), "No message should "
                                                                                                    "be stored in the "
                                                                                                    "DB.")

        # Run multiple steps to increase the chances of failure (which should still be 0)
        self.force_take_step(1, 5)
        yield self.deliver_messages()

        self.assertTrue(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "The message was not "
                                                                                            "stored in the DB")
        self.assertTrue(self.nodes[0].overlay.has_message(
            first_node_pk, message_contents + MockGossipOverlayListenerAppending.APPENDED_LITERAL), "The message was "
                                                                                                    "not stored in "
                                                                                                    "the DB")

    @inlineCallbacks
    def test_message_rule_COLLECT_neighbor(self):
        """
        Test the COLLECT Gossip Rule, when the interaction is carried out from a neighboring peer whose rule is set
        to DEFAULT

        :return: None
        """
        second_node_pk = self.nodes[1].my_peer.key.pub().key_to_bin()

        # Set the COLLECT rule for the second peer
        self.nodes[0].overlay.set_rule(second_node_pk, GossipRule.COLLECT)

        # Add a simple message in the second peer
        message_contents = b"asd"
        self.nodes[1].overlay.store(second_node_pk, message_contents)

        # Make sure the first peer has no messages for this peer
        self.assertIsNone(self.nodes[0].overlay.message_db.get(second_node_pk, None), "The message DB should be empty "
                                                                                      "for this peer")

        self.force_take_step(0)
        yield self.deliver_messages()

        self.assertTrue(self.nodes[0].overlay.has_message(second_node_pk, message_contents), "The message should have "
                                                                                             "been added")

    @inlineCallbacks
    def test_message_rule_COLLECT_non_neighbor(self):
        """
        Test the COLLECT Gossip Rule, when the interaction is carried out from a non-neighboring peer whose rule is set
        to DEFAULT

        :return: None
        """
        self.remove_neighborhood(self.nodes[0])
        second_node_pk = self.nodes[1].my_peer.key.pub().key_to_bin()

        # Set the COLLECT rule for the second peer
        self.nodes[0].overlay.set_rule(second_node_pk, GossipRule.COLLECT)

        # Add a simple message in the second peer
        message_contents = "asd"
        self.nodes[1].overlay.store(second_node_pk, message_contents)

        # Make sure the first peer has no messages for this peer
        self.assertIsNone(self.nodes[0].overlay.message_db.get(second_node_pk, None), "The message DB should be empty "
                                                                                      "for this peer.")

        self.force_take_step(0)
        yield self.deliver_messages()

        self.assertIsNone(self.nodes[0].overlay.message_db.get(second_node_pk, None), "The message DB should be empty "
                                                                                      "for this peer.")

    @inlineCallbacks
    def test_message_rule_SUPPRESS_when_SUPPRESSED(self):
        """
        Test the gossip message rule SUPPRESS when one interacting peer is SUPPRESSED

        :return: None
        """
        self.tgo_add_node_to_experiment(self.create_node(), self.nodes[0].overlay.prefix)
        target_public_key = self.nodes[0].overlay.my_peer.public_key.key_to_bin()
        source_public_key = self.nodes[1].overlay.my_peer.public_key.key_to_bin()
        voting_public_key = self.nodes[2].overlay.my_peer.public_key.key_to_bin()

        self.nodes[1].overlay.set_rule(target_public_key, GossipRule.SUPPRESS)
        self.nodes[2].overlay.set_rule(target_public_key, GossipRule.SUPPRESS)

        # Ignore one of the peers
        self.nodes[0].overlay.set_rule(source_public_key, GossipRule.SUPPRESS)

        self.force_take_step(1, 2)
        self.force_take_step(2, 2)

        yield self.deliver_messages()

        self.assertTrue(voting_public_key in self.nodes[0].overlay.rule_change_db[target_public_key]._votes
                        and source_public_key not in self.nodes[0].overlay.rule_change_db[target_public_key]._votes,
                        "Either one vote was not recorded or the other was recorded when it shouldn't have been.")

        self.assertEqual(self.nodes[0].overlay.get_rule(target_public_key), GossipRule.DEFAULT, "The rule was changed.")

    @inlineCallbacks
    def test_peer_rule_DEFAULT_when_SUPPRESSED(self):
        """
        Test the gossip peer rule DEFAULT when the other interacting peer is SUPPRESSED

        :return: None
        """
        # Remove the neighborhood of the first peer
        self.remove_neighborhood(self.nodes[0])

        first_node_pk = self.nodes[0].my_peer.key.pub().key_to_bin()
        second_node_pk = self.nodes[1].my_peer.key.pub().key_to_bin()

        message_contents = b"asd"

        # Store the message in the second peer's DB and set the local rule for the first peer
        self.nodes[1].overlay.store(first_node_pk, self.generate_signed_payload(self.nodes[0], message_contents))
        self.nodes[1].overlay.set_rule(first_node_pk, GossipRule.SPREAD)

        # Store the message in the first peer's DB, make the second peer SUPPRESSED
        self.nodes[0].overlay.set_rule(second_node_pk, GossipRule.SUPPRESS)
        self.nodes[0].overlay.store(first_node_pk, message_contents)

        # Add a listener which deletes all messages when called (which should never happen normally)
        self.nodes[0].overlay.add_listener(MockGossipOverlayListenerDeleting(self.nodes[0]))

        # Send the same message from the second peer
        self.assertTrue(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "The message could not be "
                                                                                            "stored in the first "
                                                                                            "node's DB.")

        self.force_take_step(1)
        yield self.deliver_messages()

        # Check that it was removed
        self.assertTrue(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "The message was deleted "
                                                                                            "from the first node's DB.")

    @inlineCallbacks
    def test_message_rule_SPREAD_when_SUPPRESSED(self):
        """
        Test the gossip message rule SPREAD when one interacting peer is SUPPRESSED

        :return: None
        """
        first_node_pk = self.nodes[0].my_peer.key.pub().key_to_bin()
        second_node_pk = self.nodes[1].my_peer.key.pub().key_to_bin()

        message_contents = b"asd"

        # Store the message in the second peer's DB and set the local rule for the first peer
        self.nodes[1].overlay.store(first_node_pk, self.generate_signed_payload(self.nodes[0], message_contents))
        self.nodes[1].overlay.set_rule(first_node_pk, GossipRule.SPREAD)

        # SUPPRESS the second peer and add a listener to the first peer
        self.nodes[0].overlay.set_rule(second_node_pk, GossipRule.SUPPRESS)
        self.nodes[0].overlay.add_listener(MockGossipOverlayListenerAppending(self.nodes[0]))

        # Assert no messages are stored in the first peer prior to the message transmission
        self.assertFalse(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "No message should be "
                                                                                             "stored in the DB.")
        self.assertFalse(self.nodes[0].overlay.has_message(
            first_node_pk, message_contents + MockGossipOverlayListenerAppending.APPENDED_LITERAL), "No message should "
                                                                                                    "be stored in the "
                                                                                                    "DB.")

        self.force_take_step(1)
        yield self.deliver_messages()

        self.assertFalse(self.nodes[0].overlay.has_message(first_node_pk, message_contents), "No message should be "
                                                                                             "stored in the DB.")
        self.assertFalse(self.nodes[0].overlay.has_message(
            first_node_pk, message_contents + MockGossipOverlayListenerAppending.APPENDED_LITERAL), "No message should "
                                                                                                    "be stored in the "
                                                                                                    "DB.")

    @inlineCallbacks
    def test_message_rule_COLLECT_when_SUPPRESSED_target(self):
        """
        Test the gossip message rule COLLECT when the receiving peer is SUPPRESSED in the requesting peer

        :return: None
        """
        second_node_pk = self.nodes[1].my_peer.key.pub().key_to_bin()

        # Set the COLLECT rule for the second peer
        self.nodes[0].overlay.set_rule(second_node_pk, GossipRule.COLLECT)

        # Add a simple message in the second peer
        message_contents = b"asd"
        self.nodes[1].overlay.store(second_node_pk, message_contents)

        # Make the source second peer is SUPPRESSED in the first
        self.nodes[0].overlay.set_rule(second_node_pk, GossipRule.SUPPRESS)

        # Make sure the first peer has no messages for this peer
        self.assertIsNone(self.nodes[0].overlay.message_db.get(second_node_pk, None), "The message DB should be empty "
                                                                                      "for this peer")

        self.force_take_step(0)
        yield self.deliver_messages()

        self.assertIsNone(self.nodes[0].overlay.message_db.get(second_node_pk, None), "The message DB should be empty "
                                                                                      "for this peer")

    @inlineCallbacks
    def test_message_rule_COLLECT_when_SUPPRESSED_source(self):
        """
        Test the gossip message rule COLLECT when the requesting peer is SUPPRESSED in the receiving peer

        :return: None
        """
        first_node_pk = self.nodes[0].my_peer.key.pub().key_to_bin()
        second_node_pk = self.nodes[1].my_peer.key.pub().key_to_bin()

        # Set the COLLECT rule for the second peer
        self.nodes[0].overlay.set_rule(second_node_pk, GossipRule.COLLECT)

        # Add a simple message in the second peer
        message_contents = b"asd"
        self.nodes[1].overlay.store(second_node_pk, message_contents)

        # Make the source second peer SUPPRESSED in the first
        self.nodes[1].overlay.set_rule(first_node_pk, GossipRule.SUPPRESS)

        # Make sure the first peer has no messages for this peer
        self.assertIsNone(self.nodes[0].overlay.message_db.get(second_node_pk, None), "The message DB should be empty "
                                                                                      "for this peer")

        self.force_take_step(0)
        yield self.deliver_messages()

        self.assertIsNone(self.nodes[0].overlay.message_db.get(second_node_pk, None), "The message DB should be empty "
                                                                                      "for this peer")
