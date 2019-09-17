from __future__ import absolute_import

import collections

from twisted.internet.defer import inlineCallbacks

from ...base import TestBase
from ....peer import Peer
from ....peerdiscovery.latency.community import LatencyCommunity


class TestLatencyCommunity(TestBase):

    @inlineCallbacks
    def setUp(self):
        super(TestLatencyCommunity, self).setUp()
        self.initialize(LatencyCommunity, 2, preferred_count=1)
        self.peer0 = Peer(self.nodes[0].my_peer.key.pub(), self.nodes[0].my_peer.address)
        self.peer0.pings = collections.deque([0.1, 0.11, 0.09, 0.1, 0.1], maxlen=5)
        self.peer1 = Peer(self.nodes[1].my_peer.key.pub(), self.nodes[1].my_peer.address)
        self.peer1.pings = collections.deque([0.1, 0.11, 0.09, 0.1, 0.1], maxlen=5)
        yield self.introduce_nodes()

    @inlineCallbacks
    def test_match(self):
        """
        If two peers match, they should end up in each others matches.
        """
        self.nodes[0].overlay.possible_peers = [self.peer1]
        self.nodes[1].overlay.possible_peers = [self.peer0]

        self.nodes[0].overlay.update_acceptable_peers()
        self.nodes[1].overlay.update_acceptable_peers()

        yield self.deliver_messages()

        self.assertIn(self.peer1, self.nodes[0].overlay.accepted_proposals)
        self.assertIn(self.peer0, self.nodes[1].overlay.accepted_proposals)

    @inlineCallbacks
    def test_no_match(self):
        """
        If two peers don't match, they shouldn't end up in each others matches.
        """
        self.nodes[0].overlay.possible_peers = []
        self.nodes[1].overlay.possible_peers = [self.peer0]

        self.nodes[0].overlay.update_acceptable_peers()
        self.nodes[1].overlay.update_acceptable_peers()

        yield self.deliver_messages()

        self.assertListEqual([], list(self.nodes[0].overlay.accepted_proposals))
        self.assertListEqual([], list(self.nodes[1].overlay.accepted_proposals))

    @inlineCallbacks
    def test_unmatch(self):
        """
        If a peer breaks a match, both peers should remove their matching.
        """
        self.nodes[0].overlay.possible_peers = [self.peer1]
        self.nodes[0].overlay.accepted_proposals = {self.peer1}
        self.nodes[1].overlay.possible_peers = [self.peer0]
        self.nodes[1].overlay.accepted_proposals = {self.peer0}

        self.nodes[0].overlay.preferred_count = 1
        self.nodes[0].overlay.update_acceptable_peers()

        yield self.deliver_messages()

        self.assertListEqual([], list(self.nodes[0].overlay.accepted_proposals))
        self.assertListEqual([], list(self.nodes[1].overlay.accepted_proposals))

    @inlineCallbacks
    def test_stats(self):
        """
        Check if we can collect a peer's stats
        """
        self.nodes[0].overlay.possible_peers = [self.peer0, self.peer1, self.peer0, self.peer1]
        self.nodes[0].overlay.accepted_proposals = {self.peer1}

        stats = yield self.nodes[1].overlay.send_stats_request(self.peer0)

        self.assertEqual(1, stats.total)
        self.assertEqual(4, stats.possible)
        self.assertEqual(1, stats.matched)
