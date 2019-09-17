from __future__ import absolute_import

import collections

from twisted.trial import unittest

from ....keyvault.crypto import default_eccrypto
from ....peer import Peer
from ....peerdiscovery.latency.discovery import LatencyEdgeWalk
from ....peerdiscovery.network import Network


class MockOverlay(object):

    def __init__(self):
        # Mocking
        self.max_peers = 0
        self.network = Network()

        # Walker output
        self.possible_peers = []

        # Call inspection
        self.sent_introduction_requests = []
        self.sent_walk_to = []
        self.sent_pings = []
        self.has_bootstrapped = False

    def send_introduction_request(self, peer):
        self.sent_introduction_requests.append(peer)

    def send_ping(self, peer):
        self.sent_pings.append(peer)

    def walk_to(self, address):
        self.sent_walk_to.append(address)

    def get_peers(self):
        return self.network.verified_peers

    def get_walkable_addresses(self):
        return self.network.get_walkable_addresses()

    def bootstrap(self):
        self.has_bootstrapped = True


class TestLatencyEdgeWalk(unittest.TestCase):
    tracker_peer = None
    root_peer = None
    root_peer_pinged = None

    def setUp(self):
        super(TestLatencyEdgeWalk, self).setUp()
        self.overlay = MockOverlay()

        self.overlay.network.blacklist.append(self.tracker_peer.address)
        self.overlay.network.blacklist_mids.append(self.tracker_peer.mid)

        self.walker = LatencyEdgeWalk(self.overlay)

    @classmethod
    def setUpClass(cls):
        cls.tracker_peer = Peer(default_eccrypto.generate_key(u"low").pub())
        cls.root_peer = Peer(default_eccrypto.generate_key(u"low").pub(), ("1.1.1.1", 1))
        cls.root_peer_pinged = Peer(default_eccrypto.generate_key(u"low").pub(), ("1.1.1.2", 1))
        cls.root_peer_pinged.pings = collections.deque([0.1, 0.11, 0.09, 0.1, 0.1], maxlen=5)

    def test_get_root_address_none(self):
        """
        Check whether we try to bootstrap when requesting a root node.
        """
        self.walker.get_root_address()

        self.assertTrue(self.overlay.has_bootstrapped)
        self.assertListEqual([], self.walker.roots)

    def test_get_root_address_one(self):
        """
        Check whether we add a root node when requesting a root node.
        """
        self.overlay.network.add_verified_peer(self.root_peer)
        self.walker.get_root_address()

        self.assertTrue(self.overlay.has_bootstrapped)
        self.assertListEqual([self.root_peer], self.walker.roots)

    def test_get_granular_ping_no_data(self):
        """
        Check if get_granular_ping returns None without enough pings.
        """
        ping = self.walker.get_granular_ping(self.root_peer)

        self.assertIsNone(ping)
        self.assertListEqual([self.root_peer], self.overlay.sent_pings)

    def test_get_granular_ping_data(self):
        """
        Check if get_granular_ping returns the median ping with enough pings.
        """
        ping = self.walker.get_granular_ping(self.root_peer_pinged)

        self.assertEqual(0.1, ping)
        self.assertListEqual([], self.overlay.sent_pings)

    def test_check_extend_edge_unknown(self):
        """
        Check if we walk to a possible edge extension.
        """
        introduced = ('1.2.3.4', 5)
        self.overlay.network.discover_address(self.root_peer_pinged, introduced)

        removed = []
        self.walker.check_extend_edge(self.root_peer_pinged, [self.root_peer_pinged.get_median_ping()], removed)

        self.assertListEqual([introduced], self.overlay.sent_walk_to)
        self.assertListEqual([], removed)

    def test_check_extend_edge_ping_known(self):
        """
        Check if we explore the current leaf's subgraph.
        """
        verified_peer = Peer(default_eccrypto.generate_key(u"low").pub(), ('1.2.3.4', 5))
        self.overlay.network.discover_address(self.root_peer_pinged, verified_peer.address)
        self.overlay.network.add_verified_peer(verified_peer)
        self.walker.ancestry[verified_peer] = None

        removed = []
        self.walker.check_extend_edge(self.root_peer_pinged, [self.root_peer_pinged.get_median_ping()], removed)

        self.assertListEqual([verified_peer.address], self.overlay.sent_walk_to)
        self.assertListEqual([], removed)
        self.assertListEqual([verified_peer], self.overlay.sent_pings)

    def test_check_extend_edge_ensure_ping(self):
        """
        Don't add verified peers without sufficient ping information.
        """
        verified_peer = Peer(default_eccrypto.generate_key(u"low").pub(), ('1.2.3.4', 5))
        self.overlay.network.discover_address(self.root_peer_pinged, verified_peer.address)
        self.overlay.network.add_verified_peer(verified_peer)

        removed = []
        self.walker.check_extend_edge(self.root_peer_pinged, [self.root_peer_pinged.get_median_ping()], removed)

        self.assertListEqual([], self.overlay.sent_walk_to)
        self.assertListEqual([], removed)
        self.assertListEqual([verified_peer], self.overlay.sent_pings)

    def test_check_extend_edge_ensure_unique(self):
        """
        Don't add verified peers without sufficiently unique ping.
        """
        verified_peer = Peer(default_eccrypto.generate_key(u"low").pub(), ('1.2.3.4', 5))
        verified_peer.pings = self.root_peer_pinged.pings
        self.overlay.network.discover_address(self.root_peer_pinged, verified_peer.address)
        self.overlay.network.add_verified_peer(verified_peer)

        removed = []
        self.walker.check_extend_edge(self.root_peer_pinged, [self.root_peer_pinged.get_median_ping()], removed)

        self.assertListEqual([], self.overlay.sent_walk_to)
        self.assertListEqual([], removed)
        self.assertListEqual([], self.overlay.sent_pings)
        self.assertNotIn(verified_peer, self.walker.ancestry)

    def test_check_extend_edge_add_unique(self):
        """
        Add verified peers with sufficiently unique ping.
        """
        verified_peer = Peer(default_eccrypto.generate_key(u"low").pub(), ('1.2.3.4', 5))
        verified_peer.pings = collections.deque([1.0, 1.1, 0.9, 1.0, 1.0], maxlen=5)
        self.overlay.network.discover_address(self.root_peer_pinged, verified_peer.address)
        self.overlay.network.add_verified_peer(verified_peer)

        removed = []
        self.walker.check_extend_edge(self.root_peer_pinged, [self.root_peer_pinged.get_median_ping()], removed)

        self.assertListEqual([], self.overlay.sent_walk_to)
        self.assertListEqual([self.root_peer_pinged], removed)
        self.assertListEqual([], self.overlay.sent_pings)
        self.assertIn(verified_peer, self.walker.ancestry)
        self.assertEqual(self.root_peer_pinged, self.walker.ancestry[verified_peer])
        self.assertListEqual([verified_peer], self.walker.leaves)

    def test_ensure_leaf_pings_none(self):
        """
        If we have room to grow, ping the current leaf and request an introduction.
        """
        ping_times = self.walker.ensure_leaf_pings(self.root_peer)

        self.assertListEqual([self.root_peer], self.overlay.sent_pings)
        self.assertListEqual([self.root_peer], self.overlay.sent_introduction_requests)
        self.assertListEqual([], ping_times)

    def test_ensure_leaf_pings_complete(self):
        """
        If we do not have room to grow and a pinged leaf, don't ping the current leaf and request no introduction.
        """
        self.walker.max_edge_length = 1

        ping_times = self.walker.ensure_leaf_pings(self.root_peer_pinged)

        self.assertListEqual([], self.overlay.sent_pings)
        self.assertListEqual([], self.overlay.sent_introduction_requests)
        self.assertListEqual([0.1], ping_times)

    def test_ensure_leaf_pings_child_pinged(self):
        """
        Check if all ping times are measured along an edge, with an unpinged parent.
        """
        self.walker.ancestry = {self.root_peer: self.root_peer_pinged}

        ping_times = self.walker.ensure_leaf_pings(self.root_peer)

        self.assertListEqual([self.root_peer], self.overlay.sent_pings)
        self.assertListEqual([self.root_peer], self.overlay.sent_introduction_requests)
        self.assertListEqual([0.1], ping_times)

    def test_ensure_leaf_pings_parent_pinged(self):
        """
        Check if all ping times are measured along an edge, with an unpinged child.
        """
        self.walker.ancestry = {self.root_peer_pinged: self.root_peer}

        ping_times = self.walker.ensure_leaf_pings(self.root_peer_pinged)

        self.assertListEqual([self.root_peer], self.overlay.sent_pings)
        self.assertListEqual([self.root_peer_pinged], self.overlay.sent_introduction_requests)
        self.assertListEqual([0.1], ping_times)

    def test_ensure_leaf_pings_both_pinged(self):
        """
        Check if all ping times are reported along an edge, with an all members pinged.
        """
        pinged_peer = Peer(default_eccrypto.generate_key(u"low").pub(), ('1.2.3.4', 5))
        pinged_peer.pings = collections.deque([1.0, 1.1, 0.9, 1.0, 1.0], maxlen=5)
        self.walker.ancestry = {self.root_peer_pinged: pinged_peer}

        ping_times = self.walker.ensure_leaf_pings(self.root_peer_pinged)

        self.assertListEqual([], self.overlay.sent_pings)
        self.assertListEqual([self.root_peer_pinged], self.overlay.sent_introduction_requests)
        self.assertListEqual([0.1, 1.0], ping_times)

    def test_garbage_collect(self):
        """
        Check if garbage peers are removed from the network.
        """
        self.overlay.network.add_verified_peer(self.root_peer)

        self.overlay.max_peers = 0
        self.walker.max_edge_length = 0
        self.walker.garbage_collect()

        self.assertListEqual([], self.overlay.get_peers())

    def test_garbage_collect_no_leaves(self):
        """
        Check if leaves are not garbage collected.
        """
        self.overlay.network.add_verified_peer(self.root_peer)
        self.walker.leaves.append(self.root_peer)

        self.overlay.max_peers = 0
        self.walker.max_edge_length = 0
        self.walker.garbage_collect()

        self.assertListEqual([self.root_peer], self.overlay.get_peers())

    def test_garbage_collect_no_ancestry(self):
        """
        Check if nodes in edges are not garbage collected.
        """
        self.overlay.network.add_verified_peer(self.root_peer)
        self.walker.ancestry[self.root_peer] = self.root_peer

        self.overlay.max_peers = 0
        self.walker.max_edge_length = 0
        self.walker.garbage_collect()

        self.assertListEqual([self.root_peer], self.overlay.get_peers())

    def test_garbage_collect_reroute_middle(self):
        """
        Check if a middle node in an edge becomes unresponsive, the edge reroutes itself.
        """
        other_peer = Peer(default_eccrypto.generate_key(u"low").pub(), ('1.2.3.4', 5))
        self.overlay.network.add_verified_peer(self.root_peer)
        self.overlay.network.add_verified_peer(self.root_peer_pinged)
        self.walker.ancestry[self.root_peer] = other_peer
        self.walker.ancestry[other_peer] = self.root_peer_pinged
        self.walker.roots = [self.root_peer_pinged]
        self.walker.leaves = [self.root_peer]

        # Edge: (root) self.root_peer_pinged <- other_peer <- self.root_peer (leaf)
        # other_peer is unresponsive, reroute
        self.overlay.max_peers = 0
        self.walker.max_edge_length = 0
        self.walker.garbage_collect()

        # New edge: (root) self.root_peer_pinged <- self.root_peer (leaf)
        self.assertIn(self.root_peer, self.overlay.get_peers())
        self.assertIn(self.root_peer_pinged, self.overlay.get_peers())
        self.assertNotIn(other_peer, self.overlay.get_peers())
        self.assertIn(self.root_peer, self.walker.ancestry)
        self.assertIn(self.root_peer, self.walker.leaves)
        self.assertIn(self.root_peer_pinged, self.walker.roots)
        self.assertNotIn(other_peer, self.walker.ancestry)
        self.assertEqual(self.root_peer_pinged, self.walker.ancestry[self.root_peer])

    def test_garbage_collect_reroute_leaf(self):
        """
        Check if a leaf node in an edge becomes unresponsive, the edge reroutes itself.
        """
        other_peer = Peer(default_eccrypto.generate_key(u"low").pub(), ('1.2.3.4', 5))
        self.overlay.network.add_verified_peer(other_peer)
        self.overlay.network.add_verified_peer(self.root_peer_pinged)
        self.walker.ancestry[self.root_peer] = other_peer
        self.walker.ancestry[other_peer] = self.root_peer_pinged
        self.walker.roots = [self.root_peer_pinged]
        self.walker.leaves = [self.root_peer]

        # Edge: (root) self.root_peer_pinged <- other_peer <- self.root_peer (leaf)
        # self.root_peer is unresponsive, reroute
        self.overlay.max_peers = 0
        self.walker.max_edge_length = 0
        self.walker.garbage_collect()

        # New edge: (root) self.root_peer_pinged <- other_peer (leaf)
        self.assertNotIn(self.root_peer, self.overlay.get_peers())
        self.assertIn(self.root_peer_pinged, self.overlay.get_peers())
        self.assertIn(other_peer, self.overlay.get_peers())
        self.assertIn(other_peer, self.walker.ancestry)
        self.assertIn(other_peer, self.walker.leaves)
        self.assertIn(self.root_peer_pinged, self.walker.roots)
        self.assertNotIn(self.root_peer, self.walker.ancestry)
        self.assertEqual(self.root_peer_pinged, self.walker.ancestry[other_peer])

    def test_garbage_collect_reroute_root(self):
        """
        Check if a root node in an edge becomes unresponsive, the edge reroutes itself.
        """
        other_peer = Peer(default_eccrypto.generate_key(u"low").pub(), ('1.2.3.4', 5))
        self.overlay.network.add_verified_peer(self.root_peer)
        self.overlay.network.add_verified_peer(other_peer)
        self.walker.ancestry[self.root_peer] = other_peer
        self.walker.ancestry[other_peer] = self.root_peer_pinged
        self.walker.roots = [self.root_peer_pinged]
        self.walker.leaves = [self.root_peer]

        # Edge: (root) self.root_peer_pinged <- other_peer <- self.root_peer (leaf)
        # self.root_peer_pinged is unresponsive, reroute
        self.overlay.max_peers = 0
        self.walker.max_edge_length = 0
        self.walker.garbage_collect()

        # New edge: (root) self.root_peer_pinged <- self.root_peer (leaf)
        self.assertIn(self.root_peer, self.overlay.get_peers())
        self.assertNotIn(self.root_peer_pinged, self.overlay.get_peers())
        self.assertIn(other_peer, self.overlay.get_peers())
        self.assertIn(self.root_peer, self.walker.ancestry)
        self.assertIn(self.root_peer, self.walker.leaves)
        self.assertNotIn(self.root_peer_pinged, self.walker.roots)
        self.assertIn(other_peer, self.walker.roots)
        self.assertNotIn(self.root_peer_pinged, self.walker.ancestry.values())
        self.assertEqual(other_peer, self.walker.ancestry[self.root_peer])
