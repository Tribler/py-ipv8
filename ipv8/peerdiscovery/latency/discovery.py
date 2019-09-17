from __future__ import absolute_import, division

import time

from ..discovery import DiscoveryStrategy


class LatencyEdgeWalk(DiscoveryStrategy):

    def __init__(self, overlay, max_roots=30, max_edge_length=6, max_similarity=0.05, gc_delay=30.0):
        """
        Create a new LatencyEdgeWalk strategy.

        :param overlay: the overlay to apply this strategy to
        :param max_roots: the node count from the bootstrap server
        :param max_edge_length: the maximum edge length
        :param max_similarity: the maximum similarity between ping times, in seconds
        :param gc_delay: the interval for garbage collection of loose connections
        """
        super(LatencyEdgeWalk, self).__init__(overlay)

        # Variables
        self.max_roots = max_roots
        self.max_edge_length = max_edge_length
        self.max_similarity = max_similarity
        self.gc_delay = gc_delay
        self.last_gc = 0.0  # UNIX timestamp 0

        # Data structures
        self.roots = []
        self.ancestry = {}  # Peer introduced by Peer (or None)
        self.leaves = []  # Current edges' HEAD Peer objects

        # If the overlay's max_peers does not match our settings, this algorithm will fail spectacularly.
        # Therefore we override any settings from the overlay with our own automatically.
        overlay.max_peers = max_roots * max_edge_length

    def get_root_address(self):
        """
        Bootstrap into a suffient set of root nodes.

        :returns: None
        """
        self.overlay.bootstrap()
        existing_mids = [p.mid for p in self.overlay.network.verified_peers]
        for peer in self.overlay.get_peers():
            peer_descriptor = self.overlay.network._all_addresses.get(peer.address, None)
            if peer_descriptor:
                introducer, service = peer_descriptor
                if introducer not in existing_mids and peer not in self.roots:
                    # Bootstrapped peer, not in use
                    self.roots.append(peer)
                    self.leaves.append(peer)

    def get_granular_ping(self, peer):
        """
        Get the ping for a peer, measure if necessary.

        :param peer: the peer to get the ping time for
        :type peer: Peer
        :return: the median ping for this peer
        :rtype: float or None
        """
        if not peer or not peer.pings or len(peer.pings) < peer.pings.maxlen:
            self.overlay.send_ping(peer)
            return None
        return peer.get_median_ping()

    def check_extend_edge(self, leaf, leaf_pings, removed_leafs):
        """
        Check if we can extend the edge a certain leaf resides on, do so if possible.

        :param leaf: the leaf to check for extension
        :type leaf: Peer
        :param leaf_pings: the list of pings in the edge of this leaf
        :type leaf_pings: [float]
        :param removed_leafs: reference the the leaves to be removed after this iteration (we can add to this)
        :type removed_leafs: [Peer]
        :returns: None
        """
        introductions = self.overlay.network.get_introductions_from(leaf)
        for introduction in introductions:
            ipeer = self.overlay.network.get_verified_by_address(introduction)
            if ipeer and ipeer not in self.ancestry:
                ipingtime = self.get_granular_ping(ipeer)
                if ipingtime is None:
                    continue
                unique = True
                for ptime in leaf_pings:
                    if ptime - self.max_similarity <= ipingtime <= ptime + self.max_similarity:
                        unique = False
                        break
                if unique:
                    removed_leafs.append(leaf)
                    self.leaves.append(ipeer)
                    self.ancestry[ipeer] = leaf
                    for other_intro in introductions:
                        if other_intro != introduction:
                            self.overlay.network.remove_by_address(other_intro)
            else:
                if ipeer:
                    self.get_granular_ping(ipeer)
                self.overlay.walk_to(introduction)

    def ensure_leaf_pings(self, leaf):
        """
        Get all of the pings in the ancestry of a leaf (measure if necessary) and make sure the leaf introduces us
        to other peers.

        :param leaf: the leaf of a unique ping edge
        :type leaf: Peer
        :return: the list of ping times on this leaf's edge
        :rtype: [float]
        """
        depth = 0
        previous = leaf
        leaf_pings = []
        # 1. Measure pings
        while previous:
            depth += 1
            pingtime = self.get_granular_ping(previous)
            previous = self.ancestry.get(previous, None)
            if pingtime is None:
                continue
            leaf_pings.append(pingtime)
        # 2. Make sure we get introductions from the current leaf
        if depth < self.max_edge_length:
            self.overlay.send_introduction_request(leaf)
        return leaf_pings

    def garbage_collect(self):
        """
        Clean up connections we no longer use:

         - Peers which have not made it into any edge
         - Peers in an edge which have gone offline

        :returns: None
        """
        all_peers = self.overlay.get_peers()
        if len(all_peers) > self.overlay.max_peers / 2 and time.time() - self.last_gc >= self.gc_delay:
            self.last_gc = time.time()

            # 1. Remove peers which have not made it into any edge
            my_peers = set(self.leaves) | set(self.ancestry.values())

            to_remove = [peer for peer in all_peers if peer not in my_peers]
            for peer in to_remove:
                self.overlay.network.remove_peer(peer)

            # 2. Remove peers which have gone offline
            remove_set = set(p for p in my_peers if p not in all_peers)
            for leaf in self.leaves[:]:
                is_leaf = True
                re_leaf = False
                next_node = None
                current = leaf
                while True:
                    previous = self.ancestry.get(current, None)

                    if current in remove_set:
                        if is_leaf:
                            re_leaf = True  # The next online node in the edge should become the new leaf
                            self.leaves.remove(current)
                        self.ancestry.pop(current, None)
                        if current in self.roots:
                            self.roots.remove(current)
                        if next_node and previous:
                            # We are in between two nodes, relink them
                            self.ancestry[next_node] = previous
                        elif next_node:
                            # We only have a next node, which means the current is the root and we should re-root
                            self.roots.append(next_node)
                            self.ancestry.pop(next_node, None)
                    else:
                        # We should not be removed, but we might have been appointed as a new leaf
                        if re_leaf:
                            self.leaves.append(current)
                            re_leaf = False
                        next_node = current

                    current = previous
                    is_leaf = False
                    if not previous:
                        break

    def take_step(self):
        """
        Perform an iteration of peer discovery:

        1. Ensure we have enough edges
        2. Grow the edges if needed
        3. Garbage collect unused peers

        :returns: None
        """
        with self.walk_lock:
            # 1. Pick peer introduced by bootstrap
            if len(self.roots) < self.max_roots:
                self.get_root_address()

            # 2. For each edge < MAX_EDGE_LENGTH: grow edge based on last peer on edge
            removed_leafs = []
            for leaf in self.leaves:
                # 2.b. Ensure each edge has ping times and candidates to grow
                leaf_pings = self.ensure_leaf_pings(leaf)

                # 3. On response: if MYKA allowed (<> MAX_SIMILARITY) add to edge
                self.check_extend_edge(leaf, leaf_pings, removed_leafs)

            # If we updated our leaf list, remove old leaves (which are now part of the ancestry tree)
            self.leaves = [leaf for leaf in self.leaves if leaf not in removed_leafs]

            # Update the overlay with the agreeable peers and garbage collect loose connections
            self.overlay.possible_peers = [p for p in list(self.ancestry.values()) + self.leaves[:]]
            self.garbage_collect()
