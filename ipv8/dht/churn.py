from time import time

from .routing import Node
from ..peer import Peer
from ..peerdiscovery.discovery import DiscoveryStrategy


class PingChurn(DiscoveryStrategy):

    def __init__(self, overlay, ping_interval=25):
        super(PingChurn, self).__init__(overlay)
        self.ping_interval = ping_interval

    def take_step(self):
        with self.walk_lock:
            # Nothing is happening yet, skip this step
            if not self.overlay.routing_tables:
                return

            for routing_table in self.overlay.routing_tables.values():
                for node in routing_table.remove_bad_nodes():
                    self.overlay.network.remove_peer(node)

            for peer in self.overlay.get_peers():
                if peer.address in self.overlay.network.blacklist:
                    continue

                node = Node(peer.key, peer.address)
                routing_table = self.overlay.get_routing_table(node)
                if not routing_table.has(node.id) and not routing_table.add(node):
                    self.overlay.network.remove_peer(peer)

            for routing_table in self.overlay.routing_tables.values():
                for bucket in routing_table.trie.values():
                    for node in bucket.nodes.values():
                        if node not in self.overlay.get_peers():
                            peer = Peer(node.key, node.address)
                            self.overlay.network.add_verified_peer(peer)
                            self.overlay.network.discover_services(peer, [self.overlay.community_id])

            now = time()
            for routing_table in self.overlay.routing_tables.values():
                for bucket in routing_table.trie.values():
                    for node in bucket.nodes.values():
                        if node.last_ping_sent + self.ping_interval <= now:
                            self.overlay.ping(node)
