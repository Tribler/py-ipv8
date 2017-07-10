from base64 import b64encode
from networkx import draw, Graph, spring_layout, get_edge_attributes, circular_layout


class Network(object):

    def __init__(self):
        self._all_addresses = {}
        self.verified_peers = []
        self.graph = Graph()
        self.blacklist = []

    def discover_address(self, peer, address):
        """
        A peer has introduced us to another IP address.

        :param peer: the peer that performed the introduction
        :param address: the introduced address
        """
        if (address in self._all_addresses) or (address in self.blacklist):
            return

        self._all_addresses[address] = b64encode(peer.mid)

        self.graph.add_edge(b64encode(peer.mid), address, color='orange')

        if peer not in self.verified_peers:
            self.verified_peers.append(peer)

    def add_verified_peer(self, peer):
        """
        The holepunching layer has a new peer for us.

        :param peer: the new peer
        """
        if peer.address in self._all_addresses and self.graph.has_node(peer.address):
            introducer = self._all_addresses[peer.address]
            self.graph.remove_node(peer.address)
            self.graph.add_node(b64encode(peer.mid))
            self.graph.add_edge(introducer, b64encode(peer.mid), color='green')
            if peer not in self.verified_peers:
                self.verified_peers.append(peer)
        elif (peer.address not in self.blacklist) and (not self.graph.has_node(b64encode(peer.mid))):
            self.graph.add_node(b64encode(peer.mid))
            if peer not in self.verified_peers:
                self.verified_peers.append(peer)

    def get_walkable_addresses(self):
        """
        Get all addresses ready to be walked to.
        """
        verified = [peer.address for peer in self.verified_peers]
        return list(set(self._all_addresses.keys()) - set(verified))

    def get_verified_by_address(self, address):
        """
        Get a verified Peer by its IP address.

        :param address: the (IP, port) tuple to search for
        :return: the Peer object for this address or None
        """
        for i in range(len(self.verified_peers)):
            if self.verified_peers[i].address == address:
                return self.verified_peers[i]

    def get_introductions_from(self, peer):
        """
        Get the addresses introduced to us by a certain peer.

        :param peer: the peer to get the introductions for
        :return: a list of the introduced addresses (ip, port)
        """
        return [k for k, v in self._all_addresses.iteritems() if v == b64encode(peer.mid)]

    def remove_by_address(self, address):
        """
        Remove all walkable addresses and verified peers using a certain IP address.

        :param address: the (ip, port) address to remove
        """
        if address in self._all_addresses:
            del self._all_addresses[address]
        to_remove = []
        for i in range(len(self.verified_peers)):
            if self.verified_peers[i].address == address:
                to_remove.insert(0, i)
        for index in to_remove:
            self.verified_peers.pop(index)

    def remove_peer(self, peer):
        """
        Remove a verified peer.

        :param peer: the Peer to remove
        """
        if peer.address in self._all_addresses:
            del self._all_addresses[peer.address]
        if peer in self.verified_peers:
            self.verified_peers.remove(peer)

    def draw(self, filename="network_view.png"):
        """
        Draw this graph to a file, for debugging.
        """
        import matplotlib.pyplot as plt
        plt.clf()
        pos = circular_layout(self.graph)
        draw(self.graph, pos, with_labels=False, arrows=False, hold=False,
             edge_color=[self.graph[u][v]['color'] for u,v in self.graph.edges()],
             node_color=['orange' if v in self._all_addresses else 'green' for v in self.graph.nodes()])
        plt.savefig(filename)
