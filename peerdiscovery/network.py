from base64 import b64encode
from networkx import draw, Graph, spring_layout, get_edge_attributes, circular_layout


class Network(object):

    def __init__(self):
        # All known IP:port addresses
        self._all_addresses = {}
        # All verified Peer objects (Peer.address must be in _all_addresses)
        self.verified_peers = []
        # The networkx graph containing the addresses and peers
        self.graph = Graph()
        # Peers we should not add to the network
        # For example, bootstrap peers
        self.blacklist = []

        # Map of advertised services (set) per peer
        self.services_per_peer = {}
        # Map of service identifiers to local overlays
        self.service_overlays = {}

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

    def discover_services(self, peer, services):
        """
        A peer has advertised some services he can use.

        :param peer: the peer to update the services for
        :param services: the list of services to register
        """
        if peer.public_key.key_to_bin() not in self.services_per_peer:
            self.services_per_peer[peer.public_key.key_to_bin()] = set(services)
        else:
            if set(services) != self.services_per_peer[peer.public_key.key_to_bin()]:
                self.services_per_peer[peer.public_key.key_to_bin()] |= set(services)

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

    def register_service_provider(self, service_id, overlay):
        """
        Register an overlay to provide a certain service id.

        :param service_id: the name/id of the service
        :param overlay: the actual service
        """
        self.service_overlays[service_id] = overlay

    def get_peers_for_service(self, service_id):
        """
        Get peers which support a certain service.

        :param service_id: the service name/id to fetch peers for
        """
        out = []
        for peer in self.verified_peers:
            key_bin = peer.public_key.key_to_bin()
            if key_bin in self.services_per_peer:
                if service_id in self.services_per_peer[key_bin]:
                    out.append(peer)
        return out

    def get_services_for_peer(self, peer):
        """
        Get the known services supported by a peer.

        :param peer: the peer to check services for
        """
        return self.services_per_peer.get(peer.public_key.key_to_bin(), set())

    def get_walkable_addresses(self, service_id=None):
        """
        Get all addresses ready to be walked to.

        :param service_id: the service_id to filter on
        """
        verified = [peer.address for peer in self.verified_peers]
        out = list(set(self._all_addresses.keys()) - set(verified))
        if service_id:
            new_out = []
            for address in out:
                b64mid_intro = self._all_addresses[address]
                intro_peer = [peer for peer in self.verified_peers if b64encode(peer.mid) == b64mid_intro]
                if intro_peer and self.get_services_for_peer(intro_peer[0]):
                    new_out.append(address)
            out = new_out
        return out

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
                key_bin = self.verified_peers[i].public_key.key_to_bin()
                if key_bin in self.services_per_peer:
                    del self.services_per_peer[key_bin]
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
        key_bin = peer.public_key.key_to_bin()
        if key_bin in self.services_per_peer:
            del self.services_per_peer[key_bin]

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
