from base64 import b64encode
from hashlib import sha1
from threading import RLock

from networkx import draw, Graph, circular_layout


class Network(object):

    def __init__(self):
        # All known IP:port addresses
        self._all_addresses = {}
        # All verified Peer objects (Peer.address must be in _all_addresses)
        self.verified_peers = []
        # The networkx graph containing the addresses and peers
        self.graph = Graph()
        self.graph_lock = RLock()
        # Peers we should not add to the network
        # For example, bootstrap peers
        self.blacklist = []
        # Excluded mids
        self.blacklist_mids = []

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
        if address in self.blacklist:
            self.add_verified_peer(peer)
            return

        self.graph_lock.acquire()
        if (address not in self._all_addresses) or (not self.graph.has_node(self._all_addresses[address])):
            # This is a new address, or our previous parent has been removed
            self._all_addresses[address] = b64encode(peer.mid)

        if not self.get_verified_by_address(address) and not self.graph.has_edge(self._all_addresses[address], address):
            # Don't remap already verified peers and don't add an edge which already exists.
            if address in self.graph.node and address not in self.graph.adj:
                del self.graph.node[address]
            self.graph.add_edge(b64encode(peer.mid), address, color='orange')
        self.graph_lock.release()

        self.add_verified_peer(peer)

    def discover_services(self, peer, services):
        """
        A peer has advertised some services he can use.

        :param peer: the peer to update the services for
        :param services: the list of services to register
        """
        self.graph_lock.acquire()
        if peer.public_key.key_to_bin() not in self.services_per_peer:
            self.services_per_peer[peer.public_key.key_to_bin()] = set(services)
        else:
            self.services_per_peer[peer.public_key.key_to_bin()] |= set(services)
        self.graph_lock.release()

    def add_verified_peer(self, peer):
        """
        The holepunching layer has a new peer for us.

        :param peer: the new peer
        """
        if peer.mid in self.blacklist_mids:
            return
        self.graph_lock.acquire()
        # This may just be an address update
        for known in self.verified_peers:
            if known.mid == peer.mid:
                known.address = peer.address
                self.graph_lock.release()
                return
        if peer.address in self._all_addresses and self.graph.has_node(peer.address):
            introducer = self._all_addresses[peer.address]
            self.graph.remove_node(peer.address)
            self.graph.add_node(b64encode(peer.mid))
            self.graph.add_edge(introducer, b64encode(peer.mid), color='green')
            if peer not in self.verified_peers:
                # This should always happen, unless someone edits the verified_peers dict directly.
                # This would be a programmer 'error', but we will allow it.
                self.verified_peers.append(peer)
        elif (peer.address not in self.blacklist):
            if peer.address not in self._all_addresses:
                self._all_addresses[peer.address] = ''
            if not self.graph.has_node(b64encode(peer.mid)):
                self.graph.add_node(b64encode(peer.mid))
            if peer not in self.verified_peers:
                self.verified_peers.append(peer)
        self.graph_lock.release()

    def register_service_provider(self, service_id, overlay):
        """
        Register an overlay to provide a certain service id.

        :param service_id: the name/id of the service
        :param overlay: the actual service
        """
        self.graph_lock.acquire()
        self.service_overlays[service_id] = overlay
        self.graph_lock.release()

    def get_peers_for_service(self, service_id):
        """
        Get peers which support a certain service.

        :param service_id: the service name/id to fetch peers for
        """
        out = []
        with self.graph_lock:
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
        with self.graph_lock:
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
                encoded_services_per_peer = {b64encode(sha1(k).digest()): v for k, v in
                                             self.services_per_peer.iteritems()}
                services = encoded_services_per_peer.get(b64mid_intro, [])
                if service_id in services:
                    new_out.append(address)
            out = new_out
        return out

    def get_verified_by_address(self, address):
        """
        Get a verified Peer by its IP address.

        :param address: the (IP, port) tuple to search for
        :return: the Peer object for this address or None
        """
        self.graph_lock.acquire()
        for i in range(len(self.verified_peers)):
            if self.verified_peers[i].address == address:
                out = self.verified_peers[i]
                self.graph_lock.release()
                return out
        self.graph_lock.release()

    def get_verified_by_public_key_bin(self, public_key_bin):
        """
        Get a verified Peer by its public key bin.

        :param public_key_bin: the string representation of the public key
        :return: the Peer object for this public_key_bin or None
        """
        self.graph_lock.acquire()
        for i in range(len(self.verified_peers)):
            if self.verified_peers[i].public_key.key_to_bin() == public_key_bin:
                out = self.verified_peers[i]
                self.graph_lock.release()
                return out
        self.graph_lock.release()

    def get_introductions_from(self, peer):
        """
        Get the addresses introduced to us by a certain peer.

        :param peer: the peer to get the introductions for
        :return: a list of the introduced addresses (ip, port)
        """
        with self.graph_lock:
            return [k for k, v in self._all_addresses.iteritems() if v == b64encode(peer.mid)]

    def remove_by_address(self, address):
        """
        Remove all walkable addresses and verified peers using a certain IP address.

        :param address: the (ip, port) address to remove
        """
        self.graph_lock.acquire()
        if address in self._all_addresses:
            del self._all_addresses[address]
        to_remove = []
        for i in range(len(self.verified_peers)):
            if self.verified_peers[i].address == address:
                to_remove.insert(0, i)
                graph_node = b64encode(self.verified_peers[i].mid)
                if self.graph.has_node(graph_node):
                    self.graph.remove_node(graph_node)
                key_bin = self.verified_peers[i].public_key.key_to_bin()
                if key_bin in self.services_per_peer:
                    del self.services_per_peer[key_bin]
        for index in to_remove:
            self.verified_peers.pop(index)
        if self.graph.has_node(address):
            self.graph.remove_node(address)
        self.graph_lock.release()

    def remove_peer(self, peer):
        """
        Remove a verified peer.

        :param peer: the Peer to remove
        """
        self.graph_lock.acquire()
        if peer.address in self._all_addresses:
            del self._all_addresses[peer.address]
        if peer in self.verified_peers:
            self.verified_peers.remove(peer)
        graph_node = b64encode(peer.mid)
        if self.graph.has_node(graph_node):
            self.graph.remove_node(graph_node)
        if self.graph.has_node(peer.address):
            self.graph.remove_node(peer.address)
        key_bin = peer.public_key.key_to_bin()
        if key_bin in self.services_per_peer:
            del self.services_per_peer[key_bin]
        self.graph_lock.release()

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
