from collections import OrderedDict
from socket import inet_aton, inet_ntoa
from struct import pack, unpack
from threading import RLock

from ..util import cast_to_chr


class Network(object):

    def __init__(self):
        # All known IP:port addresses, mapped to (introduction peer, services)
        self._all_addresses = {}
        # All verified Peer objects (Peer.address must be in _all_addresses)
        self.verified_peers = set()
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

        # Cache of IP:port -> Peer
        self.reverse_ip_lookup = OrderedDict()
        self.reverse_ip_cache_size = 500

        # Cache of Peer -> [IP:port]
        self.reverse_intro_lookup = OrderedDict()
        self.reverse_intro_cache_size = 500

        # Cache of service_id -> [Peer]
        self.reverse_service_lookup = OrderedDict()
        self.reverse_service_cache_size = 500

    def discover_address(self, peer, address, service=None):
        """
        A peer has introduced us to another IP address.

        :param peer: the peer that performed the introduction
        :param address: the introduced address
        :param service: the service through which we discovered the peer
        """
        if address in self.blacklist:
            self.add_verified_peer(peer)
            return

        with self.graph_lock:
            if ((address not in self._all_addresses)
                    or (self._all_addresses[address][0] not in [p.mid for p in self.verified_peers])):
                # This is a new address, or our previous parent has been removed
                self._all_addresses[address] = (peer.mid, service)
                intro_cache = self.reverse_intro_lookup.get(peer, None)
                if intro_cache:
                    intro_cache.append(address)

            self.add_verified_peer(peer)

    def discover_services(self, peer, services):
        """
        A peer has advertised some services he can use.

        :param peer: the peer to update the services for
        :param services: the list of services to register
        """
        with self.graph_lock:
            if peer.mid not in self.services_per_peer:
                self.services_per_peer[peer.mid] = set(services)
            else:
                self.services_per_peer[peer.mid] |= set(services)
            for service in services:
                service_cache = self.reverse_service_lookup.get(service, [])
                self.reverse_service_lookup[service] = list(set(service_cache + [peer]))

    def add_verified_peer(self, peer):
        """
        The holepunching layer has a new peer for us.

        :param peer: the new peer
        """
        if peer.mid in self.blacklist_mids:
            return
        with self.graph_lock:
            # This may just be an address update
            for known in self.verified_peers:
                if known.mid == peer.mid:
                    known.address = peer.address
                    return
            if peer.address in self._all_addresses:
                if peer not in self.verified_peers:
                    # This should always happen, unless someone edits the verified_peers dict directly.
                    # This would be a programmer 'error', but we will allow it.
                    self.verified_peers.add(peer)
            elif peer.address not in self.blacklist:
                if peer.address not in self._all_addresses:
                    self._all_addresses[peer.address] = ('', None)
                if peer not in self.verified_peers:
                    self.verified_peers.add(peer)

    def register_service_provider(self, service_id, overlay):
        """
        Register an overlay to provide a certain service id.

        :param service_id: the name/id of the service
        :param overlay: the actual service
        """
        with self.graph_lock:
            self.service_overlays[service_id] = overlay

    def get_peers_for_service(self, service_id):
        """
        Get peers which support a certain service.

        :param service_id: the service name/id to fetch peers for
        """
        out = []
        service_cache = self.reverse_service_lookup.pop(service_id, None)
        if service_cache is None:
            with self.graph_lock:
                for peer in self.verified_peers:
                    if peer.mid in self.services_per_peer:
                        if service_id in self.services_per_peer[peer.mid]:
                            out.append(peer)
        else:
            out = [peer for peer in service_cache if
                   peer in self.verified_peers and service_id in self.services_per_peer.get(peer.mid, [])]
        self.reverse_service_lookup[service_id] = out
        if len(self.reverse_service_lookup) > self.reverse_service_cache_size:
            self.reverse_service_lookup.popitem(False)  # Pop the oldest cache entry
        return out

    def get_services_for_peer(self, peer):
        """
        Get the known services supported by a peer.

        :param peer: the peer to check services for
        """
        with self.graph_lock:
            return self.services_per_peer.get(peer.mid, set())

    def get_walkable_addresses(self, service_id=None):
        """
        Get all addresses ready to be walked to.

        :param service_id: the service_id to filter on
        """
        with self.graph_lock:
            known = self.get_peers_for_service(service_id) if service_id else self.verified_peers
            verified = [peer.address for peer in known]
            out = list(set(self._all_addresses.keys()) - set(verified))
            if service_id:
                new_out = []
                for address in out:
                    intro_peer, service = self._all_addresses[address]
                    services = self.services_per_peer.get(intro_peer, set([]))
                    if service:
                        services.add(service)
                    if service_id in services:
                        new_out.append(address)
                out = new_out
            return out

    def get_verified_by_address(self, address):
        """
        Get a verified Peer by its IP address.

        If multiple Peers use the same IP address, this method returns only one of these peers.

        :param address: the (IP, port) tuple to search for
        :return: the Peer object for this address or None
        """
        with self.graph_lock:
            peer = self.reverse_ip_lookup.pop(address, None)
            if not peer:
                for p in self.verified_peers:
                    if p.address == address:
                        peer = p
                        self.reverse_ip_lookup[peer.address] = peer
                        if len(self.reverse_ip_lookup) > self.reverse_ip_cache_size:
                            self.reverse_ip_lookup.popitem(False)  # Pop the oldest cache entry
                        break
            else:
                # Refresh the peer in the cache (by popping first, it is now on top of the stack again)
                self.reverse_ip_lookup[peer.address] = peer
        return peer

    def get_verified_by_public_key_bin(self, public_key_bin):
        """
        Get a verified Peer by its public key bin.

        :param public_key_bin: the string representation of the public key
        :return: the Peer object for this public_key_bin or None
        """
        with self.graph_lock:
            for p in self.verified_peers:
                if p.public_key.key_to_bin() == public_key_bin:
                    return p

    def get_introductions_from(self, peer):
        """
        Get the addresses introduced to us by a certain peer.

        :param peer: the peer to get the introductions for
        :return: a list of the introduced addresses (ip, port)
        """
        introductions = self.reverse_intro_lookup.get(peer, None)
        if introductions is None:
            with self.graph_lock:
                introductions = [k for k, v in self._all_addresses.items() if v[0] == peer.mid]
                self.reverse_intro_lookup[peer] = introductions
                if len(self.reverse_intro_lookup) > self.reverse_intro_cache_size:
                    self.reverse_intro_lookup.popitem(False)  # Pop the oldest cache entry
        return introductions

    def remove_by_address(self, address):
        """
        Remove all walkable addresses and verified peers using a certain IP address.

        :param address: the (ip, port) address to remove
        """
        with self.graph_lock:
            self._all_addresses.pop(address, None)
            # Note that the services_per_peer will never be 0, we abuse the lazy `or` to pop the peers from
            # the services_per_peer mapping if they are no longer included. This is fast.
            self.verified_peers = {peer for peer in self.verified_peers
                                   if peer.address != address or self.services_per_peer.pop(peer.mid, None) == 0}

    def remove_peer(self, peer):
        """
        Remove a verified peer.

        :param peer: the Peer to remove
        """
        with self.graph_lock:
            self._all_addresses.pop(peer.address, None)
            if peer in self.verified_peers:
                self.verified_peers.remove(peer)
            self.services_per_peer.pop(peer.mid, None)

    def snapshot(self):
        """
        Get a snapshot of all verified peers.

        :return: the serialization (str) of all verified peers
        """
        with self.graph_lock:
            out = b""
            for peer in self.verified_peers:
                if peer.address and peer.address != ('0.0.0.0', 0):
                    out += inet_aton(cast_to_chr(peer.address[0]) if isinstance(peer.address[0], bytes)
                                     else peer.address[0]) + pack(">H", peer.address[1])
            return out

    def load_snapshot(self, snapshot):
        """
        Load a snapshot into the walkable addresses.

        :param snapshot: the snapshot (created by snapshot())
        """
        snaplen = len(snapshot)
        if (snaplen % 6) != 0:
            import logging
            logging.error("Snapshot has invalid length! Aborting snapshot load.")
            return
        with self.graph_lock:
            for i in range(0, snaplen, 6):
                sub = snapshot[i:i + 6]
                ip = inet_ntoa(sub[0:4])
                port = unpack(">H", sub[4:])[0]
                self._all_addresses[(ip, port)] = ('', None)
