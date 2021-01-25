import logging
from collections import OrderedDict, namedtuple
from threading import RLock
from typing import Dict, Iterable, List, Optional, Set

from ..messaging.serialization import default_serializer
from ..types import Address, Overlay, Peer


MID = bytes
PublicKeyMat = bytes
Service = bytes
ServiceSet = Set[Service]
WalkableAddress = namedtuple('WalkableAddress', ['introduced_by', 'services', 'new_style'])


class Network(object):

    def __init__(self):
        self._all_addresses: Dict[Address, WalkableAddress] = {}
        '''All known IP:port addresses, mapped to (introduction peer, services, new_style).'''

        self.verified_peers: Set[Peer] = set()
        '''All verified Peer objects (Peer.address must be in _all_addresses).'''

        self.verified_by_public_key_bin: Dict[PublicKeyMat, Peer] = {}
        '''Map of known public keys to Peer objects.'''

        self.graph_lock = RLock()
        '''Lock for all updates of the peer pool.'''

        self.blacklist: List[Address] = []
        '''Peers we should not add to the network (e.g., bootstrap peers), by address.'''

        self.blacklist_mids: List[MID] = []
        '''Peers we should not add to the network (e.g., bootstrap peers), by mid.'''

        self.services_per_peer: Dict[PublicKeyMat, ServiceSet] = {}
        '''Map of advertised services (set) per peer.'''

        self.service_overlays: Dict[Service, Overlay] = {}
        '''Map of service identifiers to local overlays.'''

        self.reverse_ip_cache_size = 500
        self.reverse_ip_lookup = OrderedDict()
        '''Cache of IP:port -> Peer. This is a cache rather than a normal dictionary (the addresses of a peer are
        temporal and can grow infinitely): we rotate out old information to avoid a memory leak.'''

        self.reverse_intro_cache_size = 500
        self.reverse_intro_lookup = OrderedDict()
        '''Map of Peer -> [IP:port], reversing the information from _all_addresses. This is a cache rather than a
        normal dictionary (the addresses of a peer are temporal and can grow infinitely): we rotate out old
        information to avoid a memory leak.'''

        self.reverse_service_cache_size = 500
        self.reverse_service_lookup = OrderedDict()
        '''Cache of service_id -> [Peer]. This is a cache rather than a normal dictionary (the services of a peer may
        be temporal and can grow infinitely): we rotate out old information to avoid a memory leak.'''

    def is_new_style(self, address: Address) -> bool:
        """
        Check if an address supports new-style introduction requests and responses.

        :param address: the address to check for.
        :returns: True iff the address is both known and known to support new-style introductions.
        """
        return (self._all_addresses.get(address) or WalkableAddress(b'', None, False)).new_style

    def discover_address(self,
                         peer: Peer,
                         address: Address,
                         service: Optional[Service] = None,
                         new_style: bool = False) -> None:
        """
        A peer has introduced us to another IP address.

        :param peer: the peer that performed the introduction.
        :param address: the introduced address.
        :param service: the service through which we discovered the peer.
        :param new_style: the introduced address uses new introduction logic.
        """
        if address in self.blacklist:
            self.add_verified_peer(peer)
            return

        with self.graph_lock:
            if ((address not in self._all_addresses)
                    or (self._all_addresses[address].introduced_by not in self.verified_by_public_key_bin)):
                # This is a new address, or our previous parent has been removed
                self._all_addresses[address] = WalkableAddress(peer.public_key.key_to_bin(), service, new_style)
                intro_cache = self.reverse_intro_lookup.get(peer, None)
                if intro_cache:
                    intro_cache.append(address)
                else:
                    self.reverse_intro_lookup[peer] = [address]

            self.add_verified_peer(peer)

    def discover_services(self, peer: Peer, services: Iterable) -> None:
        """
        A peer has advertised some services he can use.

        :param peer: the peer to update the services for.
        :param services: the list of services to register.
        """
        with self.graph_lock:
            key_material = peer.public_key.key_to_bin()
            if key_material not in self.services_per_peer:
                self.services_per_peer[key_material] = set(services)
            else:
                self.services_per_peer[key_material] |= set(services)
            for service in services:
                service_cache = self.reverse_service_lookup.get(service, [])
                # Ensure that the peer instance in the cache is the same one as in verified_peers.
                if peer in service_cache:
                    service_cache.remove(peer)
                service_cache.append(self.verified_by_public_key_bin.get(key_material, peer))
                self.reverse_service_lookup[service] = service_cache

    def add_verified_peer(self, peer: Peer) -> None:
        """
        The holepunching layer has a new peer for us.

        :param peer: the new peer.
        """
        if peer.mid in self.blacklist_mids:
            return
        with self.graph_lock:
            # This may just be an address update
            known = self.verified_by_public_key_bin.get(peer.public_key.key_to_bin(), None)
            if known:
                known.addresses.update(peer.addresses)
                return
            if any(address in self._all_addresses for address in peer.addresses.values()):
                if peer not in self.verified_peers:
                    # This should always happen, unless someone edits the verified_peers dict directly.
                    # This would be a programmer 'error', but we will allow it.
                    self.verified_peers.add(peer)
                    self.verified_by_public_key_bin[peer.public_key.key_to_bin()] = peer
            elif all(address not in self.blacklist for address in peer.addresses.values()):
                for address in peer.addresses.values():
                    if address not in self._all_addresses:
                        self._all_addresses[address] = WalkableAddress(b'', None, False)
                if peer not in self.verified_peers:
                    self.verified_peers.add(peer)
                    self.verified_by_public_key_bin[peer.public_key.key_to_bin()] = peer

    def register_service_provider(self, service_id: Service, overlay: Overlay) -> None:
        """
        Register an overlay to provide a certain service id.

        :param service_id: the name/id of the service.
        :param overlay: the actual service.
        """
        with self.graph_lock:
            self.service_overlays[service_id] = overlay

    def get_peers_for_service(self, service_id: Service) -> List[Peer]:
        """
        Get peers which support a certain service.

        :param service_id: the service name/id to fetch peers for.
        """
        out = []
        service_cache = self.reverse_service_lookup.pop(service_id, None)
        if service_cache is None:
            with self.graph_lock:
                for peer in self.verified_peers:
                    key_material = peer.public_key.key_to_bin()
                    if service_id in self.services_per_peer.get(key_material, []):
                        out.append(peer)
        else:
            out = [peer for peer in service_cache if
                   peer in self.verified_peers
                   and service_id in self.services_per_peer.get(peer.public_key.key_to_bin(), [])]
        self.reverse_service_lookup[service_id] = out
        if len(self.reverse_service_lookup) > self.reverse_service_cache_size:
            self.reverse_service_lookup.popitem(False)  # Pop the oldest cache entry
        return out

    def get_services_for_peer(self, peer):
        """
        Get the known services supported by a peer.

        :param peer: the peer to check services for.
        """
        with self.graph_lock:
            return self.services_per_peer.get(peer.public_key.key_to_bin(), set())

    def get_walkable_addresses(self,
                               service_id: Optional[Service] = None,
                               old_style: bool = False) -> List[Address]:
        """
        Get all addresses ready to be walked to.

        :param service_id: the service_id to filter on.
        :param old_style: only return addresses that are not new-style.
        """
        with self.graph_lock:
            known = self.get_peers_for_service(service_id) if service_id else self.verified_peers
            verified: List[Address] = []
            for peer in known:
                verified.extend(peer.addresses.values())
            out = list(set(self._all_addresses.keys()) - set(verified))
            if service_id:
                new_out = []
                for address in out:
                    intro_peer, service, new_style = self._all_addresses[address]
                    if old_style and new_style:
                        continue
                    services = self.services_per_peer.get(intro_peer, set([]))
                    if service:
                        services.add(service)
                    if service_id in services:
                        new_out.append(address)
                out = new_out
            return out

    def get_verified_by_address(self, address: Address) -> Peer:
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
                    if address in p.addresses.values():
                        peer = p
                        self.reverse_ip_lookup[address] = peer
                        if len(self.reverse_ip_lookup) > self.reverse_ip_cache_size:
                            self.reverse_ip_lookup.popitem(False)  # Pop the oldest cache entry
                        break
            else:
                # Refresh the peer in the cache (by popping first, it is now on top of the stack again)
                self.reverse_ip_lookup[address] = peer
        return peer

    def get_verified_by_public_key_bin(self, public_key_bin: PublicKeyMat) -> Optional[Peer]:
        """
        Get a verified Peer by its public key bin.
        :param public_key_bin: the string representation of the public key
        :return: the Peer object for this public_key_bin or None
        """
        return self.verified_by_public_key_bin.get(public_key_bin)

    def get_introductions_from(self, peer: Peer) -> List[Address]:
        """
        Get the addresses introduced to us by a certain peer.

        :param peer: the peer to get the introductions for
        :return: a list of the introduced addresses (ip, port)
        """
        introductions = self.reverse_intro_lookup.get(peer, None)
        if introductions is None:
            with self.graph_lock:
                introductions = [k for k, v in self._all_addresses.items()
                                 if v.introduced_by == peer.public_key.key_to_bin()]
                self.reverse_intro_lookup[peer] = introductions
                if len(self.reverse_intro_lookup) > self.reverse_intro_cache_size:
                    self.reverse_intro_lookup.popitem(False)  # Pop the oldest cache entry
        return introductions

    def remove_by_address(self, address: Address) -> None:
        """
        Remove all walkable addresses and verified peers using a certain IP address.

        :param address: the (ip, port) address to remove
        """
        with self.graph_lock:
            self._all_addresses.pop(address, None)
            self.reverse_service_lookup.pop(address, None)
            # Note that the services_per_peer will never be 0, we abuse the lazy `or` to pop the peers from
            # the services_per_peer mapping if they are no longer included. This is fast.
            self.verified_peers = {peer for peer in self.verified_peers
                                   if address not in peer.addresses.values()
                                   or self.services_per_peer.pop(peer.public_key.key_to_bin(), None) == 0}

    def remove_peer(self, peer: Peer) -> None:
        """
        Remove a verified peer.

        :param peer: the Peer to remove
        """
        with self.graph_lock:
            for address in peer.addresses.values():
                self._all_addresses.pop(address, None)
                self.reverse_service_lookup.pop(address, None)
            if peer in self.verified_peers:
                self.verified_peers.remove(peer)
            self.verified_by_public_key_bin.pop(peer.public_key.key_to_bin(), None)
            self.services_per_peer.pop(peer.public_key.key_to_bin(), None)

    def snapshot(self) -> bytes:
        """
        Get a snapshot of all verified peers.

        :return: the serialization (bytes) of all verified peers
        """
        with self.graph_lock:
            out = b""
            for peer in self.verified_peers:
                if peer.address and peer.address != ('0.0.0.0', 0):
                    out += default_serializer.pack('address', peer.address)
            return out

    def load_snapshot(self, snapshot: bytes) -> None:
        """
        Load a snapshot into the walkable addresses.

        This method will prefer returning no peers over throwing an Exception.

        :param snapshot: the snapshot (created by snapshot())
        """
        snaplen = len(snapshot)
        offset = 0
        with self.graph_lock:
            while offset < snaplen:
                previous_offset = offset
                try:
                    address, offset = default_serializer.unpack('address', snapshot, offset)
                    self._all_addresses[address] = WalkableAddress(b'', None, False)
                except Exception:  # pylint: disable=W0703
                    if offset <= previous_offset:
                        # We got stuck, or even went back in time.
                        logging.error("Snapshot loading got stuck! Aborting snapshot load.")
                        break
                    logging.warning("Snapshot failed on entry, skipping %s!", repr(address))
