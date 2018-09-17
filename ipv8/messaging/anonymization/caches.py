from __future__ import absolute_import

import logging
import time

from ...requestcache import NumberCache, RandomNumberCache
from .tunnel import CIRCUIT_STATE_READY, PING_INTERVAL


class CircuitRequestCache(NumberCache):

    def __init__(self, community, circuit):
        super(CircuitRequestCache, self).__init__(community.request_cache, u"anon-circuit", circuit.circuit_id)
        self.tunnel_logger = logging.getLogger('TunnelLogger')
        self.community = community
        self.circuit = circuit
        self.should_forward = False

    def on_timeout(self):
        if self.circuit.state != CIRCUIT_STATE_READY:
            reason = 'timeout on CircuitRequestCache, state = %s, candidate = %s' % (
                self.circuit.state, self.circuit.peer.address)
            self.community.remove_circuit(self.number, reason)


class ExtendRequestCache(NumberCache):
    def __init__(self, community, to_circuit_id, from_circuit_id, peer, to_peer):
        super(ExtendRequestCache, self).__init__(community.request_cache, u"anon-circuit", to_circuit_id)
        self.community = community
        self.to_circuit_id = to_circuit_id
        self.from_circuit_id = from_circuit_id
        self.peer = peer
        self.to_peer = to_peer
        self.should_forward = True

    def on_timeout(self):
        to_circuit = self.community.circuits.get(self.to_circuit_id)
        if to_circuit and to_circuit.state != CIRCUIT_STATE_READY:
            self.community.remove_relay(self.to_circuit_id)


class CreatedRequestCache(NumberCache):

    def __init__(self, community, circuit_id, candidate, candidates):
        super(CreatedRequestCache, self).__init__(community.request_cache, u"anon-created", circuit_id)
        self.circuit_id = circuit_id
        self.candidate = candidate
        self.candidates = candidates

    def on_timeout(self):
        pass


class PingRequestCache(RandomNumberCache):

    def __init__(self, community, circuit):
        super(PingRequestCache, self).__init__(community.request_cache, u"ping")
        self.tunnel_logger = logging.getLogger('TunnelLogger')
        self.circuit = circuit
        self.community = community

    @property
    def timeout_delay(self):
        return PING_INTERVAL + 5

    def on_timeout(self):
        if self.circuit.last_incoming < time.time() - self.timeout_delay:
            self.tunnel_logger.info("PingRequestCache: no response on ping, circuit %d timed out",
                                    self.circuit.circuit_id)
            self.community.remove_circuit(self.circuit.circuit_id, 'ping timeout')

class IPRequestCache(RandomNumberCache):

    def __init__(self, community, circuit):
        super(IPRequestCache, self).__init__(community.request_cache, u"establish-intro")
        self.tunnel_logger = logging.getLogger('TunnelLogger')
        self.circuit = circuit
        self.community = community

    def on_timeout(self):
        self.tunnel_logger.info("IPRequestCache: no response on establish-intro (circuit %d)", self.circuit.circuit_id)
        self.community.remove_circuit(self.circuit.circuit_id, 'establish-intro timeout')


class RPRequestCache(RandomNumberCache):

    def __init__(self, community, rp):
        super(RPRequestCache, self).__init__(community.request_cache, u"establish-rendezvous")
        self.tunnel_logger = logging.getLogger('TunnelLogger')
        self.community = community
        self.rp = rp

    def on_timeout(self):
        self.tunnel_logger.info("RPRequestCache: no response on establish-rendezvous (circuit %d)",
                                self.rp.circuit.circuit_id)
        self.community.remove_circuit(self.rp.circuit.circuit_id, 'establish-rendezvous timeout')


class KeyRequestCache(RandomNumberCache):

    def __init__(self, community, circuit, sock_addr, info_hash):
        super(KeyRequestCache, self).__init__(community.request_cache, u"key-request")
        self.tunnel_logger = logging.getLogger('TunnelLogger')
        self.circuit = circuit
        self.sock_addr = sock_addr
        self.info_hash = info_hash
        self.community = community

    def on_timeout(self):
        self.tunnel_logger.info("KeyRequestCache: no response on key-request to %s",
                                self.sock_addr)
        if self.info_hash in self.community.infohash_pex:
            self.tunnel_logger.info("Remove peer %s from the peer exchange cache" % repr(self.sock_addr))
            peers = self.community.infohash_pex[self.info_hash]
            for peer in peers.copy():
                peer_sock, _ = peer
                if self.sock_addr == peer_sock:
                    self.community.infohash_pex[self.info_hash].remove(peer)


class DHTRequestCache(RandomNumberCache):

    def __init__(self, community, circuit, info_hash):
        super(DHTRequestCache, self).__init__(community.request_cache, u"dht-request")
        self.circuit = circuit
        self.info_hash = info_hash

    def on_timeout(self):
        pass


class KeyRelayCache(KeyRequestCache):

    def __init__(self, community, circuit, identifier, sock_addr, info_hash):
        super(KeyRelayCache, self).__init__(community, circuit, sock_addr, info_hash)
        self.identifier = identifier
        self.return_sock_addr = sock_addr

    def on_timeout(self):
        pass


class E2ERequestCache(RandomNumberCache):

    def __init__(self, community, info_hash, circuit, hop, sock_addr):
        super(E2ERequestCache, self).__init__(community.request_cache, u"e2e-request")
        self.circuit = circuit
        self.hop = hop
        self.info_hash = info_hash
        self.sock_addr = sock_addr

    def on_timeout(self):
        pass


class LinkRequestCache(RandomNumberCache):

    def __init__(self, community, circuit, info_hash):
        super(LinkRequestCache, self).__init__(community.request_cache, u"link-request")
        self.circuit = circuit
        self.info_hash = info_hash

    def on_timeout(self):
        pass
