import logging

from requestcache import NumberCache, RandomNumberCache
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
                self.circuit.state, self.circuit.sock_addr)
            self.community.remove_circuit(self.number, reason)


class ExtendRequestCache(NumberCache):
    def __init__(self, community, to_circuit_id, from_circuit_id, candidate_sock_addr, candidate_mid, to_candidate_sock_addr, to_candidate_mid):
        super(ExtendRequestCache, self).__init__(community.request_cache, u"anon-circuit", to_circuit_id)
        self.to_circuit_id = to_circuit_id
        self.from_circuit_id = from_circuit_id
        self.candidate_sock_addr = candidate_sock_addr
        self.candidate_mid = candidate_mid
        self.to_candidate_sock_addr = to_candidate_sock_addr
        self.to_candidate_mid = to_candidate_mid
        self.should_forward = True

    def on_timeout(self):
        pass


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
