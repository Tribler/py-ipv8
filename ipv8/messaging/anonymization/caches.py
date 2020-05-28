import logging
from asyncio import Future

from .tunnel import CIRCUIT_STATE_CLOSING, CIRCUIT_STATE_READY
from ...requestcache import NumberCache, RandomNumberCache


class CreateRequestCache(NumberCache):
    """
    Used to track outstanding create messages
    """
    def __init__(self, community, to_circuit_id, from_circuit_id, peer, to_peer):
        super(CreateRequestCache, self).__init__(community.request_cache, u"create", to_circuit_id)
        self.community = community
        self.to_circuit_id = to_circuit_id
        self.from_circuit_id = from_circuit_id
        self.peer = peer
        self.to_peer = to_peer

    def on_timeout(self):
        to_circuit = self.community.circuits.get(self.to_circuit_id)
        if to_circuit and to_circuit.state != CIRCUIT_STATE_READY:
            self.community.remove_relay(self.to_circuit_id)


class CreatedRequestCache(NumberCache):
    """
    Used to track outstanding created messages
    """
    def __init__(self, community, circuit_id, candidate, candidates, timeout):
        super(CreatedRequestCache, self).__init__(community.request_cache, u"created", circuit_id)
        self.circuit_id = circuit_id
        self.candidate = candidate
        self.candidates = candidates
        self.timeout = timeout

    @property
    def timeout_delay(self):
        return float(self.timeout)

    def on_timeout(self):
        pass


class RetryRequestCache(NumberCache):
    """
    Used to track adding additional hops to the circuit.
    """
    def __init__(self, community, circuit, candidates, max_tries, retry_func, timeout):
        super(RetryRequestCache, self).__init__(community.request_cache, u"retry", circuit.circuit_id)
        self.community = community
        self.circuit = circuit
        self.candidates = candidates
        self.max_tries = max_tries
        self.retry_func = retry_func
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    @property
    def timeout_delay(self):
        return float(self.timeout)

    def on_timeout(self):
        if self.circuit.state == CIRCUIT_STATE_CLOSING:
            return
        if not self.candidates or self.max_tries < 1:
            reason = f'timeout, {self.max_tries} tries left'
            self.community.remove_circuit(self.circuit.circuit_id, reason)
            return

        async def retry_later():
            try:
                self.retry_func(self.circuit, self.candidates, self.max_tries)
            except Exception as e:
                self.logger.info("Error encountered during 'on_timeout' (error: %s)", e)
        self.community.request_cache.register_anonymous_task("retry-later", retry_later, delay=0)


class PingRequestCache(RandomNumberCache):

    def __init__(self, community, circuit):
        super(PingRequestCache, self).__init__(community.request_cache, u"ping")

    def on_timeout(self):
        pass


class IPRequestCache(RandomNumberCache):

    def __init__(self, community, circuit):
        super(IPRequestCache, self).__init__(community.request_cache, u"establish-intro")
        self.logger = logging.getLogger(__name__)
        self.circuit = circuit
        self.community = community

    def on_timeout(self):
        self.logger.info("IPRequestCache: no response on establish-intro (circuit %d)", self.circuit.circuit_id)
        self.community.remove_circuit(self.circuit.circuit_id, 'establish-intro timeout')


class RPRequestCache(RandomNumberCache):

    def __init__(self, community, rp):
        super(RPRequestCache, self).__init__(community.request_cache, u"establish-rendezvous")
        self.logger = logging.getLogger(__name__)
        self.community = community
        self.rp = rp

    def on_timeout(self):
        self.logger.info("RPRequestCache: no response on establish-rendezvous (circuit %d)",
                         self.rp.circuit.circuit_id)
        self.rp.ready.set_result(None)
        self.community.remove_circuit(self.rp.circuit.circuit_id, 'establish-rendezvous timeout')


class PeersRequestCache(RandomNumberCache):

    def __init__(self, community, circuit, info_hash):
        super(PeersRequestCache, self).__init__(community.request_cache, u"peers-request")
        self.circuit = circuit
        self.info_hash = info_hash
        self.future = Future()

    def on_timeout(self):
        self.future.set_exception(RuntimeError("Peers request timeout"))


class E2ERequestCache(RandomNumberCache):

    def __init__(self, community, info_hash, hop, intro_point):
        super(E2ERequestCache, self).__init__(community.request_cache, u"e2e-request")
        self.community = community
        self.info_hash = info_hash
        self.hop = hop
        self.intro_point = intro_point

    def on_timeout(self):
        swarm = self.community.swarms.get(self.info_hash)
        if swarm:
            # This introduction point did not respond in time, so drop it.
            swarm.remove_intro_point(self.intro_point)


class LinkRequestCache(RandomNumberCache):

    def __init__(self, community, circuit, info_hash, hs_session_keys):
        super(LinkRequestCache, self).__init__(community.request_cache, u"link-request")
        self.circuit = circuit
        self.info_hash = info_hash
        self.hs_session_keys = hs_session_keys

    def on_timeout(self):
        pass
