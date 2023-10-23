from __future__ import annotations

import logging
import secrets
import time
from asyncio import Future
from typing import TYPE_CHECKING, Callable

from ...requestcache import NumberCacheWithName, RandomNumberCacheWithName
from .tunnel import CIRCUIT_STATE_CLOSING

if TYPE_CHECKING:
    from ...types import Peer
    from .community import TunnelCommunity
    from .crypto import SessionKeys
    from .hidden_services import HiddenTunnelCommunity
    from .tunnel import Circuit, Hop, IntroductionPoint, RendezvousPoint


class CreateRequestCache(RandomNumberCacheWithName):
    """
    Used to track outstanding create messages.
    """

    name = "create"

    def __init__(self, community: TunnelCommunity, identifier: int, to_circuit_id: int,  # noqa: PLR0913
                 from_circuit_id: int, peer: Peer, to_peer: Peer) -> None:
        """
        Create a new cache.
        """
        super().__init__(community.request_cache, self.name)
        self.community = community
        self.extend_identifier = identifier
        self.to_circuit_id = to_circuit_id
        self.from_circuit_id = from_circuit_id
        self.peer = peer
        self.to_peer = to_peer

    def on_timeout(self) -> None:
        """
        We don't need to do anything on timeout.
        """


class CreatedRequestCache(NumberCacheWithName):
    """
    Used to track outstanding created messages.
    """

    name = "created"

    def __init__(self, community: TunnelCommunity, circuit_id: int, candidate: Peer,
                 candidates: dict[bytes, Peer], timeout: float) -> None:
        """
        Create a new cache.
        """
        super().__init__(community.request_cache, self.name, circuit_id)
        self.circuit_id = circuit_id
        self.candidate = candidate
        self.candidates = candidates
        self.timeout = timeout

    @property
    def timeout_delay(self) -> float:
        """
        The configurable timeout that was set.
        """
        return float(self.timeout)

    def on_timeout(self) -> None:
        """
        We don't need to do anything on timeout.
        """


class RetryRequestCache(NumberCacheWithName):
    """
    Used to track adding additional hops to the circuit.
    """

    name = "retry"

    def __init__(self, community: TunnelCommunity, circuit: Circuit,  # noqa: PLR0913
                 candidates: list[bytes] | list[Peer], max_tries: int,
                 retry_func: Callable[[Circuit, list[bytes], int], None] | Callable[[Circuit, list[Peer], int], None],
                 timeout: float) -> None:
        """
        Create the cache.
        """
        super().__init__(community.request_cache, self.name, circuit.circuit_id)
        self.community = community
        self.circuit = circuit
        self.packet_identifier = secrets.randbelow(2**16)
        self.candidates = candidates
        self.max_tries = max_tries
        self.retry_func = retry_func
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    @property
    def timeout_delay(self) -> float:
        """
        The configurable timeout that was set.
        """
        return float(self.timeout)

    def on_timeout(self) -> None:
        """
        Retry until we run out of candidates. Otherwise, remove the circuit.
        """
        if self.circuit.state == CIRCUIT_STATE_CLOSING:
            return
        if not self.candidates or self.max_tries < 1:
            reason = f'timeout, {self.max_tries} tries left'
            self.community.remove_circuit(self.circuit.circuit_id, reason)
            return

        async def retry_later() -> None:
            try:
                self.retry_func(self.circuit, self.candidates, self.max_tries)  # type: ignore[arg-type]
            except Exception as e:
                self.logger.info("Error encountered during 'on_timeout' (error: %s)", e)
        self.community.request_cache.register_anonymous_task("retry-later", retry_later, delay=0)


class PingRequestCache(RandomNumberCacheWithName):
    """
    Manage a ping to a peer.
    """

    name = "ping"

    def __init__(self, community: TunnelCommunity) -> None:
        """
        Create a new cache.
        """
        super().__init__(community.request_cache, self.name)

    def on_timeout(self) -> None:
        """
        We don't need to do anything on timeout.
        """


class IPRequestCache(RandomNumberCacheWithName):
    """
    Manage introduction point establishment.
    """

    name = "establish-intro"

    def __init__(self, community: TunnelCommunity, circuit: Circuit) -> None:
        """
        Create a new cache.
        """
        super().__init__(community.request_cache, self.name)
        self.logger = logging.getLogger(__name__)
        self.circuit = circuit
        self.community = community

    def on_timeout(self) -> None:
        """
        We remove the circuit if we can't establish an introduction point.
        """
        self.logger.info("IPRequestCache: no response on establish-intro (circuit %d)", self.circuit.circuit_id)
        self.community.remove_circuit(self.circuit.circuit_id, 'establish-intro timeout')


class RPRequestCache(RandomNumberCacheWithName):
    """
    Manage rendezvous point establishment.
    """

    name = "establish-rendezvous"

    def __init__(self, community: TunnelCommunity, rp: RendezvousPoint) -> None:
        """
        Create a new cache.
        """
        super().__init__(community.request_cache, self.name)
        self.logger = logging.getLogger(__name__)
        self.community = community
        self.rp = rp

    def on_timeout(self) -> None:
        """
        We remove the circuit if we can't establish a rendezvous point.
        """
        self.logger.info("RPRequestCache: no response on establish-rendezvous (circuit %d)",
                         self.rp.circuit.circuit_id)
        self.rp.ready.set_result(None)
        self.community.remove_circuit(self.rp.circuit.circuit_id, 'establish-rendezvous timeout')


class PeersRequestCache(RandomNumberCacheWithName):
    """
    Request peers for the given swarm (info hash).
    """

    name = "peers-request"

    def __init__(self, community: HiddenTunnelCommunity, circuit: Circuit, info_hash: bytes,
                 target: IntroductionPoint | None) -> None:
        """
        Create a new cache, exposes the ``future`` attribute to track completion.
        """
        super().__init__(community.request_cache, self.name)
        self.community = community
        self.circuit = circuit
        self.info_hash = info_hash
        self.target = target
        self.future: Future[list[IntroductionPoint]] = Future()
        self.register_future(self.future, RuntimeError("Peers request timeout"))

    def on_timeout(self) -> None:
        """
        We remove the introduction point if we don't get a response.
        """
        swarm = self.community.swarms.get(self.info_hash)
        if swarm is not None and self.target is not None:
            # This introduction point did not respond in time, so drop it.
            swarm.remove_intro_point(self.target)


class E2ERequestCache(RandomNumberCacheWithName):
    """
    Cache to track e2e circuit creation.
    """

    name = "e2e-request"

    def __init__(self, community: TunnelCommunity, info_hash: bytes, hop: Hop, intro_point: IntroductionPoint) -> None:
        """
        Create a new cache.
        """
        super().__init__(community.request_cache, self.name)
        self.info_hash = info_hash
        self.hop = hop
        self.intro_point = intro_point

    def on_timeout(self) -> None:
        """
        We don't need to do anything on timeout.
        """


class LinkRequestCache(RandomNumberCacheWithName):
    """
    Cache to track circuit linking.
    """

    name = "link-request"

    def __init__(self, community: TunnelCommunity, circuit: Circuit, info_hash: bytes,
                 hs_session_keys: SessionKeys) -> None:
        """
        Create a new cache.
        """
        super().__init__(community.request_cache, self.name)
        self.circuit = circuit
        self.info_hash = info_hash
        self.hs_session_keys = hs_session_keys

    def on_timeout(self) -> None:
        """
        We don't need to do anything on timeout.
        """


class TestRequestCache(RandomNumberCacheWithName):
    """
    Cache to track circuit speed tests.
    """

    name = "test-request"

    def __init__(self, community: TunnelCommunity, circuit: Circuit) -> None:
        """
        Create a new cache, exposes the ``future`` attribute to track completion.
        """
        super().__init__(community.request_cache, self.name)
        self.circuit = circuit
        self.ts = time.time()
        self.future: Future[tuple[bytes, float]] = Future()
        self.register_future(self.future)

    def on_timeout(self) -> None:
        """
        We don't need to do anything on timeout.
        """
