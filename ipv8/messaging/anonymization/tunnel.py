from __future__ import annotations

import contextlib
import logging
import time
from asyncio import Future, gather
from binascii import hexlify
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Sequence, cast

from ...keyvault.public.libnaclkey import LibNaCLPK

if TYPE_CHECKING:
    from ...keyvault.private.libnaclkey import LibNaCLSK
    from ...peer import Peer
    from ...types import Address
    from .crypto import SessionKeys

FORWARD = 0
BACKWARD = 1

PEER_SOURCE_UNKNOWN = 0
PEER_SOURCE_DHT = 1
PEER_SOURCE_PEX = 2

PEER_FLAG_RELAY = 1
PEER_FLAG_EXIT_BT = 2
PEER_FLAG_EXIT_IPV8 = 4
PEER_FLAG_SPEED_TEST = 8

# Data circuits are general purpose circuits for exiting data
CIRCUIT_TYPE_DATA = 'DATA'

# The other circuits are supposed to end in a connectable node, not allowed to exit
# anything else than IPv8 messages, used for setting up end-to-end circuits
CIRCUIT_TYPE_IP_SEEDER = 'IP_SEEDER'
CIRCUIT_TYPE_RP_SEEDER = 'RP_SEEDER'
CIRCUIT_TYPE_RP_DOWNLOADER = 'RP_DOWNLOADER'

CIRCUIT_STATE_READY = 'READY'
CIRCUIT_STATE_EXTENDING = 'EXTENDING'
CIRCUIT_STATE_CLOSING = 'CLOSING'

CIRCUIT_ID_PORT = 1024
PING_INTERVAL = 7.5

# Reasons for sending destroy messages. Code 0 must not be used for legacy reasons.
DESTROY_REASON_UNKNOWN = 1
DESTROY_REASON_SHUTDOWN = 2
DESTROY_REASON_UNNEEDED = 4


@dataclass
class Hop:
    """
    Hop contains all information needed to add/remove a single layer of
    onion encryption and send it to the next target.
    """

    peer: Peer
    keys: SessionKeys | None = None
    flags: list[int] | None = None
    dh_first_part: LibNaCLPK | None = None
    dh_secret: LibNaCLSK | None = None

    @property
    def address(self) -> Address:
        """
        Get the address of this hop.
        """
        return self.peer.address

    @property
    def public_key(self) -> LibNaCLPK:
        """
        Get the public key instance of the hop.
        """
        return cast(LibNaCLPK, self.peer.public_key)

    @property
    def public_key_bin(self) -> bytes:
        """
        The hop's public_key bytes.
        """
        return self.peer.public_key.key_to_bin()

    @property
    def mid(self) -> bytes:
        """
        Get the SHA-1 of the hop's public key.
        """
        return self.peer.mid


class RoutingObject:
    """
    Statistics for a tunnel to a peer over a circuit (base class for circuits, exit sockets, and relay routes).
    """

    def __init__(self, circuit_id: int) -> None:
        """
        Maintain the stats of the given object within the tunnel community.
        """
        self.circuit_id = circuit_id
        self.creation_time = time.time()
        self.last_activity = time.time()
        self.bytes_up = self.bytes_down = 0
        self.logger = logging.getLogger(self.__class__.__name__)

    def beat_heart(self) -> None:
        """
        Notify this object that the tunnel was active.
        """
        self.last_activity = time.time()


class Circuit(RoutingObject):
    """
    A peer-to-peer encrypted communication channel, consisting of 0 or more hops (intermediate peers).
    """

    def __init__(self, circuit_id: int, goal_hops: int = 0, ctype: str = CIRCUIT_TYPE_DATA,
                 required_exit: Peer | None = None, info_hash: bytes | None = None) -> None:
        """
        Create a new circuit instance.
        """
        super().__init__(circuit_id)
        self.goal_hops = goal_hops
        self.ctype = ctype
        self.required_exit = required_exit
        self.info_hash = info_hash

        self.ready: Future[Circuit | None] = Future()
        self.closing_info = ''
        self._closing = False
        self._hops: list[Hop] = []
        self.unverified_hop: Hop | None = None
        self._hs_session_keys: SessionKeys | None = None
        self.e2e = False
        self.relay_early_count = 0

        self.dirty = False

    def add_hop(self, hop: Hop) -> None:
        """
        Adds a hop to the circuits hop collection.
        """
        self._hops.append(hop)
        if self.state == CIRCUIT_STATE_READY:
            self.ready.set_result(self)
        self.dirty = True

    @property
    def hs_session_keys(self) -> SessionKeys | None:
        """
        Get the session keys for hidden services (if any).
        """
        return self._hs_session_keys

    @hs_session_keys.setter
    def hs_session_keys(self, value: SessionKeys) -> None:
        """
        Set the session keys for hidden services.
        """
        self._hs_session_keys = value
        self.dirty = True

    @property
    def hop(self) -> Hop:
        """
        Return the first hop of the circuit.
        """
        return cast(Hop, self._hops[0] if self._hops else self.unverified_hop)

    @property
    def hops(self) -> Sequence[Hop]:
        """
        Return a read only tuple version of the hop-list of this circuit.
        """
        return tuple(self._hops)

    @property
    def exit_flags(self) -> list[int]:
        """
        Get the flags of the last hop in our circuit.
        """
        if self.hops:
            return self.hops[-1].flags or []
        return []

    @property
    def state(self) -> str:
        """
        The circuit state.

        This can be either:
            - CIRCUIT_STATE_CLOSING
            - CIRCUIT_STATE_EXTENDING
            - CIRCUIT_STATE_READY
        """
        if self._closing:
            return CIRCUIT_STATE_CLOSING

        if len(self.hops) < self.goal_hops:
            return CIRCUIT_STATE_EXTENDING

        return CIRCUIT_STATE_READY

    def close(self, closing_info: str = '') -> None:
        """
        Sets the state of the circuit to CIRCUIT_STATE_CLOSING. This ensures that this circuit
        will not be used to contact new peers.
        """
        self.closing_info = closing_info
        self._closing = True
        if not self.ready.done():
            self.ready.set_result(None)


class RelayRoute(RoutingObject):
    """
    Relay object containing the destination circuit, socket address and whether it is online or not.
    """

    def __init__(self, circuit_id: int, hop: Hop, direction: int, rendezvous_relay: bool = False) -> None:
        """
        Create a new relay route.
        """
        super().__init__(circuit_id)
        self.hop = hop
        self.direction = direction
        self.rendezvous_relay = rendezvous_relay
        # Since the creation of a RelayRoute object is triggered by an extend (which was wrapped in a cell
        # that had the early_relay flag set) we start the count at 1.
        self.relay_early_count = 1


class RendezvousPoint:
    """
    Rendezvous for circuits to link up.
    """

    def __init__(self, circuit: Circuit, cookie: bytes) -> None:
        """
        Create a new rendezvous point.
        """
        self.circuit = circuit
        self.cookie = cookie
        self.address: Address | None = None
        self.ready: Future[RendezvousPoint | None] = Future()


class IntroductionPoint:
    """
    A point of introduction, available for linking up.
    """

    def __init__(self, peer: Peer, seeder_pk: bytes, source: int = PEER_SOURCE_UNKNOWN,
                 last_seen: float | None = None) -> None:
        """
        Creates a new introduction point.
        """
        self.peer = peer
        self.seeder_pk = seeder_pk
        self.source = source
        self.last_seen = int(time.time()) if last_seen is None else last_seen

    def __eq__(self, other: object) -> bool:
        """
        Check if another object is equal to this intro point.
        """
        if not isinstance(other, IntroductionPoint):
            return False
        return self.peer == other.peer and self.seeder_pk == other.seeder_pk

    def __hash__(self) -> int:
        """
        Each intro point is unique to its peer and seeder's public key.
        """
        return hash((self.peer, self.seeder_pk))

    def to_dict(self) -> dict[str, dict[str, str | int] | str | int]:
        """
        Convert this intro point to a flat dict.
        """
        return{'address': {'ip': self.peer.address[0],
                           'port': self.peer.address[1],
                           'public_key': hexlify(self.peer.public_key.key_to_bin()).decode()},
               'seeder_pk': hexlify(self.seeder_pk).decode(),
               'source': self.source}


class Swarm:
    """
    A group of circuit exits that organizes around an SHA-1.
    """

    def __init__(self, info_hash: bytes, hops: int,  # noqa: PLR0913
                 lookup_func: Callable[[bytes, IntroductionPoint | None, int], Future[list[IntroductionPoint]]],
                 seeder_sk: LibNaCLSK | None = None, max_ip_age: float = 180.0, min_dht_lookup_interval: float = 300.0,
                 max_dht_lookup_interval: float = 120.0) -> None:
        """
        Create a new swarm instance.
        """
        self.info_hash = info_hash
        self.hops = hops
        self.lookup_func = lookup_func
        self.seeder_sk = seeder_sk
        self.max_ip_age = max_ip_age
        self.min_dht_lookup_interval = min_dht_lookup_interval
        self.max_dht_lookup_interval = max_dht_lookup_interval

        self.intro_points: list[IntroductionPoint] = []
        self.connections: dict[int, tuple[Circuit, IntroductionPoint]] = {}
        self.last_lookup: float = 0
        self.last_dht_response: float = 0
        self.transfer_history = [0, 0]

        self.logger = logging.getLogger(self.__class__.__name__)

    @property
    def seeding(self) -> bool:
        """
        Whether we are seeding data in this swarm.
        """
        return bool(self.seeder_sk)

    @property
    def _active_circuits(self) -> list[Circuit]:
        return [c for c, _ in self.connections.values() if c.state == CIRCUIT_STATE_READY and c.e2e]

    def add_connection(self, rp_circuit: Circuit, intro_point_used: IntroductionPoint) -> None:
        """
        Add a newly known circuit to this swarm.
        """
        if rp_circuit.circuit_id not in self.connections:
            self.connections[rp_circuit.circuit_id] = (rp_circuit, intro_point_used)

    def remove_connection(self, rp_circuit: Circuit) -> bool:
        """
        Remove the given circuit from this swarm, if we manage it.

        This does not close the circuit.
        """
        removed = self.connections.pop(rp_circuit.circuit_id, None)
        if removed:
            circuit, _ = removed
            self.transfer_history[0] += circuit.bytes_up
            self.transfer_history[1] += circuit.bytes_down
        return bool(removed)

    def has_connection(self, seeder_pk: bytes) -> bool:
        """
        Check if the given public key is in the swarm.
        """
        return seeder_pk in [ip.seeder_pk for _, ip in self.connections.values()]

    def get_num_connections(self) -> int:
        """
        Get the number of circuits we have in this swarm.
        """
        return len(self._active_circuits)

    def get_num_connections_incomplete(self) -> int:
        """
        Get the number of circuits we don't have yet, but know of, in this swarm.
        """
        return len(self.connections) - self.get_num_connections()

    def add_intro_point(self, ip: IntroductionPoint) -> IntroductionPoint:
        """
        Add an available introduction point to this swarm.

        Returns the introduction point we should use (not necessarily the one we just added).
        """
        old_ip = next((i for i in self.intro_points if i == ip), None)

        if old_ip:
            old_ip.last_seen = time.time()
        else:
            self.intro_points.append(ip)

        return old_ip or ip

    def remove_old_intro_points(self) -> None:
        """
        Cleanup old introduction points.
        """
        now = time.time()
        used_intro_points = [i for c, i in self.connections.values() if c.state == CIRCUIT_STATE_READY and c.e2e]
        self.intro_points = [i for i in self.intro_points
                             if i.last_seen + self.max_ip_age >= now or i in used_intro_points]

    def remove_intro_point(self, ip: IntroductionPoint) -> None:
        """
        Remove the given introduction point from this swarm.
        """
        with contextlib.suppress(ValueError):
            self.intro_points.remove(ip)

    async def lookup(self, target: IntroductionPoint | None = None) -> list[IntroductionPoint] | None:
        """
        Lookup introduction points, possibly those that match the given introduction point.
        """
        def on_success(ips: list[IntroductionPoint]) -> list[IntroductionPoint]:
            if any(ip for ip in ips if ip.source == PEER_SOURCE_DHT):
                self.last_dht_response = time.time()
            return ips

        # Are we doing a manual lookup?
        if target:
            self.logger.info("Performing manual PEX lookup for swarm %s (target %s)",
                             hexlify(self.info_hash), target.peer)
            return on_success(await self.lookup_func(self.info_hash, target, self.hops))

        now = time.time()
        self.remove_old_intro_points()
        self.last_lookup = now
        if (now - self.last_dht_response) > self.min_dht_lookup_interval or \
           (not self.intro_points and (now - self.last_dht_response) > self.max_dht_lookup_interval):
            self.logger.info("Performing DHT lookup for swarm %s", hexlify(self.info_hash))
            return on_success(await self.lookup_func(self.info_hash, None, self.hops))

        if self.intro_points:
            self.logger.info("Performing PEX lookup for swarm %s (targeting %d peer(s))",
                             hexlify(self.info_hash), len(self.intro_points))
            results = []
            tasks = [self.lookup_func(self.info_hash, ip, self.hops) for ip in self.intro_points]
            if tasks:
                for result in (await gather(*tasks, return_exceptions=True)):
                    if not isinstance(result, (BaseException, Exception)):
                        results.extend(result)
            return on_success(results)
        self.logger.info("Skipping lookup for swarm %s", hexlify(self.info_hash))
        return None

    def get_num_seeders(self) -> int:
        """
        Get the number of different seeder public keys in this swarm.
        """
        seeder_pks = {ip.seeder_pk for ip in self.intro_points}
        for _, ip in self.connections.values():
            seeder_pks.add(ip.seeder_pk)
        return len(seeder_pks)

    def get_total_up(self) -> int:
        """
        Get the total number of bytes uploaded in this swarm.
        """
        return sum([c.bytes_up for c in self._active_circuits]) + self.transfer_history[0]

    def get_total_down(self) -> int:
        """
        Get the total number of bytes downloaded from this swarm.
        """
        return sum([c.bytes_down for c in self._active_circuits]) + self.transfer_history[1]
