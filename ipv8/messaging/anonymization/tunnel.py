from __future__ import annotations

import contextlib
import logging
import socket
import sys
import time
from asyncio import CancelledError, DatagramProtocol, DatagramTransport, Future, ensure_future, gather, get_running_loop
from binascii import hexlify
from collections import deque
from struct import unpack_from
from traceback import format_exception
from typing import TYPE_CHECKING, Callable, Generic, Optional, Sequence, TypeVar, cast

from ...keyvault.public.libnaclkey import LibNaCLPK
from ...peer import Peer
from ...taskmanager import TaskManager
from ...util import succeed

if TYPE_CHECKING:
    from ...keyvault.private.libnaclkey import LibNaCLSK
    from ...types import Address
    from .community import TunnelCommunity
    from .tunnelcrypto import SessionKeys

ORIGINATOR = 0
EXIT_NODE = 1
ORIGINATOR_SALT = 2
EXIT_NODE_SALT = 3
ORIGINATOR_SALT_EXPLICIT = 4
EXIT_NODE_SALT_EXPLICIT = 5

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
DESTROY_REASON_FORWARD = 3
DESTROY_REASON_UNNEEDED = 4
DESTROY_REASON_LEAVE_SWARM = 5
DESTROY_REASON_FORBIDDEN = 6


class DataChecker:
    """
    Class to verify that only IPv8-allowed traffic is being forwarded.
    """

    @staticmethod
    def could_be_utp(data: bytes) -> bool:
        """
        Check if this data could be uTP (see also https://www.bittorrent.org/beps/bep_0029.html).

        Packets should be 20 bytes or larger.

        The type should be 0..4:
         - 0: ST_DATA
         - 1: ST_FIN
         - 2: ST_STATE
         - 3: ST_RESET
         - 4: ST_SYN

        The version should be 1.

        The extension should be 0..3:
         - 0: No extension
         - 1: Selective ACK
         - 2: Deprecated
         - 3: Close reason
        """
        if len(data) < 20:
            return False
        byte1, byte2 = unpack_from('!BB', data)
        # Type and version
        if not (0 <= (byte1 >> 4) <= 4 and (byte1 & 15) == 1):
            return False
        # Extension
        if not (0 <= byte2 <= 3):
            return False
        return True

    @staticmethod
    def could_be_udp_tracker(data: bytes) -> bool:
        """
        Check if the data could be a UDP-based tracker.
        """
        # For the UDP tracker protocol the action field is either at position 0 or 8, and should be 0..3
        if len(data) >= 8 and (0 <= unpack_from('!I', data, 0)[0] <= 3)\
                or len(data) >= 12 and (0 <= unpack_from('!I', data, 8)[0] <= 3):
            return True
        return False

    @staticmethod
    def could_be_dht(data: bytes) -> bool:
        """
        Check if the data contain a bencoded dictionary.
        """
        try:
            if len(data) > 1 and data[0:1] == b'd' and data[-1:] == b'e':
                return True
        except TypeError:
            pass
        return False

    @staticmethod
    def could_be_bt(data: bytes) -> bool:
        """
        Check if the data could be any BitTorrent traffic.
        """
        return (DataChecker.could_be_utp(data)
                or DataChecker.could_be_udp_tracker(data)
                or DataChecker.could_be_dht(data))

    @staticmethod
    def could_be_ipv8(data: bytes) -> bool:
        """
        Check if the data is likely IPv8 overlay traffic.
        """
        return len(data) >= 23 and data[0:1] == b'\x00' and data[1:2] in [b'\x01', b'\x02']


PT = TypeVar("PT", Peer, Optional[Peer])


class Tunnel(Generic[PT]):
    """
    Statistics for a tunnel to a peer over a circuit (base class for circuits, exit sockets, and relay routes).
    """

    def __init__(self, circuit_id: int, peer: PT) -> None:
        """
        Maintain the stats of the given circuit id and peer.
        """
        self.circuit_id = circuit_id
        self._peer: PT = peer
        self.creation_time = time.time()
        self.last_activity = time.time()
        self.bytes_up = self.bytes_down = 0
        self.logger = logging.getLogger(self.__class__.__name__)

    @property
    def peer(self) -> PT:
        """
        The peer on the other end of this tunnel, if it exists.
        """
        return self._peer

    def beat_heart(self) -> None:
        """
        Notify this object that the tunnel was active.
        """
        self.last_activity = time.time()


class TunnelExitSocket(Tunnel[Peer], DatagramProtocol, TaskManager):
    """
    Socket for exit nodes that communicates with the outside world.
    """

    def __init__(self, circuit_id: int, peer: Peer, overlay: TunnelCommunity) -> None:
        """
        Create a new exit socket.
        """
        Tunnel.__init__(self, circuit_id, peer)
        TaskManager.__init__(self)
        self.overlay = overlay
        self.transport: DatagramTransport | None = None
        self.queue: deque[tuple[bytes, Address]] = deque(maxlen=10)
        self.enabled = False

    def enable(self) -> None:
        """
        Allow data to be sent.

        This creates the datagram endpoint that allows us to send messages.
        """
        if not self.enabled:
            self.enabled = True

            async def create_transport() -> None:
                self.transport, _ = await get_running_loop().create_datagram_endpoint(lambda: self,
                                                                                    local_addr=('0.0.0.0', 0))
                # Send any packets that have been waiting while the transport was being created
                while self.queue:
                    self.sendto(*self.queue.popleft())
            self.register_task("create_transport", create_transport)

    def sendto(self, data: bytes, destination: Address) -> None:
        """
        Send o message over our datagram transporter.
        """
        if not self.transport:
            self.queue.append((data, destination))
            return
        transport = cast(DatagramTransport, self.transport)

        self.beat_heart()
        if self.is_allowed(data):
            def on_ip_address(future: Future[str]) -> None:
                try:
                    ip_address = future.result()
                except (CancelledError, Exception) as e:
                    self.logger.exception("Can't resolve ip address for %s. Failure: %s", destination[0], e)
                    return

                self.logger.debug("Resolved hostname %s to ip_address %s", destination[0], ip_address)
                try:
                    transport.sendto(data, (ip_address, destination[1]))
                    self.bytes_up += len(data)
                except OSError as e:
                    self.logger.exception("Failed to write to transport. Destination: %r error: %r", destination, e)

            try:
                socket.inet_aton(destination[0])
                on_ip_address(succeed(destination[0]))
            except (OSError, ValueError):
                task = ensure_future(self.resolve(destination[0]))
                # If this also fails, the TaskManager logs the packet.
                # The host probably really does not exist.
                self.register_anonymous_task("resolving_%r" % destination[0], task,
                                             ignore=(OSError, ValueError)).add_done_callback(on_ip_address)

    async def resolve(self, host: str) -> str:
        """
        Using asyncio's getaddrinfo since the aiodns resolver seems to have issues.
        Returns [(family, type, proto, canonname, sockaddr)].
        """
        infos = await get_running_loop().getaddrinfo(host, 0, family=socket.AF_INET)
        return infos[0][-1][0]

    def datagram_received(self, data: bytes, source: Address) -> None:
        """
        Callback for when data is received by the socket.
        """
        self.beat_heart()
        self.bytes_down += len(data)
        if self.is_allowed(data):
            try:
                self.tunnel_data(source, data)
            except Exception:
                self.logger.exception("Exception occurred while handling incoming exit node data!\n%s",
                                      ''.join(format_exception(*sys.exc_info())))
        else:
            self.logger.warning("Dropping forbidden packets to exit socket with circuit_id %d", self.circuit_id)

    def is_allowed(self, data: bytes) -> bool:
        """
        Check if the captured data is not malicious junk.
        """
        is_bt = DataChecker.could_be_bt(data)
        is_ipv8 = DataChecker.could_be_ipv8(data)

        if not (is_bt and PEER_FLAG_EXIT_BT in self.overlay.settings.peer_flags) \
           and not (is_ipv8 and PEER_FLAG_EXIT_IPV8 in self.overlay.settings.peer_flags) \
           and not (is_ipv8 and self.overlay._prefix == data[:22]):  # noqa: SLF001
            self.logger.warning("Dropping data packets, refusing to be an exit node (BT=%s, IPv8=%s)", is_bt, is_ipv8)
            return False
        return True

    def tunnel_data(self, source: Address, data: bytes) -> None:
        """
        Send data back over the tunnel that we are exiting for.
        """
        self.logger.debug("Tunnel data to origin %s for circuit %s", ('0.0.0.0', 0), self.circuit_id)
        self.overlay.send_data(self.peer, self.circuit_id, ('0.0.0.0', 0), source, data)

    async def close(self) -> None:
        """
        Closes the UDP socket if enabled and cancels all pending tasks.

        :return: A deferred that fires once the UDP socket has closed.
        """
        # The resolution tasks can't be cancelled, so we need to wait for
        # them to finish.
        await self.shutdown_task_manager()
        if self.transport:
            self.transport.close()
            self.transport = None


class Circuit(Tunnel[Optional[Peer]]):
    """
    A peer-to-peer encrypted communication channel, consisting of 0 or more hops (intermediate peers).
    """

    def __init__(self, circuit_id: int , goal_hops: int = 0, ctype: str = CIRCUIT_TYPE_DATA,  # noqa: PLR0913
                 required_exit: Peer | None = None, info_hash: bytes | None = None) -> None:
        """
        Create a new circuit instance.
        """
        super().__init__(circuit_id, None)
        self.goal_hops = goal_hops
        self.ctype = ctype
        self.required_exit = required_exit
        self.info_hash = info_hash

        self.ready: Future[Circuit | None] = Future()
        self.closing_info = ''
        self._closing = False
        self._hops: list[Hop] = []
        self.unverified_hop: Hop | None = None
        self.hs_session_keys: SessionKeys | None = None
        self.e2e = False
        self.relay_early_count = 0

    @property
    def peer(self) -> Peer | None:
        """
        Get the gateway peer for this tunnel, if it already exists.
        """
        if self._hops:
            return self._hops[0].peer
        if self.unverified_hop:
            return self.unverified_hop.peer
        return None

    @property
    def exit_flags(self) -> list[int]:
        """
        Get the flags of the last hop in our circuit.
        """
        return self.hops[-1].flags if self.hops else []

    @property
    def hops(self) -> Sequence[Hop]:
        """
        Return a read only tuple version of the hop-list of this circuit.
        """
        return tuple(self._hops)

    def add_hop(self, hop: Hop) -> None:
        """
        Adds a hop to the circuits hop collection.
        """
        self._hops.append(hop)
        if self.state == CIRCUIT_STATE_READY:
            self.ready.set_result(self)

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

    def __eq__(self, other: object) -> bool:
        """
        Check if the other object is equal to this circuit.
        """
        if not isinstance(other, Circuit):
            return False
        return self.circuit_id == other.circuit_id


class Hop:
    """
    Circuit Hop containing the address, its public key and the first part of
    the Diffie-Hellman handshake.
    """

    def __init__(self, peer: Peer, flags: list[int] | None = None) -> None:
        """
        Create a new hop instance for the given peer.
        """
        self.peer = peer
        self.session_keys: SessionKeys | None = None
        self.dh_first_part: LibNaCLPK | None = None
        self.dh_secret: LibNaCLSK | None = None
        self.flags: list[int] = [] if flags is None else flags

    @property
    def public_key(self) -> LibNaCLPK:
        """
        Get the public key instance of the hop.
        """
        return cast(LibNaCLPK, self.peer.public_key)

    @property
    def node_public_key(self) -> bytes:
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


class RelayRoute(Tunnel[Peer]):
    """
    Relay object containing the destination circuit, socket address and whether it is online or not.
    """

    def __init__(self, circuit_id: int, peer: Peer, rendezvous_relay: bool = False) -> None:
        """
        Create a new relay route.
        """
        super().__init__(circuit_id, peer)
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
        Createa a new introduction point.
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
    A group of circuit exits that organizes around a SHA-1.
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
                results = [result for result in (await gather(*tasks, return_exceptions=True))
                           if not isinstance(result, (CancelledError, Exception))]
                results = sum(results, [])
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
