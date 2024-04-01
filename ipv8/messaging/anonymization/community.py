"""
The tunnel community.

Author(s): Egbert Bouman
"""
from __future__ import annotations

import os
import random
import sys
from asyncio import ensure_future, iscoroutine, sleep
from binascii import unhexlify
from collections import defaultdict
from traceback import format_exception
from typing import TYPE_CHECKING, Awaitable, List, Optional, Set

from ...community import Community, CommunitySettings
from ...keyvault.private.libnaclkey import LibNaCLSK
from ...lazy_community import lazy_wrapper
from ...peer import Peer
from ...requestcache import RequestCache
from ...taskmanager import task
from ...types import Address
from ..interfaces.dispatcher.endpoint import DispatcherEndpoint
from ..interfaces.endpoint import Endpoint
from .caches import *
from .crypto import CryptoEndpoint, PythonCryptoEndpoint, TunnelCrypto
from .endpoint import TunnelEndpoint
from .exit_socket import DataChecker, TunnelExitSocket
from .payload import *
from .tunnel import *
from .tunnel import RelayRoute

if TYPE_CHECKING:
    from collections.abc import Collection

    from ...dht.provider import DHTCommunityProvider
    from ...messaging.payload_headers import GlobalTimeDistributionPayload
    from ..lazy_payload import VariablePayloadWID
    from ..payload import (
        IntroductionRequestPayload,
        IntroductionResponsePayload,
        NewIntroductionRequestPayload,
        NewIntroductionResponsePayload,
    )
    from ..serialization import Serializable, Serializer


def unpack_cell(payload_cls: type[Serializable]) -> Callable[...,  # User function
    Callable[[TunnelCommunity, Address, bytes, int | None], None]]:  # Actual call signature
    """
    This function wrapper will unpack the normal payload for you, and handle a singular circuit_id parameter at
    the end of the parameter list
    You can now write your non-authenticated and signed functions as follows:
    ::
        @unpack_cell(DataPayload)
        def on_message(source_address, payload):
            '''
            :type source_address: str
            :type payload: DataPayload
            '''
            pass.
    """

    def decorator(func: Callable[[TunnelCommunity, Address, Serializable, int | None], None]) -> \
            Callable[[TunnelCommunity, Address, bytes, int | None], None]:
        def wrapper(self: TunnelCommunity, source_address: Address, data: bytes, circuit_id: int | None = None) -> None:
            payload, _ = self.serializer.unpack_serializable(payload_cls, data, offset=23)
            return func(self, source_address, payload, circuit_id)
        return wrapper
    return decorator


class TunnelSettings(CommunitySettings):
    """
    Settings to forward to the TunnelCommunity.
    """

    min_circuits = 1
    max_circuits = 8
    max_joined_circuits = 100

    # Maximum number of seconds that a circuit should exist
    max_time = 60 * 60
    # Maximum number of seconds that an introduction point should exist
    max_time_ip = 24 * 60 * 60
    # Maximum number of seconds before a circuit is considered inactive (and is removed)
    max_time_inactive = 20
    max_traffic = 10 * 1024**3

    # Maximum number of seconds circuit creation is allowed to take. Within this time period, the unverified hop
    # of the circuit can still change in case it is unresponsive.
    circuit_timeout = 60
    # Maximum number of seconds that a hop allows us to change the next hop
    unstable_timeout = 60
    # Maximum number of seconds adding a single hop to a circuit is allowed to take.
    next_hop_timeout = 10

    swarm_lookup_interval = 30
    swarm_connection_limit = 15

    # We have a small delay when removing circuits/relays/exit nodes. This is to allow some post-mortem data
    # to flow over the circuit (i.e. bandwidth payouts to intermediate nodes in a circuit).
    remove_tunnel_delay = 5

    _peer_flags: Set[int] = {PEER_FLAG_RELAY, PEER_FLAG_SPEED_TEST}

    _max_relay_early = 8

    dht_provider: DHTCommunityProvider | None = None

    @property
    def max_relay_early(self) -> int:
        """
        Return the maximum number of relay_early cells that are allowed to pass a relay.
        """
        return self._max_relay_early

    @max_relay_early.setter
    def max_relay_early(self, value: int) -> None:
        """
        Set the maximum number of relay_early cells that are allowed to pass a relay.
        """
        self._max_relay_early = value
        if hasattr(self, 'endpoint') and hasattr(self.endpoint, 'set_max_relay_early'):
            self.endpoint.set_max_relay_early(value)

    @property
    def peer_flags(self) -> Set[int]:
        """
        Return the peer flags.
        """
        return self._peer_flags

    @peer_flags.setter
    def peer_flags(self, value: Set[int]) -> None:
        """
        Set the peer flags.
        """
        self._peer_flags = value
        if hasattr(self, 'endpoint') and hasattr(self.endpoint, 'set_peer_flags'):
            self.endpoint.set_peer_flags(value)


class TunnelCommunity(Community):
    """
    Community to create circuits of intermediate peers (hops) that send data into (exit) and receive from the Internet.
    """

    version = b'\x02'
    community_id = unhexlify('81ded07332bdc775aa5a46f96de9f8f390bbc9f3')
    settings_class = TunnelSettings

    def __init__(self, settings: TunnelSettings) -> None:
        """
        Create a new TunnelCommunity.
        """
        self.settings = settings
        self.dht_provider = settings.dht_provider

        super().__init__(settings)

        self.request_cache = RequestCache()
        self.decode_map_private: dict[int, Callable[[TunnelCommunity, Address, bytes, int | None], None]
                                           | Callable[[Address, bytes, int | None], None]] = {}

        # Messages that can arrive from the socket
        self.add_message_handler(CellPayload.msg_id, self.on_cell)
        self.add_message_handler(DestroyPayload, self.on_destroy)

        # Messages that can arrive from a circuit (i.e., they are wrapped in a cell)
        self.add_cell_handler(DataPayload, self.on_data)
        self.add_cell_handler(CreatePayload, self.on_create)
        self.add_cell_handler(CreatedPayload, self.on_created)
        self.add_cell_handler(ExtendPayload, self.on_extend)
        self.add_cell_handler(ExtendedPayload, self.on_extended)
        self.add_cell_handler(PingPayload, self.on_ping)
        self.add_cell_handler(PongPayload, self.on_pong)
        self.add_cell_handler(TestRequestPayload, self.on_test_request)
        self.add_cell_handler(TestResponsePayload, self.on_test_response)

        self.circuits_needed: dict[int, int] = defaultdict(int)
        self.candidates: dict[Peer, list[int]] = {}  # Keeps track of the candidates that want to be a relay/exit node

        self.logger.info("Exit settings: BT=%s, IPv8=%s",
                         PEER_FLAG_EXIT_BT in self.settings.peer_flags,
                         PEER_FLAG_EXIT_IPV8 in self.settings.peer_flags)

        self.crypto: TunnelCrypto = TunnelCrypto()
        self.crypto.initialize(cast(LibNaCLSK, self.my_peer.key))

        # For now, the TunnelCommunity only supports IPv4 for control messages.
        # Data packets can still be sent to IPv6 destinations.
        if isinstance(self.endpoint, DispatcherEndpoint):
            ipv4_endpoint = cast(Endpoint, self.endpoint.interfaces["UDPIPv4"])
        else:
            ipv4_endpoint = self.endpoint

        self.crypto_endpoint = ipv4_endpoint if isinstance(ipv4_endpoint,
                                                           CryptoEndpoint) else PythonCryptoEndpoint(self.endpoint)
        self.crypto_endpoint.setup_tunnels(self, self.settings)

        self.circuits = self.crypto_endpoint.circuits
        self.relay_from_to = self.crypto_endpoint.relays
        self.exit_sockets = self.crypto_endpoint.exit_sockets

        if isinstance(self.endpoint, TunnelEndpoint):
            self.endpoint.set_tunnel_community(self)
            self.endpoint.set_anonymity(self._prefix, False)

        self.register_task("do_circuits", self.do_circuits, interval=5, delay=0)
        self.register_task("do_ping", self.do_ping, interval=PING_INTERVAL)

    async def unload(self) -> None:
        """
        Remove all circuits/relays/exitsockets.
        """
        for circuit_id in list(self.circuits.keys()):
            self.remove_circuit(circuit_id, 'unload', remove_now=True, destroy=DESTROY_REASON_SHUTDOWN)
        for circuit_id in list(self.relay_from_to.keys()):
            self.remove_relay(circuit_id, 'unload', remove_now=True, destroy=DESTROY_REASON_SHUTDOWN)
        for circuit_id in list(self.exit_sockets.keys()):
            self.remove_exit_socket(circuit_id, 'unload', remove_now=True, destroy=DESTROY_REASON_SHUTDOWN)

        await self.request_cache.shutdown()

        await super().unload()

    def get_serializer(self) -> Serializer:
        """
        Extend our serializer with the ability to (un)pack exit node flags.
        """
        serializer = super().get_serializer()
        serializer.add_packer('flags', Flags())
        return serializer

    def add_cell_handler(self, payload_cls: type[VariablePayloadWID],
                         handler: Callable[[TunnelCommunity, Address, bytes, int | None], None] | \
                                  Callable[[Address, bytes, int | None], None]) -> None:
        """
        Handler for messages that are exclusively tunneled (i.e., never handled plaintext).
        """
        self.decode_map_private[payload_cls.msg_id] = handler

    def _generate_circuit_id(self) -> int:
        circuit_id = random.getrandbits(32)

        # Prevent collisions.
        while circuit_id in self.circuits:
            circuit_id = random.getrandbits(32)

        return circuit_id

    def do_circuits(self) -> None:
        """
        Check if we have sufficient circuits and attempt to create new circuits if we have too little.
        """
        for circuit_length, num_circuits in self.circuits_needed.items():
            num_to_build = max(0, num_circuits - len(self.find_circuits(state=None, hops=circuit_length)))
            self.logger.info("Want %d data circuits of length %d", num_to_build, circuit_length)
            for _ in range(num_to_build):
                if not self.create_circuit(circuit_length):
                    self.logger.info("Circuit creation of %d circuits failed, no need to continue", num_to_build)
                    break
        self.do_remove()

    def build_tunnels(self, hops: int) -> None:
        """
        Signal that we want circuits of a given number of hops.

        The number of circuits created for this hop count is dictated by the ``max_circuits`` setting.
        """
        if hops > 0:
            self.circuits_needed[hops] = self.settings.max_circuits
            self.do_circuits()

    def tunnels_ready(self, hops: int) -> float:
        """
        Fraction of circuits that are available for the given hop count.
        """
        if hops > 0 and self.circuits_needed.get(hops, 0):
            return len(self.find_circuits(hops=hops)) / float(self.circuits_needed[hops])
        return 1.0

    def do_remove(self) -> None:  # noqa: C901, PLR0912
        """
        Remove all circuits that are inactive, old or overused and remove old peers from our candidate list.
        """
        # Remove circuits that are inactive / are too old / have transferred too many bytes.
        for circuit_id, circuit in list(self.circuits.items()):
            if circuit.state == CIRCUIT_STATE_READY and \
                    circuit.last_activity < time.time() - self.settings.max_time_inactive:
                self.remove_circuit(circuit_id, 'no activity')
            elif circuit.creation_time < time.time() - self.get_max_time(circuit_id):
                self.remove_circuit(circuit_id, 'too old')
            elif circuit.bytes_up + circuit.bytes_down > self.settings.max_traffic:
                self.remove_circuit(circuit_id, 'traffic limit exceeded', destroy=True)

        # Remove relays that are inactive / have transferred too many bytes.
        for circuit_id, relay in list(self.relay_from_to.items()):
            if relay.last_activity < time.time() - self.settings.max_time_inactive:
                self.remove_relay(circuit_id, 'no activity')
            elif relay.bytes_up + relay.bytes_down > self.settings.max_traffic:
                self.remove_relay(circuit_id, 'traffic limit exceeded', destroy=True)

        # Remove exit sockets that are too old / have transferred too many bytes.
        for circuit_id, exit_socket in list(self.exit_sockets.items()):
            if exit_socket.last_activity < time.time() - self.settings.max_time_inactive:
                self.remove_exit_socket(circuit_id, 'no activity')
            elif exit_socket.creation_time < time.time() - self.get_max_time(circuit_id):
                self.remove_exit_socket(circuit_id, 'too old')
            elif exit_socket.bytes_up + exit_socket.bytes_down > self.settings.max_traffic:
                self.remove_exit_socket(circuit_id, 'traffic limit exceeded', destroy=True)

        # Remove candidates that are not returned as verified peers
        current_peers = self.get_peers()
        for peer in list(self.candidates):
            if peer not in current_peers:
                self.candidates.pop(peer)

    def get_candidates(self, *requested_flags: int) -> list[Peer]:
        """
        Get all the peers that we can create circuits with.
        """
        return [peer for peer, flags in self.candidates.items()
                if set(requested_flags) <= set(flags) and self.crypto.is_key_compatible(peer.public_key)]

    def get_max_time(self, circuit_id: int) -> float:
        """
        Get the maximum time (in seconds) that the given circuit is allowed to exist.
        """
        return self.settings.max_time

    def find_circuits(self, ctype: str | None = CIRCUIT_TYPE_DATA, state: str | None = CIRCUIT_STATE_READY,
                      exit_flags: Collection[int] | None = None, hops: int | None = None) -> list[Circuit]:
        """
        Get circuits of the given type and state (and potentially exit flags and a given number of hops).
        """
        return [c for c in self.circuits.values()
                if (state is None or c.state == state)
                and (ctype is None or c.ctype == ctype)
                and (exit_flags is None or set(exit_flags) <= set(c.exit_flags))
                and (hops is None or hops == c.goal_hops)]

    def create_circuit(self, goal_hops: int, ctype: str = CIRCUIT_TYPE_DATA,
                       exit_flags: Collection[int] | None = None, required_exit: Peer | None = None,
                       info_hash: bytes | None = None) -> Circuit | None:
        """
        Create a circuit of a given number of hops. The circuit will be created immediately but not be available
        for transmission of data immediately. Note that not all circuits exist to send data.

        :return: None if we are supposed to find an exit node and know of none.
        """
        self.logger.info("Creating a new circuit of length %d (type: %s)", goal_hops, ctype)

        # Determine the last hop
        if not required_exit:
            if exit_flags is not None:
                exit_candidates = self.get_candidates(*exit_flags)
            elif ctype == CIRCUIT_TYPE_DATA:
                exit_candidates = self.get_candidates(PEER_FLAG_EXIT_BT)
            elif ctype == CIRCUIT_TYPE_IP_SEEDER:
                # For introduction points we prefer exit nodes, but perhaps a relay peer would also suffice..
                exit_candidates = self.get_candidates(PEER_FLAG_EXIT_BT) \
                                  or self.get_candidates(PEER_FLAG_EXIT_IPV8) \
                                  or self.get_candidates(PEER_FLAG_RELAY)
            else:
                # For exit nodes that don't exit actual data, we prefer relay candidates,
                # but we also consider exit candidates.
                exit_candidates = self.get_candidates(PEER_FLAG_RELAY) or self.get_candidates(PEER_FLAG_EXIT_BT)

            if not exit_candidates:
                self.logger.info("Could not create circuit, no available exit-nodes")
                return None

            required_exit = random.choice(exit_candidates)

        # Determine the first hop
        if goal_hops == 1 and required_exit:
            # If the number of hops is 1, it should immediately be the required_exit hop.
            self.logger.info("First hop is required exit")
            possible_first_hops = [required_exit]
        else:
            self.logger.info("Look for a first hop that is not an exit node and is not used before")
            # First build a list of hops, then filter the list. Avoids issues when create_circuit is called
            # from a different thread (caused by circuit.peer being reset to None).
            first_hops = {h for h in [c.hop.peer for c in self.circuits.values()] if h}
            relay_candidates = self.get_candidates(PEER_FLAG_RELAY)
            possible_first_hops = [c for c in relay_candidates if c not in first_hops and c != required_exit]

        if not possible_first_hops:
            self.logger.info("Could not create circuit, no first hop available")
            return None

        # Finally, construct the Circuit object and send the CREATE message
        circuit_id = self._generate_circuit_id()
        self.circuits[circuit_id] = circuit = Circuit(circuit_id, goal_hops, ctype, required_exit, info_hash)
        self.send_initial_create(circuit, possible_first_hops,
                                 self.settings.circuit_timeout // self.settings.next_hop_timeout)

        return circuit

    def send_initial_create(self, circuit: Circuit, candidate_peers: list[Peer], max_tries: int) -> None:
        """
        Attempt to establish the first hop in a Circuit.
        """
        if self.request_cache.has(RetryRequestCache, circuit.circuit_id):
            self.request_cache.pop(RetryRequestCache, circuit.circuit_id)
            self.logger.info("Retrying first hop for circuit %d", circuit.circuit_id)

        first_hop = random.choice(candidate_peers)
        alt_first_hops = [c for c in candidate_peers if c != first_hop]

        circuit.unverified_hop = Hop(first_hop, flags=self.candidates.get(first_hop))
        circuit.unverified_hop.dh_secret, circuit.unverified_hop.dh_first_part = self.crypto.generate_diffie_secret()

        self.logger.info("Adding first hop %s:%d to circuit %d", *(*first_hop.address, circuit.circuit_id))

        cache = RetryRequestCache(self, circuit, alt_first_hops, max_tries - 1,
                                  self.send_initial_create, self.settings.next_hop_timeout)
        self.request_cache.add(cache)

        self.send_cell(first_hop.address, CreatePayload(circuit.circuit_id,
                                                        cache.packet_identifier,
                                                        self.my_peer.public_key.key_to_bin(),
                                                        circuit.unverified_hop.dh_first_part))

    @task
    async def remove_circuit(self, circuit_id: int, additional_info: str = '', remove_now: bool = False,
                             destroy: bool | int = False) -> None:
        """
        Remove a circuit and optionally send a destroy message.
        """
        if self.request_cache.has(RetryRequestCache, circuit_id):
            self.request_cache.pop(RetryRequestCache, circuit_id)

        circuit_to_remove = self.circuits.get(circuit_id, None)
        if circuit_to_remove is None:
            self.logger.warning('Cannot remove unknown circuit %d', circuit_id)
            return

        self.logger.info("Removing %s circuit %d %s", circuit_to_remove.ctype, circuit_id, additional_info)

        if destroy:
            self.destroy_circuit(circuit_to_remove, reason=destroy)

        circuit_to_remove.close(additional_info)

        if not remove_now or self.settings.remove_tunnel_delay > 0:
            await sleep(self.settings.remove_tunnel_delay)

        circuit = self.circuits.pop(circuit_id, None)
        if circuit:
            self.logger.info("Removed circuit %d %s", circuit_id, additional_info)

    @task
    async def remove_relay(self, circuit_id: int, additional_info: str = '', remove_now: bool = False,
                           destroy: bool = False) -> RelayRoute | None:
        """
        Remove a relay and all information associated with the relay. Return the relays that have been removed.
        """
        # Send destroy
        if destroy:
            self.destroy_relay(circuit_id, reason=destroy)

        if not remove_now or self.settings.remove_tunnel_delay > 0:
            await sleep(self.settings.remove_tunnel_delay)

        self.logger.info("Removing relay %d %s", circuit_id, additional_info)

        return self.relay_from_to.pop(circuit_id, None)

    @task
    async def remove_exit_socket(self, circuit_id: int, additional_info: str = '', remove_now: bool = False,
                                 destroy: bool = False) -> TunnelExitSocket | None:
        """
        Remove an exit socket. Send a destroy message if necessary.
        """
        exit_socket_to_destroy = self.exit_sockets.get(circuit_id, None)
        if exit_socket_to_destroy and destroy:
            self.destroy_exit_socket(exit_socket_to_destroy, reason=destroy)

        if not remove_now or self.settings.remove_tunnel_delay > 0:
            await sleep(self.settings.remove_tunnel_delay)

        self.logger.info("Removing exit socket %d %s", circuit_id, additional_info)
        exit_socket = self.exit_sockets.pop(circuit_id, None)
        if exit_socket:
            # Close socket
            if exit_socket.enabled:
                await exit_socket.close()
            await exit_socket.shutdown_task_manager()
        return exit_socket

    def destroy_circuit(self, circuit: Circuit, reason: int = 0) -> None:
        """
        Send a destroy message over a circuit.

        Note that the circuit will still exist.
        """
        sock_addr = circuit.hop.address
        self.send_destroy(sock_addr, circuit.circuit_id, reason)
        self.logger.info("destroy_circuit %s %s", circuit.circuit_id, sock_addr)

    def destroy_relay(self, circuit_id: int, reason: int = 0) -> None:
        """
        Destroy our relay circuit upon request and forward a destroy message.

        Note that the relay route will still exist.
        """
        relay = self.relay_from_to.get(circuit_id)

        if relay:
            self.logger.info("Send destroy for relay %s -> %s (%s)", circuit_id, relay.circuit_id, relay.hop.address)
            self.send_destroy(relay.hop.address, relay.circuit_id, reason)

    def destroy_exit_socket(self, exit_socket: TunnelExitSocket, reason: int = 0) -> None:
        """
        Destroy an exit socket.

        Note that the exit socket will still exist.
        """
        sock_addr = exit_socket.hop.address
        self.send_destroy(sock_addr, exit_socket.circuit_id, reason)
        self.logger.info("Destroy_exit_socket %s %s", exit_socket.circuit_id, sock_addr)

    def send_cell(self, target_addr: Address, payload: CellablePayload) -> None:
        """
        Send the given payload DIRECTLY to the given peer with the appropriate encryption rules.
        """
        message = self.serializer.pack_serializable(payload)[4:]
        cell = CellPayload(payload.circuit_id, pack('!B', payload.msg_id) + message)
        cell.plaintext = payload.msg_id in NO_CRYPTO_PACKETS
        return self.crypto_endpoint.send_cell(target_addr, cell)

    def send_data(self, target: Address, circuit_id: int, dest_address: Address,
                  source_address: Address, data: bytes) -> None:
        """
        Pack the given binary data and forward it to the given peer.
        """
        payload = DataPayload(circuit_id, dest_address, source_address, data)
        return self.send_cell(target, payload)

    def send_packet(self, target: Address, packet: bytes) -> int:
        """
        Send raw data over the socket to a given peer and return the length of the sent data.
        """
        self.endpoint.send(target, packet)
        return len(packet)

    def send_destroy(self, target: Address, circuit_id: int, reason: int) -> None:
        """
        Send a destroy message directly to the given peer.
        """
        packet = self.ezr_pack(DestroyPayload.msg_id, DestroyPayload(circuit_id, reason))
        self.send_packet(target, packet)

    def _ours_on_created_extended(self, circuit_id: int, payload: CreatedPayload | ExtendedPayload) -> None:
        circuit = self.circuits[circuit_id]
        hop = circuit.unverified_hop

        if not hop or not hop.dh_secret:
            self.logger.error("Can't extend circuit %d (no unverified hop)", circuit_id)
            return

        try:
            shared_secret = self.crypto.verify_and_generate_shared_secret(hop.dh_secret, payload.key, payload.auth,
                                                                          cast(LibNaCLPK, hop.peer.public_key).key.pk)
            session_keys = self.crypto.generate_session_keys(shared_secret)
            hop.keys = session_keys

        except ValueError:
            self.remove_circuit(circuit.circuit_id, "error while verifying shared secret")
            return

        circuit.unverified_hop = None
        circuit.add_hop(hop)
        self.circuits.get(circuit_id)  # Needed for notifying the RustEndpoint
        self.logger.info("Added hop %d (%s) to circuit %d", len(circuit.hops), hop.peer, circuit.circuit_id)

        if circuit.state == CIRCUIT_STATE_EXTENDING:
            candidates_enc = payload.candidates_enc
            candidates_bin = self.crypto.decrypt_str(candidates_enc, session_keys, FORWARD)
            candidates, _ = self.serializer.unpack('varlenH-list', candidates_bin)

            cache = self.request_cache.pop(RetryRequestCache, circuit.circuit_id)
            self.send_extend(circuit, cast(List[bytes], candidates), cache.max_tries if cache else 1)

        elif circuit.state == CIRCUIT_STATE_READY:
            self.request_cache.pop(RetryRequestCache, circuit.circuit_id)

    def send_extend(self, circuit: Circuit, candidates: list[bytes], max_tries: int) -> None:
        """
        Extend a circuit by choosing one of the given candidates.
        """
        become_exit = circuit.goal_hops - 1 == len(circuit.hops)
        if become_exit and circuit.required_exit:
            # Set the required exit according to the circuit setting (e.g. for linking e2e circuits)
            extend_hop_public_bin = circuit.required_exit.public_key.key_to_bin()
            extend_hop_addr = circuit.required_exit.address

        else:
            # Chose the next candidate. Ensure we didn't use this candidate already, and its key is compatible.
            exclude = [hop.public_key_bin for hop in circuit.hops] + [self.my_peer.public_key.key_to_bin()]
            if circuit.required_exit:
                exclude.append(circuit.required_exit.public_key.key_to_bin())
            candidates = [c for c in candidates if c not in exclude and self.crypto.key_from_public_bin(c)]
            extend_hop_public_bin = next(iter(candidates), b'')
            extend_hop_addr = ('0.0.0.0', 0)

            if not extend_hop_public_bin:
                # By default, nodes will give a number of relays to which we can extend the circuit (i.e., peers
                # that have already been punctured). However, it could be that there simply aren't enough relays
                # available. When this happens, we try to extend to exit nodes (which we assume are connectable).
                choices = [peer for peer in self.get_candidates(PEER_FLAG_EXIT_BT, PEER_FLAG_RELAY)
                           if peer.public_key.key_to_bin() not in exclude]
                if choices:
                    peer = random.choice(choices)
                    extend_hop_public_bin = peer.public_key.key_to_bin()
                    extend_hop_addr = peer.address
                    self.logger.info('No candidates to extend to, trying exit node %s instead', peer)

        if extend_hop_public_bin:
            if self.request_cache.has(RetryRequestCache, circuit.circuit_id):
                self.request_cache.pop(RetryRequestCache, circuit.circuit_id)
                self.logger.info("Retrying hop %d for circuit %d", len(circuit.hops) + 1, circuit.circuit_id)

            extend_hop_public_key = self.crypto.key_from_public_bin(extend_hop_public_bin)
            hop = Hop(Peer(extend_hop_public_key), flags=self.candidates.get(Peer(extend_hop_public_bin)))
            hop.dh_secret, hop.dh_first_part = self.crypto.generate_diffie_secret()
            circuit.unverified_hop = hop

            self.logger.info("Extending circuit %d with %s", circuit.circuit_id, hexlify(extend_hop_public_bin))

            # Only retry if we are allowed to use another node
            if not become_exit or not circuit.required_exit:
                alt_candidates = [c for c in candidates if c != extend_hop_public_bin]
            else:
                alt_candidates = []

            cache = RetryRequestCache(self, circuit, alt_candidates, max_tries - 1,
                                      self.send_extend, self.settings.next_hop_timeout)
            self.request_cache.add(cache)

            self.send_cell(circuit.hop.address, ExtendPayload(circuit.circuit_id,
                                                              cache.packet_identifier,
                                                              circuit.unverified_hop.public_key_bin,
                                                              circuit.unverified_hop.dh_first_part,
                                                              extend_hop_addr))

        else:
            self.remove_circuit(circuit.circuit_id, "no candidates to extend")

    def extract_peer_flags(self, extra_bytes: bytes) -> list[int]:
        """
        Convert piggybacked introduction bytes to a list of peer flags.
        """
        if not extra_bytes:
            return []

        payload, _ = self.serializer.unpack_serializable(ExtraIntroductionPayload, extra_bytes)
        return payload.flags

    def introduction_request_callback(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                      payload: IntroductionRequestPayload | NewIntroductionRequestPayload) -> None:
        """
        Try to extract piggybacked data from the introduction request.
        """
        self.candidates[peer] = self.extract_peer_flags(payload.extra_bytes)

    def introduction_response_callback(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                       payload: IntroductionResponsePayload | NewIntroductionResponsePayload) -> None:
        """
        Try to extract piggybacked data from the introduction response.
        """
        self.candidates[peer] = self.extract_peer_flags(payload.extra_bytes)

    def create_introduction_request(self, socket_address: Address, extra_bytes: bytes = b'',
                                    new_style: bool = False, prefix: bytes | None = None) -> bytes:
        """
        Add peer flags to our introduction requests.
        """
        extra_payload = ExtraIntroductionPayload(self.settings.peer_flags)
        extra_bytes = self.serializer.pack_serializable(extra_payload)
        return super().create_introduction_request(socket_address, extra_bytes, new_style)

    def create_introduction_response(self, lan_socket_address: Address, socket_address: Address,  # noqa: PLR0913
                                     identifier: int, introduction: Peer | None = None, extra_bytes: bytes = b'',
                                     prefix: bytes | None = None,
                                     new_style: bool = False) -> bytes:
        """
        Add peer flags to our introduction responses.
        """
        extra_payload = ExtraIntroductionPayload(self.settings.peer_flags)
        extra_bytes = self.serializer.pack_serializable(extra_payload)
        return super().create_introduction_response(lan_socket_address, socket_address,
                                                    identifier, introduction, extra_bytes,
                                                    prefix, new_style)

    def on_cell(self, source_address: Address, data: bytes) -> None:
        """
        Process an incoming cell, originating from a given address.
        """
        cell = CellPayload.from_bin(data)
        if cell.plaintext and cell.message[0] not in NO_CRYPTO_PACKETS:
            self.logger.warning("Got a cell with wrongfully set plaintext flag from circuit %s", cell.circuit_id)
            return

        self.on_packet_from_circuit(source_address, cell.unwrap(self._prefix), cell.circuit_id)

    def on_packet_from_circuit(self, source_address: Address, data: bytes, circuit_id: int) -> None:
        """
        Process incoming raw data, assumed to be an IPv8 packet, originating from a given address.
        """
        if self._prefix != data[:22]:
            return
        msg_id = data[22]
        if msg_id in self.decode_map_private:
            try:
                handler = cast(Callable[[Address, bytes, Optional[int]], None], self.decode_map_private[msg_id])
                result = handler(source_address, data, circuit_id)
                if iscoroutine(result):
                    aw_result = cast(Awaitable, result)
                    self.register_anonymous_task('on_packet_from_circuit', ensure_future(aw_result),
                                                 ignore=(Exception,))
            except Exception:
                self.logger.exception("Exception occurred while handling packet!\n%s",
                                      "".join(format_exception(*sys.exc_info())))

    async def should_join_circuit(self, create_payload: CreatePayload, previous_node_address: Address) -> bool:
        """
        Check whether we should join a circuit.

        Note that this method is intended to be overwritten and, therefore, has unused arguments.
        """
        if self.settings.max_joined_circuits <= len(self.relay_from_to) + len(self.exit_sockets):
            self.logger.warning("Too many relays (%d)", (len(self.relay_from_to) + len(self.exit_sockets)))
            return False
        return True

    def join_circuit(self, create_payload: CreatePayload, previous_node_address: Address) -> None:
        """
        Actively join a circuit and send a created message back.
        """
        circuit_id = create_payload.circuit_id

        self.logger.info('We joined circuit %d with neighbour %s', circuit_id, previous_node_address)

        shared_secret, key, auth = self.crypto.generate_diffie_shared_secret(create_payload.key)
        session_keys = self.crypto.generate_session_keys(shared_secret)

        peers_list = [peer for peer in self.get_candidates(PEER_FLAG_RELAY)
                      if PEER_FLAG_EXIT_BT not in self.candidates.get(peer, [])][:4]
        peers_keys = {peer.public_key.key_to_bin(): peer for peer in peers_list}

        peer = Peer(create_payload.node_public_key, previous_node_address)
        self.request_cache.add(CreatedRequestCache(self, circuit_id, peer, peers_keys, self.settings.unstable_timeout))

        candidates_bin = self.serializer.pack('varlenH-list', list(peers_keys.keys()))
        candidates_enc = self.crypto.encrypt_str(candidates_bin, session_keys, FORWARD)
        self.exit_sockets[circuit_id] = TunnelExitSocket(circuit_id, Hop(peer, session_keys), self)
        self.send_cell(previous_node_address,
                       CreatedPayload(circuit_id, create_payload.identifier, key, auth, candidates_enc))

    @unpack_cell(CreatePayload)
    async def on_create(self, source_address: Address, payload: CreatePayload, _: int | None) -> None:
        """
        Process a request to join someone's circuit.
        """
        if not self.settings.peer_flags:
            self.logger.warning("Ignoring create for circuit %d", payload.circuit_id)
            return
        if self.request_cache.has(CreatedRequestCache, payload.circuit_id):
            self.logger.warning("Already have a request for circuit %d", payload.circuit_id)
            return

        result = await self.should_join_circuit(payload, source_address)
        if result:
            self.join_circuit(payload, source_address)
        else:
            self.logger.warning("We're not joining circuit with ID %s", payload.circuit_id)

    @unpack_cell(CreatedPayload)
    def on_created(self, source_address: Address, payload: CreatedPayload, _: int | None) -> None:
        """
        Callback for when another peer signals that they have joined our circuit.
        """
        circuit_id = payload.circuit_id

        if self.request_cache.has(CreateRequestCache, payload.identifier):
            request = self.request_cache.pop(CreateRequestCache, payload.identifier)

            self.logger.info("Got CREATED message forward as EXTENDED to origin.")

            if request.from_circuit_id not in self.exit_sockets:
                self.logger.info("Created for unknown exit socket %s", request.from_circuit_id)
                return
            session_keys = self.exit_sockets[request.from_circuit_id].hop.keys
            self.remove_exit_socket(request.from_circuit_id, remove_now=True)

            bw_relay = RelayRoute(request.from_circuit_id, Hop(request.peer, session_keys), BACKWARD)
            fw_relay = RelayRoute(request.to_circuit_id, Hop(request.to_peer, session_keys), FORWARD)

            self.relay_from_to[request.to_circuit_id] = bw_relay
            self.relay_from_to[request.from_circuit_id] = fw_relay

            self.send_cell(bw_relay.hop.address,
                           ExtendedPayload(bw_relay.circuit_id, request.extend_identifier,
                                           payload.key, payload.auth, payload.candidates_enc))
            return

        cache = self.request_cache.get(RetryRequestCache, circuit_id)

        # Check payload.identifier to ensure we're not accepting old created messages that have since timed out.
        if cache and cache.packet_identifier == payload.identifier:
            self._ours_on_created_extended(circuit_id, payload)
        else:
            self.logger.warning("Received unexpected created for circuit %d", circuit_id)

    @unpack_cell(ExtendPayload)
    async def on_extend(self, source_address: Address, payload: ExtendPayload, _: int | None) -> None:
        """
        Callback for when a peer asks us to extend for their circuit.
        """
        if PEER_FLAG_RELAY not in self.settings.peer_flags:
            self.logger.warning("Ignoring create for circuit %d", payload.circuit_id)
            return

        circuit_id = payload.circuit_id
        # Leave the RequestCache in case the circuit owner wants to reuse the tunnel for a different next-hop
        request = self.request_cache.get(CreatedRequestCache, circuit_id)

        if request is None:
            self.logger.warning("Received unexpected extend for circuit %d", payload.circuit_id)
            return

        if payload.node_addr == ('0.0.0.0', 0) and payload.node_public_key not in request.candidates:
            self.logger.warning("Node public key not in request candidates and no ip specified")
            return

        if payload.node_public_key in request.candidates:
            extend_candidate = request.candidates[payload.node_public_key]
        else:
            known_candidate = self.network.get_verified_by_public_key_bin(payload.node_public_key)
            extend_candidate = (Peer(payload.node_public_key, payload.node_addr) if known_candidate is None
                                else known_candidate)

            # Ensure that we are able to contact this peer
            if extend_candidate.last_response + 57.5 < time.time():
                await self.dht_peer_lookup(extend_candidate.mid, peer=extend_candidate)

        self.logger.info("On_extend send CREATE for circuit (%s, %d) to %s:%d", source_address,
                         circuit_id, *extend_candidate.address)

        to_circuit_id = self._generate_circuit_id()

        if circuit_id in self.circuits:
            candidate = self.circuits[circuit_id].hop.peer
        elif circuit_id in self.exit_sockets:
            candidate = self.exit_sockets[circuit_id].hop.peer
        elif circuit_id in self.relay_from_to:
            candidate = self.relay_from_to[circuit_id].hop.peer
        else:
            self.logger.error("Got extend for unknown source circuit_id")
            return

        self.logger.info("Extending circuit, got candidate with IP %s:%d from cache", *extend_candidate.address)

        cache = CreateRequestCache(self, payload.identifier, to_circuit_id, circuit_id, cast(Peer, candidate),
                                   extend_candidate)
        self.request_cache.add(cache)

        self.send_cell(extend_candidate.address,
                       CreatePayload(to_circuit_id, cache.number, self.my_peer.public_key.key_to_bin(), payload.key))

    @unpack_cell(ExtendedPayload)
    def on_extended(self, source_address: Address, payload: ExtendedPayload, _: int | None) -> None:
        """
        Callback for when a peer signals that they have extended our circuit.
        """
        circuit_id = payload.circuit_id
        cache = self.request_cache.get(RetryRequestCache, circuit_id)
        if not cache or cache.packet_identifier != payload.identifier:
            self.logger.warning("Received unexpected extended for circuit %s", circuit_id)
            return

        self._ours_on_created_extended(circuit_id, payload)

    def on_raw_data(self, circuit: Circuit, origin: Address, data: bytes) -> None:
        """
        Handle data, coming from a specific circuit and origin.
        This method is usually implemented in subclasses of this community.
        """

    def on_data(self, sock_addr: Address, data: bytes, _: int | None) -> None:
        """
        Callback for when we receive a DataPayload out of a circuit.

        Data is readable only if this handler is (a) an exit node or (b) the one that created the circuit.
        """
        payload, _ = self.serializer.unpack_serializable(DataPayload, data, offset=23)

        # If its our circuit, the messenger is the candidate assigned to that circuit and the DATA's destination
        # is set to the zero-address then the packet is from the outside world and addressed to us from.
        circuit_id = payload.circuit_id
        destination = payload.dest_address
        origin = payload.org_address
        data = payload.data

        self.logger.debug("Got data (%d) from %s", circuit_id, sock_addr)

        circuit = self.circuits.get(circuit_id, None)
        if circuit and origin and sock_addr == circuit.hop.address:
            circuit.beat_heart()

            e2e_data = circuit.ctype in [CIRCUIT_TYPE_RP_DOWNLOADER, CIRCUIT_TYPE_RP_SEEDER]
            if DataChecker.could_be_ipv8(data) and not e2e_data:
                if self._prefix == data[:22]:
                    self.logger.debug("Incoming packet meant for us")
                    self.on_packet_from_circuit(origin, data, circuit_id)
                    return

                if isinstance(self.endpoint, TunnelEndpoint):
                    self.logger.debug("Incoming packet meant for other community")
                    self.endpoint.notify_listeners((origin, data), from_tunnel=True)
                else:
                    self.logger.debug("Incoming packet meant for other community, dropping")
            else:
                # We probably received raw data, handle it
                self.on_raw_data(circuit, origin, data)

        # It is not our circuit so we got it from a relay, we need to EXIT it!
        else:
            self.logger.debug("Data for circuit %d exiting tunnel (%s)", circuit_id, destination)
            if destination != ('0.0.0.0', 0):
                self.exit_data(circuit_id, sock_addr, destination, data)
            else:
                self.logger.warning("Cannot exit data, destination is 0.0.0.0:0")

    @unpack_cell(PingPayload)
    def on_ping(self, source_address: Address, payload: PingPayload, _: int | None) -> None:
        """
        Callback for when we received a tunneled ping message.
        """
        if not (payload.circuit_id in self.circuits
                or payload.circuit_id in self.exit_sockets
                or payload.circuit_id in self.relay_from_to):
            return

        exit_socket = self.exit_sockets.get(payload.circuit_id)
        if exit_socket:
            exit_socket.beat_heart()

        self.send_cell(source_address, PongPayload(payload.circuit_id, payload.identifier))
        self.logger.debug("Got ping from %s", source_address)

    @unpack_cell(PongPayload)
    def on_pong(self, source_address: Address, payload: PongPayload, _: int | None) -> None:
        """
        Callback for when we received a tunneled pong (response) message.
        """
        if not self.request_cache.has(PingRequestCache, payload.identifier):
            self.logger.warning("Invalid ping circuit_id")
            return

        self.request_cache.pop(PingRequestCache, payload.identifier)
        self.logger.debug("Got pong from %s", source_address)

        circuit = self.circuits.get(payload.circuit_id)
        if circuit:
            circuit.beat_heart()

    def do_ping(self, exclude: list[int] | None = None) -> None:
        """
        Ping circuits. Pings are only sent to the first hop, subsequent hops will relay the ping.
        """
        exclude = [] if exclude is None else exclude
        for circuit in list(self.circuits.values()):
            if circuit.state in [CIRCUIT_STATE_READY, CIRCUIT_STATE_EXTENDING] \
                    and circuit.circuit_id not in exclude \
                    and circuit.hops:
                cache = PingRequestCache(self)
                self.request_cache.add(cache)
                self.send_cell(circuit.hop.address, PingPayload(circuit.circuit_id, cache.number))

    @lazy_wrapper(DestroyPayload)
    def on_destroy(self, peer: Peer, payload: DestroyPayload) -> None:
        """
        Callback for when we received a destroy message.
        """
        source_address = peer.address
        circuit_id = payload.circuit_id
        self.logger.info("Got destroy from %s for circuit %s", source_address, circuit_id)

        # Find the RelayRoute object for the other direction (if any).
        next_relay = self.relay_from_to.get(circuit_id)
        prev_relay = self.relay_from_to.get(next_relay.circuit_id) if next_relay else None
        if prev_relay and peer == prev_relay.hop.peer:
            self.remove_relay(circuit_id, f"got destroy with reason {payload.reason}", destroy=payload.reason)
            self.remove_relay(cast(RelayRoute, next_relay).circuit_id, f"got destroy with reason {payload.reason}")

        elif circuit_id in self.exit_sockets and peer == self.exit_sockets[circuit_id].hop.peer:
            self.remove_exit_socket(circuit_id, f"got destroy with reason {payload.reason}")

        elif circuit_id in self.circuits and peer == self.circuits[circuit_id].hop.peer:
            self.remove_circuit(circuit_id, f"got destroy with reason {payload.reason}")

        else:
            self.logger.warning("Invalid or unauthorized destroy")

    def exit_data(self, circuit_id: int, sock_addr: Address, destination: Address, data: bytes) -> None:
        """
        Exit data (to the destination) out of the exit socket associated with the given circuit id.
        """
        if circuit_id not in self.exit_sockets:
            self.logger.error("Dropping data packets with unknown circuit_id")
            return

        if not self.exit_sockets[circuit_id].enabled:
            # Check that we got the data from the correct IP.
            if sock_addr[0] == self.exit_sockets[circuit_id].hop.address[0]:
                self.exit_sockets[circuit_id].enable()
            else:
                self.logger.error("Dropping outbound relayed packet: IP's are %s != %s",
                                  str(sock_addr), str(self.exit_sockets[circuit_id].hop.address))
                return
        try:
            self.exit_sockets[circuit_id].sendto(data, destination)
        except Exception:
            self.logger.warning("Dropping data packets while exiting")

    async def dht_peer_lookup(self, mid: bytes, peer: Peer | None = None) -> None:
        """
        Perform a DHT lookup for a given SHA-1 hash of a public key.

        Note that connections (if any) will be performed in the background. Query for results manually later.
        """
        if self.dht_provider:
            await self.dht_provider.peer_lookup(mid, peer)
        else:
            self.logger.error("Need a DHT provider to connect to a peer using the DHT")

    def send_test_request(self, circuit: Circuit, request_size: int = 0,
                          response_size: int = 0) -> Future[tuple[bytes, float]]:
        """
        Send a speed test request and wait for a (data, RTT time in seconds) tuple to be recorded.
        """
        cache = TestRequestCache(self, circuit)
        self.request_cache.add(cache)
        self.send_cell(circuit.hop.address,
                       TestRequestPayload(circuit.circuit_id, cache.number, response_size, os.urandom(request_size)))
        return cache.future

    def on_test_request(self, source_address: Address, data: bytes, circuit_id: int | None) -> None:
        """
        Callback for when we receive a speed test request.
        """
        if PEER_FLAG_SPEED_TEST not in self.settings.peer_flags:
            self.logger.warning("Ignoring test-request from circuit %d", circuit_id)
            return

        if circuit_id is None:
            self.logger.error("Dropping test-request without circuit_id")
            return

        payload, _ = self.serializer.unpack_serializable(TestRequestPayload, data, offset=23)
        exit_socket = self.exit_sockets.get(circuit_id)
        circuit = self.circuits.get(circuit_id)
        if not exit_socket and not (circuit and circuit.ctype in [CIRCUIT_TYPE_RP_SEEDER, CIRCUIT_TYPE_RP_DOWNLOADER]):
            self.logger.error("Dropping test-request with unknown circuit_id")
            return

        self.logger.debug("Got test-request (%d) from %s, replying with response", circuit_id, source_address)
        if exit_socket:
            exit_socket.beat_heart()
        self.send_cell(source_address,
                       TestResponsePayload(circuit_id, payload.identifier, os.urandom(payload.response_size)))

    def on_test_response(self, source_address: Address, data: bytes, circuit_id: int | None) -> None:
        """
        Callback for when we received a test response.

        We record the data that the response contained and the time since we sent the original request.
        """
        if circuit_id is None:
            self.logger.error("Dropping test-response without circuit_id")
            return

        payload, _ = self.serializer.unpack_serializable(TestResponsePayload, data, offset=23)
        circuit = self.circuits.get(circuit_id)
        if circuit is None:
            self.logger.error("Dropping test-response with unknown circuit_id")
            return
        if not self.request_cache.has(TestRequestCache, payload.identifier):
            self.logger.warning("Dropping unexpected test-response")
            return

        self.logger.debug("Got test-response (%d) from %s", circuit_id, source_address)
        cache = self.request_cache.pop(TestRequestCache, payload.identifier)
        cache.future.set_result((payload.data, time.time() - cache.ts))
