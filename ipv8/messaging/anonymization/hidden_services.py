"""
The hidden tunnel community.

Author(s): Egbert Bouman
"""
from __future__ import annotations

import binascii
import os
import random
import socket
import struct
from asyncio import gather, iscoroutine
from typing import TYPE_CHECKING, Any, Coroutine, Set, Tuple, cast

from ...bootstrapping.dispersy.bootstrapper import DispersyBootstrapper
from ...configuration import DISPERSY_BOOTSTRAPPER
from ...keyvault.private.libnaclkey import LibNaCLSK
from ...keyvault.public.libnaclkey import LibNaCLPK
from ...messaging.anonymization.pex import PexCommunity, PexSettings
from ...peer import Peer
from ...peerdiscovery.churn import RandomChurn
from ...peerdiscovery.discovery import RandomWalk
from ...peerdiscovery.network import Network
from ...taskmanager import task
from ...util import fail
from .caches import *
from .community import TunnelCommunity, TunnelSettings, unpack_cell
from .exit_socket import TunnelExitSocket
from .payload import *
from .tunnel import (
    CIRCUIT_ID_PORT,
    CIRCUIT_STATE_READY,
    CIRCUIT_TYPE_IP_SEEDER,
    CIRCUIT_TYPE_RP_DOWNLOADER,
    CIRCUIT_TYPE_RP_SEEDER,
    DESTROY_REASON_UNNEEDED,
    FORWARD,
    PEER_SOURCE_DHT,
    PEER_SOURCE_PEX,
    Hop,
    IntroductionPoint,
    RelayRoute,
    RendezvousPoint,
    Swarm,
)

if TYPE_CHECKING:
    from ...types import IPv8


class HiddenTunnelSettings(TunnelSettings):
    """
    Settings for the hidden tunnel community.
    """

    ipv8: IPv8 | None = None

    e2e_callbacks: dict[bytes, Callable[[Address], None] | None] | None = None


class HiddenTunnelCommunity(TunnelCommunity):
    """
    Extension of TunnelCommunity logic to link up circuits and create closed-loop e2e circuits.
    """

    settings_class = HiddenTunnelSettings

    def __init__(self, settings: HiddenTunnelSettings) -> None:
        """
        Create a new e2e-capable tunnel community.
        """
        self.ipv8 = settings.ipv8
        self.e2e_callbacks: dict[bytes, Callable[[Address], None] | None] = ({} if settings.e2e_callbacks is None
                                                                             else settings.e2e_callbacks)

        self.swarms: dict[bytes, Swarm] = {}
        self.pex: dict[bytes, PexCommunity] = {}

        super().__init__(settings)

        self.intro_point_for: dict[bytes, tuple[TunnelExitSocket,
                                                bytes]] = {}  # {seeder_pk: (TunnelExitSocket, info_hash)}
        self.rendezvous_point_for: dict[bytes, TunnelExitSocket] = {}  # {cookie: TunnelExitSocket}

        # Messages that can arrive from the socket
        # The circuit id is optional, so we can safely cast these handlers.
        self.add_message_handler(CreateE2EPayload, cast(Callable[[Tuple[str, int], bytes], None],
                                                        self.on_create_e2e))
        self.add_message_handler(PeersRequestPayload, cast(Callable[[Tuple[str, int], bytes], None],
                                                           self.on_peers_request))
        self.add_message_handler(PeersResponsePayload, cast(Callable[[Tuple[str, int], bytes], None],
                                                            self.on_peers_response))

        # Messages that can arrive from a circuit (i.e., they are wrapped in a cell)
        self.add_cell_handler(EstablishIntroPayload, self.on_establish_intro)
        self.add_cell_handler(IntroEstablishedPayload, self.on_intro_established)
        self.add_cell_handler(EstablishRendezvousPayload, self.on_establish_rendezvous)
        self.add_cell_handler(RendezvousEstablishedPayload, self.on_rendezvous_established)
        self.add_cell_handler(CreateE2EPayload, self.on_create_e2e)
        self.add_cell_handler(CreatedE2EPayload, self.on_created_e2e)
        self.add_cell_handler(LinkE2EPayload, self.on_link_e2e)
        self.add_cell_handler(LinkedE2EPayload, self.on_linked_e2e)
        self.add_cell_handler(PeersRequestPayload, self.on_peers_request)
        self.add_cell_handler(PeersResponsePayload, self.on_peers_response)

        self.register_task("do_peer_discovery", self.do_peer_discovery, interval=10)

    def join_swarm(self, info_hash: bytes, hops: int, callback: Callable[[Address], None] | None = None,
                   seeding: bool = True) -> None:
        """
        Join a hidden swarm. This should be called by both the downloader and the seeder. Calling this method while
        already part of the swarm will cause the community to drop all pre-existing connections.
        Note that the seeder should also create introduction points by calling create_introduction_point().

        :param info_hash: the swarm identifier
        :param hops: the amount of hops for our introduction/rendezvous circuits
        :param callback: the callback function to call when we have established an e2e circuit
        :param seeding: whether the swarm should be joined as seeder
        """
        if info_hash in self.swarms:
            self.logger.warning('Already part of hidden swarm %s, leaving existing', binascii.hexlify(info_hash))
            self.leave_swarm(info_hash)

        self.swarms[info_hash] = Swarm(info_hash, hops, self.send_peers_request,
                                       cast(LibNaCLSK, self.crypto.generate_key("curve25519")) if seeding else None)
        self.e2e_callbacks[info_hash] = callback

    def leave_swarm(self, info_hash: bytes) -> None:
        """
        Leave a hidden swarm. Can be called by both the downloader and the seeder.

        :param info_hash: the swarm identifier
        """
        # Remove all introduction points and e2e circuits for this swarm
        for circuit in self.circuits.values():
            if circuit.info_hash == info_hash and circuit.ctype in [CIRCUIT_TYPE_IP_SEEDER,
                                                                    CIRCUIT_TYPE_RP_SEEDER,
                                                                    CIRCUIT_TYPE_RP_DOWNLOADER]:
                _ = self.remove_circuit(circuit.circuit_id, 'leaving hidden swarm', destroy=DESTROY_REASON_UNNEEDED)
        # Remove swarm and callback
        self.swarms.pop(info_hash, None)
        self.e2e_callbacks.pop(info_hash, None)

    async def estimate_swarm_size(self, info_hash: bytes, hops: int = 1, max_requests: int = 10) -> int:
        """
        Estimate the number of unique seeders that are part of a hidden swarm.

        :param info_hash: the swarm identifier
        :param hops: the amount of hops to use for contacting introduction points
        :param max_requests: the number of introduction points we should send a get-peers message to
        :return: number of unique seeders
        """
        swarm = Swarm(info_hash, hops, self.send_peers_request)

        # None represents a DHT request
        all_: list[IntroductionPoint | None] = [None]
        tried: Set[IntroductionPoint | None] = set()

        while len(tried) < max_requests:
            not_tried = set(all_) - tried
            if not not_tried:
                break

            # Issue as many requests as possible in parallel
            ips = random.sample(list(not_tried), min(len(not_tried), max_requests - len(tried)))
            responses = await gather(*[swarm.lookup(ip) for ip in ips], return_exceptions=True)

            # Collect responses
            for result in responses:
                if result and not isinstance(result, (BaseException, Exception)):
                    all_.extend(result)
            tried |= set(ips)

        return len({ip.seeder_pk for ip in all_ if ip is not None and ip.source == PEER_SOURCE_PEX})

    def select_circuit_for_infohash(self, info_hash: bytes) -> Circuit | None:
        """
        Get a circuit that connectes to the swarm of the given SHA-1 hash.
        """
        swarm = self.swarms.get(info_hash)
        if not swarm or not swarm.hops:
            self.logger.info('Can\'t get hop count, download cancelled?')
            return None

        return self.select_circuit(None, swarm.hops)

    def create_circuit_for_infohash(self, info_hash: bytes, ctype: str, exit_flags: Set[int] | None = None,
                                    required_exit: Peer | None = None) -> Circuit | None:
        """
        Create a circuit that connects to the swarm given by the SHA-1 (info) hash.
        """
        swarm = self.swarms.get(info_hash)
        if not swarm or not swarm.hops:
            self.logger.info('Can\'t get hop count, download cancelled?')
            return None

        # Introduction point circuits need an additional hop, or we will talk directly to the the introduction point.
        # Also, rendezvous circuits need an additional hop, since the seeder chooses the rendezvous_point.
        hops = swarm.hops
        if ctype in [CIRCUIT_TYPE_IP_SEEDER, CIRCUIT_TYPE_RP_DOWNLOADER]:
            hops += 1

        return self.create_circuit(hops, ctype, exit_flags, required_exit, info_hash)

    def ip_to_circuit_id(self, ip_str: str) -> int:
        """
        Convert an IP to a (special) circuit id.
        """
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]

    def circuit_id_to_ip(self, circuit_id: int) -> str:
        """
        Convert an IP-embedded circuit id back to the original IP.
        """
        return socket.inet_ntoa(struct.pack("!I", circuit_id))

    async def do_peer_discovery(self) -> None:
        """
        Find peers in the swarms that we are a part of.
        """
        now = time.time()
        for info_hash, swarm in list(self.swarms.items()):
            if not swarm.seeding and swarm.last_lookup + self.settings.swarm_lookup_interval <= now \
               and swarm.get_num_connections() < self.settings.swarm_connection_limit:
                try:
                    ips = await swarm.lookup()
                except (IndexError, RuntimeError):
                    self.logger.info('Failed to do peer discovery for swarm %s', binascii.hexlify(info_hash))
                    continue

                if ips is None:
                    self.logger.info('Skipping peer discovery for swarm %s', binascii.hexlify(info_hash))
                    continue
                self.logger.info('Found %d/%d peer(s) for swarm %s',
                                 len([ip for ip in ips if ip.source == PEER_SOURCE_DHT]),
                                 len([ip for ip in ips if ip.source == PEER_SOURCE_PEX]),
                                 binascii.hexlify(info_hash))
                for ip in set(ips):
                    swarm.add_intro_point(ip)
                for ip in swarm.intro_points:
                    if not swarm.has_connection(ip.seeder_pk):
                        self.create_e2e(info_hash, ip)

    def do_circuits(self) -> None:
        """
        Beyond normal circuit creation, make sure we have circuits for introduction points.
        """
        super().do_circuits()

        # Make sure we have at least 1 data circuit for every hop count. This circuit will be used for
        # communication with introduction points.
        for hop_count in {swarm.hops for swarm in self.swarms.values()}:
            if not self.find_circuits(state=None, hops=hop_count):
                self.create_circuit(hop_count)

    def do_ping(self, exclude: list[int] | None = None) -> None:
        """
        Ping all circuits, except pending e2e circuits.
        """
        exclude = [] if exclude is None else exclude
        exclude += [c.circuit_id for c in self.circuits.values()
                    if (c.ctype == CIRCUIT_TYPE_RP_SEEDER) or (c.ctype == CIRCUIT_TYPE_RP_DOWNLOADER and not c.e2e)]
        super().do_ping(exclude=exclude)

    def remove_circuit(self, circuit_id: int, additional_info: str = '', remove_now: bool = False,
                       destroy: bool | int = False) -> Coroutine[Any, Any, None]:
        """
        Remove the given circuit and update any swarms it may be part of.
        """
        circuit = self.circuits.get(circuit_id, None)
        if circuit and circuit.ctype == CIRCUIT_TYPE_RP_DOWNLOADER:
            swarm = self.swarms.get(cast(bytes, circuit.info_hash))
            if swarm:
                swarm.remove_connection(circuit)
        return super().remove_circuit(circuit_id, additional_info, remove_now, destroy)

    def remove_exit_socket(self, circuit_id: int, additional_info: str = '', remove_now: bool = False,
                           destroy: bool = False) -> Coroutine[Any, Any, TunnelExitSocket | None]:
        """
        Remove the given exit circuit, remove associated rendezvous points and update any PEX communities
        it may be part of.
        """
        for seeder_pk, (intro_circuit, info_hash) in list(self.intro_point_for.items()):
            if intro_circuit.circuit_id == circuit_id:
                self.intro_point_for.pop(seeder_pk)

                # Stop announcing in PEX community
                pex = self.pex.get(info_hash)
                if pex:
                    pex.stop_announce(seeder_pk)

                    # Unload PEX community
                    if pex.done:
                        self.pex.pop(info_hash, None)
                        if self.ipv8 is not None:
                            self.ipv8.overlays.remove(pex)
                            self.ipv8.strategies = [t for t in self.ipv8.strategies if t[0].overlay != pex]
                        self.register_anonymous_task('unload_pex', pex.unload)

        for cookie, rendezvous_circuit in list(self.rendezvous_point_for.items()):
            if rendezvous_circuit.circuit_id == circuit_id:
                self.rendezvous_point_for.pop(cookie)

        return super().remove_exit_socket(circuit_id, additional_info, remove_now, destroy)

    def get_max_time(self, circuit_id: int) -> float:
        """
        Get the maximum time that a given circuit is allowed to exist.
        """
        if circuit_id in self.circuits and self.circuits[circuit_id].ctype == CIRCUIT_TYPE_IP_SEEDER:
            return self.settings.max_time_ip
        if circuit_id in self.exit_sockets and circuit_id in [c.circuit_id for c, _ in self.intro_point_for.values()]:
            return self.settings.max_time_ip
        return super().get_max_time(circuit_id)

    def tunnel_data(self, circuit: Circuit | TunnelExitSocket, destination: Address,
                    payload: VariablePayloadWID) -> None:
        """
        Send any serializable payload to the next hop in the circuit.
        """
        packet = self.ezr_pack(payload.msg_id, payload, sig=False)
        pre = ('0.0.0.0', 0)
        post = ('0.0.0.0', 0)
        if isinstance(circuit, TunnelExitSocket):
            post = destination
        else:
            pre = destination
        self.send_data(circuit.hop.address, circuit.circuit_id, pre, post, packet)

    def select_circuit(self, destination: Address | None, hops: int) -> Circuit | None:
        """
        Make sure that we select the right circuit when dealing with an e2e connection.
        """
        if destination is not None and destination[1] == CIRCUIT_ID_PORT:
            circuit_id = self.ip_to_circuit_id(destination[0])
            circuit = self.circuits.get(circuit_id, None)

            if circuit and circuit.state == CIRCUIT_STATE_READY and \
               circuit.ctype == CIRCUIT_TYPE_RP_DOWNLOADER:
                return circuit

        circuits = self.find_circuits(hops=hops)
        return random.choice(circuits) if circuits else None

    def send_peers_request(self, info_hash: bytes, target: IntroductionPoint | None,
                           hops: int) -> Future[list[IntroductionPoint]]:
        """
        Attempt to find peers for a given SHA-1 (info) hash.
        """
        circuit = self.select_circuit(None, hops)
        if not circuit:
            self.logger.info("No circuit for peers-request")
            return fail(RuntimeError("No circuit for peers-request"))

        # Send a peers-request message over this circuit
        cache = PeersRequestCache(self, circuit, info_hash, target)
        self.request_cache.add(cache)
        payload = PeersRequestPayload(circuit.circuit_id, cache.number, info_hash)

        # Ask an introduction point if available (in which case we'll use PEX), otherwise let
        # the exit node do a DHT request.
        if target is not None and target.peer.public_key != circuit.hops[-1].public_key:
            self.tunnel_data(circuit, target.peer.address, payload)
            self.logger.info("Sending peers request (intro point %s)", target.peer)
        else:
            self.send_cell(circuit.hop.address, payload)
            self.logger.info("Sending peers request as cell")
        return cache.future

    @unpack_cell(PeersRequestPayload)
    async def on_peers_request(self, source_address: Address, payload: PeersRequestPayload,
                               circuit_id: int | None = None) -> None:
        """
        Callback for when someone wants us to find peers for their circuit.
        """
        info_hash = payload.info_hash
        self.logger.info("Doing hidden seeders lookup for info_hash %s", binascii.hexlify(info_hash))
        if info_hash in self.pex:
            # Get peers from PEX community
            intro_points = self.pex[info_hash].get_intro_points()
            self.send_peers_response(source_address, payload, intro_points, circuit_id)
        elif circuit_id in self.exit_sockets:
            # Get peers from DHT community
            results = await self.dht_lookup(info_hash)
            if results:
                _, intro_points = results
                self.send_peers_response(source_address, payload, intro_points, circuit_id)
        elif circuit_id is not None:
            self.logger.warning("Received a peers-request over circuit %d, but unable to do a DHT lookup", circuit_id)
        else:
            self.logger.warning("Received a peers-request over the socket, but unable to do a PEX lookup")

    def send_peers_response(self, target_addr: Address, request: PeersRequestPayload,
                            intro_points: list[IntroductionPoint], circuit_id: int | None) -> None:
        """
        Send a response with the peers that we found through the DHT.
        """
        peers = [IntroductionInfo(ip.peer.address, ip.peer.public_key.key_to_bin(), ip.seeder_pk, ip.source)
                 for ip in random.sample(intro_points, min(len(intro_points), 7))]
        payload = PeersResponsePayload(request.circuit_id, request.identifier, request.info_hash, peers)

        if circuit_id is not None:
            # Send back to origin
            self.send_cell(target_addr, payload)
        else:
            # Send back to exit node
            packet = self.ezr_pack(payload.msg_id, payload, sig=False)
            self.send_packet(target_addr, packet)

    @unpack_cell(PeersResponsePayload)
    def on_peers_response(self, source_address: Address, payload: PeersResponsePayload, circuit_id: int | None) -> None:
        """
        Callback for when someone performed a DHT lookup for us.
        """
        if not self.request_cache.has(PeersRequestCache, payload.identifier):
            self.logger.warning('Got a peers-response with an unknown identifier')
            return
        cache = self.request_cache.pop(PeersRequestCache, payload.identifier)

        self.logger.info("Received peers-response containing %d peers", len(payload.peers))
        ips = [IntroductionPoint(Peer(peer.key, address=peer.address), peer.seeder_pk, peer.source)
               for peer in payload.peers if peer.address != ('0.0.0.0', 0)]
        cache.future.set_result(ips)

    def create_e2e(self, info_hash: bytes, intro_point: IntroductionPoint) -> None:
        """
        Create an e2e bridge for the given SHA-1 (info) hash over the given introduction point.
        """
        circuit = self.select_circuit_for_infohash(info_hash)
        if not circuit:
            self.logger.error("No circuit for contacting the introduction point")
            return

        hop = Hop(Peer(LibNaCLPK(intro_point.seeder_pk[10:])))
        hop.dh_secret, hop.dh_first_part = self.crypto.generate_diffie_secret()
        self.logger.info('Creating e2e circuit for introduction point %s', intro_point.peer)
        cache = E2ERequestCache(self, info_hash, hop, intro_point)
        self.request_cache.add(cache)
        self.tunnel_data(circuit, intro_point.peer.address,
                         CreateE2EPayload(cache.number, info_hash, hop.public_key_bin, hop.dh_first_part))

    @unpack_cell(CreateE2EPayload)
    async def on_create_e2e(self, source_address: Address, payload: CreateE2EPayload,
                            circuit_id: int | None = None) -> None:
        """
        Callback for when we receive a creation message for an e2e circuit.
        """
        # If we have received this message over a socket, we need to forward it
        if circuit_id is None:
            if payload.node_public_key in self.intro_point_for:
                self.logger.info('On create-e2e: forwarding message because received over socket')
                relay_circuit, _ = self.intro_point_for[payload.node_public_key]
                self.tunnel_data(relay_circuit, source_address, payload)
            else:
                self.logger.info('On create-e2e: dropping message for unknown seeder key %s',
                                 binascii.hexlify(payload.node_public_key))
        else:
            self.logger.info('On create-e2e: creating rendezvous point')
            swarm = self.swarms.get(payload.info_hash)
            if swarm and swarm.seeding:
                rp = await self.create_rendezvous_point(payload.info_hash)
                if rp and await rp.ready:
                    self.create_created_e2e(rp, source_address, payload, circuit_id)

    def create_created_e2e(self, rp: RendezvousPoint, source_address: Address,
                           payload: CreateE2EPayload, circuit_id: int | None) -> None:
        """
        Callback for when we receive "create" or "created" payloads.
        """
        key = self.swarms[payload.info_hash].seeder_sk
        shared_secret, y, auth = self.crypto.generate_diffie_shared_secret(payload.key, key)
        rp.circuit.hs_session_keys = self.crypto.generate_session_keys(shared_secret)

        rp_info = RendezvousInfo(rp.address, rp.circuit.hops[-1].public_key.key_to_bin(), rp.cookie)
        rp_info_bin = self.serializer.pack('payload', rp_info)
        rp_info_enc = self.crypto.encrypt_str(rp_info_bin, rp.circuit.hs_session_keys, FORWARD)

        self.circuits.get(rp.circuit.circuit_id)  # Needed for notifying the RustEndpoint
        circuit = self.circuits[cast(int, circuit_id)]
        self.tunnel_data(circuit, source_address, CreatedE2EPayload(payload.identifier, y, auth, rp_info_enc))

    @unpack_cell(CreatedE2EPayload)
    async def on_created_e2e(self, source_address: Address, payload: CreatedE2EPayload, circuit_id: int | None) -> None:
        """
        Callback for when peers signal that they have created an e2e circuit.
        """
        if not self.request_cache.has(E2ERequestCache, payload.identifier):
            self.logger.warning("Invalid created-e2e identifier")
            return

        cache = self.request_cache.pop(E2ERequestCache, payload.identifier)
        shared_secret = self.crypto.verify_and_generate_shared_secret(cast(LibNaCLSK, cache.hop.dh_secret),
                                                                      payload.key,
                                                                      payload.auth,
                                                                      cache.hop.public_key.key.pk)
        session_keys = self.crypto.generate_session_keys(shared_secret)

        rp_info_enc = payload.rp_info_enc
        rp_info_bin = self.crypto.decrypt_str(rp_info_enc, session_keys, FORWARD)
        rp_info, _ = cast(Tuple[RendezvousInfo, int], self.serializer.unpack(RendezvousInfo, rp_info_bin))

        required_exit = Peer(rp_info.key, rp_info.address)
        circuit = self.create_circuit_for_infohash(cache.info_hash, CIRCUIT_TYPE_RP_DOWNLOADER,
                                                   required_exit=required_exit)
        if circuit:
            self.swarms[cache.info_hash].add_connection(circuit, cache.intro_point)
            if await circuit.ready:
                link_cache = LinkRequestCache(self, circuit, cache.info_hash, session_keys)
                self.request_cache.add(link_cache)
                self.send_cell(circuit.hop.address,
                               LinkE2EPayload(circuit.circuit_id, link_cache.number, rp_info.cookie))

    @unpack_cell(LinkE2EPayload)
    def on_link_e2e(self, source_address: Address, payload: LinkE2EPayload, circuit_id: int | None) -> None:
        """
        Callback for when an e2e circuit attempts to link up sender and receiver.
        """
        if payload.cookie not in self.rendezvous_point_for:
            self.logger.warning("Not a rendezvous point for this cookie")
            return

        if circuit_id is None:
            self.logger.warning("Attempted link without circuit id")
            return

        exit_socket = self.exit_sockets[circuit_id]
        if exit_socket.enabled:
            self.logger.warning("Exit socket for circuit is enabled, cannot link")
            return

        relay_circuit = self.rendezvous_point_for[payload.cookie]
        exit_socket_rp = self.exit_sockets[relay_circuit.circuit_id]
        if exit_socket_rp.enabled:
            self.logger.warning("Exit socket for relay_circuit is enabled, cannot link")
            return

        _ = self.remove_exit_socket(exit_socket.circuit_id, 'linking circuit')
        _ = self.remove_exit_socket(exit_socket_rp.circuit_id, 'linking circuit')

        self.relay_from_to[exit_socket.circuit_id] = RelayRoute(exit_socket_rp.circuit_id,
                                                                Hop(exit_socket_rp.hop.peer, exit_socket.hop.keys),
                                                                FORWARD, True)
        self.relay_from_to[exit_socket_rp.circuit_id] = RelayRoute(exit_socket.circuit_id,
                                                                   Hop(exit_socket.hop.peer, exit_socket_rp.hop.keys),
                                                                   FORWARD, True)

        self.send_cell(source_address, LinkedE2EPayload(exit_socket.circuit_id, payload.identifier))

    @unpack_cell(LinkedE2EPayload)
    def on_linked_e2e(self, source_address: Address, payload: LinkedE2EPayload, circuit_id: int | None) -> None:
        """
        Callback for when a sender and receiver circuit have been linked up.
        """
        if not self.request_cache.has(LinkRequestCache, payload.identifier):
            self.logger.warning("Invalid linked-e2e identifier")
            return

        cache = self.request_cache.pop(LinkRequestCache, payload.identifier)
        circuit = cache.circuit
        circuit.e2e = True
        circuit.hs_session_keys = cache.hs_session_keys
        self.circuits.get(circuit.circuit_id)

        callback = self.e2e_callbacks.get(cache.info_hash, None)
        if callback:
            result = callback((self.circuit_id_to_ip(circuit.circuit_id), CIRCUIT_ID_PORT))
            if iscoroutine(result):
                self.register_anonymous_task('e2e_callback', result)
        else:
            self.logger.error('On linked e2e: could not find download for %s!', cache.info_hash)

    async def create_introduction_point(self, info_hash: bytes, required_ip: Peer | None = None) -> None:
        """
        Create an introduction point for the given SHA-1 (info) hash.
        """
        self.logger.info("Creating introduction point")

        if info_hash not in self.swarms:
            self.logger.warning('Cannot create introduction point for unknown swarm')
            return
        if not self.swarms[info_hash].seeding:
            self.logger.warning('Cannot create introduction point for swarm that is not seeding')
            return

        circuit = self.create_circuit_for_infohash(info_hash, CIRCUIT_TYPE_IP_SEEDER, required_exit=required_ip)

        if circuit and await circuit.ready:
            # We got a circuit, now let's create an introduction point
            seed_pk = cast(LibNaCLSK, self.swarms[info_hash].seeder_sk).pub().key_to_bin()
            circuit_id = circuit.circuit_id
            cache = IPRequestCache(self, circuit)
            self.request_cache.add(cache)
            self.send_cell(circuit.hop.address, EstablishIntroPayload(circuit_id, cache.number, info_hash, seed_pk))
            self.logger.info("Established introduction tunnel %s", circuit_id)

    @unpack_cell(EstablishIntroPayload)
    def on_establish_intro(self, source_address: Address, payload: EstablishIntroPayload,
                           circuit_id: int | None) -> None:
        """
        Callback for when we are asked to be an introduction point.
        """
        if payload.public_key in self.intro_point_for:
            self.logger.warning('Already have an introduction point for %s', binascii.hexlify(payload.public_key))
            return

        if circuit_id is None:
            self.logger.warning('Trying to establish an introduction point without a circuit id')
            return

        self.logger.info('Established introduction point for %s', binascii.hexlify(payload.public_key))

        circuit = self.exit_sockets[circuit_id]
        self.intro_point_for[payload.public_key] = circuit, payload.info_hash

        if self.ipv8 is None:
            self.logger.error('No IPv8 service object available, cannot start PEXCommunity')
        elif payload.info_hash not in self.pex:
            community = PexCommunity(PexSettings(my_peer=self.my_peer, endpoint=self.endpoint, network=Network(),
                                                 info_hash=payload.info_hash))
            community.bootstrappers = [DispersyBootstrapper(**DISPERSY_BOOTSTRAPPER['init'])]
            # Since IPv8 takes a step every .5s until we have 10 peers, the PexCommunity will generate
            # a lot of traffic in case there are <10 peers in existence. Therefore, we slow the walk down to a 5s/step.
            self.ipv8.add_strategy(community, RandomWalk(community, target_interval=5), 10)
            self.ipv8.add_strategy(community, RandomChurn(community), -1)
            self.pex[payload.info_hash] = community

        # PEX announce
        if payload.info_hash in self.pex:
            self.pex[payload.info_hash].start_announce(payload.public_key)

        # DHT announce
        self.dht_announce(payload.info_hash, IntroductionPoint(Peer(self.my_peer.key, self.my_estimated_wan),
                                                               payload.public_key))

        self.send_cell(source_address, IntroEstablishedPayload(circuit.circuit_id, payload.identifier))

    @unpack_cell(IntroEstablishedPayload)
    def on_intro_established(self, source_address: Address, payload: IntroEstablishedPayload,
                             circuit_id: int | None) -> None:
        """
        Callback for when a peer signals that an introduction point has been created for us.
        """
        if not self.request_cache.has(IPRequestCache, payload.identifier):
            self.logger.warning("Invalid intro-established request identifier")
            return

        self.request_cache.pop(IPRequestCache, payload.identifier)
        self.logger.info("Got intro-established from %s", source_address)

    async def create_rendezvous_point(self, info_hash: bytes) -> RendezvousPoint | None:
        """
        Create a new rendezvous point for the given SHA-1 (info) hash.
        """
        # Create a new circuit to be used for transferring data
        circuit = self.create_circuit_for_infohash(info_hash, CIRCUIT_TYPE_RP_SEEDER)

        if circuit and await circuit.ready:
            # We got a circuit, now let's create a rendezvous point
            rp = RendezvousPoint(circuit, os.urandom(20))
            cache = RPRequestCache(self, rp)
            self.request_cache.add(cache)
            self.send_cell(circuit.hop.address, EstablishRendezvousPayload(circuit.circuit_id, cache.number, rp.cookie))
            return rp
        return None

    @unpack_cell(EstablishRendezvousPayload)
    def on_establish_rendezvous(self, source_address: Address, payload: EstablishRendezvousPayload,
                                circuit_id: int | None) -> None:
        """
        Callback for when we are requested to be a rendezvous point.
        """
        if circuit_id is None:
            self.logger.warning('Trying to establish a rendezvous point without a circuit id')
            return

        circuit = self.exit_sockets[circuit_id]
        self.rendezvous_point_for[payload.cookie] = circuit

        self.send_cell(source_address,
                       RendezvousEstablishedPayload(circuit.circuit_id, payload.identifier, self.my_estimated_wan))

    @unpack_cell(RendezvousEstablishedPayload)
    def on_rendezvous_established(self, source_address: Address, payload: RendezvousEstablishedPayload,
                                  circuit_id: int | None) -> None:
        """
        Callback for when a peer signals that they act as a rendezvous point for us.
        """
        if not self.request_cache.has(RPRequestCache, payload.identifier):
            self.logger.warning("Invalid rendezvous-established request identifier")
            return

        rp = self.request_cache.pop(RPRequestCache, payload.identifier).rp
        rp.address = payload.rendezvous_point_addr
        rp.ready.set_result(rp)

    async def dht_lookup(self, info_hash: bytes) -> tuple[bytes, list[IntroductionPoint]] | None:
        """
        Attempt to find introduction points for the given SHA-1 (info) hash.
        """
        if self.dht_provider:
            return await self.dht_provider.lookup(info_hash)

        self.logger.error("Need a DHT provider to lookup on the DHT")
        return None

    @task
    async def dht_announce(self, info_hash: bytes, intro_point: IntroductionPoint) -> None:
        """
        Announce ourselves as a candidate for the given SHA-1 (info) hash.
        """
        if self.dht_provider:
            return await self.dht_provider.announce(info_hash, intro_point)

        self.logger.error("Need a DHT provider to announce to the DHT")
        return None
