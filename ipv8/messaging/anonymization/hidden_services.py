"""
The hidden tunnel community.

Author(s): Egbert Bouman
"""
import binascii
import os
import random
import struct
import time
from asyncio import gather, iscoroutine

from .caches import *
from .community import TunnelCommunity, message_to_payload, tc_lazy_wrapper_unsigned
from .payload import *
from .tunnel import (CIRCUIT_ID_PORT, CIRCUIT_TYPE_IP_SEEDER, CIRCUIT_TYPE_RP_DOWNLOADER, CIRCUIT_TYPE_RP_SEEDER,
                     DESTROY_REASON_LEAVE_SWARM, DESTROY_REASON_UNNEEDED, EXIT_NODE, EXIT_NODE_SALT, Hop,
                     IntroductionPoint, PEER_SOURCE_DHT, PEER_SOURCE_PEX, RelayRoute, RendezvousPoint, Swarm,
                     TunnelExitSocket)
from ...keyvault.public.libnaclkey import LibNaCLPK
from ...messaging.anonymization.pex import PexCommunity
from ...messaging.deprecated.encoding import decode, encode
from ...peer import Peer
from ...peerdiscovery.discovery import RandomWalk
from ...peerdiscovery.network import Network
from ...taskmanager import task
from ...util import fail


class HiddenTunnelCommunity(TunnelCommunity):

    def __init__(self, *args, **kwargs):
        self.ipv8 = kwargs.pop('ipv8', None)
        self.e2e_callbacks = kwargs.pop('e2e_callbacks', {})

        self.swarms = {}
        self.pex = {}

        super(HiddenTunnelCommunity, self).__init__(*args, **kwargs)

        self.intro_point_for = {}  # {seeder_pk: (TunnelExitSocket, info_hash)}
        self.rendezvous_point_for = {}  # {cookie: TunnelExitSocket}

        # Messages that can arrive from the socket
        self.decode_map.update({
            chr(17): self.on_create_e2e,
            chr(21): self.on_peers_request,
            chr(22): self.on_peers_response
        })

        # Messages that can arrive from a circuit (i.e., they are wrapped in a cell)
        self.decode_map_private.update({
            chr(11): self.on_establish_intro,
            chr(12): self.on_intro_established,
            chr(15): self.on_establish_rendezvous,
            chr(16): self.on_rendezvous_established,
            chr(17): self.on_create_e2e,
            chr(18): self.on_created_e2e,
            chr(19): self.on_link_e2e,
            chr(20): self.on_linked_e2e,
            chr(21): self.on_peers_request,
            chr(22): self.on_peers_response
        })

        self.register_task("do_peer_discovery", self.do_peer_discovery, interval=10)

    def join_swarm(self, info_hash, hops, callback=None, seeding=True):
        """
        Join a hidden swarm. This should be called by both the downloader and the seeder. Calling this method while
        already part of the swarm will cause the community to drop all pre-existing connections.
        Note that the seeder should also create introduction points by calling create_introduction_point().

        :param info_hash: the swarm identifier
        :type info_hash: bytes
        :param hops: the amount of hops for our introduction/rendezvous circuits
        :type hops: int
        :param callback: the callback function to call when we have established an e2e circuit
        :param seeding: whether or not the swarm should be joined as seeder
        :type seeding: bool
        """
        if info_hash in self.swarms:
            self.logger.warning('Already part of hidden swarm %s, leaving existing', binascii.hexlify(info_hash))
            self.leave_swarm(info_hash)

        self.swarms[info_hash] = Swarm(info_hash, hops, self.send_peers_request,
                                       self.crypto.generate_key(u"curve25519") if seeding else None)
        self.e2e_callbacks[info_hash] = callback

    def leave_swarm(self, info_hash):
        """
        Leave a hidden swarm. Can be called by both the downloader and the seeder.

        :param info_hash: the swarm identifier
        :type info_hash: bytes
        """
        self.e2e_callbacks.pop(info_hash, None)
        swarm = self.swarms.pop(info_hash, None)
        if swarm:
            # If there are no other swarms with the same hop count, remove the data circuits
            if not [s for s in self.swarms.values() if s != swarm and s.hops == swarm.hops]:
                for circuit in self.find_circuits(hops=swarm.hops, state=None):
                    self.remove_circuit(circuit.circuit_id, 'not needed', destroy=DESTROY_REASON_UNNEEDED)
            # Remove e2e circuits
            for rp_circuit, _ in swarm.connections.values():
                self.remove_circuit(rp_circuit.circuit_id, 'leaving hidden swarm', destroy=DESTROY_REASON_LEAVE_SWARM)
        # Remove introduction points
        for ip_circuit in self.circuits.values():
            if ip_circuit.info_hash == info_hash and ip_circuit.ctype == CIRCUIT_TYPE_IP_SEEDER:
                self.remove_circuit(ip_circuit.circuit_id, 'leaving hidden swarm', destroy=DESTROY_REASON_LEAVE_SWARM)

    async def estimate_swarm_size(self, info_hash, hops=1, max_requests=10):
        """
        Estimate the number of unique seeders that are part of a hidden swarm.

        :param info_hash: the swarm identifier
        :type info_hash: str
        :param hops: the amount of hops to use for contacting introduction points
        :type hops: int
        :param max_requests: the number of introduction points we should send a get-peers message to
        :type max_requests: int
        :return: number of unique seeders
        :rtype: Deferred
        """
        swarm = Swarm(info_hash, hops, self.send_peers_request)

        # None represents a DHT request
        all_ = [None]
        tried = set()

        while len(tried) < max_requests:
            not_tried = set(all_) - tried
            if not not_tried:
                break

            # Issue as many requests as possible in parallel
            ips = random.sample(not_tried, min(len(not_tried), max_requests - len(tried)))
            responses = await gather(*[swarm.lookup(ip) for ip in ips], return_exceptions=True)

            # Collect responses
            all_ += sum([result for result in responses if not isinstance(result, Exception)], [])
            tried |= set(ips)

        return len({ip.seeder_pk for ip in all_ if ip and ip.source == PEER_SOURCE_PEX})

    def select_circuit_for_infohash(self, info_hash):
        swarm = self.swarms.get(info_hash)
        if not swarm or not swarm.hops:
            self.logger.info('Can\'t get hop count, download cancelled?')
            return

        return self.select_circuit(None, swarm.hops)

    def create_circuit_for_infohash(self, info_hash, ctype, *args, **kwargs):
        swarm = self.swarms.get(info_hash)
        if not swarm or not swarm.hops:
            self.logger.info('Can\'t get hop count, download cancelled?')
            return

        # Introduction point circuits need an additional hop, or we will talk directly to the the introduction point.
        # Also, rendezvous circuits need an additional hop, since the seeder chooses the rendezvous_point.
        hops = swarm.hops
        if ctype in [CIRCUIT_TYPE_IP_SEEDER, CIRCUIT_TYPE_RP_DOWNLOADER]:
            hops += 1

        return self.create_circuit(hops, ctype, *args, info_hash=info_hash, **kwargs)

    def ip_to_circuit_id(self, ip_str):
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]

    def circuit_id_to_ip(self, circuit_id):
        return socket.inet_ntoa(struct.pack("!I", circuit_id))

    async def do_peer_discovery(self):
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
                    ip = swarm.add_intro_point(ip)
                    if not swarm.has_connection(ip.seeder_pk):
                        self.create_e2e(info_hash, ip)

    def do_circuits(self):
        super(HiddenTunnelCommunity, self).do_circuits()

        # Make sure we have at least 1 data circuit for every hop count. This circuit will be used for
        # communication with introduction points.
        for hop_count in {swarm.hops for swarm in self.swarms.values()}:
            if not self.find_circuits(state=None, hops=hop_count):
                self.create_circuit(hop_count)

    def do_ping(self, exclude=None):
        # Ping all circuits, except pending e2e circuits
        exclude = [] if exclude is None else exclude
        exclude += [c.circuit_id for c in self.circuits.values()
                    if (c.ctype == CIRCUIT_TYPE_RP_SEEDER) or (c.ctype == CIRCUIT_TYPE_RP_DOWNLOADER and not c.e2e)]
        super(HiddenTunnelCommunity, self).do_ping(exclude=exclude)

    def remove_circuit(self, circuit_id, additional_info='', remove_now=False, destroy=False):
        circuit = self.circuits.get(circuit_id, None)
        if circuit and circuit.ctype == CIRCUIT_TYPE_RP_DOWNLOADER:
            swarm = self.swarms.get(circuit.info_hash)
            if swarm:
                swarm.remove_connection(circuit)
        return super(HiddenTunnelCommunity, self).remove_circuit(circuit_id, additional_info, remove_now, destroy)

    def remove_exit_socket(self, circuit_id, additional_info='', remove_now=False, destroy=False):
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
                        self.ipv8.overlays.remove(pex)
                        self.ipv8.strategies = [t for t in self.ipv8.strategies if t[0].overlay != pex]
                        self.register_anonymous_task('unload_pex', pex.unload)

        for cookie, rendezvous_circuit in list(self.rendezvous_point_for.items()):
            if rendezvous_circuit.circuit_id == circuit_id:
                self.rendezvous_point_for.pop(cookie)

        return super(HiddenTunnelCommunity, self).remove_exit_socket(circuit_id, additional_info, remove_now, destroy)

    def get_max_time(self, circuit_id):
        if circuit_id in self.circuits and self.circuits[circuit_id].ctype == CIRCUIT_TYPE_IP_SEEDER:
            return self.settings.max_time_ip
        if circuit_id in self.exit_sockets and circuit_id in [c.circuit_id for c, _ in self.intro_point_for.values()]:
            return self.settings.max_time_ip
        return super(HiddenTunnelCommunity, self).get_max_time(circuit_id)

    def tunnel_data(self, circuit, destination, message_type, payload):
        message_id, _ = message_to_payload[message_type]
        packet = self._ez_pack(self._prefix, message_id, [payload.to_pack_list()], False)
        pre = ('0.0.0.0', 0)
        post = ('0.0.0.0', 0)
        if isinstance(circuit, TunnelExitSocket):
            post = destination
        else:
            pre = destination
        self.send_data([circuit.peer], circuit.circuit_id, pre, post, packet)

    def select_circuit(self, destination, hops):
        # Make sure that we select the right circuit when dealing with an e2e connection
        if destination and destination[1] == CIRCUIT_ID_PORT:
            circuit_id = self.ip_to_circuit_id(destination[0])
            circuit = self.circuits.get(circuit_id, None)

            if circuit and circuit.state == CIRCUIT_STATE_READY and \
               circuit.ctype == CIRCUIT_TYPE_RP_DOWNLOADER:
                return circuit
        return super(HiddenTunnelCommunity, self).select_circuit(destination, hops)

    def send_peers_request(self, info_hash, target, hops):
        circuit = self.select_circuit(None, hops)
        if not circuit:
            self.logger.info("No circuit for peers-request")
            return fail(RuntimeError("No circuit for peers-request"))

        # Send a peers-request message over this circuit
        cache = self.request_cache.add(PeersRequestCache(self, circuit, info_hash))
        payload = PeersRequestPayload(circuit.circuit_id, cache.number, info_hash)

        # Ask an introduction point if available (in which case we'll use PEX), otherwise let
        # the exit node do a DHT request.
        if target and target.peer.public_key != circuit.hops[-1].public_key:
            self.tunnel_data(circuit, target.peer.address, u"peers-request", payload)
            self.logger.info("Sending peers request (intro point %s)", target.peer)
        else:
            self.send_cell([circuit.peer], u"peers-request", payload)
            self.logger.info("Sending peers request as cell")
        return cache.future

    @tc_lazy_wrapper_unsigned(PeersRequestPayload)
    async def on_peers_request(self, source_address, payload, circuit_id=None):
        info_hash = payload.info_hash
        self.logger.info("Doing hidden seeders lookup for info_hash %s", binascii.hexlify(info_hash))
        if info_hash in self.pex:
            # Get peers from PEX community
            intro_points = self.pex[info_hash].get_intro_points()
            self.send_peers_response(source_address, payload, intro_points, circuit_id)
        elif circuit_id in self.exit_sockets:
            # Get peers from DHT community
            _, intro_points = await self.dht_lookup(info_hash)
            self.send_peers_response(source_address, payload, intro_points, circuit_id)
        elif circuit_id is not None:
            self.logger.warning("Received a peers-request over circuit %d, but unable to do a DHT lookup", circuit_id)
        else:
            self.logger.warning("Received a peers-request over the socket, but unable to do a PEX lookup")

    def send_peers_response(self, target_addr, request, intro_points, circuit_id):
        result = encode([(ip.peer.address, ip.peer.public_key.key_to_bin(),
                          ip.seeder_pk, ip.source) for ip in intro_points[:7]])
        payload = PeersResponsePayload(request.circuit_id, request.identifier, request.info_hash, result)

        if circuit_id is not None:
            # Send back to origin
            self.send_cell([target_addr], 'peers-response', payload)
        else:
            # Send back to exit node
            message_id, _ = message_to_payload['peers-response']
            packet = self._ez_pack(self._prefix, message_id, [payload.to_pack_list()], False)
            self.send_packet([target_addr], packet)

    @tc_lazy_wrapper_unsigned(PeersResponsePayload)
    def on_peers_response(self, source_address, payload, circuit_id):
        if not self.request_cache.has(u"peers-request", payload.identifier):
            self.logger.warning('Got a peers-response with an unknown identifier')
            return
        cache = self.request_cache.pop(u"peers-request", payload.identifier)

        _, peers = decode(payload.peers)
        self.logger.info("Received peers-response containing %d peers", len(peers))
        ips = [IntroductionPoint(Peer(ip_pk, address=address), seeder_pk, source)
               for address, ip_pk, seeder_pk, source in peers if address != ('0.0.0.0', 0)]
        cache.future.set_result(ips)

    def create_e2e(self, info_hash, intro_point):
        circuit = self.select_circuit_for_infohash(info_hash)
        if not circuit:
            self.logger.error("No circuit for contacting the introduction point")
            return

        hop = Hop(LibNaCLPK(intro_point.seeder_pk[10:]))
        hop.dh_secret, hop.dh_first_part = self.crypto.generate_diffie_secret()
        self.logger.info('Creating e2e circuit for introduction point %s', intro_point.peer)
        cache = self.request_cache.add(E2ERequestCache(self, info_hash, hop, intro_point))
        self.tunnel_data(circuit, intro_point.peer.address, u'create-e2e',
                         CreateE2EPayload(cache.number, info_hash, hop.node_public_key, hop.dh_first_part))

    @tc_lazy_wrapper_unsigned(CreateE2EPayload)
    async def on_create_e2e(self, source_address, payload, circuit_id=None):
        # If we have received this message over a socket, we need to forward it
        if circuit_id is None:
            if payload.node_public_key in self.intro_point_for:
                self.logger.info('On create-e2e: forwarding message because received over socket')
                relay_circuit, _ = self.intro_point_for[payload.node_public_key]
                self.tunnel_data(relay_circuit, source_address, u'create-e2e', payload)
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

    def create_created_e2e(self, rendezvous_point, source_address, payload, circuit_id):
        key = self.swarms[payload.info_hash].seeder_sk
        shared_secret, Y, AUTH = self.crypto.generate_diffie_shared_secret(payload.key, key)
        rendezvous_point.circuit.hs_session_keys = self.crypto.generate_session_keys(shared_secret)
        rp_info_enc = self.crypto.encrypt_str(
            encode((rendezvous_point.rp_info, rendezvous_point.cookie)),
            *self.crypto.get_session_keys(rendezvous_point.circuit.hs_session_keys, EXIT_NODE))

        circuit = self.circuits[circuit_id]
        self.tunnel_data(circuit, source_address, u'created-e2e',
                         CreatedE2EPayload(payload.identifier, Y, AUTH, rp_info_enc))

    @tc_lazy_wrapper_unsigned(CreatedE2EPayload)
    async def on_created_e2e(self, source_address, payload, circuit_id):
        if not self.request_cache.has(u"e2e-request", payload.identifier):
            self.logger.warning("Invalid created-e2e identifier")
            return

        cache = self.request_cache.pop(u"e2e-request", payload.identifier)
        shared_secret = self.crypto.verify_and_generate_shared_secret(cache.hop.dh_secret,
                                                                      payload.key,
                                                                      payload.auth,
                                                                      cache.hop.public_key.key.pk)
        session_keys = self.crypto.generate_session_keys(shared_secret)

        _, decoded = decode(self.crypto.decrypt_str(payload.rp_info_enc,
                                                    session_keys[EXIT_NODE],
                                                    session_keys[EXIT_NODE_SALT]))
        rp_info, cookie = decoded

        required_exit = Peer(rp_info[2], rp_info[:2])
        circuit = self.create_circuit_for_infohash(cache.info_hash, CIRCUIT_TYPE_RP_DOWNLOADER,
                                                   required_exit=required_exit)
        if circuit:
            self.swarms[cache.info_hash].add_connection(circuit, cache.intro_point)
            if await circuit.ready:
                cache = self.request_cache.add(LinkRequestCache(self, circuit, cache.info_hash, session_keys))
                self.send_cell([circuit.peer], u'link-e2e', LinkE2EPayload(circuit.circuit_id, cache.number, cookie))

    @tc_lazy_wrapper_unsigned(LinkE2EPayload)
    def on_link_e2e(self, source_address, payload, circuit_id):
        if payload.cookie not in self.rendezvous_point_for:
            self.logger.warning("Not a rendezvous point for this cookie")
            return

        if self.exit_sockets[circuit_id].enabled:
            self.logger.warning("Exit socket for circuit is enabled, cannot link")
            return

        relay_circuit = self.rendezvous_point_for[payload.cookie]
        if self.exit_sockets[relay_circuit.circuit_id].enabled:
            self.logger.warning("Exit socket for relay_circuit is enabled, cannot link")

        circuit = self.exit_sockets[circuit_id]

        self.remove_exit_socket(circuit.circuit_id, 'linking circuit')
        self.remove_exit_socket(relay_circuit.circuit_id, 'linking circuit')

        self.relay_from_to[circuit.circuit_id] = RelayRoute(relay_circuit.circuit_id, relay_circuit.peer, True)
        self.relay_from_to[relay_circuit.circuit_id] = RelayRoute(circuit.circuit_id, circuit.peer, True)

        self.send_cell([source_address], u"linked-e2e", LinkedE2EPayload(circuit.circuit_id, payload.identifier))

    @tc_lazy_wrapper_unsigned(LinkedE2EPayload)
    def on_linked_e2e(self, source_address, payload, circuit_id):
        if not self.request_cache.has(u"link-request", payload.identifier):
            self.logger.warning("Invalid linked-e2e identifier")
            return

        cache = self.request_cache.pop(u"link-request", payload.identifier)
        circuit = cache.circuit
        circuit.e2e = True
        circuit.hs_session_keys = cache.hs_session_keys
        callback = self.e2e_callbacks.get(cache.info_hash, None)
        if callback:
            result = callback((self.circuit_id_to_ip(circuit.circuit_id), CIRCUIT_ID_PORT))
            if iscoroutine(result):
                self.register_anonymous_task('e2e_callback', result)
        else:
            self.logger.error('On linked e2e: could not find download for %s!', cache.info_hash)

    async def create_introduction_point(self, info_hash, required_ip=None):
        self.logger.info("Creating introduction point")

        if info_hash not in self.swarms:
            self.logger.warning('Cannot create introduction point for unknown swarm')
            return
        elif not self.swarms[info_hash].seeding:
            self.logger.warning('Cannot create introduction point for swarm that is not seeding')
            return

        circuit = self.create_circuit_for_infohash(info_hash, CIRCUIT_TYPE_IP_SEEDER, required_exit=required_ip)

        if circuit and await circuit.ready:
            # We got a circuit, now let's create an introduction point
            seed_pk = self.swarms[info_hash].seeder_sk.pub().key_to_bin()
            circuit_id = circuit.circuit_id
            cache = self.request_cache.add(IPRequestCache(self, circuit))
            self.send_cell([circuit.peer], 'establish-intro', EstablishIntroPayload(circuit_id, cache.number,
                                                                                    info_hash, seed_pk))
            self.logger.info("Established introduction tunnel %s", circuit_id)

    @tc_lazy_wrapper_unsigned(EstablishIntroPayload)
    def on_establish_intro(self, source_address, payload, circuit_id):
        if payload.public_key in self.intro_point_for:
            self.logger.warning('Already have an introduction point for %s', binascii.hexlify(payload.public_key))
            return

        self.logger.info('Established introduction point for %s', binascii.hexlify(payload.public_key))

        circuit = self.exit_sockets[circuit_id]
        self.intro_point_for[payload.public_key] = circuit, payload.info_hash

        if not self.ipv8:
            self.logger.error('No IPv8 service object available, cannot start PEXCommunity')
        elif payload.info_hash not in self.pex:
            community = PexCommunity(self.my_peer, self.endpoint, Network(), info_hash=payload.info_hash)
            self.ipv8.overlays.append(community)
            # Since IPv8 takes a step every .5s until we have 10 peers, the PexCommunity will generate
            # a lot of traffic in case there are <10 peers in existence. Therefore, we slow the walk down to a 5s/step.
            self.ipv8.strategies.append((RandomWalk(community, target_interval=5), 10))
            self.pex[payload.info_hash] = community

        # PEX announce
        if payload.info_hash in self.pex:
            self.pex[payload.info_hash].start_announce(payload.public_key)

        # DHT announce
        self.dht_announce(payload.info_hash, IntroductionPoint(Peer(self.my_peer.key, self.my_estimated_wan),
                                                               payload.public_key))

        self.send_cell([source_address], u"intro-established",
                       IntroEstablishedPayload(circuit.circuit_id, payload.identifier))

    @tc_lazy_wrapper_unsigned(IntroEstablishedPayload)
    def on_intro_established(self, source_address, payload, circuit_id):
        if not self.request_cache.has(u"establish-intro", payload.identifier):
            self.logger.warning("Invalid intro-established request identifier")
            return

        self.request_cache.pop(u"establish-intro", payload.identifier)
        self.logger.info("Got intro-established from %s", source_address)

    async def create_rendezvous_point(self, info_hash):
        # Create a new circuit to be used for transferring data
        circuit = self.create_circuit_for_infohash(info_hash, CIRCUIT_TYPE_RP_SEEDER)

        if circuit and await circuit.ready:
            # We got a circuit, now let's create a rendezvous point
            rp = RendezvousPoint(circuit, os.urandom(20))
            cache = self.request_cache.add(RPRequestCache(self, rp))
            self.send_cell([circuit.peer],
                           'establish-rendezvous', EstablishRendezvousPayload(circuit.circuit_id,
                                                                              cache.number, rp.cookie))
            return rp

    @tc_lazy_wrapper_unsigned(EstablishRendezvousPayload)
    def on_establish_rendezvous(self, source_address, payload, circuit_id):
        circuit = self.exit_sockets[circuit_id]
        self.rendezvous_point_for[payload.cookie] = circuit

        self.send_cell([source_address], u"rendezvous-established",
                       RendezvousEstablishedPayload(circuit.circuit_id, payload.identifier, self.my_estimated_wan))

    @tc_lazy_wrapper_unsigned(RendezvousEstablishedPayload)
    def on_rendezvous_established(self, source_address, payload, circuit_id):
        if not self.request_cache.has(u"establish-rendezvous", payload.identifier):
            self.logger.warning("Invalid rendezvous-established request identifier")
            return

        rp = self.request_cache.pop(u"establish-rendezvous", payload.identifier).rp

        sock_addr = payload.rendezvous_point_addr
        rp.rp_info = (sock_addr[0], sock_addr[1], self.crypto.key_to_bin(rp.circuit.hops[-1].public_key))
        rp.ready.set_result(rp)

    async def dht_lookup(self, info_hash):
        if self.dht_provider:
            return await self.dht_provider.lookup(info_hash)
        else:
            self.logger.error("Need a DHT provider to lookup on the DHT")

    @task
    async def dht_announce(self, info_hash, intro_point):
        if self.dht_provider:
            return await self.dht_provider.announce(info_hash, intro_point)
        else:
            self.logger.error("Need a DHT provider to announce to the DHT")
