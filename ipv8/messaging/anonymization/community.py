"""
The tunnel community.

Author(s): Egbert Bouman
"""
from asyncio import iscoroutine, sleep
from binascii import unhexlify

from .caches import *
from .endpoint import TunnelEndpoint
from .payload import *
from .tunnel import *
from .tunnelcrypto import CryptoException, TunnelCrypto
from ...community import Community
from ...lazy_community import lazy_wrapper, lazy_wrapper_unsigned
from ...messaging.deprecated.encoding import decode, encode
from ...messaging.payload_headers import BinMemberAuthenticationPayload
from ...peer import Peer
from ...requestcache import RequestCache
from ...taskmanager import task

message_to_payload = {
    "data": (0, DataPayload),
    "cell": (1, CellPayload),
    "create": (2, CreatePayload),
    "created": (3, CreatedPayload),
    "extend": (4, ExtendPayload),
    "extended": (5, ExtendedPayload),
    "ping": (6, PingPayload),
    "pong": (7, PongPayload),
    "destroy": (10, DestroyPayload),
    "establish-intro": (11, EstablishIntroPayload),
    "intro-established": (12, IntroEstablishedPayload),
    "establish-rendezvous": (15, EstablishRendezvousPayload),
    "rendezvous-established": (16, RendezvousEstablishedPayload),
    "create-e2e": (17, CreateE2EPayload),
    "created-e2e": (18, CreatedE2EPayload),
    "link-e2e": (19, LinkE2EPayload),
    "linked-e2e": (20, LinkedE2EPayload),
    "peers-request": (21, PeersRequestPayload),
    "peers-response": (22, PeersResponsePayload)
}


def tc_lazy_wrapper_unsigned(*payloads):
    """
    This function wrapper will unpack just the normal payloads for you, and handle a singular circuit_id parameter at
    the end of the parameter list

    You can now write your non-authenticated and signed functions as follows:

    ::

        @tc_lazy_wrapper_unsigned(GlobalTimeDistributionPayload, IntroductionRequestPayload,
                                  IntroductionResponsePayload, circuit_id)
        def on_message(source_address, payload1, payload2):
            '''
            :type source_address: str
            :type payload1: IntroductionRequestPayload
            :type payload2: IntroductionResponsePayload
            '''
            pass
    """
    def decorator(func):
        def wrapper(self, source_address, data, circuit_id=None):

            @lazy_wrapper_unsigned(*payloads)
            def inner_wrapper(inner_self, inner_source_address, *pyls):
                combo = list(pyls) + [circuit_id]
                return func(inner_self, inner_source_address, *combo)

            return inner_wrapper(self, source_address, data)
        return wrapper
    return decorator


class TunnelSettings(object):

    def __init__(self):
        self.crypto = TunnelCrypto()

        self.min_circuits = 1
        self.max_circuits = 8
        self.max_joined_circuits = 100

        # Maximum number of seconds that a circuit should exist
        self.max_time = 10 * 60
        # Maximum number of seconds that an introduction point should exist
        self.max_time_ip = 24 * 60 * 60
        # Maximum number of seconds before a circuit is considered inactive (and is removed)
        self.max_time_inactive = 20
        self.max_traffic = 250 * 1024 * 1024

        self.max_packets_without_reply = 50

        # Maximum number of seconds circuit creation is allowed to take. Within this time period, the unverified hop
        # of the circuit can still change in case it is unresponsive.
        self.circuit_timeout = 60
        # Maximum number of seconds that a hop allows us to change the next hop
        self.unstable_timeout = 60
        # Maximum number of seconds adding a single hop to a circuit is allowed to take.
        self.next_hop_timeout = 10

        self.swarm_lookup_interval = 30
        self.swarm_connection_limit = 5

        # We have a small delay when removing circuits/relays/exit nodes. This is to allow some post-mortem data
        # to flow over the circuit (i.e. bandwidth payouts to intermediate nodes in a circuit).
        self.remove_tunnel_delay = 5

        self.num_ip_circuits = 3
        self.peer_flags = {PEER_FLAG_RELAY}


class TunnelCommunity(Community):

    version = b'\x02'
    master_peer = Peer(unhexlify("4c69624e61434c504b3adbd575f1902f1d39debeb3d7b576dff1652ab6cede21c14545d134219b57b"
                                 "413a597c87c2e37b8c9f99938e0d4db3cd4a79d6b53fb5bc0cb7d222d5c6eabfaa9"))

    def __init__(self, *args, **kwargs):
        self.settings = kwargs.pop('settings', TunnelSettings())
        self.dht_provider = kwargs.pop('dht_provider', None)
        if isinstance(self.settings, dict):
            settings = TunnelSettings()
            for k, v in self.settings.items():
                setattr(settings, k, v)
            self.settings = settings

        super(TunnelCommunity, self).__init__(*args, **kwargs)

        self.request_cache = RequestCache()

        # Messages that can arrive from the socket
        self.decode_map.update({
            chr(1): self.on_cell,
            chr(10): self.on_destroy
        })

        # Messages that can arrive from a circuit (i.e., they are wrapped in a cell)
        self.decode_map_private = {
            chr(0): self.on_data,
            chr(2): self.on_create,
            chr(3): self.on_created,
            chr(4): self.on_extend,
            chr(5): self.on_extended,
            chr(6): self.on_ping,
            chr(7): self.on_pong
        }

        self.select_index = -1
        self.circuits = {}
        self.directions = {}
        self.relay_from_to = {}
        self.relay_session_keys = {}
        self.exit_sockets = {}
        self.circuits_needed = defaultdict(int)
        self.num_hops_by_downloads = defaultdict(int)  # Keeps track of the number of hops required by downloads
        self.candidates = {}  # Keeps track of the candidates that want to be a relay/exit node

        self.crypto = self.settings.crypto

        self.logger.info("Setting exitnode = %s", PEER_FLAG_EXIT_ANY in self.settings.peer_flags)

        self.crypto.initialize(self.my_peer.key)

        if isinstance(self.endpoint, TunnelEndpoint):
            self.endpoint.set_tunnel_community(self)
            self.endpoint.set_anonymity(self._prefix, False)

        self.register_task("do_circuits", self.do_circuits, interval=5, delay=0)
        self.register_task("do_ping", self.do_ping, interval=PING_INTERVAL)

    async def unload(self):
        # Remove all circuits/relays/exitsockets
        for circuit_id in list(self.circuits.keys()):
            self.remove_circuit(circuit_id, 'unload', remove_now=True, destroy=DESTROY_REASON_SHUTDOWN)
        for circuit_id in list(self.relay_from_to.keys()):
            self.remove_relay(circuit_id, 'unload', remove_now=True, destroy=DESTROY_REASON_SHUTDOWN, both_sides=False)
        for circuit_id in list(self.exit_sockets.keys()):
            self.remove_exit_socket(circuit_id, 'unload', remove_now=True, destroy=DESTROY_REASON_SHUTDOWN)

        await self.request_cache.shutdown()

        await super(TunnelCommunity, self).unload()

    def _generate_circuit_id(self):
        circuit_id = random.getrandbits(32)

        # Prevent collisions.
        while circuit_id in self.circuits:
            circuit_id = random.getrandbits(32)

        return circuit_id

    def do_circuits(self):
        for circuit_length, num_circuits in self.circuits_needed.items():
            num_to_build = max(0, num_circuits - len(self.find_circuits(state=None, hops=circuit_length)))
            self.logger.info("Want %d data circuits of length %d", num_to_build, circuit_length)
            for _ in range(num_to_build):
                if not self.create_circuit(circuit_length):
                    self.logger.info("circuit creation of %d circuits failed, no need to continue", num_to_build)
                    break
        self.do_remove()

    def build_tunnels(self, hops):
        if hops > 0:
            self.circuits_needed[hops] = max(self.settings.max_circuits,
                                             min(self.settings.max_circuits, self.circuits_needed.get(hops, 0) + 1))
            self.do_circuits()

    def tunnels_ready(self, hops):
        if hops > 0 and self.circuits_needed.get(hops, 0):
            return len(self.find_circuits(hops=hops)) / float(self.circuits_needed[hops])
        return 1.0

    def do_remove(self):
        # Remove circuits that are inactive / are too old / have transferred too many bytes.
        for circuit_id, circuit in list(self.circuits.items()):
            if circuit.state == CIRCUIT_STATE_READY and \
               circuit.last_activity < time.time() - self.settings.max_time_inactive:
                self.remove_circuit(circuit_id, 'no activity')
            elif circuit.creation_time < time.time() - self.get_max_time(circuit_id):
                self.remove_circuit(circuit_id, 'too old')
            elif circuit.bytes_up + circuit.bytes_down > self.settings.max_traffic:
                self.remove_circuit(circuit_id, 'traffic limit exceeded')

        # Remove relays that are inactive / have transferred too many bytes.
        for circuit_id, relay in list(self.relay_from_to.items()):
            if relay.last_activity < time.time() - self.settings.max_time_inactive:
                self.remove_relay(circuit_id, 'no activity', both_sides=False)
            elif relay.bytes_up + relay.bytes_down > self.settings.max_traffic:
                self.remove_relay(circuit_id, 'traffic limit exceeded', both_sides=False)

        # Remove exit sockets that are too old / have transferred too many bytes.
        for circuit_id, exit_socket in list(self.exit_sockets.items()):
            if exit_socket.last_activity < time.time() - self.settings.max_time_inactive:
                self.remove_exit_socket(circuit_id, 'no activity')
            elif exit_socket.creation_time < time.time() - self.get_max_time(circuit_id):
                self.remove_exit_socket(circuit_id, 'too old')
            elif exit_socket.bytes_up + exit_socket.bytes_down > self.settings.max_traffic:
                self.remove_exit_socket(circuit_id, 'traffic limit exceeded')

        # Remove candidates that are not returned as verified peers
        current_peers = self.get_peers()
        for peer in list(self.candidates):
            if peer not in current_peers:
                self.candidates.pop(peer)
                self.logger.info("Removed candidate from candidates dictionary")

    def get_candidates(self, flag):
        return [peer for peer, flags in self.candidates.items()
                if flag in flags and self.crypto.is_key_compatible(peer.public_key)]

    def get_max_time(self, circuit_id):
        return self.settings.max_time

    def find_circuits(self, ctype=CIRCUIT_TYPE_DATA, state=CIRCUIT_STATE_READY, hops=None):
        return [c for c in self.circuits.values()
                if (state is None or c.state == state)
                and (ctype is None or c.ctype == ctype)
                and (hops is None or hops == c.goal_hops)]

    def select_circuit(self, destination, hops):
        circuits = sorted(self.find_circuits(hops=hops), key=lambda c: c.circuit_id)
        if not circuits:
            return None

        self.select_index = (self.select_index + 1) % len(circuits)
        return circuits[self.select_index]

    def create_circuit(self, goal_hops, ctype=CIRCUIT_TYPE_DATA, required_exit=None, info_hash=None):
        self.logger.info("Creating a new circuit of length %d (type: %s)", goal_hops, ctype)
        exit_candidates = self.get_candidates(PEER_FLAG_EXIT_ANY)
        if ctype == CIRCUIT_TYPE_IPV8:
            exit_candidates = self.get_candidates(PEER_FLAG_EXIT_IPV8) or exit_candidates
        relay_candidates = self.get_candidates(PEER_FLAG_RELAY)

        # Determine the last hop
        if not required_exit:
            if ctype in [CIRCUIT_TYPE_DATA, CIRCUIT_TYPE_IPV8, CIRCUIT_TYPE_IP_SEEDER]:
                required_exit = random.choice(exit_candidates) if exit_candidates else None
                # For introduction points we prefer exit nodes, but perhaps a relay peer would also suffice..
                if not required_exit and relay_candidates and ctype == CIRCUIT_TYPE_IP_SEEDER:
                    required_exit = random.choice(relay_candidates)
            else:
                # For exit nodes that don't exit actual data, we prefer relay candidates,
                # but we also consider exit candidates.
                if relay_candidates:
                    required_exit = random.choice(relay_candidates)
                elif exit_candidates:
                    required_exit = random.choice(exit_candidates)

        if not required_exit:
            self.logger.info("Could not create circuit, no available exit-nodes")
            return

        # Determine the first hop
        if goal_hops == 1 and required_exit:
            # If the number of hops is 1, it should immediately be the required_exit hop.
            self.logger.info("First hop is required exit")
            possible_first_hops = [required_exit]
        else:
            self.logger.info("Look for a first hop that is not an exit node and is not used before")
            # First build a list of hops, then filter the list. Avoids issues when create_circuit is called
            # from a different thread (caused by circuit.peer being reset to None).
            first_hops = [c.peer for c in self.circuits.values()]
            first_hops = {h.address for h in first_hops if h}
            possible_first_hops = [c for c in relay_candidates if c.address not in first_hops
                                   and c.address != required_exit.address]

        if not possible_first_hops:
            self.logger.info("Could not create circuit, no first hop available")
            return

        # Finally, construct the Circuit object and send the CREATE message
        circuit_id = self._generate_circuit_id()
        self.circuits[circuit_id] = circuit = Circuit(circuit_id, goal_hops, ctype, required_exit, info_hash)
        self.send_initial_create(circuit, possible_first_hops,
                                 self.settings.circuit_timeout // self.settings.next_hop_timeout)

        return circuit

    def send_initial_create(self, circuit, candidate_list, max_tries):
        if self.request_cache.has("retry", circuit.circuit_id):
            self.request_cache.pop("retry", circuit.circuit_id)

        first_hop = random.choice(candidate_list)
        alt_first_hops = [c for c in candidate_list if c != first_hop]

        circuit.unverified_hop = Hop(first_hop.public_key, flags=self.candidates.get(first_hop))
        circuit.unverified_hop.address = first_hop.address
        circuit.unverified_hop.dh_secret, circuit.unverified_hop.dh_first_part = self.crypto.generate_diffie_secret()

        self.logger.info("Adding first hop %s:%d to circuit %d", *(first_hop.address + (circuit.circuit_id,)))

        self.request_cache.add(RetryRequestCache(self, circuit, alt_first_hops, max_tries - 1,
                                                 self.send_initial_create, self.settings.next_hop_timeout))

        self.increase_bytes_sent(circuit, self.send_cell([first_hop],
                                                         "create",
                                                         CreatePayload(circuit.circuit_id,
                                                                       self.my_peer.public_key.key_to_bin(),
                                                                       circuit.unverified_hop.dh_first_part)))

    @task
    async def remove_circuit(self, circuit_id, additional_info='', remove_now=False, destroy=False):
        """
        Remove a circuit and return a deferred that fires when all data associated with the circuit is destroyed.
        Optionally send a destroy message.
        """
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
            self.logger.info("Removed circuit %d " + additional_info, circuit_id)

        # Clean up the directions dictionary
        self.directions.pop(circuit_id, None)

    @task
    async def remove_relay(self, circuit_id, additional_info='', remove_now=False, destroy=False,
                           got_destroy_from=None, both_sides=True):
        """
        Remove a relay and all information associated with the relay. Return the relays that have been removed.
        """
        to_remove = [circuit_id]
        if both_sides:
            # Find other side of relay
            for k, v in self.relay_from_to.items():
                if circuit_id == v.circuit_id:
                    to_remove.append(k)

        # Send destroy
        if destroy:
            self.destroy_relay(to_remove, got_destroy_from=got_destroy_from, reason=destroy)

        if not remove_now or self.settings.remove_tunnel_delay > 0:
            await sleep(self.settings.remove_tunnel_delay)

        removed_relays = []
        for cid in to_remove:
            # Remove the relay
            self.logger.info("Removing relay %d %s", cid, additional_info)

            relay = self.relay_from_to.pop(cid, None)
            if relay:
                removed_relays.append(relay)

            # Remove old session key
            self.relay_session_keys.pop(cid, None)

            # Clean directions dictionary
            self.directions.pop(cid, None)

        return removed_relays

    @task
    async def remove_exit_socket(self, circuit_id, additional_info='', remove_now=False, destroy=False):
        """
        Remove an exit socket. Send a destroy message if necessary.
        """
        exit_socket_to_destroy = self.exit_sockets.get(circuit_id, None)
        if exit_socket_to_destroy and destroy:
            self.destroy_exit_socket(exit_socket_to_destroy, reason=destroy)

        if not remove_now or self.settings.remove_tunnel_delay > 0:
            await sleep(self.settings.remove_tunnel_delay)

        exit_socket = self.exit_sockets.pop(circuit_id, None)
        if exit_socket:
            # Close socket
            if exit_socket.enabled:
                self.logger.info("Removing exit socket %d %s", circuit_id, additional_info)
                await exit_socket.close()
                # Remove old session key
                self.relay_session_keys.pop(circuit_id, None)
            await exit_socket.shutdown_task_manager()
        return exit_socket

    def destroy_circuit(self, circuit, reason=0):
        sock_addr = circuit.peer.address
        self.send_destroy(sock_addr, circuit.circuit_id, reason)
        self.logger.info("destroy_circuit %s %s", circuit.circuit_id, sock_addr)

    def destroy_relay(self, circuit_ids, reason=0, got_destroy_from=None):
        relays = {cid_from: (self.relay_from_to[cid_from].circuit_id,
                             self.relay_from_to[cid_from].peer.address) for cid_from in circuit_ids
                  if cid_from in self.relay_from_to}

        if got_destroy_from and got_destroy_from not in relays.values():
            self.logger.error("%s not allowed send destroy for circuit %s", *reversed(got_destroy_from))
            return

        for cid_from, (cid_to, sock_addr) in relays.items():
            self.logger.info("Found relay %s -> %s (%s)", cid_from, cid_to, sock_addr)
            if (cid_to, sock_addr) != got_destroy_from:
                self.send_destroy(sock_addr, cid_to, reason)
                self.logger.info("Fw destroy to %s %s", cid_to, sock_addr)

    def destroy_exit_socket(self, exit_socket, reason=0):
        sock_addr = exit_socket.peer.address
        self.send_destroy(sock_addr, exit_socket.circuit_id, reason)
        self.logger.info("Destroy_exit_socket %s %s", exit_socket.circuit_id, sock_addr)

    def is_relay(self, circuit_id):
        return circuit_id > 0 and circuit_id in self.relay_from_to

    def is_circuit(self, circuit_id):
        return circuit_id > 0 and circuit_id in self.circuits

    def is_exit(self, circuit_id):
        return circuit_id > 0 and circuit_id in self.exit_sockets

    def send_cell(self, candidates, message_type, payload, circuit_id=None):
        message_id, _ = message_to_payload[message_type]
        circuit_id = circuit_id or payload.circuit_id
        if isinstance(payload, DataPayload):
            message = payload.to_bin()
        else:
            message = self.serializer.pack_multiple(payload.to_pack_list()[1:])[0]
        cell = CellPayload(circuit_id, pack('!B', message_id) + message, message_id in NO_CRYPTO_PACKETS)
        try:
            cell.encrypt(self.crypto, self.circuits.get(circuit_id), self.relay_session_keys.get(circuit_id))
        except CryptoException as e:
            self.logger.warning(str(e))
            return
        packet = cell.to_bin(self._prefix)
        return self.send_packet(candidates, packet)

    def send_data(self, candidates, circuit_id, dest_address, source_address, data):
        payload = DataPayload(circuit_id, dest_address, source_address, data)
        return self.send_cell(candidates, "data", payload, circuit_id)

    def send_packet(self, candidates, packet):
        for candidate in candidates:
            address = candidate if isinstance(candidate, tuple) else candidate.address
            self.endpoint.send(address, packet)
        return len(packet)

    def send_destroy(self, candidate, circuit_id, reason):
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = DestroyPayload(circuit_id, reason).to_pack_list()
        packet = self._ez_pack(self._prefix, 10, [auth, payload])
        self.send_packet([candidate], packet)

    def relay_cell(self, cell):
        next_relay = self.relay_from_to[cell.circuit_id]
        if cell.plaintext:
            self.logger.warning('Dropping cell (cell not encrypted)')
            return

        try:
            if next_relay.rendezvous_relay:
                cell.decrypt(self.crypto, relay_session_keys=self.relay_session_keys[cell.circuit_id])
                cell.encrypt(self.crypto, relay_session_keys=self.relay_session_keys[next_relay.circuit_id])
            else:
                direction = self.directions[cell.circuit_id]
                if direction == ORIGINATOR:
                    cell.encrypt(self.crypto, relay_session_keys=self.relay_session_keys[cell.circuit_id])
                elif direction == EXIT_NODE:
                    cell.decrypt(self.crypto, relay_session_keys=self.relay_session_keys[cell.circuit_id])
        except CryptoException as e:
            self.logger.warning(str(e))
            return

        cell.circuit_id = next_relay.circuit_id
        packet = cell.to_bin(self._prefix)
        self.increase_bytes_sent(next_relay, self.send_packet([next_relay.peer], packet))

    def _ours_on_created_extended(self, circuit, payload):
        hop = circuit.unverified_hop

        try:
            shared_secret = self.crypto.verify_and_generate_shared_secret(hop.dh_secret, payload.key,
                                                                          payload.auth, hop.public_key.key.pk)
            hop.session_keys = self.crypto.generate_session_keys(shared_secret)

        except CryptoException:
            self.remove_circuit(circuit.circuit_id, "error while verifying shared secret, bailing out.")
            return

        circuit.unverified_hop = None
        circuit.add_hop(hop)

        if circuit.state == CIRCUIT_STATE_EXTENDING:
            candidate_list_enc = payload.candidate_list_enc
            _, candidate_list = decode(self.crypto.decrypt_str(candidate_list_enc,
                                                               hop.session_keys[EXIT_NODE],
                                                               hop.session_keys[EXIT_NODE_SALT]))
            cache = self.request_cache.get("retry", payload.circuit_id)
            self.send_extend(circuit, candidate_list, cache.max_tries if cache else 1)

        elif circuit.state == CIRCUIT_STATE_READY:
            self.request_cache.pop("retry", payload.circuit_id)

    def send_extend(self, circuit, candidate_list, max_tries):
        if self.request_cache.has("retry", circuit.circuit_id):
            self.request_cache.pop("retry", circuit.circuit_id)

        ignore_candidates = [hop.node_public_key for hop in circuit.hops] + [self.my_peer.public_key.key_to_bin()]
        if circuit.required_exit:
            ignore_candidates.append(circuit.required_exit.public_key.key_to_bin())

        become_exit = circuit.goal_hops - 1 == len(circuit.hops)
        if become_exit and circuit.required_exit:
            # Set the required exit according to the circuit setting (e.g. for linking e2e circuits)
            extend_hop_public_bin = circuit.required_exit.public_key.key_to_bin()
            extend_hop_addr = circuit.required_exit.address

        else:
            # The next candidate is chosen from the returned list of possible candidates
            for ignore_candidate in ignore_candidates:
                if ignore_candidate in candidate_list:
                    candidate_list.remove(ignore_candidate)

            for i in range(len(candidate_list) - 1, -1, -1):
                public_key = self.crypto.key_from_public_bin(candidate_list[i])
                if not self.crypto.is_key_compatible(public_key):
                    candidate_list.pop(i)

            extend_hop_public_bin = next(iter(candidate_list), None)
            extend_hop_addr = None

        if extend_hop_public_bin:
            extend_hop_public_key = self.crypto.key_from_public_bin(extend_hop_public_bin)
            circuit.unverified_hop = Hop(extend_hop_public_key,
                                         flags=self.candidates.get(Peer(extend_hop_public_bin)))
            circuit.unverified_hop.dh_secret, circuit.unverified_hop.dh_first_part = \
                self.crypto.generate_diffie_secret()

            self.logger.info("Extending circuit %d with %s", circuit.circuit_id, hexlify(extend_hop_public_bin))

            # Only retry if we are allowed to use another node
            if not become_exit or not circuit.required_exit:
                alt_candidates = [c for c in candidate_list if c != extend_hop_public_bin]
            else:
                alt_candidates = []
            self.request_cache.add(RetryRequestCache(self, circuit, alt_candidates, max_tries - 1,
                                                     self.send_extend, self.settings.next_hop_timeout))

            self.increase_bytes_sent(circuit, self.send_cell([circuit.peer],
                                                             "extend",
                                                             ExtendPayload(circuit.circuit_id,
                                                                           circuit.unverified_hop.node_public_key,
                                                                           extend_hop_addr,
                                                                           circuit.unverified_hop.dh_first_part)))

        else:
            self.remove_circuit(circuit.circuit_id, "no candidates to extend, bailing out.")

    def extract_peer_flags(self, extra_bytes):
        if not extra_bytes:
            return []

        payload = self.serializer.unpack_to_serializables([ExtraIntroductionPayload], extra_bytes)[0]
        return payload.flags

    def introduction_request_callback(self, peer, dist, payload):
        self.candidates[peer] = self.extract_peer_flags(payload.extra_bytes)

    def introduction_response_callback(self, peer, dist, payload):
        self.candidates[peer] = self.extract_peer_flags(payload.extra_bytes)

    def create_introduction_request(self, socket_address, extra_bytes=b''):
        extra_payload = ExtraIntroductionPayload(self.settings.peer_flags)
        extra_bytes = self.serializer.pack_multiple(extra_payload.to_pack_list())[0]
        return super(TunnelCommunity, self).create_introduction_request(socket_address, extra_bytes)

    def create_introduction_response(self, lan_socket_address, socket_address, identifier,
                                     introduction=None, extra_bytes=b''):
        extra_payload = ExtraIntroductionPayload(self.settings.peer_flags)
        extra_bytes = self.serializer.pack_multiple(extra_payload.to_pack_list())[0]
        return super(TunnelCommunity, self).create_introduction_response(lan_socket_address, socket_address,
                                                                         identifier, introduction, extra_bytes)

    def on_cell(self, source_address, data):
        cell = CellPayload.from_bin(data)
        circuit_id = cell.circuit_id

        if self.is_relay(circuit_id):
            next_relay = self.relay_from_to[circuit_id]
            this_relay = self.relay_from_to.get(next_relay.circuit_id, None)
            if this_relay:
                this_relay.beat_heart()
                self.increase_bytes_received(this_relay, len(data))
            self.logger.debug("Relaying cell from circuit %d to %d", circuit_id, next_relay.circuit_id)
            self.relay_cell(cell)
            return

        circuit = self.circuits.get(circuit_id, None)
        try:
            cell.decrypt(self.crypto, circuit=circuit, relay_session_keys=self.relay_session_keys.get(circuit_id))
        except CryptoException:
            if circuit:
                self.send_destroy(circuit.peer, circuit_id, 0)
            return
        self.logger.debug("Got cell(%s) from circuit %d (sender %s, receiver %s)",
                          cell.message[0], circuit_id, source_address, self.my_peer)
        if cell.plaintext and ord(cell.message[0:1]) not in NO_CRYPTO_PACKETS:
            self.logger.warning('Dropping cell (only create/created can have plaintext flag set)')
            return
        self.on_packet_from_circuit(source_address, cell.unwrap(self._prefix), circuit_id)

        if circuit:
            circuit.beat_heart()
            self.increase_bytes_received(circuit, len(data))

    def on_packet_from_circuit(self, source_address, data, circuit_id):
        if self._prefix != data[:22]:
            return
        msg_id = chr(ord(data[22:23]))
        if msg_id in self.decode_map_private:
            try:
                handler = self.decode_map_private[msg_id]
                result = handler(source_address, data, circuit_id)
                if iscoroutine(result):
                    self.register_anonymous_task('on_packet_from_circuit', ensure_future(result), ignore=(Exception,))
            except Exception:
                self.logger.error("Exception occurred while handling packet!\n"
                                  + ''.join(format_exception(*sys.exc_info())))

    async def should_join_circuit(self, create_payload, previous_node_address):
        """
        Check whether we should join a circuit.
        Returns a deferred that fires with a boolean.
        """
        if self.settings.max_joined_circuits <= len(self.relay_from_to) + len(self.exit_sockets):
            self.logger.warning("Too many relays (%d)", (len(self.relay_from_to) + len(self.exit_sockets)))
            return False
        return True

    def join_circuit(self, create_payload, previous_node_address):
        """
        Actively join a circuit and send a created message back
        """
        circuit_id = create_payload.circuit_id

        self.directions[circuit_id] = EXIT_NODE
        self.logger.info('We joined circuit %d with neighbour %s', circuit_id, previous_node_address)

        shared_secret, key, auth = self.crypto.generate_diffie_shared_secret(create_payload.key)
        self.relay_session_keys[circuit_id] = self.crypto.generate_session_keys(shared_secret)

        peers_list = [peer for peer in self.get_candidates(PEER_FLAG_RELAY)
                      if peer not in self.get_candidates(PEER_FLAG_EXIT_ANY)][:4]
        peers_keys = {c.public_key.key_to_bin(): c for c in peers_list}

        peer = Peer(create_payload.node_public_key, previous_node_address)
        self.request_cache.add(CreatedRequestCache(self, circuit_id, peer, peers_keys, self.settings.unstable_timeout))
        self.exit_sockets[circuit_id] = TunnelExitSocket(circuit_id, peer, self)

        candidate_list_enc = self.crypto.encrypt_str(encode(list(peers_keys.keys())),
                                                     *self.crypto.get_session_keys(self.relay_session_keys[circuit_id],
                                                                                   EXIT_NODE))
        self.send_cell([Peer(create_payload.node_public_key, previous_node_address)], "created",
                       CreatedPayload(circuit_id, key, auth, candidate_list_enc))

    @tc_lazy_wrapper_unsigned(CreatePayload)
    async def on_create(self, source_address, payload, _):
        if not self.settings.peer_flags:
            self.logger.warning("Ignoring create for circuit %d", payload.circuit_id)
            return
        if self.request_cache.has("created", payload.circuit_id):
            self.logger.warning("Already have a request for circuit %d", payload.circuit_id)
            return

        result = await self.should_join_circuit(payload, source_address)
        if result:
            self.join_circuit(payload, source_address)
        else:
            self.logger.warning("We're not joining circuit with ID %s", payload.circuit_id)

    @tc_lazy_wrapper_unsigned(CreatedPayload)
    def on_created(self, source_address, payload, _):
        circuit_id = payload.circuit_id
        self.directions[circuit_id] = ORIGINATOR

        if self.request_cache.has("create", payload.circuit_id):
            request = self.request_cache.pop("create", circuit_id)

            self.logger.info("Got CREATED message forward as EXTENDED to origin.")

            self.relay_from_to[request.to_circuit_id] = relay = RelayRoute(request.from_circuit_id, request.peer)
            self.relay_from_to[request.from_circuit_id] = RelayRoute(request.to_circuit_id, request.to_peer)
            self.relay_session_keys[request.to_circuit_id] = self.relay_session_keys[request.from_circuit_id]

            self.directions[request.from_circuit_id] = EXIT_NODE
            self.remove_exit_socket(request.from_circuit_id)

            self.send_cell([relay.peer], "extended", ExtendedPayload(relay.circuit_id,
                                                                     payload.key,
                                                                     payload.auth,
                                                                     payload.candidate_list_enc))
        elif self.request_cache.has("retry", payload.circuit_id):
            circuit = self.circuits[circuit_id]
            self._ours_on_created_extended(circuit, payload)
        else:
            self.logger.warning("Received unexpected created for circuit %d", payload.circuit_id)

    @tc_lazy_wrapper_unsigned(ExtendPayload)
    async def on_extend(self, source_address, payload, _):
        if PEER_FLAG_RELAY not in self.settings.peer_flags:
            self.logger.warning("Ignoring create for circuit %d", payload.circuit_id)
            return
        if not self.request_cache.has("created", payload.circuit_id):
            self.logger.warning("Received unexpected extend for circuit %d", payload.circuit_id)
            return

        circuit_id = payload.circuit_id
        # Leave the RequestCache in case the circuit owner wants to reuse the tunnel for a different next-hop
        request = self.request_cache.get("created", circuit_id)
        if not (payload.node_addr or payload.node_public_key in request.candidates):
            self.logger.warning("Node public key not in request candidates and no ip specified")
            return

        if payload.node_public_key in request.candidates:
            extend_candidate = request.candidates[payload.node_public_key]
        else:
            extend_candidate = self.network.get_verified_by_public_key_bin(payload.node_public_key)
            if not extend_candidate:
                extend_candidate = Peer(payload.node_public_key, payload.node_addr)

            # Ensure that we are able to contact this peer
            if extend_candidate.last_response + 57.5 < time.time():
                await self.dht_peer_lookup(extend_candidate.mid, peer=extend_candidate)

        self.logger.info("On_extend send CREATE for circuit (%s, %d) to %s:%d", source_address,
                         circuit_id, *extend_candidate.address)

        to_circuit_id = self._generate_circuit_id()

        if circuit_id in self.circuits:
            candidate = self.circuits[circuit_id].peer
        elif circuit_id in self.exit_sockets:
            candidate = self.exit_sockets[circuit_id].peer
        elif circuit_id in self.relay_from_to:
            candidate = self.relay_from_to[circuit_id].peer
        else:
            self.logger.error("Got extend for unknown source circuit_id")
            return

        self.logger.info("Extending circuit, got candidate with IP %s:%d from cache", *extend_candidate.address)

        self.request_cache.add(CreateRequestCache(self, to_circuit_id, circuit_id,
                                                  candidate, extend_candidate))

        self.send_cell([extend_candidate], "create",
                       CreatePayload(to_circuit_id, self.my_peer.public_key.key_to_bin(), payload.key))

    @tc_lazy_wrapper_unsigned(ExtendedPayload)
    def on_extended(self, source_address, payload, _):
        if not self.request_cache.has("retry", payload.circuit_id):
            self.logger.warning("Received unexpected extended for circuit %s", payload.circuit_id)
            return

        circuit_id = payload.circuit_id
        circuit = self.circuits[circuit_id]
        self._ours_on_created_extended(circuit, payload)

    def on_raw_data(self, circuit, origin, data):
        """
        Handle data, coming from a specific circuit and origin.
        This method is usually implemented in subclasses of this community.
        """
        pass

    def on_data(self, sock_addr, data, _):
        payload = DataPayload.from_bin(data)

        # If its our circuit, the messenger is the candidate assigned to that circuit and the DATA's destination
        # is set to the zero-address then the packet is from the outside world and addressed to us from.
        circuit_id = payload.circuit_id
        destination = payload.dest_address
        origin = payload.org_address
        data = payload.data

        self.logger.debug("Got data (%d) from %s", circuit_id, sock_addr)

        circuit = self.circuits.get(circuit_id, None)
        if circuit and origin and sock_addr == circuit.peer.address:
            circuit.beat_heart()

            if DataChecker.could_be_ipv8(data):
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

    @tc_lazy_wrapper_unsigned(PingPayload)
    def on_ping(self, source_address, payload, _):
        if not (payload.circuit_id in self.circuits
                or payload.circuit_id in self.exit_sockets
                or payload.circuit_id in self.relay_from_to):
            return

        exit_socket = self.exit_sockets.get(payload.circuit_id)
        if exit_socket:
            exit_socket.beat_heart()

        self.send_cell([source_address], "pong", PongPayload(payload.circuit_id, payload.identifier))
        self.logger.debug("Got ping from %s", source_address)

    @tc_lazy_wrapper_unsigned(PongPayload)
    def on_pong(self, source_address, payload, _):
        if not self.request_cache.has("ping", payload.identifier):
            self.logger.warning("Invalid ping circuit_id")
            return

        self.request_cache.pop("ping", payload.identifier)
        self.logger.debug("Got pong from %s", source_address)

    def do_ping(self, exclude=None):
        # Ping circuits. Pings are only sent to the first hop, subsequent hops will relay the ping.
        exclude = [] if exclude is None else exclude
        for circuit in list(self.circuits.values()):
            if circuit.state in [CIRCUIT_STATE_READY, CIRCUIT_STATE_EXTENDING] \
                    and circuit.circuit_id not in exclude \
                    and circuit.hops:
                cache = self.request_cache.add(PingRequestCache(self, circuit))
                self.increase_bytes_sent(circuit, self.send_cell([circuit.peer], "ping",
                                                                 PingPayload(circuit.circuit_id, cache.number)))

    @lazy_wrapper(DestroyPayload)
    def on_destroy(self, peer, payload):
        source_address = peer.address
        circuit_id = payload.circuit_id
        self.logger.info("Got destroy from %s for circuit %s", source_address, circuit_id)

        if circuit_id in self.relay_from_to:
            self.remove_relay(circuit_id, "got destroy", destroy=DESTROY_REASON_FORWARD,
                              got_destroy_from=(circuit_id, source_address))

        elif circuit_id in self.exit_sockets and source_address == self.exit_sockets[circuit_id].peer.address:
            self.logger.info("Got an exit socket %s %s", circuit_id, source_address)
            self.remove_exit_socket(circuit_id, f"got destroy with reason {payload.reason}")

        elif circuit_id in self.circuits and source_address == self.circuits[circuit_id].peer.address:
            self.logger.info("Got a circuit %s %s", circuit_id, source_address)
            self.remove_circuit(circuit_id, f"got destroy with reason {payload.reason}")

        else:
            self.logger.warning("Invalid or unauthorized destroy")

    def exit_data(self, circuit_id, sock_addr, destination, data):
        is_ipv8 = DataChecker.could_be_ipv8(data)
        is_ipv8_tunnel = is_ipv8 and self._prefix == data[:22]

        if not (is_ipv8 or PEER_FLAG_EXIT_ANY in self.settings.peer_flags):
            self.logger.error("Dropping data packets, refusing to be an exit node for data")

        elif not (is_ipv8_tunnel
                  or PEER_FLAG_EXIT_IPV8 in self.settings.peer_flags
                  or PEER_FLAG_EXIT_ANY in self.settings.peer_flags):
            self.logger.error("Dropping data packets, refusing to be an exit node for ipv8")

        elif circuit_id in self.exit_sockets:
            if not self.exit_sockets[circuit_id].enabled:
                # Check that we got the data from the correct IP.
                if sock_addr[0] == self.exit_sockets[circuit_id].peer.address[0]:
                    self.exit_sockets[circuit_id].enable()
                else:
                    self.logger.error("Dropping outbound relayed packet: IP's are %s != %s",
                                      str(sock_addr), str(self.exit_sockets[circuit_id].peer.address))
            try:
                self.exit_sockets[circuit_id].sendto(data, destination)
            except Exception:
                self.logger.warning("Dropping data packets while EXITing")
        else:
            self.logger.error("Dropping data packets with unknown circuit_id")

    def increase_bytes_sent(self, obj, num_bytes):
        obj.bytes_up += num_bytes

    def increase_bytes_received(self, obj, num_bytes):
        obj.bytes_down += num_bytes

    async def dht_peer_lookup(self, mid, peer=None):
        if self.dht_provider:
            await self.dht_provider.peer_lookup(mid, peer)
        else:
            self.logger.error("Need a DHT provider to connect to a peer using the DHT")
