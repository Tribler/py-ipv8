"""
The tunnel community.

Author(s): Egbert Bouman
"""
import os
import random
from asyncio import iscoroutine, sleep
from binascii import unhexlify
from collections import defaultdict

from .caches import *
from .endpoint import TunnelEndpoint
from .payload import *
from .tunnel import *
from .tunnelcrypto import CryptoException, TunnelCrypto
from ...community import Community
from ...lazy_community import lazy_wrapper
from ...messaging.payload_headers import BinMemberAuthenticationPayload
from ...peer import Peer
from ...requestcache import RequestCache
from ...taskmanager import task


def unpack_cell(payload_cls):
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
            pass
    """
    def decorator(func):
        def wrapper(self, source_address, data, circuit_id=None):
            payload, _ = self.serializer.unpack_serializable(payload_cls, data, offset=23)
            return func(self, source_address, payload, circuit_id)
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

        # Maximum number of seconds circuit creation is allowed to take. Within this time period, the unverified hop
        # of the circuit can still change in case it is unresponsive.
        self.circuit_timeout = 60
        # Maximum number of seconds that a hop allows us to change the next hop
        self.unstable_timeout = 60
        # Maximum number of seconds adding a single hop to a circuit is allowed to take.
        self.next_hop_timeout = 10

        self.swarm_lookup_interval = 30
        self.swarm_connection_limit = 15

        # We have a small delay when removing circuits/relays/exit nodes. This is to allow some post-mortem data
        # to flow over the circuit (i.e. bandwidth payouts to intermediate nodes in a circuit).
        self.remove_tunnel_delay = 5

        self.peer_flags = {PEER_FLAG_RELAY, PEER_FLAG_SPEED_TEST}

        # Maximum number of relay_early cells that are allowed to pass a relay.
        self.max_relay_early = 8

    @classmethod
    def from_dict(cls, d):
        result = cls()
        for k, v in d.items():
            setattr(result, k, v)
        return result


class TunnelCommunity(Community):

    version = b'\x02'
    community_id = unhexlify('81ded07332bdc775aa5a46f96de9f8f390bbc9f3')

    def __init__(self, *args, **kwargs):
        settings = kwargs.pop('settings', TunnelSettings())
        if isinstance(settings, dict):
            settings = TunnelSettings.from_dict(settings)
        self.settings = settings
        self.dht_provider = kwargs.pop('dht_provider', None)

        super(TunnelCommunity, self).__init__(*args, **kwargs)

        self.request_cache = RequestCache()
        self.decode_map_private = {}

        # Messages that can arrive from the socket
        self.add_message_handler(CellPayload, self.on_cell)
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

        self.circuits = {}
        self.directions = {}
        self.relay_from_to = {}
        self.relay_session_keys = {}
        self.exit_sockets = {}
        self.circuits_needed = defaultdict(int)
        self.num_hops_by_downloads = defaultdict(int)  # Keeps track of the number of hops required by downloads
        self.candidates = {}  # Keeps track of the candidates that want to be a relay/exit node

        self.crypto = self.settings.crypto

        self.logger.info("Exit settings: BT=%s, IPv8=%s",
                         PEER_FLAG_EXIT_BT in self.settings.peer_flags,
                         PEER_FLAG_EXIT_IPV8 in self.settings.peer_flags)

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

    def get_serializer(self):
        serializer = super().get_serializer()
        serializer.add_packer('flags', Flags())
        return serializer

    def add_cell_handler(self, payload_cls, handler):
        self.decode_map_private[payload_cls.msg_id] = handler

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

    def get_candidates(self, *requested_flags):
        return [peer for peer, flags in self.candidates.items()
                if set(requested_flags) <= set(flags) and self.crypto.is_key_compatible(peer.public_key)]

    def get_max_time(self, circuit_id):
        return self.settings.max_time

    def find_circuits(self, ctype=CIRCUIT_TYPE_DATA, state=CIRCUIT_STATE_READY, exit_flags=None, hops=None):
        return [c for c in self.circuits.values()
                if (state is None or c.state == state)
                and (ctype is None or c.ctype == ctype)
                and (exit_flags is None or set(exit_flags) <= set(c.exit_flags))
                and (hops is None or hops == c.goal_hops)]

    def create_circuit(self, goal_hops, ctype=CIRCUIT_TYPE_DATA, exit_flags=None, required_exit=None, info_hash=None):
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
                return

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
            first_hops = [c.peer for c in self.circuits.values()]
            first_hops = {h for h in first_hops if h}
            relay_candidates = self.get_candidates(PEER_FLAG_RELAY)
            possible_first_hops = [c for c in relay_candidates if c not in first_hops and c != required_exit]

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
        first_hop = random.choice(candidate_list)
        alt_first_hops = [c for c in candidate_list if c != first_hop]

        circuit.unverified_hop = Hop(first_hop, flags=self.candidates.get(first_hop))
        circuit.unverified_hop.dh_secret, circuit.unverified_hop.dh_first_part = self.crypto.generate_diffie_secret()

        self.logger.info("Adding first hop %s:%d to circuit %d", *(first_hop.address + (circuit.circuit_id,)))

        cache = RetryRequestCache(self, circuit, alt_first_hops, max_tries - 1,
                                  self.send_initial_create, self.settings.next_hop_timeout)
        self.request_cache.add(cache)

        self.send_cell(first_hop, CreatePayload(circuit.circuit_id,
                                                cache.number,
                                                self.my_peer.public_key.key_to_bin(),
                                                circuit.unverified_hop.dh_first_part))

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

    def send_cell(self, peer, payload):
        circuit_id = payload.circuit_id
        message = self.serializer.pack_serializable(payload)[4:]
        cell = CellPayload(circuit_id, pack('!B', payload.msg_id) + message)

        cell.plaintext = payload.msg_id in NO_CRYPTO_PACKETS
        if circuit_id in self.circuits:
            circuit = self.circuits[circuit_id]
            cell.relay_early = payload.msg_id == 4 or circuit.relay_early_count < self.settings.max_relay_early
            if cell.relay_early:
                circuit.relay_early_count += 1

        try:
            cell.encrypt(self.crypto, self.circuits.get(circuit_id), self.relay_session_keys.get(circuit_id))
        except CryptoException as e:
            self.logger.warning(str(e))
            return
        packet = cell.to_bin(self._prefix)
        packet_len = self.send_packet(peer, packet)

        tunnel_obj = self.circuits.get(circuit_id) or self.relay_from_to.get(circuit_id)
        if tunnel_obj:
            tunnel_obj.bytes_up += packet_len

    def send_data(self, peer, circuit_id, dest_address, source_address, data):
        payload = DataPayload(circuit_id, dest_address, source_address, data)
        return self.send_cell(peer, payload)

    def send_packet(self, peer, packet):
        self.endpoint.send(peer if isinstance(peer, tuple) else peer.address, packet)
        return len(packet)

    def send_destroy(self, peer, circuit_id, reason):
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin())
        payload = DestroyPayload(circuit_id, reason)
        packet = self._ez_pack(self._prefix, DestroyPayload.msg_id, [auth, payload])
        self.send_packet(peer, packet)

    def relay_cell(self, cell):
        next_relay = self.relay_from_to[cell.circuit_id]
        if cell.plaintext:
            self.logger.warning('Dropping cell (cell not encrypted)')
            return
        if cell.relay_early and next_relay.relay_early_count >= self.settings.max_relay_early:
            self.logger.warning('Dropping cell (too many relay_early cells)')
            return

        try:
            if next_relay.rendezvous_relay:
                cell.decrypt(self.crypto, relay_session_keys=self.relay_session_keys[cell.circuit_id])
                cell.encrypt(self.crypto, relay_session_keys=self.relay_session_keys[next_relay.circuit_id])
                cell.relay_early = False
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
        next_relay.bytes_up += self.send_packet(next_relay.peer, packet)
        next_relay.relay_early_count += 1

    def _ours_on_created_extended(self, circuit, payload):
        hop = circuit.unverified_hop

        try:
            shared_secret = self.crypto.verify_and_generate_shared_secret(hop.dh_secret, payload.key,
                                                                          payload.auth, hop.public_key.key.pk)
            hop.session_keys = self.crypto.generate_session_keys(shared_secret)

        except CryptoException:
            self.remove_circuit(circuit.circuit_id, "error while verifying shared secret")
            return

        circuit.unverified_hop = None
        circuit.add_hop(hop)

        if circuit.state == CIRCUIT_STATE_EXTENDING:
            candidate_list_enc = payload.candidate_list_enc
            candidate_list_bin = self.crypto.decrypt_str(candidate_list_enc,
                                                         hop.session_keys[EXIT_NODE],
                                                         hop.session_keys[EXIT_NODE_SALT])
            candidate_list, _ = self.serializer.unpack('varlenH-list', candidate_list_bin)

            cache = self.request_cache.pop("retry", payload.identifier)
            self.send_extend(circuit, candidate_list, cache.max_tries if cache else 1)

        elif circuit.state == CIRCUIT_STATE_READY:
            self.request_cache.pop("retry", payload.identifier)

    def send_extend(self, circuit, candidate_list, max_tries):
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
            extend_hop_addr = ('0.0.0.0', 0)

        if extend_hop_public_bin:
            extend_hop_public_key = self.crypto.key_from_public_bin(extend_hop_public_bin)
            circuit.unverified_hop = Hop(Peer(extend_hop_public_key),
                                         flags=self.candidates.get(Peer(extend_hop_public_bin)))
            circuit.unverified_hop.dh_secret, circuit.unverified_hop.dh_first_part = \
                self.crypto.generate_diffie_secret()

            self.logger.info("Extending circuit %d with %s", circuit.circuit_id, hexlify(extend_hop_public_bin))

            # Only retry if we are allowed to use another node
            if not become_exit or not circuit.required_exit:
                alt_candidates = [c for c in candidate_list if c != extend_hop_public_bin]
            else:
                alt_candidates = []

            cache = RetryRequestCache(self, circuit, alt_candidates, max_tries - 1,
                                      self.send_extend, self.settings.next_hop_timeout)
            self.request_cache.add(cache)

            self.send_cell(circuit.peer, ExtendPayload(circuit.circuit_id,
                                                       cache.number,
                                                       circuit.unverified_hop.node_public_key,
                                                       circuit.unverified_hop.dh_first_part,
                                                       extend_hop_addr))

        else:
            self.remove_circuit(circuit.circuit_id, "no candidates to extend")

    def extract_peer_flags(self, extra_bytes):
        if not extra_bytes:
            return []

        payload, _ = self.serializer.unpack_serializable(ExtraIntroductionPayload, extra_bytes)
        return payload.flags

    def introduction_request_callback(self, peer, dist, payload):
        self.candidates[peer] = self.extract_peer_flags(payload.extra_bytes)

    def introduction_response_callback(self, peer, dist, payload):
        self.candidates[peer] = self.extract_peer_flags(payload.extra_bytes)

    def create_introduction_request(self, socket_address, extra_bytes=b'', new_style=False):
        extra_payload = ExtraIntroductionPayload(self.settings.peer_flags)
        extra_bytes = self.serializer.pack_serializable(extra_payload)
        return super().create_introduction_request(socket_address, extra_bytes, new_style)

    def create_introduction_response(self, lan_socket_address, socket_address, identifier,
                                     introduction=None, extra_bytes=b'', prefix=None, new_style=False):
        extra_payload = ExtraIntroductionPayload(self.settings.peer_flags)
        extra_bytes = self.serializer.pack_serializable(extra_payload)
        return super(TunnelCommunity, self).create_introduction_response(lan_socket_address, socket_address,
                                                                         identifier, introduction, extra_bytes,
                                                                         prefix, new_style)

    def on_cell(self, source_address, data):
        cell = CellPayload.from_bin(data)
        circuit_id = cell.circuit_id

        if circuit_id in self.relay_from_to:
            next_relay = self.relay_from_to[circuit_id]
            this_relay = self.relay_from_to.get(next_relay.circuit_id, None)
            if this_relay:
                this_relay.beat_heart()
                this_relay.bytes_down += len(data)
            self.logger.debug("Relaying cell from circuit %d to %d", circuit_id, next_relay.circuit_id)
            self.relay_cell(cell)
            return

        circuit = self.circuits.get(circuit_id, None)
        try:
            cell.decrypt(self.crypto, circuit=circuit, relay_session_keys=self.relay_session_keys.get(circuit_id))
        except CryptoException as e:
            self.logger.debug(str(e))
            if circuit:
                self.send_destroy(circuit.peer, circuit_id, 0)
            return
        self.logger.debug("Got cell(%s) from circuit %d (sender %s, receiver %s)",
                          cell.message[0], circuit_id, source_address, self.my_peer)

        if (not cell.relay_early and cell.message[0] == 4) or self.settings.max_relay_early <= 0:
            self.logger.info('Dropping cell (missing or unexpected relay_early flag)')
            return
        if cell.plaintext and cell.message[0] not in NO_CRYPTO_PACKETS:
            self.logger.warning('Dropping cell (only create/created can have plaintext flag set)')
            return

        self.on_packet_from_circuit(source_address, cell.unwrap(self._prefix), circuit_id)

        if circuit:
            circuit.beat_heart()
            circuit.bytes_down += len(data)

    def on_packet_from_circuit(self, source_address, data, circuit_id):
        if self._prefix != data[:22]:
            return
        msg_id = data[22]
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
                      if peer not in self.get_candidates(PEER_FLAG_EXIT_BT)][:4]
        peers_keys = {c.public_key.key_to_bin(): c for c in peers_list}

        peer = Peer(create_payload.node_public_key, previous_node_address)
        self.request_cache.add(CreatedRequestCache(self, circuit_id, peer, peers_keys, self.settings.unstable_timeout))
        self.exit_sockets[circuit_id] = TunnelExitSocket(circuit_id, peer, self)

        candidate_list_bin = self.serializer.pack('varlenH-list', list(peers_keys.keys()))
        candidate_list_enc = self.crypto.encrypt_str(candidate_list_bin,
                                                     *self.crypto.get_session_keys(self.relay_session_keys[circuit_id],
                                                                                   EXIT_NODE))
        self.send_cell(Peer(create_payload.node_public_key, previous_node_address),
                       CreatedPayload(circuit_id, create_payload.identifier, key, auth, candidate_list_enc))

    @unpack_cell(CreatePayload)
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

    @unpack_cell(CreatedPayload)
    def on_created(self, source_address, payload, _):
        circuit_id = payload.circuit_id
        self.directions[circuit_id] = ORIGINATOR

        if self.request_cache.has("create", payload.identifier):
            request = self.request_cache.pop("create", payload.identifier)

            self.logger.info("Got CREATED message forward as EXTENDED to origin.")

            self.relay_from_to[request.to_circuit_id] = relay = RelayRoute(request.from_circuit_id, request.peer)
            self.relay_from_to[request.from_circuit_id] = RelayRoute(request.to_circuit_id, request.to_peer)
            self.relay_session_keys[request.to_circuit_id] = self.relay_session_keys[request.from_circuit_id]

            self.directions[request.from_circuit_id] = EXIT_NODE
            self.remove_exit_socket(request.from_circuit_id)

            self.send_cell(relay.peer,
                           ExtendedPayload(relay.circuit_id, request.extend_identifier,
                                           payload.key, payload.auth, payload.candidate_list_enc))
        elif self.request_cache.has("retry", payload.identifier):
            circuit = self.circuits[circuit_id]
            self._ours_on_created_extended(circuit, payload)
        else:
            self.logger.warning("Received unexpected created for circuit %d", payload.circuit_id)

    @unpack_cell(ExtendPayload)
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
        if payload.node_addr == ('0.0.0.0', 0) and payload.node_public_key not in request.candidates:
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

        cache = CreateRequestCache(self, payload.identifier, to_circuit_id, circuit_id, candidate, extend_candidate)
        self.request_cache.add(cache)

        self.send_cell(extend_candidate,
                       CreatePayload(to_circuit_id, cache.number, self.my_peer.public_key.key_to_bin(), payload.key))

    @unpack_cell(ExtendedPayload)
    def on_extended(self, source_address, payload, _):
        if not self.request_cache.has("retry", payload.identifier):
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
        payload, _ = self.serializer.unpack_serializable(DataPayload, data, offset=23)

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
    def on_ping(self, source_address, payload, _):
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
                cache = PingRequestCache(self)
                self.request_cache.add(cache)
                self.send_cell(circuit.peer, PingPayload(circuit.circuit_id, cache.number))

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
        if circuit_id not in self.exit_sockets:
            self.logger.error("Dropping data packets with unknown circuit_id")
            return

        if not self.exit_sockets[circuit_id].enabled:
            # Check that we got the data from the correct IP.
            if sock_addr[0] == self.exit_sockets[circuit_id].peer.address[0]:
                self.exit_sockets[circuit_id].enable()
            else:
                self.logger.error("Dropping outbound relayed packet: IP's are %s != %s",
                                  str(sock_addr), str(self.exit_sockets[circuit_id].peer.address))
                return
        try:
            self.exit_sockets[circuit_id].sendto(data, destination)
        except Exception:
            self.logger.warning("Dropping data packets while exiting")

    async def dht_peer_lookup(self, mid, peer=None):
        if self.dht_provider:
            await self.dht_provider.peer_lookup(mid, peer)
        else:
            self.logger.error("Need a DHT provider to connect to a peer using the DHT")

    def send_test_request(self, circuit, request_size=0, response_size=0):
        cache = TestRequestCache(self, circuit)
        self.request_cache.add(cache)
        self.send_cell(circuit.peer,
                       TestRequestPayload(circuit.circuit_id, cache.number, response_size, os.urandom(request_size)))
        return cache.future

    def on_test_request(self, source_address, data, circuit_id):
        if PEER_FLAG_SPEED_TEST not in self.settings.peer_flags:
            self.logger.warning("Ignoring test-request from circuit %d", circuit_id)
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

    def on_test_response(self, source_address, data, circuit_id):
        payload, _ = self.serializer.unpack_serializable(TestResponsePayload, data, offset=23)
        circuit = self.circuits.get(circuit_id)
        if not circuit:
            self.logger.error("Dropping test-response with unknown circuit_id")
            return
        if not self.request_cache.has("test-request", payload.identifier):
            self.logger.error("Dropping unexpected test-response")
            return

        self.logger.debug("Got test-response (%d) from %s", circuit_id, source_address)
        cache = self.request_cache.pop("test-request", payload.identifier)
        cache.future.set_result((payload.data, time.time() - cache.ts))
