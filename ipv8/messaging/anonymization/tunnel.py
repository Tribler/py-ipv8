import logging
import random
import socket
import sys
import time
from asyncio import DatagramProtocol, Future, ensure_future, get_event_loop
from binascii import hexlify
from collections import defaultdict, deque
from struct import unpack_from
from traceback import format_exception

from ...keyvault.public.libnaclkey import LibNaCLPK
from ...taskmanager import TaskManager
from ...util import succeed

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
PEER_FLAG_EXIT_ANY = 2
PEER_FLAG_EXIT_IPV8 = 4

# Data circuits are supposed to end in an exit peer that allows exiting data to the outside world
CIRCUIT_TYPE_DATA = 'DATA'
CIRCUIT_TYPE_IPV8 = 'IPV8'

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


class DataChecker(object):

    @staticmethod
    def could_be_utp(data):
        if len(data) < 20:
            return False
        byte1, byte2 = unpack_from('!BB', data)
        # Type should be 0..4, Ver should be 1
        if not (0 <= (byte1 >> 4) <= 4 and (byte1 & 15) == 1):
            return False
        # Extension should be 0..2
        if not (0 <= byte2 <= 2):
            return False
        return True

    @staticmethod
    def could_be_udp_tracker(data):
        # For the UDP tracker protocol the action field is either at position 0 or 8, and should be 0..3
        if len(data) >= 8 and (0 <= unpack_from('!I', data, 0)[0] <= 3)\
                or len(data) >= 12 and (0 <= unpack_from('!I', data, 8)[0] <= 3):
            return True
        return False

    @staticmethod
    def could_be_dht(data):
        try:
            if len(data) > 1 and data[0:1] == b'd' and data[-1:] == b'e':
                return True
        except TypeError:
            pass
        return False

    @staticmethod
    def could_be_ipv8(data):
        return len(data) >= 23 and data[0:1] == b'\x00' and data[1:2] in [b'\x01', b'\x02']

    @staticmethod
    def is_allowed(data):
        return (DataChecker.could_be_utp(data)
                or DataChecker.could_be_udp_tracker(data)
                or DataChecker.could_be_dht(data)
                or DataChecker.could_be_ipv8(data))


class Tunnel(object):

    def __init__(self, circuit_id, peer):
        self.circuit_id = circuit_id
        self._peer = peer
        self.creation_time = time.time()
        self.last_activity = time.time()
        self.bytes_up = self.bytes_down = 0
        self.logger = logging.getLogger(self.__class__.__name__)

    @property
    def peer(self):
        return self._peer

    def beat_heart(self):
        self.last_activity = time.time()


class TunnelExitSocket(Tunnel, DatagramProtocol, TaskManager):

    def __init__(self, circuit_id, peer, overlay):
        Tunnel.__init__(self, circuit_id, peer)
        TaskManager.__init__(self)
        self.overlay = overlay
        self.transport = None
        self.queue = deque(maxlen=10)
        self.enabled = False
        self.ips = defaultdict(int)

    def enable(self):
        if not self.enabled:
            self.enabled = True

            async def create_transport():
                self.transport, _ = await get_event_loop().create_datagram_endpoint(lambda: self,
                                                                                    local_addr=('0.0.0.0', 0))
                # Send any packets that have been waiting while the transport was being created
                while self.queue:
                    self.sendto(*self.queue.popleft())
            self.register_task("create_transport", create_transport)

    def sendto(self, data, destination):
        if not self.transport:
            self.queue.append((data, destination))
            return

        self.beat_heart()
        if self.check_num_packets(destination, False):
            if DataChecker.is_allowed(data):
                def on_ip_address(future):
                    try:
                        ip_address = future.result()
                    except Exception as e:
                        self.logger.error("Can't resolve ip address for %s. Failure: %s", destination[0], e)
                        return

                    self.logger.debug("Resolved hostname %s to ip_address %s", destination[0], ip_address)
                    try:
                        self.transport.sendto(data, (ip_address, destination[1]))
                        self.overlay.increase_bytes_sent(self, len(data))
                    except socket.error as e:
                        self.logger.error("Failed to write to transport. Destination: %r error: %r", destination, e)

                try:
                    socket.inet_aton(destination[0])
                    on_ip_address(succeed(destination[0]))
                except (OSError, ValueError):
                    task = ensure_future(self.resolve(destination[0]))
                    # If this also fails, the TaskManager logs the packet.
                    # The host probably really does not exist.
                    self.register_anonymous_task("resolving_%r" % destination[0], task,
                                                 ignore=(OSError, ValueError)).add_done_callback(on_ip_address)

    async def resolve(self, host):
        # Using asyncio's getaddrinfo since the aiodns resolver seems to have issues.
        # Returns [(family, type, proto, canonname, sockaddr)].
        infos = await get_event_loop().getaddrinfo(host, 0, family=socket.AF_INET)
        return infos[0][-1][0]

    def datagram_received(self, data, source):
        self.beat_heart()
        self.overlay.increase_bytes_received(self, len(data))
        if self.check_num_packets(source, True):
            if DataChecker.is_allowed(data):
                try:
                    self.tunnel_data(source, data)
                except Exception:
                    self.logger.error("Exception occurred while handling incoming exit node data!\n"
                                      + ''.join(format_exception(*sys.exc_info())))
            else:
                self.logger.warning("Dropping forbidden packets to exit socket with circuit_id %d", self.circuit_id)

    def tunnel_data(self, source, data):
        self.logger.debug("Tunnel data to origin %s for circuit %s", ('0.0.0.0', 0), self.circuit_id)
        self.overlay.send_data([self.peer], self.circuit_id, ('0.0.0.0', 0), source, data)

    async def close(self):
        """
        Closes the UDP socket if enabled and cancels all pending deferreds.
        :return: A deferred that fires once the UDP socket has closed.
        """
        # The resolution tasks can't be cancelled, so we need to wait for
        # them to finish.
        await self.shutdown_task_manager()
        self.transport.close()
        self.transport = None

    def check_num_packets(self, ip, incoming):
        if self.ips[ip] < 0:
            return True

        max_packets_without_reply = self.overlay.settings.max_packets_without_reply
        if self.ips[ip] >= (max_packets_without_reply + 1 if incoming else max_packets_without_reply):
            self.overlay.remove_exit_socket(self.circuit_id, destroy=DESTROY_REASON_FORBIDDEN)
            self.logger.error("too many packets to a destination without a reply, "
                              "removing exit socket with circuit_id %d", self.circuit_id)
            return False

        if incoming:
            self.ips[ip] = -1
        else:
            self.ips[ip] += 1

        return True


class Circuit(Tunnel):

    def __init__(self, circuit_id, goal_hops=0, ctype=CIRCUIT_TYPE_DATA, required_exit=None, info_hash=None):
        super(Circuit, self).__init__(circuit_id, None)
        self.goal_hops = goal_hops
        self.ctype = ctype
        self.required_exit = required_exit
        self.info_hash = info_hash

        self.ready = Future()
        self.closing_info = ''
        self._closing = False
        self._hops = []
        self.unverified_hop = None
        self.hs_session_keys = None
        self.e2e = False

    @property
    def peer(self):
        return self._hops[0] if self._hops else self.unverified_hop

    @property
    def exit_flags(self):
        return self.hops[-1].flags if self.hops else []

    @property
    def hops(self):
        """
        Return a read only tuple version of the hop-list of this circuit
        @rtype tuple[Hop]
        """
        return tuple(self._hops)

    def add_hop(self, hop):
        """
        Adds a hop to the circuits hop collection
        @param Hop hop: the hop to add
        """
        self._hops.append(hop)
        if self.state == CIRCUIT_STATE_READY:
            self.ready.set_result(self)

    @property
    def state(self):
        """
        The circuit state, can be either:
        CIRCUIT_STATE_CLOSING, CIRCUIT_STATE_EXTENDING or CIRCUIT_STATE_READY
        @rtype: str
        """
        if self._closing:
            return CIRCUIT_STATE_CLOSING

        if len(self.hops) < self.goal_hops:
            return CIRCUIT_STATE_EXTENDING
        else:
            return CIRCUIT_STATE_READY

    def close(self, closing_info=''):
        """
        Sets the state of the circuit to CIRCUIT_STATE_CLOSING. This ensures that this circuit
        will not be used to contact new peers.
        """
        self.closing_info = closing_info
        self._closing = True
        if not self.ready.done():
            self.ready.set_result(None)

    def __eq__(self, other):
        return other and self.circuit_id == other.circuit_id


class Hop(object):

    """
    Circuit Hop containing the address, its public key and the first part of
    the Diffie-Hellman handshake
    """

    def __init__(self, public_key, flags=None):
        """
        @param LibNaCLPK public_key: public key object of the hop
        """
        assert isinstance(public_key, LibNaCLPK)

        self.session_keys = None
        self.dh_first_part = None
        self.dh_secret = None
        self.address = None
        self.public_key = public_key
        self.flags = flags or []

    @property
    def host(self):
        """
        The hop's hostname
        """
        if self.address:
            return self.address[0]
        return " UNKNOWN HOST "

    @property
    def port(self):
        """
        The hop's port
        """
        if self.address:
            return self.address[1]
        return " UNKNOWN PORT "

    @property
    def node_public_key(self):
        """
        The hop's public_key
        """
        if self.public_key:
            return self.public_key.key_to_bin()

        raise RuntimeError("public key unknown")

    @property
    def mid(self):
        return self.public_key.key_to_hash()


class RelayRoute(Tunnel):

    """
    Relay object containing the destination circuit, socket address and whether
    it is online or not
    """

    def __init__(self, circuit_id, peer, rendezvous_relay=False):
        """
        @type sock_addr: (str, int)
        @type circuit_id: int
        @return:
        """
        super(RelayRoute, self).__init__(circuit_id, peer)
        self.rendezvous_relay = rendezvous_relay


class RendezvousPoint(object):

    def __init__(self, circuit, cookie):
        self.circuit = circuit
        self.cookie = cookie
        self.ready = Future()
        self.rp_info = None


class IntroductionPoint(object):

    def __init__(self, peer, seeder_pk, source=PEER_SOURCE_UNKNOWN, last_seen=int(time.time())):
        self.peer = peer
        self.seeder_pk = seeder_pk
        self.source = source
        self.last_seen = last_seen

    def __eq__(self, other):
        return self.peer == other.peer and self.seeder_pk == other.seeder_pk

    def __hash__(self):
        return hash((self.peer, self.seeder_pk))


class Swarm(object):

    def __init__(self, info_hash, hops, lookup_func, seeder_sk=None, max_ip_age=180,
                 min_dht_lookup_interval=300, max_dht_lookup_interval=120):
        self.info_hash = info_hash
        self.hops = hops
        self.lookup_func = lookup_func
        self.seeder_sk = seeder_sk
        self.max_ip_age = max_ip_age
        self.min_dht_lookup_interval = min_dht_lookup_interval
        self.max_dht_lookup_interval = max_dht_lookup_interval

        self.intro_points = []
        self.connections = {}
        self.last_lookup = 0
        self.last_dht_response = 0
        self.transfer_history = [0, 0]

        self.logger = logging.getLogger(self.__class__.__name__)

    @property
    def seeding(self):
        return bool(self.seeder_sk)

    @property
    def _active_circuits(self):
        return [c for c, _ in self.connections.values() if c.state == CIRCUIT_STATE_READY and c.e2e]

    def add_connection(self, rp_circuit, intro_point_used):
        if rp_circuit.circuit_id not in self.connections:
            self.connections[rp_circuit.circuit_id] = (rp_circuit, intro_point_used)

    def remove_connection(self, rp_circuit):
        removed = self.connections.pop(rp_circuit.circuit_id, None)
        if removed:
            circuit, _ = removed
            self.transfer_history[0] += circuit.bytes_up
            self.transfer_history[1] += circuit.bytes_down
        return bool(removed)

    def has_connection(self, seeder_pk):
        return seeder_pk in [ip.seeder_pk for _, ip in self.connections.values()]

    def get_num_connections(self):
        return len(self._active_circuits)

    def get_num_connections_incomplete(self):
        return len(self.connections) - self.get_num_connections()

    def add_intro_point(self, ip):
        old_ip = next((i for i in self.intro_points if i == ip), None)

        if old_ip:
            old_ip.last_seen = time.time()
        else:
            self.intro_points.append(ip)

        return old_ip or ip

    def remove_old_intro_points(self):
        # Cleanup old introduction points
        now = time.time()
        used_intro_points = [i for c, i in self.connections.values() if c.state == CIRCUIT_STATE_READY and c.e2e]
        self.intro_points = [i for i in self.intro_points
                             if i.last_seen + self.max_ip_age >= now or i in used_intro_points]

    def remove_intro_point(self, ip):
        try:
            self.intro_points.remove(ip)
        except ValueError:
            pass

    async def lookup(self, target=None):
        def on_success(ips):
            if any([ip for ip in ips if ip.source == PEER_SOURCE_DHT]):
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
        elif self.intro_points:
            target = random.choice(self.intro_points)
            self.logger.info("Performing PEX lookup for swarm %s (target %s)",
                             hexlify(self.info_hash), target.peer)
            return on_success(await self.lookup_func(self.info_hash, target, self.hops))
        self.logger.info("Skipping lookup for swarm %s", hexlify(self.info_hash))

    def get_num_seeders(self):
        seeder_pks = {ip.seeder_pk for ip in self.intro_points}
        for _, ip in self.connections.values():
            seeder_pks.add(ip.seeder_pk)
        return len(seeder_pks)

    def get_total_up(self):
        return sum([c.bytes_up for c in self._active_circuits]) + self.transfer_history[0]

    def get_total_down(self):
        return sum([c.bytes_down for c in self._active_circuits]) + self.transfer_history[1]
