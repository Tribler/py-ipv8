from collections import defaultdict
import logging
import socket
from struct import unpack_from
import time

from twisted.internet import reactor
from twisted.internet.error import MessageLengthError
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.defer import inlineCallbacks, maybeDeferred, returnValue, succeed

from ...keyvault.public.libnaclkey import LibNaCLPK
from ...taskmanager import TaskManager
from ...util import blocking_call_on_reactor_thread


ORIGINATOR = 0
EXIT_NODE = 1
ORIGINATOR_SALT = 2
EXIT_NODE_SALT = 3
ORIGINATOR_SALT_EXPLICIT = 4
EXIT_NODE_SALT_EXPLICIT = 5

# Data circuits are supposed to end in an exit peer that allows exiting data to the outside world
CIRCUIT_TYPE_DATA = 'DATA'

# The other circuits are supposed to end in a connectable node, not allowed to exit
# anything else than IPv8 messages, used for setting up end-to-end circuits
CIRCUIT_TYPE_IP = 'IP'
CIRCUIT_TYPE_RP = 'RP'
CIRCUIT_TYPE_RENDEZVOUS = 'RENDEZVOUS'

CIRCUIT_STATE_READY = 'READY'
CIRCUIT_STATE_EXTENDING = 'EXTENDING'
CIRCUIT_STATE_TO_BE_EXTENDED = 'TO_BE_EXTENDED'
CIRCUIT_STATE_CLOSING = 'CLOSING'

CIRCUIT_ID_PORT = 1024
PING_INTERVAL = 15.0


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
        if len(data) >= 8 and (0 <= unpack_from('!I', data, 0)[0] <= 3) or \
                                len(data) >= 12 and (0 <= unpack_from('!I', data, 8)[0] <= 3):
            return True
        return False

    @staticmethod
    def could_be_dht(data):
        try:
            if len(data) > 1 and data[0] == 'd' and data[-1] == 'e':
                return True
        except:
            pass
        return False

    @staticmethod
    def could_be_ipv8(data):
        return data[0] == 0 and data[1] in [1, 2] and len(data) >= 23

    @staticmethod
    def is_allowed(data):
        return (DataChecker.could_be_utp(data) or
                DataChecker.could_be_udp_tracker(data) or
                DataChecker.could_be_dht(data) or
                DataChecker.could_be_ipv8(data))


class Tunnel(object):

    def __init__(self, circuit_id, peer):
        self.circuit_id = circuit_id
        self.peer = peer
        self.creation_time = time.time()
        self.last_incoming = time.time()
        self.bytes_up = self.bytes_down = 0
        self.logger = logging.getLogger(self.__class__.__name__)


class TunnelExitSocket(Tunnel, DatagramProtocol, TaskManager):

    def __init__(self, circuit_id, peer, overlay):
        Tunnel.__init__(self, circuit_id, peer)
        TaskManager.__init__(self)
        self.overlay = overlay
        self.port = None
        self.ips = defaultdict(int)

    @blocking_call_on_reactor_thread
    def enable(self):
        if not self.enabled:
            self.port = reactor.listenUDP(0, self)

    @property
    def enabled(self):
        return self.port is not None

    def sendto(self, data, destination):
        self.last_incoming = time.time()
        if self.check_num_packets(destination, False):
            if DataChecker.is_allowed(data):
                def on_error(failure):
                    self.logger.error("Can't resolve ip address for hostname %s. Failure: %s",
                                             destination[0], failure)

                def on_ip_address(ip_address):
                    self.logger.debug("Resolved hostname %s to ip_address %s", destination[0], ip_address)
                    try:
                        self.transport.write(data, (ip_address, destination[1]))
                        self.overlay.increase_bytes_sent(self, len(data))
                    except (AttributeError, MessageLengthError, socket.error) as exception:
                        self.logger.error(
                            "Failed to write data to transport: %s. Destination: %r error was: %r",
                            exception, destination, exception)

                resolve_ip_address_deferred = reactor.resolve(destination[0])
                resolve_ip_address_deferred.addCallbacks(on_ip_address, on_error)
                self.register_task("resolving_%r" % destination[0], resolve_ip_address_deferred)
            else:
                self.logger.error("dropping forbidden packets from exit socket with circuit_id %d",
                                         self.circuit_id)

    def datagramReceived(self, data, source):
        self.last_incoming = time.time()
        self.overlay.increase_bytes_received(self, len(data))
        if self.check_num_packets(source, True):
            if DataChecker.is_allowed(data):
                self.tunnel_data(source, data)
            else:
                self.logger.warning("dropping forbidden packets to exit socket with circuit_id %d",
                                           self.circuit_id)

    def tunnel_data(self, source, data):
        self.logger.debug("Tunnel data to origin %s for circuit %s", ('0.0.0.0', 0), self.circuit_id)
        self.overlay.send_data([self.peer], self.circuit_id, ('0.0.0.0', 0), source, data)

    @inlineCallbacks
    def close(self):
        """
        Closes the UDP socket if enabled and cancels all pending deferreds.
        :return: A deferred that fires once the UDP socket has closed.
        """
        # The resolution deferreds can't be cancelled, so we need to wait for
        # them to finish.
        yield self.wait_for_deferred_tasks()
        self.shutdown_task_manager()
        done_closing_deferred = succeed(None)
        if self.enabled:
            done_closing_deferred = maybeDeferred(self.port.stopListening)
            self.port = None
        res = yield done_closing_deferred
        returnValue(res)

    def check_num_packets(self, ip, incoming):
        if self.ips[ip] < 0:
            return True

        max_packets_without_reply = self.overlay.settings.max_packets_without_reply
        if self.ips[ip] >= (max_packets_without_reply + 1 if incoming else max_packets_without_reply):
            self.overlay.remove_exit_socket(self.circuit_id, destroy=True)
            self.logger.error("too many packets to a destination without a reply, "
                               "removing exit socket with circuit_id %d", self.circuit_id)
            return False

        if incoming:
            self.ips[ip] = -1
        else:
            self.ips[ip] += 1

        return True


class Circuit(Tunnel):

    def __init__(self, circuit_id, peer, goal_hops=0, ctype=CIRCUIT_TYPE_DATA,
                 callback=None, required_exit=None, info_hash=None):
        super(Circuit, self).__init__(circuit_id, peer)
        self.goal_hops = goal_hops
        self.ctype = ctype
        self.callback = callback
        self.required_exit = required_exit
        self.info_hash = info_hash

        self._closing = False
        self._hops = []
        self.unverified_hop = None
        self.hs_session_keys = None

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

    def beat_heart(self):
        """
        Mark the circuit as active
        """
        self.last_incoming = time.time()

    def close(self):
        """
        Sets the state of the circuit to CIRCUIT_STATE_CLOSING. This ensures that this circuit
        will not be used to contact new peers.
        """
        self._closing = True


class Hop(object):

    """
    Circuit Hop containing the address, its public key and the first part of
    the Diffie-Hellman handshake
    """

    def __init__(self, public_key=None):
        """
        @param None|LibNaCLPK public_key: public key object of the hop
        """

        assert public_key is None or isinstance(public_key, LibNaCLPK)

        self.session_keys = None
        self.dh_first_part = None
        self.dh_secret = None
        self.address = None
        self.public_key = public_key

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

    def __init__(self, circuit, cookie, finished_callback):
        self.circuit = circuit
        self.cookie = cookie
        self.finished_callback = finished_callback
        self.rp_info = None
