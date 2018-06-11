import socket

from twisted.internet import protocol, reactor, error
from twisted.internet.error import MessageLengthError

from ..endpoint import Endpoint, EndpointClosedException

UDP_MAX_SIZE = 2 ** 16 - 60


class UDPEndpoint(Endpoint, protocol.DatagramProtocol):

    def __init__(self, port, ip="0.0.0.0"):
        Endpoint.__init__(self)
        self._port = port
        self._ip = ip
        self._running = False
        self._listening_port = False

    def datagramReceived(self, datagram, addr):
        self.notify_listeners((addr, datagram))

    def send(self, socket_address, packet):
        """
        Send a packet to a given address.
        :param socket_address: Tuple of (IP, port) which indicates the destination of the packet.
        :param packet: The packet to send.
        """
        self.assert_open()
        try:
            self.transport.write(packet, socket_address)
        except socket.error as exc:
            self._logger.warning("Dropping packet due to socket error: %s", exc)
        except MessageLengthError:
            self._logger.error("Sending a packet that is too big (length: %d)", len(packet))

    def open(self):
        for _ in xrange(10000):
            try:
                self._listening_port = reactor.listenUDP(self._port, self, self._ip, UDP_MAX_SIZE)
                self._logger.debug("Listening at %d", self._port)
                break
            except error.CannotListenError:
                self._logger.debug("Listening failed at %d", self._port)
                self._port += 1
                continue
        self._running = True
        return True

    def assert_open(self):
        if not self._running:
            raise EndpointClosedException(self)

    def close(self):
        self._running = False
        return self._listening_port.stopListening()

    def get_address(self):
        """
        Get the address for this Endpoint.
        """
        self.assert_open()
        return (self._listening_port.getHost().host,
                self._listening_port.getHost().port)

    def is_open(self):
        """
        Check if the underlying socket is open.
        """
        return self._listening_port and self._running
