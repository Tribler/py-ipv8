from __future__ import absolute_import

import errno
from collections import deque
import socket
import sys

from six.moves import xrange
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
        # If the outbound network buffer is blocked, buffer up to 100 packets
        # Pop from the left and append to the right side of the double-ended queue
        self._delayed_packets = deque(maxlen=min(100, max(0, sys.getrecursionlimit() - 2)))

        self.bytes_up = 0
        self.bytes_down = 0

    def datagramReceived(self, datagram, addr):
        self.bytes_down += len(datagram)
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
            self.bytes_up += len(packet)
            # If the write succeeded, try sending one of our previously blocked packets
            try:
                self.send(*self._delayed_packets.popleft())
            except IndexError:
                # This can happen if the queue is empty, in which case we don't care
                pass
        except socket.error as exc:
            # Not all OSes have WSAEWOULDBLOCK: Windows may have a blocked output buffer
            errnum = exc[0] if hasattr(exc, "__getitem__") else exc.errno
            if errnum == getattr(errno, 'WSAEWOULDBLOCK', 10035):
                self._logger.info("Rescheduling packet (due to blocked socket) outbound to %s", str(socket_address))
                self._delayed_packets.append((socket_address, packet))
            else:
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
