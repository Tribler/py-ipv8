import asyncio
import collections
import logging
import socket

from ..endpoint import Endpoint, EndpointClosedException


UDPv4Address = collections.namedtuple("UDPv4Address", ["ip", "port"])
UDPv4LANAddress = collections.namedtuple("UDPv4LANAddress", ["ip", "port"])
UDPv6Address = collections.namedtuple("UDPv6Address", ["ip", "port"])
DomainAddress = collections.namedtuple("DomainAddress", ["host", "port"])


class UDPEndpoint(Endpoint, asyncio.DatagramProtocol):

    SOCKET_FAMILY = socket.AF_INET

    def __init__(self, port=0, ip="0.0.0.0"):
        Endpoint.__init__(self)
        # Endpoint info
        self._port = port
        self._ip = ip
        self._running = False

        # The transport object passed on by Asyncio
        self._transport = None

        # Byte counters
        self.bytes_up = 0
        self.bytes_down = 0

    def datagram_received(self, datagram, addr):
        # If the endpoint is still running, accept incoming requests, otherwise drop them
        if self._running:
            self.bytes_down += len(datagram)
            self.notify_listeners((UDPv4Address(*addr), datagram))

    def send(self, socket_address, packet):
        """
        Send a packet to a given address.
        :param socket_address: Tuple of (IP, port) which indicates the destination of the packet.
        """
        self.assert_open()
        try:
            self._transport.sendto(packet, socket_address)
            self.bytes_up += len(packet)
        except (TypeError, ValueError, AttributeError) as exc:
            self._logger.warning("Dropping packet due to message formatting error: %s", exc)

    def log_error(self, message, level=logging.WARNING):
        self._logger.log(level, message)

    async def open(self):
        """
        Open the the Endpoint.

        :return: True is the Endpoint was successfully opened, False otherwise.
        """
        # If the endpoint is already running, then there is no need to try and open it again

        if self._running:
            return True

        loop = asyncio.get_event_loop()

        for _ in range(10000):
            try:
                # It is recommended that this endpoint is opened at port = 0,
                # such that the OS handles the port assignment
                self._transport = socket.socket(self.SOCKET_FAMILY, socket.SOCK_DGRAM)
                self._transport.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 870400)
                self._transport.bind((self._ip, self._port))
                self._transport.setblocking(False)
                self._port = self._transport.getsockname()[1]

                self._transport, _ = await loop.create_datagram_endpoint(lambda: self,
                                                                         sock=self._transport)

                self._logger.debug("Listening at %d", self._port)
                break
            except (OSError, ValueError):
                self._logger.debug("Listening failed at %d", self._port)
                self._port += 1
                continue

        self._running = True
        return True

    def assert_open(self):
        if not self._running and (not self._transport or not self._transport.is_closing()):
            raise EndpointClosedException(self)

    def close(self):
        """
        Closes the Endpoint.
        """
        if not self._running:
            return

        self._running = False

        if not self._transport.is_closing():
            self._transport.close()

    def get_address(self):
        """
        Get the address for this Endpoint.
        """
        self.assert_open()
        return self._transport.get_extra_info("socket").getsockname()

    def is_open(self):
        """
        Check if the underlying socket is open.
        """
        return self._running

    def reset_byte_counters(self):
        """
        Set bytes_up and bytes_down to 0.
        """
        self.bytes_up = 0
        self.bytes_down = 0


class UDPv6Endpoint(UDPEndpoint):

    SOCKET_FAMILY = socket.AF_INET6

    def __init__(self, port=0, ip="::"):
        super(UDPv6Endpoint, self).__init__(port, ip)

    def datagram_received(self, datagram, addr):
        # If the endpoint is still running, accept incoming requests, otherwise drop them
        if self._running:
            self.bytes_down += len(datagram)
            self.notify_listeners((UDPv6Address(*addr[:2]), datagram))
