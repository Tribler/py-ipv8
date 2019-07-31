from __future__ import absolute_import

import asyncio
import logging


from ..endpoint import Endpoint, EndpointClosedException

UDP_MAX_SIZE = 2 ** 16 - 60


class DatagramProtocolWrapper(asyncio.DatagramProtocol):
    """
    Implements the callbacks for when a datagram is received and when an error is received
    """

    def __init__(self, endpoint):
        self._endpoint = endpoint

    def connection_made(self, transport):
        self._endpoint._transport = transport

    def connection_lost(self, exc):
        if exc:
            self._endpoint.log_error("Connection lost due to: {}".format(exc))
        self._endpoint.close()

    def datagram_received(self, data, addr):
        self._endpoint.datagram_received(data, addr)

    def error_received(self, exc):
        self._endpoint.log_error("Error received: {}".format(exc))


class UDPEndpoint(Endpoint):

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
            self.notify_listeners((addr, datagram))

    async def send(self, socket_address, packet):
        """
        Send a packet to a given address.
        :param socket_address: Tuple of (IP, port) which indicates the destination of the packet.
        """
        self.assert_open()
        try:
            self._transport.sendto(packet, socket_address)
            self.bytes_up += len(packet)
        except (TypeError, ValueError) as exc:
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

        try:
            # It is recommended that this endpoint is opened at port = 0, such that the OS handles the port assignment
            await loop.create_datagram_endpoint(local_addr=(self._ip, self._port),
                                                protocol_factory=lambda: DatagramProtocolWrapper(self),
                                                reuse_port=False)
        except (OSError, ValueError) as exc:
            self._logger.error("Could not start Datagram Endpoint due to: {!r}".format(exc))
            return False
        else:
            self._running = True
            return True

    def assert_open(self):
        if not self._running and not self._transport.is_closing():
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
