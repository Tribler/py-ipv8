from __future__ import annotations

import asyncio
import logging
import socket
from asyncio import DatagramTransport
from typing import NamedTuple, TypeAlias, cast

from ..endpoint import Endpoint, EndpointClosedException


class UDPv4Address(NamedTuple):
    """
    An IPv4 address intended for UDP communication.
    """

    ip: str
    port: int


class UDPv4LANAddress(NamedTuple):
    """
    An IPv4 address intended for UDP communication over lan networks.
    """

    ip: str
    port: int


class UDPv6Address(NamedTuple):
    """
    An IPv6 address intended for UDP communication.
    """

    ip: str
    port: int


class DomainAddress(NamedTuple):
    """
    A host-port combination for DNS servers.
    """

    host: str
    port: int


Address: TypeAlias = tuple[str, int] | UDPv4Address | UDPv6Address | DomainAddress
SocketOption = tuple[int, int, int]


class UDPEndpoint(Endpoint, asyncio.DatagramProtocol):
    """
    Endpoint that binds UDP (over IPv4 by default).
    """

    SOCKET_FAMILY = socket.AF_INET

    def __init__(self, port: int = 0, ip: str = "0.0.0.0", sockopts: list[SocketOption] | None = None) -> None:
        """
        Create a new UDP endpoint that will attempt to bind on the given ip and ATTEMPT to claim the given port.

        WARNING: If the given port is in use, the next 10k available ports will be attempted until a free one is found.
        """
        Endpoint.__init__(self)
        # Endpoint info
        self._port = port
        self._ip = ip
        self._running = False
        self._sockopts = [(socket.SOL_SOCKET, socket.SO_RCVBUF, 870400)] if sockopts is None else sockopts

        # The transport object passed on by Asyncio
        self._transport: DatagramTransport | None = None

        # Byte counters
        self.bytes_up = 0
        self.bytes_down = 0

    def datagram_received(self, datagram: bytes, addr: Address) -> None:
        """
        Process incoming data.
        """
        # If the endpoint is still running, accept incoming requests, otherwise drop them
        if self._running:
            self.bytes_down += len(datagram)
            self.notify_listeners((UDPv4Address(*addr), datagram))

    def send(self, socket_address: Address, packet: bytes) -> None:
        """
        Send a packet to a given address.

        :param socket_address: Tuple of (IP, port) which indicates the destination of the packet.
        :param packet: the raw (binary) data to send.
        """
        self.assert_open()
        try:
            cast("DatagramTransport", self._transport).sendto(packet, socket_address)
            self.bytes_up += len(packet)
        except (TypeError, ValueError, AttributeError) as exc:
            self._logger.warning("Dropping packet due to message formatting error: %s", exc)

    def log_error(self, message: str, level: int = logging.WARNING) -> None:
        """
        Log a message using our own logger instance.
        """
        self._logger.log(level, message)

    async def open(self) -> bool:
        """
        Open the Endpoint.

        :return: True is the Endpoint was successfully opened, False otherwise.
        """
        # If the endpoint is already running, then there is no need to try and open it again

        if self._running:
            return True

        loop = asyncio.get_running_loop()

        for _ in range(10000):
            try:
                # It is recommended that this endpoint is opened at port = 0,
                # such that the OS handles the port assignment
                s = socket.socket(self.SOCKET_FAMILY, socket.SOCK_DGRAM)
                for level, optname, value in self._sockopts:
                    s.setsockopt(level, optname, value)
                s.bind((self._ip, self._port))
                s.setblocking(False)
                self._port = s.getsockname()[1]

                self._transport, _ = await loop.create_datagram_endpoint(lambda: self, sock=s)

                self._logger.debug("Listening at %d", self._port)
                break
            except (OSError, ValueError):
                self._logger.debug("Listening failed at %d", self._port)
                self._port += 1
                continue

        self._running = True
        return True

    def assert_open(self) -> None:
        """
        Check if we are opened by the programmer and if the underlying transport is fully open.
        """
        if not self._running and (not self._transport or not cast("DatagramTransport", self._transport).is_closing()):
            raise EndpointClosedException(self)

    def close(self) -> None:
        """
        Closes the Endpoint.
        """
        if not self._running:
            return

        self._running = False

        if not cast("DatagramTransport", self._transport).is_closing():
            cast("DatagramTransport", self._transport).close()

    def get_address(self) -> Address:
        """
        Get the address for this Endpoint.
        """
        self.assert_open()
        return cast("DatagramTransport", self._transport).get_extra_info("socket").getsockname()

    def is_open(self) -> bool:
        """
        Check if the underlying socket is open.
        """
        return self._running

    def reset_byte_counters(self) -> None:
        """
        Set bytes_up and bytes_down to 0.
        """
        self.bytes_up = 0
        self.bytes_down = 0


class UDPv6Endpoint(UDPEndpoint):
    """
    UDPEndpoint subclass that binds to IPv6 instead of IPv4.
    """

    SOCKET_FAMILY = socket.AF_INET6

    def __init__(self, port: int = 0, ip: str = "::") -> None:
        """
        Create new UDP endpoint over IPv6.
        """
        super().__init__(port, ip, [(socket.SOL_SOCKET, socket.SO_RCVBUF, 870400),
                                    (socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)])

    def datagram_received(self, datagram: bytes, addr: Address) -> None:
        """
        Process incoming data.
        """
        # If the endpoint is still running, accept incoming requests, otherwise drop them
        if self._running:
            self.bytes_down += len(datagram)
            self.notify_listeners((UDPv6Address(*addr[:2]), datagram))
