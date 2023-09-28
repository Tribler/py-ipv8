from __future__ import annotations

import logging
from asyncio import BaseTransport, DatagramProtocol, get_running_loop
from binascii import hexlify
from socket import AF_INET, SO_BROADCAST, SO_REUSEADDR, SOCK_DGRAM, SOL_SOCKET, socket
from time import time
from typing import TYPE_CHECKING, Iterable

from ..bootstrapper_interface import Bootstrapper

if TYPE_CHECKING:
    from ...types import Address, Community

PROTOCOL_VERSION = b'\x00\x00'
MAGIC = b'\x49\x50\x76\x38'

HDR_ANNOUNCE = PROTOCOL_VERSION + MAGIC + b'\x00'


class BroadcastBootstrapEndpoint(DatagramProtocol):
    """
    Endpoint that opens a broadcast socket.
    """

    def __init__(self, overlay: Community) -> None:
        """
        Create a new endpoint instance.
        """
        super().__init__()

        self._socket: socket | None = None
        self._transport: BaseTransport | None = None
        self.overlay = overlay
        self.logger = logging.getLogger(self.__class__.__name__)

    async def open(self) -> bool:  # noqa: A003
        """
        Open the broadcast socket.
        """
        loop = get_running_loop()

        try:
            self._socket = socket(AF_INET, SOCK_DGRAM)
            self._socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            self._socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
            self._socket.bind(('', 0))
            self._transport, _ = await loop.create_datagram_endpoint(lambda: self, sock=self._socket)
        except (OSError, ValueError):
            return False

        return True

    def send(self, socket_address: Address, data: bytes) -> None:
        """
        Attempt to send data to the given socket address and silently fail.
        """
        try:
            if self._socket is not None:
                self._socket.sendto(data, socket_address)
        except (TypeError, ValueError, AttributeError, OSError):
            pass  # Windows doesn't really care, Ubuntu throws an exception on "illegal" ports

    def datagram_received(self, data: bytes, addr: Address) -> None:
        """
        We received data on our broadcast socket.

        Note that we do not use the broadcast socket but the overlay socket to send a reply.
        """
        if data.startswith(HDR_ANNOUNCE):
            if self.overlay.get_prefix() == data[len(HDR_ANNOUNCE):]:
                self.logger.debug("Received data from beacon %s: attempting walk!", repr(addr))
                self.overlay.walk_to(addr)
            # Otherwise: valid, but not for our overlay
        elif data.startswith(self.overlay.get_prefix()):
            self.logger.debug("Walk success by %s: attempting handoff!", repr(addr))
            self.overlay.on_packet((addr, data))
        else:
            self.logger.debug("Dropping garbage packet from %s: %s", repr(addr), hexlify(data))

    def close(self) -> None:
        """
        Close this endpoint.
        """
        if self._transport is not None and not self._transport.is_closing():
            self._transport.close()


class UDPBroadcastBootstrapper(Bootstrapper):
    """
    Bootstrapper that finds peers by iterating over ALL 65k ports of the local broadcast address.
    """

    def __init__(self, bootstrap_timeout: float = 30.0) -> None:
        """
        Create a new bootstrapper instance.
        """
        super().__init__()

        self.endpoint: BroadcastBootstrapEndpoint | None = None
        self.overlay: Community | None = None

        self.bootstrap_timeout = bootstrap_timeout

        self.last_bootstrap: float = 0

    async def initialize(self, overlay: Community) -> bool:
        """
        Initialize this bootstrapper for the given overlay.
        """
        if self.initialized:
            return True
        self.initialized = True

        self.overlay = overlay

        # Open the socket
        endpoint = BroadcastBootstrapEndpoint(overlay)
        success = await endpoint.open()
        if not success:
            return False
        self.endpoint = endpoint

        # Start sending
        self.beacon(overlay.get_prefix())

        return True

    def beacon(self, service_prefix: bytes) -> None:
        """
        Try to find a listener (fire and forget).
        """
        if self.endpoint is not None:
            for p in range(65535):
                self.endpoint.send(('255.255.255.255', p), HDR_ANNOUNCE + service_prefix)

    async def get_addresses(self, overlay: Community, timeout: float) -> Iterable[Address]:
        """
        Attempt to find addresses. This method will never return addresses immediately.
        """
        if time() - self.last_bootstrap < self.bootstrap_timeout:
            return []
        logging.debug("Bootstrapping %s, current peers %d", overlay.__class__.__name__,
                      len(overlay.get_peers()))
        self.last_bootstrap = time()
        self.beacon(overlay.get_prefix())
        return []

    def keep_alive(self, overlay: Community) -> None:
        """
        Send a "keep alive" message.
        """
        self.beacon(overlay.get_prefix())

    def blacklist(self) -> Iterable[Address]:
        """
        Get the blacklisted addresses.
        """
        return []

    def unload(self) -> None:
        """
        Stop this bootstrapper.
        """
        if self.endpoint:
            self.endpoint.close()
