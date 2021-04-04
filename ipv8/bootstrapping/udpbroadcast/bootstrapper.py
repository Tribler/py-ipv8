import logging
from asyncio import BaseTransport, DatagramProtocol, get_event_loop
from asyncio.futures import Future
from binascii import hexlify
from socket import AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, SO_REUSEADDR, socket
from typing import Coroutine, Iterable, Optional, Union

from ..bootstrapper_interface import Bootstrapper
from ...types import Address, Community
from ...util import succeed


PROTOCOL_VERSION = b'\x00\x00'
MAGIC = b'\x49\x50\x76\x38'

HDR_ANNOUNCE = PROTOCOL_VERSION + MAGIC + b'\x00'


class BroadcastBootstrapEndpoint(DatagramProtocol):

    def __init__(self, overlay: Community):
        super().__init__()

        self._socket: Optional[socket] = None
        self._transport: Optional[BaseTransport] = None
        self.overlay = overlay
        self.logger = logging.getLogger(self.__class__.__name__)

    async def open(self) -> bool:
        loop = get_event_loop()

        try:
            self._socket = socket(AF_INET, SOCK_DGRAM)
            self._socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            self._socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
            self._socket.bind(('', 0))
            self._transport, _ = await loop.create_datagram_endpoint(lambda: self, sock=self._socket)
        except (OSError, ValueError):
            return False

        return True

    def send(self, socket_address, data: bytes):
        try:
            if self._socket is not None:
                self._socket.sendto(data, socket_address)
        except (TypeError, ValueError, AttributeError, OSError):
            pass  # Windows doesn't really care, Ubuntu throws an exception on "illegal" ports

    def datagram_received(self, data: bytes, addr) -> None:
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
        if self._transport is not None and not self._transport.is_closing():
            self._transport.close()


class UDPBroadcastBootstrapper(Bootstrapper):

    def __init__(self):
        self.endpoint = None
        self.overlay = None

    async def initialize(self, overlay: Community) -> Union[Future, Coroutine]:  # pylint: disable=W0236
        self.overlay = overlay

        # Open the socket
        endpoint = BroadcastBootstrapEndpoint(overlay)
        success = await endpoint.open()
        if not success:
            return succeed(False)
        self.endpoint = endpoint

        # Start sending
        self.beacon(overlay.get_prefix())

        return succeed(True)

    def beacon(self, service_prefix: bytes) -> None:
        """
        Try to find a listener (fire and forget).
        """
        if self.endpoint is not None:
            for p in range(65535):
                self.endpoint.send(('255.255.255.255', p), HDR_ANNOUNCE + service_prefix)

    async def get_addresses(self, overlay: Community, timeout: float) -> Iterable[Address]:
        self.beacon(overlay.get_prefix())
        return []

    def keep_alive(self, overlay: Community) -> None:
        self.beacon(overlay.get_prefix())

    def blacklist(self) -> Iterable[Address]:
        return []

    def unload(self) -> None:
        if self.endpoint:
            self.endpoint.close()
