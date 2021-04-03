import logging
from asyncio.futures import Future
from binascii import hexlify
from socket import AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, SO_REUSEADDR, socket
from threading import Thread
from typing import Coroutine, Iterable, Optional, Union

from ..bootstrapper_interface import Bootstrapper
from ...types import Address, Community
from ...util import succeed


PROTOCOL_VERSION = b'\x00\x00'
MAGIC = b'\x49\x50\x76\x38'

HDR_ANNOUNCE = PROTOCOL_VERSION + MAGIC + b'\x00'


class UDPBroadcastBootstrapper(Bootstrapper):

    def __init__(self):
        self.socket: Optional[socket] = None
        self.receive_thread = None
        self.overlay = None
        self.logger = logging.getLogger(self.__class__.__name__)

    def receive(self):
        while True:
            data, address = self.socket.recvfrom(1024)

            if data.startswith(HDR_ANNOUNCE):
                if self.overlay.get_prefix() == data[len(HDR_ANNOUNCE):]:
                    self.logger.debug("Received data from beacon %s: attempting walk!", repr(address))
                    self.overlay.walk_to(address)
                # Otherwise: valid, but not for our overlay
            elif data.startswith(self.overlay.get_prefix()):
                self.logger.debug("Walk success by %s: attempting handoff!", repr(address))
                self.overlay.on_packet((address, data))
            else:
                self.logger.debug("Dropping garbage packet from %s: %s", repr(address), hexlify(data))

    def initialize(self, overlay: Community) -> Union[Future, Coroutine]:
        self.overlay = overlay

        # Open the socket
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        self.socket.bind(('', 0))

        # Start listening
        self.receive_thread = Thread(target=self.receive, daemon=True)
        self.receive_thread.start()

        # Start sending
        self.beacon(overlay.get_prefix())

        return succeed(True)

    def beacon(self, service_prefix: bytes) -> None:
        """
        Try to find a listener (fire and forget).
        """
        if self.socket is not None:
            for p in range(65535):
                try:
                    self.socket.sendto(HDR_ANNOUNCE + service_prefix, ('255.255.255.255', p))
                except OSError:
                    pass  # Windows doesn't really care, Ubuntu throws an exception on "illegal" ports

    async def get_addresses(self, overlay: Community, timeout: float) -> Iterable[Address]:
        self.beacon(overlay.get_prefix())
        return []

    def keep_alive(self, overlay: Community) -> None:
        self.beacon(overlay.get_prefix())

    def blacklist(self) -> Iterable[Address]:
        return []
