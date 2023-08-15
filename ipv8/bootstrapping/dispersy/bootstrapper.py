from __future__ import annotations

import logging
from random import choice
from socket import gethostbyname
from threading import Thread
from time import time
from typing import TYPE_CHECKING, Iterable

from ...messaging.interfaces.udp.endpoint import UDPv4Address
from ...util import succeed
from ..bootstrapper_interface import Bootstrapper

if TYPE_CHECKING:
    from asyncio import Future

    from ...community import Community
    from ...types import Address

# Workaround for unnecessarily failing gethostbyname from a worker thread (https://bugs.python.org/issue29288)
''.encode('idna')


class DispersyBootstrapper(Bootstrapper):
    """
    Bootstrapper that uses the Dispersy protocol to find initial peers.
    """

    def __init__(self,
                 ip_addresses: Iterable[Address],
                 dns_addresses: Iterable[Address],
                 bootstrap_timeout: float = 30.0) -> None:
        """
        Create a new bootstrapper without resolving DNS addresses or initializing the blacklist.
        """
        self.ip_addresses = [UDPv4Address(*addr) for addr in ip_addresses]
        self.dns_addresses = dns_addresses

        self.bootstrap_timeout = bootstrap_timeout

        self.last_bootstrap: float = 0

    def resolve_dns_bootstrap_addresses(self) -> None:
        """
        Resolve the bootstrap server DNS names defined in ``dns_addresses`` and insert them into ``ip_addresses``.
        """
        def resolve_addresses(dns_names: Iterable[Address], ip_addresses: list[Address]) -> None:
            current_addresses = ip_addresses[:]  # Copy the existing addresses (don't loop through our additions)
            for (address, port) in dns_names:
                try:
                    resolved_address = UDPv4Address(gethostbyname(address), port)
                    if resolved_address not in current_addresses:
                        # NOTE: append() is thread-safe. Don't call remove() here!
                        ip_addresses.append(resolved_address)
                except OSError:
                    logging.info("Unable to resolve bootstrap DNS address (%s, %d)", address, port)

        resolution_thread = Thread(name="resolve_dns_bootstrap_addresses",
                                   target=resolve_addresses,
                                   args=(self.dns_addresses, self.ip_addresses),
                                   daemon=True)
        resolution_thread.start()

    def initialize(self, overlay: Community) -> Future:
        """
        Initialize this bootstrapper for the given Community, settings its blacklist.
        """
        overlay.network.blacklist.extend(self.ip_addresses)
        self.resolve_dns_bootstrap_addresses()
        return succeed(True)

    async def get_addresses(self, overlay: Community, timeout: float) -> Iterable[Address]:
        """
        Attempt to find new addresses for the given overlay.

        We never have pending addresses and this function always returns an empty list.
        """
        if time() - self.last_bootstrap < self.bootstrap_timeout:
            return []
        logging.debug("Bootstrapping %s, current peers %d", overlay.__class__.__name__, len(overlay.get_peers()))
        self.last_bootstrap = time()
        for socket_address in self.ip_addresses:
            overlay.ensure_blacklisted(socket_address)
            overlay.walk_to(socket_address)
        return []

    def keep_alive(self, overlay: Community) -> None:
        """
        Keep at least one connection to any bootstrap server open. This avoids network splits/partitioning.
        """
        if self.ip_addresses:
            address = choice(self.ip_addresses)
            overlay.ensure_blacklisted(address)
            overlay.walk_to(address)

    def blacklist(self) -> Iterable[Address]:
        """
        Overlays should not consider bootstrap nodes to be normal peers.
        """
        return self.ip_addresses

    def unload(self) -> None:
        """
        Unload this bootstrapper.
        """
