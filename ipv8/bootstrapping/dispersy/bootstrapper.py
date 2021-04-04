import logging
from asyncio import Future
from random import choice
from socket import error, gethostbyname
from threading import Thread
from time import time
from typing import Iterable

from ..bootstrapper_interface import Bootstrapper
from ...community import Community
from ...messaging.interfaces.udp.endpoint import UDPv4Address
from ...types import Address
from ...util import succeed


class DispersyBootstrapper(Bootstrapper):

    def __init__(self, ip_addresses, dns_addresses, bootstrap_timeout=30.0):
        self.ip_addresses = [UDPv4Address(*addr) for addr in ip_addresses]
        self.dns_addresses = dns_addresses

        self.bootstrap_timeout = bootstrap_timeout

        self.last_bootstrap = 0

    def resolve_dns_bootstrap_addresses(self):
        """
        Resolve the bootstrap server DNS names defined in ``dns_addresses`` and insert them into ``ip_addresses``.
        """
        def resolve_addresses(dns_names, ip_addresses):
            current_addresses = ip_addresses[:]  # Copy the existing addresses (don't loop through our additions)
            for (address, port) in dns_names:
                try:
                    resolved_address = UDPv4Address(gethostbyname(address), port)
                    if resolved_address not in current_addresses:
                        # NOTE: append() is thread-safe. Don't call remove() here!
                        ip_addresses.append(resolved_address)
                except error:
                    logging.info("Unable to resolve bootstrap DNS address (%s, %d)", address, port)

        resolution_thread = Thread(name="resolve_dns_bootstrap_addresses",
                                   target=resolve_addresses,
                                   args=(self.dns_addresses, self.ip_addresses),
                                   daemon=True)
        resolution_thread.start()

    def initialize(self, overlay: Community) -> Future:
        overlay.network.blacklist.extend(self.ip_addresses)
        self.resolve_dns_bootstrap_addresses()
        return succeed(True)

    async def get_addresses(self, overlay: Community, timeout: float) -> Iterable[Address]:
        if time() - self.last_bootstrap < self.bootstrap_timeout:
            return []
        logging.debug("Bootstrapping %s, current peers %d", overlay.__class__.__name__, len(overlay.get_peers()))
        self.last_bootstrap = time()
        for socket_address in self.ip_addresses:
            overlay.ensure_blacklisted(socket_address)
            overlay.walk_to(socket_address)
        return []

    def keep_alive(self, overlay: Community) -> None:
        if self.ip_addresses:
            address = choice(self.ip_addresses)
            overlay.ensure_blacklisted(address)
            overlay.walk_to(address)

    def blacklist(self) -> Iterable[Address]:
        return self.ip_addresses

    def unload(self) -> None:
        pass
