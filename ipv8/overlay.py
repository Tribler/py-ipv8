from __future__ import annotations

import abc
import asyncio
import logging
from types import SimpleNamespace
from typing import TYPE_CHECKING, Generic, TypeVar

from .keyvault.crypto import default_eccrypto
from .messaging.interfaces.endpoint import EndpointListener
from .messaging.interfaces.lan_addresses.interfaces import get_providers
from .messaging.serialization import Serializer
from .taskmanager import TaskManager

if TYPE_CHECKING:
    from .peerdiscovery.discovery import DiscoveryStrategy
    from .peerdiscovery.network import Network
    from .types import Address, Endpoint, Peer


class Settings(SimpleNamespace):
    """
    Overlay settings, extensible for Overlay subclasses.
    """

    community_id: bytes
    """The byte-string used to identify this overlay."""

    my_peer: Peer
    """The (private key) peer of this peer."""

    endpoint: Endpoint
    """The endpoint to use for messaging."""

    network: Network
    """The network graph backend."""


SettingsClass = TypeVar("SettingsClass", bound=Settings)


class Overlay(EndpointListener, TaskManager, Generic[SettingsClass], metaclass=abc.ABCMeta):
    """
    Interface for an Internet overlay.
    """

    settings_class: type[SettingsClass] = Settings  # type: ignore[assignment]

    def __init__(self, settings: SettingsClass) -> None:
        """
        Create a new overlay for the Internet.
        """
        EndpointListener.__init__(self, settings.endpoint)
        TaskManager.__init__(self)
        self.serializer = self.get_serializer()
        self.crypto = default_eccrypto

        self.community_id = settings.community_id
        self.my_peer = settings.my_peer

        self.endpoint.add_listener(self)

        self.logger = logging.getLogger(self.__class__.__name__)

        self.network = settings.network

        self.register_task('discover_lan_addresses', self.discover_lan_addresses, interval=10, delay=0)

    async def discover_lan_addresses(self) -> None:
        """
        Called for discovering LAN addresses.
        """
        loop = asyncio.get_running_loop()
        for provider in get_providers():
            await loop.run_in_executor(None, provider.discover_addresses)

    async def unload(self) -> None:
        """
        Called when this overlay needs to shut down.
        """
        self.endpoint.remove_listener(self)
        await self.shutdown_task_manager()

    def get_serializer(self) -> Serializer:
        """
        Get a Serializer for this Overlay.
        """
        return Serializer()

    @abc.abstractmethod
    def on_packet(self, packet: tuple[Address, bytes]) -> None:
        """
        Callback for when data is received on this endpoint.

        :param packet: the received packet, in (source, binary string) format.
        """

    @property
    def global_time(self) -> int:
        """
        The lamport timestamp of this overlay.
        """
        return self.my_peer.get_lamport_timestamp()

    def claim_global_time(self) -> int:
        """
        Increments the current global time by one and returns this value.
        """
        self.update_global_time(self.global_time + 1)
        return self.global_time

    def update_global_time(self, global_time: int) -> None:
        """
        Increase the local global time if the given GLOBAL_TIME is larger.
        """
        if global_time > self.global_time:
            self.my_peer.update_clock(global_time)

    def get_available_strategies(self) -> dict[str, type[DiscoveryStrategy]]:
        """
        Supply custom DiscoveryStrategies for use with this Overlay.
        This is used by the configuration system to allow for non-globally defined strategies.

        :return: a dictionary of names and DiscoveryStrategy subclass classes
        :rtype: {str: class<DiscoveryStrategy>}
        """
        return {}

    def bootstrap(self) -> None:
        """
        Perform introduction logic to get into the network.
        """

    @abc.abstractmethod
    def walk_to(self, address: Address) -> None:
        """
        Puncture the NAT of an address.

        :param address: the address to walk to (ip, port)
        """

    @abc.abstractmethod
    def get_new_introduction(self, from_peer: Peer | None = None) -> None:
        """
        Get a new IP address to walk to from a random, or selected peer.

        :param from_peer: the peer to ask for an introduction
        """

    @abc.abstractmethod
    def get_peers(self) -> list[Peer]:
        """
        Get the peers for this specific overlay.

        :return: the peers in the Network that use this overlay
        """

    @abc.abstractmethod
    def get_walkable_addresses(self) -> list[Address]:
        """
        Get the list of IPv4 addresses we can walk to on this overlay.

        :return: a list of IPv4 addresses
        :rtype: [(str, int)]
        """

    def get_peer_for_introduction(self, exclude: Peer | None = None) -> Peer | None:
        """
        Get a peer for introduction.

        :param: exclude: optionally specify a peer that is not considered eligible for introduction
        :return: a Peer to send an introduction request to, or None if there are no available
        """
