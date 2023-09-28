from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Coroutine, Iterable

if TYPE_CHECKING:
    from asyncio import Future

    from ..types import Address, Community


class Bootstrapper(ABC):
    """
    A script to connect to external bootstrapping resources, using external hardware.

    When not to crash:
     - Loading this module file when missing dependencies.
     - Initializing a subclass when the service is unavailable (return ``False``).
     - Failing to retrieve peers for a service (return an empty iterable, e.g. ``[]``).

    When to crash:
     - Initializing this module subclass when missing dependencies.
    """

    def __init__(self) -> None:
        """
        Create a new ``Bootstrapper``.
        """
        self.initialized = False

    @abstractmethod
    def initialize(self, overlay: Community) -> Future | Coroutine:
        """
        Start connecting to this bootstrapping service. Don't perform any network traffic in ``__init__``!

        You are encourages to implement this method as non-async to have faster bootstrapper inclusion.

        :param overlay: the network overlay to initialize for.
        :returns: whether the initialization was successful.
        """

    @abstractmethod
    async def get_addresses(self, overlay: Community, timeout: float) -> Iterable[Address]:
        """
        Return some IPv8 addresses (if available) from this bootstrapping service.
        These addresses should be walkable (not blocked by a NAT or firewall).

        :param overlay: the network overlay to get peers for.
        :param timeout: the maximum time we wish to wait until we get any result (i.e. an empty list).
        :returns: the addresses for the given service_id.
        """

    @abstractmethod
    def keep_alive(self, overlay: Community) -> None:
        """
        Periodically called to keep this bootstrap connection alive.

        :param overlay: the network overlay to keep alive.
        """

    @abstractmethod
    def blacklist(self) -> Iterable[Address]:
        """
        Returns the blacklisted addresses for this Bootstrapper.
        """

    @abstractmethod
    def unload(self) -> None:
        """
        Stop and unload all the resources used by this Bootstrapper.
        """
