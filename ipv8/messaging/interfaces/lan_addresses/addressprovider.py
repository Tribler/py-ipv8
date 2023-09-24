from __future__ import annotations

import traceback
import typing
from abc import ABC, abstractmethod
from time import time


class AddressProvider(ABC):
    """
    Interface for OS-specific methods of finding local interfaces addresses.
    """

    def __init__(self, verbose: bool = False) -> None:
        """
        Create a new ``AddressProvider``.

        :param verbose: Log any errors that are encountered while fetching addresses.
        """
        self.verbose = verbose
        self.addresses: typing.Set[str] = set()
        self.addresses_ts = 0.0

    def on_exception(self) -> None:
        """
        Called by provider implementations that encounter an ``Exception``.
        """
        if self.verbose:
            traceback.print_exc()

    def discover_addresses(self, min_interval: float = 10.0) -> None:
        """
        Discovers the LAN addresses using this provider. The addresses are only discovered if
        the previous call was more than ``min_interval`` seconds ago. The most recent results
        can be retrieved through ``get_addresses_buffered()``.

        :param min_interval: Minimum time in seconds between discoveries.
        """
        if time() - self.addresses_ts > min_interval:
            # Set the timestamp immediately to avoid concurrent calls
            self.addresses_ts = time()
            self.addresses = self.get_addresses()
            # Since get_addresses may take a while, we set the timestamp for a second time
            self.addresses_ts = time()

    @abstractmethod
    def get_addresses(self) -> typing.Set[str]:
        """
        Get a set of LAN addresses using this provider.
        """

    def get_addresses_buffered(self) -> typing.Set[str]:
        """
        Return the known addresses from when ``discover_addresses()`` was last successfully called.
        If discovery hasn't been performed yet, do so now.
        """
        if not self.addresses:
            self.discover_addresses()
        return self.addresses
