from __future__ import annotations

import traceback
import typing
from abc import ABC, abstractmethod
from functools import lru_cache
from time import time


class AddressProvider(ABC):

    def __init__(self, verbose: bool = False) -> None:
        """
        Create a new ``AddressProvider``.

        :param verbose: Log any errors that are encountered while fetching addresses.
        """
        self.verbose = verbose

        # This needs to be instance-unique.
        # A "normal" method would give one entry for all ``AddressProvider`` implementations.
        self._get_addresses_buffered = lru_cache(maxsize=1)(lambda t: self.get_addresses())

    def on_exception(self) -> None:
        """
        Called by provider implementations that encounter an ``Exception``.
        """
        if self.verbose:
            traceback.print_exc()

    @abstractmethod
    def get_addresses(self) -> typing.Set[str]:
        """
        Get a set of LAN addresses using this provider.
        """
        pass

    def get_addresses_buffered(self, buffer_time_secs: float = 10.0) -> typing.Set[str]:
        """
        Return a buffered view of the last known addresses from ``get_addresses()``.

        :param buffer_time_secs: The time span in seconds that the last values stay valid.
        """
        return self._get_addresses_buffered(time() // buffer_time_secs)
