from __future__ import annotations

import contextlib
import io
from asyncio import sleep
from time import time
from typing import Set

from .....messaging.interfaces.lan_addresses.addressprovider import AddressProvider
from ....base import TestBase


class ErroringProvider(AddressProvider):
    """
    A provider that errors out when getting addresses.
    """

    def get_addresses(self) -> Set[str]:
        """
        Raise and set an exception.
        """
        try:
            msg = "Force exception into log entry."
            raise RuntimeError(msg)
        except:
            self.on_exception()
        return set()


class InvocationCountingProvider(AddressProvider):
    """
    Provider that counts the number of address getter invocations.
    """

    def __init__(self) -> None:
        """
        Create a new counting provider.
        """
        super().__init__()
        self.invocations = 0

    def get_addresses(self) -> Set[str]:
        """
        Add to the count and return no addresses.
        """
        self.invocations += 1
        return set()


class TestAddressProvider(TestBase):
    """
    Tests related to address providers.
    """

    def test_log_verbose(self) -> None:
        """
        Check if a verbose provider logs its exceptions.
        """
        provider = ErroringProvider(verbose=True)

        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            provider.get_addresses()

        self.assertNotEqual("", log.getvalue())

    def test_log_non_verbose(self) -> None:
        """
        Check if a non-verbose provider does not log its exceptions.
        """
        provider = ErroringProvider(verbose=False)

        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            provider.get_addresses()

        self.assertEqual("", log.getvalue())

    def test_get_addresses_buffered(self) -> None:
        """
        Check if the buffer of a provider is used if called within the valid buffer time.
        """
        provider = InvocationCountingProvider()

        # This call shouldn't use the buffer
        provider.get_addresses_buffered()
        self.assertEqual(1, provider.invocations)

        # The second call should use the buffer
        provider.get_addresses_buffered()
        self.assertEqual(1, provider.invocations)

    async def test_get_addresses_buffered_timeout(self) -> None:
        """
        Check if the buffer of a provider is used if called within the valid buffer time.
        """
        provider = InvocationCountingProvider()
        provider.get_addresses_buffered()

        while time() - provider.addresses_ts <= 0.01:
            await sleep(0.01)

        # 0.01 seconds should have passed, so the addresses should be re-discovered
        provider.discover_addresses(0.01)
        self.assertEqual(2, provider.invocations)

        # Multiple calls to discover_addresses shouldn't do anything
        provider.discover_addresses(0.01)
        self.assertEqual(2, provider.invocations)

        # the buffer should be used
        provider.get_addresses_buffered()
        self.assertEqual(2, provider.invocations)
