from __future__ import annotations

import contextlib
import io
from asyncio import sleep
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
        provider.get_addresses_buffered(10.0)

        # This call should happen well within 10 seconds, so the buffer should be used
        provider.get_addresses_buffered(10.0)

        self.assertEqual(1, provider.invocations)

    async def test_get_addresses_buffered_timeout(self) -> None:
        """
        Check if the buffer of a provider is used if called within the valid buffer time.
        """
        provider = InvocationCountingProvider()
        provider.get_addresses_buffered(0.01)

        await sleep(0.02)

        # 0.01 seconds should have passed, so the buffer should NOT be used
        provider.get_addresses_buffered(0.01)

        self.assertEqual(2, provider.invocations)
