import contextlib
import io
from asyncio import sleep

from ....base import TestBase
from .....messaging.interfaces.lan_addresses.addressprovider import AddressProvider


class ErroringProvider(AddressProvider):

    def get_addresses(self):
        try:
            raise RuntimeError("Force exception into log entry.")
        except:
            self.on_exception()
        return set()


class InvocationCountingProvider(AddressProvider):

    def __init__(self):
        super().__init__()
        self.invocations = 0

    def get_addresses(self):
        self.invocations += 1
        return set()


class TestAddressProvider(TestBase):

    def test_log_verbose(self):
        """
        Check if a verbose provider logs its exceptions.
        """
        provider = ErroringProvider(verbose=True)

        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            provider.get_addresses()

        self.assertNotEqual("", log.getvalue())

    def test_log_non_verbose(self):
        """
        Check if a non-verbose provider does not log its exceptions.
        """
        provider = ErroringProvider(verbose=False)

        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            provider.get_addresses()

        self.assertEqual("", log.getvalue())

    def test_get_addresses_buffered(self):
        """
        Check if the buffer of a provider is used if called within the valid buffer time.
        """
        provider = InvocationCountingProvider()
        provider.get_addresses_buffered(10.0)

        # This call should happen well within 10 seconds, so the buffer should be used
        provider.get_addresses_buffered(10.0)

        self.assertEqual(1, provider.invocations)

    async def test_get_addresses_buffered_timeout(self):
        """
        Check if the buffer of a provider is used if called within the valid buffer time.
        """
        provider = InvocationCountingProvider()
        provider.get_addresses_buffered(0.01)

        await sleep(0.02)

        # 0.01 seconds should have passed, so the buffer should NOT be used
        provider.get_addresses_buffered(0.01)

        self.assertEqual(2, provider.invocations)
