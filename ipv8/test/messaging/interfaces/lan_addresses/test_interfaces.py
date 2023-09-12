from __future__ import annotations

from typing import Collection, Set

from .....messaging.interfaces.lan_addresses.addressprovider import AddressProvider
from .....messaging.interfaces.lan_addresses.interfaces import get_lan_addresses
from ....base import TestBase


class PresetProvider(AddressProvider):
    """
    Provider that returns a specific value.
    """

    def __init__(self, return_value: Set[str]) -> None:
        """
        Create a new provider with a preset return value.
        """
        super().__init__()
        self.return_value = return_value

    def get_addresses(self) -> Set[str]:
        """
        Return our preset return value.
        """
        return self.return_value


class MockProviders:
    """
    Manage a list of providers with preset return values.
    """

    def __init__(self) -> None:
        """
        Initialize an empty list of providers.
        """
        super().__init__()
        self.return_values = []

    def set_return_values(self, return_values: Collection[Set[str]]) -> None:
        """
        Initialize providers for the given return values.
        """
        self.return_values = [PresetProvider(return_value) for return_value in return_values]

    def get_providers(self, _: bool = False) -> list[PresetProvider]:
        """
        Get our providers.
        """
        return self.return_values


class TestInterfaces(TestBase):
    """
    Tests related to the interface api.
    """

    def setUp(self) -> None:
        """
        Create mocked providers to test with.
        """
        super().setUp()

        self.mock_providers = MockProviders()
        get_lan_addresses.__globals__["get_providers"] = self.mock_providers.get_providers

    def test_aggregate_votes_none(self) -> None:
        """
        Check that aggregating no results with no results leads to no results.
        """
        self.mock_providers.set_return_values([set(), set()])
        self.assertListEqual([], get_lan_addresses())

    def test_aggregate_votes_one(self) -> None:
        """
        Check that aggregating one result with no results leads to one result.
        """
        self.mock_providers.set_return_values([{"1.2.3.4"}, set()])
        self.assertListEqual(["1.2.3.4"], get_lan_addresses())

    def test_aggregate_votes_many(self) -> None:
        """
        Check that aggregating two results with one results leads to two results, sorted on frequency.
        """
        self.mock_providers.set_return_values([{"5.6.7.8.9", "1.2.3.4"}, {"1.2.3.4"}])
        self.assertListEqual(["1.2.3.4", "5.6.7.8.9"], get_lan_addresses())

    def test_aggregate_votes_blacklisted(self) -> None:
        """
        Check that results do not include blacklisted IPs.
        """
        self.mock_providers.set_return_values([{"5.6.7.8.9", "127.0.0.1"},
                                               {"127.0.0.1", "127.0.1.1", "0.0.0.0", "255.255.255.255", "::1"}])
        self.assertListEqual(["5.6.7.8.9"], get_lan_addresses())
