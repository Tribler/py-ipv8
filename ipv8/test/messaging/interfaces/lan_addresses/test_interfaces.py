from ....base import TestBase
from .....messaging.interfaces.lan_addresses.addressprovider import AddressProvider
from .....messaging.interfaces.lan_addresses.interfaces import get_lan_addresses


class PresetProvider(AddressProvider):

    def __init__(self, return_value):
        super().__init__()
        self.return_value = return_value

    def get_addresses(self):
        return self.return_value


class MockProviders:

    def __init__(self):
        super().__init__()
        self.return_values = []

    def set_return_values(self, return_values):
        self.return_values = [PresetProvider(return_value) for return_value in return_values]

    def get_providers(self, _=False):
        return self.return_values


class TestInterfaces(TestBase):

    def setUp(self):
        super().setUp()

        self.mock_providers = MockProviders()
        get_lan_addresses.__globals__["get_providers"] = self.mock_providers.get_providers

    def test_aggregate_votes_none(self):
        """
        Check that aggregating no results with no results leads to no results.
        """
        self.mock_providers.set_return_values([set(), set()])
        self.assertListEqual([], get_lan_addresses())

    def test_aggregate_votes_one(self):
        """
        Check that aggregating one result with no results leads to one result.
        """
        self.mock_providers.set_return_values([{"1.2.3.4"}, set()])
        self.assertListEqual(["1.2.3.4"], get_lan_addresses())

    def test_aggregate_votes_many(self):
        """
        Check that aggregating two results with one results leads to two results, sorted on frequency.
        """
        self.mock_providers.set_return_values([{"5.6.7.8.9", "1.2.3.4"}, {"1.2.3.4"}])
        self.assertListEqual(["1.2.3.4", "5.6.7.8.9"], get_lan_addresses())

    def test_aggregate_votes_blacklisted(self):
        """
        Check that results do not include blacklisted IPs.
        """
        self.mock_providers.set_return_values([{"5.6.7.8.9", "127.0.0.1"},
                                               {"127.0.0.1", "127.0.1.1", "0.0.0.0", "255.255.255.255", "::1"}])
        self.assertListEqual(["5.6.7.8.9"], get_lan_addresses())
