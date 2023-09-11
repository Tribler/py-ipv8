from ....messaging.interfaces.network_stats import NetworkStat
from ...base import TestBase


class TestNetworkStat(TestBase):
    """
    Tests related to the network stat object.
    """

    async def test_initialize(self) -> None:
        """
        Check if the starting values of NetworkStat are sane.
        """
        stats = NetworkStat(1447)

        self.assertEqual(1447, stats.identifier)
        self.assertEqual(0, stats.num_up)
        self.assertEqual(0, stats.num_down)
        self.assertEqual(0, stats.bytes_up)
        self.assertEqual(0, stats.bytes_down)
        self.assertEqual(0, stats.first_measured_up)
        self.assertEqual(0, stats.first_measured_down)
        self.assertEqual(0, stats.last_measured_up)
        self.assertEqual(0, stats.last_measured_down)

    async def test_add_sent_stat(self) -> None:
        """
        Check if an added sent statistic is correctly registered.
        """
        stats = NetworkStat(0)

        stats.add_sent_stat(1492, 1776)

        self.assertEqual(1, stats.num_up)
        self.assertEqual(1776, stats.bytes_up)
        self.assertEqual(1492, stats.first_measured_up)
        self.assertEqual(1492, stats.last_measured_up)

    async def test_add_sent_stat_first_up(self) -> None:
        """
        Check if the first_measured_up is correctly registered on send.
        """
        stats = NetworkStat(0)

        stats.add_sent_stat(1492, 1776)
        stats.add_sent_stat(1619, 1776)

        self.assertEqual(1492, stats.first_measured_up)

    async def test_add_received_stat(self) -> None:
        """
        Check if an added received statistic is correctly registered.
        """
        stats = NetworkStat(0)

        stats.add_received_stat(1492, 1776)

        self.assertEqual(1, stats.num_down)
        self.assertEqual(1776, stats.bytes_down)
        self.assertEqual(1492, stats.first_measured_down)
        self.assertEqual(1492, stats.last_measured_down)

    async def test_add_received_stat_first_down(self) -> None:
        """
        Check if the first_measured_up is correctly registered on receive.
        """
        stats = NetworkStat(0)

        stats.add_received_stat(1492, 1776)
        stats.add_received_stat(1619, 1776)

        self.assertEqual(1492, stats.first_measured_down)

    async def test_to_dict(self) -> None:
        """
        Check if the dictionary form of the NetworkStat is correct.
        """
        stats = NetworkStat(1849)
        stats.add_sent_stat(1492, 1776)
        stats.add_received_stat(1619, 1787)
        stats.add_sent_stat(1783, 1794)
        stats.add_received_stat(1789, 1798)

        self.assertDictEqual({
            "identifier": 1849,
            "num_up": 2,
            "num_down": 2,
            "bytes_up": 1776 + 1794,
            "bytes_down": 1787 + 1798,
            "first_measured_up": 1492,
            "first_measured_down": 1619,
            "last_measured_up": 1783,
            "last_measured_down": 1789
        }, stats.to_dict())

    async def test_to_str(self) -> None:
        """
        Check if a NetworkStat is correctly formatted as a str.
        """
        stats = NetworkStat(1849)
        stats.add_sent_stat(1492, 1776)
        stats.add_received_stat(1619, 1787)
        stats.add_sent_stat(1783, 1794)
        stats.add_received_stat(1789, 1798)

        self.assertEqual("NetworkStat{num_up:2, num_down:2, bytes_up:3570, bytes_down:3585, ...}", str(stats))
