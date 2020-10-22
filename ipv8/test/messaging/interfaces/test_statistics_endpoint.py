from ...base import TestBase
from ...mocking.endpoint import AutoMockEndpoint
from ....messaging.interfaces.network_stats import NetworkStat
from ....messaging.interfaces.statistics_endpoint import StatisticsEndpoint


class NoSendEndpoint(AutoMockEndpoint):

    def send(self, socket_address, packet):
        pass


class TestStatisticsEndpoint(TestBase):

    def setUp(self):
        super().setUp()
        self.raw_ep = NoSendEndpoint()
        self.stats_ep = StatisticsEndpoint(self.raw_ep)

        self.prefix = b'0' * 22
        self.msg_id = b'\x01'
        self.msg_num = self.msg_id[0]
        self.fake_addr = ("0.0.0.0", 0)

    async def test_getattribute(self):
        """
        Check if calls to the underlying Endpoint are forwarded.

        Note: ``wan_address`` is specific to ``AutoMockEndpoint``.
        """
        self.assertEqual(self.raw_ep.wan_address, self.stats_ep.wan_address)

    async def test_capture_send_enabled(self):
        """
        Check if send calls are registered when the prefix is enabled.
        """
        self.stats_ep.enable_community_statistics(self.prefix, True)
        self.stats_ep.send(self.fake_addr, self.prefix + self.msg_id + b'Hello World!')

        statistics = self.stats_ep.get_statistics(self.prefix)

        self.assertIsNotNone(statistics)
        self.assertIn(self.msg_num, statistics)
        self.assertEqual(1, statistics[self.msg_num].num_up)
        self.assertEqual(0, statistics[self.msg_num].num_down)

    async def test_no_capture_send_disabled(self):
        """
        Check if send calls are not registered when the prefix is disabled.
        """
        self.stats_ep.enable_community_statistics(self.prefix, False)
        self.stats_ep.send(self.fake_addr, self.prefix + self.msg_id + b'Hello World!')

        statistics = self.stats_ep.get_statistics(self.prefix)

        self.assertIsNotNone(statistics)
        self.assertFalse(statistics)

    async def test_capture_receive_enabled(self):
        """
        Check if receive calls are registered when the prefix is enabled.
        """
        self.stats_ep.enable_community_statistics(self.prefix, True)
        self.stats_ep.on_packet((self.fake_addr, self.prefix + self.msg_id + b'Hello World!'))

        statistics = self.stats_ep.get_statistics(self.prefix)

        self.assertIsNotNone(statistics)
        self.assertIn(self.msg_num, statistics)
        self.assertEqual(0, statistics[self.msg_num].num_up)
        self.assertEqual(1, statistics[self.msg_num].num_down)

    async def test_no_capture_receive_disabled(self):
        """
        Check if receive calls are not registered when the prefix is disabled.
        """
        self.stats_ep.enable_community_statistics(self.prefix, False)
        self.stats_ep.on_packet((self.fake_addr, self.prefix + self.msg_id + b'Hello World!'))

        statistics = self.stats_ep.get_statistics(self.prefix)

        self.assertIsNotNone(statistics)
        self.assertFalse(statistics)

    async def test_get_sent(self):
        """
        Check if sent messages are correctly logged for an unknown and known prefix.
        """
        stats = NetworkStat(self.msg_num)
        stats.num_up = 2
        stats.bytes_up = 42
        self.stats_ep.statistics = {self.prefix: {self.msg_num: stats}}
        unknown_prefix = b'some other prefix'

        self.assertEqual(0, self.stats_ep.get_message_sent(unknown_prefix))
        self.assertEqual(2, self.stats_ep.get_message_sent(self.prefix))
        self.assertEqual(0, self.stats_ep.get_bytes_sent(unknown_prefix))
        self.assertEqual(42, self.stats_ep.get_bytes_sent(self.prefix))

    async def test_get_received(self):
        """
        Check if received messages are correctly logged for an unknown and known prefix.
        """
        stats = NetworkStat(self.msg_num)
        stats.num_down = 2
        stats.bytes_down = 42
        self.stats_ep.statistics = {self.prefix: {self.msg_num: stats}}
        unknown_prefix = b'some other prefix'

        self.assertEqual(0, self.stats_ep.get_message_received(unknown_prefix))
        self.assertEqual(2, self.stats_ep.get_message_received(self.prefix))
        self.assertEqual(0, self.stats_ep.get_bytes_received(unknown_prefix))
        self.assertEqual(42, self.stats_ep.get_bytes_received(self.prefix))

    async def test_get_sent_excluded(self):
        """
        Check if excluded sent messages are not counted.
        """
        stats_intro, stats_puncture, stats_deprecated = NetworkStat(245), NetworkStat(249), NetworkStat(235)
        stats_intro.num_up = stats_puncture.num_up = stats_deprecated.num_up = 1
        self.stats_ep.statistics = {self.prefix: {245: stats_intro, 249: stats_puncture, 235: stats_deprecated}}

        self.assertEqual(0, self.stats_ep.get_message_sent(self.prefix))
        self.assertEqual(3, self.stats_ep.get_message_sent(self.prefix, True, True, True))
        self.assertEqual(1, self.stats_ep.get_message_sent(self.prefix, include_introduction=True))
        self.assertEqual(1, self.stats_ep.get_message_sent(self.prefix, include_puncture=True))
        self.assertEqual(1, self.stats_ep.get_message_sent(self.prefix, include_deprecated=True))

    async def test_get_received_excluded(self):
        """
        Check if excluded received messages are not counted.
        """
        stats_intro, stats_puncture, stats_deprecated = NetworkStat(245), NetworkStat(249), NetworkStat(235)
        stats_intro.num_down = stats_puncture.num_down = stats_deprecated.num_down = 1
        self.stats_ep.statistics = {self.prefix: {245: stats_intro, 249: stats_puncture, 235: stats_deprecated}}

        self.assertEqual(0, self.stats_ep.get_message_received(self.prefix))
        self.assertEqual(3, self.stats_ep.get_message_received(self.prefix, True, True, True))
        self.assertEqual(1, self.stats_ep.get_message_received(self.prefix, include_introduction=True))
        self.assertEqual(1, self.stats_ep.get_message_received(self.prefix, include_puncture=True))
        self.assertEqual(1, self.stats_ep.get_message_received(self.prefix, include_deprecated=True))

    async def test_aggregate_statistics_sum(self):
        """
        Check if network stats are correctly summed.
        """
        stat1 = NetworkStat(1)
        stat1.num_up, stat1.num_down, stat1.bytes_up, stat1.bytes_down = 2, 3, 4, 5
        stat2 = NetworkStat(2)
        stat2.num_up, stat2.num_down, stat2.bytes_up, stat2.bytes_down = 6, 7, 8, 9
        self.stats_ep.statistics = {self.prefix: {stat1.identifier: stat1, stat2.identifier: stat2}}

        statistics = self.stats_ep.get_aggregate_statistics(self.prefix)

        self.assertIsNotNone(statistics)
        self.assertEqual(8, statistics['num_up'])
        self.assertEqual(10, statistics['num_down'])
        self.assertEqual(12, statistics['bytes_up'])
        self.assertEqual(14, statistics['bytes_down'])
        self.assertEqual(0, statistics['diff_time'])

    async def test_aggregate_statistics_diff_one(self):
        """
        Check if the time diff is correctly calculated, with one positive stat.
        """
        stat1 = NetworkStat(1)
        stat1.last_measured_down, stat1.last_measured_up = 0, 0
        stat1.first_measured_down, stat1.first_measured_up = 0, 0
        stat2 = NetworkStat(2)
        stat2.last_measured_down, stat2.last_measured_up = 0, 5
        stat2.first_measured_down, stat2.first_measured_up = 0, 1
        self.stats_ep.statistics = {self.prefix: {stat1.identifier: stat1, stat2.identifier: stat2}}

        statistics = self.stats_ep.get_aggregate_statistics(self.prefix)

        self.assertIsNotNone(statistics)
        self.assertEqual(4, statistics['diff_time'])

    async def test_aggregate_statistics_diff_two(self):
        """
        Check if the time diff is correctly calculated, with two positive stats.
        """
        stat1 = NetworkStat(1)
        stat1.last_measured_down, stat1.last_measured_up = 0, 6
        stat1.first_measured_down, stat1.first_measured_up = 0, 2
        stat2 = NetworkStat(2)
        stat2.last_measured_down, stat2.last_measured_up = 0, 5
        stat2.first_measured_down, stat2.first_measured_up = 0, 1
        self.stats_ep.statistics = {self.prefix: {stat1.identifier: stat1, stat2.identifier: stat2}}

        statistics = self.stats_ep.get_aggregate_statistics(self.prefix)

        self.assertIsNotNone(statistics)
        self.assertEqual(5, statistics['diff_time'])

    async def test_aggregate_statistics_diff_many(self):
        """
        Check if the time diff is correctly calculated, with four positive stats.
        """
        stat1 = NetworkStat(1)
        stat1.last_measured_down, stat1.last_measured_up = 7, 6
        stat1.first_measured_down, stat1.first_measured_up = 3, 2
        stat2 = NetworkStat(2)
        stat2.last_measured_down, stat2.last_measured_up = 0, 5
        stat2.first_measured_down, stat2.first_measured_up = 1, 2
        self.stats_ep.statistics = {self.prefix: {stat1.identifier: stat1, stat2.identifier: stat2}}

        statistics = self.stats_ep.get_aggregate_statistics(self.prefix)

        self.assertIsNotNone(statistics)
        self.assertEqual(6, statistics['diff_time'])
