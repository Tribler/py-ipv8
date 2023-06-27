from binascii import unhexlify

from ...base import TestBase
from ....messaging.anonymization.tunnel import DataChecker

tracker_pkt = unhexlify('00000417271019800000000012345678')
dht_pkt = b'd1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe'
utp_pkt = unhexlify('210086446ed69ec1ddbd9e6000100000f32e86be')
utp_ext3_pkt = unhexlify('110309d69087c1e7b69c0980001000009868b984000400000008')
ipv8_pkt = unhexlify('0002123456789abcdef123456789abcdef123456789a00000001')
tunnel_pkt = unhexlify('000281ded07332bdc775aa5a46f96de9f8f390bbc9f300000001')


class TestDataChecker(TestBase):

    def test_unlimited_bandwidth(self):
        """
        Check if bandwidth is not restricted when the magic value for unlimited data is passed.
        """
        data_checker = DataChecker(0)
        packet = b"x" * 10

        self.assertTrue(data_checker.within_speed_limit(packet))

    def test_limit_bandwidth(self):
        """
        Check if bandwidth is correctly limited.
        """
        data_checker = DataChecker(100)  # 100 bytes per second
        packet = b"x" * 26  # 26 bytes (should fit 3 per second)

        self.assertTrue(data_checker.within_speed_limit(packet))  # 1/3
        self.assertTrue(data_checker.within_speed_limit(packet))  # 2/3
        self.assertTrue(data_checker.within_speed_limit(packet))  # 3/3
        self.assertFalse(data_checker.within_speed_limit(packet))  # 4/3 -> DROP!

    def test_limit_bandwidth_buffer_clear(self):
        """
        Check if bandwidth is correctly limited when the buffer is stale.
        """
        data_checker = DataChecker(100)  # 100 bytes per second
        packet = b"x" * 26  # 26 bytes (should fit 3 per second)
        data_checker.simulated_packet_buffer.append(DataChecker.SimulatedPacket(26, 0))  # 1/3 (timestamp 0 is very old)

        self.assertTrue(data_checker.within_speed_limit(packet))  # 1/3
        self.assertEqual(1, len(data_checker.simulated_packet_buffer))  # Old data has been removed

        self.assertTrue(data_checker.within_speed_limit(packet))  # 2/3
        self.assertTrue(data_checker.within_speed_limit(packet))  # 3/3
        self.assertFalse(data_checker.within_speed_limit(packet))  # 4/3 -> DROP!

    def test_could_be_dht(self):
        """
        Check if a DHT packet is correctly identified.
        """
        self.assertFalse(DataChecker.could_be_dht(tracker_pkt))
        self.assertTrue(DataChecker.could_be_dht(dht_pkt))
        self.assertFalse(DataChecker.could_be_dht(utp_pkt))
        self.assertFalse(DataChecker.could_be_dht(ipv8_pkt))
        self.assertFalse(DataChecker.could_be_dht(tunnel_pkt))

    def test_could_be_udp_tracker(self):
        """
        Check if a UDP tracker packet is correctly identified.
        """
        self.assertTrue(DataChecker.could_be_udp_tracker(tracker_pkt))
        self.assertFalse(DataChecker.could_be_udp_tracker(dht_pkt))
        self.assertFalse(DataChecker.could_be_udp_tracker(utp_pkt))
        self.assertFalse(DataChecker.could_be_udp_tracker(ipv8_pkt))
        self.assertFalse(DataChecker.could_be_udp_tracker(tunnel_pkt))

    def test_could_be_utp(self):
        """
        Check if a UTP packet is correctly identified.
        """
        self.assertFalse(DataChecker.could_be_utp(tracker_pkt))
        self.assertFalse(DataChecker.could_be_utp(dht_pkt))
        self.assertTrue(DataChecker.could_be_utp(utp_pkt))
        self.assertTrue(DataChecker.could_be_utp(utp_ext3_pkt))  # non-BEP29 extension 3 (close reason)
        self.assertFalse(DataChecker.could_be_utp(ipv8_pkt))
        self.assertFalse(DataChecker.could_be_utp(tunnel_pkt))

    def test_could_be_ipv8(self):
        """
        Check if a IPv8 packet is correctly identified.
        """
        self.assertFalse(DataChecker.could_be_ipv8(tracker_pkt))
        self.assertFalse(DataChecker.could_be_ipv8(dht_pkt))
        self.assertFalse(DataChecker.could_be_ipv8(utp_pkt))
        self.assertTrue(DataChecker.could_be_ipv8(ipv8_pkt))
        self.assertTrue(DataChecker.could_be_ipv8(tunnel_pkt))

    def test_could_be_bt(self):
        """
        Check if a BitTorrent packet is correctly identified.
        """
        self.assertTrue(DataChecker.could_be_bt(tracker_pkt))
        self.assertTrue(DataChecker.could_be_bt(dht_pkt))
        self.assertTrue(DataChecker.could_be_bt(utp_pkt))
        self.assertFalse(DataChecker.could_be_bt(ipv8_pkt))
        self.assertFalse(DataChecker.could_be_bt(tunnel_pkt))
