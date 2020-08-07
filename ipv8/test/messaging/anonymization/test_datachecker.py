from binascii import unhexlify

from ...base import TestBase
from ....messaging.anonymization.tunnel import DataChecker

tracker_pkt = unhexlify('00000417271019800000000012345678')
dht_pkt = b'd1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe'
utp_pkt = unhexlify('210086446ed69ec1ddbd9e6000100000f32e86be')
ipv8_pkt = unhexlify('0002123456789abcdef123456789abcdef123456789a00000001')
tunnel_pkt = unhexlify('000281ded07332bdc775aa5a46f96de9f8f390bbc9f300000001')


class TestDataChecker(TestBase):

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
