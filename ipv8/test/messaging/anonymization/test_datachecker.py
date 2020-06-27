from binascii import unhexlify

from ...base import TestBase
from ....messaging.anonymization.tunnel import DataChecker


class TestDataChecker(TestBase):

    def test_could_be_dht_correct(self):
        """
        Check if a valid DHT packet is correctly identified.
        """
        pkt = b"64313a6164323a696432303a3b2cb14348257b7a481f7010ca7c519b8bef5086393a696e666f5f6861736832303af84b51" \
              b"f0d2c3455ab5dabb6643b4340234cd036e65313a71393a6765745f7065657273313a74323ae037313a76343a4c54010131" \
              b"3a79313a7165"
        self.assertTrue(DataChecker.is_allowed(unhexlify(pkt)))

    def test_could_be_dht_incorrect(self):
        """
        Check if an invalid DHT packet is correctly identified.
        """
        pkt = b"63313a6164323a696432303a3b2cb14348257b7a481f7010ca7c519b8bef5086393a696e666f5f6861736832303af84b51" \
              b"f0d2c3455ab5dabb6643b4340234cd036e65313a71393a6765745f7065657273313a74323ae037313a76343a4c54010131" \
              b"3a79313a7165"
        self.assertFalse(DataChecker.is_allowed(unhexlify(pkt)))
