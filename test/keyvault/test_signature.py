import unittest

from keyvault.crypto import ECCrypto


class TestSignatures(unittest.TestCase):
    """
    Test whether signatures can be created and then decoded correctly.
    """

    def setUp(self):
        self.ec = ECCrypto()
        self.data = "".join([chr(i) for i in range(256)])

    def test_vlow(self):
        key = self.ec.generate_key(u"very-low")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_low(self):
        key = self.ec.generate_key(u"low")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_medium(self):
        key = self.ec.generate_key(u"medium")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_high(self):
        key = self.ec.generate_key(u"high")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_curve25519(self):
        key = self.ec.generate_key(u"curve25519")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))
