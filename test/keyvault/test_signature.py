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
        """
        Check if very-low security keys generate a valid signature.
        """
        key = self.ec.generate_key(u"very-low")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_low(self):
        """
        Check if low security keys generate a valid signature.
        """
        key = self.ec.generate_key(u"low")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_medium(self):
        """
        Check if medium security keys generate a valid signature.
        """
        key = self.ec.generate_key(u"medium")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_high(self):
        """
        Check if high security keys generate a valid signature.
        """
        key = self.ec.generate_key(u"high")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_curve25519(self):
        """
        Check if curve25519 keys generate a valid signature.
        """
        key = self.ec.generate_key(u"curve25519")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))
