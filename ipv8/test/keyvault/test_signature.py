import unittest

from ...keyvault.crypto import ECCrypto


class TestSignatures(unittest.TestCase):
    """
    Test whether signatures can be created and then decoded correctly.
    """

    def setUp(self):
        self.ec = ECCrypto()
        self.data = b"".join([bytes([i]) for i in range(256)])

    def test_vlow(self):
        """
        Check if very-low security keys generate a valid signature.
        """
        key = self.ec.generate_key("very-low")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_low(self):
        """
        Check if low security keys generate a valid signature.
        """
        key = self.ec.generate_key("low")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_medium(self):
        """
        Check if medium security keys generate a valid signature.
        """
        key = self.ec.generate_key("medium")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_high(self):
        """
        Check if high security keys generate a valid signature.
        """
        key = self.ec.generate_key("high")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_curve25519(self):
        """
        Check if curve25519 keys generate a valid signature.
        """
        key = self.ec.generate_key("curve25519")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_invalid_m2crypto(self):
        """
        Check if an M2Crypto key detects an invalid signature.
        """
        key = self.ec.generate_key("very-low")

        signature = b""

        self.assertFalse(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_invalid_nacl(self):
        """
        Check if an libnacl key detects an invalid signature.
        """
        key = self.ec.generate_key("curve25519")

        signature = b""

        self.assertFalse(self.ec.is_valid_signature(key.pub(), self.data, signature))
