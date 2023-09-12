from ...keyvault.crypto import default_eccrypto
from ..base import TestBase


class TestSignatures(TestBase):
    """
    Test whether signatures can be created and then decoded correctly.
    """

    def setUp(self) -> None:
        """
        Generate fake data to test with.
        """
        super().setUp()
        self.ec = default_eccrypto
        self.data = bytes(range(256))

    def test_vlow(self) -> None:
        """
        Check if very-low security keys generate a valid signature.
        """
        key = self.ec.generate_key("very-low")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_low(self) -> None:
        """
        Check if low security keys generate a valid signature.
        """
        key = self.ec.generate_key("low")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_medium(self) -> None:
        """
        Check if medium security keys generate a valid signature.
        """
        key = self.ec.generate_key("medium")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_high(self) -> None:
        """
        Check if high security keys generate a valid signature.
        """
        key = self.ec.generate_key("high")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_curve25519(self) -> None:
        """
        Check if curve25519 keys generate a valid signature.
        """
        key = self.ec.generate_key("curve25519")

        signature = key.signature(self.data)

        self.assertTrue(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_invalid_m2crypto(self) -> None:
        """
        Check if an M2Crypto key detects an invalid signature.
        """
        key = self.ec.generate_key("very-low")

        signature = ""

        self.assertFalse(self.ec.is_valid_signature(key.pub(), self.data, signature))

    def test_invalid_nacl(self) -> None:
        """
        Check if an libnacl key detects an invalid signature.
        """
        key = self.ec.generate_key("curve25519")

        signature = ""

        self.assertFalse(self.ec.is_valid_signature(key.pub(), self.data, signature))
