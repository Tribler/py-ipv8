from base64 import decodebytes
from typing import cast

from ...keyvault.crypto import default_eccrypto
from ...keyvault.private.libnaclkey import LibNaCLSK
from ...keyvault.private.m2crypto import M2CryptoSK
from ...keyvault.public.m2crypto import M2CryptoPK
from ..base import TestBase


class TestSerialization(TestBase):
    """
    Test whether keys can be serialized and unserialized correctly.
    """

    def setUp(self) -> None:
        """
        Create a M2Crypto private key and a LibNaCL private key.
        """
        super().setUp()
        self.ec = default_eccrypto
        self.key = cast(M2CryptoSK, self.ec.generate_key("very-low"))
        self.key_nacl = cast(LibNaCLSK, self.ec.generate_key("curve25519"))

    def test_private_to_bin(self) -> None:
        """
        Check if M2Crypto derived key bins are valid.
        """
        private_bin = self.key.key_to_bin()

        self.assertTrue(self.ec.is_valid_private_bin(private_bin))

    def test_private_nacl_to_bin(self) -> None:
        """
        Check if libnacl derived key bins are valid.
        """
        private_bin = self.key_nacl.key_to_bin()

        self.assertTrue(self.ec.is_valid_private_bin(private_bin))

    def test_private_to_pem(self) -> None:
        """
        Check if keys can be serialized and loaded correctly in PEM format.
        """
        private_pem = self.key.key_to_pem()

        # Convert the PEM to a DER keystring
        prefix = "-----BEGIN EC PRIVATE KEY-----\n"
        postfix = "-----END EC PRIVATE KEY-----\n"
        keystring = decodebytes(private_pem[len(prefix):-len(postfix)])

        # Reconstruct a key with this keystring
        key = M2CryptoSK(keystring=keystring)

        self.assertEqual(private_pem, key.key_to_pem())

    def test_public_to_bin(self) -> None:
        """
        Check if M2Crypto derived public key bins are valid.
        """
        public_bin = self.key.pub().key_to_bin()

        self.assertTrue(self.ec.is_valid_public_bin(public_bin))

    def test_public_nacl_to_bin(self) -> None:
        """
        Check if libnacl derived public key bins are valid.
        """
        public_bin = self.key_nacl.pub().key_to_bin()

        self.assertTrue(self.ec.is_valid_public_bin(public_bin))

    def test_public_to_pem(self) -> None:
        """
        Check if public keys can be serialized and loaded correctly in PEM format.
        """
        public_pem = self.key.pub().key_to_pem()

        # Convert the PEM to a DER keystring
        prefix = "-----BEGIN PUBLIC KEY-----\n"
        postfix = "-----END PUBLIC KEY-----\n"
        keystring = decodebytes(public_pem[len(prefix):-len(postfix)])

        # Reconstruct a key with this keystring
        key = M2CryptoPK(keystring=keystring)

        self.assertEqual(public_pem, key.key_to_pem())
