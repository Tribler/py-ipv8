from twisted.trial import unittest

from ...keyvault.crypto import ECCrypto
from ...keyvault.public.m2crypto import M2CryptoPK
from ...keyvault.private.m2crypto import M2CryptoSK


class TestSerialization(unittest.TestCase):
    """
    Test whether keys can be serialized and unserialized correctly.
    """

    def setUp(self):
        super(TestSerialization, self).setUp()
        self.ec = ECCrypto()
        self.key = self.ec.generate_key(u"very-low")
        self.key_nacl = self.ec.generate_key(u"curve25519")

    def test_private_to_bin(self):
        """
        Check if M2Crypto derived key bins are valid.
        """
        private_bin = self.key.key_to_bin()

        self.assertTrue(self.ec.is_valid_private_bin(private_bin))

    def test_private_nacl_to_bin(self):
        """
        Check if libnacl derived key bins are valid.
        """
        private_bin = self.key_nacl.key_to_bin()

        self.assertTrue(self.ec.is_valid_private_bin(private_bin))

    def test_private_to_pem(self):
        """
        Check if keys can be serialized and loaded correctly in PEM format.
        """
        private_pem = self.key.key_to_pem()

        # Convert the PEM to a DER keystring
        prefix = "-----BEGIN EC PRIVATE KEY-----\n"
        postfix = "-----END EC PRIVATE KEY-----\n"
        keystring = private_pem[len(prefix):-len(postfix)].decode("BASE64")

        # Reconstruct a key with this keystring
        key = M2CryptoSK(keystring=keystring)

        self.assertEqual(private_pem, key.key_to_pem())

    def test_public_to_bin(self):
        """
        Check if M2Crypto derived public key bins are valid.
        """
        public_bin = self.key.pub().key_to_bin()

        self.assertTrue(self.ec.is_valid_public_bin(public_bin))

    def test_public_nacl_to_bin(self):
        """
        Check if libnacl derived public key bins are valid.
        """
        public_bin = self.key_nacl.pub().key_to_bin()

        self.assertTrue(self.ec.is_valid_public_bin(public_bin))

    def test_public_to_pem(self):
        """
        Check if public keys can be serialized and loaded correctly in PEM format.
        """
        public_pem = self.key.pub().key_to_pem()

        # Convert the PEM to a DER keystring
        prefix = "-----BEGIN PUBLIC KEY-----\n"
        postfix = "-----END PUBLIC KEY-----\n"
        keystring = public_pem[len(prefix):-len(postfix)].decode("BASE64")

        # Reconstruct a key with this keystring
        key = M2CryptoPK(keystring=keystring)

        self.assertEqual(public_pem, key.key_to_pem())
