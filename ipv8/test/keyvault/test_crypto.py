from ..base import TestBase
from ...keyvault.crypto import ECCrypto
from ...keyvault.keys import Key, PrivateKey, PublicKey
from ...keyvault.private.libnaclkey import LibNaCLPK, LibNaCLSK
from ...keyvault.private.m2crypto import M2CryptoPK, M2CryptoSK


class TestECCrypto(TestBase):

    m2crypto_key = ECCrypto().generate_key(u"very-low")
    libnacl_key = ECCrypto().generate_key(u"curve25519")

    def setUp(self):
        super(TestECCrypto, self).setUp()
        self.ecc = ECCrypto()

    def test_available(self):
        """
        Check if the required curves are available.
        """
        available = self.ecc.security_levels

        self.assertIn(u"very-low", available)
        self.assertIn(u"low", available)
        self.assertIn(u"medium", available)
        self.assertIn(u"high", available)
        self.assertIn(u"curve25519", available)

    def test_generate_m2crypto(self):
        """
        Check if M2Crypto backend keys can be generated correctly.
        """
        self.assertIsInstance(TestECCrypto.m2crypto_key, Key)
        self.assertIsInstance(TestECCrypto.m2crypto_key, PrivateKey)
        self.assertIsInstance(TestECCrypto.m2crypto_key, PublicKey)
        self.assertIsInstance(TestECCrypto.m2crypto_key, M2CryptoSK)
        self.assertIsInstance(TestECCrypto.m2crypto_key, M2CryptoPK)

    def test_generate_nacl(self):
        """
        Check if libnacl backend keys can be generated correctly.
        """
        self.assertIsInstance(TestECCrypto.libnacl_key, Key)
        self.assertIsInstance(TestECCrypto.libnacl_key, PrivateKey)
        self.assertIsInstance(TestECCrypto.libnacl_key, PublicKey)
        self.assertIsInstance(TestECCrypto.libnacl_key, LibNaCLSK)
        self.assertIsInstance(TestECCrypto.libnacl_key, LibNaCLPK)

    def test_generate_bogus(self):
        """
        Check if a bogus curve produces a RuntimeError
        """
        self.assertRaises(RuntimeError, self.ecc.generate_key, u"idontexist")

    def test_key_to_bin_m2crypto(self):
        """
        Check if ECCrypto correctly detects an M2Crypto key for bin.
        """
        key_bin = self.ecc.key_to_bin(TestECCrypto.m2crypto_key)

        self.assertEqual(key_bin, TestECCrypto.m2crypto_key.key_to_bin())

    def test_key_to_bin_nacl(self):
        """
        Check if ECCrypto correctly detects an libnacl key for bin.
        """
        key_bin = self.ecc.key_to_bin(TestECCrypto.libnacl_key)

        self.assertEqual(key_bin, TestECCrypto.libnacl_key.key_to_bin())

    def test_key_to_hash_m2crypto(self):
        """
        Check if ECCrypto correctly detects an M2Crypto key for hash.
        """
        key_hash = self.ecc.key_to_hash(TestECCrypto.m2crypto_key)

        self.assertEqual(key_hash, TestECCrypto.m2crypto_key.key_to_hash())

    def test_key_to_hash_nacl(self):
        """
        Check if ECCrypto correctly detects an libnacl key for hash.
        """
        key_hash = self.ecc.key_to_hash(TestECCrypto.libnacl_key)

        self.assertEqual(key_hash, TestECCrypto.libnacl_key.key_to_hash())

    def test_is_valid_private_bin_m2crypto(self):
        """
        Check if ECCrypto can detect a valid M2Crypto private key.
        """
        self.assertTrue(self.ecc.is_valid_private_bin(TestECCrypto.m2crypto_key.key_to_bin()))

    def test_is_valid_private_bin_m2crypto_public(self):
        """
        Check if ECCrypto doesn't detect a valid public M2Crypto key as a private key.
        """
        self.assertFalse(self.ecc.is_valid_private_bin(TestECCrypto.m2crypto_key.pub().key_to_bin()))

    def test_is_valid_private_bin_nacl(self):
        """
        Check if ECCrypto can detect a valid libnacl private key.
        """
        self.assertTrue(self.ecc.is_valid_private_bin(TestECCrypto.libnacl_key.key_to_bin()))

    def test_is_valid_private_bin_nacl_public(self):
        """
        Check if ECCrypto doesn't detect a valid public libnacl key as a private key.
        """
        self.assertFalse(self.ecc.is_valid_private_bin(TestECCrypto.libnacl_key.pub().key_to_bin()))

    def test_is_valid_public_bin_m2crypto(self):
        """
        Check if ECCrypto doesn't detect a valid M2Crypto private key as a public key.
        """
        self.assertFalse(self.ecc.is_valid_public_bin(TestECCrypto.m2crypto_key.key_to_bin()))

    def test_is_valid_public_bin_m2crypto_public(self):
        """
        Check if ECCrypto detects a valid public M2Crypto key as a public key.
        """
        self.assertTrue(self.ecc.is_valid_public_bin(TestECCrypto.m2crypto_key.pub().key_to_bin()))

    def test_is_valid_public_bin_nacl(self):
        """
        Check if ECCrypto doesn't detect a valid libnacl private key as a public key.
        """
        self.assertFalse(self.ecc.is_valid_public_bin(TestECCrypto.libnacl_key.key_to_bin()))

    def test_is_valid_public_bin_nacl_public(self):
        """
        Check if ECCrypto detects a valid public libnacl key as a public key.
        """
        self.assertTrue(self.ecc.is_valid_public_bin(TestECCrypto.libnacl_key.pub().key_to_bin()))
