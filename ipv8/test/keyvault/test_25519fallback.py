from __future__ import annotations

from ...keyvault.private.cryptography25519 import Cryptography25519SK
from ...keyvault.private.libnaclkey import LibNaCLSK
from ..base import TestBase


class TestFallback(TestBase):
    """
    Check if the fallback NaCL implementation does the same as the real thing (albeit slower).
    """

    nacl_key: LibNaCLSK
    nacl_copy: LibNaCLSK
    crypto_key: Cryptography25519SK
    crypto_copy: Cryptography25519SK

    @classmethod
    def setUpClass(cls: TestFallback) -> None:
        """
        Create a real NaCL key and a cryptography-based copy.
        """
        super().setUpClass()

        cls.nacl_key = LibNaCLSK()  # Generates a new NaCL key
        cls.crypto_copy = Cryptography25519SK(cls.nacl_key.key_to_bin()[10:])

        cls.crypto_key = Cryptography25519SK()  # Generates a new cryptography-based key
        cls.nacl_copy = LibNaCLSK(cls.crypto_key.key_to_bin()[10:])

    def test_sk_to_bin(self) -> None:
        """
        Check if the secret key binary formats are interchangeable.
        """
        self.assertEqual(self.nacl_key.key_to_bin(), self.crypto_copy.key_to_bin())
        self.assertEqual(self.crypto_key.key_to_bin(), self.nacl_copy.key_to_bin())

    def test_pk_to_bin(self) -> None:
        """
        Check if the public key binary formats are interchangeable.
        """
        self.assertEqual(self.nacl_key.pub().key_to_bin(), self.crypto_copy.pub().key_to_bin())
        self.assertEqual(self.crypto_key.pub().key_to_bin(), self.nacl_copy.pub().key_to_bin())

    def test_sk_to_hash(self) -> None:
        """
        Check if the hashes of the secret keys are interchangeable.
        """
        self.assertEqual(self.nacl_key.key_to_hash(), self.crypto_copy.key_to_hash())
        self.assertEqual(self.crypto_key.key_to_hash(), self.nacl_copy.key_to_hash())

    def test_pk_to_hash(self) -> None:
        """
        Check if the hashes of the secret keys are interchangeable.
        """
        self.assertEqual(self.nacl_key.pub().key_to_hash(), self.crypto_copy.pub().key_to_hash())
        self.assertEqual(self.crypto_key.pub().key_to_hash(), self.nacl_copy.pub().key_to_hash())

    def test_sign_and_verify_nacl_to_crypto(self) -> None:
        """
        Check if NaCL signatures can be verified by the cryptography fallback.
        """
        signed = self.nacl_key.signature(b"hello")
        self.assertTrue(self.crypto_copy.pub().verify(signed, b"hello"))

    def test_sign_and_verify_crypto_to_nacl(self) -> None:
        """
        Check if the cryptography fallback signatures can be verified by NaCL.
        """
        signed = self.crypto_key.signature(b"hello")
        self.assertTrue(self.nacl_copy.pub().verify(signed, b"hello"))
