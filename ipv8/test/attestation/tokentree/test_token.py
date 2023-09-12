from __future__ import annotations

from ....attestation.tokentree.token import Token
from ....keyvault.crypto import ECCrypto
from ...base import TestBase


class TestToken(TestBase):
    """
    Tests related to tokens.
    """

    @classmethod
    def setUpClass(cls: type[TestToken]) -> None:
        """
        Load in test data.
        """
        cls.test_data = b"1234567890abcdefghijklmnopqrstuvwxyz" * 69
        cls.test_data_hash = b"[B\xc79lC\x07\xc88T\xe4yVN0+\x9e}\xc1\x1e\xfc\x88'm\x8d7\xe1\xa4*5\x06$"
        cls.test_public_key = ECCrypto().key_from_public_bin(b'LibNaCLPK:\xc8\xf38};U\xe4\xd5\xf7\xfd\xbc+J!\xbe\xba'
                                                             b'\x81M\xda\xef\xb7\x8c\xacL\x1eZ\x9d\xaf\xaaX+&\xac\xe2'
                                                             b'\xd2\xdd\x86\xa9\x97\xb8T\x9b\x82\xc1>\xa2\r\x11?\xef'
                                                             b'\x137\xf1\xdc!\x7f\x9fW\xe7\x11.\xe2\xc8)')
        cls.test_signature = (b'2\x05\xb3\xf24\xad\xc8)\xf5\x8bh+(0\x153\x01L\xfd-\x8e\x8bWr\xcbz\xd7\xbdEt\\\xd7\xe4'
                              b',\x80g\xbe\x7fT\x9c8\xb0\xc5\x80\xe4\xfa\xec\xad\xceY\xb8\xcek\x8bp\x81\xb0,j7`\x0f'
                              b'\xf8\x0f')

    def setUp(self) -> None:
        """
        Create a new private key for testing.
        """
        super().setUp()

        self.private_key = ECCrypto().generate_key("curve25519")

    def test_create_private_token(self) -> None:
        """
        Check if a token is correctly created with a private key.
        """
        token = Token(b"test_previous_token_hash", content=self.test_data, private_key=self.private_key)

        self.assertEqual(b"test_previous_token_hash", token.previous_token_hash)
        self.assertEqual(self.test_data, token.content)
        self.assertEqual(self.test_data_hash, token.content_hash)
        self.assertTrue(token.verify(self.private_key.pub()))

    def test_verify_token_illegal(self) -> None:
        """
        Check if a token does not verify for a different public key.
        """
        token = Token(b"test_previous_token_hash", content=self.test_data, private_key=self.private_key)
        other_key = ECCrypto().generate_key("curve25519").pub()

        self.assertFalse(token.verify(other_key))

    def test_create_public_token(self) -> None:
        """
        Check if a token is correctly loaded with a public key.
        """
        token = Token(b"test_previous_token_hash", content_hash=self.test_data_hash, signature=self.test_signature)

        self.assertEqual(b"test_previous_token_hash", token.previous_token_hash)
        self.assertIsNone(token.content)
        self.assertEqual(self.test_data_hash, token.content_hash)
        self.assertTrue(token.verify(self.test_public_key))

    def test_update_public_token(self) -> None:
        """
        Check if a token with only a content hash accepts the correct content.
        """
        token = Token(b"test_previous_token_hash", content_hash=self.test_data_hash, signature=self.test_signature)

        return_value = token.receive_content(self.test_data)

        self.assertTrue(return_value)
        self.assertEqual(b"test_previous_token_hash", token.previous_token_hash)
        self.assertEqual(self.test_data, token.content)
        self.assertEqual(self.test_data_hash, token.content_hash)
        self.assertTrue(token.verify(self.test_public_key))

    def test_update_public_token_illegal(self) -> None:
        """
        Check if a token with only a content hash rejects invalid content.
        """
        token = Token(b"test_previous_token_hash", content_hash=self.test_data_hash, signature=self.test_signature)

        return_value = token.receive_content(b"some other data")

        self.assertFalse(return_value)
        self.assertEqual(b"test_previous_token_hash", token.previous_token_hash)
        self.assertIsNone(token.content)
        self.assertEqual(self.test_data_hash, token.content_hash)
        self.assertTrue(token.verify(self.test_public_key))
