from ....attestation.tokentree.token import Token
from ....attestation.tokentree.tree import TokenTree
from ....keyvault.crypto import ECCrypto
from ....keyvault.keys import PublicKey
from ...base import TestBase


class TestTree(TestBase):
    """
    Tests related to the token tree.
    """

    def setUp(self) -> None:
        """
        Set up a new private key for testing.
        """
        super().setUp()
        self.crypto = ECCrypto()
        self.private_key = self.crypto.generate_key("curve25519")
        self.public_key = self.private_key.pub()

    def test_create_own_empty(self) -> None:
        """
        Check if we can create our own tree without content.
        """
        tree = TokenTree(private_key=self.private_key)

        self.assertEqual(0, len(tree.elements))
        self.assertEqual(0, len(tree.unchained))
        self.assertEqual(0, len(tree.get_missing()))
        self.assertIsInstance(tree.public_key, PublicKey)

    def test_create_other_empty(self) -> None:
        """
        Check if we can create a tree without content of someone else.
        """
        tree = TokenTree(public_key=self.public_key)

        self.assertEqual(0, len(tree.elements))
        self.assertEqual(0, len(tree.unchained))
        self.assertEqual(0, len(tree.get_missing()))

    def test_own_add(self) -> None:
        """
        Check if content is correctly added to the tree.
        """
        tree = TokenTree(private_key=self.private_key)
        content = b"test content"
        token = tree.add(content)

        self.assertEqual(1, len(tree.elements))
        self.assertEqual(0, len(tree.unchained))
        self.assertEqual(0, len(tree.get_missing()))
        self.assertTrue(tree.verify(token))
        self.assertEqual(content, token.content)

    def test_other_add_insequence(self) -> None:
        """
        Check if content is correctly added to another's tree, in order.
        """
        tree = TokenTree(public_key=self.public_key)
        real_token = Token(tree.genesis_hash, content=b"some data", private_key=self.private_key)
        pub_token = Token.unserialize(real_token.get_plaintext_signed(), self.public_key)
        token = tree.gather_token(pub_token)

        self.assertEqual(1, len(tree.elements))
        self.assertEqual(0, len(tree.unchained))
        self.assertEqual(0, len(tree.get_missing()))
        self.assertTrue(tree.verify(pub_token))
        self.assertIsNone(token.content)

    def test_other_add_outsequence(self) -> None:
        """
        Check if content is not added to another's tree if it is not linked to existing data.
        """
        tree = TokenTree(public_key=self.public_key)
        real_token = Token(b"ab" * 16, content=b"some data", private_key=self.private_key)
        pub_token = Token.unserialize(real_token.get_plaintext_signed(), self.public_key)
        token = tree.gather_token(pub_token)

        self.assertEqual(0, len(tree.elements))
        self.assertEqual(1, len(tree.unchained))
        self.assertListEqual([b"ab" * 16], list(tree.get_missing()))
        self.assertFalse(tree.verify(pub_token))
        self.assertIsNone(token)

    def test_other_add_outsequence_overflow(self) -> None:
        """
        Check if content is not added to another's tree if it is not linked to existing data.
        Remove the oldest data when too much data is pending.
        """
        tree = TokenTree(public_key=self.public_key)
        tree.unchained_max_size = 1
        real_token1 = Token(b"ab" * 16, content=b"some data", private_key=self.private_key)
        real_token2 = Token(b"cd" * 16, content=b"some other data", private_key=self.private_key)
        pub_token1 = Token.unserialize(real_token1.get_plaintext_signed(), self.public_key)
        pub_token2 = Token.unserialize(real_token2.get_plaintext_signed(), self.public_key)
        tree.gather_token(pub_token1)
        tree.gather_token(pub_token2)

        self.assertEqual(0, len(tree.elements))
        self.assertEqual(1, len(tree.unchained))
        self.assertListEqual([b"cd" * 16], list(tree.get_missing()))
        self.assertFalse(tree.verify(pub_token1))
        self.assertFalse(tree.verify(pub_token2))

    def test_other_add_duplicate(self) -> None:
        """
        Check if tokens are not added twice (by branch position and content hash).
        """
        tree = TokenTree(public_key=self.public_key)
        real_token = Token(tree.genesis_hash, content=b"some data", private_key=self.private_key)
        pub_token = Token.unserialize(real_token.get_plaintext_signed(), self.public_key)
        token = tree.gather_token(pub_token)
        tree.gather_token(pub_token)

        self.assertEqual(1, len(tree.elements))
        self.assertEqual(0, len(tree.unchained))
        self.assertEqual(0, len(tree.get_missing()))
        self.assertTrue(tree.verify(pub_token))
        self.assertIsNone(token.content)

    def test_other_add_duplicate_wcontent(self) -> None:
        """
        Check if a token passes on its content to a duplicate entry without content.
        """
        tree = TokenTree(public_key=self.public_key)
        real_token = Token(tree.genesis_hash, content=b"some data", private_key=self.private_key)
        pub_token = Token.unserialize(real_token.get_plaintext_signed(), self.public_key)
        token = tree.gather_token(pub_token)
        tree.gather_token(real_token)

        self.assertEqual(1, len(tree.elements))
        self.assertEqual(0, len(tree.unchained))
        self.assertEqual(0, len(tree.get_missing()))
        self.assertTrue(tree.verify(pub_token))
        self.assertTrue(tree.verify(token))
        self.assertEqual(b"some data", token.content)

    def test_serialize_public(self) -> None:
        """
        Check if the public tree data is serialized correctly.
        """
        tree = TokenTree(private_key=self.private_key)
        tree.add(b"data1")
        tree.add(b"data2")
        tree.add(b"data3")

        self.assertEqual(128 * 3, len(tree.serialize_public()))

    def test_serialize_public_partial(self) -> None:
        """
        Check if the public tree data is partially serialized correctly.
        """
        tree = TokenTree(private_key=self.private_key)
        first_token = tree.add(b"data1")
        second_token = tree.add(b"data2", first_token)
        tree.add(b"data3", second_token)

        self.assertEqual(128 * 2, len(tree.serialize_public(second_token)))

    def test_unserialize_public(self) -> None:
        """
        Check if serialized public tree data can be paired with its source data.
        """
        public_key = self.crypto.key_from_public_bin(b'LibNaCLPK:/N\xc5\xd1#\xd4\xc5\x02\xca\xb4\xa4\xd4vKD\xf1"\xf0'
                                                     b'1,\\\xde\x14\x87\xa9\xf6T\x90\xd9\xb0qk\xdbPS\xfbqm\xc1,i\xca'
                                                     b'\x88\x7fm\xe8\\\x0f\xe9\xee\xec\xce\xbeN\xdc\x94\xc4\x84\'\x8b'
                                                     b'\xb8\x8e\x1b\xc4')
        s = (b'\xb1\xa6\xf8#\x91q\xa2\x95 \xb7\xa1\x0c"6 1&\xdd\xf6\xf53\x0b\xe6\x17\xe3 H\xa6\xe0\xfa\x1d4\x1f\xef'
             b'\xf3:1\xfe{\xd7\x10\xf78\xec\x96\xe9Z\x8a\x85Q\xa2\x04z\xbdF0\x9b{%\x94\xe6\x065\x95(\xc9\x9c(\x87\xe0'
             b'Z\xff\xcf\xfd\x880}\\\xa0\xf5WD\x00\x14D.\x8d\x99p\xc6%3:\xc1\x1d\xaeP\x8bU\xc5\xe6\xe2,\xc01MN\x96\xdf'
             b'\xad=\xf1J\x1f\x12\x19B\x96e\x98EV\xa0-i\xb1\xa3\x04\xdd\xc2\xef\\\xc7\x93\xb2?0\xba4\xda\xac\x87\xd0o'
             b'\xe0cl\xd4\xe5\x86\xdb\xb1K\x84\xe3oE\x1e\xcb\x9b\xf3\xab>\xc9<\xbe\xcf*\xe8(\x0f\rx!\x11\xab2\x02\xdf'
             b'\xa6\xee\xf6yr\x03\xb8\x86\xe2\x15\xfc{n@\x9a\xcb\xb8I\xfa\x91\xf6\xb5\xac\x82\x9e\x18;\xcd\xba\x13\x94'
             b'\x91{%,[k\xe9\xb1,E\xb1\n$\xb5\xd2\xfe\xeb\xe2\x1bS4;0\xc2\xd2\xf5*\x98\xacxc\xebb\x9d\'<E\x8az\xf6\xc9'
             b'Z)x\x83\x02\xc2\x87\x92KU`\x80\x9btH\x17\xd00\xea\x8e4\x19\xc7\x1c5\xff\xdb\xc4\xd5e\xdfw\x02\xb0N\xe9'
             b'\x82Lu\xb3\x10\xb7i\xb0\xa0\xc8R\x1a@\x96\x8a\xf4=\xafb\xce\xc5\xab\x1ae\xdce\x80\x93\x19  \x89|\xf2'
             b'\x0cM^q\xb7\xa8{\xa9\xf2Y\x8d<\xb5\x8e\xec6S_\x96\x03\x9c\xd1\xb1\x03\x9b\xe7\x89{_\xd8`\x91\xe8{>\x07'
             b'M\xce\xd9!\x88]\xe6\x1c\xf7\x99\x9f\xc3au\xdd\x9f\\\xaf0\xe0L\xfcu\xd0e\x84\x05')
        tree = TokenTree(public_key=public_key)
        tree.unserialize_public(s)

        self.assertEqual(3, len(tree.elements))

        for token in tree.elements.values():
            self.assertTrue(tree.verify(token))

        # By design, the TokenTree does not keep the mapping between content and Tokens.
        # But we can show the three different values are captured by the three Tokens.
        for content in [b"data1", b"data2", b"data3"]:
            self.assertTrue(any(token.receive_content(content) for token in tree.elements.values()))
