from asynctest import TestCase

from ....attestation.tokenchain.chain import TokenChain
from ....attestation.tokenchain.token import Token
from ....keyvault.crypto import ECCrypto
from ....keyvault.keys import PublicKey


class TestChain(TestCase):

    def setUp(self) -> None:
        self.crypto = ECCrypto()
        self.private_key = self.crypto.generate_key("curve25519")
        self.public_key = self.private_key.pub()

    def test_create_own_empty(self) -> None:
        """
        Check if we can create our own chain without content.
        """
        chain = TokenChain(private_key=self.private_key)

        self.assertEqual(0, len(chain.chain))
        self.assertEqual(0, len(chain.unchained))
        self.assertEqual(0, len(chain.get_missing()))
        self.assertIsInstance(chain.public_key, PublicKey)
        self.assertTrue(chain.verify())

    def test_create_other_empty(self) -> None:
        """
        Check if we can create a chain without content of someone else.
        """
        chain = TokenChain(public_key=self.public_key)

        self.assertEqual(0, len(chain.chain))
        self.assertEqual(0, len(chain.unchained))
        self.assertEqual(0, len(chain.get_missing()))
        self.assertTrue(chain.verify())

    def test_own_add(self):
        """
        Check if content is correctly added to the chain.
        """
        chain = TokenChain(private_key=self.private_key)
        content = b"test content"
        token = chain.add(content)

        self.assertEqual(1, len(chain.chain))
        self.assertEqual(0, len(chain.unchained))
        self.assertEqual(0, len(chain.get_missing()))
        self.assertTrue(chain.verify())
        self.assertEqual(content, token.content)
        self.assertEqual(0, chain.chain_lookup[token.get_hash()])

    def test_other_add_insequence(self):
        """
        Check if content is correctly added to another's chain, in order.
        """
        chain = TokenChain(public_key=self.public_key)
        real_token = Token(chain.genesis_hash, content=b"some data", private_key=self.private_key)
        token = chain.gather(real_token.previous_token_hash, real_token.content_hash, real_token.signature)

        self.assertEqual(1, len(chain.chain))
        self.assertEqual(0, len(chain.unchained))
        self.assertEqual(0, len(chain.get_missing()))
        self.assertTrue(chain.verify())
        self.assertIsNone(token.content)
        self.assertEqual(0, chain.chain_lookup[token.get_hash()])

    def test_other_add_outsequence(self):
        """
        Check if content is not added to another's chain if it is not linked to existing data.
        """
        chain = TokenChain(public_key=self.public_key)
        real_token = Token(b"some hash", content=b"some data", private_key=self.private_key)
        token = chain.gather(real_token.previous_token_hash, real_token.content_hash, real_token.signature)

        self.assertEqual(0, len(chain.chain))
        self.assertEqual(1, len(chain.unchained))
        self.assertListEqual([b"some hash"], list(chain.get_missing()))
        self.assertTrue(chain.verify())
        self.assertIsNone(token.content)
        self.assertNotIn(token.get_hash(), chain.chain_lookup)

    def test_other_add_outsequence_overflow(self):
        """
        Check if content is not added to another's chain if it is not linked to existing data.
        Remove the oldest data when too much data is pending.
        """
        chain = TokenChain(public_key=self.public_key)
        chain.unchained_max_size = 1
        real_token1 = Token(b"some hash", content=b"some data", private_key=self.private_key)
        real_token2 = Token(b"some other hash", content=b"some other data", private_key=self.private_key)
        chain.gather(real_token1.previous_token_hash, real_token1.content_hash, real_token1.signature)
        chain.gather(real_token2.previous_token_hash, real_token2.content_hash, real_token2.signature)

        self.assertEqual(0, len(chain.chain))
        self.assertEqual(1, len(chain.unchained))
        self.assertListEqual([b"some other hash"], list(chain.get_missing()))
        self.assertTrue(chain.verify())

    def test_other_add_duplicate(self):
        """
        Check if tokens are not added twice (by chain position and content hash).
        """
        chain = TokenChain(public_key=self.public_key)
        real_token = Token(chain.genesis_hash, content=b"some data", private_key=self.private_key)
        token = chain.gather(real_token.previous_token_hash, real_token.content_hash, real_token.signature)
        chain.gather(real_token.previous_token_hash, real_token.content_hash, real_token.signature)

        self.assertEqual(1, len(chain.chain))
        self.assertEqual(0, len(chain.unchained))
        self.assertEqual(0, len(chain.get_missing()))
        self.assertTrue(chain.verify())
        self.assertIsNone(token.content)
        self.assertEqual(0, chain.chain_lookup[token.get_hash()])

    def test_other_add_duplicate_wcontent(self):
        """
        Check if a token passes on its content to a duplicate entry without content.
        """
        chain = TokenChain(public_key=self.public_key)
        real_token = Token(chain.genesis_hash, content=b"some data", private_key=self.private_key)
        token = chain.gather(real_token.previous_token_hash, real_token.content_hash, real_token.signature)
        chain.gather_token(real_token)

        self.assertEqual(1, len(chain.chain))
        self.assertEqual(0, len(chain.unchained))
        self.assertEqual(0, len(chain.get_missing()))
        self.assertTrue(chain.verify())
        self.assertEquals(b"some data", token.content)
        self.assertEqual(0, chain.chain_lookup[token.get_hash()])

    def test_serialize_public(self):
        """
        Check if the public chain data is serialized correctly.
        """
        chain = TokenChain(private_key=self.private_key)
        chain.add(b"data1")
        chain.add(b"data2")
        chain.add(b"data3")

        self.assertEqual(128 * 3, len(chain.serialize_public()))

    def test_unserialize_public(self):
        """
        Check if serialized public chain data can be paired with its source data.
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
        chain = TokenChain.unserialize_public(s, public_key)

        self.assertTrue(chain.verify())
        self.assertEqual(3, len(chain.chain))
        self.assertTrue(chain.content_matches(0, b"data1"))
        self.assertTrue(chain.content_matches(1, b"data2"))
        self.assertTrue(chain.content_matches(2, b"data3"))
