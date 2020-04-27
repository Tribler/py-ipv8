from binascii import hexlify
from hashlib import sha3_256
from struct import unpack
from typing import Optional, Tuple, TypeVar

from ...keyvault.crypto import ECCrypto
from ...keyvault.keys import PrivateKey, PublicKey


TokenType = TypeVar('TokenType', bound='Token')


class Token(object):
    """
    A double pointer, pointing to a previous token and content.
    The contents belonging to the content pointer can be added to a Token object.

    Tokens do not and should not contain an index (but occupy one in a chain).
    Tokens do not and should not contain a reference to the public key (but are signed by one).
    """

    def __init__(self,
                 previous_token_hash: bytes,
                 content: Optional[bytes] = None,
                 content_hash: Optional[bytes] = None,
                 private_key: Optional[PrivateKey] = None,
                 signature: Optional[bytes] = None) -> None:
        """
        Create a new Token object, always specify the hash of the preceding Token.

        For a Token belonging to yourself, give the content and private key and the content hash and signature will
        be automatically created.
        For a Token of someone else or your own reloaded Token, give the content hash and the signature.

        :param previous_token_hash: a string pointing to the hash of the preceding Token.
        :param content: the content to tokenize.
        :param content_hash: the hash of the tokenized content.
        :param private_key: the private key of the current user, creating this new Token.
        :param signature: the signature for this Token.
        """
        super(Token, self).__init__()

        if content is not None and content_hash is None:
            self.content = content
            self.content_hash = sha3_256(content).digest()
        elif content is None and content_hash is not None:
            self.content = None
            self.content_hash = content_hash
        else:
            raise RuntimeError("Specify either content or content_hash!")

        self.previous_token_hash = previous_token_hash

        self._hash = b''
        self._sign(private_key, signature)

        self.crypto = ECCrypto()

    def get_plaintext(self) -> bytes:
        """
        Return the double pointer of this Token in plain text format, being the concatenation of two hashes.
        """
        return self.previous_token_hash + self.content_hash

    def get_plaintext_signed(self) -> bytes:
        """
        Return the double pointer and the signature in plain text format, being the concatenation of the three items.
        """
        return self.get_plaintext() + self.signature

    def get_hash(self) -> bytes:
        """
        Return the hash of this Token itself.
        """
        return self._hash

    def _sign(self, private_key: Optional[PrivateKey] = None, signature: Optional[bytes] = None) -> None:
        """
        Add a signature to this Token.
        Supply either your private key for signing or pass an existing signature.

        :param private_key: the private key to sign with.
        :param signature: the signature to adapt.
        """
        if private_key is not None and signature is None:
            self.signature = private_key.signature(self.get_plaintext())
        elif private_key is None and signature is not None:
            self.signature = signature
        else:
            raise RuntimeError("Specify either private_key or signature!")
        self._hash = sha3_256(self.get_plaintext_signed()).digest()

    def receive_content(self, content: bytes) -> bool:
        """
        Attempt to receive some content, only add it if its hash matches what we expect.

        :param content: the content potentially belonging to the hash pointed to by this Token.
        :returns: whether we accepted the content.
        """
        content_hash = sha3_256(content).digest()
        if content_hash == self.content_hash:
            self.content = content
            return True
        return False

    def verify(self, public_key: PublicKey) -> bool:
        """
        Verify if a public key belongs to this Token.

        :returns: whether the given public key has signed for this Token.
        """
        return self.crypto.is_valid_signature(public_key, self.get_plaintext(), self.signature)

    def to_database_tuple(self) -> Tuple[bytes, bytes, bytes, bytes]:
        """
        Get a representation of this Token as four byte strings (previous hash, signature, content hash and content).

        :returns: the four byte strings for database insertion.
        """
        return self.previous_token_hash, self.signature, self.content_hash, self.content

    @classmethod
    def from_database_tuple(cls,
                            previous_token_hash: bytes,
                            signature: bytes,
                            content_hash: bytes,
                            content: Optional[bytes]) -> TokenType:
        """
        Create a Token from a four-byte-string representation (previous hash, signature, content hash and content).

        :param previous_token_hash: the hash of the preceding Token.
        :param signature: the signature over the plaintext Token.
        :param content_hash: the content hash of this Token.
        :param content: optionally the content belonging to this Token.
        """
        token = Token(previous_token_hash, content_hash=content_hash, signature=signature)
        if content is not None:
            token.receive_content(content)
        return token

    def __str__(self) -> str:
        return f"Token({hexlify(self.previous_token_hash).decode()}, {hexlify(self.content_hash).decode()})"

    def __hash__(self) -> int:
        return unpack(">Q", self._hash[:8])[0]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Token):
            return False
        return self.get_plaintext_signed() == other.get_plaintext_signed()

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, Token):
            return True
        return self.get_plaintext_signed() != other.get_plaintext_signed()
