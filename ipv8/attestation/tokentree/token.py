import binascii
import hashlib
import struct
import typing

from ..signed_object import AbstractSignedObject
from ...keyvault.keys import PrivateKey


TokenType = typing.TypeVar('TokenType', bound='Token')


class Token(AbstractSignedObject):
    """
    A double pointer, pointing to a previous token and content.
    The contents belonging to the content pointer can be added to a Token object.

    Tokens do not and should not contain an index (but occupy one in a chain).
    Tokens do not and should not contain a reference to the public key (but are signed by one).
    """

    def __init__(self,
                 previous_token_hash: bytes,
                 content: typing.Optional[bytes] = None,
                 content_hash: typing.Optional[bytes] = None,
                 private_key: typing.Optional[PrivateKey] = None,
                 signature: typing.Optional[bytes] = None) -> None:
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
        if content is not None and content_hash is None:
            self.content = content
            self.content_hash = hashlib.sha3_256(content).digest()
        elif content is None and content_hash is not None:
            self.content = None
            self.content_hash = content_hash
        else:
            raise RuntimeError("Specify either content or content_hash!")

        self.previous_token_hash = previous_token_hash

        super(Token, self).__init__(private_key, signature)

    def get_plaintext(self) -> bytes:
        """
        Return the double pointer of this Token in plain text format, being the concatenation of two hashes.
        """
        return self.previous_token_hash + self.content_hash

    @classmethod
    def unserialize(cls, data, public_key, offset=0) -> TokenType:
        sig_len = public_key.get_signature_length()
        previous_token_hash, content_hash, signature = struct.unpack_from(f">32s32s{sig_len}s", data, offset=offset)
        return Token(previous_token_hash, content_hash=content_hash, signature=signature)

    def receive_content(self, content: bytes) -> bool:
        """
        Attempt to receive some content, only add it if its hash matches what we expect.

        :param content: the content potentially belonging to the hash pointed to by this Token.
        :returns: whether we accepted the content.
        """
        content_hash = hashlib.sha3_256(content).digest()
        if content_hash == self.content_hash:
            self.content = content
            return True
        return False

    @classmethod
    def create(cls, previous_token: TokenType, content: bytes, private_key: PrivateKey) -> TokenType:
        return Token(previous_token.get_hash(), content, private_key=private_key)

    def to_database_tuple(self) -> typing.Tuple[bytes, bytes, bytes, bytes]:
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
                            content: typing.Optional[bytes]) -> TokenType:
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
        return (f"Token[{binascii.hexlify(self.get_hash()).decode()}]"
                f"({binascii.hexlify(self.previous_token_hash).decode()}, "
                f"{binascii.hexlify(self.content_hash).decode()})")
