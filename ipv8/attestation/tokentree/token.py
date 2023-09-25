from __future__ import annotations

import binascii
import hashlib
import struct
from typing import TYPE_CHECKING

from ..signed_object import AbstractSignedObject

if TYPE_CHECKING:
    from ...keyvault.keys import PublicKey
    from ...types import PrivateKey


class Token(AbstractSignedObject):
    """
    A double pointer, pointing to a previous token and content.
    The contents belonging to the content pointer can be added to a Token object.

    Tokens do not and should not contain an index (but occupy one in a chain).
    Tokens do not and should not contain a reference to the public key (but are signed by one).
    """

    def __init__(self,
                 previous_token_hash: bytes,
                 content: bytes | None = None,
                 content_hash: bytes | None = None,
                 private_key: PrivateKey | None = None,
                 signature: bytes | None = None) -> None:
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
            self.content: bytes | None = content
            self.content_hash = hashlib.sha3_256(content).digest()
        elif content is None and content_hash is not None:
            self.content = None
            self.content_hash = content_hash
        else:
            msg = "Specify either content or content_hash!"
            raise RuntimeError(msg)

        self.previous_token_hash = previous_token_hash

        super().__init__(private_key, signature)

    def get_plaintext(self) -> bytes:
        """
        Return the double pointer of this Token in plain text format, being the concatenation of two hashes.
        """
        return self.previous_token_hash + self.content_hash

    @classmethod
    def unserialize(cls: type[Token], data: bytes, public_key: PublicKey, offset: int = 0) -> Token:
        """
        Unserialize a token from the given binary data.
        """
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
    def create(cls: type[Token], previous_token: Token, content: bytes, private_key: PrivateKey) -> Token:
        """
        Create an sign a token that exists in a token tree.
        """
        return Token(previous_token.get_hash(), content, private_key=private_key)

    def to_database_tuple(self) -> tuple[bytes, bytes, bytes, bytes | None]:
        """
        Get a representation of this Token as four byte strings (previous hash, signature, content hash and content).

        :returns: the four byte strings for database insertion.
        """
        return self.previous_token_hash, self.signature, self.content_hash, self.content

    @classmethod
    def from_database_tuple(cls: type[Token],
                            previous_token_hash: bytes,
                            signature: bytes,
                            content_hash: bytes,
                            content: bytes | None) -> Token:
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
        """
        Represent this token as a human-readable string.
        """
        return (f"Token[{binascii.hexlify(self.get_hash()).decode()}]"
                f"({binascii.hexlify(self.previous_token_hash).decode()}, "
                f"{binascii.hexlify(self.content_hash).decode()})")
