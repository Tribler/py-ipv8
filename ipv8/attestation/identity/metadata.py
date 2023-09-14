from __future__ import annotations

import binascii
import json
from typing import TYPE_CHECKING

from ..signed_object import AbstractSignedObject

if TYPE_CHECKING:
    from ...keyvault.keys import PublicKey
    from ...types import PrivateKey, Token


class Metadata(AbstractSignedObject):
    """
    A JSON dictionary and a pointer to a Token.

    Metadata does not and should not contain an index.
    Metadata does not and should not contain a reference to the public key (but is signed by one).
    """

    def __init__(self,
                 token_pointer: bytes,
                 serialized_json_dict: bytes,
                 private_key: PrivateKey | None = None,
                 signature: bytes | None = None) -> None:
        """
        Create a new Metadata object, always specify the token it belongs to and its contents as a JSON dictionary.

        For Metadata belonging to yourself, give the token pointer, the JSON dictionary and private key and the content
        hash and signature will be automatically created.
        For Metadata of someone else or your own reloaded Metadata, give the token pointer, the JSON dictionary and
        the signature.

        :param token_pointer: a string pointing to the hash of the Token.
        :param serialized_json_dict: the JSON dictionary of metadata to tokenize.
        :param private_key: the private key of the current user, creating this new Token.
        :param signature: the signature for this Token.
        """
        self.token_pointer = token_pointer
        self.serialized_json_dict = serialized_json_dict
        super().__init__(private_key, signature)

    def get_plaintext(self) -> bytes:
        """
        Serialized Metadata consists of a token pointer and serialized JSON.
        """
        return self.token_pointer + self.serialized_json_dict

    @classmethod
    def unserialize(cls: type[Metadata], data: bytes, public_key: PublicKey, offset: int = 0) -> Metadata:
        """
        Unserialize metadata from the given bytes.
        """
        if offset != 0:
            msg = "Offset is not supported for Metadata!"
            raise RuntimeError(msg)
        sig_len = public_key.get_signature_length()
        return Metadata(data[:32], data[32:-sig_len], signature=data[-sig_len:])

    @classmethod
    def create(cls: type[Metadata], token: Token, json_dict: dict, private_key: PrivateKey) -> Metadata:
        """
        Create new metadata for a token from a JSON dict, signed using our key.
        """
        return Metadata(token.get_hash(), json.dumps(json_dict).encode(), private_key=private_key)

    def to_database_tuple(self) -> tuple[bytes, bytes, bytes]:
        """
        Get a representation of this Metadata as three byte strings (token hash, signature and json dictionary).

        :returns: the three byte strings for database insertion.
        """
        return self.token_pointer, self.signature, self.serialized_json_dict

    @classmethod
    def from_database_tuple(cls: type[Metadata],
                            token_pointer: bytes,
                            signature: bytes,
                            serialized_json_dict: bytes) -> Metadata:
        """
        Create a Token from a three-byte-string representation (token hash, signature and json dictionary).

        :param token_pointer: the hash of the Token.
        :param signature: the signature over the plaintext Metadata.
        :param serialized_json_dict: the serialized json dictionary of this Metadata.
        """
        return Metadata(token_pointer, serialized_json_dict, signature=signature)

    def __str__(self) -> str:
        """
        Convert this Metadata to human-readable format.
        """
        return (f"Metadata({binascii.hexlify(self.token_pointer).decode()},\n"
                f"{self.serialized_json_dict.decode()})")
