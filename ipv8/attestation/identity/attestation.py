from __future__ import annotations

import binascii
import struct
from typing import TYPE_CHECKING

from ..signed_object import AbstractSignedObject

if TYPE_CHECKING:
    from ...types import Metadata, PrivateKey, PublicKey


class Attestation(AbstractSignedObject):
    """
    A pointer to Metadata.

    An Attestation does not and should not contain an index.
    An Attestation does not and should not contain a reference to the public key (directly).
    """

    def __init__(self,
                 metadata_pointer: bytes,
                 private_key: PrivateKey | None = None,
                 signature: bytes | None = None) -> None:
        """
        Create a new business-layer attestation (not the actual crypto attestation).
        """
        self.metadata_pointer = metadata_pointer
        super().__init__(private_key, signature)

    def get_plaintext(self) -> bytes:
        """
        Convert to bytes.
        """
        return self.metadata_pointer

    @classmethod
    def unserialize(cls: type[Attestation], data: bytes, public_key: PublicKey, offset: int = 0) -> Attestation:
        """
        Read from bytes.
        """
        sig_len = public_key.get_signature_length()
        metadata_pointer, signature = struct.unpack_from(f">32s{sig_len}s", data, offset=offset)
        return Attestation(metadata_pointer, signature=signature)

    @classmethod
    def create(cls: type[Attestation], metadata: Metadata, private_key: PrivateKey) -> Attestation:
        """
        Create an attestation for given metadata using our key.
        """
        return Attestation(metadata.get_hash(), private_key=private_key)

    def to_database_tuple(self) -> tuple[bytes, bytes]:
        """
        Get a representation of this Attestation as two byte strings (metadata hash and signature).

        :returns: the two byte strings for database insertion.
        """
        return self.metadata_pointer, self.signature

    @classmethod
    def from_database_tuple(cls: type[Attestation],
                            metadata_pointer: bytes,
                            signature: bytes) -> Attestation:
        """
        Create a Token from a two-byte-string representation (metadata hash and signature).

        :param metadata_pointer: the hash of the Attestation.
        :param signature: the signature over the plaintext Attestation.
        """
        return Attestation(metadata_pointer, signature=signature)

    def __str__(self) -> str:
        """
        Convert this attestation to a human-readable string.
        """
        return f"Attestation({binascii.hexlify(self.metadata_pointer).decode()})"
