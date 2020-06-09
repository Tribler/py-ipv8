import binascii
import struct
import typing

from .metadata import Metadata
from ..signed_object import AbstractSignedObject
from ...keyvault.keys import PrivateKey


AttestationType = typing.TypeVar('AttestationType', bound='Attestation')


class Attestation(AbstractSignedObject):
    """
    A pointer to Metadata.

    An Attestation does not and should not contain an index.
    An Attestation does not and should not contain a reference to the public key (directly).
    """

    def __init__(self,
                 metadata_pointer: bytes,
                 private_key: typing.Optional[PrivateKey] = None,
                 signature: typing.Optional[bytes] = None):
        self.metadata_pointer = metadata_pointer
        super(Attestation, self).__init__(private_key, signature)

    def get_plaintext(self) -> bytes:
        return self.metadata_pointer

    @classmethod
    def unserialize(cls, data, public_key, offset=0) -> AttestationType:
        sig_len = public_key.get_signature_length()
        metadata_pointer, signature = struct.unpack_from(f">32s{sig_len}s", data, offset=offset)
        return Attestation(metadata_pointer, signature=signature)

    @classmethod
    def create(cls, metadata: Metadata, private_key: PrivateKey) -> AttestationType:
        return Attestation(metadata.get_hash(), private_key=private_key)

    def __str__(self) -> str:
        return f"Attestation({binascii.hexlify(self.metadata_pointer).decode()})"
