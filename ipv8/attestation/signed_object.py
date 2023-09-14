from __future__ import annotations

import abc
import hashlib
import struct
import typing

from ..keyvault.crypto import ECCrypto

if typing.TYPE_CHECKING:
    from ..types import PrivateKey, PublicKey

T = typing.TypeVar('T')


class AbstractSignedObject(metaclass=abc.ABCMeta):
    """
    To reach immutability different objects will have to be signed to reach non-repudiation.
    Examples are Tokens, Metadata and Attestation objects.

    This class handles many of the commonly required interactions for this type of signed data.
    """

    def __init__(self,
                 private_key: PrivateKey | None = None,
                 signature: bytes | None = None) -> None:
        """
        Create a new object that can be serialized and signed.
        Call this after the data has been established for the `get_plaintext()` method.
        """
        self._hash = b''
        self.crypto = ECCrypto()
        self._sign(private_key, signature)

    def get_hash(self) -> bytes:
        """
        Return the hash of this object itself.
        """
        return self._hash

    def verify(self, public_key: PublicKey) -> bool:
        """
        Verify if a public key belongs to this object.

        :returns: whether the given public key has signed for this object.
        """
        return self.crypto.is_valid_signature(public_key, self.get_plaintext(), self.signature)

    def _sign(self,
              private_key: PrivateKey | None = None,
              signature: bytes | None = None) -> None:
        """
        Add a signature to this data.
        Supply either your private key for signing or pass an existing signature.

        :param private_key: the private key to sign with.
        :param signature: the signature to adapt.
        """
        if private_key is not None and signature is None:
            self.signature = private_key.signature(self.get_plaintext())
        elif private_key is None and signature is not None:
            self.signature = signature
        else:
            msg = "Specify either private_key or signature!"
            raise RuntimeError(msg)
        self._hash = hashlib.sha3_256(self.get_plaintext_signed()).digest()

    @abc.abstractmethod
    def get_plaintext(self) -> bytes:
        """
        Retrieve the content that needs to be signed, in serialized form (bytes).
        """

    def get_plaintext_signed(self) -> bytes:
        """
        Concatenate the signature to the plaintext.
        """
        return self.get_plaintext() + self.signature

    @classmethod
    @abc.abstractmethod
    def unserialize(cls: type[T], data: bytes, public_key: PublicKey, offset: int = 0) -> T:
        """
        Read this signed object from its serialized form.
        """

    def __hash__(self) -> int:
        """
        The hash of this signed object.
        """
        return struct.unpack(">Q", self._hash[:8])[0]

    def __eq__(self, other: object) -> bool:
        """
        Signed objects are equal if their signed plaintext is equal.
        """
        if not isinstance(other, self.__class__):
            return False
        return self.get_plaintext_signed() == other.get_plaintext_signed()

    def __ne__(self, other: object) -> bool:
        """
        Signed objects are not equal if their signed plaintext is not equal.
        """
        if not isinstance(other, self.__class__):
            return True
        return self.get_plaintext_signed() != other.get_plaintext_signed()
