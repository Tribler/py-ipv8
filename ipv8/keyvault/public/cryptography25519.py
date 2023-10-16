from __future__ import annotations

from binascii import unhexlify
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ...keyvault.keys import PublicKey

KEY_LENGTH = 32


class Cryptography25519PK(PublicKey):
    """
    A fallback implementation for LibNaCL public keys.
    """

    def __init__(self, binarykey: bytes = b"", pk: bytes | None = None, hex_vk: bytes | None = None) -> None:
        """
        Create a new LibNaCL public key. Optionally load it from a string representation or
        using a public key and verification key.

        :param binarykey: load the pk from this string (see key_to_bin())
        :param pk: the libnacl public key to use in byte format
        :param hex_vk: a verification key in hex format
        """
        # Load the key, if specified
        if binarykey:
            pk, vk = (binarykey[:KEY_LENGTH], binarykey[KEY_LENGTH: KEY_LENGTH * 2])
        else:
            vk = unhexlify(cast(bytes, hex_vk))
        # Construct the public key and verifier objects
        self.key = Ed25519PublicKey.from_public_bytes(cast(bytes, pk))
        self.veri = Ed25519PublicKey.from_public_bytes(vk)

    def verify(self, signature: bytes, msg: bytes) -> bool:
        """
        Verify whether a given signature is correct for a message.

        :param signature: the given signature
        :param msg: the given message
        """
        try:
            self.veri.verify(signature, msg)
            return True
        except InvalidSignature:
            return False

    def key_to_bin(self) -> bytes:
        """
        Get the string representation of this key.
        """
        return (b"LibNaCLPK:"
                + self.key.public_bytes(Encoding.Raw, PublicFormat.Raw)
                + self.veri.public_bytes(Encoding.Raw, PublicFormat.Raw))

    def get_signature_length(self) -> int:
        """
        Returns the length, in bytes, of each signature made using EC.
        """
        return KEY_LENGTH
