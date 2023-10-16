from binascii import hexlify
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from ...keyvault.keys import PrivateKey
from ..public.cryptography25519 import KEY_LENGTH, Cryptography25519PK


class Cryptography25519SK(PrivateKey, Cryptography25519PK):
    """
    A fallback implementation for LibNaCL secret keys.
    """

    def __init__(self, binarykey: bytes = b"") -> None:
        """
        Create a new LibNaCL secret key. Optionally load it from a string representation.
        Otherwise, generate it from the 25519 curve.

        :param binarykey: load the sk from this string (see key_to_bin())
        """
        # Load the key, if specified
        if binarykey:
            crypt, seed = (binarykey[:KEY_LENGTH], binarykey[KEY_LENGTH: KEY_LENGTH * 2])
            key = X25519PrivateKey.from_private_bytes(crypt)
            self.vk = Ed25519PrivateKey.from_private_bytes(seed)
        else:
            key = X25519PrivateKey.generate()
            self.vk = Ed25519PrivateKey.generate()
        hex_vk = hexlify(self.vk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

        super().__init__(pk=key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), hex_vk=hex_vk)
        self.key = key  # type: ignore[assignment]

    def pub(self) -> Cryptography25519PK:
        """
        Get the public key for this secret key.
        """
        return Cryptography25519PK(pk=cast(X25519PrivateKey, self.key).public_key().public_bytes(Encoding.Raw,
                                                                                                 PublicFormat.Raw),
                                   hex_vk=hexlify(self.veri.public_bytes(Encoding.Raw, PublicFormat.Raw)))

    def signature(self, msg: bytes) -> bytes:
        """
        Create a signature for a message.

        :param msg: the message to sign
        :return: the signature for the message
        """
        return self.vk.sign(msg)

    def key_to_bin(self) -> bytes:
        """
        Get the string representation of this key.
        """
        return (b"LibNaCLSK:"
                + cast(X25519PrivateKey, self.key).private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
                + self.vk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
