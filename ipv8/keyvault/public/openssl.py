from __future__ import annotations

from base64 import decodebytes

from ipv8_rust_tunnels import PublicKey as RustPublicKey

from ...keyvault.keys import PublicKey


class OpenSSLPK(PublicKey):
    """
    A pyca implementation of a public key, backwards compatible with Dispersy M2Crypto public keys.
    """

    ec: RustPublicKey

    def __init__(self, keystring: bytes) -> None:
        """
        Create a new M2Crypto public key. Optionally load it from a string representation or
        using a public key.

        :param ec_pub: load the pk from a PubicKey object
        :param keystring: load the pk from this string (see key_to_bin())
        """
        self.ec = RustPublicKey(keystring)

    def pem_to_bin(self, pem: bytes) -> bytes:
        """
        Convert a key in the PEM format into a key in the binary format.
        @note: Encrypted pem's are NOT supported and will silently fail.
        """
        return decodebytes(b"".join(pem.split(b"\n")[1:-2]))

    def key_to_pem(self) -> bytes:
        """
        Convert a key to the PEM format.
        """
        return self.ec.key_to_pem()

    def key_to_bin(self) -> bytes:
        """
        Get the string representation of this key.
        """
        return self.ec.key_to_bin()

    def get_signature_length(self) -> int:
        """
        Returns the length, in bytes, of each signature made using EC.
        """
        return self.ec.get_signature_length()

    def verify(self, signature: bytes, msg: bytes) -> bool:
        """
        Verify whether a given signature is correct for a message.

        :param signature: the given signature
        :param msg: the given message
        """
        return self.ec.verify(signature, msg)

    def get_crypt_pk(self) -> bytes:
        """
        Get the raw X25519 public key bytes for encryption/key exchange.

        :return: The 32-byte public key representation.
        :raises ValueError: If the key does not support X25519 or is in an invalid format.
        """
        return self.ec.get_crypt_pk()

    def curve_name(self) -> str:
        """
        Return the string name of the curve used by this key.
        """
        return self.ec.curve_name()
