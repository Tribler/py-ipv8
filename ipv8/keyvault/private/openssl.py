from __future__ import annotations

from ipv8_rust_tunnels import PrivateKey as RustPrivateKey

from ...keyvault.keys import PrivateKey
from ...keyvault.public.openssl import OpenSSLPK


class OpenSSLSK(PrivateKey, OpenSSLPK):
    """
    A pyca implementation of a secret key, backwards compatible with Dispersy M2Crypto secret keys.
    """

    ec: RustPrivateKey  # type: ignore[assignment]

    def __init__(self, keystring: bytes | RustPrivateKey) -> None:
        """
        Create a new M2Crypto secret key. Optionally load it from a string representation (in a file)
        or generate it using some curve.

        :param keys: the string to load the key from, or an _rust.PrivateKey object
        """
        if isinstance(keystring, RustPrivateKey):
            self.ec = keystring
        else:
            self.ec = RustPrivateKey(keystring)

    def pub(self) -> OpenSSLPK:
        """
        Get the public key for this secret key.
        """
        return OpenSSLPK(keystring=self.ec.pub().key_to_bin())

    def has_secret_key(self) -> bool:
        """
        Is this is a secret key (yes it is)?
        """
        return True

    def key_to_pem(self) -> bytes:
        """
        Convert a key to the PEM format.
        """
        return self.ec.key_to_pem()

    def signature(self, msg: bytes) -> bytes:
        """
        Create a signature for a message in a backwards compatible fashion.

        :param msg: the message to sign
        """
        return self.ec.signature(msg)

    @staticmethod
    def generate(curve_name: str) -> PrivateKey:
        """
        Generate a new keypair. Supporting 'ed25519' (dual-key LibNaCLSK)
         or standard OpenSSL curve names (e.g., 'secp256k1').

        :param curve_name: Name of the elliptic curve to use.
        :return: A new PrivateKey instance.
        :raises ValueError: If generation fails or the curve is unknown.
        """
        return OpenSSLSK(RustPrivateKey.generate(curve_name))

    def diffie_hellman(self, peer_pub_bytes: bytes) -> bytes:
        """
        Perform a Diffie-Hellman key exchange with a peer's public key.

        :param peer_pub_bytes: The raw X25519 public key bytes from the peer.
        :return: The resulting shared secret bytes.
        :raises ValueError: If the exchange fails due to invalid peer bytes or incompatible curves.
        """
        return self.ec.diffie_hellman(peer_pub_bytes)

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
