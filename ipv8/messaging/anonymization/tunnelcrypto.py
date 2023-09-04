from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import libnacl
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from libnacl.aead import AEAD

from ...keyvault.crypto import ECCrypto, LibNaCLPK
from ...keyvault.private.libnaclkey import LibNaCLSK

if TYPE_CHECKING:
    from ...types import PublicKey


class CryptoException(Exception):
    """
    Exception for when anything goes wrong with sessions, encoding, and decoding.
    """


@dataclass
class SessionKeys:
    """
    Session keys to communicate between hops.
    """

    key_forward: bytes
    key_backward: bytes
    salt_forward: bytes
    salt_backward: bytes
    salt_explicit_forward: int
    salt_explicit_backward: int


class TunnelCrypto(ECCrypto):
    """
    Add Diffie-Hellman key establishment logic to ECCrypto.
    """

    def initialize(self, key: LibNaCLPK) -> None:
        """
        Make this ECCrypto fit for key establishment based on the given public key.
        """
        self.key = key
        assert isinstance(self.key, LibNaCLPK), type(self.key)

    def is_key_compatible(self, key: PublicKey) -> bool:
        """
        Whether the given key is a ``LibNaCLPK`` instance.
        """
        return isinstance(key, LibNaCLPK)

    def generate_diffie_secret(self) -> tuple[LibNaCLSK, LibNaCLPK]:
        """
        Create a a new private-public keypair.
        """
        tmp_key = cast(LibNaCLSK, self.generate_key("curve25519"))
        x = tmp_key.key.pk

        return tmp_key, x

    def generate_diffie_shared_secret(self, dh_received: bytes,
                                      key: LibNaCLPK | None = None) -> tuple[bytes, LibNaCLPK, bytes]:
        """
        Generate the shared secret from the received string and the given key.
        """
        if key is None:
            key = self.key

        tmp_key = cast(LibNaCLSK, self.generate_key("curve25519"))
        shared_secret = (libnacl.crypto_box_beforenm(dh_received, tmp_key.key.sk)
                         + libnacl.crypto_box_beforenm(dh_received, key.key.sk))

        auth = libnacl.crypto_auth(tmp_key.key.pk, shared_secret[:32])
        return shared_secret, tmp_key.key.pk, auth

    def verify_and_generate_shared_secret(self, dh_secret: LibNaCLSK, dh_received: bytes, auth: bytes,
                                          b: bytes) -> bytes:
        """
        Generate the shared secret based on the response to the shared string and our own key.
        """
        shared_secret = (libnacl.crypto_box_beforenm(dh_received, dh_secret.key.sk)
                         + libnacl.crypto_box_beforenm(b, dh_secret.key.sk))
        libnacl.crypto_auth_verify(auth, dh_received, shared_secret[:32])

        return shared_secret

    def generate_session_keys(self, shared_secret: bytes) -> SessionKeys:
        """
        Generate new session keys based on the shared secret.
        """
        hkdf = HKDFExpand(algorithm=hashes.SHA256(), backend=default_backend(), length=72, info=b"key_generation")
        key = hkdf.derive(shared_secret)

        kf = key[:32]
        kb = key[32:64]
        sf = key[64:68]
        sb = key[68:72]

        return SessionKeys(kf, kb, sf, sb, 1, 1)

    def get_session_keys(self, keys: SessionKeys, direction: int) -> tuple[bytes, bytes, int]:
        """
        Get the session keys for forward (0) or backward (1) communication.
        """
        # increment salt_explicit
        if direction == 1:
            keys.salt_explicit_backward += 1
            return keys.key_backward, keys.salt_backward, keys.salt_explicit_backward
        keys.salt_explicit_forward += 1
        return keys.key_forward, keys.salt_forward, keys.salt_explicit_forward

    def encrypt_str(self, content: bytes, key: bytes, salt: bytes, salt_explicit: int) -> bytes:
        """
        Encrypt content using the given key, salt, and incremental session salt.
        """
        # return the encrypted content prepended with salt_explicit
        aead = AEAD(key)
        _, _, ciphertext = aead.encrypt(content, b'',
                                        nonce=salt + struct.pack('!q', salt_explicit),
                                        pack_nonce_aad=False)
        return struct.pack('!q', salt_explicit) + ciphertext

    def decrypt_str(self, content: bytes, key: bytes, salt: bytes) -> bytes:
        """
        Decrypt the given content using a key and salt.
        """
        # content contains the tag and salt_explicit in plaintext
        if len(content) < 24:
            msg = "truncated content"
            raise CryptoException(msg)

        aead = AEAD(key)
        return aead.decrypt(salt + content, 0)
