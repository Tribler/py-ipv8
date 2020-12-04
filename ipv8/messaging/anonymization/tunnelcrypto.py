import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

import libnacl
from libnacl.aead import AEAD

from ...keyvault.crypto import ECCrypto, LibNaCLPK


class CryptoException(Exception):
    pass


class TunnelCrypto(ECCrypto):

    def initialize(self, key):
        self.key = key
        assert isinstance(self.key, LibNaCLPK), type(self.key)

    def is_key_compatible(self, key):
        return isinstance(key, LibNaCLPK)

    def generate_diffie_secret(self):
        tmp_key = self.generate_key("curve25519")
        X = tmp_key.key.pk

        return tmp_key, X

    def generate_diffie_shared_secret(self, dh_received, key=None):
        if key is None:
            key = self.key

        tmp_key = self.generate_key("curve25519")
        y = tmp_key.key.sk
        Y = tmp_key.key.pk
        shared_secret = libnacl.crypto_box_beforenm(dh_received, y) + libnacl.crypto_box_beforenm(dh_received, key.key.sk)

        AUTH = libnacl.crypto_auth(Y, shared_secret[:32])
        return shared_secret, Y, AUTH

    def verify_and_generate_shared_secret(self, dh_secret, dh_received, auth, B):
        shared_secret = libnacl.crypto_box_beforenm(dh_received, dh_secret.key.sk) + libnacl.crypto_box_beforenm(B, dh_secret.key.sk)
        libnacl.crypto_auth_verify(auth, dh_received, shared_secret[:32])

        return shared_secret

    def generate_session_keys(self, shared_secret):
        hkdf = HKDFExpand(algorithm=hashes.SHA256(), backend=default_backend(), length=72, info=b"key_generation")
        key = hkdf.derive(shared_secret)

        kf = key[:32]
        kb = key[32:64]
        sf = key[64:68]
        sb = key[68:72]
        return [kf, kb, sf, sb, 1, 1]

    def get_session_keys(self, keys, direction):
        # increment salt_explicit
        keys[direction + 4] += 1
        return keys[direction], keys[direction + 2], keys[direction + 4]

    def encrypt_str(self, content, key, salt, salt_explicit):
        # return the encrypted content prepended with salt_explicit
        aead = AEAD(key)
        _, _, ciphertext = aead.encrypt(content, b'',
                                        nonce=salt + struct.pack('!q', salt_explicit),
                                        pack_nonce_aad=False)
        return struct.pack('!q', salt_explicit) + ciphertext

    def decrypt_str(self, content, key, salt):
        # content contains the tag and salt_explicit in plaintext
        if len(content) < 24:
            raise CryptoException("truncated content")

        aead = AEAD(key)
        return aead.decrypt(salt + content, 0)
