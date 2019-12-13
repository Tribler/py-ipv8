import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

import libnacl

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
        tmp_key = self.generate_key(u"curve25519")
        X = tmp_key.key.pk

        return tmp_key, X

    def generate_diffie_shared_secret(self, dh_received, key=None):
        if key is None:
            key = self.key

        tmp_key = self.generate_key(u"curve25519")
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
        hkdf = HKDFExpand(algorithm=hashes.SHA256(), backend=default_backend(), length=40, info=b"key_generation")
        key = hkdf.derive(shared_secret)

        kf = key[:16]
        kb = key[16:32]
        sf = key[32:36]
        sb = key[36:40]
        return [kf, kb, sf, sb, 1, 1]

    def _build_iv(self, salt, salt_explicit):
        assert isinstance(salt, (bytes, str)), type(salt)
        assert isinstance(salt_explicit, int), type(salt_explicit)

        if salt_explicit == 0:
            raise CryptoException("salt_explicit wrapped")

        return salt + str(salt_explicit).encode()

    def get_session_keys(self, keys, direction):
        # increment salt_explicit
        keys[direction + 4] += 1
        return keys[direction], keys[direction + 2], keys[direction + 4]

    def encrypt_str(self, content, key, salt, salt_explicit):
        # return the encrypted content prepended with salt_explicit
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(self._build_iv(salt, salt_explicit), content, None)
        return struct.pack('!q', salt_explicit) + ciphertext

    def decrypt_str(self, content, key, salt):
        # content contains the gcm tag and salt_explicit in plaintext
        if len(content) < 24:
            raise CryptoException("truncated content")

        salt_explicit, = struct.unpack_from('!q', content)
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(self._build_iv(salt, salt_explicit), content[8:], None)
