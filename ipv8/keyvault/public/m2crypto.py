from base64 import decodebytes, encodebytes
from binascii import hexlify
from math import ceil

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .. import NEW_CRYPTOGRAPHY_SIGN_VERSION
from ...keyvault.keys import PublicKey


class M2CryptoPK(PublicKey):

    def __init__(self, ec_pub=None, keystring=None):
        """
        Create a new M2Crypto public key. Optionally load it from a string representation or
        using a public key.

        :param ec_pub: load the pk from a PubicKey object
        :param keystring: load the pk from this string (see key_to_bin())
        """
        if ec_pub:
            self.ec = ec_pub
        elif keystring:
            self.ec = self.key_from_pem(b"-----BEGIN PUBLIC KEY-----\n%s-----END PUBLIC KEY-----\n" %
                                        encodebytes(keystring))

    def pem_to_bin(self, pem):
        """
        Convert a key in the PEM format into a key in the binary format.
        @note: Encrypted pem's are NOT supported and will silently fail.
        """
        return decodebytes(b"".join(pem.split(b"\n")[1:-2]))

    def key_to_pem(self):
        "Convert a key to the PEM format."
        return self.ec.public_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def key_from_pem(self, pem):
        "Get the EC from a public PEM."
        return serialization.load_pem_public_key(pem, backend=default_backend())

    def key_to_bin(self):
        """
        Get the string representation of this key.
        """
        return self.pem_to_bin(self.key_to_pem())

    def get_signature_length(self):
        """
        Returns the length, in bytes, of each signature made using EC.
        """
        return int(ceil(self.ec.curve.key_size / 8.0)) * 2

    def verify(self, signature, msg):
        """
        Verify whether a given signature is correct for a message.

        :param signature: the given signature
        :param msg: the given message
        """
        length = len(signature) // 2
        r = signature[:length]
        # remove all "\x00" prefixes
        while r and r[0:1] == "\x00":
            r = r[1:]
        # prepend "\x00" when the most significant bit is set
        if ord(r[0:1]) & 128:
            r = "\x00" + r

        s = signature[length:]
        # remove all "\x00" prefixes
        while s and s[0:1] == "\x00":
            s = s[1:]
        # prepend "\x00" when the most significant bit is set
        if ord(s[0:1]) & 128:
            s = "\x00" + s
        # turn back into int
        r = int(hexlify(r), 16)
        s = int(hexlify(s), 16)
        # verify
        try:
            if NEW_CRYPTOGRAPHY_SIGN_VERSION:
                self.ec.verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA1()))
            else:
                self.ec.verifier(encode_dss_signature(r, s), ec.ECDSA(hashes.SHA1()))
            return True
        except InvalidSignature:
            return False
