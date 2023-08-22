from __future__ import annotations

from base64 import decodebytes, encodebytes
from binascii import hexlify
from math import ceil
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ...keyvault.keys import PublicKey


class M2CryptoPK(PublicKey):
    """
    A pyca implementation of a public key, backwards compatible with Dispersy M2Crypto public keys.
    """

    def __init__(self, ec_pub: EllipticCurvePrivateKey | EllipticCurvePublicKey | None = None,
                 keystring: bytes | None = None) -> None:
        """
        Create a new M2Crypto public key. Optionally load it from a string representation or
        using a public key.

        :param ec_pub: load the pk from a PubicKey object
        :param keystring: load the pk from this string (see key_to_bin())
        """
        if ec_pub:
            self.ec = ec_pub
        elif keystring:
            self.ec = self.key_from_pem(b"-----BEGIN PUBLIC KEY-----\n"
                                        + encodebytes(keystring)
                                        + b"-----END PUBLIC KEY-----\n")

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
        pub = self.ec.public_key() if isinstance(self.ec, EllipticCurvePrivateKey) else self.ec
        return pub.public_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def key_from_pem(self, pem: bytes) -> EllipticCurvePrivateKey | EllipticCurvePublicKey:
        """
        Get the EC from a public PEM.
        """
        return cast(EllipticCurvePublicKey, serialization.load_pem_public_key(pem, backend=default_backend()))

    def key_to_bin(self) -> bytes:
        """
        Get the string representation of this key.
        """
        return self.pem_to_bin(self.key_to_pem())

    def get_signature_length(self) -> int:
        """
        Returns the length, in bytes, of each signature made using EC.
        """
        return int(ceil(self.ec.curve.key_size / 8.0)) * 2

    def verify(self, signature: bytes, msg: bytes) -> bool:
        """
        Verify whether a given signature is correct for a message.

        :param signature: the given signature
        :param msg: the given message
        """
        length = len(signature) // 2
        r = signature[:length].lstrip(b"\x00")  # remove all "\x00" prefixes
        # prepend "\x00" when the most significant bit is set
        if r[0] & 128:
            r = b"\x00" + r

        s = signature[length:].lstrip(b"\x00")  # remove all "\x00" prefixes
        # prepend "\x00" when the most significant bit is set
        if s[0] & 128:
            s = b"\x00" + s
        # turn back into int
        ri = int(hexlify(r), 16)
        si = int(hexlify(s), 16)
        # verify
        try:
            pub = cast(M2CryptoPK, self.pub())
            pub_ec = cast(EllipticCurvePublicKey, pub.ec)
            pub_ec.verify(encode_dss_signature(ri, si), msg, ec.ECDSA(hashes.SHA1()))
            return True
        except InvalidSignature:
            return False
