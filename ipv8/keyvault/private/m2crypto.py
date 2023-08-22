from __future__ import annotations

from base64 import encodebytes
from binascii import unhexlify
from typing import TYPE_CHECKING, cast

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from ...keyvault.keys import PrivateKey
from ...keyvault.public.m2crypto import M2CryptoPK

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve


class M2CryptoSK(PrivateKey, M2CryptoPK):
    """
    A pyca implementation of a secret key, backwards compatible with Dispersy M2Crypto secret keys.
    """

    def __init__(self, curve: EllipticCurve | None = None, keystring: bytes | None = None,
                 filename: str | None = None) -> None:
        """
        Create a new M2Crypto secret key. Optionally load it from a string representation (in a file)
        or generate it using some curve.

        :param curve: the EllipticCurve object specifying the curve
        :param keystring: the string to load the key from
        :param filename: the filename to load the key from
        """
        if curve:
            super().__init__(ec_pub=ec.generate_private_key(curve, default_backend()))

        elif keystring:
            super().__init__(ec_pub=self.key_from_pem(b"-----BEGIN EC PRIVATE KEY-----\n"
                                                      + encodebytes(keystring)
                                                      + b"-----END EC PRIVATE KEY-----\n"))

        elif filename:
            with open(filename, 'rb') as keyfile:
                super().__init__(self.key_from_pem(keyfile.read()))

    def pub(self) -> M2CryptoPK:
        """
        Get the public key for this secret key.
        """
        return M2CryptoPK(ec_pub=cast(EllipticCurvePrivateKey, self.ec).public_key())

    def has_secret_key(self) -> bool:
        """
        Is this is a secret key (yes it is)?
        """
        return True

    def key_to_pem(self) -> bytes:
        """
        Convert a key to the PEM format.
        """
        return cast(EllipticCurvePrivateKey, self.ec).private_bytes(serialization.Encoding.PEM,
                                                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                                                    serialization.NoEncryption())

    def key_from_pem(self, pem: bytes) -> EllipticCurvePrivateKey:
        """
        Load a key from a pem certificate.

        :param pem: the PEM formatted private key
        """
        return cast(EllipticCurvePrivateKey,
                    serialization.load_pem_private_key(pem, password=None, backend=default_backend()))

    def signature(self, msg: bytes) -> bytes:
        """
        Create a signature for a message in a backwards compatible fashion.

        :param msg: the message to sign
        """
        signature = cast(EllipticCurvePrivateKey, self.ec).sign(msg, ec.ECDSA(hashes.SHA1()))
        # Decode the DSS r and s variables from the pyca signature
        # We are going to turn these longs into (binary) string format
        r, s = decode_dss_signature(signature)
        # Convert the r and s to a valid hex representation
        rh = hex(r).rstrip("L").lstrip("0x") or "0"
        sh = hex(s).rstrip("L").lstrip("0x") or "0"
        # We want bytes: one byte is two nibbles:
        # Prefix with a 0 if the result is of odd length
        if len(rh) % 2 == 1:
            rh = "0" + rh
        if len(sh) % 2 == 1:
            sh = "0" + sh
        # Now we can turn this into a binary string
        rb = unhexlify(rh)
        sb = unhexlify(sh)
        key_len = self.get_signature_length() // 2
        # For easy decoding, prepend 0 to r and s until they are of >equal length<
        return b"".join((b"\x00" * (key_len - len(rb)), rb, b"\x00" * (key_len - len(sb)), sb))
