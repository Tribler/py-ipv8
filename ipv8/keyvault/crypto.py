from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve

from ..keyvault.keys import Key
from .private.libnaclkey import LibNaCLSK
from .private.m2crypto import M2CryptoSK
from .public.libnaclkey import LibNaCLPK
from .public.m2crypto import M2CryptoPK

if TYPE_CHECKING:
    from ..keyvault.keys import PrivateKey, PublicKey


class SECT163K1(EllipticCurve):
    """
    Deprecated SECT163K1 curve.
    """

    name = "sect163k1"
    key_size = 163
    group_order = 0x4000000000000000000020108A2E0CC0D99F8A5EF


class SECT233K1(EllipticCurve):
    """
    Deprecated SECT233K1 curve.
    """

    name = "sect233k1"
    key_size = 233
    group_order = 0x8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF


class SECT409K1(EllipticCurve):
    """
    Deprecated SECT409K1 curve.
    """

    name = "sect409k1"
    key_size = 409
    group_order = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F83B2D4EA20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF


class SECT571R1(EllipticCurve):
    """
    Deprecated SECT571R1 curve.
    """

    name = "sect571r1"
    key_size = 570
    group_order = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE661CE18FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47


# We want to provide a few default curves.  We will change these curves as new become available and
# old ones to small to provide sufficient security.
_CURVES: dict[str, tuple[EllipticCurve | None, str]] = {
    "very-low": (SECT163K1(), "M2Crypto"),
    "low": (SECT233K1(), "M2Crypto"),
    "medium": (SECT409K1(), "M2Crypto"),
    "high": (SECT571R1(), "M2Crypto"),
    "curve25519": (None, "libnacl")
}

logger = logging.getLogger(__name__)


class ECCrypto:
    """
    A crypto object which provides a layer between Dispersy and low level eccrypographic features.

    Most methods are implemented by:
        :author: Boudewijn Schoon
        :organization: Technical University Delft
        :contact: dispersy@frayja.com

    However since then, most functionality was completely rewritten by:
        :author: Niels Zeilemaker
    """

    @property
    def security_levels(self) -> list[str]:
        """
        Returns the names of all available curves.
        """
        return list(_CURVES.keys())

    def generate_key(self, security_level: str) -> PrivateKey:
        """
        Generate a new Elliptic Curve object with a new public / private key pair.

        Security can be "low", "medium", or "high" depending on how secure you need your Elliptic
        Curve to be.  Currently, these values translate into:
            - very-low: NID_sect163k1  ~42 byte signatures
            - low:      NID_sect233k1  ~60 byte signatures
            - medium:   NID_sect409k1 ~104 byte signatures
            - high:     NID_sect571r1 ~144 byte signatures

        Besides these predefined curves, all other curves provided by M2Crypto are also available.  For
        a full list of available curves, see ec_get_curves().

        :param security_level: Level of security {"very-low", "low", "medium", or "high"}.
        :type security_level: unicode
        """
        if security_level in _CURVES:
            curve = _CURVES[security_level]
            if curve[1] == "M2Crypto":
                return M2CryptoSK(curve[0])

            if curve[1] == "libnacl":
                return LibNaCLSK()

        msg = f"Illegal curve for key generation: {security_level}"
        raise RuntimeError(msg)

    def key_to_bin(self, ec_key: Key) -> bytes:
        """
        Convert the key to a binary format.
        """
        assert isinstance(ec_key, Key), ec_key
        return ec_key.key_to_bin()

    def key_to_hash(self, ec_key: Key) -> bytes:
        """
        Get a hash representation from a key.
        """
        assert isinstance(ec_key, Key), ec_key
        return ec_key.key_to_hash()

    def is_valid_private_bin(self, string: bytes) -> bool:
        """
        Returns True if the input is a valid public/private keypair stored in a binary format.
        """
        try:
            self.key_from_private_bin(string)
        except Exception:
            return False
        return True

    def is_valid_public_bin(self, string: bytes) -> bool:
        """
        Returns True if the input is a valid public key.
        """
        try:
            self.key_from_public_bin(string)
        except Exception:
            return False
        return True

    def key_from_private_bin(self, string: bytes) -> PrivateKey:
        """
        Get the EC from a public/private keypair stored in a binary format.
        """
        if string.startswith(b"LibNaCLSK:"):
            return LibNaCLSK(string[10:])
        return M2CryptoSK(keystring=string)

    def key_from_public_bin(self, string: bytes) -> PublicKey:
        """
        Get the EC from a public key in binary format.
        """
        if string.startswith(b"LibNaCLPK:"):
            return LibNaCLPK(string[10:])
        return M2CryptoPK(keystring=string)

    def get_signature_length(self, ec_key: PublicKey) -> int:
        """
        Returns the length, in bytes, of each signature made using EC.
        """
        assert isinstance(ec_key, Key), ec_key
        return ec_key.get_signature_length()

    def create_signature(self, ec_key: PrivateKey, data: bytes) -> bytes:
        """
        Returns the signature of DIGEST made using EC.
        """
        assert isinstance(ec_key, Key), ec_key
        assert isinstance(data, (bytes, str)), type(data)
        return ec_key.signature(data)

    def is_valid_signature(self, ec_key: PublicKey, data: bytes, signature: bytes) -> bool:
        """
        Returns True when SIGNATURE matches the DIGEST made using EC.
        """
        assert isinstance(ec_key, Key), ec_key
        assert isinstance(data, (bytes, str)), type(data)
        assert isinstance(signature, (bytes, str)), type(signature)

        try:
            return ec_key.verify(signature, data)
        except Exception:
            return False


# ECCrypto should be stateless.
# Therefore, we can expose a global singleton for efficiency.
# If you do need a ECCrypto with a state, be sure to use your own instance.
default_eccrypto = ECCrypto()
