"""
Implementation of proofs for checking commitment equality and if a commitment is a square ("Efficient Proofs that a
Committed NumberLies in an Interval" by F. Boudot).

Modified for use with range proofs ("An efficient range proof scheme." by K. Peng and F. Bao).
"""
# ruff: noqa: N806

from __future__ import annotations

from binascii import hexlify
from math import ceil, log
from os import urandom
from struct import pack, unpack
from typing import Iterator

from ..primitives.attestation import sha256_as_int
from ..primitives.structs import ipack, iunpack
from ..primitives.value import FP2Value


def secure_randint(nmin: int, nmax: int) -> int:
    """
    Generate a secure random integer.
    """
    normalized_range = nmax - nmin
    n = int(ceil(log(normalized_range, 2) / 8.0))
    rbytes_int = int(hexlify(urandom(n)), 16)
    return nmin + (rbytes_int % normalized_range)


def _sipack(*n: int) -> bytes:
    """
    Pack a list of up to 8 ints to a bytes string, prepended with a byte for which each bit specifies if the packed
    int was negative.
    """
    if len(n) > 8:
        msg = "More than 8 values specified to _sipack"
        raise RuntimeError(msg)
    sign_byte = 0
    packed = b''
    for i in n:
        sign_byte = sign_byte << 1
        sign_byte |= 1 if i < 0 else 0
        packed = ipack(-i if i < 0 else i) + packed
    return pack(">B", sign_byte) + packed


def _siunpack(buf: bytes, amount: int) -> tuple[Iterator[int], bytes]:
    """
    Unpack a given number of integer values from a buffer, packed with ``_sipack()``.
    """
    rem = buf[1:]
    nums: list[int] = []
    sign_byte, = unpack(">B", buf[0:1])
    while rem and len(nums) < amount:
        unpacked, rem = iunpack(rem)
        negative = sign_byte & 0x01
        sign_byte = sign_byte >> 1
        nums.append(-unpacked if negative else unpacked)
    return reversed(nums), rem


class EL:
    """
    Proof that two commitments hide the same secret.
    """

    def __init__(self, c: int, D: int, D1: int, D2: int) -> None:  # noqa: N803
        """
        Create a new public proof to check secret equivalence for.

        See equation (3) of "An efficient range proof scheme." by K. Peng and F. Bao.
        """
        self.c = c
        self.D = D
        self.D1 = D1
        self.D2 = D2

    @classmethod
    def create(cls: type[EL], x: int, r1: int, r2: int,  # noqa: PLR0913
               g1: FP2Value, h1: FP2Value, g2: FP2Value, h2: FP2Value, b: int,
               bitspace: int, t: int = 80, l: int = 40) -> EL:
        """
        Create a new commitment that allows one to prove knowledge of secret integers x, r1 and r2.
        """
        maxrange_w = 2 ^ (l + t) * b - 1
        maxrange_n = 2 ^ (l + t + bitspace) * g1.mod - 1
        w = secure_randint(1, maxrange_w)
        n1 = secure_randint(1, maxrange_n)
        n2 = secure_randint(1, maxrange_n)
        W1 = g1.intpow(w) * h1.intpow(n1)
        W2 = g2.intpow(w) * h2.intpow(n2)
        cW1 = (W1.wp_nominator() * W1.wp_denom_inverse()).normalize()
        cW2 = (W2.wp_nominator() * W2.wp_denom_inverse()).normalize()

        c = sha256_as_int(str(cW1.a).encode('utf-8') + str(cW1.b).encode('utf-8')
                          + str(cW2.a).encode('utf-8') + str(cW2.b).encode('utf-8'))
        D = w + c * x
        D1 = n1 + c * r1
        D2 = n2 + c * r2
        return cls(c, D, D1, D2)

    def check(self,  # noqa: PLR0913
              g1: FP2Value,
              h1: FP2Value,
              g2: FP2Value,
              h2: FP2Value,
              y1: FP2Value,
              y2: FP2Value) -> bool:
        """
        Check for equality with another commitment.
        """
        cW1 = g1.intpow(self.D) * h1.intpow(self.D1) * y1.intpow(-self.c)
        cW2 = g2.intpow(self.D) * h2.intpow(self.D2) * y2.intpow(-self.c)
        cW1 = (cW1.wp_nominator() * cW1.wp_denom_inverse()).normalize()
        cW2 = (cW2.wp_nominator() * cW2.wp_denom_inverse()).normalize()

        return self.c == sha256_as_int(str(cW1.a).encode('utf-8') + str(cW1.b).encode('utf-8')
                                       + str(cW2.a).encode('utf-8') + str(cW2.b).encode('utf-8'))

    def serialize(self) -> bytes:
        """
        Convert this commitment to bytes.
        """
        return _sipack(self.c, self.D, self.D1, self.D2)

    @classmethod
    def unserialize(cls: type[EL], s: bytes) -> tuple[EL, bytes]:
        """
        Convert bytes to a commitment.
        """
        unpacked, rem = _siunpack(s, 4)
        return cls(*unpacked), rem

    def __eq__(self, other: object) -> bool:
        """
        Check if this object is equal to another object.
        """
        if not isinstance(other, EL):
            return False
        return (self.c == other.c) and (self.D == other.D) and (self.D1 == other.D1) and (self.D2 == other.D2)

    def __hash__(self) -> int:
        """
        Get the hash of this object. Always 6976 to enforce a "heavy" equality check.
        """
        return 6976

    def __str__(self) -> str:
        """
        Stringify this EL for printing.
        """
        return 'EL<%d,%d,%d,%d>' % (self.c, self.D, self.D1, self.D2)


class SQR:
    """
    Proof that a committed number is a square.
    """

    def __init__(self, F: FP2Value, el: EL) -> None:  # noqa: N803
        """
        Create a new public proof to check secret "squareness" for.
        """
        self.F = F
        self.el = el

    @classmethod
    def create(cls: type[SQR],  # noqa: PLR0913
               x: int,
               r1: int,
               g: FP2Value,
               h: FP2Value,
               b: int,
               bitspace: int) -> SQR:
        """
        Create a new commitment that allows one to prove that the committed integer x is a square.
        """
        r2 = secure_randint(-2 ^ bitspace * g.mod + 1, 2 ^ bitspace * g.mod - 1)
        F = g.intpow(x) * h.intpow(r2)
        r3 = r1 - r2 * x
        return cls(F, EL.create(x, r2, r3, g, h, F, h, b, bitspace))

    def check(self, g: FP2Value, h: FP2Value, y: FP2Value) -> bool:
        """
        Check for a committed square.
        """
        return self.el.check(g, h, self.F, h, self.F, y)

    def serialize(self) -> bytes:
        """
        Convert this commitment to bytes.
        """
        min_f = self.F.wp_compress()
        return ipack(min_f.mod) + ipack(min_f.a) + ipack(min_f.b) + self.el.serialize()

    @classmethod
    def unserialize(cls: type[SQR], s: bytes) -> tuple[SQR, bytes]:
        """
        Convert bytes to a commitment.
        """
        rem = s
        mod, rem = iunpack(rem)
        Fa, rem = iunpack(rem)
        Fb, rem = iunpack(rem)
        el, rem = EL.unserialize(rem)
        return cls(FP2Value(mod, Fa, Fb), el), rem

    def __eq__(self, other: object) -> bool:
        """
        Check if this object is equal to another object.
        """
        if not isinstance(other, SQR):
            return False
        return (self.F == other.F) and (self.el == other.el)

    def __hash__(self) -> int:
        """
        Get the hash of this object. Always 838182 to enforce a "heavy" equality check.
        """
        return 838182

    def __str__(self) -> str:
        """
        Stringify this EL for printing.
        """
        return f'SQR<{self.F!s},{self.el!s}>'
