"""
Implementation of proofs for checking commitment equality and if a commitment is a square ("Efficient Proofs that a
Committed NumberLies in an Interval" by F. Boudot).

Modified for use with range proofs ("An efficient range proof scheme." by K. Peng and F. Bao).
"""
from binascii import hexlify
from math import ceil, log
from os import urandom
from struct import pack, unpack

from ..primitives.attestation import sha256_as_int
from ..primitives.structs import ipack, iunpack
from ..primitives.value import FP2Value


def secure_randint(nmin, nmax):
    normalized_range = nmax - nmin
    n = int(ceil(log(normalized_range, 2) / 8.0))
    rbytes_int = int(hexlify(urandom(n)), 16)
    return nmin + (rbytes_int % normalized_range)


def _sipack(*n):
    if len(n) > 8:
        raise RuntimeError("More than 8 values specified to _sipack")
    sign_byte = 0
    packed = b''
    for i in n:
        sign_byte = sign_byte << 1
        sign_byte |= 1 if i < 0 else 0
        packed = ipack(-i if i < 0 else i) + packed
    return pack(">B", sign_byte) + packed


def _siunpack(buf, amount):
    rem = buf[1:]
    nums = []
    sign_byte, = unpack(">B", buf[0:1])
    while rem and len(nums) < amount:
        unpacked, rem = iunpack(rem)
        negative = sign_byte & 0x01
        sign_byte = sign_byte >> 1
        nums.append(-unpacked if negative else unpacked)
    return reversed(nums), rem


class EL(object):

    def __init__(self, c, D, D1, D2):
        self.c = c
        self.D = D
        self.D1 = D1
        self.D2 = D2

    @classmethod
    def create(cls, x, r1, r2, g1, h1, g2, h2, b, bitspace, t=80, l=40):  # pylint: disable=R0913,R0914
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

    def check(self, g1, h1, g2, h2, y1, y2):
        cW1 = g1.intpow(self.D) * h1.intpow(self.D1) * y1.intpow(-self.c)
        cW2 = g2.intpow(self.D) * h2.intpow(self.D2) * y2.intpow(-self.c)
        cW1 = (cW1.wp_nominator() * cW1.wp_denom_inverse()).normalize()
        cW2 = (cW2.wp_nominator() * cW2.wp_denom_inverse()).normalize()

        return self.c == sha256_as_int(str(cW1.a).encode('utf-8') + str(cW1.b).encode('utf-8')
                                       + str(cW2.a).encode('utf-8') + str(cW2.b).encode('utf-8'))

    def serialize(self):
        return _sipack(self.c, self.D, self.D1, self.D2)

    @classmethod
    def unserialize(cls, s):
        unpacked, rem = _siunpack(s, 4)
        return cls(*unpacked), rem

    def __eq__(self, other):
        if not isinstance(other, EL):
            return False
        return (self.c == other.c) and (self.D == other.D) and (self.D1 == other.D1) and (self.D2 == other.D2)

    def __hash__(self):
        return 6976

    def __str__(self):
        return 'EL<%d,%d,%d,%d>' % (self.c, self.D, self.D1, self.D2)


class SQR(object):

    def __init__(self, F, el):
        self.F = F
        self.el = el

    @classmethod
    def create(cls, x, r1, g, h, b, bitspace):
        r2 = secure_randint(-2 ^ bitspace * g.mod + 1, 2 ^ bitspace * g.mod - 1)
        F = g.intpow(x) * h.intpow(r2)
        r3 = r1 - r2 * x
        return cls(F, EL.create(x, r2, r3, g, h, F, h, b, bitspace))

    def check(self, g, h, y):
        return self.el.check(g, h, self.F, h, self.F, y)

    def serialize(self):
        min_f = self.F.wp_compress()
        return ipack(min_f.mod) + ipack(min_f.a) + ipack(min_f.b) + self.el.serialize()

    @classmethod
    def unserialize(cls, s):
        rem = s
        mod, rem = iunpack(rem)
        Fa, rem = iunpack(rem)
        Fb, rem = iunpack(rem)
        el, rem = EL.unserialize(rem)
        return cls(FP2Value(mod, Fa, Fb), el), rem

    def __eq__(self, other):
        if not isinstance(other, SQR):
            return False
        return (self.F == other.F) and (self.el == other.el)

    def __hash__(self):
        return 838182

    def __str__(self):
        return 'SQR<%s,%s>' % (str(self.F), str(self.el))
