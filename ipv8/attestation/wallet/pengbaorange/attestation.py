from binascii import hexlify
from math import sqrt
from os import urandom

from ..primitives.structs import BonehPublicKey
from .boudot import EL, SQR
from .structs import PengBaoAttestation, PengBaoCommitment, PengBaoCommitmentPrivate, PengBaoPublicData


def _random_number(bytelen: int) -> int:
    """
    Generate a random integer of a given number of bytes.
    """
    return int(hexlify(urandom(bytelen)), 16)


def create_attest_pair(PK: BonehPublicKey,  # noqa: N803
                       value: int,
                       a: int,
                       b: int,
                       bitspace: int) -> PengBaoAttestation:
    """
    Create an proof that a <= value <= b, for a public key's value lying within a certain bitspace.
    """
    bytespace = bitspace // 8
    r = _random_number(bytespace)
    ra = _random_number(bytespace)
    raa = _random_number(bitspace // 16)
    raa = raa * raa

    w = _random_number(bytespace)
    w2 = w * w

    c = PK.g.intpow(value) * PK.h.intpow(r)

    c1 = c // (PK.g.intpow(a - 1))
    c2 = PK.g.intpow(b + 1) // c
    ca = c1.intpow(b - value + 1) * PK.h.intpow(ra)
    caa = ca.intpow(w2) * PK.h.intpow(raa)

    mst = w2 * (value - a + 1) * (b - value + 1)
    m4 = 0
    while not m4:
        m4 = _random_number(bytespace) % (int(sqrt(mst)) - 1)
    m3 = m4 * m4
    m1 = 0
    while not m1:
        m1 = _random_number(bytespace) % (mst - m4)
    m2 = mst - m1 - m3

    rst = w2 * ((b - value + 1) * r + ra) + raa
    r1 = 0
    while not r1:
        r1 = _random_number(bytespace * bytespace) % (rst // 2 - 1)
    r2 = 0
    while not r2:
        r2 = _random_number(bytespace * bytespace) % (rst // 2 - 1)
    r3 = rst - r1 - r2

    ca1 = PK.g.intpow(m1) * PK.h.intpow(r1)
    ca2 = PK.g.intpow(m2) * PK.h.intpow(r2)
    ca3 = caa // (ca1 * ca2)

    el = EL.create(b - value + 1, -r, ra, PK.g, PK.h, c1, PK.h, b, bitspace)
    sqr1 = SQR.create(w, raa, ca, PK.h, b, bitspace)
    sqr2 = SQR.create(m4, r3, PK.g, PK.h, b, bitspace)

    publicdata = PengBaoPublicData(PK, bitspace, PengBaoCommitment(c, c1, c2, ca, ca1, ca2, ca3, caa), el, sqr1, sqr2)
    privatedata = PengBaoCommitmentPrivate(m1, m2, m3, r1, r2, r3)

    return PengBaoAttestation(publicdata, privatedata)
