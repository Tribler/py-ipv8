from __future__ import annotations

from binascii import hexlify, unhexlify
from struct import pack, unpack
from typing import cast

from ...identity_formats import Attestation
from ..pengbaorange.boudot import EL, SQR
from ..primitives.boneh import decode, encode
from ..primitives.structs import BonehPrivateKey, BonehPublicKey, ipack, iunpack
from ..primitives.value import FP2Value


def _serialize_fp2value(value: FP2Value) -> bytes:
    """
    Convert an FP2Value to bytes.
    """
    normalized = value.wp_compress()
    return ipack(normalized.a) + ipack(normalized.b)


def _unserialize_fp2value(mod: int, value: bytes) -> tuple[FP2Value, bytes]:
    """
    Decode serialized bytes back into an FP2Value of the given modulus.
    """
    rem = value
    a, rem = iunpack(rem)
    b, rem = iunpack(rem)
    return FP2Value(mod, a, b), rem


class PengBaoCommitment:
    """
    The proof structure that a commitment hides a value within a certain range.
    """

    def __init__(self,  # noqa: PLR0913
                 c: FP2Value,
                 c1: FP2Value,
                 c2: FP2Value,
                 ca: FP2Value,
                 ca1: FP2Value,
                 ca2: FP2Value,
                 ca3: FP2Value,
                 caa: FP2Value) -> None:
        """
        Create a new public proof to check secret range for.
        """
        self.c = c
        self.c1 = c1
        self.c2 = c2
        self.ca = ca
        self.ca1 = ca1
        self.ca2 = ca2
        self.ca3 = ca3
        self.caa = caa

    def serialize(self) -> bytes:
        """
        Convert this commitment to bytes.
        """
        return (ipack(self.c.mod) + _serialize_fp2value(self.c) + _serialize_fp2value(self.c1)
                + _serialize_fp2value(self.c2) + _serialize_fp2value(self.ca) + _serialize_fp2value(self.ca1)
                + _serialize_fp2value(self.ca2) + _serialize_fp2value(self.ca3) + _serialize_fp2value(self.caa))

    @classmethod
    def unserialize(cls: type[PengBaoCommitment], s: bytes) -> tuple[PengBaoCommitment, bytes]:
        """
        Convert bytes to a commitment.
        """
        mod, rem = iunpack(s)
        c, rem = _unserialize_fp2value(mod, rem)
        c1, rem = _unserialize_fp2value(mod, rem)
        c2, rem = _unserialize_fp2value(mod, rem)
        ca, rem = _unserialize_fp2value(mod, rem)
        ca1, rem = _unserialize_fp2value(mod, rem)
        ca2, rem = _unserialize_fp2value(mod, rem)
        ca3, rem = _unserialize_fp2value(mod, rem)
        caa, rem = _unserialize_fp2value(mod, rem)
        return cls(c, c1, c2, ca, ca1, ca2, ca3, caa), rem


class PengBaoCommitmentPrivate:
    """
    Private part of the PengBaoCommitment.
    """

    MSGSPACE: list[int] = list(range(256))

    def __init__(self, m1: int, m2: int, m3: int, r1: int, r2: int, r3: int) -> None:  # noqa: PLR0913
        """
        Private values for to answer challenges for our public range proof.
        """
        self.m1 = m1
        self.m2 = m2
        self.m3 = m3
        self.r1 = r1
        self.r2 = r2
        self.r3 = r3

    def generate_response(self, s: int, t: int) -> tuple[int, int, int, int]:
        """
        Given s and t and our private information, generate the appropriate response.

        The calling function should make sure s and t are large integers (at least larger than 0).

        :param s: the challenge value s
        :type s: int
        :param t: the challenge value t
        :type t: int
        :return: the challenge response
        :rtype: int
        """
        return (s * self.m1 + self.m2 + self.m3,
                self.m1 + t * self.m2 + self.m3,
                s * self.r1 + self.r2 + self.r3,
                self.r1 + t * self.r2 + self.r3)

    def serialize(self) -> bytes:
        """
        Convert this commitment to bytes.
        """
        return ipack(self.m1) + ipack(self.m2) + ipack(self.m3) + ipack(self.r1) + ipack(self.r2) + ipack(self.r3)

    @classmethod
    def unserialize(cls: type[PengBaoCommitmentPrivate], s: bytes) -> tuple[PengBaoCommitmentPrivate, bytes]:
        """
        Convert bytes to a commitment.
        """
        m1, rem = iunpack(s)
        m2, rem = iunpack(rem)
        m3, rem = iunpack(rem)
        r1, rem = iunpack(rem)
        r2, rem = iunpack(rem)
        r3, rem = iunpack(rem)
        return cls(m1, m2, m3, r1, r2, r3), rem

    def encode(self, PK: BonehPublicKey) -> bytes:  # noqa: N803
        """
        Serialize and encode using a given public key.
        """
        serialized = self.serialize()
        hex_serialized = hexlify(serialized)
        serialized_encodings = pack(">B", len(hex_serialized) // 2)
        for i in range(0, len(hex_serialized), 2):
            intval = int(hex_serialized[i:i + 2], 16)
            serialized_encodings += _serialize_fp2value(encode(PK, intval))
        return serialized_encodings

    @classmethod
    def decode(cls: type[PengBaoCommitmentPrivate],
               SK: BonehPrivateKey,  # noqa: N803
               s: bytes) -> PengBaoCommitmentPrivate:
        """
        Decode an encoded PengBaoCommitmentPrivate using a secret key.
        """
        serialized = b""
        count, = unpack(">B", s[0:1])
        rem = s[1:]
        for _ in range(count):
            unpacked, rem = _unserialize_fp2value(SK.g.mod, rem)
            hexed = hex(cast(int, decode(SK, cls.MSGSPACE, unpacked)))[2:]
            if hexed.endswith('L'):
                hexed = hexed[:-1]
            if len(hexed) % 2 == 1:
                hexed = '0' + hexed
            serialized += unhexlify(hexed)
        return cls.unserialize(serialized)[0]


class PengBaoPublicData:
    """
    Public data required to verify a Peng Bao proof.
    """

    def __init__(self,  # noqa: PLR0913
                 PK: BonehPublicKey,  # noqa: N803
                 bitspace: int,
                 commitment: PengBaoCommitment,
                 el: EL,
                 sqr1: SQR,
                 sqr2: SQR) -> None:
        """
        :param PK: the BonehPublicKey of the owner
        :param bitspace: the bitspace for the commitment message
        :param commitment: the range commitment
        :param el: the Boudot equality commitment
        :param sqr1: the first Boudot square commitment
        :param sqr2: the second Boudot square commitment
        """
        self.PK = PK
        self.bitspace = bitspace
        self.commitment = commitment
        self.el = el
        self.sqr1 = sqr1
        self.sqr2 = sqr2

    def check(self,  # noqa: PLR0913
              a: int,
              b: int,
              s: int,
              t: int,
              x: int,
              y: int,
              u: int,
              v: int) -> bool:
        """
        Check whether the given range is correct.
        """
        out = True
        out &= self.el.check(self.PK.g, self.PK.h, self.commitment.c1, self.PK.h, self.commitment.c2,
                             self.commitment.ca)
        out &= self.sqr1.check(self.commitment.ca, self.PK.h, self.commitment.caa)
        out &= self.sqr2.check(self.PK.g, self.PK.h, self.commitment.ca3)
        out &= self.commitment.c1 == self.commitment.c // self.PK.g.intpow(a - 1)
        out &= self.commitment.c2 == self.PK.g.intpow(b + 1) // self.commitment.c
        out &= self.commitment.caa == self.commitment.ca1 * self.commitment.ca2 * self.commitment.ca3
        out &= (self.PK.g.intpow(x) * self.PK.h.intpow(u)) == (self.commitment.ca1.intpow(s) * self.commitment.ca2
                                                               * self.commitment.ca3)
        out &= (self.PK.g.intpow(y) * self.PK.h.intpow(v)) == (self.commitment.ca1 * self.commitment.ca2.intpow(t)
                                                               * self.commitment.ca3)
        out &= x > 0
        out &= y > 0
        return out

    def serialize(self) -> bytes:
        """
        Serialize this Attestation to a string.

        :return: the serialized form of this attestation
        :rtype: str
        """
        return (self.PK.serialize() + ipack(self.bitspace) + self.commitment.serialize() + self.el.serialize()
                + self.sqr1.serialize() + self.sqr2.serialize())

    @classmethod
    def unserialize(cls: type[PengBaoPublicData], s: bytes) -> tuple[PengBaoPublicData, bytes]:
        """
        Given a string, create an Attestation object.

        :param s: the string to unserialize
        :type s: str
        :return: the attestation object
        :rtype: PengBaoPublicData
        """
        rem = s
        pk = cast(BonehPublicKey, BonehPublicKey.unserialize(rem))
        rem = rem[len(pk.serialize()):]
        bitspace, rem = iunpack(rem)
        commitment, rem = PengBaoCommitment.unserialize(rem)
        el, rem = EL.unserialize(rem)
        sqr1, rem = SQR.unserialize(rem)
        sqr2, rem = SQR.unserialize(rem)
        return cls(pk, bitspace, commitment, el, sqr1, sqr2), rem


class PengBaoAttestation(Attestation):
    """
    An attestation for a Peng Bao range proof.
    """

    def __init__(self,
                 publicdata: PengBaoPublicData,
                 privatedata: PengBaoCommitmentPrivate | None,
                 id_format: str | None = None) -> None:
        """
        :type publicdata: PengBaoPublicData
        :type privatedata: PengBaoCommitmentPrivate or None
        """
        super().__init__()
        self.publicdata = publicdata
        self.privatedata = privatedata
        self.id_format = id_format
        self.PK = publicdata.PK

    def serialize(self) -> bytes:
        """
        Serialize this Attestation to a string.

        :return: the serialized form of this attestation
        :rtype: str
        """
        return self.publicdata.serialize()

    def serialize_private(self, PK: BonehPublicKey) -> bytes:  # noqa: N803
        """
        Serialize this Attestation to a string, include shared secrets (not to be published!).

        :param PK: the public key to encode for
        :return: the serialized form of this attestation
        :rtype: str
        """
        assert self.privatedata
        return self.publicdata.serialize() + self.privatedata.encode(PK)

    @classmethod
    def unserialize(cls: type[PengBaoAttestation], s: bytes, id_format: str | None = None) -> PengBaoAttestation:
        """
        Given a string, create an Attestation object.

        :param s: the string to unserialize
        :type s: str
        :param id_format: the identity format
        :type id_format: str
        :return: the attestation object
        :rtype: Attestation
        """
        publicdata, _ = PengBaoPublicData.unserialize(s)
        return cls(publicdata, None, id_format)

    @classmethod
    def unserialize_private(cls: type[PengBaoAttestation],
                            SK: BonehPrivateKey,  # noqa: N803
                            s: bytes,
                            id_format: str | None = None) -> PengBaoAttestation:
        """
        Given a string, create an Attestation object.
        The input contains shared secrets not to be published.

        :param SK: the secret key to decode with
        :param s: the string to unserialize
        :type s: str
        :param id_format: the identity format
        :type id_format: str
        :return: the attestation object
        :rtype: Attestation
        """
        publicdata, rem = PengBaoPublicData.unserialize(s)
        privatedata = PengBaoCommitmentPrivate.decode(SK, rem)

        return cls(publicdata, privatedata, id_format)
