from __future__ import annotations

from typing import TYPE_CHECKING, cast

from ...identity_formats import Attestation
from ..primitives.structs import BonehPrivateKey, BonehPublicKey, ipack, iunpack
from ..primitives.value import FP2Value

if TYPE_CHECKING:
    from typing_extensions import Self

__all__ = ['BitPairAttestation', 'BonehAttestation']

# ruff: noqa: N803


class BitPairAttestation:
    """
    An attestation of a single bitpair of a larger Attestation.
    """

    def __init__(self, a: FP2Value, b: FP2Value, complement: FP2Value) -> None:
        """
        Create a new bitpair attestation.
        """
        self.a = a
        self.b = b
        self.complement = complement

    def compress(self) -> FP2Value:
        """
        Compress this attestation.
        """
        return self.a * self.b * self.complement

    def serialize(self) -> bytes:
        """
        Convert the attestation to bytes.
        """
        return (ipack(self.a.a) + ipack(self.a.b) + ipack(self.b.a) + ipack(self.b.b)
                + ipack(self.complement.a) + ipack(self.complement.b))

    @classmethod
    def unserialize(cls: type[Self], s: bytes, p: int) -> Self:
        """
        Unserialize using a pre-known modulus p.
        """
        rem = s
        nums: list[int] = []
        while rem and len(nums) < 6:
            unpacked, rem = iunpack(rem)
            nums.append(unpacked)
        inits = [FP2Value(p, nums[0], nums[1]),
                 FP2Value(p, nums[2], nums[3]),
                 FP2Value(p, nums[4], nums[5])]
        return cls(*inits)


class BonehAttestation(Attestation):
    """
    An attestation for a public key of a value consisting of multiple bitpairs.
    """

    def __init__(self, PK: BonehPublicKey, bitpairs: list[BitPairAttestation],
                 id_format: str | None = None) -> None:
        """
        Create a new Boneh-based attestation.
        """
        super().__init__()
        self.bitpairs = bitpairs
        self.PK = PK
        self.id_format = id_format

    def serialize(self) -> bytes:
        """
        Serialize this attestation to bytes.
        """
        out = b''
        out += self.PK.serialize()
        for bitpair in self.bitpairs:
            out += bitpair.serialize()
        return out

    def serialize_private(self, PK: BonehPublicKey) -> bytes:
        """
        Serialize the private part of this attestation.
        """
        return self.serialize()

    @classmethod
    def unserialize(cls: type[Self], s: bytes, id_format: str | None = None) -> Self:
        """
        Unserialize the public format of this attestation.
        """
        pk = cast(BonehPublicKey, BonehPublicKey.unserialize(s))
        bitpairs = []
        rem = s[len(pk.serialize()):]
        while rem:
            attest = BitPairAttestation.unserialize(rem, pk.p)
            bitpairs.append(attest)
            rem = rem[len(attest.serialize()):]
        return cls(pk, bitpairs, id_format)

    @classmethod
    def unserialize_private(cls: type[Self], sk: BonehPrivateKey, s: bytes,  # noqa: ARG003
                            id_format: str | None = None) -> Self:
        """
        Unserialize the private format of this attestation.
        """
        return cls.unserialize(s, id_format)
