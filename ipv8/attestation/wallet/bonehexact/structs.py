from ..primitives.structs import BonehPublicKey, ipack, iunpack
from ..primitives.value import FP2Value
from ...identity_formats import Attestation

__all__ = ['BitPairAttestation', 'BonehAttestation']


class BitPairAttestation(object):
    """
    An attestation of a single bitpair of a larger Attestation.
    """

    def __init__(self, a, b, complement):
        self.a = a
        self.b = b
        self.complement = complement

    def compress(self):
        return self.a * self.b * self.complement

    def serialize(self):
        return (ipack(self.a.a) + ipack(self.a.b) + ipack(self.b.a) + ipack(self.b.b)
                + ipack(self.complement.a) + ipack(self.complement.b))

    @classmethod
    def unserialize(cls, s, p):
        rem = s
        nums = []
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

    def __init__(self, PK, bitpairs, id_format=None):
        super(BonehAttestation, self).__init__()
        self.bitpairs = bitpairs
        self.PK = PK
        self.id_format = id_format

    def serialize(self):
        out = b''
        out += self.PK.serialize()
        for bitpair in self.bitpairs:
            out += bitpair.serialize()
        return out

    def serialize_private(self, PK):
        return self.serialize()

    @classmethod
    def unserialize(cls, s, id_format=None):
        PK = BonehPublicKey.unserialize(s)
        bitpairs = []
        rem = s[len(PK.serialize()):]
        while rem:
            attest = BitPairAttestation.unserialize(rem, PK.p)
            bitpairs.append(attest)
            rem = rem[len(attest.serialize()):]
        return cls(PK, bitpairs, id_format)

    @classmethod
    def unserialize_private(cls, SK, s, id_format=None):
        return cls.unserialize(s, id_format)
