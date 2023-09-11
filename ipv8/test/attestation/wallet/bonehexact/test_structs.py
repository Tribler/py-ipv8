from .....attestation.wallet.bonehexact.structs import BitPairAttestation, BonehAttestation
from .....attestation.wallet.primitives.structs import BonehPrivateKey, BonehPublicKey, pack_pair, unpack_pair
from .....attestation.wallet.primitives.value import FP2Value
from ....base import TestBase


class TestStructs(TestBase):
    """
    Tests related to boneh attestation structs.
    """

    def test_pack_pair(self) -> None:
        """
        Check if a pair of integers can be packed and unpacked correctly.
        """
        a = 21909485029845092485
        b = 9809809809800134013490

        packed = pack_pair(a, b)
        unpacked_a, unpacked_b, remainder = unpack_pair(packed)

        self.assertEqual(a, unpacked_a)
        self.assertEqual(b, unpacked_b)
        self.assertEqual(b'', remainder)

    def test_pack_pair_with_remainder(self) -> None:
        """
        Check if a pair of integers can be packed and unpacked correctly with a remainder.
        """
        a = 4684868464648654646385464634636
        b = 3212316546461687987934688
        remainder = b'iljaerlijerwfjilrwuj'

        packed = pack_pair(a, b) + remainder
        unpacked_a, unpacked_b, unpacked_remainder = unpack_pair(packed)

        self.assertEqual(a, unpacked_a)
        self.assertEqual(b, unpacked_b)
        self.assertEqual(remainder, unpacked_remainder)

    def test_serialize_boneh_pk(self) -> None:
        """
        Check if a BonehPublicKey can be serialized and unserialized correctly.
        """
        p = 884546864135123153155516635631631
        g = FP2Value(p, 58468546584635416356, 51468468484864846451)
        h = FP2Value(p, 651465444864846456151, 31213216564)
        key = BonehPublicKey(p, g, h)

        serialized = key.serialize()
        unserialized = BonehPublicKey.unserialize(serialized)

        self.assertEqual(p, unserialized.p)
        self.assertEqual(g, unserialized.g)
        self.assertEqual(h, unserialized.h)

    def test_serialize_boneh_pk_garbage(self) -> None:
        """
        Check if a BonehPublicKey returns None when unserializing garbage data.
        """
        unserialized = BonehPublicKey.unserialize(b'wowiuuorfuuj')

        self.assertEqual(None, unserialized)

    def test_serialize_boneh_pk_with_remainder(self) -> None:
        """
        Check if a BonehPublicKey can be serialized and unserialized correctly with remainder.
        """
        p = 69484635115151351513652987894784654156545665
        g = FP2Value(p, 68461115156531651631653163563, 132319884561841)
        h = FP2Value(p, 98781236511, 32185666658636546663635165635)
        key = BonehPublicKey(p, g, h)

        serialized = key.serialize() + b'iejriq94u2305ijiqnfa'
        unserialized = BonehPublicKey.unserialize(serialized)

        self.assertEqual(p, unserialized.p)
        self.assertEqual(g, unserialized.g)
        self.assertEqual(h, unserialized.h)

    def test_serialize_boneh_sk(self) -> None:
        """
        Check if a BonehPrivateKey can be serialized and unserialized correctly.
        """
        n = 684684664663646413641656355663
        p = 13121354644565465
        g = FP2Value(p, 96874984765651564, 3216465486956184847984564)
        h = FP2Value(p, 987987984, 8794181684561484515646518456148156454544)
        t1 = 6848489484665156651566515665163565636663563
        key = BonehPrivateKey(p, g, h, n, t1)

        serialized = key.serialize()
        unserialized = BonehPrivateKey.unserialize(serialized)

        self.assertEqual(n, unserialized.n)
        self.assertEqual(p, unserialized.p)
        self.assertEqual(g, unserialized.g)
        self.assertEqual(h, unserialized.h)
        self.assertEqual(t1, unserialized.t1)

    def test_serialize_boneh_sk_with_remainder(self) -> None:
        """
        Check if a BonehPrivateKey can be serialized and unserialized correctly with remainder.
        """
        n = 8441516511511
        p = 6415165156531635115353115155153515335333521
        g = FP2Value(p, 86416515655841555261455, 84986446854656165)
        h = FP2Value(p, 156151352151313613651, 84686815661132515513313)
        t1 = 321321564645164653164687
        key = BonehPrivateKey(p, g, h, n, t1)

        serialized = key.serialize() + b';k;mezrako;erjiragtijtgrioj'
        unserialized = BonehPrivateKey.unserialize(serialized)

        self.assertEqual(n, unserialized.n)
        self.assertEqual(p, unserialized.p)
        self.assertEqual(g, unserialized.g)
        self.assertEqual(h, unserialized.h)
        self.assertEqual(t1, unserialized.t1)

    def test_serialize_boneh_sk_garbage(self) -> None:
        """
        Check if a BonehPrivateKey returns None when unserializing garbage data.
        """
        unserialized = BonehPrivateKey.unserialize(b'wowiuuorfuuj')

        self.assertEqual(None, unserialized)

    def test_serialize_bitpair_attestation(self) -> None:
        """
        Check if a BitPairAttestation can be serialized and unserialized correctly.
        """
        p = 64151651565316351153531151551535153353335217
        a = FP2Value(p, 86416515655841555261455, 84986446854656165)
        b = FP2Value(p, 156151352151313613651, 84686815661132515513313)
        c = FP2Value(p, 8468548546854654, 6846843513131351)
        attest = BitPairAttestation(a, b, c)

        serialized = attest.serialize()
        unserialized = BitPairAttestation.unserialize(serialized, p)

        self.assertEqual(a, unserialized.a)
        self.assertEqual(b, unserialized.b)
        self.assertEqual(c, unserialized.complement)

    def test_serialize_bitpair_attestation_with_remainder(self) -> None:
        """
        Check if a BitPairAttestation can be serialized and unserialized correctly with remainder.
        """
        p = 6416514551355336516355565655656541131
        a = FP2Value(p, 64168498535685461646, 6846513216165165)
        b = FP2Value(p, 32184987216545974, 987984116541354132132165464)
        c = FP2Value(p, 13265, 848464848609849840645102)
        attest = BitPairAttestation(a, b, c)

        serialized = attest.serialize() + b'ih43qo8hepi9fjaegihngatejlidgvujhnmk '
        unserialized = BitPairAttestation.unserialize(serialized, p)

        self.assertEqual(a, unserialized.a)
        self.assertEqual(b, unserialized.b)
        self.assertEqual(c, unserialized.complement)

    def test_serialize_bitpair_compress(self) -> None:
        """
        Check if a BitPairAttestation can be compressed for proofing.
        """
        p = 64151651565316351153531151551535153353335217
        a = FP2Value(p, 86416515655841555261455, 84986446854656165)
        b = FP2Value(p, 156151352151313613651, 84686815661132515513313)
        c = FP2Value(p, 8468548546854654, 6846843513131351)
        attest = BitPairAttestation(a, b, c)

        self.assertEqual(a * b * c, attest.compress())

    def test_serialize_attestation_empty(self) -> None:
        """
        Check if an Attestation can be serialized and unserialized correctly with no bitpairs.
        """
        p = 884546864135123153155516635631631
        g = FP2Value(p, 58468546584635416356, 51468468484864846451)
        h = FP2Value(p, 651465444864846456151, 31213216564)
        key = BonehPublicKey(p, g, h)
        bitpairs = []
        attest = BonehAttestation(key, bitpairs)

        serialized = attest.serialize()
        unserialized = BonehAttestation.unserialize(serialized)

        self.assertEqual(p, unserialized.PK.p)
        self.assertEqual(g, unserialized.PK.g)
        self.assertEqual(h, unserialized.PK.h)
        self.assertListEqual(bitpairs, unserialized.bitpairs)

    def test_serialize_attestation_one(self) -> None:
        """
        Check if an Attestation can be serialized and unserialized correctly with one bitpair.
        """
        p = 884546864135123153155516635631631
        g = FP2Value(p, 58468546584635416356, 51468468484864846451)
        h = FP2Value(p, 651465444864846456151, 31213216564)
        a = FP2Value(p, 64168498535685461646, 6846513216165165)
        b = FP2Value(p, 32184987216545974, 987984116541354132132165464)
        c = FP2Value(p, 13265, 848464848609849840645102)
        bitpair = BitPairAttestation(a, b, c)
        key = BonehPublicKey(p, g, h)
        bitpairs = [bitpair]
        attest = BonehAttestation(key, bitpairs)

        serialized = attest.serialize()
        unserialized = BonehAttestation.unserialize(serialized)

        self.assertEqual(p, unserialized.PK.p)
        self.assertEqual(g, unserialized.PK.g)
        self.assertEqual(h, unserialized.PK.h)
        for bp in unserialized.bitpairs:
            self.assertEqual(bitpair.a, bp.a)
            self.assertEqual(bitpair.b, bp.b)
            self.assertEqual(bitpair.complement, bp.complement)

    def test_serialize_attestation_many(self) -> None:
        """
        Check if an Attestation can be serialized and unserialized correctly with twenty bitpairs.
        """
        p = 884546864135123153155516635631631
        g = FP2Value(p, 58468546584635416356, 51468468484864846451)
        h = FP2Value(p, 651465444864846456151, 31213216564)
        a = FP2Value(p, 64168498535685461646, 6846513216165165)
        b = FP2Value(p, 32184987216545974, 987984116541354132132165464)
        c = FP2Value(p, 13265, 848464848609849840645102)
        bitpair = BitPairAttestation(a, b, c)
        key = BonehPublicKey(p, g, h)
        bitpairs = [bitpair] * 20
        attest = BonehAttestation(key, bitpairs)

        serialized = attest.serialize()
        unserialized = BonehAttestation.unserialize(serialized)

        self.assertEqual(p, unserialized.PK.p)
        self.assertEqual(g, unserialized.PK.g)
        self.assertEqual(h, unserialized.PK.h)
        for bp in unserialized.bitpairs:
            self.assertEqual(bitpair.a, bp.a)
            self.assertEqual(bitpair.b, bp.b)
            self.assertEqual(bitpair.complement, bp.complement)
