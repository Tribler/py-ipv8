from binascii import unhexlify

from .....attestation.wallet.primitives.boneh import (
    FP2Value,
    bilinear_group,
    decode,
    encode,
    generate_keypair,
    generate_prime,
    get_good_wp,
    is_good_wp,
)
from .....attestation.wallet.primitives.structs import BonehPrivateKey
from ....base import TestBase


class TestBoneh(TestBase):
    """
    Tests related to boneh paper constructions.
    """

    private_key = BonehPrivateKey.unserialize(unhexlify("0142018eceb3e03820006219a5c5a959abfd40b042c381ff894f7c3d62"
                                                        "5ee9a02302dcdeda322aa8372b66c8d9b4df981e96eb1e4f7dacda5bca"
                                                        "7399d864941a4b3ab55101415e009ff86a3288953321922929aaaaecdf"
                                                        "ba4663004f3b6caa1a32df6af462659a7bb4659f2325eba7e8518b526b"
                                                        "e30b0002d304429b21643154f8cec968d6156e0141608dd4640f02a8dd"
                                                        "1b98c012df578840cabadbe985e50ba5481e4f5ea9640fb363c4772998"
                                                        "5405ee29cacc9786ba747d9a26a9e98752d728c459bd3b8214f302be01"
                                                        "4143286cfe8bf4b0b0283714068ced3bb6be72e5a913ecfe5827cbee71"
                                                        "ce11a69f6a0ead8270430c3717606c1e93b7e60d2e426f26bf1ad9e81f"
                                                        "d260da09e47281fb0142017cdb49d11264889ce2d989f540196f3bfb01"
                                                        "02021d0426667e137c76b5c993406681f6b2335b2734ee6c6e251706f6"
                                                        "c2bf0c4fe53d0956410512f90465a3f777810140b6f72590286e1bb3e3"
                                                        "64d3cd3c6898e3df165f3361f76cf42e8361ae2a4547f73947a8e871e0"
                                                        "6bff71401841e0db916571eb947f03d5b236dee592286b7d5a3f0120cd"
                                                        "8489a2b149edce500b4357aa9ed0b6c220d7a7c16706531671e30d0334"
                                                        "2ef3"))

    def test_generate_prime(self) -> None:
        """
        Check if the next prime (= l * n - 1 = 2 mod 3) after 10 is 29.
        """
        self.assertEqual(generate_prime(10), 29)

    def test_bilinear_group(self) -> None:
        """
        Check if a bilinear group can be created.
        """
        self.assertEqual(bilinear_group(10, 29, 4, 5, 4, 5), FP2Value(29, 19, 5))

    def test_bilinear_group_torsion_point(self) -> None:
        """
        Check if a bilinear group returns 0 if there is no possible pairing.
        """
        self.assertEqual(bilinear_group(10, 29, 2, 3, 2, 3), FP2Value(29))

    def test_is_good_weil_pairing(self) -> None:
        """
        Check if is_good_wp returns True for 26 + 17x with n = 10.
        """
        self.assertTrue(is_good_wp(10, FP2Value(29, 26, 17)))

    def test_is_bad_weil_pairing(self) -> None:
        """
        Check if is_good_wp returns False for 0, 1 and x with n = 10.
        """
        self.assertFalse(is_good_wp(10, FP2Value(29)))
        self.assertFalse(is_good_wp(10, FP2Value(29, 1)))
        self.assertFalse(is_good_wp(10, FP2Value(29, b=1)))

    def test_get_good_weil_pairing(self) -> None:
        """
        Check if get_good_wp returns a proper Weil pairing for n = 10, p = 29.
        """
        _, wp = get_good_wp(10, 29)

        self.assertTrue(is_good_wp(10, wp))

    def test_encoding_random(self) -> None:
        """
        Check if the same value is encoded with a random masking.
        """
        pk = TestBoneh.private_key.public_key()

        self.assertNotEqual(encode(pk, 0), encode(pk, 0))

    def test_decoding_same(self) -> None:
        """
        Check if values are encoded with a random masking.
        """
        pk = TestBoneh.private_key.public_key()
        a = encode(pk, 0)
        b = encode(pk, 0)

        self.assertEqual(decode(TestBoneh.private_key, [0], a), decode(TestBoneh.private_key, [0], b))

    def test_decoding_after_homomorphic_add(self) -> None:
        """
        Check if values can still be decrypted after a homomorphic add.
        """
        pk = TestBoneh.private_key.public_key()
        a = encode(pk, 1)
        b = encode(pk, 3)

        self.assertEqual(decode(TestBoneh.private_key, [4], a * b), 4)

    def test_decoding_out_of_space(self) -> None:
        """
        Check if decode return None if the message is outside of the allowed space.
        """
        pk = TestBoneh.private_key.public_key()

        self.assertIsNone(decode(TestBoneh.private_key, [0], encode(pk, 1)))

    def test_generate_keypair(self) -> None:
        """
        Check if we can create a new keypair.
        """
        pk, sk = generate_keypair(32)

        self.assertEqual(pk.p, sk.p)
        self.assertEqual(pk.g, sk.g)
        self.assertEqual(pk.h, sk.h)
        self.assertEqual(decode(sk, [0, 1, 2], encode(pk, 0)), 0)
        self.assertEqual(decode(sk, [0, 1, 2], encode(pk, 1)), 1)
        self.assertEqual(decode(sk, [0, 1, 2], encode(pk, 2)), 2)
