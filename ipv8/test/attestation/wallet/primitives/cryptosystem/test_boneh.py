from twisted.trial import unittest

from ......attestation.wallet.primitives.cryptosystem.boneh import *
from ......attestation.wallet.primitives.structs import BonehPrivateKey


class TestBoneh(unittest.TestCase):

    private_key = BonehPrivateKey.unserialize(("0142018eceb3e03820006219a5c5a959abfd40b042c381ff894f7c3d625ee9a02" +
                                               "302dcdeda322aa8372b66c8d9b4df981e96eb1e4f7dacda5bca7399d864941a4b" +
                                               "3ab55101415e009ff86a3288953321922929aaaaecdfba4663004f3b6caa1a32d" +
                                               "f6af462659a7bb4659f2325eba7e8518b526be30b0002d304429b21643154f8ce" +
                                               "c968d6156e0141608dd4640f02a8dd1b98c012df578840cabadbe985e50ba5481" +
                                               "e4f5ea9640fb363c47729985405ee29cacc9786ba747d9a26a9e98752d728c459" +
                                               "bd3b8214f302be014143286cfe8bf4b0b0283714068ced3bb6be72e5a913ecfe5" +
                                               "827cbee71ce11a69f6a0ead8270430c3717606c1e93b7e60d2e426f26bf1ad9e8" +
                                               "1fd260da09e47281fb0142017cdb49d11264889ce2d989f540196f3bfb0102021" +
                                               "d0426667e137c76b5c993406681f6b2335b2734ee6c6e251706f6c2bf0c4fe53d" +
                                               "0956410512f90465a3f777810140b6f72590286e1bb3e364d3cd3c6898e3df165" +
                                               "f3361f76cf42e8361ae2a4547f73947a8e871e06bff71401841e0db916571eb94" +
                                               "7f03d5b236dee592286b7d5a3f0120cd8489a2b149edce500b4357aa9ed0b6c22" +
                                               "0d7a7c16706531671e30d03342ef3").decode('hex'))

    def test_generate_prime(self):
        """
        Check if the next prime (= l * n - 1 = 2 mod 3) after 10 is 29.
        """
        self.assertEqual(generate_prime(10), 29)

    def test_bilinear_group(self):
        """
        Check if a bilinear group can be created.
        """
        self.assertEqual(bilinear_group(10, 29, 4, 5, 4, 5), FP2Value(29, 19, 5))

    def test_bilinear_group_torsion_point(self):
        """
        Check if a bilinear group returns 0 if there is no possible pairing.
        """
        self.assertEqual(bilinear_group(10, 29, 2, 3, 2, 3), FP2Value(29))

    def test_is_good_weil_pairing(self):
        """
        Check if is_good_wp returns True for 26 + 17x with n = 10
        """
        self.assertTrue(is_good_wp(10, FP2Value(29, 26, 17)))

    def test_is_bad_weil_pairing(self):
        """
        Check if is_good_wp returns False for 0, 1 and x with n = 10
        """
        self.assertFalse(is_good_wp(10, FP2Value(29)))
        self.assertFalse(is_good_wp(10, FP2Value(29, 1)))
        self.assertFalse(is_good_wp(10, FP2Value(29, b=1)))

    def test_get_good_weil_pairing(self):
        """
        Check if get_good_wp returns a proper Weil pairing for n = 10, p = 29.
        """
        _, wp = get_good_wp(10, 29)

        self.assertTrue(is_good_wp(10, wp))

    def test_encoding_random(self):
        """
        Check if the same value is encoded with a random masking.
        """
        PK = TestBoneh.private_key.public_key()

        self.assertNotEqual(encode(PK, 0), encode(PK, 0))

    def test_decoding_same(self):
        """
        Check if values are encoded with a random masking.
        """
        PK = TestBoneh.private_key.public_key()
        a = encode(PK, 0)
        b = encode(PK, 0)

        self.assertEqual(decode(TestBoneh.private_key, [0], a), decode(TestBoneh.private_key, [0], b))

    def test_decoding_after_homomorphic_add(self):
        """
        Check if values can still be decrypted after a homomorphic add.
        """
        PK = TestBoneh.private_key.public_key()
        a = encode(PK, 1)
        b = encode(PK, 3)

        self.assertEqual(decode(TestBoneh.private_key, [4], a*b), 4)

    def test_decoding_out_of_space(self):
        """
        Check if decode return None if the message is outside of the allowed space.
        """
        PK = TestBoneh.private_key.public_key()

        self.assertIsNone(decode(TestBoneh.private_key, [0], encode(PK, 1)))

    def test_generate_keypair(self):
        """
        Check if we can create a new keypair.
        """
        PK, SK = generate_keypair(32)

        self.assertEqual(PK.p, SK.p)
        self.assertEqual(PK.g, SK.g)
        self.assertEqual(PK.h, SK.h)
        self.assertEqual(decode(SK, [0, 1, 2], encode(PK, 0)), 0)
        self.assertEqual(decode(SK, [0, 1, 2], encode(PK, 1)), 1)
        self.assertEqual(decode(SK, [0, 1, 2], encode(PK, 2)), 2)
