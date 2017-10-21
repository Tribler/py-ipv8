import unittest

from ipv8.attestation.wallet.primitives.cryptosystem.boneh import *
from ipv8.attestation.wallet.primitives.structs import BonehPrivateKey


class TestBoneh(unittest.TestCase):

    private_key = BonehPrivateKey.unserialize('\x01@\xe2W\x0e\x1b\x9c\x86\xd8`w\xc9a\x90:\xb4\xc1\xb8\xb2\r\xe8%2' +
                                              '\xafM0\xc0Q\x0e\xa8\xe0\xf4V\n&.\x1a\xce\x9e\xa2\xcc;\\\x0f2\x91\xda' +
                                              '\x83*\x95\xc7k%\x87W\xc4\x05,\xe9\xa0\xe6p\x15D?\xff\x01A\xaf\x0fT' +
                                              '\xe9[\x10KZ\x9c\xa5\xc1u\x8dg\xcd\xd4\xd9\xb6\xc1\x8c\xc53\x95\xb3' +
                                              '\xb4\xbe\xb1V\x9d\xfc\xfa\x8b\xd9\x87\xa8\xbb\xce\xb1\xe9\xf5\xe93' +
                                              '\xc1\x1c\xcf\x01r\xef\xd8<\xdf\x06\xad\xe1\x9c\x00\xbc\xb2r:\xb0r' +
                                              '\xc9\x7f9\x01AT}d\xa4\xcf\xb4b\x89\xe8\x19\xac\xc1\x1b\xcf`)]=\xd5' +
                                              '\x99I\x88H\xeb [\x8bb2\ta\xc9\xdb9\xe4\x1a\xffe\xd0TF\x05aA/\x9bDj' +
                                              '\xb0|(;\xf1\xd4@R_D\xf4\x91\x1e\x14\xcf\x1b\xe0\x01A\xa2\x9f\x99%L' +
                                              '\x1ap:\x1e\xe7\t\xf1\x08\xa9\xfc0l1\xd9\x012\xa5\xda\xa8Zr\xee\x19' +
                                              '\xb5\x11\xc3oQ.\xfa\xad7\xbd\xde\xf84\x9e\xc2\xae^C\xfb=N\x0b\xe72' +
                                              '\x1aNx\xa8uW\x8cO\x8f\xba\xee+\xad\x01A\x81CI\xc8:v\xd2\xc0S\xe8\xca' +
                                              '\x17\xd6\xa6\x91]x4{\x16\xf8ak\xd9\x8f\xee\xacc\x85R\xe0\xd6M\x9a;k' +
                                              '\xbf%\xf0P\x97\xbd4\xf0\\\x99a\x1a\x7f\xf1\x82qUi\x14z1\x05)\x99\xbc' +
                                              'L\xf9\xb42\x01A\x10\x8a\x08\xeb\xdf\x07\x16\x00\xff\x8c`\x17_\xfc\xce' +
                                              '\xad\xb7\xbct%P\x0c\x97V\xaeUf\x97\x0e0\xcc\xb4\x7f\xbf\x80\xc53D\x88' +
                                              '\xc5\n\xdc\xa5?\xd9\xa7\xfaU\x1f\xb2;\xb1`\xdb\xdc\x8ba\xd7\xfabY\xb9' +
                                              '\xc1\xbf\x9c\x01 \xe8\xc0\xb9\xbcx\xcf\xd6\xe5X\xcd\x85\xf1Un\x08\x165' +
                                              '\x9apB\xf2\x9aC \xda!\x98\xb2\x8c\xe9\x7fI')

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
