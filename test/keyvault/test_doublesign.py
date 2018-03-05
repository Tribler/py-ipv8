import unittest

from ipv8.keyvault.doublesign import SECP256k1


class TestDoubleSign(unittest.TestCase):
    """
    Test whether two signatures can be exploited to derive the private key.
    """
    def setUp(self):
        self.ecdsa = SECP256k1()

    def test_signature_verification(self):
        """
        Tests if signature generation and verification works fine.
        """
        # Private key and the sign secret
        priv = 0xd117d1ca1399054080869f50373b93310c7bd19c26a760a58c8c18fea892729f
        signsecret1 = 0x8ea5791d51a6895eaf2143185caa5a3e2dd3752ad4fa28aa8282331d37f4ea2e

        # Messages to sign
        msg1 = 0x1234123412341234123412341234123412341234123412341234123412341234
        msg2 = 0x1111111111111111111111111111111111111111111111111111111111111111

        # Derive public key from private key
        pubkey = self.ecdsa.pubkey(priv)

        # Sign the first message and verify the signature
        (r1, s1) = self.ecdsa.sign(msg1, priv, signsecret1)
        check1 = self.ecdsa.verify(msg1, pubkey, r1, s1)
        self.assertTrue(check1, "Signature 1 verification failed")

        # Sign the second message and verify the signature
        (r2, s2) = self.ecdsa.sign(msg2, priv, signsecret1)
        check2 = self.ecdsa.verify(msg2, pubkey, r2, s2)
        self.assertTrue(check2, "Signature 2 verification failed")

    def test_privatekey_recovery(self):
        """
        Test if private key recovery works.
        """
        # Private key and the sign secret (both strings)
        priv_hex = "d117d1ca1399054080869f50373b93310c7bd19c26a760a58c8c18fea892729f"
        signsecret1 = "8ea5791d51a6895eaf2143185caa5a3e2dd3752ad4fa28aa8282331d37f4ea2e"

        # Messages to sign
        msg1 = "0x1234123412341234123412341234123412341234123412341234123412341234"
        msg2 = "0x1111111111111111111111111111111111111111111111111111111111111111"

        # Sign the first message and verify the signature
        signature = self.ecdsa.custom_sign(priv_hex, msg1, signsecret1)
        check1 = self.ecdsa.custom_verify(msg1, signature)
        self.assertTrue(check1, "Signature 1 verification failed")

        # Sign the second message and verify the signature
        signature2 = self.ecdsa.custom_sign(priv_hex, msg2, signsecret1)
        check2 = self.ecdsa.custom_verify(msg2, signature2)
        self.assertTrue(check2, "Signature 2 verification failed")

        # Recover the private key from these two signatures
        (_, crackedprivkey) = self.ecdsa.recover_from_double_signatures(msg1, msg2, signature, signature2)
        self.assertEqual(priv_hex, crackedprivkey.encode('hex'))
