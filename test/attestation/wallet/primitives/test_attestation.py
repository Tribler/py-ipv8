import unittest

from ipv8.attestation.wallet.primitives.structs import BonehPrivateKey
from ipv8.attestation.wallet.primitives.attestation import *


class TestAttestation(unittest.TestCase):

    private_key = BonehPrivateKey.unserialize('01011d01011401011101011c01011c01010f010103'.decode('hex'))

    def test_generate_minverse_group(self):
        """
        Check if additive inverse group generation modulo (p + 1) is correct.
        """
        p = 12253454
        n = 20
        group = generate_modular_additive_inverse(p, n)

        self.assertEqual(20, len(group))
        self.assertEqual(0, sum(group) % (p + 1))

    def test_attest(self):
        """
        Check if Attestations can be created correctly.
        """
        attestations = [
            attest(self.private_key, 0, 2),
            attest(self.private_key, 1, 2),
            attest(self.private_key, 2, 2),
            attest(self.private_key, 3, 2)
        ]

        self.assertListEqual([0, 1, 1, 2],
                             [decode(self.private_key, range(4), a.bitpairs[0].compress()) for a in attestations])

    def test_empty_relativity_map(self):
        """
        Check if a new relativity map is empty.
        """
        map = create_empty_relativity_map()

        self.assertSetEqual({0, 1, 2, 3}, set(map.keys()))
        self.assertEqual(0, sum(map.values()))

    def test_binary_relativity(self):
        """
        Check if the binary relativity of several numbers is calculated correctly.
        """
        values = [
            ({0: 0, 1: 1, 2: 1, 3: 0}, 7, 4),  # 0111
            ({0: 0, 1: 1, 2: 2, 3: 0}, 55, 6),  # 110111
            ({0: 1, 1: 1, 2: 1, 3: 0}, 199, 6)  # 11000111
        ]

        for expected, value, bitspace in values:
            self.assertDictEqual(expected, binary_relativity(value, bitspace))

    def test_binary_relativity_match(self):
        """
        Check if matching percentages between maps are relatively correct.
        """
        a = {0: 0, 1: 1, 2: 1, 3: 0}
        b = {0: 0, 1: 1, 2: 2, 3: 0}
        c = {0: 1, 1: 1, 2: 1, 3: 0}

        self.assertLess(0, binary_relativity_match(b, a))
        self.assertEqual(0, binary_relativity_match(a, b))

        self.assertLess(0, binary_relativity_match(c, a))
        self.assertEqual(0, binary_relativity_match(a, c))

        self.assertEqual(0, binary_relativity_match(b, c))
        self.assertEqual(0, binary_relativity_match(c, b))

    def test_binary_relativity_certainty(self):
        """
        Check if matching certainties between maps are relatively correct.
        """
        a = {0: 0, 1: 1, 2: 1, 3: 0}
        b = {0: 0, 1: 1, 2: 2, 3: 0}

        # (1 * 1 * .5 * 1)*(1 - .25) = .5 * .75 = .375
        self.assertEqual(0.375, binary_relativity_certainty(b, a))

    def test_create_challenge(self):
        """
        Check if challenges can be created and are properly responded to.
        """
        PK = self.private_key.public_key()
        challenges = [
            create_challenge(PK, attest(PK, 0, 2).bitpairs[0]),
            create_challenge(PK, attest(PK, 1, 2).bitpairs[0]),
            create_challenge(PK, attest(PK, 2, 2).bitpairs[0]),
            create_challenge(PK, attest(PK, 3, 2).bitpairs[0])
        ]

        self.assertListEqual([0, 1, 1, 2], [create_challenge_response(self.private_key, c) for c in challenges])

    def test_process_challenge_response(self):
        """
        Check if a map is properly updates when a challenge response comes in.
        """
        a = {0: 0, 1: 1, 2: 1, 3: 0}
        b = {0: 0, 1: 1, 2: 2, 3: 0}

        process_challenge_response(a, 2)

        self.assertDictEqual(a, b)
