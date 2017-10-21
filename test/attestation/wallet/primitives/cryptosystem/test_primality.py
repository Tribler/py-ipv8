import unittest

from ipv8.attestation.wallet.primitives.cryptosystem.primality import isLucasPseudoprime


class TestPrimality(unittest.TestCase):

    def test_primes(self):
        """
        Check known primes for primality.
        """
        primes = [
            104239,
            104729,
            86719,
            15373,
            247451,
            9002663
        ]

        for prime in primes:
            self.assertTrue(isLucasPseudoprime(prime))
