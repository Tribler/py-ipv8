"""
Implementation of the Boneh 2-DNF scheme ("Evaluating 2-DNF Formulas on Ciphertexts" by Boneh et al.).
"""
from __future__ import annotations

from random import randint

from .cryptography_wrapper import generate_safe_prime, is_prime
from .ec import weilpairing
from .structs import BonehPrivateKey, BonehPublicKey
from .value import FP2Value


def generate_prime(n: int) -> int:
    """
    Generate p = l * n - 1 such that:
     - p is "prime"
     - p mod 3 = 2
     - l is an as small as possible positive integer.
    """
    p = 1
    l = 0
    while (p % 3) != 2 or not is_prime(p):
        l += 1
        p = l * n - 1
    return p


def bilinear_group(n: int, p: int, g1x: int, g1y: int, g2x: int, g2y: int) -> FP2Value:
    """
    Generate a bilinear group for two generators.
    """
    try:
        return weilpairing(p,
                         n,
                         (FP2Value(p, g1x), FP2Value(p, g1y)),
                         (FP2Value(p, b=g2x), FP2Value(p, g2y)),
                         (FP2Value(p), FP2Value(p)))
    except Exception:
        return FP2Value(p)


def get_random_exponentiation(p: FP2Value, n: int) -> FP2Value:
    """
    Create a random exponentiation of p in message space n.
    """
    r = randint(4, n - 1)
    test = p.intpow(r)
    while test == FP2Value(p.mod, 1):
        test = p.intpow(randint(4, n - 1))
    return test


def get_random_base(n: int) -> tuple[int, int]:
    """
    Create a generator for the EC.
    """
    x = randint(2, n - 1)
    y = randint(2, n - 1)
    return x, y


def is_good_wp(n: int, wp: FP2Value) -> bool:
    """
    A good pairing is not 0 and has order n.
    """
    is_one = wp == FP2Value(wp.mod, 1)
    is_zero = wp == FP2Value(wp.mod)
    good_order = wp.intpow(n + 1) == wp
    return good_order and not is_zero and not is_one


def get_good_wp(n: int, p: int | None = None) -> tuple[int, FP2Value]:
    """
    Instead of inspecting torsion points and checking for co-primality:
    just brute force generate pairings until we get a good one.

    :return: modulus, weilparing.
    """
    wp = None
    if not p:
        p = generate_prime(n)
    while (wp is None) or not is_good_wp(n, wp):
        g1x, g1y = get_random_base(n)
        wp = bilinear_group(n, p, g1x, g1y, g1x, g1y)
        if not is_good_wp(n, wp):
            wp = wp.intpow((p + 1) // n)
    return p, wp


def generate_primes(key_size: int = 128) -> tuple[int, int]:
    """
    Generate some primes. Key size in bits.
    """
    if key_size >= 512:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
        private_numbers = private_key.private_numbers()
        p, q = private_numbers.p, private_numbers.q
    else:
        p, q = generate_safe_prime(key_size), generate_safe_prime(key_size)
    return min(p, q), max(p, q)


def generate_keypair(key_size: int = 32) -> tuple[BonehPublicKey, BonehPrivateKey]:
    """
    Generate a keypair for a certain prime bit space.
    """
    t1, t2 = generate_primes(key_size)
    n = t1 * t2
    p, g = get_good_wp(n)
    u = None
    while not u or (u.intpow(t2) == FP2Value(p, 1)):
        _, u = get_good_wp(n, p)
    h = u.intpow(t2)
    return BonehPublicKey(p, g, h), BonehPrivateKey(p, g, h, t1 * t2, t1)


def encode(pubkey: BonehPublicKey, m: int) -> FP2Value:
    """
    Encode a message m given a public key.
    """
    return pubkey.g.intpow(m) * get_random_exponentiation(pubkey.h, pubkey.p)


def decode(privkey: BonehPrivateKey, msgspace: list[int], c: FP2Value) -> int | None:
    """
    Decode a ciphertext c given a private key and the possible source messages.
    """
    d = c.intpow(privkey.t1)
    t = privkey.g.intpow(privkey.t1)
    for m in msgspace:
        if d == t.intpow(m):
            return m
    return None
