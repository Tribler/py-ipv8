"""
Copyright (c) 2016, Maarten Everts
All rights reserved.

This source code has been ported from https://github.com/privacybydesign/gabi
The authors of this file are not -in any way- affiliated with the original authors or organizations.
"""
from __future__ import annotations

from binascii import hexlify
from os import urandom
from typing import cast

from cryptography.hazmat.primitives.asymmetric.rsa import _modinv

from .....util import byte2int, int2byte
from ...primitives.attestation import sha256_as_int
from ...primitives.cryptography_wrapper import generate_safe_prime, is_prime
from ...primitives.value import FP2Value
from .. import secure_randint

DefaultEpochLength = 432000

# ruff: noqa: N802,N803,N806,N816


class BaseParameters:
    """
    Algorithm parameters for Gabi.
    """

    def __init__(self, LePrime: int, Lh: int, Lm: int, Ln: int, Lstatzk: int) -> None:
        """
        Create new base parameters.
        """
        self.LePrime = LePrime
        self.Lh = Lh
        self.Lm = Lm
        self.Ln = Ln
        self.Lstatzk = Lstatzk

        self.Lv = Ln + 2 * Lstatzk + Lh + Lm + 4
        self.Le = Lstatzk + Lh + Lm + 5
        self.LeCommit = LePrime + Lstatzk + Lh
        self.LmCommit = Lm + Lstatzk + Lh
        self.LRA = Ln + Lstatzk
        self.LsCommit = Lm + Lstatzk + Lh + 1
        self.LvCommit = self.Lv + Lstatzk + Lh
        self.LvPrime = Ln + Lstatzk
        self.LvPrimeCommit = Ln + 2 * Lstatzk + Lh


DefaultSystemParameters = {
    1024: BaseParameters(120, 256, 256, 1024, 80),
    2048: BaseParameters(120, 256, 256, 2048, 128),
    4096: BaseParameters(120, 256, 512, 4096, 128)
}


class PrivateKey:
    """
    Gabi private key.
    """

    def __init__(self, p: int, q: int, counter: int, expiryDate: int) -> None:
        """
        Create a new private key.
        """
        self.Counter = counter
        self.ExpiryData = expiryDate
        self.P = p
        self.Q = q
        self.PPrime = (p - 1) >> 1
        self.QPrime = (q - 1) >> 1


class PublicKey:
    """
    Gabi public key.
    """

    def __init__(self, N: int, Z: int, S: int, R: list[int], counter: int, expiryDate: int,  # noqa: PLR0913
                 param: BaseParameters | None = None) -> None:
        """
        Create a new Gabi public key.
        """
        self.Counter = counter
        self.ExpiryDate = expiryDate
        self.N = N
        self.Z = Z
        self.S = S
        self.R = R
        self.EpochLength = DefaultEpochLength
        self.Params: BaseParameters = param or DefaultSystemParameters[N.bit_length()]
        self.Issuer = "-"


def findMatch(safeprimes: list[int], param: BaseParameters, p: int) -> int | None:
    """
    Select a safe prime from the given list that fits the Gabi protocol's requirements.
    """
    for q in safeprimes:
        if (p * q).bit_length() == param.Ln and (p % 8) != 0 and (q % 8) != 0:
            return q
    return None


def generateSafePrimePair(param: BaseParameters) -> tuple[int, int]:
    """
    Generate a prime pair that fits Gabi's protocol requirements.
    """
    primeSize = param.Ln // 2
    safeprimes: list[int] = []
    q = None
    while True:
        p = generate_safe_prime(primeSize)
        pPrime = p >> 1
        pPrimeMod8 = pPrime % 8
        if pPrimeMod8 == 1:
            continue
        q = findMatch(safeprimes, param, p)
        if not safeprimes or q is None:
            safeprimes.append(p)
            continue
        break
    return p, cast(int, q)


def legendreSymbol(a: int, p: int) -> int:
    """
    Calculate the Legendre Symbol for numbner a and prime p.
    """
    j = 1
    n = a % p
    m = p
    while n != 0:
        t = 0
        while (n & 1) == 0:
            n >>= 1
            t += 1
        tmp = m % 8
        if (t & 1) == 1 and tmp in {3, 5}:
            j = -j
        if (m % 4) == 3 or (n % 4) == 3:
            j = -j
        m = m % n
        n, m = m, n
    if m == 1:
        return j
    return 0


def GenerateKeyPair(param: BaseParameters, numAttributes: int, counter: int,
                    expiryDate: int) -> tuple[PrivateKey, PublicKey]:
    """
    Generate a new key pair for a given number of attributes.
    """
    p, q = generateSafePrimePair(param)
    priv = PrivateKey(p, q, counter, expiryDate)

    N = p * q

    while True:
        S = secure_randint(param.Ln)
        if S > N:
            continue
        if legendreSymbol(S, p) == 1 and legendreSymbol(S, q) == 1:
            break

    primeSize = param.Ln // 2
    while True:
        x = secure_randint(primeSize)
        if x > 2 and x < N:
            break

    Z = FP2Value(N, S).intpow(x).a

    R = []

    for _i in range(numAttributes):
        while True:
            x = secure_randint(primeSize)
            if x > 2 and x < N:
                break
        R.append(FP2Value(N, S).intpow(x).a)

    pubk = PublicKey(N, Z, S, R, counter, expiryDate, param=param)

    if not SignMessageBlock(priv, pubk, [1]).Verify(pubk, [1]):
        return GenerateKeyPair(param, numAttributes, counter, expiryDate)
    return priv, pubk


class CLSignature:
    """
    A Camenisch-Lysyanskaya signature.
    """

    def __init__(self, A: int, E: int, V: int, KeyshareP: int | None = None) -> None:
        """
        Represent the given signature data.
        """
        self.A = A
        self.E = E
        self.V = V
        self.KeyshareP = KeyshareP

    def Verify(self, pk: PublicKey, ms: list[int]) -> bool:
        """
        Verify the signature for the given public key.
        """
        start = 1 << (pk.Params.Le - 1)
        end = 1 << (pk.Params.LePrime - 1)
        end = end + start

        if start > self.E or end < self.E:
            return False

        Ae = FP2Value(pk.N, self.A).intpow(self.E).a
        R = RepresentToPublicKey(pk, ms)

        if self.KeyshareP is not None:
            R = R * self.KeyshareP

        Sv = FP2Value(pk.N, pk.S).intpow(self.V).a
        Q = Ae * R
        Q = (Q * Sv) % pk.N

        return pk.Z == Q

    def Randomize(self, pk: PublicKey) -> CLSignature:
        """
        Mask the signature without changing its underlying data.
        """
        r = secure_randint(pk.Params.LRA)
        APrime = (FP2Value(pk.N, self.A) * FP2Value(pk.N, pk.S).intpow(r)).a
        t = self.E * r
        VPrime = self.V - t
        return CLSignature(APrime, self.E, VPrime, None)


def representToBases(bases: list[int], exps: list[int], modulus: int, maxMessageLength: int) -> int:
    """
    CRT the given exponents (or their hashes if they are bigger than the max length).
    """
    r = 1
    for i in range(len(exps)):
        exp = exps[i]
        if exp.bit_length() > maxMessageLength:
            exp = sha256_as_int(str(exp))
        tmp = FP2Value(modulus, bases[i]).intpow(exp).a
        r = (r * tmp) % modulus
    return r


def RepresentToPublicKey(pk: PublicKey, exps: list[int]) -> int:
    """
    CRT the given exponents using public key information.
    """
    return representToBases(pk.R, exps, pk.N, pk.Params.Lm)


smallPrimes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]
smallPrimesProduct = 16294579238595022365


def randomPrimeInRange(start: int, length: int) -> int:
    """
    Generate a prime in a given range.
    """
    b = length % 8
    if b == 0:
        b = 8
    startVal = 1 << start
    endVal = (1 << length) + startVal

    while True:
        bytez = urandom((length + 7) // 8)
        bytez = int2byte(byte2int(bytez[0:1]) & (1 << b) - 1) + bytez[1:]
        bytez = bytez[:-1] + int2byte(byte2int(bytez[-1:]) | 1)
        offset = int(hexlify(bytez), 16)
        p = startVal + offset
        bigMod = p % smallPrimesProduct
        mod = bigMod

        delta = 0
        while delta < (1 << 20):
            m = mod + delta
            if any(m % prime == 0 and (start > 6 or m != prime) for prime in smallPrimes):
                break
            if delta > 0:
                bigMod = delta
                p += bigMod
            delta += 2

        if is_prime(p) and p < endVal:
            return p


def signMessageBlockAndCommitment(sk: PrivateKey, pk: PublicKey, U: int, ms: list[int]) -> CLSignature:
    """
    Sign a bunch of messages using our key material.
    """
    R = RepresentToPublicKey(pk, ms)
    vTilde = secure_randint(pk.Params.Lv)
    twoLv = 1 << (pk.Params.Lv - 1)
    v = twoLv + vTilde

    numerator = FP2Value(pk.N, pk.S).intpow(v).a
    numerator = (numerator * R * U) % pk.N

    invNumerator = _modinv(numerator, pk.N)
    Q = (pk.Z * invNumerator) % pk.N

    e = randomPrimeInRange(pk.Params.Le - 1, pk.Params.LePrime - 1)

    order = sk.PPrime * sk.QPrime
    d = _modinv(e, order)
    A = FP2Value(pk.N, Q).intpow(d).a

    return CLSignature(A, e, v, None)


def SignMessageBlock(sk: PrivateKey, pk: PublicKey, ms: list[int]) -> CLSignature:
    """
    Sign a bunch of messages using our key material.
    """
    return signMessageBlockAndCommitment(sk, pk, 1, ms)
