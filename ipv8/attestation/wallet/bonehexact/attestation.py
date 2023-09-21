from __future__ import annotations

from random import randint, shuffle
from threading import Lock
from typing import TYPE_CHECKING

from ..primitives.attestation import sha256_4_as_int, sha256_as_int, sha512_as_int
from ..primitives.boneh import decode, encode
from ..primitives.value import FP2Value
from .structs import BitPairAttestation, BonehAttestation

if TYPE_CHECKING:
    from ..primitives.structs import BonehPrivateKey, BonehPublicKey

multithread_update_lock = Lock()

# ruff: noqa: N803,N806


def generate_modular_additive_inverse(p: int, n: int) -> list[int]:
    """
    Generate a group of size n which is its own modular additive inverse modulo p + 1.
    """
    R = [randint(1, p - 1) for _ in range(n - 1)]
    R.append(p - (sum(R) % (p + 1)) + 1)
    shuffle(R)
    return R


def attest(PK: BonehPublicKey, value: int, bitspace: int) -> BonehAttestation:
    """
    Create an attestation for a public key's value lying within a certain bitspace.
    """
    A = [int(c) for c in str(bin(value))[2:]]
    while len(A) < bitspace:
        A.insert(0, 0)
    R = generate_modular_additive_inverse(PK.p, bitspace)
    t_out_public_v = [encode(PK, a + b) for (a, b) in zip(A, R)]
    t_out_private = [(i, encode(PK, PK.p - ((R[i] + R[i + 1]) % (PK.p + 1)) + 1)) for i in range(0, len(A) - 1, 2)]
    # Shuffle:
    t_out_public = [(i, t_out_public_v[i], t_out_public_v[i + 1]) for i in range(0, len(t_out_public_v), 2)]
    shuffle(t_out_public)
    out_public: list[FP2Value] = []
    out_private = []
    shuffle_map = {}
    for (i, v1, v2) in t_out_public:
        shuffle_map[i] = len(out_public)
        out_public.append(v1)
        out_public.append(v2)
    for (i, e) in t_out_private:
        out_private.append((shuffle_map[i], e))
    shuffle(out_private)
    # Formalize
    bitpairs = []
    for (i, e) in out_private:
        bitpairs.append(BitPairAttestation(out_public[i], out_public[i + 1], e))
    return BonehAttestation(PK, bitpairs)


def attest_sha512(PK: BonehPublicKey, value: bytes) -> BonehAttestation:
    """
    Create an attestation for a value using a SHA512 hash.
    """
    return attest(PK, sha512_as_int(value), 512)


def binary_relativity_sha512(value: bytes) -> dict[int, int]:
    """
    Create the inter-bitpair relativity map of a value using the SHA512 hash.
    """
    return binary_relativity(sha512_as_int(value), 512)


def attest_sha256(PK: BonehPublicKey, value: bytes) -> BonehAttestation:
    """
    Create an attestation for a value using a SHA256 hash.
    """
    return attest(PK, sha256_as_int(value), 256)


def binary_relativity_sha256(value: bytes) -> dict[int, int]:
    """
    Create the inter-bitpair relativity map of a value using the SHA256 hash.
    """
    return binary_relativity(sha256_as_int(value), 256)


def attest_sha256_4(PK: BonehPublicKey, value: bytes) -> BonehAttestation:
    """
    Create an attestation for a value using a SHA256 4 byte hash.
    """
    return attest(PK, sha256_4_as_int(value), 32)


def binary_relativity_sha256_4(value: bytes) -> dict[int, int]:
    """
    Create the inter-bitpair relativity map of a value using the SHA256 4 byte hash.
    """
    return binary_relativity(sha256_4_as_int(value), 32)


def create_empty_relativity_map() -> dict[int, int]:
    """
    Construct a map of possible challenge responses.
    """
    return {0: 0, 1: 0, 2: 0, 3: 0}


def binary_relativity(value: int, bitspace: int) -> dict[int, int]:
    """
    Create the inter-bitpair relativity map of a value.
    """
    out = {0: 0, 1: 0, 2: 0}
    A = [int(c) for c in str(bin(value))[2:]]
    while len(A) < bitspace:
        A.insert(0, 0)
    for i in range(0, bitspace - 1, 2):
        out[A[i] + A[i + 1]] += 1
    out[3] = 0
    return out


def binary_relativity_match(expected: dict[int, int], value: dict[int, int]) -> float:
    """
    Get the matching percentage between relativity maps.
    Mismatches result in 0.0.
    """
    match = 1.0
    for k in expected:
        if expected[k] < value[k]:
            return 0.0
        if not expected[k] or not value[k]:
            continue
        match *= float(value[k]) / float(expected[k])
    return match


def binary_relativity_certainty(expected: dict[int, int], value: dict[int, int]) -> float:
    """
    Give the chance of a current relativity map being the expected one.
    """
    cert = 1 - 0.5 ** (sum(value.values()))
    return binary_relativity_match(expected, value) * cert


def create_challenge(PK: BonehPublicKey, bitpair: BitPairAttestation) -> FP2Value:
    """
    Create a challenge for a bitpair attestation of a certain public key.
    """
    return bitpair.compress() * encode(PK, 0)


def create_honesty_check(PK: BonehPublicKey, value: int) -> FP2Value:
    """
    Create a honesty check challenge.
    """
    return encode(PK, value)


def create_challenge_response_from_pair(SK: BonehPrivateKey,
                                        pair: tuple[int, int] | tuple[int, int, bytes]) -> int:
    """
    Respond to a bitpair challenge.
    """
    return create_challenge_response(SK, FP2Value(SK.p, pair[0], pair[1]))


def create_challenge_response(SK: BonehPrivateKey, challenge: FP2Value) -> int:
    """
    Respond to a bitpair challenge.
    """
    decoded = decode(SK, [0, 1, 2], challenge)
    return 3 if decoded is None else decoded


def process_challenge_response(relativity_map: dict[int, int], response: int) -> None:
    """
    Process a challenge response in a relativity map.
    """
    multithread_update_lock.acquire()
    relativity_map[response] += 1
    multithread_update_lock.release()
