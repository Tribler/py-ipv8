from hashlib import sha256, sha512
from random import randint, shuffle
from threading import Lock

from .cryptosystem.boneh import decode, encode
from .cryptosystem.value import FP2Value
from .structs import Attestation, BitPairAttestation

multithread_update_lock = Lock()


def generate_modular_additive_inverse(p, n):
    """
    Generate a group of size n which is its own modular additive inverse modulo p + 1.
    """
    R = [randint(1, p - 1) for _ in range(n - 1)]
    R.append(p - (sum(R) % (p + 1)) + 1)
    shuffle(R)
    return R


def attest(PK, value, bitspace):
    """
    Create an attestation for a public key's value lying within a certain bitspace.
    """
    A = list([int(c) for c in str(bin(value))[2:]])
    while len(A) < bitspace:
        A.insert(0, 0)
    R = generate_modular_additive_inverse(PK.p, bitspace)
    t_out_public = list(map(lambda a, b: encode(PK, a + b), A, R))
    t_out_private = []
    for i in range(0, len(A) - 1, 2):
        t_out_private.append((i, encode(PK, PK.p - ((R[i] + R[i + 1]) % (PK.p + 1)) + 1)))
    # Shuffle:
    t_out_public = [(i, t_out_public[i], t_out_public[i+1]) for i in range(0, len(t_out_public), 2)]
    shuffle(t_out_public)
    out_public = []
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
        bitpairs.append(BitPairAttestation(out_public[i], out_public[i+1], e))
    return Attestation(PK, bitpairs)


def sha512_as_int(value):
    """
    Convert a SHA512 hash to an integer.
    """
    out = 0
    for c in sha512(str(value)).digest():
        out <<= 8
        out |= ord(c)
    return out


def attest_sha512(PK, value):
    """
    Create an attestation for a value using a SHA512 hash.
    """
    return attest(PK, sha512_as_int(value), 512)


def binary_relativity_sha512(value):
    """
    Create the inter-bitpair relativity map of a value using the SHA512 hash.
    """
    return binary_relativity(sha512_as_int(value), 512)


def sha256_as_int(value):
    """
    Convert a SHA256 hash to an integer.
    """
    out = 0
    for c in sha256(str(value)).digest():
        out <<= 8
        out |= ord(c)
    return out


def attest_sha256(PK, value):
    """
    Create an attestation for a value using a SHA256 hash.
    """
    return attest(PK, sha256_as_int(value), 256)


def binary_relativity_sha256(value):
    """
    Create the inter-bitpair relativity map of a value using the SHA256 hash.
    """
    return binary_relativity(sha256_as_int(value), 256)


def sha256_4_as_int(value):
    """
    Convert a SHA256 4 byte hash to an integer.
    """
    out = 0
    for c in sha256(value.encode()).digest()[:4]:
        out <<= 8
        out |= c
    return out


def attest_sha256_4(PK, value):
    """
    Create an attestation for a value using a SHA256 4 byte hash.
    """
    return attest(PK, sha256_4_as_int(value), 32)


def binary_relativity_sha256_4(value):
    """
    Create the inter-bitpair relativity map of a value using the SHA256 4 byte hash.
    """
    return binary_relativity(sha256_4_as_int(value), 32)


def create_empty_relativity_map():
    """
    Construct a map of possible challenge responses.
    """
    return {0: 0, 1: 0, 2: 0, 3: 0}


def binary_relativity(value, bitspace):
    """
    Create the inter-bitpair relativity map of a value.
    """
    out = {0: 0, 1: 0, 2: 0}
    A = list([int(c) for c in str(bin(value))[2:]])
    while len(A) < bitspace:
        A.insert(0, 0)
    for i in range(0, bitspace - 1, 2):
        out[A[i] + A[i + 1]] += 1
    out[3] = 0
    return out


def binary_relativity_match(expected, value):
    """
    Get the matching percentage between relativity maps.
    Mismatches result in 0.0.
    """
    match = 0.0
    for k in expected:
        if expected[k] < value[k]:
            return 0.0
        if not expected[k]:
            continue
        match += float(value[k])/float(expected[k])
    return match/(len(expected)-1)


def binary_relativity_certainty(expected, value):
    """
    Give the chance of a current relativity map being the expected one.
    """
    cert = 1 - 0.5 ** (sum(value.values()))
    return binary_relativity_match(expected, value) * cert


def create_challenge(PK, bitpair):
    """
    Create a challenge for a bitpair attestation of a certain public key.
    """
    return bitpair.compress() * encode(PK, 0)


def create_honesty_check(PK, value):
    """
    Create a honesty check challenge.
    """
    return encode(PK, value)


def create_challenge_response_from_pair(SK, pair):
    """
    Respond to a bitpair challenge.
    """
    return create_challenge_response(SK, FP2Value(SK.p, pair[0], pair[1]))


def create_challenge_response(SK, challenge):
    """
    Respond to a bitpair challenge.
    """
    decoded = decode(SK, list(range(3)), challenge)
    return 3 if decoded is None else decoded


def process_challenge_response(relativity_map, response):
    """
    Process a challenge response in a relativity map.
    """
    multithread_update_lock.acquire()
    relativity_map[response] += 1
    multithread_update_lock.release()
