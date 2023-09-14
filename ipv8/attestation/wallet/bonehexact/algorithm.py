from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any

from ...identity_formats import IdentityAlgorithm
from ..primitives.boneh import generate_keypair
from ..primitives.structs import BonehPrivateKey, BonehPublicKey, pack_pair, unpack_pair
from .attestation import (
    attest_sha256,
    attest_sha256_4,
    attest_sha512,
    binary_relativity_certainty,
    binary_relativity_sha256,
    binary_relativity_sha256_4,
    binary_relativity_sha512,
    create_challenge,
    create_challenge_response_from_pair,
    create_empty_relativity_map,
    create_honesty_check,
    process_challenge_response,
)
from .structs import BonehAttestation

if TYPE_CHECKING:
    from ..database import SecretKeyProtocol

# ruff: noqa: N803


class BonehExactAlgorithm(IdentityAlgorithm):
    """
    IPv8 wrapper around ZKP using Boneh partially-homom. crypto scheme.
    """

    def __init__(self, id_format: str, formats: dict[str, dict[str, Any]]) -> None:
        """
        Create a new Boneh-based ZKP algorithm wrapper.
        """
        super().__init__(id_format, formats)
        self.honesty_check = True

        # Check algorithm match
        if formats[id_format]["algorithm"] != "bonehexact":
            msg = "Identity format linked to wrong algorithm"
            raise RuntimeError(msg)

        # Check key size match
        self.key_size = formats[self.id_format]["key_size"]
        if self.key_size < 32 or self.key_size > 512:
            msg = "Illegal key size specified"
            raise RuntimeError(msg)

        # Check hash mode match
        hash_mode = formats[self.id_format]["hash"]
        if hash_mode == "sha256":
            self.attest_function = attest_sha256
            self.aggregate_reference = binary_relativity_sha256
        elif hash_mode == "sha256_4":
            self.attest_function = attest_sha256_4
            self.aggregate_reference = binary_relativity_sha256_4
        elif hash_mode == "sha512":
            self.attest_function = attest_sha512
            self.aggregate_reference = binary_relativity_sha512
        else:
            msg = "Unknown hashing mode"
            raise RuntimeError(msg)

    def generate_secret_key(self) -> BonehPrivateKey:
        """
        Generate a secret key.

        :return: the secret key
        """
        return generate_keypair(self.key_size)[1]

    def load_secret_key(self, serialized: bytes) -> BonehPublicKey | None:
        """
        Unserialize a secret key from the key material.

        :param serialized: the string of the private key
        :return: the private key
        """
        return BonehPrivateKey.unserialize(serialized)

    def load_public_key(self, serialized: bytes) -> BonehPublicKey | None:
        """
        Unserialize a public key from the key material.

        :param serialized: the string of the public key
        :return: the public key
        """
        return BonehPublicKey.unserialize(serialized)

    def get_attestation_class(self) -> type[BonehAttestation]:
        """
        Return the Attestation (sub)class for serialization.

        :return: the Attestation object
        :rtype: BonehAttestation
        """
        return BonehAttestation

    def attest(self, PK: BonehPublicKey, value: bytes) -> bytes:
        """
        Attest to a value for a certain public key.

        :param PK: the public key of the party we are attesting for
        :type PK: BonehPublicKey
        :param value: the value we are attesting to
        :type value: str
        :return: the attestation string
        :rtype: str
        """
        return self.attest_function(PK, value).serialize()

    def certainty(self, value: bytes, aggregate: dict) -> float:
        """
        The current certainty of the aggregate object representing a certain value.

        :param value: the value to match to
        :type value: str
        :param aggregate: the aggregate object
        :type aggregate: dict
        :return: the matching factor [0.0-1.0]
        :rtype: float
        """
        return binary_relativity_certainty(self.aggregate_reference(value), aggregate)

    def create_challenges(self, PK: BonehPublicKey, attestation: BonehAttestation) -> list[bytes]:
        """
        Create challenges for a certain counterparty.

        :param PK: the public key of the party we are challenging
        :type PK: BonehPublicKey
        :param attestation: the attestation information
        :type attestation: BonehAttestation
        :return: the challenges to send
        :rtype: [str]
        """
        challenges = []
        for bitpair in attestation.bitpairs:
            challenge = create_challenge(attestation.PK, bitpair)
            serialized = pack_pair(challenge.a, challenge.b)
            challenges.append(serialized)
        return challenges

    def create_challenge_response(self, SK: BonehPrivateKey, attestation: BonehAttestation, challenge: bytes) -> bytes:
        """
        Create an honest response to a challenge of our value.

        :param SK: our secret key
        :type SK: BonehPrivateKey
        :param attestation: the attestation information
        :type attestation: Attestation
        :param challenge: the challenge to respond to
        :return: the response to a challenge
        :rtype: str
        """
        return struct.pack(">B", create_challenge_response_from_pair(SK, unpack_pair(challenge)))

    def create_certainty_aggregate(self, attestation: BonehAttestation | None) -> dict:
        """
        Create an empty aggregate object, for matching to values.

        :param attestation: the attestation information
        :type attestation: Attestation
        :return: the aggregate object
        :rtype: dict
        """
        return create_empty_relativity_map()

    def create_honesty_challenge(self, PK: BonehPublicKey, value: int) -> bytes:
        """
        Use a known value to check for honesty.

        :param PK: the public key of the party we are challenging
        :type PK: BonehPublicKey
        :param value: the value to use
        :type value: str
        :return: the challenge to send
        :rtype: str
        """
        raw_challenge = create_honesty_check(PK, value)
        return pack_pair(raw_challenge.a, raw_challenge.b)

    def process_honesty_challenge(self, value: int, response: bytes) -> bool:
        """
        Given a response, check if it matches the expected value.

        :param value: the expected value
        :type value: int
        :param response: the returned response
        :type response: str
        :return: if the value matches the response
        :rtype: bool
        """
        unpacked, = struct.unpack(">B", response)
        return value == unpacked

    def process_challenge_response(self, aggregate: dict, challenge: bytes, response: bytes) -> dict:
        """
        Given a response, update the current aggregate.

        :param aggregate: the aggregate object
        :type aggregate: dict
        :param challenge: the sent challenge
        :type challenge: str
        :param response: the response to introduce
        :type response: str
        :return: the new aggregate
        :rtype: dict
        """
        unpacked, = struct.unpack(">B", response)
        process_challenge_response(aggregate, unpacked)
        return aggregate

    def import_blob(self, blob: bytes) -> tuple[bytes, SecretKeyProtocol]:
        """
        Not supported.
        """
        raise NotImplementedError


__all__ = ["BonehAttestation", "BonehExactAlgorithm"]
