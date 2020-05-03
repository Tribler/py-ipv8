import struct

from .attestation import (attest_sha256, attest_sha256_4, attest_sha512, binary_relativity_certainty,
                          binary_relativity_sha256, binary_relativity_sha256_4, binary_relativity_sha512,
                          create_challenge, create_challenge_response_from_pair, create_empty_relativity_map,
                          create_honesty_check, process_challenge_response)
from .structs import BonehAttestation
from ..primitives.boneh import generate_keypair
from ..primitives.structs import BonehPrivateKey, BonehPublicKey, pack_pair, unpack_pair
from ...identity_formats import IdentityAlgorithm


class BonehExactAlgorithm(IdentityAlgorithm):

    def __init__(self, id_format, formats):
        super(BonehExactAlgorithm, self).__init__(id_format, formats)
        self.honesty_check = True

        # Check algorithm match
        if formats[id_format]["algorithm"] != "bonehexact":
            raise RuntimeError("Identity format linked to wrong algorithm")

        # Check key size match
        self.key_size = formats[self.id_format]["key_size"]
        if self.key_size < 32 or self.key_size > 512:
            raise RuntimeError("Illegal key size specified")

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
            raise RuntimeError("Unknown hashing mode")

    def generate_secret_key(self):
        """
        Generate a secret key.

        :return: the secret key
        """
        return generate_keypair(self.key_size)[1]

    def load_secret_key(self, serialized):
        """
        Unserialize a secret key from the key material.

        :param serialized: the string of the private key
        :return: the private key
        """
        return BonehPrivateKey.unserialize(serialized)

    def load_public_key(self, serialized):
        """
        Unserialize a public key from the key material.

        :param serialized: the string of the public key
        :return: the public key
        """
        return BonehPublicKey.unserialize(serialized)

    def get_attestation_class(self):
        """
        Return the Attestation (sub)class for serialization

        :return: the Attestation object
        :rtype: BonehAttestation
        """
        return BonehAttestation

    def attest(self, PK, value):
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

    def certainty(self, value, aggregate):
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

    def create_challenges(self, PK, attestation):
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

    def create_challenge_response(self, SK, attestation, challenge):
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

    def create_certainty_aggregate(self, attestation):
        """
        Create an empty aggregate object, for matching to values.

        :param attestation: the attestation information
        :type attestation: Attestation
        :return: the aggregate object
        :rtype: dict
        """
        return create_empty_relativity_map()

    def create_honesty_challenge(self, PK, value):
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

    def process_honesty_challenge(self, value, response):
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

    def process_challenge_response(self, aggregate, challenge, response):
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
        return process_challenge_response(aggregate, unpacked)


__all__ = ["BonehAttestation", "BonehExactAlgorithm"]
