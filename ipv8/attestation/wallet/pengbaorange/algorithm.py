import struct
from binascii import hexlify
from os import urandom

from ..pengbaorange.attestation import create_attest_pair
from ..pengbaorange.structs import PengBaoAttestation
from ..primitives.boneh import generate_keypair
from ..primitives.structs import BonehPrivateKey, BonehPublicKey, pack_pair, unpack_pair
from ...identity_formats import IdentityAlgorithm

LARGE_INTEGER = 32765


def _safe_rndint(key_size, mod):
    """
    Generate a urandom number which is larger than LARGE_INTEGER.

    :param key_size: the bitspace of the number
    :param mod: the modulo
    :return: the random value
    """
    rndint = lambda: int(hexlify(urandom(key_size // 8)), 16) % mod
    out = rndint()
    while out < LARGE_INTEGER:
        out = rndint()
    return out


class PengBaoRangeAlgorithm(IdentityAlgorithm):

    def __init__(self, id_format, formats):
        super(PengBaoRangeAlgorithm, self).__init__(id_format, formats)

        # Check algorithm match
        if formats[id_format]["algorithm"] != "pengbaorange":
            raise RuntimeError("Identity format linked to wrong algorithm")

        # Check key size match
        self.key_size = formats[self.id_format]["key_size"]
        if self.key_size < 32 or self.key_size > 512:
            raise RuntimeError("Illegal key size specified")

        self.a = formats[self.id_format]["min"]
        self.b = formats[self.id_format]["max"]

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
        :rtype: PengBaoAttestation
        """
        return PengBaoAttestation

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
        ivalue = int(hexlify(value), 16)
        return create_attest_pair(PK, ivalue, self.a, self.b, self.key_size).serialize_private(PK)

    def certainty(self, value, aggregate):
        """
        The current certainty of the aggregate object representing a certain value.

        1 is in range, 0 is out of range.

        :param value: the value to match to
        :type value: str
        :param aggregate: the aggregate object
        :type aggregate: dict
        :return: the matching factor [0.0-1.0]
        :rtype: float
        """
        in_range = len(aggregate) > 1
        for k, v in aggregate.items():
            if k != 'attestation':
                in_range &= v
        match = 1.0 if in_range else 0.0
        return match if struct.unpack('>?', value)[0] else 1.0 - match

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
        mod = PK.g.mod - 1
        challenges = [pack_pair(_safe_rndint(self.key_size, mod), _safe_rndint(self.key_size, mod)) for _ in range(1)]
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
        s, t = unpack_pair(challenge)[0:2]
        # If someone is trying to cheat us by selecting an s or t which is too small, we return random garbage.
        if s < LARGE_INTEGER or t < LARGE_INTEGER:
            return (pack_pair(_safe_rndint(self.key_size, SK.g.mod), _safe_rndint(self.key_size, SK.g.mod))
                    + pack_pair(_safe_rndint(self.key_size, SK.g.mod), _safe_rndint(self.key_size, SK.g.mod)))
        x, y, u, v = attestation.privatedata.generate_response(s, t)
        return pack_pair(x, y) + pack_pair(u, v)

    def create_certainty_aggregate(self, attestation):
        """
        Create an empty aggregate object, for matching to values.

        :return: the aggregate object
        :rtype: dict
        """
        return {'attestation': attestation}

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
        raise NotImplementedError()

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
        raise NotImplementedError()

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
        x, y, rem = unpack_pair(response)
        u, v, _ = unpack_pair(rem)
        s, t, _ = unpack_pair(challenge)
        attestation = aggregate['attestation']
        aggregate[challenge] = attestation.publicdata.check(self.a, self.b, s, t, x, y, u, v)
        return aggregate


__all__ = ["PengBaoAttestation", "PengBaoRangeAlgorithm"]
