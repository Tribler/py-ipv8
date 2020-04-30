import abc
import hashlib


class IdentityAlgorithm(metaclass=abc.ABCMeta):

    def __init__(self, id_format, formats):
        self.id_format = id_format
        self.honesty_check = False

        if id_format not in formats:
            raise RuntimeError("Tried to initialize with illegal identity format")

    @abc.abstractmethod
    def generate_secret_key(self):
        """
        Generate a secret key.

        :return: the secret key
        """
        pass

    @abc.abstractmethod
    def load_secret_key(self, serialized):
        """
        Unserialize a secret key from the key material.

        :param serialized: the string of the private key
        :return: the private key
        """
        pass

    @abc.abstractmethod
    def load_public_key(self, serialized):
        """
        Unserialize a public key from the key material.

        :param serialized: the string of the public key
        :return: the public key
        """
        pass

    @abc.abstractmethod
    def get_attestation_class(self):
        """
        Return the Attestation (sub)class for serialization

        :return: the Attestation object
        :rtype: Attestation
        """
        pass

    @abc.abstractmethod
    def attest(self, PK, value):
        """
        Attest to a value for a certain public key.

        :param PK: the public key of the party we are attesting for
        :param value: the value we are attesting to
        :type value: str
        :return: the attestation string
        :rtype: str
        """
        pass

    @abc.abstractmethod
    def certainty(self, value, aggregate):
        """
        The current certainty of the aggregate object representing a certain value.

        :param value: the value to match to
        :type value: str
        :param aggregate: the aggregate object
        :return: the matching factor [0.0-1.0]
        :rtype: float
        """
        pass

    @abc.abstractmethod
    def create_challenges(self, PK, attestation):
        """
        Create challenges for a certain counterparty.

        :param PK: the public key of the party we are challenging
        :type PK: BonehPublicKey
        :param attestation: the attestation information
        :type attestation: Attestation
        :return: the challenges to send
        :rtype: [str]
        """

    @abc.abstractmethod
    def create_challenge_response(self, SK, attestation, challenge):
        """
        Create an honest response to a challenge of our value.

        :param SK: our secret key
        :param attestation: the attestation information
        :type attestation: Attestation
        :param challenge: the challenge to respond to
        :return: the response to a challenge
        :rtype: str
        """
        pass

    @abc.abstractmethod
    def create_certainty_aggregate(self, attestation):
        """
        Create an empty aggregate object, for matching to values.

        :param attestation: the attestation information
        :type attestation: Attestation
        :return: the aggregate object
        """
        pass

    @abc.abstractmethod
    def create_honesty_challenge(self, PK, value):
        """
        Use a known value to check for honesty.

        :param PK: the public key of the party we are challenging
        :param value: the value to use
        :type value: str
        :return: the challenge to send
        :rtype: str
        """
        pass

    @abc.abstractmethod
    def process_honesty_challenge(self, value, response):
        """
        Given a response, check if it matches the expected value.

        :param value: the expected value
        :param response: the returned response
        :type response: str
        :return: if the value matches the response
        :rtype: bool
        """

    @abc.abstractmethod
    def process_challenge_response(self, aggregate, challenge, response):
        """
        Given a response, update the current aggregate.

        :param aggregate: the aggregate object
        :param challenge: the sent challenge
        :type challenge: str
        :param response: the response to introduce
        :type response: str
        :return: the new aggregate
        """
        pass


class Attestation(metaclass=abc.ABCMeta):
    """
    An attestation for a public key of a value.

    !!! Requires implementation of a `.id_format` field.
    """

    @abc.abstractmethod
    def serialize(self):
        """
        Serialize this Attestation to a string.

        :return: the serialized form of this attestation
        :rtype: str
        """
        pass

    @abc.abstractmethod
    def serialize_private(self, PK):
        """
        Serialize this Attestation to a string, include shared secrets (not to be published!).

        :param PK: the public key to encode for
        :return: the serialized form of this attestation
        :rtype: str
        """
        pass

    @classmethod
    def unserialize(cls, s, id_format):
        """
        Given a string, create an Attestation object.

        :param s: the string to unserialize
        :type s: str
        :param id_format: the identity format
        :type id_format: str
        :return: the attestation object
        :rtype: Attestation
        """
        raise NotImplementedError()

    @classmethod
    def unserialize_private(cls, SK, s, id_format):
        """
        Given a string, create an Attestation object.
        The input contains shared secrets not to be published.

        :param SK: the secret key to decode with
        :param s: the string to unserialize
        :type s: str
        :param id_format: the identity format
        :type id_format: str
        :return: the attestation object
        :rtype: Attestation
        """
        raise NotImplementedError()

    def get_hash(self):
        """
        The hash over the public part of this Attestation.
        """
        return hashlib.sha1(self.serialize()).digest()


__all__ = ["IdentityAlgorithm", "Attestation"]
