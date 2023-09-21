from __future__ import annotations

import abc
import hashlib
from typing import TYPE_CHECKING, Any, Generic, TypeVar

if TYPE_CHECKING:
    from typing_extensions import Self

    from .wallet.database import SecretKeyProtocol


# ruff: noqa: ANN401,N803

class Attestation(metaclass=abc.ABCMeta):
    """
    An attestation for a public key of a value.

    !!! Requires implementation of a `.id_format` field.
    """

    id_format: str | None
    PK: Any

    @abc.abstractmethod
    def serialize(self) -> bytes:
        """
        Serialize this Attestation to a string.

        :return: the serialized form of this attestation
        :rtype: str
        """

    @abc.abstractmethod
    def serialize_private(self, PK: Any) -> bytes:
        """
        Serialize this Attestation to a string, include shared secrets (not to be published!).

        :param PK: the public key to encode for
        :return: the serialized form of this attestation
        :rtype: str
        """

    @classmethod
    def unserialize(cls: type[Self], s: bytes, id_format: str) -> Self:
        """
        Given a string, create an Attestation object.

        :param s: the string to unserialize
        :type s: str
        :param id_format: the identity format
        :type id_format: str
        :return: the attestation object
        :rtype: Attestation
        """
        raise NotImplementedError

    @classmethod
    def unserialize_private(cls: type[Self], SK: Any, s: bytes, id_format: str) -> Self:
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
        raise NotImplementedError

    def get_hash(self) -> bytes:
        """
        The hash over the public part of this Attestation.
        """
        return hashlib.sha1(self.serialize()).digest()

AT = TypeVar("AT", bound=Attestation)


class IdentityAlgorithm(Generic[AT], metaclass=abc.ABCMeta):
    """
    Interface for IPv8-compatible identity/credential algorithms.
    """

    def __init__(self, id_format: str, formats: dict[str, dict[str, Any]]) -> None:
        """
        Register a new algorithm of a certain format identifier and given format info.
        """
        self.id_format = id_format
        self.honesty_check = False

        if id_format not in formats:
            msg = "Tried to initialize with illegal identity format"
            raise RuntimeError(msg)

    @abc.abstractmethod
    def generate_secret_key(self) -> Any:
        """
        Generate a secret key.

        :return: the secret key
        """

    @abc.abstractmethod
    def load_secret_key(self, serialized: bytes) -> Any:
        """
        Unserialize a secret key from the key material.

        :param serialized: the string of the private key
        :return: the private key
        """

    @abc.abstractmethod
    def load_public_key(self, serialized: bytes) -> Any:
        """
        Unserialize a public key from the key material.

        :param serialized: the string of the public key
        :return: the public key
        """

    @abc.abstractmethod
    def get_attestation_class(self) -> type[AT]:
        """
        Return the Attestation (sub)class for serialization.

        :return: the Attestation object
        :rtype: Attestation
        """

    @abc.abstractmethod
    def attest(self, PK: Any, value: bytes) -> bytes:
        """
        Attest to a value for a certain public key.

        :param PK: the public key of the party we are attesting for
        :param value: the value we are attesting to
        :type value: str
        :return: the attestation string
        :rtype: str
        """

    @abc.abstractmethod
    def certainty(self, value: bytes, aggregate: dict) -> float:
        """
        The current certainty of the aggregate object representing a certain value.

        :param value: the value to match to
        :type value: str
        :param aggregate: the aggregate object
        :return: the matching factor [0.0-1.0]
        :rtype: float
        """

    @abc.abstractmethod
    def create_challenges(self, PK: Any, attestation: AT) -> list[bytes]:
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
    def create_challenge_response(self, SK: Any, attestation: AT, challenge: bytes) -> bytes:
        """
        Create an honest response to a challenge of our value.

        :param SK: our secret key
        :param attestation: the attestation information
        :type attestation: Attestation
        :param challenge: the challenge to respond to
        :return: the response to a challenge
        :rtype: str
        """

    @abc.abstractmethod
    def create_certainty_aggregate(self, attestation: AT | None) -> dict:
        """
        Create an empty aggregate object, for matching to values.

        :param attestation: the attestation information
        :type attestation: Attestation
        :return: the aggregate object
        """

    @abc.abstractmethod
    def create_honesty_challenge(self, PK: Any, value: int) -> bytes:
        """
        Use a known value to check for honesty.

        :param PK: the public key of the party we are challenging
        :param value: the value to use
        :type value: str
        :return: the challenge to send
        :rtype: str
        """

    @abc.abstractmethod
    def process_honesty_challenge(self, value: int, response: bytes) -> bool:
        """
        Given a response, check if it matches the expected value.

        :param value: the expected value
        :param response: the returned response
        :type response: str
        :return: if the value matches the response
        :rtype: bool
        """

    @abc.abstractmethod
    def process_challenge_response(self, aggregate: dict, challenge: bytes, response: bytes) -> dict:
        """
        Given a response, update the current aggregate.

        :param aggregate: the aggregate object
        :param challenge: the sent challenge
        :type challenge: str
        :param response: the response to introduce
        :type response: str
        :return: the new aggregate
        """

    @abc.abstractmethod
    def import_blob(self, blob: bytes) -> tuple[bytes, SecretKeyProtocol]:
        """
        Directly import a raw serialized form.
        """


__all__ = ["IdentityAlgorithm", "Attestation"]
