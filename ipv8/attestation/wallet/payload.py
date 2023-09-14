from __future__ import annotations

from ...messaging.payload import Payload


class RequestAttestationPayload(Payload):
    """
    Request an attestation based on some meta data.
    """

    msg_id = 5
    format_list = ['raw']

    def __init__(self, metadata: bytes) -> None:
        """
        Create a new payload to request attestations.
        """
        super().__init__()
        self.metadata = metadata

    def to_pack_list(self) -> list[tuple]:
        """
        Convert this payload to a serializable pack list.
        """
        return [('raw', self.metadata)]

    @classmethod
    def from_unpack_list(cls: type[RequestAttestationPayload], metadata: bytes) -> RequestAttestationPayload:
        """
        Unserialize this paylaod from received bytes.
        """
        return cls(metadata)


class VerifyAttestationRequestPayload(Payload):
    """
    Request an attestation by hash (published with metadata somewhere).
    """

    msg_id = 1
    format_list = ['20s']

    def __init__(self, hash: bytes) -> None:  # noqa: A002
        """
        Create a new payload to request verification of an attestation.
        """
        super().__init__()
        self.hash = hash

    def to_pack_list(self) -> list[tuple]:
        """
        Convert this payload to a serializable pack list.
        """
        return [('20s', self.hash)]

    @classmethod
    def from_unpack_list(cls: type[VerifyAttestationRequestPayload],
                         hash: bytes) -> VerifyAttestationRequestPayload:  # noqa: A002
        """
        Unserialize this paylaod from received bytes.
        """
        return cls(hash)


class AttestationChunkPayload(Payload):
    """
    A chunk of Attestation.
    """

    msg_id = 2
    format_list = ['20s', 'H', 'raw']

    def __init__(self, hash: bytes, sequence_number: int, data: bytes) -> None:  # noqa: A002
        """
        Create a new payload to send an attestation.
        """
        super().__init__()
        self.hash = hash
        self.sequence_number = sequence_number
        self.data = data

    def to_pack_list(self) -> list[tuple]:
        """
        Convert this payload to a serializable pack list.
        """
        return [('20s', self.hash),
                ('H', self.sequence_number),
                ('raw', self.data)]


    @classmethod
    def from_unpack_list(cls: type[AttestationChunkPayload], hash: bytes,  # noqa: A002
                         sequence_number: int, data: bytes) -> AttestationChunkPayload:
        """
        Unserialize this paylaod from received bytes.
        """
        return cls(hash, sequence_number, data)


class ChallengePayload(Payload):
    """
    A challenge for an Attestee by a Verifier.
    """

    msg_id = 3
    format_list = ['20s', 'raw']

    def __init__(self, attestation_hash: bytes, challenge: bytes) -> None:
        """
        Create a new payload to send challenges to an attestation.
        """
        self.attestation_hash = attestation_hash
        self.challenge = challenge

    def to_pack_list(self) -> list[tuple]:
        """
        Convert this payload to a serializable pack list.
        """
        return [('20s', self.attestation_hash),
                ('raw', self.challenge)]

    @classmethod
    def from_unpack_list(cls: type[ChallengePayload], attestation_hash: bytes, challenge: bytes) -> ChallengePayload:
        """
        Unserialize this paylaod from received bytes.
        """
        return cls(attestation_hash, challenge)


class ChallengeResponsePayload(Payload):
    """
    A challenge response from an Attestee to a Verifier.
    """

    msg_id = 4
    format_list = ['20s', 'raw']

    def __init__(self, challenge_hash: bytes, response: bytes) -> None:
        """
        Create a new payload to responds to challenges.
        """
        self.challenge_hash = challenge_hash
        self.response = response

    def to_pack_list(self) -> list[tuple]:
        """
        Convert this payload to a serializable pack list.
        """
        return [('20s', self.challenge_hash),
                ('raw', self.response)]

    @classmethod
    def from_unpack_list(cls: type[ChallengeResponsePayload], challenge_hash: bytes,
                         response: bytes) -> ChallengeResponsePayload:
        """
        Unserialize this paylaod from received bytes.
        """
        return cls(challenge_hash, response)
