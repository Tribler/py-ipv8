from ...messaging.payload import Payload


class RequestAttestationPayload(Payload):
    """
    Request an attestation based on some meta data.
    """
    msg_id = 5
    format_list = ['raw']

    def __init__(self, metadata):
        super(RequestAttestationPayload, self).__init__()
        self.metadata = metadata

    def to_pack_list(self):
        data = [('raw', self.metadata)]
        return data

    @classmethod
    def from_unpack_list(cls, metadata):
        return cls(metadata)


class VerifyAttestationRequestPayload(Payload):
    """
    Request an attestation by hash (published with metadata somewhere).
    """
    msg_id = 1
    format_list = ['20s']

    def __init__(self, hash):
        super(VerifyAttestationRequestPayload, self).__init__()
        self.hash = hash

    def to_pack_list(self):
        data = [('20s', self.hash)]
        return data

    @classmethod
    def from_unpack_list(cls, hash):
        return cls(hash)


class AttestationChunkPayload(Payload):
    """
    A chunk of Attestation.
    """
    msg_id = 2
    format_list = ['20s', 'H', 'raw']

    def __init__(self, hash, sequence_number, data):
        super(AttestationChunkPayload, self).__init__()
        self.hash = hash
        self.sequence_number = sequence_number
        self.data = data

    def to_pack_list(self):
        data = [('20s', self.hash),
                ('H', self.sequence_number),
                ('raw', self.data)]

        return data

    @classmethod
    def from_unpack_list(cls, hash, sequence_number, data):
        return cls(hash, sequence_number, data)


class ChallengePayload(Payload):
    """
    A challenge for an Attestee by a Verifier
    """
    msg_id = 3
    format_list = ['20s', 'raw']

    def __init__(self, attestation_hash, challenge):
        self.attestation_hash = attestation_hash
        self.challenge = challenge

    def to_pack_list(self):
        data = [('20s', self.attestation_hash),
                ('raw', self.challenge)]
        return data

    @classmethod
    def from_unpack_list(cls, attestation_hash, challenge):
        return cls(attestation_hash, challenge)


class ChallengeResponsePayload(Payload):
    """
    A challenge response from an Attestee to a Verifier
    """
    msg_id = 4
    format_list = ['20s', 'raw']

    def __init__(self, challenge_hash, response):
        self.challenge_hash = challenge_hash
        self.response = response

    def to_pack_list(self):
        data = [('20s', self.challenge_hash),
                ('raw', self.response)]
        return data

    @classmethod
    def from_unpack_list(cls, challenge_hash, response):
        return cls(challenge_hash, response)
