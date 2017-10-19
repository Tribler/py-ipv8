from ...deprecated.payload import Payload


class AttestationChunkPayload(Payload):
    """
    A chunk of Attestation.
    """
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
    format_list = ['raw']

    def __init__(self, challenge):
        self.challenge = challenge

    def to_pack_list(self):
        data = [('raw', self.challenge)]
        return data

    @classmethod
    def from_unpack_list(cls, challenge):
        return cls(challenge)


class ChallengeResponsePayload(Payload):
    """
    A challenge response from an Attestee to a Verifier
    """
    format_list = ['20s', 'B']

    def __init__(self, challenge_hash, response):
        self.challenge_hash = challenge_hash
        self.response = response

    def to_pack_list(self):
        data = [('20s', self.challenge_hash),
                ('B', self.response)]
        return data

    @classmethod
    def from_unpack_list(cls, challenge_hash, response):
        return cls(challenge_hash, response)
