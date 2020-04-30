import binascii
import json
import os

from .gabi.attributes import make_attribute_list
from .gabi.keys import DefaultSystemParameters
from .gabi.proofs import createChallenge
from .wrappers import challenge_response, serialize_proof_d, unserialize_proof_d
from ..primitives.structs import ipack, iunpack
from ...identity_formats import Attestation, IdentityAlgorithm


class IRMAAttestation(Attestation):

    def __init__(self, sign_date, proofd, z=None):
        self.sign_date = sign_date
        self.proofd = proofd
        self.z = z

    def serialize(self):
        return ipack(self.sign_date) + serialize_proof_d(self.proofd)

    def serialize_private(self, PK):
        return ipack(self.z) + ipack(self.sign_date) + serialize_proof_d(self.proofd)

    @classmethod
    def unserialize(cls, s, id_format):
        sign_date, rem = iunpack(s)
        return IRMAAttestation(sign_date, unserialize_proof_d(rem))

    @classmethod
    def unserialize_private(cls, SK, s, id_format):
        z, rem = iunpack(s)
        sign_date, rem = iunpack(rem)
        return IRMAAttestation(sign_date, unserialize_proof_d(rem), z)


class KeyStub(object):

    def public_key(self):
        return self

    def serialize(self):
        return b''

    @classmethod
    def unserialize(cls, s):
        return KeyStub()


class IRMAExactAlgorithm(IdentityAlgorithm):

    def __init__(self, id_format, formats):
        super(IRMAExactAlgorithm, self).__init__(id_format, formats)

        # Check algorithm match
        if formats[id_format]["algorithm"] != "irmaexact":
            raise RuntimeError("Identity format linked to wrong algorithm")

        self.issuer_pk = formats[self.id_format]["issuer_pk"]
        self.attribute_order = formats[self.id_format]["order"]
        self.validity = formats[self.id_format]["validity"]

        self.base_meta = {
            u"credential": formats[self.id_format]["credential"],
            u"keyCounter": formats[self.id_format]["keyCounter"],
            u"validity": formats[self.id_format]["validity"]
        }

        self.system_parameters = DefaultSystemParameters[1024]
        self.challenge_count = 8

    def generate_secret_key(self):
        return KeyStub()

    def load_secret_key(self, serialized):
        return KeyStub()

    def load_public_key(self, serialized):
        return KeyStub()

    def get_attestation_class(self):
        return IRMAAttestation

    def attest(self, PK, value):
        raise NotImplementedError("Only import_blob is supported (now) for IRMA.")

    def certainty(self, value, aggregate):
        value_json = {u"attributes": json.loads(value)}
        value_json.update(self.base_meta)
        attestation = aggregate['attestation']
        attr_ints, sign_date = make_attribute_list(value_json, self.attribute_order,
                                                   (self.validity, attestation.sign_date))
        reconstructed_attr_map = {}
        for i in range(len(attr_ints)):
            reconstructed_attr_map[i + 1] = attr_ints[i]

        verified = 0.0
        failure = False
        for k, v in aggregate.items():
            if k != 'attestation' and v:
                challenge_verif, _ = iunpack(k)
                p = attestation.proofd.Copy()
                p.ADisclosed = reconstructed_attr_map
                Ap, Zp = p.ChallengeContribution(self.issuer_pk)
                p.C, _ = iunpack(v)
                reconstructed_challenge = createChallenge(challenge_verif, challenge_verif, [Ap, Zp], False)
                if p.VerifyWithChallenge(self.issuer_pk, reconstructed_challenge):
                    verified += 1.0
                else:
                    failure = True

        return 0.0 if failure else (verified / self.challenge_count)

    def create_challenges(self, PK, attestation):
        return [ipack(int(binascii.hexlify(os.urandom(32)), 16) % self.issuer_pk.N)
                for _ in range(self.challenge_count)]

    def create_challenge_response(self, SK, attestation, challenge):
        return challenge_response(attestation.proofd, attestation.z, challenge)

    def create_certainty_aggregate(self, attestation):
        return {'attestation': attestation}

    def create_honesty_challenge(self, PK, value):
        raise NotImplementedError()

    def process_honesty_challenge(self, value, response):
        raise NotImplementedError()

    def process_challenge_response(self, aggregate, challenge, response):
        aggregate[challenge] = response

    def import_blob(self, blob):
        blob_json = json.loads(blob)

        sign_date = blob_json["sign_date"]
        proofd = unserialize_proof_d(binascii.unhexlify(blob_json["proofd"]))
        z = blob_json["z"]

        inst = self.get_attestation_class()(sign_date, proofd, z)

        return inst.serialize_private(None), None
