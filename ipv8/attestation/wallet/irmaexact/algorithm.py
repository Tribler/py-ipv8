from __future__ import annotations

import binascii
import json
import os
from typing import Any, cast

from ...identity_formats import Attestation, IdentityAlgorithm
from ..primitives.structs import ipack, iunpack
from .gabi.attributes import make_attribute_list
from .gabi.keys import DefaultSystemParameters
from .gabi.proofs import ProofD, createChallenge
from .wrappers import challenge_response, serialize_proof_d, unserialize_proof_d

# ruff: noqa: N803,N806


class IRMAAttestation(Attestation):
    """
    IPv8 wrapper for IRMA-based attestations.
    """

    def __init__(self, sign_date: int, proofd: ProofD, z: int | None = None) -> None:
        """
        Create a new IPv8 attestation for the given diclosure proof and Z value.
        """
        self.sign_date = sign_date
        self.proofd = proofd
        self.z = z

    def serialize(self) -> bytes:
        """
        Make this attestation transferrable.
        """
        return ipack(self.sign_date) + serialize_proof_d(self.proofd)

    def serialize_private(self, PK: None) -> bytes:
        """
        We don't use a base key for serialization.
        """
        return ipack(cast(int, self.z)) + ipack(self.sign_date) + serialize_proof_d(self.proofd)

    @classmethod
    def unserialize(cls: type[IRMAAttestation], s: bytes, id_format: str) -> IRMAAttestation:  # noqa: ARG003
        """
        Read an attestation from its serialized form.
        """
        sign_date, rem = iunpack(s)
        return IRMAAttestation(sign_date, unserialize_proof_d(rem))

    @classmethod
    def unserialize_private(cls: type[IRMAAttestation], SK: None,  # noqa: ARG003
                            s: bytes, id_format: str) -> IRMAAttestation:  # noqa: ARG003
        """
        Read the secret part of an attestation from its serialized form.
        """
        z, rem = iunpack(s)
        sign_date, rem = iunpack(rem)
        return IRMAAttestation(sign_date, unserialize_proof_d(rem), z)


class KeyStub:
    """
    We don't use an IPv8 key for this algorithm.
    """

    def public_key(self) -> KeyStub:
        """
        The public part of this key.
        """
        return self

    def serialize(self) -> bytes:
        """
        The serialized form of this key.
        """
        return b''

    @classmethod
    def unserialize(cls: type[KeyStub], s: bytes) -> KeyStub:  # noqa: ARG003
        """
        Load the key from the given bytes.
        """
        return KeyStub()


class IRMAExactAlgorithm(IdentityAlgorithm):
    """
    IPv8 wrapper around the IRMA business logic.
    """

    def __init__(self, id_format: str, formats: dict[str, dict[str, Any]]) -> None:
        """
        Create a new IRMA wrapper.
        """
        super().__init__(id_format, formats)

        # Check algorithm match
        if formats[id_format]["algorithm"] != "irmaexact":
            msg = "Identity format linked to wrong algorithm"
            raise RuntimeError(msg)

        self.issuer_pk = formats[self.id_format]["issuer_pk"]
        self.attribute_order = formats[self.id_format]["order"]
        self.validity = formats[self.id_format]["validity"]

        self.base_meta = {
            "credential": formats[self.id_format]["credential"],
            "keyCounter": formats[self.id_format]["keyCounter"],
            "validity": formats[self.id_format]["validity"]
        }

        self.system_parameters = DefaultSystemParameters[1024]
        self.challenge_count = 8

    def generate_secret_key(self) -> KeyStub:
        """
        Generate a fake secret key, we need none.
        """
        return KeyStub()

    def load_secret_key(self, serialized: bytes) -> KeyStub:
        """
        Load a fake secret key, we need none.
        """
        return KeyStub()

    def load_public_key(self, serialized: bytes) -> KeyStub:
        """
        Load a fake public key, we need none.
        """
        return KeyStub()

    def get_attestation_class(self) -> type[IRMAAttestation]:
        """
        Get our class.
        """
        return IRMAAttestation

    def attest(self, PK: KeyStub, value: bytes) -> bytes:
        """
        Not implemented.
        """
        raise NotImplementedError("Only import_blob is supported (now) for IRMA.")

    def certainty(self, value: bytes, aggregate: dict) -> float:
        """
        Get the certainty that the given value is equal to the attestation in the aggregate.
        """
        value_json = {"attributes": json.loads(value)}
        value_json.update(self.base_meta)
        attestation = cast(IRMAAttestation, aggregate['attestation'])
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

    def create_challenges(self, PK: KeyStub, attestation: IRMAAttestation) -> list[bytes]:
        """
        Generate the raw messages to be sent over the Internet as challenges.
        """
        return [ipack(int(binascii.hexlify(os.urandom(32)), 16) % self.issuer_pk.N)
                for _ in range(self.challenge_count)]

    def create_challenge_response(self, SK: KeyStub, attestation: IRMAAttestation, challenge: bytes) -> bytes:
        """
        Create a response to a given challenge to our attestation.
        """
        return challenge_response(attestation.proofd, cast(int, attestation.z), challenge)

    def create_certainty_aggregate(self, attestation: IRMAAttestation | None) -> dict:
        """
        Create the aggregation dictionary (just one key with the attestation).
        """
        return {'attestation': attestation}

    def create_honesty_challenge(self, PK: KeyStub, value: int) -> bytes:
        """
        Not implemented.
        """
        raise NotImplementedError

    def process_honesty_challenge(self, value: int, response: bytes) -> bool:
        """
        Not implemented.
        """
        raise NotImplementedError

    def process_challenge_response(self, aggregate: dict, challenge: bytes, response: bytes) -> dict:
        """
        Process the response to our challenge.
        """
        aggregate[challenge] = response
        return aggregate

    def import_blob(self, blob: bytes) -> tuple[bytes, KeyStub]:
        """
        Import raw data needed to construct an attestation for this algorithm.
        """
        blob_json = json.loads(blob)

        sign_date = blob_json["sign_date"]
        proofd = unserialize_proof_d(binascii.unhexlify(blob_json["proofd"]))
        z = blob_json["z"]

        inst = self.get_attestation_class()(sign_date, proofd, z)

        return inst.serialize_private(None), KeyStub()
