"""
Copyright (c) 2016, Maarten Everts
All rights reserved.

This source code has been ported from https://github.com/privacybydesign/gabi
The authors of this file are not -in any way- affiliated with the original authors or organizations.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ...primitives.attestation import sha256_as_int
from ...primitives.value import FP2Value
from .. import secure_randint
from .proofs import ProofD, ProofPCommitment, hashCommit

if TYPE_CHECKING:
    from .keys import CLSignature, PublicKey

# ruff: noqa: N802,N803,N806


class Credential:
    """
    A credential (attributes + public key + signature).
    """

    def __init__(self, Pk: PublicKey, Attributes: list[int], Signature: CLSignature) -> None:
        """
        Create a new credential.
        """
        self.Signature = Signature
        self.Pk = Pk
        self.Attributes = Attributes

    def CreateDisclosureProof(self, disclosedAttributes: dict[int, int], context: int, nonce1: int) -> ProofD:
        """
        Create a disclosure proof for the specified attributes and their values.
        """
        undisclosedAttributes = getUndisclosedAttributes(disclosedAttributes, len(self.Attributes))

        randSig = self.Signature.Randomize(self.Pk)

        eCommit = secure_randint(self.Pk.Params.LeCommit)
        vCommit = secure_randint(self.Pk.Params.LvCommit)

        aCommits = {}

        for v in undisclosedAttributes:
            aCommits[v] = secure_randint(self.Pk.Params.LmCommit)

        Ae = FP2Value(self.Pk.N, randSig.A).intpow(eCommit).a
        Sv = FP2Value(self.Pk.N, self.Pk.S).intpow(vCommit).a
        Z = (Ae * Sv) % self.Pk.N

        for v in undisclosedAttributes:
            Z = (Z * FP2Value(self.Pk.N, self.Pk.R[v]).intpow(aCommits[v]).a) % self.Pk.N

        c = hashCommit([context, randSig.A, Z, nonce1], False)

        ePrime = randSig.E - (1 << (self.Pk.Params.Le - 1))
        eResponse = c * ePrime + eCommit
        vResponse = c * randSig.V + vCommit

        aResponses = {}
        for v in undisclosedAttributes:
            exp = self.Attributes[v]
            if exp.bit_length() > self.Pk.Params.Lm:
                exp = sha256_as_int(str(exp))
            t = c * exp
            aResponses[v] = t + aCommits[v]

        aDisclosed = {}
        for v in disclosedAttributes:
            aDisclosed[v] = self.Attributes[v]

        return ProofD(c, randSig.A, eResponse, vResponse, aResponses, aDisclosed)

    def CreateDisclosureProofBuilder(self, disclosedAttributes: dict[int, int]) -> DisclosureProofBuilder:
        """
        Create a disclosure proof builder for the specified attributes and their values.
        """
        return DisclosureProofBuilder(self.Signature.Randomize(self.Pk),
                                      secure_randint(self.Pk.Params.LeCommit),
                                      secure_randint(self.Pk.Params.LvCommit),
                                      {v: secure_randint(self.Pk.Params.LmCommit) for v
                                       in getUndisclosedAttributes(disclosedAttributes, len(self.Attributes))},
                                      1,
                                      disclosedAttributes,
                                      getUndisclosedAttributes(disclosedAttributes, len(self.Attributes)),
                                      self.Pk,
                                      self.Attributes)


class DisclosureProofBuilder:
    """
    Helper to create disclosure proofs.
    """

    def __init__(self, randomizedSignature: CLSignature,  # noqa: PLR0913
                 eCommit: int, vCommit: int,
                 attrRandomizers: dict[int, int],
                 z: int,
                 disclosedAttributes: dict[int, int], undisclosedAttributes: list[int],
                 pk: PublicKey, attributes: list[int]) -> None:
        """
        Create a new helper for the given information.
        """
        self.randomizedSignature = randomizedSignature
        self.eCommit = eCommit
        self.vCommit = vCommit
        self.attrRandomizers = attrRandomizers
        self.z = z
        self.disclosedAttributes = disclosedAttributes
        self.undisclosedAttributes = undisclosedAttributes
        self.pk = pk
        self.attributes = attributes

    def MergeProofPCommitment(self, commitment: ProofPCommitment) -> None:
        """
        Merge in a partial proof to reconstruct Z.
        """
        self.z = (self.z * commitment.Pcommit) % self.pk.N

    def PublicKey(self) -> PublicKey:
        """
        Get the public key.
        """
        return self.pk

    def Commit(self, skRandomizer: int) -> list[int]:
        """
        Get A and Z for the given randomizer.
        """
        self.attrRandomizers[0] = skRandomizer

        Ae = FP2Value(self.pk.N, self.randomizedSignature.A).intpow(self.eCommit).a
        Sv = FP2Value(self.pk.N, self.pk.S).intpow(self.vCommit).a
        self.z = (self.z * Ae * Sv) % self.pk.N

        for v in self.undisclosedAttributes:
            self.z = (self.z * FP2Value(self.pk.N, self.pk.R[v]).intpow(self.attrRandomizers[v]).a) % self.pk.N

        return [self.randomizedSignature.A, self.z]

    def CreateProof(self, challenge: int) -> ProofD:
        """
        Create a disclosure proof for the given challange.
        """
        ePrime = self.randomizedSignature.E - (1 << (self.pk.Params.Le - 1))
        eResponse = challenge * ePrime + self.eCommit
        vResponse = challenge * self.randomizedSignature.V + self.vCommit

        aResponses = {}
        for v in self.undisclosedAttributes:
            exp = self.attributes[v]
            if exp.bit_length() > self.pk.Params.Lm:
                exp = sha256_as_int(str(exp))
            aResponses[v] = challenge * exp + self.attrRandomizers[v]

        aDisclosed = {v: self.attributes[v] for v in self.disclosedAttributes}

        return ProofD(challenge, self.randomizedSignature.A, eResponse, vResponse, aResponses, aDisclosed)

    def TimestampRequestContributions(self) -> tuple[int, list[int]]:
        """
        Fill in the disclosed attributes into a complete list (0 when undisclosed).
        """
        disclosed = [0] * len(self.attributes)
        for i in self.disclosedAttributes:
            disclosed[i] = self.attributes[i]
        return self.randomizedSignature.A, disclosed


def getUndisclosedAttributes(disclosedAttributes: dict[int, int], numAttributes: int) -> list[int]:
    """
    Get the keys of undisclosed attributes.
    """
    return list(set(range(numAttributes)) - set(disclosedAttributes))
