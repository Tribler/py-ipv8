"""
Copyright (c) 2016, Maarten Everts
All rights reserved.

This source code has been ported from https://github.com/privacybydesign/gabi
The authors of this file are not -in any way- affiliated with the original authors or organizations.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.rsa import _modinv
from pyasn1.codec.ber.encoder import encode
from pyasn1.type import univ

from ...primitives.attestation import sha256_as_int
from ...primitives.value import FP2Value

if TYPE_CHECKING:
    from .keys import CLSignature, PublicKey

# ruff: noqa: N802,N803,N806,N815


class Record(univ.SequenceOf):
    """
    PyASN1 container for records (of integers).
    """

    componentType = univ.Integer()


def custom_asn1_marshal(values: list[int]) -> bytes:
    """
    Use ASN1 marshalling with universal integer encoding.
    """
    return encode(values, asn1Spec=Record())


def hashCommit(values: list[int], issig: bool) -> int:
    """
    Hash a list of values.
    """
    tmp = [1] if issig else []
    tmp = [*tmp, len(values), *values]
    r = custom_asn1_marshal(tmp)
    if issig:
        indx = r.find(b'\x02\x01\x01')
        r = r[:indx] + b'\x01\x01\xFF' + r[indx + 3:]
    return sha256_as_int(r)


def createChallenge(context: int, nonce: int, contributions: list[int], issig: bool) -> int:
    """
    Create a challenge for the given contributions.
    """
    return hashCommit([context, *contributions, nonce], issig)


class ProofU:
    """
    A proof of commitment to a value for U.
    """

    def __init__(self, U: int, C: int, VPrimeResponse: int, SResponse: int) -> None:
        """
        Store the proof information.
        """
        self.U = U
        self.C = C
        self.VPrimeResponse = VPrimeResponse
        self.SResponse = SResponse

    def MergeProofP(self, proofP: ProofP, pk: PublicKey) -> None:
        """
        Merge in a partial proof to reconstruct U.
        """
        self.U = (self.U * proofP.P) % pk.N
        self.SResponse = self.SResponse + proofP.SResponse

    def Verify(self, pk: PublicKey, context: int, nonce: int) -> bool:
        """
        Verify this proof for a given public key.
        """
        return self.VerifyWithChallenge(pk, createChallenge(context, nonce, self.ChallengeContribution(pk), False))

    def correctResponseSizes(self, pk: PublicKey) -> bool:
        """
        Check if our stored responses conform to the format of the given public key.
        """
        maximum = (1 << (pk.Params.LvPrimeCommit + 1)) - 1
        minimum = -maximum
        return self.VPrimeResponse >= minimum and self.VPrimeResponse <= maximum

    def VerifyWithChallenge(self, pk: PublicKey, reconstructedChallenge: int) -> bool:
        """
        Check if a given challenge is equal to our challenge.
        """
        return self.correctResponseSizes(pk) and reconstructedChallenge == self.C

    def reconstructUcommit(self, pk: PublicKey) -> int:
        """
        Construct the value for U from our challenge and responses.
        """
        Uc = FP2Value(pk.N, self.U).intpow(-self.C)
        Sv = FP2Value(pk.N, pk.S).intpow(self.VPrimeResponse)
        R0s = FP2Value(pk.N, pk.R[0]).intpow(self.SResponse)
        return (Uc * Sv * R0s).a

    def SecretKeyResponse(self) -> int:
        """
        The secret key response.
        """
        return self.SResponse

    def Challenge(self) -> int:
        """
        The challenge.
        """
        return self.C

    def ChallengeContribution(self, pk: PublicKey) -> list[int]:
        """
        Get our value for U and our reconstructed value for U, given the public key.
        """
        return [self.U, self.reconstructUcommit(pk)]


class ProofS:
    """
    A proof of signature issuance.
    """

    def __init__(self, C: int, EResponse: int) -> None:
        """
        Get a proof of issuance.
        """
        self.C = C
        self.EResponse = EResponse

    def Verify(self, pk: PublicKey, signature: CLSignature, context: int, nonce: int) -> bool:
        """
        Verify the issuance of the signature by a public key.
        """
        exponent = self.EResponse * signature.E + self.C
        ACommit = FP2Value(pk.N, signature.A).intpow(exponent).a
        Q = FP2Value(pk.N, signature.A).intpow(signature.E).a
        cPrime = hashCommit([context, Q, signature.A, nonce, ACommit], False)
        return cPrime == self.C


class ProofD:
    """
    A disclosure proof for identity information.
    """

    def __init__(self, C: int, A: int, EResponse: int, VResponse: int, AResponses: dict[int, int],  # noqa: PLR0913
                 ADisclosed: dict[int, int]) -> None:
        """
        Create a container for the necessary values.
        """
        self.C = C
        self.A = A
        self.EResponse = EResponse
        self.VResponse = VResponse
        self.AResponses = AResponses
        self.ADisclosed = ADisclosed

    def MergeProofP(self, proofP: ProofP, pk: PublicKey) -> None:
        """
        Merge in a partial proof.
        """
        self.AResponses[0] += proofP.SResponse

    def correctResponseSizes(self, pk: PublicKey) -> bool:
        """
        Check if our responses conform to the public key format.
        """
        maximum = (1 << (pk.Params.LmCommit + 1)) - 1
        minimum = -maximum

        for aResponse in self.AResponses:
            if aResponse < minimum or aResponse > maximum:
                return False

        maximum = (1 << (pk.Params.LeCommit + 1)) - 1
        minimum = -maximum

        if self.EResponse < minimum or self.EResponse > maximum:
            return False

        return True

    def reconstructZ(self, pk: PublicKey) -> int:
        """
        Reconstruct the value of Z using our information.
        """
        numerator = 1 << (pk.Params.Le - 1)
        numerator = FP2Value(pk.N, self.A).intpow(numerator).a

        for i, exp in self.ADisclosed.items():
            short_exp = sha256_as_int(str(exp)) if exp.bit_length() > pk.Params.Lm else exp
            numerator *= FP2Value(pk.N, pk.R[i]).intpow(short_exp).a
        numerator = numerator % pk.N

        known = pk.Z * _modinv(numerator, pk.N)
        knownC = FP2Value(pk.N, known).intpow(-self.C).a
        Ae = FP2Value(pk.N, self.A).intpow(self.EResponse).a
        Sv = FP2Value(pk.N, pk.S).intpow(self.VResponse).a
        Rs = 1
        for i, response in self.AResponses.items():
            Rs *= FP2Value(pk.N, pk.R[i]).intpow(response).a
        return (knownC * Ae * Rs * Sv) % pk.N

    def Verify(self, pk: PublicKey, context: int, nonce1: int, issig: bool) -> bool:
        """
        Verify this proof for the given public key.
        """
        return self.VerifyWithChallenge(pk, createChallenge(context, nonce1, self.ChallengeContribution(pk), issig))

    def VerifyWithChallenge(self, pk: PublicKey, reconstructedChallenge: int) -> bool:
        """
        Verify that the given challenge matches our challenge value.
        """
        return self.correctResponseSizes(pk) and reconstructedChallenge == self.C

    def ChallengeContribution(self, pk: PublicKey) -> list[int]:
        """
        Get our A and reconstructed Z.
        """
        return [self.A, self.reconstructZ(pk)]

    def SecretKeyResponse(self) -> int:
        """
        Get the secret key response value.
        """
        return self.AResponses[0]

    def Challenge(self) -> int:
        """
        Get our challenge.
        """
        return self.C

    def Copy(self) -> ProofD:
        """
        Create an exact copy of this instance.
        """
        ADisclosed = {}
        for k, v in self.ADisclosed.items():
            ADisclosed[k] = v
        return ProofD(self.C, self.A, self.EResponse, self.VResponse, self.AResponses, ADisclosed)


class ProofP:
    """
    Partial proof to reconstruct values.
    """

    def __init__(self, P: int, C: int, SResponse: int) -> None:
        """
        Create new partial proof information.
        """
        self.P = P
        self.C = C
        self.SResponse = SResponse


class ProofPCommitment:
    """
    A commitment to a value of P.
    """

    def __init__(self, P: int, Pcommit: int) -> None:
        """
        Create a new container.
        """
        self.P = P
        self.Pcommit = Pcommit
