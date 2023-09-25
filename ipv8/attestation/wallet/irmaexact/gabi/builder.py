"""
Copyright (c) 2016, Maarten Everts
All rights reserved.

This source code has been ported from https://github.com/privacybydesign/gabi
The authors of this file are not -in any way- affiliated with the original authors or organizations.
"""
from __future__ import annotations

from random import randint
from typing import cast

from cryptography.hazmat.primitives.asymmetric.rsa import _modinv

from ...primitives.value import FP2Value
from .. import secure_randint
from .credential import Credential
from .keys import CLSignature, DefaultSystemParameters, PrivateKey, PublicKey, signMessageBlockAndCommitment
from .proofs import ProofP, ProofPCommitment, ProofS, ProofU, createChallenge, hashCommit

# ruff: noqa: N802,N803,N806


class Issuer:
    """
    A signature issuer.
    """

    def __init__(self, Sk: PrivateKey, Pk: PublicKey, Context: int) -> None:
        """
        Create a new issuer.
        """
        self.Sk = Sk
        self.Pk = Pk
        self.Context = Context

    def IssueSignature(self, U: int, attributes: list[int], nonce2: int) -> IssueSignatureMessage:
        """
        Generate an issued signature message.
        """
        signature = self.signCommitmentAndAttributes(U, attributes)
        proof = self.proveSignature(signature, nonce2)
        return IssueSignatureMessage(signature, proof)

    def signCommitmentAndAttributes(self, U: int, attributes: list[int]) -> CLSignature:
        """
        Sign the commitment to the U value and given attribute values.
        """
        return signMessageBlockAndCommitment(self.Sk, self.Pk, U, [0, *attributes])

    def randomElementMultiplicativeGroup(self, modulus: int) -> int:
        """
        Generate a random number that is relatively coprime to the modulus.
        """
        r = 0
        while r <= 0 or _modinv(r, modulus) == 1:
            r = randint(1, modulus - 1)
        return r

    def proveSignature(self, signature: CLSignature, nonce2: int) -> ProofS:
        """
        Create a proof of signature issuance.
        """
        Q = FP2Value(self.Pk.N, signature.A).intpow(signature.E).a
        groupModulus = self.Sk.PPrime * self.Sk.QPrime
        d = FP2Value(groupModulus, signature.E).inverse().normalize().a

        eCommit = self.randomElementMultiplicativeGroup(groupModulus)
        ACommit = FP2Value(self.Pk.N, Q).intpow(eCommit).a

        c = hashCommit([self.Context, Q, signature.A, nonce2, ACommit], False)
        eResponse = (eCommit - c * d) % groupModulus

        return ProofS(c, eResponse)


def GetProofU(pl: list, n: int) -> ProofU | None:
    """
    Get the i'th (starting at 0) ProofU instance from a list of proof instances.
    """
    count = 0
    for proof in pl:
        if isinstance(proof, ProofU):
            if count == n:
                return proof
            count += 1
    return None


def GetFirstProofU(pl: list) -> ProofU | None:
    """
    Get the first ProofU from a given list of proofs.
    """
    return GetProofU(pl, 0)


def challengeContributions(pl: list, publicKeys: list[PublicKey], context: int, nonce: int) -> list[int]:
    """
    Aggregate all challenge contributions of a given proof list.
    """
    contributions = []
    for i in range(len(pl)):
        proof = pl[i]
        contributions.extend(proof.ChallengeContribution(publicKeys[i]))
    return contributions


def Verify(pl: list, publicKeys: list[PublicKey], context: int, nonce: int, issig: bool,
           keyshareServers: list | None = None) -> bool:
    """
    Verify a list of proofs for a list of public keys.
    """
    if keyshareServers is None:
        keyshareServers = []
    if not pl or len(pl) != len(publicKeys) or (len(keyshareServers) > 0 and len(pl) != len(keyshareServers)):
        return False

    secretkeyResponses = {}

    contributions = challengeContributions(pl, publicKeys, context, nonce)
    expectedChallenge = createChallenge(context, nonce, contributions, issig)

    kss = ""

    for i in range(len(pl)):
        proof = pl[i]
        if not proof.VerifyWithChallenge(publicKeys[i], expectedChallenge):
            return False
        if len(keyshareServers) > 0:
            kss = keyshareServers[i]
        if kss not in secretkeyResponses:
            secretkeyResponses[kss] = proof.SecretKeyResponse()
        elif secretkeyResponses[kss] != proof.SecretKeyResponse():
            return False

    return True


def Challenge(builders: list[CredentialBuilder], context: int, nonce: int, issig: bool) -> int:
    """
    Create a challenge.
    """
    skCommitment = secure_randint(DefaultSystemParameters[1024].LmCommit)

    commitmentValues = []
    for pb in builders:
        commitmentValues.extend(pb.Commit(skCommitment))

    return createChallenge(context, nonce, commitmentValues, issig)


def BuildDistributedProofList(builders: list[CredentialBuilder], challenge: int,
                              proofPs: list[ProofP]) -> list[ProofU] | None:
    """
    Create a proof list from multiple partial proofs.
    """
    if proofPs and len(builders) != len(proofPs):
        return None

    proofs = []

    for i in range(len(builders)):
        v = builders[i]
        proofs.append(v.CreateProof(challenge))
        if proofPs and proofPs[i]:
            proofs[i].MergeProofP(proofPs[i], v.PublicKey())

    return proofs


def BuildProofList(builders: list[CredentialBuilder], context: int, nonce: int, issig: bool) -> list[ProofU] | None:
    """
    Create a list of U proofs without distributed partial proofs.
    """
    challenge = Challenge(builders, context, nonce, issig)
    return BuildDistributedProofList(builders, challenge, [])


class IssueCommitmentMessage:
    """
    JWT commitment information.
    """

    def __init__(self, U: int | None, Proofs: list[ProofU] | None, Nonce2: int,
                 ProofPjwt: None = None, ProofPjwts: None = None) -> None:
        """
        Create a new issued commitment message container.
        """
        self.U = U
        self.Nonce2 = Nonce2
        self.Proofs = Proofs
        self.ProofPjwt = ProofPjwt
        self.ProofPjwts = ProofPjwts


class IssueSignatureMessage:
    """
    Issued signature information.
    """

    def __init__(self, Signature: CLSignature, Proof: ProofS) -> None:
        """
        Create a new signature message container.
        """
        self.Proof = Proof
        self.Signature = Signature


def commitmentToSecret(pk: PublicKey, secret: int) -> tuple[int, int]:
    """
    Create a commitment for a given value.
    """
    vPrime = secure_randint(pk.Params.LvPrime)

    Sv = FP2Value(pk.N, pk.S).intpow(vPrime).a
    R0s = FP2Value(pk.N, pk.R[0]).intpow(secret).a

    return vPrime, (Sv * R0s) % pk.N


class CredentialBuilder:
    """
    Helper class to create credentials.
    """

    def __init__(self, pk: PublicKey, context: int, secret: int, nonce2: int) -> None:
        """
        Create a new credential builder.
        """
        vPrime, U = commitmentToSecret(pk, secret)
        self.pk = pk
        self.context = context
        self.secret = secret
        self.vPrime = vPrime
        self.u = U
        self.uCommit = 1
        self.nonce2 = nonce2

        self.proofPcomm: ProofPCommitment | None = None
        self.skRandomizer: int | None = None
        self.vPrimeCommit: int | None = None

    def CommitToSecretAndProve(self, nonce1: int) -> IssueCommitmentMessage:
        """
        Create a commitment and associated message.
        """
        proofU = self.proveCommitment(self.u, nonce1)
        return IssueCommitmentMessage(self.u, [proofU], self.nonce2)

    def CreateIssueCommitmentMessage(self, proofs: list[ProofU]) -> IssueCommitmentMessage:
        """
        Create the associated message for given U commitments.
        """
        return IssueCommitmentMessage(self.u, proofs, self.nonce2)

    def ConstructCredential(self, msg: IssueSignatureMessage, attributes: list[int]) -> Credential | None:
        """
        Create a credential from the given signature message and our attributes.
        """
        if not msg.Proof.Verify(self.pk, msg.Signature, self.context, self.nonce2):
            return None

        signature = CLSignature(msg.Signature.A, msg.Signature.E, msg.Signature.V + self.vPrime)
        if self.proofPcomm:
            signature.KeyshareP = self.proofPcomm.P

        exponents = [self.secret, *attributes]

        if not signature.Verify(self.pk, exponents):
            return None

        return Credential(self.pk, exponents, signature)

    def proveCommitment(self, U: int, nonce1: int) -> ProofU:
        """
        Create a proof for the commitment to U.
        """
        sCommit = secure_randint(self.pk.Params.LsCommit)
        vPrimeCommit = secure_randint(self.pk.Params.LvPrimeCommit)

        Sv = FP2Value(self.pk.N, self.pk.S).intpow(vPrimeCommit).a
        R0s = FP2Value(self.pk.N, self.pk.R[0]).intpow(sCommit).a
        Ucommit = (Sv * R0s) % self.pk.N

        c = hashCommit([self.context, U, Ucommit, nonce1], False)
        sResponse = (c * self.secret) + sCommit
        vPrimeResponse = (c * self.vPrime) + vPrimeCommit

        return ProofU(U, c, vPrimeResponse, sResponse)

    def MergeProofPCommitment(self, commitment: ProofPCommitment) -> None:
        """
        Merge in a given commitment to a ProofP.
        """
        self.proofPcomm = commitment
        self.uCommit = (self.uCommit * commitment.Pcommit) % self.pk.N

    def PublicKey(self) -> PublicKey:
        """
        Our public key.
        """
        return self.pk

    def Commit(self, skRandomizer: int) -> list[int]:
        """
        Create a new commitment for the given randomizer value.
        """
        self.skRandomizer = skRandomizer
        self.vPrimeCommit = secure_randint(self.pk.Params.LvPrimeCommit)

        sv = FP2Value(self.pk.N, self.pk.S).intpow(self.vPrimeCommit).a
        r0s = FP2Value(self.pk.N, self.pk.R[0]).intpow(self.skRandomizer).a
        self.uCommit = (self.uCommit * sv * r0s) % self.pk.N

        ucomm = self.u
        if self.proofPcomm:
            ucomm = (ucomm * self.proofPcomm.P) % self.pk.N

        return [ucomm, self.uCommit]

    def CreateProof(self, challenge: int) -> ProofU:
        """
        Create a new proof for U for the given challenge.
        """
        sResponse = cast(int, self.skRandomizer) + challenge * self.secret
        vPrimeResponse = cast(int, self.vPrimeCommit) + challenge * self.vPrime

        return ProofU(self.u, challenge, vPrimeResponse, sResponse)
