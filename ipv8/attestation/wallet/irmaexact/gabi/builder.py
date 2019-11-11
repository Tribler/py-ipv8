"""
Copyright (c) 2016, Maarten Everts
All rights reserved.

This source code has been ported from https://github.com/privacybydesign/gabi
The authors of this file are not -in any way- affiliated with the original authors or organizations.
"""
from random import randint

from cryptography.hazmat.primitives.asymmetric.rsa import _modinv

from .credential import Credential
from .keys import CLSignature, DefaultSystemParameters, signMessageBlockAndCommitment
from .proofs import ProofS, ProofU, createChallenge, hashCommit
from .. import secure_randint
from ...primitives.value import FP2Value


class Issuer(object):

    def __init__(self, Sk, Pk, Context):
        self.Sk = Sk
        self.Pk = Pk
        self.Context = Context

    def IssueSignature(self, U, attributes, nonce2):
        signature = self.signCommitmentAndAttributes(U, attributes)
        proof = self.proveSignature(signature, nonce2)
        return IssueSignatureMessage(signature, proof)

    def signCommitmentAndAttributes(self, U, attributes):
        return signMessageBlockAndCommitment(self.Sk, self.Pk, U, [0] + attributes)

    def randomElementMultiplicativeGroup(self, modulus):
        r = 0
        while r <= 0 or _modinv(r, modulus) == 1:
            r = randint(1, modulus - 1)
        return r

    def proveSignature(self, signature, nonce2):
        Q = FP2Value(self.Pk.N, signature.A).intpow(signature.E).a
        groupModulus = self.Sk.PPrime * self.Sk.QPrime
        d = FP2Value(groupModulus, signature.E).inverse().normalize().a

        eCommit = self.randomElementMultiplicativeGroup(groupModulus)
        ACommit = FP2Value(self.Pk.N, Q).intpow(eCommit).a

        c = hashCommit([self.Context, Q, signature.A, nonce2, ACommit], False)
        eResponse = (eCommit - c * d) % groupModulus

        return ProofS(c, eResponse)


def GetProofU(pl, n):
    count = 0
    for proof in pl:
        if isinstance(proof, ProofU):
            if count == n:
                return proof
            count += 1
    return None


def GetFirstProofU(pl):
    return GetProofU(pl, 0)


def challengeContributions(pl, publicKeys, context, nonce):
    contributions = []
    for i in range(len(pl)):
        proof = pl[i]
        contributions.extend(proof.ChallengeContribution(publicKeys[i]))
    return contributions


def Verify(pl, publicKeys, context, nonce, issig, keyshareServers=[]):
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
        else:
            if secretkeyResponses[kss] != proof.SecretKeyResponse():
                return False

    return True


def Challenge(builders, context, nonce, issig):
    skCommitment = secure_randint(DefaultSystemParameters[1024].LmCommit)

    commitmentValues = []
    for pb in builders:
        commitmentValues.extend(pb.Commit(skCommitment))

    return createChallenge(context, nonce, commitmentValues, issig)


def BuildDistributedProofList(builders, challenge, proofPs):
    if proofPs and len(builders) != len(proofPs):
        return None

    proofs = []

    for i in range(len(builders)):
        v = builders[i]
        proofs.append(v.CreateProof(challenge))
        if proofPs and proofPs[i]:
            proofs[i].MergeProofP(proofPs[i], v.PublicKey())

    return proofs


def BuildProofList(builders, context, nonce, issig):
    challenge = Challenge(builders, context, nonce, issig)
    return BuildDistributedProofList(builders, challenge, [])


class IssueCommitmentMessage(object):

    def __init__(self, U, Proofs, Nonce2, ProofPjwt=None, ProofPjwts=None):
        self.U = U
        self.Nonce2 = Nonce2
        self.Proofs = Proofs
        self.ProofPjwt = ProofPjwt
        self.ProofPjwts = ProofPjwts


class IssueSignatureMessage(object):

    def __init__(self, Signature, Proof):
        self.Proof = Proof
        self.Signature = Signature


def commitmentToSecret(pk, secret):
    vPrime = secure_randint(pk.Params.LvPrime)

    Sv = FP2Value(pk.N, pk.S).intpow(vPrime).a
    R0s = FP2Value(pk.N, pk.R[0]).intpow(secret).a

    return vPrime, (Sv * R0s) % pk.N


class CredentialBuilder(object):

    def __init__(self, pk, context, secret, nonce2):
        vPrime, U = commitmentToSecret(pk, secret)
        self.pk = pk
        self.context = context
        self.secret = secret
        self.vPrime = vPrime
        self.u = U
        self.uCommit = 1
        self.nonce2 = nonce2

        self.proofPcomm = None
        self.skRandomizer = None
        self.vPrimeCommit = None

    def CommitToSecretAndProve(self, nonce1):
        proofU = self.proveCommitment(self.u, nonce1)
        return IssueCommitmentMessage(self.u, [proofU], self.nonce2)

    def CreateIssueCommitmentMessage(self, proofs):
        return IssueCommitmentMessage(self.u, proofs, self.nonce2)

    def ConstructCredential(self, msg, attributes):
        if not msg.Proof.Verify(self.pk, msg.Signature, self.context, self.nonce2):
            return None

        signature = CLSignature(msg.Signature.A, msg.Signature.E, msg.Signature.V + self.vPrime)
        if self.proofPcomm:
            signature.KeyshareP = self.proofPcomm.P

        exponents = [self.secret] + attributes

        if not signature.Verify(self.pk, exponents):
            return None

        return Credential(self.pk, exponents, signature)

    def proveCommitment(self, U, nonce1):
        sCommit = secure_randint(self.pk.Params.LsCommit)
        vPrimeCommit = secure_randint(self.pk.Params.LvPrimeCommit)

        Sv = FP2Value(self.pk.N, self.pk.S).intpow(vPrimeCommit).a
        R0s = FP2Value(self.pk.N, self.pk.R[0]).intpow(sCommit).a
        Ucommit = (Sv * R0s) % self.pk.N

        c = hashCommit([self.context, U, Ucommit, nonce1], False)
        sResponse = (c * self.secret) + sCommit
        vPrimeResponse = (c * self.vPrime) + vPrimeCommit

        return ProofU(U, c, vPrimeResponse, sResponse)

    def MergeProofPCommitment(self, commitment):
        self.proofPcomm = commitment
        self.uCommit = (self.uCommit * commitment.Pcommit) % self.pk.N

    def PublicKey(self):
        return self.pk

    def Commit(self, skRandomizer):
        self.skRandomizer = skRandomizer
        self.vPrimeCommit = secure_randint(self.pk.Params.LvPrimeCommit)

        sv = FP2Value(self.pk.N, self.pk.S).intpow(self.vPrimeCommit).a
        r0s = FP2Value(self.pk.N, self.pk.R[0]).intpow(self.skRandomizer).a
        self.uCommit = (self.uCommit * sv * r0s) % self.pk.N

        ucomm = self.u
        if self.proofPcomm:
            ucomm = (ucomm * self.proofPcomm.P) % self.pk.N

        return [ucomm, self.uCommit]

    def CreateProof(self, challenge):
        sResponse = self.skRandomizer + challenge * self.secret
        vPrimeResponse = self.vPrimeCommit + challenge * self.vPrime

        return ProofU(self.u, challenge, vPrimeResponse, sResponse)
