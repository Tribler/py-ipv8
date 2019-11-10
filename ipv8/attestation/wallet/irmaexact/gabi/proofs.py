"""
Copyright (c) 2016, Maarten Everts
All rights reserved.

This source code has been ported from https://github.com/privacybydesign/gabi
The authors of this file are not -in any way- affiliated with the original authors or organizations.
"""
from cryptography.hazmat.primitives.asymmetric.rsa import _modinv

from pyasn1.codec.ber.encoder import encode
from pyasn1.type import univ

from ...primitives.attestation import sha256_as_int
from ...primitives.value import FP2Value


class Record(univ.SequenceOf):
    componentType = univ.Integer()


def custom_asn1_marshal(values):
    return encode(values, asn1Spec=Record())


def hashCommit(values, issig):
    tmp = [True] if issig else []
    tmp = tmp + [len(values)] + values
    r = custom_asn1_marshal(tmp)
    if issig:
        indx = r.find(b'\x02\x01\x01')
        r = r[:indx] + b'\x01\x01\xFF' + r[indx + 3:]
    return sha256_as_int(r)


def createChallenge(context, nonce, contributions, issig):
    return hashCommit([context] + contributions + [nonce], issig)


class ProofU(object):

    def __init__(self, U, C, VPrimeResponse, SResponse):
        self.U = U
        self.C = C
        self.VPrimeResponse = VPrimeResponse
        self.SResponse = SResponse

    def MergeProofP(self, proofP, pk):
        self.U = (self.U * proofP.P) % pk.N
        self.SResponse = self.SResponse + proofP.SResponse

    def Verify(self, pk, context, nonce):
        return self.VerifyWithChallenge(pk, createChallenge(context, nonce, self.ChallengeContribution(pk), False))

    def correctResponseSizes(self, pk):
        maximum = (1 << (pk.Params.LvPrimeCommit + 1)) - 1
        minimum = -maximum
        return self.VPrimeResponse >= minimum and self.VPrimeResponse <= maximum

    def VerifyWithChallenge(self, pk, reconstructedChallenge):
        return self.correctResponseSizes(pk) and self.C == reconstructedChallenge

    def reconstructUcommit(self, pk):
        Uc = FP2Value(pk.N, self.U).intpow(-self.C)
        Sv = FP2Value(pk.N, pk.S).intpow(self.VPrimeResponse)
        R0s = FP2Value(pk.N, pk.R[0]).intpow(self.SResponse)
        return (Uc * Sv * R0s).a

    def SecretKeyResponse(self):
        return self.SResponse

    def Challenge(self):
        return self.C

    def ChallengeContribution(self, pk):
        return [self.U, self.reconstructUcommit(pk)]


class ProofS(object):

    def __init__(self, C, EResponse):
        self.C = C
        self.EResponse = EResponse

    def Verify(self, pk, signature, context, nonce):
        exponent = self.EResponse * signature.E + self.C
        ACommit = FP2Value(pk.N, signature.A).intpow(exponent).a
        Q = FP2Value(pk.N, signature.A).intpow(signature.E).a
        cPrime = hashCommit([context, Q, signature.A, nonce, ACommit], False)
        return self.C == cPrime


class ProofD(object):

    def __init__(self, C, A, EResponse, VResponse, AResponses, ADisclosed):
        self.C = C
        self.A = A
        self.EResponse = EResponse
        self.VResponse = VResponse
        self.AResponses = AResponses
        self.ADisclosed = ADisclosed

    def MergeProofP(self, proofP, pk):
        self.AResponses[0] += proofP.SResponse

    def correctResponseSizes(self, pk):
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

    def reconstructZ(self, pk):
        numerator = 1 << (pk.Params.Le - 1)
        numerator = FP2Value(pk.N, self.A).intpow(numerator).a

        for i, exp in self.ADisclosed.items():
            if exp.bit_length() > pk.Params.Lm:
                exp = sha256_as_int(str(exp))
            numerator *= FP2Value(pk.N, pk.R[i]).intpow(exp).a
        numerator = numerator % pk.N

        known = pk.Z * _modinv(numerator, pk.N)
        knownC = FP2Value(pk.N, known).intpow(-self.C).a
        Ae = FP2Value(pk.N, self.A).intpow(self.EResponse).a
        Sv = FP2Value(pk.N, pk.S).intpow(self.VResponse).a
        Rs = 1
        for i, response in self.AResponses.items():
            Rs *= FP2Value(pk.N, pk.R[i]).intpow(response).a
        Z = (knownC * Ae * Rs * Sv) % pk.N
        return Z

    def Verify(self, pk, context, nonce1, issig):
        return self.VerifyWithChallenge(pk, createChallenge(context, nonce1, self.ChallengeContribution(pk), issig))

    def VerifyWithChallenge(self, pk, reconstructedChallenge):
        return self.correctResponseSizes(pk) and self.C == reconstructedChallenge

    def ChallengeContribution(self, pk):
        return [self.A, self.reconstructZ(pk)]

    def SecretKeyResponse(self):
        return self.AResponses[0]

    def Challenge(self):
        return self.C

    def Copy(self):
        ADisclosed = {}
        for k, v in self.ADisclosed.items():
            ADisclosed[k] = v
        return ProofD(self.C, self.A, self.EResponse, self.VResponse, self.AResponses, ADisclosed)


class ProofP(object):

    def __init__(self, P, C, SResponse):
        self.P = P
        self.C = C
        self.SResponse = SResponse


class ProofPCommitment(object):

    def __init__(self, P, Pcommit):
        self.P = P
        self.Pcommit = Pcommit
